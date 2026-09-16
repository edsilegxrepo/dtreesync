// Package core implements directory scanning, snapshot creation, restoration,
// drift verification, mirror evacuation, and retention lifecycle management.
//
// Objectives:
//   - Traverse massive directory hierarchies (>1,000,000 directories) at speeds exceeding 900,000 dirs/sec.
//   - Enforce the Zero-Payload File I/O architecture: discover directory topology without reading file contents.
//   - Provide an unbounded in-memory task backlog coordinator with zero CPU spin and waitgroup task tracking.
//   - Support optional single-pass live payload file discovery via the OnFile callback without extra filesystem sweeps.
//
// Core Components:
//   - Scanner: Master traversal orchestrator managing worker pools, rate limiting, and device boundary checks.
//   - ScanTask: Atomic unit of traversal pairing absolute filesystem location with normalized relative path.
//   - Coordinator Loop: Goroutine dispatching tasks to workers without blocking or channel capacity overflows.
//   - readSubdirs: High-speed directory reader filtering exclusions, symlinks, and cross-device mount links.
//
// Data Flow:
//
//	Root Directory -> readSubdirs() -> discoveryChan -> Coordinator Queue -> taskChan -> Workers
//	Workers -> PlatformEngine.ReadMeta() -> model.DirRecord -> outChan -> Serialization Pipeline.
package core

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/edsilegxrepo/dtreesync/internal/meta"
	"github.com/edsilegxrepo/dtreesync/internal/model"
)

// ScanTask defines a directory to be read and traversed.
type ScanTask struct {
	AbsPath string
	RelPath string
}

// Scanner coordinates concurrent discovery of directory hierarchies without payload file I/O.
type Scanner struct {
	rootAbs     string
	opts        model.ScanOptions
	limiter     *model.IOPSLimiter
	engine      meta.PlatformEngine
	auditLogger *model.AuditLogger
	scannedDirs atomic.Int64
	rootDev     uint64
	hasRootDev  bool
}

// NewScanner constructs a verified Scanner instance.
func NewScanner(root string, opts model.ScanOptions, al *model.AuditLogger) (*Scanner, error) {
	cleanRoot, err := model.ValidateAndCleanPath(root)
	if err != nil {
		return nil, err
	}

	workers := opts.Workers
	if workers <= 0 {
		workers = min(runtime.NumCPU()*2, 32)
	}
	if workers < 1 {
		workers = 1
	}
	if workers > 32 {
		workers = 32
	}
	opts.Workers = workers

	s := &Scanner{
		rootAbs:     cleanRoot,
		opts:        opts,
		limiter:     model.NewIOPSLimiter(opts.MaxIOPS),
		engine:      meta.DefaultEngine,
		auditLogger: al,
	}

	if opts.OneFileSystem {
		s.initRootDevice()
	}

	return s, nil
}

// ScannedCount returns total directories processed.
func (s *Scanner) ScannedCount() int64 {
	return s.scannedDirs.Load()
}

// Stream walks the directory tree rooted at rootAbs and streams DirRecord entries into outChan.
func (s *Scanner) Stream(ctx context.Context, outChan chan<- model.DirRecord) error {
	defer close(outChan)

	// Verify root existence
	rootInfo, err := os.Lstat(s.rootAbs)
	if err != nil {
		return fmt.Errorf("root directory not accessible: %w", err)
	}
	if !rootInfo.IsDir() {
		return fmt.Errorf("%w: root path %q is not a directory", model.ErrInvalidPath, s.rootAbs)
	}

	// Capture root metadata
	rootMeta, err := s.engine.ReadMeta(s.rootAbs)
	if err != nil {
		return fmt.Errorf("failed to read root metadata on %q: %w", s.rootAbs, err)
	}

	// Emit root record
	rootRecord := model.DirRecord{
		Entity:   "",
		RelPath:  "",
		Metadata: *rootMeta,
	}
	select {
	case outChan <- rootRecord:
		s.scannedDirs.Add(1)
	case <-ctx.Done():
		return ctx.Err()
	}

	// Read initial root subdirectories
	initialTasks, err := s.readSubdirs(ctx, s.rootAbs, "")
	if err != nil {
		return err
	}
	if len(initialTasks) == 0 {
		return nil
	}

	// Unbounded coordinator task queue and discovery channel
	taskChan := make(chan ScanTask, s.opts.Workers*2)
	discoveryChan := make(chan []ScanTask, s.opts.Workers*4)
	var taskWG sync.WaitGroup
	var workerWG sync.WaitGroup

	// Launch worker pool
	for i := 0; i < s.opts.Workers; i++ {
		workerWG.Add(1)
		go func() {
			defer workerWG.Done()
			s.worker(ctx, taskChan, discoveryChan, outChan, &taskWG)
		}()
	}

	taskWG.Add(len(initialTasks))

	allTasksDone := make(chan struct{})
	go func() {
		taskWG.Wait()
		close(allTasksDone)
	}()

	// Coordinator goroutine managing dynamic backlog
	coordinatorDone := make(chan struct{})
	go func() {
		defer close(coordinatorDone)
		defer close(taskChan)

		var queue []ScanTask
		queue = append(queue, initialTasks...)

		for {
			var nextTask ScanTask
			var currentOut chan<- ScanTask

			if len(queue) > 0 {
				nextTask = queue[0]
				currentOut = taskChan
			}

			select {
			case <-ctx.Done():
				return

			case newBatch, ok := <-discoveryChan:
				if ok {
					queue = append(queue, newBatch...)
				}

			case currentOut <- nextTask:
				queue[0] = ScanTask{}
				queue = queue[1:]
				if len(queue) == 0 && cap(queue) > 4096 {
					queue = nil
				}

			case <-allTasksDone:
				return
			}
		}
	}()

	<-coordinatorDone
	workerWG.Wait()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return nil
}

func (s *Scanner) worker(ctx context.Context, taskChan <-chan ScanTask, discoveryChan chan<- []ScanTask, outChan chan<- model.DirRecord, taskWG *sync.WaitGroup) {
	for {
		select {
		case <-ctx.Done():
			return
		case task, ok := <-taskChan:
			if !ok {
				return
			}
			s.processTask(ctx, task, discoveryChan, outChan, taskWG)
			taskWG.Done()
		}
	}
}

func (s *Scanner) processTask(ctx context.Context, task ScanTask, discoveryChan chan<- []ScanTask, outChan chan<- model.DirRecord, taskWG *sync.WaitGroup) {
	select {
	case <-ctx.Done():
		return
	default:
	}

	// Read directory metadata
	pMeta, err := s.engine.ReadMeta(task.AbsPath)
	if err != nil {
		// Log warning on transient permission error and continue
		if s.auditLogger != nil {
			s.auditLogger.LogWarn("scanner", "meta_read_failed", task.AbsPath, err.Error(), nil)
		}
		pMeta = &model.PlatformMeta{}
	}

	// Extract entity: first directory segment of relative path
	entity := ""
	if parts := strings.Split(task.RelPath, "/"); len(parts) > 0 {
		entity = parts[0]
	}

	rec := model.DirRecord{
		Entity:   entity,
		RelPath:  task.RelPath,
		Metadata: *pMeta,
	}

	if s.isMatchInclude(task.RelPath) {
		select {
		case outChan <- rec:
			s.scannedDirs.Add(1)
			if s.auditLogger != nil {
				s.auditLogger.LogInfo("scanner", "dir_scanned", task.AbsPath, map[string]any{
					"rel_path": task.RelPath,
				})
			}
		case <-ctx.Done():
			return
		}
	}

	// Read children
	children, err := s.readSubdirs(ctx, task.AbsPath, task.RelPath)
	if err != nil {
		if s.auditLogger != nil {
			s.auditLogger.LogWarn("scanner", "readdir_failed", task.AbsPath, err.Error(), nil)
		}
		return
	}

	if len(children) > 0 {
		taskWG.Add(len(children))
		select {
		case discoveryChan <- children:
		case <-ctx.Done():
			for i := 0; i < len(children); i++ {
				taskWG.Done()
			}
			return
		}
	}
}

func (s *Scanner) readSubdirs(ctx context.Context, absDir, relDir string) ([]ScanTask, error) {
	// IOPS rate limiter wait
	if err := s.limiter.Wait(ctx); err != nil {
		return nil, err
	}

	cleanDir := filepath.Clean(absDir)
	// #nosec G304 -- Directory path is traversed internal to scanner root.
	f, err := os.Open(cleanDir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	// Read all directory entries at once (low syscall count)
	entries, err := f.ReadDir(-1)
	if err != nil {
		return nil, err
	}

	var tasks []ScanTask
	for _, entry := range entries {
		// ZERO PAYLOAD FILE I/O: discard regular files immediately unless OnFile callback is set
		if !entry.IsDir() {
			if s.opts.OnFile != nil && (entry.Type()&os.ModeSymlink == 0) {
				fileRel := entry.Name()
				if relDir != "" {
					fileRel = relDir + "/" + entry.Name()
				}
				s.opts.OnFile(fileRel)
			}
			continue
		}

		// Avoid symlink loops / reparse junctions
		if entry.Type()&os.ModeSymlink != 0 {
			continue
		}

		// Scope to immediate root entity if configured
		if relDir == "" && s.opts.Entity != "" && entry.Name() != s.opts.Entity {
			continue
		}

		childRel := entry.Name()
		if relDir != "" {
			childRel = relDir + "/" + entry.Name()
		}

		// Apply exclusion filter
		if s.isExcluded(childRel) {
			continue
		}

		// Apply inclusion traversal filter
		if !s.isTraversable(childRel) {
			continue
		}

		childAbs := filepath.Join(absDir, entry.Name())

		// Apply one-file-system check
		if s.opts.OneFileSystem && !s.isSameDevice(childAbs) {
			continue
		}

		tasks = append(tasks, ScanTask{
			AbsPath: childAbs,
			RelPath: childRel,
		})
	}

	return tasks, nil
}

// isExcluded tests whether relPath matches any configured exclusion glob pattern.
func (s *Scanner) isExcluded(relPath string) bool {
	if len(s.opts.Exclude) == 0 {
		return false
	}
	for _, pattern := range s.opts.Exclude {
		if model.MatchGlob(pattern, relPath) {
			return true
		}
	}
	return false
}

// isTraversable checks whether relPath either matches an include pattern or is an
// ancestor prefix along the path to an included directory, ensuring intermediate directories are traversed.
func (s *Scanner) isTraversable(relPath string) bool {
	if len(s.opts.Include) == 0 {
		return true
	}
	for _, pattern := range s.opts.Include {
		if model.MatchGlob(pattern, relPath) {
			return true
		}
		cleanPat := strings.Trim(filepath.ToSlash(pattern), "/")
		if strings.HasPrefix(cleanPat, relPath+"/") || strings.HasPrefix(cleanPat, relPath) {
			return true
		}
	}
	return false
}

// isMatchInclude checks whether relPath strictly matches configured inclusion patterns
// for record emission to the output stream.
func (s *Scanner) isMatchInclude(relPath string) bool {
	if len(s.opts.Include) == 0 || relPath == "" {
		return true
	}
	for _, pattern := range s.opts.Include {
		if model.MatchGlob(pattern, relPath) {
			return true
		}
	}
	return false
}
