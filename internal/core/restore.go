// Package core implements directory restoration and topology reconstitution.
//
// Objectives:
//   - Reconstitute complex directory structures from snapshot archives with exact permission parity.
//   - Execute a deterministic two-pass synchronization model:
//     1. Forward Pass (depth 0..maxDepth): Creates parent directories first and applies permissions/SDDL.
//     2. Mirror Evacuation: Archives untracked files/folders before timestamp freezing.
//     3. Reverse Pass (depth maxDepth..0): Freezes timestamps bottom-up to prevent parent mtime invalidation.
//   - Support re-rooting snapshots via base substitution and cross-domain identity translation.
//
// Core Components:
//   - Restore: Master reconstitution workflow driving forward creation, evacuation, and reverse timestamping.
//   - Depth Stratifier: Buckets directory records by path depth to guarantee strict topological creation order.
//   - readSnapshotFromReader / readSnapshotFromSource: Streaming snapshot ingestion with Zstandard decompression.
//
// Data Flow:
//
//	Snapshot Stream -> Format Decoder -> Base Re-rooting -> IdentityMap Translation -> Depth Map
//	-> Forward Pass (os.MkdirAll + ApplyMeta) -> Mirror Evacuation -> Reverse Pass (SetTimes) -> RestoreResult.
package core

import (
	"bufio"
	"cmp"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/edsilegxrepo/dtreesync/internal/format"
	"github.com/edsilegxrepo/dtreesync/internal/meta"
	"github.com/edsilegxrepo/dtreesync/internal/model"
	"github.com/edsilegxrepo/dtreesync/internal/storage"
)

// Restore executes depth-sorted directory reconstitution with bottom-up timestamp preservation.
func Restore(ctx context.Context, cfg model.RestoreConfig, al *model.AuditLogger) (*model.RestoreResult, error) {
	start := time.Now()

	cleanTarget, err := model.ValidateAndCleanPath(cfg.TargetFolder)
	if err != nil {
		return nil, fmt.Errorf("target folder invalid: %w", err)
	}

	// Parse base substitute if provided
	var oldBase, newBase string
	if cfg.BaseSubstitute != "" {
		oldBase, newBase, err = model.ParseBaseSubstitute(cfg.BaseSubstitute)
		if err != nil {
			return nil, err
		}
	}

	// Determine workers
	workers := cfg.Workers
	if workers <= 0 {
		workers = min(runtime.NumCPU()*2, 32)
	}
	if workers < 1 {
		workers = 1
	}
	if workers > 32 {
		workers = 32
	}

	limiter := model.NewIOPSLimiter(cfg.MaxIOPS)
	engine := meta.DefaultEngine
	_ = engine.InitPrivileges()

	// 1. Read all snapshot records from Reader or file
	var records []model.DirRecord
	var snapshotMeta *model.BackupMetadata
	filter := model.NewRecordFilter(cfg.Entities, cfg.Include, cfg.Exclude)

	recordCollector := func(rec model.DirRecord) error {
		// Apply base substitute if active
		if oldBase != "" && newBase != "" {
			fullPath := filepath.Join(cleanTarget, filepath.FromSlash(rec.RelPath))
			rebased := model.RebasePath(fullPath, oldBase, newBase)
			if rel, relErr := filepath.Rel(cleanTarget, rebased); relErr == nil {
				if norm, normErr := model.NormalizeRelPath(rel); normErr == nil {
					rec.RelPath = norm
				}
			}
		}

		// Apply identity mapping
		if cfg.IdentityMap != nil {
			rec.Metadata = cfg.IdentityMap.ApplyToPlatformMeta(rec.Metadata)
		}

		// Apply unified entity, inclusion, and exclusion filtering
		if !filter.Matches(rec) {
			return nil
		}

		records = append(records, rec)
		return nil
	}

	// Read stream
	if cfg.Reader != nil {
		snapshotMeta, err = readSnapshotFromReader(cfg.Reader, cfg.Format, cfg.Compression, recordCollector)
	} else if cfg.SourceURL != "" {
		snapshotMeta, err = readSnapshotFromSource(ctx, cfg.SourceURL, cfg.Format, cfg.Compression, recordCollector)
	} else {
		return nil, fmt.Errorf("%w: neither Reader nor SourceURL supplied", model.ErrSnapshotNotFound)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to read snapshot: %w", err)
	}
	_ = snapshotMeta

	var (
		createdDirs  atomic.Int64
		appliedPerms atomic.Int64
		warningsMu   sync.Mutex
		warnings     []string
	)

	addWarning := func(msg string) {
		warningsMu.Lock()
		warnings = append(warnings, msg)
		warningsMu.Unlock()
	}

	// 2. Group records by depth for deterministic parent-first creation
	depthMap := make(map[int][]model.DirRecord)
	maxDepth := 0

	for _, r := range records {
		d := 0
		if r.RelPath != "" {
			d = strings.Count(r.RelPath, "/") + 1
		}
		if d > maxDepth {
			maxDepth = d
		}
		depthMap[d] = append(depthMap[d], r)
	}

	// 3. Forward Pass: Create directories and apply permissions depth-by-depth
	for d := 0; d <= maxDepth; d++ {
		layer := depthMap[d]
		if len(layer) == 0 {
			continue
		}

		// Sort lexicographically within depth layer
		slices.SortFunc(layer, func(a, b model.DirRecord) int {
			return cmp.Compare(a.RelPath, b.RelPath)
		})

		// Parallel worker execution for layer
		sem := make(chan struct{}, workers)
		var layerWG sync.WaitGroup

		for _, rec := range layer {
			select {
			case <-ctx.Done():
				layerWG.Wait()
				return nil, ctx.Err()
			case sem <- struct{}{}:
			}

			layerWG.Add(1)

			go func(r model.DirRecord) {
				defer func() {
					<-sem
					layerWG.Done()
				}()

				if ctx.Err() != nil {
					return
				}

				targetPath := cleanTarget
				if r.RelPath != "" {
					targetPath = filepath.Join(cleanTarget, filepath.FromSlash(r.RelPath))
					rel, relErr := filepath.Rel(cleanTarget, targetPath)
					if relErr != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
						addWarning(fmt.Sprintf("skipped path escaping target directory: %q", r.RelPath))
						return
					}
				}

				if err := limiter.Wait(ctx); err != nil {
					return
				}

				perm := os.FileMode(0o755)
				if r.Metadata.Mode != nil {
					perm = os.FileMode(*r.Metadata.Mode)
				}

				if err := os.MkdirAll(targetPath, perm); err != nil {
					addWarning(fmt.Sprintf("mkdir failed on %q: %v", targetPath, err))
					return
				}
				createdDirs.Add(1)

				if cfg.ApplyPerms {
					if err := engine.ApplyMeta(targetPath, &r.Metadata, true); err != nil {
						addWarning(fmt.Sprintf("perm apply error on %q: %v", targetPath, err))
					} else {
						appliedPerms.Add(1)
					}
				}

				if al != nil {
					al.LogInfo("restore", "dir_created", targetPath, map[string]any{
						"depth": d,
					})
				}
			}(rec)
		}

		layerWG.Wait()

		if cfg.OnProgress != nil {
			cfg.OnProgress(model.RestoreProgress{
				CreatedDirs:  createdDirs.Load(),
				AppliedPerms: appliedPerms.Load(),
				CurrentDepth: d,
				ElapsedTime:  time.Since(start),
			})
		}
	}

	// 4. Mirror Evacuation: Relocate untracked items before timestamp freeze
	var evacuatedArchive string
	if cfg.Type == "mirror" && cfg.ArchiveExtraFolder != "" {
		expectedMap := make(map[string]bool)
		for _, r := range records {
			expectedMap[r.RelPath] = true
		}

		var untrackedList []string
		_ = filepath.WalkDir(cleanTarget, func(p string, d os.DirEntry, walkErr error) error {
			if walkErr != nil || p == cleanTarget {
				return nil
			}
			rel, err := filepath.Rel(cleanTarget, p)
			if err != nil {
				return nil
			}
			normRel := filepath.ToSlash(rel)
			if d.IsDir() {
				if !expectedMap[normRel] {
					untrackedList = append(untrackedList, normRel)
					return filepath.SkipDir
				}
			} else {
				untrackedList = append(untrackedList, normRel)
			}
			return nil
		})

		if len(untrackedList) > 0 {
			archivePath, err := EvacuateUntracked(ctx, cleanTarget, cfg.ArchiveExtraFolder, untrackedList, al)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("mirror evacuation failed: %v", err))
			} else {
				evacuatedArchive = archivePath
			}
		}
	}

	// 5. Reverse Pass: Apply bottom-up timestamps (depth descending)
	for d := maxDepth; d >= 0; d-- {
		layer := depthMap[d]
		if len(layer) == 0 {
			continue
		}

		sem := make(chan struct{}, workers)
		var layerWG sync.WaitGroup

	LayerLoop:
		for _, rec := range layer {
			select {
			case <-ctx.Done():
				break LayerLoop
			case sem <- struct{}{}:
			}

			layerWG.Add(1)

			go func(r model.DirRecord) {
				defer func() {
					<-sem
					layerWG.Done()
				}()

				if ctx.Err() != nil {
					return
				}

				targetPath := cleanTarget
				if r.RelPath != "" {
					targetPath = filepath.Join(cleanTarget, filepath.FromSlash(r.RelPath))
					rel, relErr := filepath.Rel(cleanTarget, targetPath)
					if relErr != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
						return
					}
				}

				_ = limiter.Wait(ctx)
				_ = engine.SetTimes(targetPath, r.Metadata.BirthTime, r.Metadata.ModTime, r.Metadata.AccessTime)
			}(rec)
		}

		layerWG.Wait()
	}

	duration := time.Since(start)
	if al != nil {
		al.LogInfo("core", "restore_complete", cleanTarget, map[string]any{
			"created_dirs": createdDirs.Load(),
			"duration_ms":  duration.Milliseconds(),
		})
	}

	return &model.RestoreResult{
		CreatedFolders:   createdDirs.Load(),
		AppliedPerms:     appliedPerms.Load(),
		EvacuatedArchive: evacuatedArchive,
		Warnings:         warnings,
		Duration:         duration,
	}, nil
}

func readSnapshotFromReader(r io.Reader, fmtType model.FormatType, comp model.CompressionType, onRec func(r model.DirRecord) error) (*model.BackupMetadata, error) {
	bufR := bufio.NewReader(r)

	// Auto-detect Zstandard compression if not explicitly specified
	isZstd := comp == model.CompressionZstd
	if comp == "" {
		if peekMagic, err := bufR.Peek(4); err == nil && len(peekMagic) >= 4 {
			if peekMagic[0] == 0x28 && peekMagic[1] == 0xb5 && peekMagic[2] == 0x2f && peekMagic[3] == 0xfd {
				isZstd = true
			}
		}
	}

	var reader io.Reader = bufR
	if isZstd {
		dec, err := format.NewZstdReader(bufR, 4)
		if err != nil {
			return nil, err
		}
		defer dec.Close()
		reader = dec
	}

	// Auto-detect format from first non-empty byte if not specified
	if fmtType == "" {
		textBuf := bufio.NewReader(reader)
		if peekLead, err := textBuf.Peek(1); err == nil && len(peekLead) > 0 {
			if peekLead[0] == '#' {
				fmtType = model.FormatTSV
			} else {
				fmtType = model.FormatNDJSON
			}
		} else {
			fmtType = model.FormatNDJSON
		}
		reader = textBuf
	}

	switch fmtType {
	case model.FormatTSV:
		return format.ReadTSVRecords(reader, onRec)
	case model.FormatNDJSON:
		return format.ReadNDJSONRecords(reader, onRec)
	default:
		return nil, fmt.Errorf("%w: %s", model.ErrFormatUnsupported, fmtType)
	}
}

func readSnapshotFromSource(ctx context.Context, sourceURL string, fmtType model.FormatType, comp model.CompressionType, onRec func(r model.DirRecord) error) (*model.BackupMetadata, error) {
	// Deduce format and compression if not specified
	if fmtType == "" || comp == "" {
		deducedFmt, deducedComp := format.DeduceFormatAndCompression(sourceURL)
		if fmtType == "" {
			fmtType = deducedFmt
		}
		if comp == "" {
			comp = deducedComp
		}
	}

	if fmtType == model.FormatSQLite {
		return format.ReadSQLiteRecords(sourceURL, onRec)
	}

	if storage.IsCloudURL(sourceURL) {
		cr, err := storage.NewCloudReader(ctx, sourceURL)
		if err != nil {
			return nil, fmt.Errorf("failed to open cloud source %q: %w", sourceURL, err)
		}
		defer func() { _ = cr.Close() }()
		return readSnapshotFromReader(cr, fmtType, comp, onRec)
	}

	cleanPath, err := model.ValidateAndCleanPath(sourceURL)
	if err != nil {
		return nil, err
	}

	// #nosec G304 -- Snapshot source path is validated and sanitized via ValidateAndCleanPath.
	f, err := os.Open(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open snapshot file %q: %w", cleanPath, err)
	}
	defer func() { _ = f.Close() }()

	return readSnapshotFromReader(f, fmtType, comp, onRec)
}
