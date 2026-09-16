// Package main implements the production CLI driver for dtreesync.
//
// OBJECTIVES:
// Provide an enterprise-grade command-line interface for snapshotting, restoring,
// diffing, verifying, and inspecting high-scale directory trees (millions of nodes)
// without payload file I/O overhead while maintaining complete cross-platform
// permission and metadata fidelity across Linux and Windows.
//
// CORE COMPONENTS:
// - Subcommand Router: Dispatches CLI invocations to dedicated subcommand runners.
// - Flag Parsers: Validates and sanitizes CLI flags, enforcing absolute path boundaries.
// - Signal Trap: Installs two-tier graceful termination traps (Tier 1 drain, Tier 2 hard kill).
// - Output Formatters: Serializes operational metrics in Human-Readable Table, JSON, or YAML.
// - Diagnostic Exit Handlers: Returns granular POSIX/standardized diagnostic exit codes.
//
// DATA FLOW:
// CLI Arguments -> Flag Parsing & Validation -> Signal Trap Setup ->
// Programmatic Engine Invocation (pkg/dtreesync) -> Metric Formatting -> Granular os.Exit
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/edsilegxrepo/dtreesync/internal/core"
	"github.com/edsilegxrepo/dtreesync/internal/model"
	"github.com/edsilegxrepo/dtreesync/internal/storage"
	"github.com/edsilegxrepo/dtreesync/pkg/dtreesync"
)

// version specifies the application build version.
// Defaults to "dev", but can be overridden at link time via:
//
//	-ldflags "-X main.version=xxxx"
var version = "dev"

// osExit is the exit handler, stubbed out during testing.
var osExit = os.Exit

// clampWorkers confines concurrency strictly between 1 and 32 threads,
// defaulting to min(NumCPU * 2, 32) to prevent scheduler and OS thread exhaustion.
func clampWorkers(w int) int {
	if w <= 0 {
		w = runtime.NumCPU() * 2
	}
	if w < 1 {
		w = 1
	}
	if w > 32 {
		w = 32
	}
	return w
}

// applyMemoryLimit configures Go runtime soft memory limit via debug.SetMemoryLimit.
func applyMemoryLimit(limitMB int) {
	if limitMB > 0 {
		debug.SetMemoryLimit(int64(limitMB) * 1024 * 1024)
	}
}

// printJSON serializes an output struct as indented JSON to stdout.
func printJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// printYAML serializes an output struct to stdout using a clean, dependency-free YAML formatter.
func printYAML(v any) {
	// Clean, dependency-free YAML serialization via intermediate map
	data, err := json.Marshal(v)
	if err != nil {
		printJSON(v)
		return
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		printJSON(v)
		return
	}
	for k, val := range m {
		fmt.Printf("%s: %v\n", k, val)
	}
}

// resolveLogPath reconciles primary and alias log flags (--log vs --log-file).
func resolveLogPath(log1, log2 string) string {
	if log1 != "" {
		return log1
	}
	return log2
}

// resolveOutputMode normalizes output flags (--output=json/yaml/table vs --json).
func resolveOutputMode(outputFlag string, jsonFlag bool) string {
	if jsonFlag {
		return "json"
	}
	if outputFlag != "" {
		return strings.ToLower(outputFlag)
	}
	return "table"
}

// main is the primary entrypoint for the dtreesync CLI binary.
func main() {
	if len(os.Args) < 2 {
		printUsage()
		osExit(core.ExitUsageError)
	}

	subcommand := os.Args[1]
	args := os.Args[2:]

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	core.SetupSignalTrap(ctx, cancel, nil)

	switch subcommand {
	case "backup":
		runBackup(ctx, args)
	case "restore":
		runRestore(ctx, args)
	case "diff":
		runDiff(ctx, args)
	case "verify":
		runVerify(ctx, args)
	case "status", "inspect":
		runStatus(ctx, args)
	case "version", "--version", "-v":
		runVersion(args)
	case "-h", "--help", "help":
		printUsage()
		osExit(core.ExitSuccess)
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q. Run 'dtreesync help' for usage.\n", subcommand)
		osExit(core.ExitUsageError)
	}
}

// printUsage renders top-level CLI help and available subcommands.
func printUsage() {
	fmt.Println(`dtreesync - High-Performance Enterprise Directory Synchronization & Metadata Preservation

Usage:
  dtreesync <subcommand> [flags]

Subcommands:
  backup    Scan directory hierarchy and create snapshot archive
  restore   Materialize directory tree from snapshot archive
  diff      Inspect drift between live filesystem and baseline snapshot
  status    Inspect snapshot headers and list repository status (alias: inspect)
  verify    Zero-disk-write cryptographic integrity verification
  version   Display version and runtime information

Run 'dtreesync <subcommand> --help' for flag details.`)
}

// runVersion prints the application version and runtime metadata.
func runVersion(args []string) {
	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	jsonFlag := fs.Bool("json", false, "Output version information in JSON format")
	outputFlag := fs.String("output", "", "Output format: table (default) or json")
	_ = fs.Parse(args)

	mode := resolveOutputMode(*outputFlag, *jsonFlag)
	if mode == "json" {
		info := struct {
			Version   string `json:"version"`
			GoVersion string `json:"go_version"`
			OS        string `json:"os"`
			Arch      string `json:"arch"`
		}{
			Version:   version,
			GoVersion: runtime.Version(),
			OS:        runtime.GOOS,
			Arch:      runtime.GOARCH,
		}
		printJSON(info)
		osExit(core.ExitSuccess)
	}

	fmt.Printf("dtreesync version %s (Go runtime: %s, OS: %s/%s)\n", version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
	osExit(core.ExitSuccess)
}

// runBackup parses flags, executes directory hierarchy discovery without payload I/O,
// canonically sorts directory records, writes the snapshot stream, and handles optional Git commits.
func runBackup(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("backup", flag.ContinueOnError)

	baseFolder := fs.String("base-folder", "", "Required: absolute path to source directory root")
	treeFile := fs.String("tree-file", "", "Target snapshot output destination or cloud URL")
	formatType := fs.String("format", "", "Serialization format: ndjson, tsv, sqlite (alias: --tree-format)")
	treeFormat := fs.String("tree-format", "", "Alias for --format: ndjson, tsv, sqlite")
	compression := fs.String("compression", "", "Compression: zstd, none")
	backupCompress := fs.Bool("backup-compress", true, "Enable Zstandard compression")
	threads := fs.Int("threads", 0, "Concurrent scanning threads (1..32, default: min(NumCPU*2, 32))")
	maxIOPS := fs.Int("max-iops", 0, "Token-bucket IOPS limit (0 for unlimited)")
	maxMemoryMB := fs.Int("max-memory-mb", 0, "Soft heap memory limit in MB (0 for unlimited)")
	oneFileSystem := fs.Bool("one-file-system", false, "Confine traversal to initial filesystem mount")
	log1 := fs.String("log", "", "Path to machine-readable NDJSON audit log")
	log2 := fs.String("log-file", "", "Alias for --log")
	outputMode := fs.String("output", "table", "Output format: table, json, yaml")
	jsonOutput := fs.Bool("json", false, "Alias for --output=json")
	retentionDays := fs.Int("retention-days", 0, "FIFO retention window in days (0 to disable)")
	backupRetention := fs.Int("backup-retention", 0, "Alias for --retention-days")
	retentionCount := fs.Int("retention-count", 0, "FIFO retention count (0 to disable)")
	entity := fs.String("entity", "", "Restricts scanning to a single immediate top-level partner/tenant folder")
	includeStr := fs.String("include", "", "Comma-separated glob include patterns")
	excludeStr := fs.String("exclude", "", "Comma-separated glob exclude patterns")
	dryRun := fs.Bool("dry-run", false, "Traverse tree and report projected count without creating snapshot")
	sortOrder := fs.String("sort", "path", "Record sort order: path (canonical lexicographical), depth (topological), none (unsorted)")

	// Git flags
	gitRepo := fs.String("git-repo", "", "Commit snapshot directly to Git repository")
	gitBranch := fs.String("git-branch", "main", "Target Git branch")
	gitTag := fs.String("git-tag", "", "Create immutable Git tag on compliance commit")
	gitSSHKey := fs.String("git-ssh-key", "", "Path to private SSH key for remote Git auth")
	gitToken := fs.String("git-token", "", "Personal access token for remote Git auth (supports secretprotector)")
	gitPassphrase := fs.String("git-passphrase", "", "Passphrase for private SSH key (supports secretprotector)")
	gitUser := fs.String("git-username", "", "Username for Git authentication")
	secretKey := fs.String("secret-key", "", "SecretProtector AES-256-GCM master key (hex or raw)")
	secretKeyFile := fs.String("secret-key-file", "", "Path to file containing SecretProtector master key")

	if err := fs.Parse(args); err != nil {
		osExit(core.ExitUsageError)
	}

	targetDest := *treeFile
	isTempGitSnapshot := false
	if targetDest == "" && *gitRepo != "" {
		targetDest = filepath.Join(os.TempDir(), "dtreesync_git_tree.ndjson.zst")
		isTempGitSnapshot = true
	}

	if *baseFolder == "" || (targetDest == "" && !*dryRun) {
		fmt.Fprintln(os.Stderr, "Error: both --base-folder and --tree-file (or --git-repo) are required.")
		fs.Usage()
		osExit(core.ExitUsageError)
	}

	applyMemoryLimit(*maxMemoryMB)

	// Resolve format
	fmtChoice := *formatType
	if fmtChoice == "" {
		fmtChoice = *treeFormat
	}

	// Resolve compression
	compChoice := *compression
	if compChoice == "" {
		if *backupCompress {
			compChoice = "zstd"
		} else {
			compChoice = "none"
		}
	}

	// Resolve retention
	retDays := *retentionDays
	if retDays == 0 {
		retDays = *backupRetention
	}

	logPath := resolveLogPath(*log1, *log2)
	cleanSort := strings.ToLower(strings.TrimSpace(*sortOrder))
	if cleanSort == "" || cleanSort == "canonical" {
		cleanSort = "path"
	}
	if cleanSort != "path" && cleanSort != "depth" && cleanSort != "none" {
		fmt.Fprintf(os.Stderr, "Error: invalid --sort value %q (must be 'path', 'depth', or 'none')\n", *sortOrder)
		osExit(core.ExitUsageError)
	}
	outFmt := resolveOutputMode(*outputMode, *jsonOutput)

	var includes, excludes []string
	if *includeStr != "" {
		includes = strings.Split(*includeStr, ",")
	}
	if *excludeStr != "" {
		excludes = strings.Split(*excludeStr, ",")
	}

	if *dryRun {
		scanOpts := model.ScanOptions{
			Workers:       clampWorkers(*threads),
			MaxIOPS:       *maxIOPS,
			Entity:        *entity,
			OneFileSystem: *oneFileSystem,
			Include:       includes,
			Exclude:       excludes,
		}
		var al *model.AuditLogger
		if logPath != "" {
			var err error
			al, err = model.NewAuditLoggerFromFile(logPath, 10000)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to initialize audit log: %v\n", err)
				osExit(core.ExitFatalError)
			}
			defer func() { _ = al.Close() }()
		}
		scanner, err := core.NewScanner(*baseFolder, scanOpts, al)
		if err != nil {
			fmt.Fprintf(os.Stderr, "scanner initialization failed: %v\n", err)
			osExit(core.ExitFatalError)
		}
		ch := make(chan model.DirRecord, 2048)
		var count atomic.Int64
		var drainWG sync.WaitGroup
		drainWG.Add(1)
		go func() {
			defer drainWG.Done()
			for range ch {
				count.Add(1)
			}
		}()
		if err := scanner.Stream(ctx, ch); err != nil {
			drainWG.Wait()
			fmt.Fprintf(os.Stderr, "dry-run scan failed: %v\n", err)
			osExit(core.ExitFatalError)
		}
		drainWG.Wait()
		if outFmt == "json" {
			printJSON(map[string]any{"dry_run": true, "folders_projected": count.Load(), "base_folder": *baseFolder})
		} else {
			fmt.Printf("Dry-Run Completed: Projected %d directories in %s\n", count.Load(), *baseFolder)
		}
		osExit(core.ExitSuccess)
	}

	cfg := dtreesync.BackupConfig{
		BaseFolder:     *baseFolder,
		TargetURL:      targetDest,
		Entity:         *entity,
		Format:         model.FormatType(fmtChoice),
		Compression:    model.CompressionType(compChoice),
		Workers:        clampWorkers(*threads),
		MaxIOPS:        *maxIOPS,
		MaxMemoryMB:    *maxMemoryMB,
		OneFileSystem:  *oneFileSystem,
		LogFile:        logPath,
		RetentionDays:  retDays,
		RetentionCount: *retentionCount,
		Include:        includes,
		Exclude:        excludes,
		SecretKey:      *secretKey,
		SecretKeyFile:  *secretKeyFile,
		SortOrder:      cleanSort,
	}

	res, err := dtreesync.Backup(ctx, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "backup failed: %v\n", err)
		osExit(core.ExitFatalError)
	}

	// Handle Git commit if requested
	if *gitRepo != "" {
		cleanDest := filepath.Clean(targetDest)
		// #nosec G304 -- Target snapshot file path is cleaned with filepath.Clean.
		data, err := os.ReadFile(cleanDest)
		if err == nil {
			commitHash, err := storage.CommitSnapshotToGit(ctx, storage.GitCommitConfig{
				RepoURL:          *gitRepo,
				Branch:           *gitBranch,
				Tag:              *gitTag,
				SnapshotFilename: filepath.Base(targetDest),
				SnapshotData:     data,
				AuthOpts: storage.GitAuthOptions{
					Username:      *gitUser,
					Password:      *gitToken,
					SSHKeyPath:    *gitSSHKey,
					SSHPassphrase: *gitPassphrase,
					MasterKey:     *secretKey,
					MasterKeyFile: *secretKeyFile,
				},
			})
			if err != nil {
				fmt.Fprintf(os.Stderr, "warning: git commit failed: %v\n", err)
			} else {
				res.ArtifactURL = fmt.Sprintf("git:%s@%s", *gitRepo, commitHash)
			}
		}
		if isTempGitSnapshot {
			_ = os.Remove(targetDest)
		}
	}

	switch outFmt {
	case "json":
		printJSON(res)
	case "yaml":
		printYAML(res)
	default:
		fmt.Printf("Backup completed successfully.\n")
		fmt.Printf("  Folders Scanned : %d\n", res.FolderCount)
		fmt.Printf("  Payload Bytes   : %d\n", res.PayloadBytes)
		fmt.Printf("  SHA-256 Hash    : %s\n", res.SHA256Hash)
		fmt.Printf("  Duration        : %v\n", res.Duration.Round(time.Millisecond))
		if res.ArtifactURL != "" {
			fmt.Printf("  Artifact URL    : %s\n", res.ArtifactURL)
		}
	}

	osExit(core.ExitSuccess)
}

// runRestore parses flags, parses base substitutions and identity mappings,
// reconstructs directories depth-by-depth, executes mirror evacuation if requested,
// and freezes bottom-up directory timestamps.
func runRestore(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("restore", flag.ContinueOnError)

	treeFile := fs.String("tree-file", "", "Source snapshot archive or cloud URL")
	baseFolder := fs.String("base-folder", "", "Required: absolute destination directory root")
	baseSubstitute := fs.String("base-substitute", "", "Base path rewrite '<old_abs>,<new_abs>'")
	idMapPath := fs.String("id-map", "", "Path to identity mapping JSON configuration")
	syncType := fs.String("type", "incremental", "Synchronization mode: incremental, mirror")
	archiveExtra := fs.String("archive-extra-folder", "", "Mirror mode: destination for evacuated .tar.zst archive")
	threads := fs.Int("threads", 0, "Concurrent restoration threads (1..32, default: min(NumCPU*2, 32))")
	maxIOPS := fs.Int("max-iops", 0, "Token-bucket IOPS limit (0 for unlimited)")
	maxMemoryMB := fs.Int("max-memory-mb", 0, "Soft heap memory limit in MB (0 for unlimited)")
	applyPerms := fs.Bool("apply-perms", true, "Apply permissions, owners, modes, and ACLs/SDDL")
	log1 := fs.String("log", "", "Path to machine-readable NDJSON audit log")
	log2 := fs.String("log-file", "", "Alias for --log")
	outputMode := fs.String("output", "table", "Output format: table, json, yaml")
	jsonOutput := fs.Bool("json", false, "Alias for --output=json")
	entity := fs.String("entity", "", "Selective restore: limits reconstitution to specified tenant entities (comma-separated)")
	includeStr := fs.String("include", "", "Comma-separated glob include patterns")
	excludeStr := fs.String("exclude", "", "Comma-separated glob exclude patterns")
	progress := fs.Bool("progress", true, "Dynamic terminal throughput and telemetry display")
	dryRun := fs.Bool("dry-run", false, "Simulate restoration without modifying disk")

	gitRepo := fs.String("git-repo", "", "Pull snapshot from Git repository")
	gitRef := fs.String("git-ref", "HEAD", "Git branch, tag, or SHA")
	gitSSHKey := fs.String("git-ssh-key", "", "Path to private SSH key for remote Git auth")
	gitToken := fs.String("git-token", "", "Personal access token for remote Git auth (supports secretprotector)")
	gitPassphrase := fs.String("git-passphrase", "", "Passphrase for private SSH key (supports secretprotector)")
	gitUser := fs.String("git-username", "", "Username for Git authentication")
	secretKey := fs.String("secret-key", "", "SecretProtector AES-256-GCM master key (hex or raw)")
	secretKeyFile := fs.String("secret-key-file", "", "Path to file containing SecretProtector master key")

	if err := fs.Parse(args); err != nil {
		osExit(core.ExitUsageError)
	}

	sourceDest := *treeFile
	if sourceDest == "" && *gitRepo != "" {
		sourceDest = "tree.ndjson.zst"
	}

	if sourceDest == "" || *baseFolder == "" {
		fmt.Fprintln(os.Stderr, "Error: both --tree-file (or --git-repo) and --base-folder are required.")
		fs.Usage()
		osExit(core.ExitUsageError)
	}

	applyMemoryLimit(*maxMemoryMB)

	logPath := resolveLogPath(*log1, *log2)
	outFmt := resolveOutputMode(*outputMode, *jsonOutput)

	var entities, includes, excludes []string
	if *entity != "" {
		entities = strings.Split(*entity, ",")
	}
	if *includeStr != "" {
		includes = strings.Split(*includeStr, ",")
	}
	if *excludeStr != "" {
		excludes = strings.Split(*excludeStr, ",")
	}

	var idMap *model.IdentityMap
	if *idMapPath != "" {
		var err error
		idMap, err = model.LoadIdentityMapFromFile(*idMapPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to load identity map: %v\n", err)
			osExit(core.ExitFatalError)
		}
	}

	var streamReader io.Reader
	if *gitRepo != "" {
		data, err := storage.ReadSnapshotFromGit(ctx, *gitRepo, *gitRef, *gitRef, sourceDest, storage.GitAuthOptions{
			Username:      *gitUser,
			Password:      *gitToken,
			SSHKeyPath:    *gitSSHKey,
			SSHPassphrase: *gitPassphrase,
			MasterKey:     *secretKey,
			MasterKeyFile: *secretKeyFile,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to read snapshot from git repo: %v\n", err)
			osExit(core.ExitAuthFailure)
		}
		streamReader = strings.NewReader(string(data))
	}

	if *dryRun {
		fmt.Printf("Dry-Run: Simulation completed. Would restore snapshot %s into %s (mode=%s)\n",
			sourceDest, *baseFolder, *syncType)
		osExit(core.ExitSuccess)
	}

	var onProgress func(stats dtreesync.RestoreProgress)
	if *progress && outFmt == "table" {
		onProgress = func(stats dtreesync.RestoreProgress) {
			fmt.Fprintf(os.Stderr, "\rRestoring: %d dirs created, %d perms applied...", stats.CreatedDirs, stats.AppliedPerms)
		}
	}

	cfg := dtreesync.RestoreConfig{
		SourceURL:          sourceDest,
		Reader:             streamReader,
		TargetFolder:       *baseFolder,
		BaseSubstitute:     *baseSubstitute,
		IdentityMap:        idMap,
		Entities:           entities,
		Include:            includes,
		Exclude:            excludes,
		Type:               *syncType,
		ArchiveExtraFolder: *archiveExtra,
		Workers:            clampWorkers(*threads),
		MaxIOPS:            *maxIOPS,
		MaxMemoryMB:        *maxMemoryMB,
		ApplyPerms:         *applyPerms,
		LogFile:            logPath,
		OnProgress:         onProgress,
		SecretKey:          *secretKey,
		SecretKeyFile:      *secretKeyFile,
	}

	res, err := dtreesync.Restore(ctx, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "restore failed: %v\n", err)
		osExit(core.ExitFatalError)
	}

	switch outFmt {
	case "json":
		printJSON(res)
	case "yaml":
		printYAML(res)
	default:
		fmt.Printf("Restoration completed successfully.\n")
		fmt.Printf("  Folders Created : %d\n", res.CreatedFolders)
		fmt.Printf("  Perms Applied   : %d\n", res.AppliedPerms)
		fmt.Printf("  Warnings        : %d\n", len(res.Warnings))
		if res.EvacuatedArchive != "" {
			fmt.Printf("  Evacuated Tar   : %s\n", res.EvacuatedArchive)
		}
		fmt.Printf("  Duration        : %v\n", res.Duration.Round(time.Millisecond))
	}

	if len(res.Warnings) > 0 {
		osExit(core.ExitPartialWarning)
	}
	osExit(core.ExitSuccess)
}

// runDiff compares a live directory tree against a baseline snapshot,
// detects missing/untracked directories and permission drift, and reports structured discrepancies.
func runDiff(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)

	baseFolder := fs.String("base-folder", "", "Required: absolute live directory root to inspect")
	treeFile := fs.String("tree-file", "", "Required: baseline snapshot archive or cloud URL")
	idMapPath := fs.String("id-map", "", "Path to identity mapping JSON configuration")
	threads := fs.Int("threads", 0, "Concurrent verification threads (1..32)")
	maxIOPS := fs.Int("max-iops", 0, "Token-bucket IOPS limit")
	maxMemoryMB := fs.Int("max-memory-mb", 0, "Soft heap memory limit in MB")
	ignoreBTime := fs.Bool("ignore-btime", false, "Ignore birth time differences")
	ignoreOwner := fs.Bool("ignore-owner", false, "Ignore UID/SID ownership discrepancies")
	log1 := fs.String("log", "", "Path to machine-readable NDJSON audit log")
	log2 := fs.String("log-file", "", "Alias for --log")
	outputMode := fs.String("output", "table", "Output format: table, json, yaml")
	jsonOutput := fs.Bool("json", false, "Alias for --output=json")
	entity := fs.String("entity", "", "Selective diff: scopes verification to specific tenant entities (comma-separated)")
	includeStr := fs.String("include", "", "Comma-separated glob include patterns")
	excludeStr := fs.String("exclude", "", "Comma-separated glob exclude patterns")

	gitRepo := fs.String("git-repo", "", "Pull baseline snapshot directly from Git repo")
	gitRef := fs.String("git-ref", "HEAD", "Git branch, tag, or commit SHA")
	gitSSHKey := fs.String("git-ssh-key", "", "Path to private SSH key for remote Git auth")
	gitToken := fs.String("git-token", "", "Personal access token for remote Git auth (supports secretprotector)")
	gitPassphrase := fs.String("git-passphrase", "", "Passphrase for private SSH key (supports secretprotector)")
	gitUser := fs.String("git-username", "", "Username for Git authentication")
	secretKey := fs.String("secret-key", "", "SecretProtector AES-256-GCM master key (hex or raw)")
	secretKeyFile := fs.String("secret-key-file", "", "Path to file containing SecretProtector master key")

	if err := fs.Parse(args); err != nil {
		osExit(core.ExitUsageError)
	}

	snapURL := *treeFile
	if snapURL == "" && *gitRepo != "" {
		snapURL = "tree.ndjson.zst"
	}

	if *baseFolder == "" || snapURL == "" {
		fmt.Fprintln(os.Stderr, "Error: both --base-folder and --tree-file (or --git-repo) are required.")
		fs.Usage()
		osExit(core.ExitUsageError)
	}

	applyMemoryLimit(*maxMemoryMB)
	logPath := resolveLogPath(*log1, *log2)
	outFmt := resolveOutputMode(*outputMode, *jsonOutput)

	var entities, includes, excludes []string
	if *entity != "" {
		entities = strings.Split(*entity, ",")
	}
	if *includeStr != "" {
		includes = strings.Split(*includeStr, ",")
	}
	if *excludeStr != "" {
		excludes = strings.Split(*excludeStr, ",")
	}

	var idMap *model.IdentityMap
	if *idMapPath != "" {
		var err error
		idMap, err = model.LoadIdentityMapFromFile(*idMapPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to load identity map: %v\n", err)
			osExit(core.ExitFatalError)
		}
	}

	var streamReader io.Reader
	if *gitRepo != "" {
		data, err := storage.ReadSnapshotFromGit(ctx, *gitRepo, *gitRef, *gitRef, snapURL, storage.GitAuthOptions{
			Username:      *gitUser,
			Password:      *gitToken,
			SSHKeyPath:    *gitSSHKey,
			SSHPassphrase: *gitPassphrase,
			MasterKey:     *secretKey,
			MasterKeyFile: *secretKeyFile,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to read snapshot from git repo: %v\n", err)
			osExit(core.ExitAuthFailure)
		}
		streamReader = strings.NewReader(string(data))
	}

	cfg := dtreesync.DiffConfig{
		LiveFolder:     *baseFolder,
		SnapshotURL:    snapURL,
		SnapshotReader: streamReader,
		IdentityMap:    idMap,
		Entities:       entities,
		Include:        includes,
		Exclude:        excludes,
		Workers:        clampWorkers(*threads),
		MaxIOPS:        *maxIOPS,
		MaxMemoryMB:    *maxMemoryMB,
		IgnoreBTime:    *ignoreBTime,
		IgnoreOwner:    *ignoreOwner,
		LogFile:        logPath,
		SecretKey:      *secretKey,
		SecretKeyFile:  *secretKeyFile,
	}

	res, err := dtreesync.Diff(ctx, cfg)
	if err != nil && !errors.Is(err, model.ErrDriftDetected) {
		fmt.Fprintf(os.Stderr, "diff execution failed: %v\n", err)
		osExit(core.ExitFatalError)
	}

	switch outFmt {
	case "json":
		printJSON(res)
	case "yaml":
		printYAML(res)
	default:
		fmt.Printf("Drift Evaluation: %s\n", strings.ToUpper(res.Status))
		fmt.Printf("  Expected Dirs : %d\n", res.Summary.ExpectedDirectories)
		fmt.Printf("  Scanned Dirs  : %d\n", res.Summary.ScannedDirectories)
		fmt.Printf("  Missing Dirs  : %d\n", res.Summary.MissingCount)
		fmt.Printf("  Extra Items   : %d\n", res.Summary.ExtraCount)
		fmt.Printf("  Perm Drifts   : %d\n", res.Summary.DriftCount)
		fmt.Printf("  Total Drift   : %d\n", res.TotalDrift)
		fmt.Printf("  Duration      : %v\n", res.Duration.Round(time.Millisecond))

		if len(res.DriftItems) > 0 {
			fmt.Println("\nDiscrepancies:")
			for _, item := range res.DriftItems {
				fmt.Printf("  [%s] %s (%s: expected %q, actual %q)\n",
					item.Type, item.Path, item.Field, item.Expected, item.Actual)
			}
		}
	}

	if res.TotalDrift > 0 {
		osExit(core.ExitDriftDetected)
	}
	osExit(core.ExitSuccess)
}

// runVerify performs zero-disk-write cryptographic integrity verification,
// validating SHA-256 payload checksums, Zstandard framing, and record schema syntax.
func runVerify(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)

	treeFile := fs.String("tree-file", "", "Snapshot archive or cloud URL to verify")
	threads := fs.Int("threads", 0, "Concurrent verification threads (1..32)")
	maxMemoryMB := fs.Int("max-memory-mb", 0, "Soft heap memory limit in MB")
	log1 := fs.String("log", "", "Path to machine-readable NDJSON audit log")
	log2 := fs.String("log-file", "", "Alias for --log")
	outputMode := fs.String("output", "table", "Output format: table, json, yaml")
	jsonOutput := fs.Bool("json", false, "Alias for --output=json")

	gitRepo := fs.String("git-repo", "", "Pull snapshot from Git repo")
	gitRef := fs.String("git-ref", "HEAD", "Git branch, tag, or SHA")
	gitSSHKey := fs.String("git-ssh-key", "", "Path to private SSH key for remote Git auth")
	gitToken := fs.String("git-token", "", "Personal access token for remote Git auth (supports secretprotector)")
	gitPassphrase := fs.String("git-passphrase", "", "Passphrase for private SSH key (supports secretprotector)")
	gitUser := fs.String("git-username", "", "Username for Git authentication")
	secretKey := fs.String("secret-key", "", "SecretProtector AES-256-GCM master key (hex or raw)")
	secretKeyFile := fs.String("secret-key-file", "", "Path to file containing SecretProtector master key")

	if err := fs.Parse(args); err != nil {
		osExit(core.ExitUsageError)
	}

	sourceURL := *treeFile
	if sourceURL == "" && *gitRepo != "" {
		sourceURL = "tree.ndjson.zst"
	}

	if sourceURL == "" {
		fmt.Fprintln(os.Stderr, "Error: --tree-file (or --git-repo) is required.")
		fs.Usage()
		osExit(core.ExitUsageError)
	}

	applyMemoryLimit(*maxMemoryMB)
	logPath := resolveLogPath(*log1, *log2)
	outFmt := resolveOutputMode(*outputMode, *jsonOutput)

	var streamReader io.Reader
	if *gitRepo != "" {
		data, err := storage.ReadSnapshotFromGit(ctx, *gitRepo, *gitRef, *gitRef, sourceURL, storage.GitAuthOptions{
			Username:      *gitUser,
			Password:      *gitToken,
			SSHKeyPath:    *gitSSHKey,
			SSHPassphrase: *gitPassphrase,
			MasterKey:     *secretKey,
			MasterKeyFile: *secretKeyFile,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to read snapshot from git repo: %v\n", err)
			osExit(core.ExitAuthFailure)
		}
		streamReader = strings.NewReader(string(data))
	}

	cfg := dtreesync.VerifyConfig{
		SourceURL:     sourceURL,
		Reader:        streamReader,
		Workers:       clampWorkers(*threads),
		MaxMemoryMB:   *maxMemoryMB,
		LogFile:       logPath,
		SecretKey:     *secretKey,
		SecretKeyFile: *secretKeyFile,
	}

	res, err := dtreesync.Verify(ctx, cfg)
	if err != nil && !errors.Is(err, model.ErrVerificationFailed) {
		fmt.Fprintf(os.Stderr, "verify execution failed: %v\n", err)
		osExit(core.ExitFatalError)
	}

	switch outFmt {
	case "json":
		printJSON(res)
	case "yaml":
		printYAML(res)
	default:
		validStr := "PASSED"
		if !res.ChecksumValid || !res.FramesValid || !res.SyntaxValid {
			validStr = "FAILED"
		}
		fmt.Printf("Verification Result: %s\n", validStr)
		fmt.Printf("  Format        : %s (compressed=%v)\n", res.Format, res.Compression)
		fmt.Printf("  Record Count  : %d\n", res.RecordCount)
		fmt.Printf("  Payload SHA256: %s\n", res.PayloadSHA256)
		fmt.Printf("  Frames Valid  : %v\n", res.FramesValid)
		fmt.Printf("  Syntax Valid  : %v\n", res.SyntaxValid)
		fmt.Printf("  Checksum Valid: %v\n", res.ChecksumValid)
		fmt.Printf("  Duration      : %v\n", res.Duration.Round(time.Millisecond))

		if len(res.Errors) > 0 {
			fmt.Println("\nErrors:")
			for _, e := range res.Errors {
				fmt.Printf("  - %s\n", e)
			}
		}
	}

	if !res.ChecksumValid || !res.FramesValid || !res.SyntaxValid {
		osExit(core.ExitVerificationFailed)
	}
	osExit(core.ExitSuccess)
}

// runStatus fast-peeks metadata from a single snapshot or scans a repository directory
// to render an audit summary table of all stored snapshots.
func runStatus(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)

	treeFile := fs.String("tree-file", "", "Fast peeks metadata for a single snapshot file")
	treePath := fs.String("tree-path", "", "Scans a folder of snapshots and renders a tabular summary")
	maxMemoryMB := fs.Int("max-memory-mb", 0, "Soft heap memory limit in MB")
	log1 := fs.String("log", "", "Path to machine-readable NDJSON audit log")
	log2 := fs.String("log-file", "", "Alias for --log")
	outputMode := fs.String("output", "table", "Output format: table, json, yaml")
	jsonOutput := fs.Bool("json", false, "Alias for --output=json")

	if err := fs.Parse(args); err != nil {
		osExit(core.ExitUsageError)
	}

	if *treeFile == "" && *treePath == "" {
		fmt.Fprintln(os.Stderr, "Error: either --tree-file or --tree-path is required.")
		fs.Usage()
		osExit(core.ExitUsageError)
	}

	applyMemoryLimit(*maxMemoryMB)
	logPath := resolveLogPath(*log1, *log2)
	var al *model.AuditLogger
	if logPath != "" {
		logger, err := model.NewAuditLoggerFromFile(logPath, 10000)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to initialize audit log: %v\n", err)
			osExit(core.ExitFatalError)
		}
		defer func() { _ = logger.Close() }()
		al = logger
	}
	outFmt := resolveOutputMode(*outputMode, *jsonOutput)

	// Single snapshot file inspection
	if *treeFile != "" {
		var r io.Reader
		var cleanPath string
		if storage.IsCloudURL(*treeFile) {
			cr, err := storage.NewCloudReaderWithKey(ctx, *treeFile, nil)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to open cloud snapshot: %v\n", err)
				osExit(core.ExitFatalError)
			}
			defer func() { _ = cr.Close() }()
			r = cr
			cleanPath = *treeFile
		} else {
			var err error
			cleanPath, err = model.ValidateAndCleanPath(*treeFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "invalid tree-file: %v\n", err)
				osExit(core.ExitFatalError)
			}

			// #nosec G304 -- Snapshot file path is validated and cleaned via ValidateAndCleanPath.
			f, err := os.Open(cleanPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to open snapshot file: %v\n", err)
				osExit(core.ExitFatalError)
			}
			defer func() { _ = f.Close() }()
			r = f
		}

		hdr, err := dtreesync.InspectHeader(ctx, r)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to inspect header: %v\n", err)
			osExit(core.ExitFatalError)
		}

		if al != nil {
			al.LogInfo("status", "snapshot_inspected", cleanPath, map[string]any{
				"format":      hdr.TreeFormat,
				"folders":     hdr.FolderCount,
				"sha256":      hdr.PayloadSHA256,
				"compression": hdr.Compression,
			})
		}

		switch outFmt {
		case "json":
			printJSON(hdr)
		case "yaml":
			printYAML(hdr)
		default:
			fmt.Printf("Snapshot Header (Line 1 Metadata):\n")
			fmt.Printf("  Version       : %s\n", hdr.Version)
			fmt.Printf("  Base Folder   : %s\n", hdr.BaseFolder)
			fmt.Printf("  Tree Format   : %s (compressed=%v)\n", hdr.TreeFormat, hdr.Compression)
			fmt.Printf("  Folder Count  : %d\n", hdr.FolderCount)
			fmt.Printf("  Host OS       : %s\n", hdr.HostOS)
			fmt.Printf("  Hostname      : %s\n", hdr.Hostname)
			fmt.Printf("  Created At    : %s\n", hdr.CreatedAt.Format(time.RFC3339))
			fmt.Printf("  Payload SHA256: %s\n", hdr.PayloadSHA256)
		}
		if al != nil {
			_ = al.Close()
		}
		return
	}

	// Repository directory scan (--tree-path)
	cleanDir, err := model.ValidateAndCleanPath(*treePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid tree-path: %v\n", err)
		osExit(core.ExitFatalError)
	}

	entries, err := os.ReadDir(cleanDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read tree-path directory: %v\n", err)
		osExit(core.ExitFatalError)
	}

	var headers []*model.BackupMetadata
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".zst") && !strings.HasSuffix(name, ".tsv") &&
			!strings.HasSuffix(name, ".ndjson") && !strings.HasSuffix(name, ".jsonl") &&
			!strings.HasSuffix(name, ".sqlite") && !strings.HasSuffix(name, ".db") {
			continue
		}

		fullFile := filepath.Join(cleanDir, name)
		cleanFull := filepath.Clean(fullFile)
		// #nosec G304 -- Directory entry full path is constructed from validated clean directory and entry name.
		f, err := os.Open(cleanFull)
		if err != nil {
			continue
		}
		hdr, err := dtreesync.InspectHeader(ctx, f)
		_ = f.Close()
		if err == nil {
			hdr.TreeFile = name
			headers = append(headers, hdr)
		}
	}

	if al != nil {
		al.LogInfo("status", "repo_scanned", cleanDir, map[string]any{
			"snapshots": len(headers),
		})
	}

	switch outFmt {
	case "json":
		printJSON(headers)
	case "yaml":
		printYAML(headers)
	default:
		fmt.Printf("Repository Status for %s (%d snapshots found):\n\n", cleanDir, len(headers))
		fmt.Printf("%-35s %-8s %-6s %-10s %-22s %-16s\n", "FILENAME", "FORMAT", "ZSTD", "FOLDERS", "CREATED (UTC)", "SHA256")
		fmt.Println(strings.Repeat("-", 105))
		for _, h := range headers {
			shaShort := h.PayloadSHA256
			if len(shaShort) > 16 {
				shaShort = shaShort[:16] + "..."
			}
			fmt.Printf("%-35s %-8s %-6v %-10d %-22s %-16s\n",
				h.TreeFile, h.TreeFormat, h.Compression, h.FolderCount,
				h.CreatedAt.Format("2006-01-02 15:04:05"), shaShort)
		}
	}

	if al != nil {
		_ = al.Close()
	}
}
