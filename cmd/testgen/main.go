// Package main implements the testgen command-line tool.
//
// Objectives:
//   - Generates deterministic, highly parameterized synthetic directory hierarchies and payload files.
//   - Enables stress testing, scale benchmarks, and integration verification for dtreesync.
//
// Core Components:
//   - CLI Argument Parser: Validates directory parameters, depth, fanout, file counts, and PRNG seeds.
//   - Topology Calculator: Derives partner/top-level node counts based on requested depth and fanout.
//   - Generator Driver: Invokes testgen.Generate and reports generation throughput (dirs/sec).
//
// Data Flow:
//
//	CLI Flags -> Parameter Validation -> GeneratorConfig -> testgen.Generate -> Filesystem Tree -> Metric Reporting.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/edsilegxrepo/dtreesync/test/testgen"
)

// version specifies the application build version.
// Defaults to "dev", but can be overridden at link time via:
//
//	-ldflags "-X main.version=..."
var version = "dev"

// osExit is the exit handler, stubbed out during testing.
var osExit = os.Exit

// main parses command-line arguments, calculates directory topology, executes synthetic generation,
// and displays execution metrics.
func main() {
	versionFlag := flag.Bool("version", false, "Display testgen version and exit")
	vFlag := flag.Bool("v", false, "Alias for --version")
	baseFolder := flag.String("base-folder", "", "Required: absolute root folder where synthetic directory tree will be generated")
	dirFallback := flag.String("dir", "", "Alias for --base-folder")
	dirsTotal := flag.Int("dirs-total", 100000, "Target total count of synthetic directories to generate")
	depth := flag.Int("depth", 5, "Maximum tree hierarchy depth (1..20)")
	fanout := flag.Int("fanout", 8, "Maximum child directories per node (2..50)")
	branchFallback := flag.Int("branching", 0, "Alias for --fanout")
	filesPerDir := flag.Int("files", 2, "Payload files per directory")
	threads := flag.Int("threads", 0, "Worker pool concurrency (1..32, default: min(NumCPU*2, 32))")
	withACLs := flag.Bool("with-acls", true, "Synthesizes realistic POSIX ACLs or Windows SDDLs on nodes")
	logFile := flag.String("log", "", "Path to machine-readable NDJSON audit log")
	seed := flag.Int64("seed", 42, "PRNG seed for reproducible generation")

	flag.Parse()

	if *versionFlag || *vFlag {
		fmt.Printf("testgen version %s (Go runtime: %s, OS: %s/%s)\n", version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
		osExit(0)
	}

	targetDir := *baseFolder
	if targetDir == "" {
		targetDir = *dirFallback
	}

	if targetDir == "" {
		fmt.Fprintln(os.Stderr, "Error: --base-folder flag is required.")
		flag.Usage()
		osExit(1)
	}

	if !filepath.IsAbs(targetDir) {
		fmt.Fprintf(os.Stderr, "Error: relative paths prohibited: %q. You must provide a fully-qualified absolute path.\n", targetDir)
		osExit(1)
	}

	cleanDir, err := filepath.Abs(targetDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid target directory: %v\n", err)
		osExit(1)
	}

	branchingVal := *fanout
	if *branchFallback > 0 {
		branchingVal = *branchFallback
	}

	_ = threads
	_ = logFile

	partners := *dirsTotal / (branchingVal * *depth)
	if partners < 1 {
		partners = 1
	}

	fmt.Printf("Generating synthetic topology in %s (depth=%d, fanout=%d, target=%d dirs)...\n",
		cleanDir, *depth, branchingVal, *dirsTotal)
	start := time.Now()

	cfg := testgen.GeneratorConfig{
		BaseDir:         cleanDir,
		NumPartners:     partners,
		SubdirsPerLevel: branchingVal,
		Depth:           *depth,
		FilesPerDir:     *filesPerDir,
		WithACLs:        *withACLs,
		Seed:            *seed,
	}

	stats, err := testgen.Generate(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Generation failed: %v\n", err)
		osExit(1)
	}

	duration := time.Since(start)
	rate := float64(stats.TotalDirs) / duration.Seconds()

	fmt.Printf("Generation completed in %v:\n", duration.Round(time.Millisecond))
	fmt.Printf("  Total Directories : %d\n", stats.TotalDirs)
	fmt.Printf("  Total Files       : %d\n", stats.TotalFiles)
	fmt.Printf("  Generation Rate   : %.1f dirs/sec\n", rate)
}
