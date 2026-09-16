// Package main provides unit tests for the testgen CLI binary.
//
// Objectives:
//   - Validate argument parsing, flags, aliases (--dir, --branching), and version output.
//   - Ensure relative path rejections and synthetic generation driver executions.
//
// Test Strategy:
//   - In-Process Invocation: Intercepts osExit to capture exit codes without killing test process.
//   - Parameter Variations: Tests missing base-folder (exit 1), relative path (exit 1), version (exit 0),
//     and synthetic topology creation in t.TempDir() (exit 0).
package main

import (
	"flag"
	"os"
	"path/filepath"
	"testing"
)

type exitCodePanic int

func runTestgenInProcess(args ...string) (exitCode int) {
	origExit := osExit
	defer func() {
		osExit = origExit
	}()
	osExit = func(code int) {
		panic(exitCodePanic(code))
	}

	defer func() {
		if r := recover(); r != nil {
			if code, ok := r.(exitCodePanic); ok {
				exitCode = int(code)
			} else {
				panic(r)
			}
		}
	}()

	origArgs := os.Args
	defer func() { os.Args = origArgs }()
	os.Args = append([]string{"testgen"}, args...)

	// Reset default flagset for repeated parsing in-process
	flag.CommandLine = flag.NewFlagSet("testgen", flag.ContinueOnError)

	main()
	return 0
}

func TestTestgen_CLI(t *testing.T) {
	// 1. Version flag
	if code := runTestgenInProcess("--version"); code != 0 {
		t.Fatalf("expected exit 0 for --version, got %d", code)
	}
	if code := runTestgenInProcess("-v"); code != 0 {
		t.Fatalf("expected exit 0 for -v, got %d", code)
	}

	// 2. Missing base-folder -> exit 1
	if code := runTestgenInProcess(); code != 1 {
		t.Fatalf("expected exit 1 for missing base-folder, got %d", code)
	}

	// 3. Relative path -> exit 1
	if code := runTestgenInProcess("--base-folder", "relative/path"); code != 1 {
		t.Fatalf("expected exit 1 for relative path, got %d", code)
	}

	// 4. Successful generation in t.TempDir()
	outDir := filepath.Join(t.TempDir(), "gen_out")
	if code := runTestgenInProcess(
		"--base-folder", outDir,
		"--depth", "2",
		"--fanout", "2",
		"--dirs-total", "4",
		"--files", "1",
		"--with-acls=false",
	); code != 0 {
		t.Fatalf("expected exit 0 for valid generation, got %d", code)
	}

	// 5. Aliases (--dir, --branching) in t.TempDir()
	outDir2 := filepath.Join(t.TempDir(), "gen_out2")
	if code := runTestgenInProcess(
		"--dir", outDir2,
		"--depth", "2",
		"--branching", "2",
		"--dirs-total", "4",
		"--files", "1",
		"--with-acls=false",
	); code != 0 {
		t.Fatalf("expected exit 0 for alias generation, got %d", code)
	}
}
