// Package main provides unit and integration tests for the dtreesync CLI binary.
//
// Objectives:
//   - Verify CLI flag sanitization, worker clamping, and output mode resolution.
//   - Validate strict diagnostic exit code compliance (ExitSuccess 0, ExitDriftDetected 3,
//     ExitVerificationFailed 4, ExitUsageError 6).
//   - Ensure end-to-end command dispatch across backup, verify, diff, and status subcommands.
//
// Test Strategy:
//   - Helper Functions: TestHelperFunctions verifies clampWorkers bounds, resolveLogPath aliases, and resolveOutputMode.
//   - Subcommand Invocation: TestMain compiles the dtreesync binary once, enabling fast, isolated subprocess tests.
//   - Exit Code Assertions: TestCLI_ExitCodes exercises valid flags (exit 0), illegal flags/no args (exit 6),
//     corrupted verification targets (exit 4), and drift-detected diffs (exit 3).
//
// Data Flow:
//
//	CLI Subprocess Invocations -> Flag Parsing -> Core Operations -> Exit Code & Stdout/Stderr Assertions.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/edsilegxrepo/dtreesync/internal/core"
)

var testBinaryPath string

func TestMain(m *testing.M) {
	tempDir, err := os.MkdirTemp("", "dtreesync_cli_test_*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create temp bin dir: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	bin := filepath.Join(tempDir, "dtreesync_test_bin")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}

	buildCmd := exec.Command("go", "build", "-o", bin, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to compile test binary: %v, output: %s\n", err, string(out))
		os.Exit(1)
	}

	testBinaryPath = bin
	os.Exit(m.Run())
}

func TestHelperFunctions(t *testing.T) {
	// 1. clampWorkers
	if w := clampWorkers(0); w < 1 || w > 32 {
		t.Errorf("clampWorkers(0) out of bounds: %d", w)
	}
	if w := clampWorkers(-5); w < 1 || w > 32 {
		t.Errorf("clampWorkers(-5) expected valid range 1..32, got %d", w)
	}
	if w := clampWorkers(100); w != 32 {
		t.Errorf("clampWorkers(100) expected 32, got %d", w)
	}
	if w := clampWorkers(16); w != 16 {
		t.Errorf("clampWorkers(16) expected 16, got %d", w)
	}

	// 2. resolveLogPath
	if p := resolveLogPath("primary.log", "secondary.log"); p != "primary.log" {
		t.Errorf("expected primary.log, got %s", p)
	}
	if p := resolveLogPath("", "secondary.log"); p != "secondary.log" {
		t.Errorf("expected secondary.log, got %s", p)
	}

	// 3. resolveOutputMode
	if m := resolveOutputMode("", true); m != "json" {
		t.Errorf("expected json from flag, got %s", m)
	}
	if m := resolveOutputMode("yaml", false); m != "yaml" {
		t.Errorf("expected yaml, got %s", m)
	}
	if m := resolveOutputMode("", false); m != "table" {
		t.Errorf("expected table default, got %s", m)
	}
}

func runCLI(t *testing.T, args ...string) (string, int) {
	cmd := exec.Command(testBinaryPath, args...)
	out, err := cmd.CombinedOutput()
	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			t.Fatalf("unexpected error running CLI: %v", err)
		}
	}
	return string(out), exitCode
}

func TestCLI_VersionAndHelp(t *testing.T) {
	// 1. Version default subcommand
	out, code := runCLI(t, "version")
	if code != core.ExitSuccess {
		t.Errorf("expected exit 0 for version, got %d", code)
	}
	if !strings.Contains(out, "dtreesync version dev") {
		t.Errorf("version output missing expected string: %q", out)
	}

	// 2. Version --version flag
	out, code = runCLI(t, "--version")
	if code != core.ExitSuccess {
		t.Errorf("expected exit 0 for --version, got %d", code)
	}
	if !strings.Contains(out, "dtreesync version dev") {
		t.Errorf("--version output missing expected string: %q", out)
	}

	// 3. Version -v flag
	out, code = runCLI(t, "-v")
	if code != core.ExitSuccess {
		t.Errorf("expected exit 0 for -v, got %d", code)
	}
	if !strings.Contains(out, "dtreesync version dev") {
		t.Errorf("-v output missing expected string: %q", out)
	}

	// 4. Version JSON output
	out, code = runCLI(t, "version", "--json")
	if code != core.ExitSuccess {
		t.Errorf("expected exit 0 for version --json, got %d", code)
	}
	var versionInfo struct {
		Version   string `json:"version"`
		GoVersion string `json:"go_version"`
		OS        string `json:"os"`
		Arch      string `json:"arch"`
	}
	if err := json.Unmarshal([]byte(out), &versionInfo); err != nil {
		t.Fatalf("failed to parse version JSON: %v, raw: %s", err, out)
	}
	if versionInfo.Version != "dev" {
		t.Errorf("expected version 'dev' in JSON, got %q", versionInfo.Version)
	}
	if versionInfo.OS != runtime.GOOS || versionInfo.Arch != runtime.GOARCH {
		t.Errorf("unexpected OS/Arch in version JSON: %s/%s", versionInfo.OS, versionInfo.Arch)
	}

	// 5. Help
	out, code = runCLI(t, "help")
	if code != core.ExitSuccess {
		t.Errorf("expected exit 0 for help, got %d", code)
	}
	if !strings.Contains(out, "Usage:") {
		t.Errorf("help output missing Usage: %q", out)
	}
}

func TestCLI_VersionLdflagsOverride(t *testing.T) {
	tempDir := t.TempDir()
	customBin := filepath.Join(tempDir, "dtreesync_custom")
	if runtime.GOOS == "windows" {
		customBin += ".exe"
	}

	// Override via -X main.version=xxxx
	customVersion := "v3.2.1-enterprise"
	ldflags := fmt.Sprintf("-X main.version=%s", customVersion)
	cmd := exec.Command("go", "build", "-ldflags", ldflags, "-o", customBin, ".")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build binary with ldflags: %v, out: %s", err, string(out))
	}

	// Verify via subcommand
	outBytes, err := exec.Command(customBin, "version").CombinedOutput()
	if err != nil {
		t.Fatalf("custom version command failed: %v", err)
	}
	if !strings.Contains(string(outBytes), "dtreesync version "+customVersion) {
		t.Errorf("expected custom version %q in output, got: %s", customVersion, string(outBytes))
	}

	// Verify via flag
	outBytes, err = exec.Command(customBin, "--version").CombinedOutput()
	if err != nil {
		t.Fatalf("custom --version command failed: %v", err)
	}
	if !strings.Contains(string(outBytes), "dtreesync version "+customVersion) {
		t.Errorf("expected custom version %q in output, got: %s", customVersion, string(outBytes))
	}
}

func TestTestgen_VersionFlag(t *testing.T) {
	tempDir := t.TempDir()
	testgenBin := filepath.Join(tempDir, "testgen_bin")
	if runtime.GOOS == "windows" {
		testgenBin += ".exe"
	}

	// 1. Default version "dev"
	cmd := exec.Command("go", "build", "-o", testgenBin, "../testgen")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build testgen: %v, out: %s", err, string(out))
	}

	outBytes, err := exec.Command(testgenBin, "--version").CombinedOutput()
	if err != nil {
		t.Fatalf("testgen --version failed: %v", err)
	}
	if !strings.Contains(string(outBytes), "testgen version dev") {
		t.Errorf("expected 'testgen version dev', got: %s", string(outBytes))
	}

	// 2. Override via ldflags
	customVersion := "v1.5.0-tg"
	ldflags := fmt.Sprintf("-X main.version=%s", customVersion)
	cmdOverride := exec.Command("go", "build", "-ldflags", ldflags, "-o", testgenBin, "../testgen")
	if out, err := cmdOverride.CombinedOutput(); err != nil {
		t.Fatalf("failed to build testgen with ldflags: %v, out: %s", err, string(out))
	}

	outBytes, err = exec.Command(testgenBin, "-v").CombinedOutput()
	if err != nil {
		t.Fatalf("testgen -v failed: %v", err)
	}
	if !strings.Contains(string(outBytes), "testgen version "+customVersion) {
		t.Errorf("expected 'testgen version %s', got: %s", customVersion, string(outBytes))
	}
}

func TestCLI_NoArgs_UsageError(t *testing.T) {
	_, code := runCLI(t)
	if code != core.ExitUsageError {
		t.Errorf("expected ExitUsageError (%d), got %d", core.ExitUsageError, code)
	}
}

func TestCLI_Backup_Verify_Diff_Lifecycle(t *testing.T) {
	tempBase := t.TempDir()
	sourceDir := filepath.Join(tempBase, "source")
	_ = os.MkdirAll(filepath.Join(sourceDir, "partner_a", "inbound"), 0o755)

	snapshotFile := filepath.Join(tempBase, "snapshot.ndjson.zst")

	// 1. Run backup
	out, code := runCLI(t, "backup", "--base-folder", sourceDir, "--tree-file", snapshotFile, "--output=json")
	if code != core.ExitSuccess {
		t.Fatalf("backup failed with code %d: %s", code, out)
	}
	if _, err := os.Stat(snapshotFile); err != nil {
		t.Fatalf("snapshot file was not created: %v", err)
	}

	// 2. Run verify on clean snapshot
	out, code = runCLI(t, "verify", "--tree-file", snapshotFile, "--output=json")
	if code != core.ExitSuccess {
		t.Fatalf("verify failed on valid snapshot with code %d: %s", code, out)
	}

	// 3. Run diff on aligned directory
	out, code = runCLI(t, "diff", "--base-folder", sourceDir, "--tree-file", snapshotFile)
	if code != core.ExitSuccess {
		t.Fatalf("diff failed on aligned directory with code %d: %s", code, out)
	}

	// 4. Inject drift (add an untracked payload file) and assert ExitDriftDetected (exit 3)
	_ = os.WriteFile(filepath.Join(sourceDir, "partner_a", "inbound", "file.dat"), []byte("payload"), 0o644)
	out, code = runCLI(t, "diff", "--base-folder", sourceDir, "--tree-file", snapshotFile)
	if code != core.ExitDriftDetected {
		t.Fatalf("expected ExitDriftDetected (%d), got %d (output: %s)", core.ExitDriftDetected, code, out)
	}

	// 5. Corrupt snapshot file and assert ExitVerificationFailed (exit 4)
	corruptFile := filepath.Join(tempBase, "corrupt.ndjson.zst")
	_ = os.WriteFile(corruptFile, []byte("NOT_A_VALID_ZSTD_OR_NDJSON_STREAM"), 0o644)
	out, code = runCLI(t, "verify", "--tree-file", corruptFile)
	if code != core.ExitVerificationFailed {
		t.Fatalf("expected ExitVerificationFailed (%d), got %d (output: %s)", core.ExitVerificationFailed, code, out)
	}
}

func TestCLI_SecretProtectorFlags(t *testing.T) {
	tempBase := t.TempDir()
	sourceDir := filepath.Join(tempBase, "source_sec")
	_ = os.MkdirAll(filepath.Join(sourceDir, "tenant"), 0o755)

	snapshotFile := filepath.Join(tempBase, "snapshot_sec.ndjson.zst")
	keyHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	// 1. Backup with --secret-key, --git-token, and --git-username flags
	out, code := runCLI(t, "backup",
		"--base-folder", sourceDir,
		"--tree-file", snapshotFile,
		"--secret-key", keyHex,
		"--git-token", "mock_token_123",
		"--git-username", "testuser",
		"--output=json",
	)
	if code != core.ExitSuccess {
		t.Fatalf("backup with secret-key failed with code %d: %s", code, out)
	}

	// 2. Verify with --secret-key flag
	out, code = runCLI(t, "verify",
		"--tree-file", snapshotFile,
		"--secret-key", keyHex,
		"--output=json",
	)
	if code != core.ExitSuccess {
		t.Fatalf("verify with secret-key failed with code %d: %s", code, out)
	}

	// 3. Diff with --secret-key and --git-token flags
	out, code = runCLI(t, "diff",
		"--base-folder", sourceDir,
		"--tree-file", snapshotFile,
		"--secret-key", keyHex,
		"--git-token", "mock_token_123",
	)
	if code != core.ExitSuccess {
		t.Fatalf("diff with secret-key failed with code %d: %s", code, out)
	}

	// 4. Restore with --secret-key and --git-passphrase flags
	restoreDir := filepath.Join(tempBase, "restore_sec")
	out, code = runCLI(t, "restore",
		"--tree-file", snapshotFile,
		"--base-folder", restoreDir,
		"--secret-key", keyHex,
		"--git-passphrase", "mock_passphrase",
		"--output=json",
	)
	if code != core.ExitSuccess {
		t.Fatalf("restore with secret-key failed with code %d: %s", code, out)
	}
}

type exitCodePanic int

func runCLIInProcess(args ...string) (exitCode int) {
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
	os.Args = append([]string{"dtreesync"}, args...)

	main()
	return 0
}

func TestCLI_InProcessCoverage(t *testing.T) {
	tempBase := t.TempDir()
	srcDir := filepath.Join(tempBase, "inproc_src")
	_ = os.MkdirAll(filepath.Join(srcDir, "sub"), 0o755)

	snapFile := filepath.Join(tempBase, "inproc_snap.ndjson.zst")
	logFile := filepath.Join(tempBase, "inproc_audit.ndjson")
	restoreDir := filepath.Join(tempBase, "inproc_dst")

	// 1. No args -> ExitUsageError
	if code := runCLIInProcess(); code != core.ExitUsageError {
		t.Fatalf("expected ExitUsageError, got %d", code)
	}

	// 2. Help -> ExitSuccess
	if code := runCLIInProcess("help"); code != core.ExitSuccess {
		t.Fatalf("expected ExitSuccess for help, got %d", code)
	}

	// 3. Unknown subcommand -> ExitUsageError
	if code := runCLIInProcess("nonexistent_subcmd"); code != core.ExitUsageError {
		t.Fatalf("expected ExitUsageError, got %d", code)
	}

	// 4. Version flags
	if code := runCLIInProcess("version"); code != core.ExitSuccess {
		t.Fatalf("expected ExitSuccess, got %d", code)
	}
	if code := runCLIInProcess("version", "--json"); code != core.ExitSuccess {
		t.Fatalf("expected ExitSuccess for version --json, got %d", code)
	}

	// 5. Backup dry run
	if code := runCLIInProcess("backup", "--dry-run", "--base-folder", srcDir, "--output=json"); code != core.ExitSuccess {
		t.Fatalf("backup dry-run failed with code %d", code)
	}

	// 6. Backup missing required args -> ExitUsageError
	if code := runCLIInProcess("backup"); code != core.ExitUsageError {
		t.Fatalf("expected backup usage error, got %d", code)
	}

	// 7. Full Backup with audit log and yaml output
	if code := runCLIInProcess("backup",
		"--base-folder", srcDir,
		"--tree-file", snapFile,
		"--log", logFile,
		"--output", "yaml",
		"--max-memory-mb", "256",
		"--threads", "4",
		"--retention-count", "5",
		"--include", "*",
		"--exclude", "*.tmp",
	); code != core.ExitSuccess {
		t.Fatalf("in-process backup failed with code %d", code)
	}

	// 8. Status single file
	if code := runCLIInProcess("status", "--tree-file", snapFile, "--output=json"); code != core.ExitSuccess {
		t.Fatalf("status single file failed with code %d", code)
	}
	if code := runCLIInProcess("status", "--tree-file", snapFile); code != core.ExitSuccess {
		t.Fatalf("status single file table output failed with code %d", code)
	}

	// 9. Status directory path
	if code := runCLIInProcess("status", "--tree-path", tempBase, "--output=json"); code != core.ExitSuccess {
		t.Fatalf("status directory failed with code %d", code)
	}
	if code := runCLIInProcess("status", "--tree-path", tempBase); code != core.ExitSuccess {
		t.Fatalf("status directory table output failed with code %d", code)
	}

	// 10. Status missing args
	if code := runCLIInProcess("status"); code != core.ExitUsageError {
		t.Fatalf("expected status usage error, got %d", code)
	}

	// 11. Verify valid snapshot (JSON, YAML, table)
	if code := runCLIInProcess("verify", "--tree-file", snapFile, "--output=json"); code != core.ExitSuccess {
		t.Fatalf("verify failed with code %d", code)
	}
	if code := runCLIInProcess("verify", "--tree-file", snapFile, "--output=yaml"); code != core.ExitSuccess {
		t.Fatalf("verify yaml failed with code %d", code)
	}
	if code := runCLIInProcess("verify", "--tree-file", snapFile); code != core.ExitSuccess {
		t.Fatalf("verify table failed with code %d", code)
	}

	// 12. Verify missing args
	if code := runCLIInProcess("verify"); code != core.ExitUsageError {
		t.Fatalf("expected verify usage error, got %d", code)
	}

	// 13. Diff aligned (JSON, YAML, table)
	if code := runCLIInProcess("diff", "--base-folder", srcDir, "--tree-file", snapFile, "--output=json"); code != core.ExitSuccess {
		t.Fatalf("diff aligned failed with code %d", code)
	}
	if code := runCLIInProcess("diff", "--base-folder", srcDir, "--tree-file", snapFile, "--output=yaml"); code != core.ExitSuccess {
		t.Fatalf("diff yaml failed with code %d", code)
	}
	if code := runCLIInProcess("diff", "--base-folder", srcDir, "--tree-file", snapFile); code != core.ExitSuccess {
		t.Fatalf("diff table failed with code %d", code)
	}

	// 14. Inject drift and assert ExitDriftDetected
	_ = os.WriteFile(filepath.Join(srcDir, "sub", "drift.txt"), []byte("payload"), 0o644)
	if code := runCLIInProcess("diff", "--base-folder", srcDir, "--tree-file", snapFile, "--output=json"); code != core.ExitDriftDetected {
		t.Fatalf("expected ExitDriftDetected (%d), got %d", core.ExitDriftDetected, code)
	}
	if code := runCLIInProcess("diff", "--base-folder", srcDir, "--tree-file", snapFile); code != core.ExitDriftDetected {
		t.Fatalf("expected ExitDriftDetected table (%d), got %d", core.ExitDriftDetected, code)
	}

	// 15. Diff missing args
	if code := runCLIInProcess("diff"); code != core.ExitUsageError {
		t.Fatalf("expected diff usage error, got %d", code)
	}

	// 16. Restore dry run
	if code := runCLIInProcess("restore", "--dry-run", "--tree-file", snapFile, "--base-folder", restoreDir); code != core.ExitSuccess {
		t.Fatalf("restore dry-run failed with code %d", code)
	}

	// 17. Restore full (JSON, YAML, table)
	if code := runCLIInProcess("restore", "--tree-file", snapFile, "--base-folder", restoreDir, "--output=json"); code != core.ExitSuccess {
		t.Fatalf("restore json failed with code %d", code)
	}
	if code := runCLIInProcess("restore", "--tree-file", snapFile, "--base-folder", restoreDir, "--output=yaml"); code != core.ExitSuccess {
		t.Fatalf("restore yaml failed with code %d", code)
	}
	if code := runCLIInProcess("restore", "--tree-file", snapFile, "--base-folder", restoreDir); code != core.ExitSuccess {
		t.Fatalf("restore table failed with code %d", code)
	}

	// 18. Restore missing args
	if code := runCLIInProcess("restore"); code != core.ExitUsageError {
		t.Fatalf("expected restore usage error, got %d", code)
	}

	// 19. TSV and SQLite backup formats
	tsvSnap := filepath.Join(tempBase, "snap.tsv")
	if code := runCLIInProcess("backup", "--base-folder", srcDir, "--tree-file", tsvSnap, "--format=tsv", "--output=json"); code != core.ExitSuccess {
		t.Fatalf("tsv backup failed with code %d", code)
	}
	sqlSnap := filepath.Join(tempBase, "snap.sqlite")
	if code := runCLIInProcess("backup", "--base-folder", srcDir, "--tree-file", sqlSnap, "--format=sqlite", "--output=json"); code != core.ExitSuccess {
		t.Fatalf("sqlite backup failed with code %d", code)
	}

	// 20. Helper function coverage: printYAML, applyMemoryLimit
	printYAML(map[string]any{"key": "value", "count": 42})
	applyMemoryLimit(128)
	applyMemoryLimit(0)
}
