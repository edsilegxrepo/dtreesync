// Package e2e_test provides subprocess-level end-to-end testing of the compiled dtreesync CLI binary.
//
// Objectives:
//   - Execute the actual compiled dtreesync binary as an external OS subprocess.
//   - Verify flag parsing, streaming standard I/O (table and JSON), and operational correctness.
//   - Validate strict adherence to Section 3.1 diagnostic exit codes:
//     Exit 0: SUCCESS (clean backup, status, verify, restore, diff)
//     Exit 1: FATAL_ERROR (relative path boundary violation)
//     Exit 3: DRIFT_DETECTED (drift detected during diff)
//     Exit 4: VERIFICATION_FAILED (tampered snapshot during verify)
//
// Test Strategy:
//   - TestE2E_CLISubprocess_FullLifecycle compiles cmd/dtreesync once into t.TempDir(), executes the full
//     5-operation lifecycle via exec.Command, verifies JSON outputs and exit codes, and confirms drift/tamper exits.
//
// Data Flow:
//
//	CLI Subprocess -> Flag Parser -> Engine -> Output Serialization -> Exit Code Assertion.
package e2e_test

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/edsilegxrepo/dtreesync/internal/core"
)

func buildBinary(t *testing.T, targetDir string) string {
	binName := "dtreesync"
	if runtime.GOOS == "windows" {
		binName += ".exe"
	}
	binPath := filepath.Join(targetDir, binName)

	cmd := exec.Command("go", "build", "-o", binPath, "../../cmd/dtreesync")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to build dtreesync binary for subprocess test: %v, out: %s", err, string(out))
	}
	return binPath
}

func getSubprocessExitCode(err error) int {
	if err == nil {
		return core.ExitSuccess
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return -1
}

func TestE2E_CLISubprocess_FullLifecycle(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess e2e test in short mode")
	}

	tmpDir := t.TempDir()
	binPath := buildBinary(t, tmpDir)

	sourceDir := filepath.Join(tmpDir, "source")
	restoreDir := filepath.Join(tmpDir, "restore")
	snapshotFile := filepath.Join(tmpDir, "topology.tsv.zst")
	logFile := filepath.Join(tmpDir, "audit.jsonl")

	// Seed source directory topology with nested structures and payload files
	dirs := []string{
		filepath.Join(sourceDir, "partner_alpha", "orders", "2026"),
		filepath.Join(sourceDir, "partner_alpha", "inbound"),
		filepath.Join(sourceDir, "partner_beta", "archive"),
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("failed to seed source dir: %v", err)
		}
	}
	if err := os.WriteFile(filepath.Join(sourceDir, "partner_alpha", "orders", "data.csv"), []byte("csv data"), 0o644); err != nil {
		t.Fatalf("failed to write payload file: %v", err)
	}

	// 1. Subprocess: backup
	backupCmd := exec.Command(binPath, "backup",
		"--base-folder="+sourceDir,
		"--tree-file="+snapshotFile,
		"--tree-format=tsv",
		"--backup-compress=true",
		"--threads=2",
		"--log="+logFile,
		"--output=json",
	)
	backupOut, err := backupCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("backup subprocess failed with exit %d: %v, out: %s", getSubprocessExitCode(err), err, string(backupOut))
	}

	var backupMetrics struct {
		FolderCount int64  `json:"folder_count"`
		SHA256Hash  string `json:"sha256_hash"`
	}
	if err := json.Unmarshal(backupOut, &backupMetrics); err != nil {
		t.Fatalf("failed to parse backup JSON output: %v, raw: %s", err, string(backupOut))
	}
	if backupMetrics.FolderCount < 4 { // root, partner_alpha, partner_alpha/orders, partner_alpha/orders/2026, ...
		t.Errorf("expected at least 4 folders in backup, got %d", backupMetrics.FolderCount)
	}
	if backupMetrics.SHA256Hash == "" {
		t.Error("expected non-empty SHA256 hash in backup metrics")
	}

	// 2. Subprocess: status (metadata header inspection)
	statusCmd := exec.Command(binPath, "status",
		"--tree-file", snapshotFile,
		"--output", "json",
	)
	statusOut, err := statusCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("status subprocess failed: %v, out: %s", err, string(statusOut))
	}

	var statusHeader struct {
		Version       string `json:"version"`
		FolderCount   int64  `json:"folder_count"`
		PayloadSHA256 string `json:"payload_sha256"`
		TreeFormat    string `json:"tree_format"`
		Compression   bool   `json:"compression"`
	}
	if err := json.Unmarshal(statusOut, &statusHeader); err != nil {
		t.Fatalf("failed to parse status JSON output: %v, raw: %s", err, string(statusOut))
	}
	if statusHeader.FolderCount != backupMetrics.FolderCount {
		t.Errorf("status folder count mismatch: expected %d, got %d", backupMetrics.FolderCount, statusHeader.FolderCount)
	}
	if statusHeader.PayloadSHA256 != backupMetrics.SHA256Hash {
		t.Errorf("status SHA256 mismatch: expected %s, got %s", backupMetrics.SHA256Hash, statusHeader.PayloadSHA256)
	}
	if statusHeader.TreeFormat != "tsv" || !statusHeader.Compression {
		t.Errorf("expected tsv format with compression, got format=%s comp=%v", statusHeader.TreeFormat, statusHeader.Compression)
	}

	// 3. Subprocess: verify (cryptographic integrity check)
	verifyCmd := exec.Command(binPath, "verify",
		"--tree-file", snapshotFile,
		"--threads", "2",
		"--output", "json",
	)
	verifyOut, err := verifyCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("verify subprocess failed with exit %d: %v, out: %s", getSubprocessExitCode(err), err, string(verifyOut))
	}

	var verifyResult struct {
		ChecksumValid bool `json:"checksum_valid"`
		FramesValid   bool `json:"frames_valid"`
		SyntaxValid   bool `json:"syntax_valid"`
	}
	if err := json.Unmarshal(verifyOut, &verifyResult); err != nil {
		t.Fatalf("failed to parse verify JSON output: %v, raw: %s", err, string(verifyOut))
	}
	if !verifyResult.ChecksumValid || !verifyResult.FramesValid || !verifyResult.SyntaxValid {
		t.Fatalf("expected all verify checks to pass: %+v", verifyResult)
	}

	// 4. Subprocess: restore
	restoreCmd := exec.Command(binPath, "restore",
		"--base-folder", restoreDir,
		"--tree-file", snapshotFile,
		"--threads", "2",
		"--output", "json",
	)
	restoreOut, err := restoreCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("restore subprocess failed with exit %d: %v, out: %s", getSubprocessExitCode(err), err, string(restoreOut))
	}

	// Verify folders created on disk
	if _, err := os.Stat(filepath.Join(restoreDir, "partner_alpha", "orders", "2026")); err != nil {
		t.Fatalf("expected restored directory hierarchy: %v", err)
	}

	// 5. Subprocess: diff (confirm zero drift)
	diffCmd := exec.Command(binPath, "diff",
		"--base-folder", restoreDir,
		"--tree-file", snapshotFile,
		"--threads", "2",
		"--output", "json",
	)
	diffOut, err := diffCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("diff subprocess failed on clean state: exit %d, err: %v, out: %s", getSubprocessExitCode(err), err, string(diffOut))
	}

	var diffResult struct {
		TotalDrift int `json:"total_drift"`
	}
	if err := json.Unmarshal(diffOut, &diffResult); err != nil {
		t.Fatalf("failed to parse diff JSON output: %v, raw: %s", err, string(diffOut))
	}
	if diffResult.TotalDrift != 0 {
		t.Fatalf("expected 0 drift after restore, got %d", diffResult.TotalDrift)
	}

	// 6. Subprocess Exit Code 3: DRIFT_DETECTED
	// Inject an untracked directory and assert that diff returns exit code 3
	rogueDir := filepath.Join(restoreDir, "unauthorized_drift_folder")
	if err := os.MkdirAll(rogueDir, 0o755); err != nil {
		t.Fatalf("failed to create rogue dir: %v", err)
	}

	driftCmd := exec.Command(binPath, "diff",
		"--base-folder", restoreDir,
		"--tree-file", snapshotFile,
		"--output", "json",
	)
	driftOut, driftErr := driftCmd.CombinedOutput()
	driftExitCode := getSubprocessExitCode(driftErr)
	if driftExitCode != core.ExitDriftDetected {
		t.Fatalf("expected exit code %d (ExitDriftDetected), got %d (out: %s)", core.ExitDriftDetected, driftExitCode, string(driftOut))
	}

	// 7. Subprocess Exit Code 4: VERIFICATION_FAILED
	// Corrupt snapshot file bytes and assert verify returns exit code 4
	tamperedSnap := filepath.Join(tmpDir, "tampered_snap.tsv.zst")
	origBytes, err := os.ReadFile(snapshotFile)
	if err != nil {
		t.Fatalf("failed to read snapshot file: %v", err)
	}
	tamperedBytes := append([]byte(nil), origBytes...)
	if len(tamperedBytes) > 20 {
		tamperedBytes[len(tamperedBytes)-10] ^= 0xFF
	}
	if err := os.WriteFile(tamperedSnap, tamperedBytes, 0o644); err != nil {
		t.Fatalf("failed to write tampered snapshot: %v", err)
	}

	failVerifyCmd := exec.Command(binPath, "verify",
		"--tree-file", tamperedSnap,
		"--output", "json",
	)
	failVerifyOut, failVerifyErr := failVerifyCmd.CombinedOutput()
	failVerifyExitCode := getSubprocessExitCode(failVerifyErr)
	if failVerifyExitCode != core.ExitVerificationFailed {
		t.Fatalf("expected exit code %d (ExitVerificationFailed), got %d (out: %s)", core.ExitVerificationFailed, failVerifyExitCode, string(failVerifyOut))
	}

	// 8. Subprocess Exit Code 1: FATAL_ERROR (Relative path boundary violation)
	relPathCmd := exec.Command(binPath, "backup",
		"--base-folder", "relative/path/forbidden",
		"--tree-file", snapshotFile,
	)
	relPathOut, relPathErr := relPathCmd.CombinedOutput()
	relPathExitCode := getSubprocessExitCode(relPathErr)
	if relPathExitCode != core.ExitUsageError && relPathExitCode != core.ExitFatalError {
		t.Fatalf("expected fatal/usage exit code (1), got %d (out: %s)", relPathExitCode, string(relPathOut))
	}
	if !strings.Contains(string(relPathOut), "absolute") {
		t.Errorf("expected error message to mention absolute path requirement, got: %s", string(relPathOut))
	}
}

func TestE2E_CLISubprocess_VersionFlag(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess test in short mode")
	}

	tmpDir := t.TempDir()
	binPath := buildBinary(t, tmpDir)

	cmd := exec.Command(binPath, "version")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("version command failed: %v, out: %s", err, string(out))
	}
	if !strings.Contains(string(out), "dtreesync version") {
		t.Fatalf("unexpected version output format: %s", string(out))
	}
}

func TestE2E_CLISubprocess_SortFlag(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess test in short mode")
	}

	tmpDir := t.TempDir()
	binPath := buildBinary(t, tmpDir)

	sourceDir := filepath.Join(tmpDir, "source")
	dirs := []string{
		filepath.Join(sourceDir, "zeta_corp", "orders", "2026"),
		filepath.Join(sourceDir, "alpha_corp", "inbound"),
		filepath.Join(sourceDir, "gamma_corp"),
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("failed to seed source dir: %v", err)
		}
	}

	// 1. Subprocess: backup with --sort=depth
	depthSnap := filepath.Join(tmpDir, "depth.tsv.zst")
	backupDepthCmd := exec.Command(binPath, "backup",
		"--base-folder="+sourceDir,
		"--tree-file="+depthSnap,
		"--sort=depth",
		"--output=json",
	)
	backupDepthOut, err := backupDepthCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("backup --sort=depth failed with exit %d: %v, out: %s", getSubprocessExitCode(err), err, string(backupDepthOut))
	}

	// Status inspection of --sort=depth snapshot
	statusDepthCmd := exec.Command(binPath, "status",
		"--tree-file="+depthSnap,
		"--output=json",
	)
	statusDepthOut, err := statusDepthCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("status on depth snap failed: %v, out: %s", err, string(statusDepthOut))
	}
	var depthHeader struct {
		SortOrder string `json:"sort_order"`
	}
	if err := json.Unmarshal(statusDepthOut, &depthHeader); err != nil {
		t.Fatalf("failed to unmarshal depth status output: %v", err)
	}
	if depthHeader.SortOrder != "depth" {
		t.Errorf("expected sort_order 'depth', got %q", depthHeader.SortOrder)
	}

	// Verify depth snapshot
	verifyDepthCmd := exec.Command(binPath, "verify", "--tree-file="+depthSnap)
	if out, err := verifyDepthCmd.CombinedOutput(); err != nil {
		t.Fatalf("verify on depth snapshot failed: %v, out: %s", err, string(out))
	}

	// 2. Subprocess: backup with --sort=none
	noneSnap := filepath.Join(tmpDir, "none.tsv.zst")
	backupNoneCmd := exec.Command(binPath, "backup",
		"--base-folder="+sourceDir,
		"--tree-file="+noneSnap,
		"--sort=none",
		"--output=json",
	)
	backupNoneOut, err := backupNoneCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("backup --sort=none failed with exit %d: %v, out: %s", getSubprocessExitCode(err), err, string(backupNoneOut))
	}

	// Status inspection of --sort=none snapshot
	statusNoneCmd := exec.Command(binPath, "status",
		"--tree-file="+noneSnap,
		"--output=json",
	)
	statusNoneOut, err := statusNoneCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("status on none snap failed: %v, out: %s", err, string(statusNoneOut))
	}
	var noneHeader struct {
		SortOrder string `json:"sort_order"`
	}
	if err := json.Unmarshal(statusNoneOut, &noneHeader); err != nil {
		t.Fatalf("failed to unmarshal none status output: %v", err)
	}
	if noneHeader.SortOrder != "none" {
		t.Errorf("expected sort_order 'none', got %q", noneHeader.SortOrder)
	}

	// Verify none snapshot
	verifyNoneCmd := exec.Command(binPath, "verify", "--tree-file="+noneSnap)
	if out, err := verifyNoneCmd.CombinedOutput(); err != nil {
		t.Fatalf("verify on none snapshot failed: %v, out: %s", err, string(out))
	}

	// 3. Subprocess: backup with invalid sort option
	invalidSnap := filepath.Join(tmpDir, "invalid.tsv.zst")
	invalidCmd := exec.Command(binPath, "backup",
		"--base-folder="+sourceDir,
		"--tree-file="+invalidSnap,
		"--sort=invalid_mode",
	)
	invalidOut, invalidErr := invalidCmd.CombinedOutput()
	invalidExitCode := getSubprocessExitCode(invalidErr)
	if invalidExitCode != core.ExitUsageError {
		t.Fatalf("expected exit code %d (ExitUsageError) for invalid sort, got %d (out: %s)",
			core.ExitUsageError, invalidExitCode, string(invalidOut))
	}
	if !strings.Contains(string(invalidOut), "invalid --sort") {
		t.Errorf("expected error message to mention 'invalid --sort', got: %s", string(invalidOut))
	}
}
