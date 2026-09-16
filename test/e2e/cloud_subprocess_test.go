// Package e2e_test validates end-to-end cloud storage workflows executed via compiled CLI subprocesses.
//
// Objectives:
//   - Verify that the compiled dtreesync CLI binary operates seamlessly against remote S3 cloud storage.
//   - Ensure the WSL Docker container (MinIO) is automatically started or verified running.
//   - Enforce pure TLS/HTTPS wire encryption (DO NOT DISABLE SSL).
//   - Validate the complete 5-operation production lifecycle via CLI subprocess:
//     Backup -> Status -> Verify -> Restore -> Diff.
package e2e_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/edsilegxrepo/dtreesync/test/testutil"
)

func TestE2E_CLISubprocess_CloudS3_Lifecycle(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping cloud subprocess e2e test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	// 1. Handle starting the WSL Docker container, or making sure it is running
	rawEndpoint, accessKey, secretKey, _ := testutil.EnsureMinIORunning(t)

	// 2. Wrap in genuine TLS reverse proxy to strictly enforce wire encryption (SSL NOT disabled)
	tlsServer, tlsEndpoint, caFile := testutil.SetupMinIOTLSProxy(t, rawEndpoint)

	bucketName := fmt.Sprintf("dtreesync-e2e-sub-%d", time.Now().UnixNano())
	if err := testutil.CreateS3Bucket(ctx, tlsEndpoint, bucketName, accessKey, secretKey, tlsServer.Client()); err != nil {
		t.Fatalf("failed to create live S3 bucket over TLS: %v", err)
	}

	// 3. Compile the actual CLI binary
	tmpDir := t.TempDir()
	binPath := buildBinary(t, tmpDir)

	// 4. Configure environment credentials for subprocess execution
	t.Setenv("AWS_ACCESS_KEY_ID", accessKey)
	t.Setenv("AWS_SECRET_ACCESS_KEY", secretKey)
	t.Setenv("AWS_REGION", "us-east-1")
	t.Setenv("AWS_CA_BUNDLE", caFile)
	t.Setenv("SSL_CERT_FILE", caFile)

	sourceDir := filepath.Join(tmpDir, "source")
	restoreDir := filepath.Join(tmpDir, "restored")

	// Seed source tree
	dirs := []string{
		filepath.Join(sourceDir, "tenant_alpha", "inbound", "2026"),
		filepath.Join(sourceDir, "tenant_alpha", "outbound"),
		filepath.Join(sourceDir, "tenant_beta", "archive", "logs"),
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("failed to seed source dir: %v", err)
		}
	}
	if err := os.WriteFile(filepath.Join(sourceDir, "tenant_alpha", "inbound", "2026", "payload.csv"), []byte("cloud payload data"), 0o644); err != nil {
		t.Fatalf("failed to write payload file: %v", err)
	}

	// Cloud snapshot URL with TLS endpoint query parameter
	cloudURL := fmt.Sprintf("s3://%s/cluster_topology.tsv.zst?endpoint=%s&s3ForcePathStyle=true&region=us-east-1", bucketName, url.QueryEscape(tlsServer.URL))

	// 5. Subprocess 1: backup directly to remote S3
	backupCmd := exec.Command(binPath, "backup",
		"--base-folder="+sourceDir,
		"--tree-file="+cloudURL,
		"--tree-format=tsv",
		"--backup-compress=true",
		"--threads=2",
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
		t.Fatalf("failed to parse backup json: %v, raw: %s", err, string(backupOut))
	}
	if backupMetrics.FolderCount < 4 {
		t.Fatalf("expected at least 4 folders in backup, got: %d", backupMetrics.FolderCount)
	}
	if backupMetrics.SHA256Hash == "" {
		t.Fatal("expected non-empty SHA256 in backup metrics")
	}

	// 6. Subprocess 2: status peeking metadata directly from S3
	statusCmd := exec.Command(binPath, "status",
		"--tree-file="+cloudURL,
		"--output=json",
	)
	statusOut, err := statusCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("status subprocess failed with exit %d: %v, out: %s", getSubprocessExitCode(err), err, string(statusOut))
	}
	var statusHeader struct {
		Version       string `json:"version"`
		FolderCount   int64  `json:"folder_count"`
		PayloadSHA256 string `json:"payload_sha256"`
		TreeFormat    string `json:"tree_format"`
		Compression   bool   `json:"compression"`
	}
	if err := json.Unmarshal(statusOut, &statusHeader); err != nil {
		t.Fatalf("failed to parse status json: %v, raw: %s", err, string(statusOut))
	}
	if statusHeader.FolderCount != backupMetrics.FolderCount {
		t.Fatalf("expected status folder count %d, got: %d", backupMetrics.FolderCount, statusHeader.FolderCount)
	}
	if statusHeader.PayloadSHA256 != backupMetrics.SHA256Hash {
		t.Fatalf("expected status payload sha256 %s, got: %s", backupMetrics.SHA256Hash, statusHeader.PayloadSHA256)
	}

	// 7. Subprocess 3: verify remote S3 snapshot framing and cryptographic checksum
	verifyCmd := exec.Command(binPath, "verify",
		"--tree-file="+cloudURL,
		"--output=json",
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
		t.Fatalf("failed to parse verify json: %v, raw: %s", err, string(verifyOut))
	}
	if !verifyResult.ChecksumValid || !verifyResult.FramesValid || !verifyResult.SyntaxValid {
		t.Fatalf("expected verify checks to pass: %+v", verifyResult)
	}

	// 8. Subprocess 4: restore from S3 onto target folder
	restoreCmd := exec.Command(binPath, "restore",
		"--tree-file="+cloudURL,
		"--base-folder="+restoreDir,
		"--threads=2",
		"--output=json",
	)
	restoreOut, err := restoreCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("restore subprocess failed with exit %d: %v, out: %s", getSubprocessExitCode(err), err, string(restoreOut))
	}

	// Verify restored topology exists on local disk
	for _, d := range dirs {
		rel, _ := filepath.Rel(sourceDir, d)
		targetPath := filepath.Join(restoreDir, rel)
		fi, err := os.Stat(targetPath)
		if err != nil || !fi.IsDir() {
			t.Fatalf("expected restored directory at %s, err: %v", targetPath, err)
		}
	}

	// 9. Subprocess 5: diff live restored directory against remote S3 baseline snapshot
	diffCmd := exec.Command(binPath, "diff",
		"--base-folder="+restoreDir,
		"--tree-file="+cloudURL,
		"--output=json",
	)
	diffOut, err := diffCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("diff subprocess failed with exit %d: %v, out: %s", getSubprocessExitCode(err), err, string(diffOut))
	}
	var diffResult struct {
		TotalDrift int `json:"total_drift"`
	}
	if err := json.Unmarshal(diffOut, &diffResult); err != nil {
		t.Fatalf("failed to parse diff json: %v, raw: %s", err, string(diffOut))
	}
	if diffResult.TotalDrift != 0 {
		t.Fatalf("expected zero drift, got %d", diffResult.TotalDrift)
	}
}
