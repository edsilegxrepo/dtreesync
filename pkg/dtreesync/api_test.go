// Package dtreesync_test provides public API integration and lifecycle verification tests.
//
// Objectives:
//   - Validate end-to-end functionality of public SDK facades (Backup, InspectHeader, Verify, Restore, Diff).
//   - Confirm absolute path security boundary enforcement.
//
// Test Strategy:
//   - Full Lifecycle Workflow: TestSDK_FullWorkflow seeds a live directory hierarchy with payload files,
//     executes Backup to create a .tsv.zst archive, verifies Line 1 metadata via InspectHeader, validates
//     payload checksums with Verify, reconstitutes the tree via Restore, and confirms zero drift via Diff.
//   - Relative Path Safety: TestSDK_RelativePathRejection validates fail-fast error rejection when non-absolute
//     paths are provided.
//
// Data Flow:
//
//	Live Source Tree -> dtreesync.Backup() -> Compressed Snapshot -> InspectHeader() & Verify()
//	-> dtreesync.Restore() -> dtreesync.Diff() -> Zero Drift Assertion.
package dtreesync_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/edsilegxrepo/dtreesync/pkg/dtreesync"
)

func TestSDK_FullWorkflow(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmpDir := t.TempDir()
	sourceDir := filepath.Join(tmpDir, "source")
	targetDir := filepath.Join(tmpDir, "target")
	snapshotPath := filepath.Join(tmpDir, "snapshot.tsv.zst")

	if err := os.MkdirAll(filepath.Join(sourceDir, "sub1", "sub2"), 0o755); err != nil {
		t.Fatalf("Failed to create source dirs: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, "sub1", "file.txt"), []byte("data"), 0o644); err != nil {
		t.Fatalf("Failed to create payload file: %v", err)
	}

	// 1. Test Backup via SDK
	bRes, err := dtreesync.Backup(ctx, dtreesync.BackupConfig{
		BaseFolder:  sourceDir,
		TargetURL:   snapshotPath,
		Format:      dtreesync.FormatTSV,
		Compression: dtreesync.CompressionZstd,
		Workers:     2,
	})
	if err != nil {
		t.Fatalf("SDK Backup failed: %v", err)
	}
	if bRes.FolderCount != 3 { // root + sub1 + sub2
		t.Errorf("Expected 3 folders, got %d", bRes.FolderCount)
	}
	if bRes.SHA256Hash == "" {
		t.Errorf("Expected non-empty SHA256Hash")
	}

	// 2. Test InspectHeader via SDK
	f, err := os.Open(snapshotPath)
	if err != nil {
		t.Fatalf("Failed to open snapshot: %v", err)
	}
	hdr, err := dtreesync.InspectHeader(ctx, f)
	_ = f.Close()
	if err != nil {
		t.Fatalf("SDK InspectHeader failed: %v", err)
	}
	if hdr.TreeFormat != "tsv" {
		t.Errorf("Expected TreeFormat tsv, got %v", hdr.TreeFormat)
	}
	if hdr.FolderCount != 3 {
		t.Errorf("Expected FolderCount 3, got %d", hdr.FolderCount)
	}

	// 3. Test Verify via SDK
	vRes, err := dtreesync.Verify(ctx, dtreesync.VerifyConfig{
		SourceURL: snapshotPath,
		Workers:   2,
	})
	if err != nil {
		t.Fatalf("SDK Verify failed: %v", err)
	}
	if !vRes.ChecksumValid || !vRes.FramesValid || !vRes.SyntaxValid {
		t.Errorf("Expected snapshot to be valid, got errors: %v", vRes.Errors)
	}

	// 4. Test Restore via SDK
	rRes, err := dtreesync.Restore(ctx, dtreesync.RestoreConfig{
		SourceURL:    snapshotPath,
		TargetFolder: targetDir,
		Workers:      2,
	})
	if err != nil {
		t.Fatalf("SDK Restore failed: %v", err)
	}
	if rRes.CreatedFolders != 3 {
		t.Errorf("Expected 3 folders created, got %d", rRes.CreatedFolders)
	}
	if _, err := os.Stat(filepath.Join(targetDir, "sub1", "sub2")); err != nil {
		t.Errorf("Expected target/sub1/sub2 to exist: %v", err)
	}

	// 5. Test Diff via SDK
	dRes, err := dtreesync.Diff(ctx, dtreesync.DiffConfig{
		SnapshotURL: snapshotPath,
		LiveFolder:  targetDir,
		Workers:     2,
	})
	if err != nil {
		t.Fatalf("SDK Diff failed: %v", err)
	}
	if dRes.TotalDrift != 0 {
		t.Errorf("Expected zero drift on freshly restored target, got %d drift items: %+v", dRes.TotalDrift, dRes.DriftItems)
	}
}

func TestSDK_RelativePathRejection(t *testing.T) {
	ctx := context.Background()

	_, err := dtreesync.Backup(ctx, dtreesync.BackupConfig{
		BaseFolder: "relative/path",
		TargetURL:  "snapshot.tsv",
	})
	if err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Errorf("Expected ErrRelativePathNotAllowed, got %v", err)
	}
}

func TestInspectHeader_SQLite(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	sourceDir := filepath.Join(tmpDir, "source")
	dbPath := filepath.Join(tmpDir, "snapshot.db")

	if err := os.MkdirAll(filepath.Join(sourceDir, "sub"), 0o755); err != nil {
		t.Fatalf("Failed to create dir: %v", err)
	}

	_, err := dtreesync.Backup(ctx, dtreesync.BackupConfig{
		BaseFolder:  sourceDir,
		TargetURL:   dbPath,
		Format:      dtreesync.FormatSQLite,
		Compression: dtreesync.CompressionNone,
		Workers:     1,
	})
	if err != nil {
		t.Fatalf("Backup SQLite failed: %v", err)
	}

	// 1. Inspect via *os.File
	f, err := os.Open(dbPath)
	if err != nil {
		t.Fatalf("Failed to open db file: %v", err)
	}
	hdr1, err := dtreesync.InspectHeader(ctx, f)
	_ = f.Close()
	if err != nil {
		t.Fatalf("InspectHeader on SQLite *os.File failed: %v", err)
	}
	if hdr1.TreeFormat != "sqlite" {
		t.Errorf("Expected format sqlite, got %s", hdr1.TreeFormat)
	}

	// 2. Inspect via non-*os.File (e.g. bytes.Reader) to test spool-to-temp logic
	data, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatalf("Failed to read db file: %v", err)
	}
	hdr2, err := dtreesync.InspectHeader(ctx, bytes.NewReader(data))
	if err != nil {
		t.Fatalf("InspectHeader on SQLite bytes.Reader failed: %v", err)
	}
	if hdr2.TreeFormat != "sqlite" {
		t.Errorf("Expected format sqlite, got %s", hdr2.TreeFormat)
	}
}

func TestInspectHeader_NDJSON(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	sourceDir := filepath.Join(tmpDir, "source")
	ndjsonPath := filepath.Join(tmpDir, "snapshot.ndjson")

	if err := os.MkdirAll(sourceDir, 0o755); err != nil {
		t.Fatalf("Failed to create dir: %v", err)
	}

	_, err := dtreesync.Backup(ctx, dtreesync.BackupConfig{
		BaseFolder:  sourceDir,
		TargetURL:   ndjsonPath,
		Format:      dtreesync.FormatNDJSON,
		Compression: dtreesync.CompressionNone,
		Workers:     1,
	})
	if err != nil {
		t.Fatalf("Backup NDJSON failed: %v", err)
	}

	f, err := os.Open(ndjsonPath)
	if err != nil {
		t.Fatalf("Failed to open ndjson file: %v", err)
	}
	defer func() { _ = f.Close() }()

	hdr, err := dtreesync.InspectHeader(ctx, f)
	if err != nil {
		t.Fatalf("InspectHeader on NDJSON failed: %v", err)
	}
	if hdr.TreeFormat != "ndjson" {
		t.Errorf("Expected format ndjson, got %s", hdr.TreeFormat)
	}
}

func TestInspectHeader_TSV_Uncompressed(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	sourceDir := filepath.Join(tmpDir, "source")
	tsvPath := filepath.Join(tmpDir, "snapshot.tsv")

	if err := os.MkdirAll(sourceDir, 0o755); err != nil {
		t.Fatalf("Failed to create dir: %v", err)
	}

	_, err := dtreesync.Backup(ctx, dtreesync.BackupConfig{
		BaseFolder:  sourceDir,
		TargetURL:   tsvPath,
		Format:      dtreesync.FormatTSV,
		Compression: dtreesync.CompressionNone,
		Workers:     1,
	})
	if err != nil {
		t.Fatalf("Backup TSV failed: %v", err)
	}

	f, err := os.Open(tsvPath)
	if err != nil {
		t.Fatalf("Failed to open tsv file: %v", err)
	}
	defer func() { _ = f.Close() }()

	hdr, err := dtreesync.InspectHeader(ctx, f)
	if err != nil {
		t.Fatalf("InspectHeader on TSV failed: %v", err)
	}
	if hdr.TreeFormat != "tsv" {
		t.Errorf("Expected format tsv, got %s", hdr.TreeFormat)
	}
}

func TestInspectHeader_Errors(t *testing.T) {
	ctx := context.Background()

	// 1. Short stream (< 4 bytes)
	_, err := dtreesync.InspectHeader(ctx, bytes.NewReader([]byte("ab")))
	if err == nil {
		t.Errorf("Expected error on short stream, got nil")
	}

	// 2. Corrupted Zstd stream (has zstd magic 0x28, 0xb5, 0x2f, 0xfd followed by garbage)
	corruptZstd := []byte{0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x00}
	_, err = dtreesync.InspectHeader(ctx, bytes.NewReader(corruptZstd))
	if err == nil {
		t.Errorf("Expected error decoding corrupted zstd header, got nil")
	}
}

func TestSDK_AuditLogging_Options(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	sourceDir := filepath.Join(tmpDir, "source")
	targetDir := filepath.Join(tmpDir, "target")
	snapshotPath := filepath.Join(tmpDir, "snapshot.tsv")
	auditLogPath := filepath.Join(tmpDir, "audit.jsonl")

	if err := os.MkdirAll(sourceDir, 0o755); err != nil {
		t.Fatalf("Failed to create dir: %v", err)
	}

	var buf bytes.Buffer
	// Test Backup with AuditLogWriter
	_, err := dtreesync.Backup(ctx, dtreesync.BackupConfig{
		BaseFolder:     sourceDir,
		TargetURL:      snapshotPath,
		Format:         dtreesync.FormatTSV,
		Compression:    dtreesync.CompressionNone,
		Workers:        1,
		AuditLogWriter: &buf,
	})
	if err != nil {
		t.Fatalf("Backup with AuditLogWriter failed: %v", err)
	}
	if buf.Len() == 0 {
		t.Errorf("Expected audit logs written to buffer")
	}

	// Test Verify with LogFile
	_, err = dtreesync.Verify(ctx, dtreesync.VerifyConfig{
		SourceURL: snapshotPath,
		Workers:   1,
		LogFile:   auditLogPath,
	})
	if err != nil {
		t.Fatalf("Verify with LogFile failed: %v", err)
	}
	if _, err := os.Stat(auditLogPath); err != nil {
		t.Errorf("Expected audit log file to exist: %v", err)
	}

	// Test Restore with AuditLogWriter
	buf.Reset()
	_, err = dtreesync.Restore(ctx, dtreesync.RestoreConfig{
		SourceURL:      snapshotPath,
		TargetFolder:   targetDir,
		Workers:        1,
		AuditLogWriter: &buf,
	})
	if err != nil {
		t.Fatalf("Restore with AuditLogWriter failed: %v", err)
	}

	// Test Diff with LogFile
	_, err = dtreesync.Diff(ctx, dtreesync.DiffConfig{
		SnapshotURL: snapshotPath,
		LiveFolder:  targetDir,
		Workers:     1,
		LogFile:     auditLogPath,
	})
	if err != nil {
		t.Fatalf("Diff with LogFile failed: %v", err)
	}
}

func TestSDK_AuditLogger_InvalidPath(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	invalidLogPath := filepath.Join(tmpDir, "nonexistent_dir", "forbidden", "audit.log")

	_, err := dtreesync.Backup(ctx, dtreesync.BackupConfig{
		BaseFolder: tmpDir,
		TargetURL:  filepath.Join(tmpDir, "out.tsv"),
		LogFile:    invalidLogPath,
	})
	if err == nil {
		t.Errorf("Expected error from invalid log path, got nil")
	}

	_, err = dtreesync.Restore(ctx, dtreesync.RestoreConfig{
		SourceURL:    filepath.Join(tmpDir, "out.tsv"),
		TargetFolder: tmpDir,
		LogFile:      invalidLogPath,
	})
	if err == nil {
		t.Errorf("Expected error from invalid log path on restore, got nil")
	}

	_, err = dtreesync.Diff(ctx, dtreesync.DiffConfig{
		SnapshotURL: filepath.Join(tmpDir, "out.tsv"),
		LiveFolder:  tmpDir,
		LogFile:     invalidLogPath,
	})
	if err == nil {
		t.Errorf("Expected error from invalid log path on diff, got nil")
	}

	_, err = dtreesync.Verify(ctx, dtreesync.VerifyConfig{
		SourceURL: filepath.Join(tmpDir, "out.tsv"),
		LogFile:   invalidLogPath,
	})
	if err == nil {
		t.Errorf("Expected error from invalid log path on verify, got nil")
	}
}
