// Package e2e_test provides end-to-end drift detection and discrepancy audit tests.
//
// Objectives:
//   - Verify that the diff engine reliably isolates multi-vector filesystem drift.
//   - Confirm accurate classification of untracked directories, rogue files, and missing directories.
//
// Test Strategy:
//   - Multi-Vector Tampering: TestE2E_Diff_DiscrepancyDetection establishes a verified baseline snapshot,
//     restores it to a live directory, injects 3 distinct anomalies (untracked folder, rogue file, deleted folder),
//     and asserts that Diff accurately flags all 3 items and returns ErrDriftDetected.
//
// Data Flow:
//
//	Baseline Snapshot -> Live Materialization -> Anomaly Injection -> dtreesync.Diff() -> Discrepancy Assertions.
package e2e_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/edsilegxrepo/dtreesync/pkg/dtreesync"
)

func TestE2E_Diff_DiscrepancyDetection(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmpDir := t.TempDir()
	sourceDir := filepath.Join(tmpDir, "source")
	liveDir := filepath.Join(tmpDir, "live")
	snapshotFile := filepath.Join(tmpDir, "baseline.ndjson.zst")

	// 1. Create initial hierarchy
	p1 := filepath.Join(sourceDir, "partner1", "inbound")
	p2 := filepath.Join(sourceDir, "partner2", "outbound")
	if err := os.MkdirAll(p1, 0o755); err != nil {
		t.Fatalf("Failed to create p1: %v", err)
	}
	if err := os.MkdirAll(p2, 0o755); err != nil {
		t.Fatalf("Failed to create p2: %v", err)
	}

	// 2. Backup to create baseline
	_, err := dtreesync.Backup(ctx, dtreesync.BackupConfig{
		BaseFolder: sourceDir,
		TargetURL:  snapshotFile,
		Workers:    2,
	})
	if err != nil {
		t.Fatalf("Backup failed: %v", err)
	}

	// 3. Restore to live directory
	_, err = dtreesync.Restore(ctx, dtreesync.RestoreConfig{
		SourceURL:    snapshotFile,
		TargetFolder: liveDir,
		Workers:      2,
	})
	if err != nil {
		t.Fatalf("Restore failed: %v", err)
	}

	// 4. Inject 3 distinct discrepancies into liveDir:
	// Discrepancy A: Untracked directory
	untrackedDir := filepath.Join(liveDir, "partner_rogue", "data")
	if err := os.MkdirAll(untrackedDir, 0o755); err != nil {
		t.Fatalf("Failed to create rogue dir: %v", err)
	}

	// Discrepancy B: Untracked payload file
	untrackedFile := filepath.Join(liveDir, "partner1", "inbound", "rogue_file.txt")
	if err := os.WriteFile(untrackedFile, []byte("untracked payload"), 0o644); err != nil {
		t.Fatalf("Failed to write rogue file: %v", err)
	}

	// Discrepancy C: Deleted expected directory
	_ = os.RemoveAll(filepath.Join(liveDir, "partner2", "outbound"))

	// 5. Run Diff
	diffRes, err := dtreesync.Diff(ctx, dtreesync.DiffConfig{
		SnapshotURL: snapshotFile,
		LiveFolder:  liveDir,
		Workers:     2,
	})

	// Diff should return ErrDriftDetected
	if !errors.Is(err, dtreesync.ErrDriftDetected) {
		t.Errorf("Expected ErrDriftDetected, got %v", err)
	}
	if diffRes == nil {
		t.Fatalf("Expected non-nil diff result")
	}

	// Assert on discrepancies
	if diffRes.Status != "drift_detected" {
		t.Errorf("Expected status 'drift_detected', got %q", diffRes.Status)
	}
	if diffRes.TotalDrift < 3 {
		t.Errorf("Expected at least 3 drift items, got %d: %+v", diffRes.TotalDrift, diffRes.DriftItems)
	}
	if diffRes.Summary.MissingCount == 0 {
		t.Errorf("Expected non-zero missing count")
	}
	if diffRes.Summary.ExtraCount == 0 {
		t.Errorf("Expected non-zero extra count")
	}
}
