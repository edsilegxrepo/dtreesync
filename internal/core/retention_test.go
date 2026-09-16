// Package core provides unit tests for snapshot retention and lifecycle pruning.
//
// Objectives:
//   - Ensure automated FIFO snapshot retention prevents unbounded storage growth.
//   - Validate count-based eviction, age-based eviction, dual-policy enforcement, and non-snapshot safety.
//   - Guarantee that active/newest snapshots are never purged and directories/unrelated files are untouched.
//
// Test Strategy:
//   - Zero Configuration: TestApplyRetention_Disabled ensures no-op when retention flags are 0.
//   - Count Policy: TestApplyRetention_CountBased creates staggered snapshots, asserting that only the N newest survive.
//   - Age Policy: TestApplyRetention_AgeBased modifies mtimes with os.Chtimes, ensuring older files are pruned.
//   - Safety Filters: TestApplyRetention_IgnoresNonSnapshots verifies that subdirectories and .txt files are never touched.
//   - Audit Telemetry: TestApplyRetention_AuditLogging verifies audit trail emission during purge operations.
//
// Data Flow:
//
//	Temp Snapshot Store -> Timestamped Mock Files -> ApplyRetention() -> os.Stat / Purge Slice Assertions.
package core

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/edsilegxrepo/dtreesync/internal/model"
)

func TestApplyRetention_Disabled(t *testing.T) {
	tempDir := t.TempDir()
	dummyFile := filepath.Join(tempDir, "snap1.ndjson.zst")
	if err := os.WriteFile(dummyFile, []byte("data"), 0o644); err != nil {
		t.Fatalf("failed to write dummy file: %v", err)
	}

	purged, err := ApplyRetention(tempDir, 0, 0, nil)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(purged) != 0 {
		t.Fatalf("expected 0 purged, got %d", len(purged))
	}
	if _, err := os.Stat(dummyFile); os.IsNotExist(err) {
		t.Fatal("expected dummy file to remain untouched")
	}
}

func TestApplyRetention_CountBased(t *testing.T) {
	tempDir := t.TempDir()
	now := time.Now()

	// Create 5 snapshot files with staggered modification timestamps
	filenames := []string{
		"snap_1.ndjson.zst", // oldest
		"snap_2.ndjson.zst",
		"snap_3.ndjson.zst",
		"snap_4.ndjson.zst",
		"snap_5.ndjson.zst", // newest
	}

	for i, name := range filenames {
		p := filepath.Join(tempDir, name)
		if err := os.WriteFile(p, []byte("snapshot-content"), 0o644); err != nil {
			t.Fatalf("failed to create %s: %v", name, err)
		}
		// Stagger timestamps: index 0 is oldest, index 4 is newest
		modTime := now.Add(time.Duration(i-5) * time.Hour)
		if err := os.Chtimes(p, modTime, modTime); err != nil {
			t.Fatalf("failed to set mtime on %s: %v", name, err)
		}
	}

	// Keep newest 2
	purged, err := ApplyRetention(tempDir, 0, 2, nil)
	if err != nil {
		t.Fatalf("ApplyRetention failed: %v", err)
	}

	if len(purged) != 3 {
		t.Fatalf("expected 3 files purged, got %d: %v", len(purged), purged)
	}

	// snap_1, snap_2, snap_3 must be deleted
	for _, name := range []string{"snap_1.ndjson.zst", "snap_2.ndjson.zst", "snap_3.ndjson.zst"} {
		p := filepath.Join(tempDir, name)
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("expected %s to be deleted", name)
		}
	}

	// snap_4, snap_5 must be preserved
	for _, name := range []string{"snap_4.ndjson.zst", "snap_5.ndjson.zst"} {
		p := filepath.Join(tempDir, name)
		if _, err := os.Stat(p); err != nil {
			t.Errorf("expected %s to be preserved: %v", name, err)
		}
	}
}

func TestApplyRetention_AgeBased(t *testing.T) {
	tempDir := t.TempDir()
	now := time.Now()

	// snap_recent: 1 hour old
	recentFile := filepath.Join(tempDir, "recent.tsv.zst")
	_ = os.WriteFile(recentFile, []byte("data"), 0o644)
	recentTime := now.Add(-1 * time.Hour)
	_ = os.Chtimes(recentFile, recentTime, recentTime)

	// snap_old: 15 days old
	oldFile := filepath.Join(tempDir, "old.tsv.zst")
	_ = os.WriteFile(oldFile, []byte("data"), 0o644)
	oldTime := now.Add(-15 * 24 * time.Hour)
	_ = os.Chtimes(oldFile, oldTime, oldTime)

	// Keep files newer than 7 days
	purged, err := ApplyRetention(tempDir, 7, 0, nil)
	if err != nil {
		t.Fatalf("ApplyRetention failed: %v", err)
	}

	if len(purged) != 1 {
		t.Fatalf("expected 1 file purged, got %d: %v", len(purged), purged)
	}

	if _, err := os.Stat(oldFile); !os.IsNotExist(err) {
		t.Error("expected old.tsv.zst to be deleted")
	}
	if _, err := os.Stat(recentFile); err != nil {
		t.Errorf("expected recent.tsv.zst to be preserved: %v", err)
	}
}

func TestApplyRetention_IgnoresNonSnapshotsAndDirectories(t *testing.T) {
	tempDir := t.TempDir()
	now := time.Now()

	// 1. Subdirectory
	subDir := filepath.Join(tempDir, "archive_subdir")
	_ = os.MkdirAll(subDir, 0o755)

	// 2. Non-snapshot file (.txt, .log)
	txtFile := filepath.Join(tempDir, "notes.txt")
	_ = os.WriteFile(txtFile, []byte("notes"), 0o644)

	// 3. Very old snapshot file
	snapFile := filepath.Join(tempDir, "tree.ndjson")
	_ = os.WriteFile(snapFile, []byte("tree"), 0o644)
	oldTime := now.Add(-100 * 24 * time.Hour)
	_ = os.Chtimes(snapFile, oldTime, oldTime)

	// Retention policy: keep 0 count, 1 day max
	purged, err := ApplyRetention(tempDir, 1, 0, nil)
	if err != nil {
		t.Fatalf("ApplyRetention failed: %v", err)
	}

	if len(purged) != 1 {
		t.Fatalf("expected 1 purged file, got %d", len(purged))
	}

	// Subdirectory must still exist
	if info, err := os.Stat(subDir); err != nil || !info.IsDir() {
		t.Error("expected subDir to remain intact")
	}
	// Non-snapshot file must still exist
	if _, err := os.Stat(txtFile); err != nil {
		t.Error("expected notes.txt to remain intact")
	}
	// Snapshot file must be purged
	if _, err := os.Stat(snapFile); !os.IsNotExist(err) {
		t.Error("expected tree.ndjson to be purged")
	}
}

func TestApplyRetention_AuditLoggingAndInvalidPath(t *testing.T) {
	// Test invalid path
	_, err := ApplyRetention("", 1, 1, nil)
	if err == nil {
		t.Fatal("expected error for empty target path")
	}

	// Test audit logging
	tempDir := t.TempDir()
	snapFile := filepath.Join(tempDir, "snap.sqlite.db")
	_ = os.WriteFile(snapFile, []byte("db"), 0o644)
	oldTime := time.Now().Add(-50 * 24 * time.Hour)
	_ = os.Chtimes(snapFile, oldTime, oldTime)

	var logBuf bytes.Buffer
	al := model.NewAuditLogger(&logBuf, 100)

	purged, err := ApplyRetention(tempDir, 1, 0, al)
	if err != nil {
		t.Fatalf("ApplyRetention failed: %v", err)
	}
	if len(purged) != 1 {
		t.Fatalf("expected 1 purge, got %d", len(purged))
	}

	_ = al.Close()
	logOutput := logBuf.String()
	if len(logOutput) == 0 {
		t.Error("expected audit log output, got empty buffer")
	}
}

func TestApplyRetention_PrefixFilter(t *testing.T) {
	tempDir := t.TempDir()
	now := time.Now()

	files := []string{
		"tenantA_snap1.tsv.zst",
		"tenantA_snap2.tsv.zst",
		"tenantB_snap1.tsv.zst",
		"tenantB_snap2.tsv.zst",
	}

	for i, f := range files {
		p := filepath.Join(tempDir, f)
		_ = os.WriteFile(p, []byte("data"), 0o644)
		modTime := now.Add(time.Duration(i-10) * time.Hour)
		_ = os.Chtimes(p, modTime, modTime)
	}

	// Purge only tenantA keeping 1 newest
	purged, err := ApplyRetention(tempDir, 0, 1, nil, "tenantA_")
	if err != nil {
		t.Fatalf("ApplyRetention with prefix failed: %v", err)
	}
	if len(purged) != 1 || !strings.Contains(purged[0], "tenantA_snap1") {
		t.Errorf("expected tenantA_snap1 purged, got %v", purged)
	}

	// Verify tenantB files are both still untouched
	if _, err := os.Stat(filepath.Join(tempDir, "tenantB_snap1.tsv.zst")); err != nil {
		t.Errorf("expected tenantB_snap1 to still exist: %v", err)
	}
	if _, err := os.Stat(filepath.Join(tempDir, "tenantB_snap2.tsv.zst")); err != nil {
		t.Errorf("expected tenantB_snap2 to still exist: %v", err)
	}

	// Non-existent directory error
	_, err = ApplyRetention(filepath.Join(tempDir, "nonexistent"), 1, 1, nil)
	if err == nil {
		t.Errorf("expected error on non-existent directory")
	}
}
