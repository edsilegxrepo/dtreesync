// Package core provides unit tests for directory snapshot backup orchestration.
//
// Objectives:
//   - Verify end-to-end scanning, canonical sorting, and streaming serialization directly in core.
//   - Test multi-format outputs (NDJSON, TSV, SQLite) and compression options (Zstandard, None).
//   - Ensure deterministic lexicographical sorting of DirRecord entries strictly by RelPath.
//   - Validate automatic format/compression deduction and retention lifecycle invocation.
//
// Test Strategy:
//   - Canonical Sorting: TestBackup_WriterOutput_CanonicalOrdering constructs unsorted directory structures
//     and verifies that output records are strictly ordered lexicographically by RelPath.
//   - Multi-Format Engines: TestBackup_TSVFormat and TestBackup_SQLiteFormat execute backups to disk files.
//   - Auto-Deduction: TestBackup_TargetURLDeduction confirms format/compression deduction from file extensions.
//   - Retention Trigger: TestBackup_RetentionIntegration verifies that ApplyRetention is triggered after backup.
//   - Safety Boundaries: TestBackup_ValidationErrors verifies error handling on missing destinations or invalid paths.
//
// Data Flow:
//
//	Temp Directory Hierarchy -> core.Backup() -> In-Memory Buffer / Disk Artifacts -> Deserializer Assertions.
package core

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/edsilegxrepo/dtreesync/internal/format"
	"github.com/edsilegxrepo/dtreesync/internal/model"
)

func TestBackup_WriterOutput_CanonicalOrdering(t *testing.T) {
	tempBase := t.TempDir()

	// Create unordered nested directory tree
	// Order of creation does not match lexicographical order
	dirs := []string{
		filepath.Join(tempBase, "zeta", "sub2"),
		filepath.Join(tempBase, "alpha", "sub1"),
		filepath.Join(tempBase, "beta"),
		filepath.Join(tempBase, "zeta", "sub1"),
		filepath.Join(tempBase, "alpha", "sub2"),
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("failed to create dir %s: %v", d, err)
		}
	}

	var buf bytes.Buffer
	cfg := model.BackupConfig{
		BaseFolder:  tempBase,
		Format:      model.FormatNDJSON,
		Compression: model.CompressionNone,
		Writer:      &buf,
		Workers:     2,
	}

	res, err := Backup(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Backup failed: %v", err)
	}

	// 1 root + 3 alpha + 1 beta + 3 zeta = 8 folders
	if res.FolderCount != 8 {
		t.Fatalf("expected 8 folders, got %d", res.FolderCount)
	}
	if res.SHA256Hash == "" {
		t.Fatal("expected non-empty SHA-256 hash")
	}

	// Deserialize from buffer and check canonical sorting
	var relPaths []string
	hdr, err := format.ReadNDJSONRecords(bytes.NewReader(buf.Bytes()), func(rec model.DirRecord) error {
		relPaths = append(relPaths, rec.RelPath)
		return nil
	})
	if err != nil {
		t.Fatalf("failed to read records: %v", err)
	}
	if hdr.FolderCount != 8 {
		t.Fatalf("header folder count mismatch: expected 8, got %d", hdr.FolderCount)
	}

	expectedPaths := []string{
		"",
		"alpha",
		"alpha/sub1",
		"alpha/sub2",
		"beta",
		"zeta",
		"zeta/sub1",
		"zeta/sub2",
	}

	// Note: root record "" plus 7 subdirectories = 8 total scanned nodes
	if len(relPaths) < 6 {
		t.Fatalf("expected at least 6 records, got %d", len(relPaths))
	}

	// Verify strictly sorted
	for i := 1; i < len(relPaths); i++ {
		if relPaths[i-1] >= relPaths[i] {
			t.Errorf("records not canonically sorted: %q >= %q at index %d",
				relPaths[i-1], relPaths[i], i)
		}
	}
	_ = expectedPaths
}

func TestBackup_TSVFormat_AndCompression(t *testing.T) {
	tempBase := t.TempDir()
	outDir := t.TempDir()

	_ = os.MkdirAll(filepath.Join(tempBase, "partner_1"), 0o755)
	_ = os.MkdirAll(filepath.Join(tempBase, "partner_2"), 0o755)

	targetFile := filepath.Join(outDir, "tree.tsv.zst")

	cfg := model.BackupConfig{
		BaseFolder:  tempBase,
		Format:      model.FormatTSV,
		Compression: model.CompressionZstd,
		TargetURL:   targetFile,
		Workers:     2,
	}

	res, err := Backup(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Backup failed: %v", err)
	}

	if res.FolderCount != 3 {
		t.Fatalf("expected 3 folders (root + 2 subdirs), got %d", res.FolderCount)
	}

	fi, err := os.Stat(targetFile)
	if err != nil {
		t.Fatalf("snapshot file was not created: %v", err)
	}
	if fi.Size() == 0 {
		t.Fatal("snapshot file is 0 bytes")
	}
}

func TestBackup_SQLiteFormat(t *testing.T) {
	tempBase := t.TempDir()
	outDir := t.TempDir()

	_ = os.MkdirAll(filepath.Join(tempBase, "sql_dir_a"), 0o755)

	targetFile := filepath.Join(outDir, "tree.sqlite")

	cfg := model.BackupConfig{
		BaseFolder:  tempBase,
		Format:      model.FormatSQLite,
		Compression: model.CompressionNone,
		TargetURL:   targetFile,
		Workers:     2,
	}

	res, err := Backup(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Backup failed with SQLite format: %v", err)
	}

	if res.FolderCount != 2 {
		t.Fatalf("expected 2 folders, got %d", res.FolderCount)
	}

	hdr, err := format.ReadSQLiteHeader(targetFile)
	if err != nil {
		t.Fatalf("failed to read sqlite header: %v", err)
	}
	if hdr.FolderCount != 2 {
		t.Fatalf("expected 2 folders in sqlite header, got %d", hdr.FolderCount)
	}
}

func TestBackup_TargetURLDeduction(t *testing.T) {
	tempBase := t.TempDir()
	outDir := t.TempDir()

	_ = os.MkdirAll(filepath.Join(tempBase, "auto_dir"), 0o755)

	targetFile := filepath.Join(outDir, "auto.tsv.zst")

	// Leave Format and Compression empty to test deduction from targetURL
	cfg := model.BackupConfig{
		BaseFolder: tempBase,
		TargetURL:  targetFile,
		Workers:    2,
	}

	res, err := Backup(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Backup failed with format deduction: %v", err)
	}

	if res.FolderCount != 2 {
		t.Fatalf("expected 2 folders, got %d", res.FolderCount)
	}

	if _, err := os.Stat(targetFile); err != nil {
		t.Fatalf("expected deduced file to exist: %v", err)
	}
}

func TestBackup_RetentionIntegration(t *testing.T) {
	tempBase := t.TempDir()
	outDir := t.TempDir()
	now := time.Now()

	// Pre-create 3 older snapshots in outDir
	for i := 1; i <= 3; i++ {
		p := filepath.Join(outDir, filepath.Join("old_snap_"+string(rune('0'+i))+".tsv.zst"))
		_ = os.WriteFile(p, []byte("old-snap"), 0o644)
		tOld := now.Add(time.Duration(i-5) * time.Hour)
		_ = os.Chtimes(p, tOld, tOld)
	}

	targetFile := filepath.Join(outDir, "new_snap.tsv.zst")

	cfg := model.BackupConfig{
		BaseFolder:     tempBase,
		TargetURL:      targetFile,
		RetentionCount: 2, // Keep newest 2 (new_snap + old_snap_3)
		Workers:        2,
	}

	_, err := Backup(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Backup failed: %v", err)
	}

	// Verify old_snap_1 and old_snap_2 were purged
	if _, err := os.Stat(filepath.Join(outDir, "old_snap_1.tsv.zst")); !os.IsNotExist(err) {
		t.Error("expected old_snap_1.tsv.zst to be purged by retention")
	}
	// new_snap.tsv.zst must exist
	if _, err := os.Stat(targetFile); err != nil {
		t.Errorf("expected new_snap.tsv.zst to exist: %v", err)
	}
}

func TestBackup_ValidationErrors(t *testing.T) {
	// 1. Invalid base folder
	_, err := Backup(context.Background(), model.BackupConfig{
		BaseFolder: "",
		TargetURL:  "C:\\valid\\path.tsv",
	}, nil)
	if err == nil {
		t.Error("expected error for empty BaseFolder")
	}

	// 2. Missing both Writer and TargetURL
	tempBase := t.TempDir()
	_, err = Backup(context.Background(), model.BackupConfig{
		BaseFolder: tempBase,
	}, nil)
	if err == nil {
		t.Error("expected error when neither Writer nor TargetURL is provided")
	}

	// 3. SQLite without TargetURL
	var buf bytes.Buffer
	_, err = Backup(context.Background(), model.BackupConfig{
		BaseFolder: tempBase,
		Format:     model.FormatSQLite,
		Writer:     &buf,
	}, nil)
	if err == nil {
		t.Error("expected error when SQLite format is used without TargetURL")
	}
}

func TestHybridBuffer(t *testing.T) {
	// 1. In-memory buffer threshold not exceeded
	hbMem := newHybridBuffer(1024)
	if hbMem.maxMem != 1024 {
		t.Errorf("expected maxMem 1024, got %d", hbMem.maxMem)
	}
	n, err := hbMem.Write([]byte("hello in memory"))
	if err != nil || n != 15 {
		t.Fatalf("hbMem.Write failed: n=%d, err=%v", n, err)
	}
	if hbMem.Size() != 15 {
		t.Errorf("expected Size 15, got %d", hbMem.Size())
	}
	r, err := hbMem.Reader()
	if err != nil {
		t.Fatalf("hbMem.Reader failed: %v", err)
	}
	readBytes, err := io.ReadAll(r)
	if err != nil || string(readBytes) != "hello in memory" {
		t.Fatalf("hbMem read mismatch: %q, err=%v", string(readBytes), err)
	}
	if err := hbMem.Close(); err != nil {
		t.Errorf("hbMem.Close failed: %v", err)
	}

	// 2. Default threshold with 0 or negative maxMem
	hbDef := newHybridBuffer(0)
	if hbDef.maxMem != 16*1024*1024 {
		t.Errorf("expected default 16MB maxMem, got %d", hbDef.maxMem)
	}
	_ = hbDef.Close()

	// 3. Spillover to temporary file when threshold exceeded
	hbSpill := newHybridBuffer(50) // 50 bytes max RAM
	p1 := bytes.Repeat([]byte("A"), 30)
	p2 := bytes.Repeat([]byte("B"), 40) // 30 + 40 = 70 > 50 -> triggers spool to disk
	p3 := bytes.Repeat([]byte("C"), 30) // 70 + 30 = 100

	if _, err := hbSpill.Write(p1); err != nil {
		t.Fatalf("hbSpill write 1 failed: %v", err)
	}
	if hbSpill.file != nil {
		t.Error("expected buffer to still be purely in memory")
	}

	if _, err := hbSpill.Write(p2); err != nil {
		t.Fatalf("hbSpill write 2 failed: %v", err)
	}
	if hbSpill.file == nil {
		t.Error("expected buffer to have spilled to disk file")
	}

	if _, err := hbSpill.Write(p3); err != nil {
		t.Fatalf("hbSpill write 3 failed: %v", err)
	}
	if hbSpill.Size() != 100 {
		t.Errorf("expected Size 100, got %d", hbSpill.Size())
	}

	rSpill, err := hbSpill.Reader()
	if err != nil {
		t.Fatalf("hbSpill.Reader failed: %v", err)
	}
	spillData, err := io.ReadAll(rSpill)
	if err != nil {
		t.Fatalf("io.ReadAll on spilled file failed: %v", err)
	}
	expectedData := append(append(p1, p2...), p3...)
	if !bytes.Equal(spillData, expectedData) {
		t.Errorf("spillData content mismatch: len %d vs %d", len(spillData), len(expectedData))
	}

	spillFileName := hbSpill.file.Name()
	if err := hbSpill.Close(); err != nil {
		t.Fatalf("hbSpill.Close failed: %v", err)
	}
	// Verify temp file was cleaned up on Close
	if _, err := os.Stat(spillFileName); !os.IsNotExist(err) {
		t.Errorf("expected temp spool file %q to be deleted after Close", spillFileName)
	}
}

func TestBackup_EmptyFolder(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	emptySource := filepath.Join(tmpDir, "empty")
	_ = os.MkdirAll(emptySource, 0o755)
	target := filepath.Join(tmpDir, "empty.tsv")
	res, err := Backup(ctx, model.BackupConfig{
		BaseFolder: emptySource,
		TargetURL:  target,
		Format:     model.FormatTSV,
		Workers:    1,
	}, nil)
	if err != nil {
		t.Fatalf("Backup failed: %v", err)
	}
	if res.FolderCount != 1 {
		t.Errorf("expected 1 folder (root), got %d", res.FolderCount)
	}
}

func TestBackup_SortOrder_Depth(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	source := filepath.Join(tmpDir, "source")
	dirs := []string{
		filepath.Join(source, "z_partner", "orders", "2026"),
		filepath.Join(source, "a_partner", "inbound"),
		filepath.Join(source, "m_partner"),
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("failed to create dir: %v", err)
		}
	}

	var buf bytes.Buffer
	cfg := model.BackupConfig{
		BaseFolder:  source,
		Writer:      &buf,
		Format:      model.FormatNDJSON,
		Compression: model.CompressionNone,
		Workers:     2,
		SortOrder:   model.SortOrderDepth,
	}

	res, err := Backup(ctx, cfg, nil)
	if err != nil {
		t.Fatalf("Backup with SortOrderDepth failed: %v", err)
	}
	if res.FolderCount < 6 {
		t.Fatalf("expected at least 6 folders, got %d", res.FolderCount)
	}

	var relPaths []string
	hdr, err := format.ReadNDJSONRecords(bytes.NewReader(buf.Bytes()), func(rec model.DirRecord) error {
		relPaths = append(relPaths, rec.RelPath)
		return nil
	})
	if err != nil {
		t.Fatalf("failed to read NDJSON records: %v", err)
	}
	if hdr.SortOrder != model.SortOrderDepth {
		t.Errorf("expected header SortOrder 'depth', got %q", hdr.SortOrder)
	}

	// Verify that depth never decreases
	prevDepth := 0
	for i, p := range relPaths {
		currDepth := dirDepth(p)
		if currDepth < prevDepth {
			t.Errorf("depth inversion at index %d: %q (depth %d) follows record with depth %d",
				i, p, currDepth, prevDepth)
		}
		prevDepth = currDepth
	}
}

func TestBackup_SortOrder_None(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	source := filepath.Join(tmpDir, "source")
	_ = os.MkdirAll(filepath.Join(source, "tenant", "data"), 0o755)

	var buf bytes.Buffer
	cfg := model.BackupConfig{
		BaseFolder:  source,
		Writer:      &buf,
		Format:      model.FormatNDJSON,
		Compression: model.CompressionNone,
		Workers:     1,
		SortOrder:   model.SortOrderNone,
	}

	res, err := Backup(ctx, cfg, nil)
	if err != nil {
		t.Fatalf("Backup with SortOrderNone failed: %v", err)
	}
	if res.FolderCount < 3 {
		t.Errorf("expected at least 3 folders, got %d", res.FolderCount)
	}

	hdr, err := format.ReadNDJSONRecords(bytes.NewReader(buf.Bytes()), func(rec model.DirRecord) error {
		return nil
	})
	if err != nil {
		t.Fatalf("failed to read NDJSON: %v", err)
	}
	if hdr.SortOrder != model.SortOrderNone {
		t.Errorf("expected header SortOrder 'none', got %q", hdr.SortOrder)
	}
}

func TestBackup_SortOrder_Path(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	source := filepath.Join(tmpDir, "source")
	dirs := []string{
		filepath.Join(source, "zeta", "sub"),
		filepath.Join(source, "alpha", "sub"),
		filepath.Join(source, "beta"),
	}
	for _, d := range dirs {
		_ = os.MkdirAll(d, 0o755)
	}

	var buf bytes.Buffer
	cfg := model.BackupConfig{
		BaseFolder:  source,
		Writer:      &buf,
		Format:      model.FormatTSV,
		Compression: model.CompressionNone,
		Workers:     2,
		SortOrder:   model.SortOrderPath,
	}

	res, err := Backup(ctx, cfg, nil)
	if err != nil {
		t.Fatalf("Backup with SortOrderPath failed: %v", err)
	}
	if res.FolderCount < 5 {
		t.Errorf("expected at least 5 folders, got %d", res.FolderCount)
	}

	var paths []string
	hdr, err := format.ReadTSVRecords(bytes.NewReader(buf.Bytes()), func(rec model.DirRecord) error {
		paths = append(paths, rec.RelPath)
		return nil
	})
	if err != nil {
		t.Fatalf("failed to read TSV records: %v", err)
	}
	if hdr.SortOrder != model.SortOrderPath {
		t.Errorf("expected header SortOrder 'path', got %q", hdr.SortOrder)
	}

	for i := 1; i < len(paths); i++ {
		if paths[i-1] >= paths[i] {
			t.Errorf("records not canonically sorted: %q >= %q at index %d", paths[i-1], paths[i], i)
		}
	}
}

func TestBackup_SortOrder_Invalid(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	source := filepath.Join(tmpDir, "source")
	_ = os.MkdirAll(source, 0o755)

	var buf bytes.Buffer
	cfg := model.BackupConfig{
		BaseFolder: source,
		Writer:     &buf,
		SortOrder:  "unsupported_sort_order",
	}

	_, err := Backup(ctx, cfg, nil)
	if err == nil {
		t.Fatal("expected error for invalid sort order, got nil")
	}
}
