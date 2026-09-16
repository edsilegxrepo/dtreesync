// Package core provides unit tests for directory tree scanning and filtering.
//
// Objectives:
//   - Validate directory hierarchy discovery correctness, channel streaming, and concurrency.
//   - Enforce the Zero-Payload File I/O architectural invariant: regular files must never leak into DirRecords.
//   - Verify path exclusion and pattern matching rules.
//
// Test Strategy:
//   - Zero-Payload Invariant: TestScanner_DiscoveryAndZeroFileOverhead creates nested directories interspersed with
//     payload files, streams the scan, and asserts that exactly 100% of directories and 0% of files are emitted.
//   - Glob Filter Exclusion: TestScanner_Exclusion verifies that directory subtrees matching exclusion patterns
//     are pruned immediately during discovery.
//
// Data Flow:
//
//	Temp Directory Tree -> Scanner.Stream() -> Output Channel -> Directory Count & Zero-File Assertions.
package core

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/edsilegxrepo/dtreesync/internal/model"
)

func TestScanner_DiscoveryAndZeroFileOverhead(t *testing.T) {
	tempRoot := t.TempDir()

	// Create test tree:
	// partner_a/
	//   inbound/
	//     payload1.bin (FILE)
	//     payload2.bin (FILE)
	//   outbound/
	// partner_b/
	//   archive/
	//     2026/
	//   large_file.iso (FILE)
	dirs := []string{
		"partner_a/inbound",
		"partner_a/outbound",
		"partner_b/archive/2026",
	}
	for _, d := range dirs {
		if err := os.MkdirAll(filepath.Join(tempRoot, d), 0o755); err != nil {
			t.Fatalf("failed to create test dir: %v", err)
		}
	}

	// Create files (which must be completely ignored by the scanner)
	files := []string{
		"partner_a/inbound/payload1.bin",
		"partner_a/inbound/payload2.bin",
		"partner_b/large_file.iso",
	}
	for _, f := range files {
		if err := os.WriteFile(filepath.Join(tempRoot, f), []byte("dummy-file-data"), 0o644); err != nil {
			t.Fatalf("failed to write dummy file: %v", err)
		}
	}

	opts := model.ScanOptions{
		Workers: 4,
	}

	scanner, err := NewScanner(tempRoot, opts, nil)
	if err != nil {
		t.Fatalf("NewScanner failed: %v", err)
	}

	recChan := make(chan model.DirRecord, 100)
	ctx := context.Background()

	errChan := make(chan error, 1)
	go func() {
		errChan <- scanner.Stream(ctx, recChan)
	}()

	var records []model.DirRecord
	for rec := range recChan {
		records = append(records, rec)
	}

	if streamErr := <-errChan; streamErr != nil {
		t.Fatalf("scanner.Stream failed: %v", streamErr)
	}

	// Expected directories:
	// 1. Root ("")
	// 2. partner_a
	// 3. partner_a/inbound
	// 4. partner_a/outbound
	// 5. partner_b
	// 6. partner_b/archive
	// 7. partner_b/archive/2026
	// Total = 7 directories. Files must NOT be present!
	if len(records) != 7 {
		t.Fatalf("expected 7 directory records, got %d", len(records))
	}

	foundPaths := make(map[string]bool)
	for _, r := range records {
		foundPaths[r.RelPath] = true
	}

	expectedPaths := []string{
		"",
		"partner_a",
		"partner_a/inbound",
		"partner_a/outbound",
		"partner_b",
		"partner_b/archive",
		"partner_b/archive/2026",
	}

	for _, ep := range expectedPaths {
		if !foundPaths[ep] {
			t.Errorf("missing expected path %q", ep)
		}
	}

	// Verify no file paths leaked into records
	for _, f := range files {
		if foundPaths[f] {
			t.Errorf("violation of zero file overhead: file %q found in records", f)
		}
	}
}

func TestScanner_Exclusion(t *testing.T) {
	tempRoot := t.TempDir()

	_ = os.MkdirAll(filepath.Join(tempRoot, "keep/subdir"), 0o755)
	_ = os.MkdirAll(filepath.Join(tempRoot, "skip/subdir"), 0o755)

	opts := model.ScanOptions{
		Workers: 2,
		Exclude: []string{"skip*"},
	}

	scanner, err := NewScanner(tempRoot, opts, nil)
	if err != nil {
		t.Fatalf("NewScanner failed: %v", err)
	}

	recChan := make(chan model.DirRecord, 50)
	go func() {
		_ = scanner.Stream(context.Background(), recChan)
	}()

	for rec := range recChan {
		if rec.RelPath == "skip" || rec.RelPath == "skip/subdir" {
			t.Fatalf("excluded directory %q was discovered", rec.RelPath)
		}
	}
}

func TestScanner_IncludeAndTraversable(t *testing.T) {
	tempRoot := t.TempDir()

	_ = os.MkdirAll(filepath.Join(tempRoot, "partner_a/inbound/orders"), 0o755)
	_ = os.MkdirAll(filepath.Join(tempRoot, "partner_b/outbound"), 0o755)

	opts := model.ScanOptions{
		Workers: 2,
		Include: []string{"partner_a/inbound/**"},
	}

	scanner, err := NewScanner(tempRoot, opts, nil)
	if err != nil {
		t.Fatalf("NewScanner failed: %v", err)
	}

	// Test isTraversable helper logic
	if !scanner.isTraversable("partner_a") {
		t.Error("expected partner_a to be traversable as prefix of include")
	}
	if !scanner.isTraversable("partner_a/inbound") {
		t.Error("expected partner_a/inbound to be traversable")
	}
	if scanner.isTraversable("partner_b") {
		t.Error("expected partner_b not to be traversable")
	}

	// Test isMatchInclude
	if !scanner.isMatchInclude("") {
		t.Error("root must always match include")
	}
	if !scanner.isMatchInclude("partner_a/inbound/orders") {
		t.Error("expected partner_a/inbound/orders to match include")
	}
	if scanner.isMatchInclude("partner_a") {
		t.Error("expected intermediate partner_a not to match include pattern")
	}

	recChan := make(chan model.DirRecord, 50)
	ctx := context.Background()
	go func() {
		_ = scanner.Stream(ctx, recChan)
	}()

	var streamed []string
	for rec := range recChan {
		streamed = append(streamed, rec.RelPath)
	}

	if len(streamed) == 0 {
		t.Errorf("expected streamed records > 0, got 0")
	}

	if scanner.ScannedCount() == 0 {
		t.Errorf("expected ScannedCount > 0, got %d", scanner.ScannedCount())
	}
}

func TestScanner_OneFileSystemBoundary(t *testing.T) {
	tempRoot := t.TempDir()
	subDir := filepath.Join(tempRoot, "mount_boundary", "sub")
	if err := os.MkdirAll(subDir, 0o755); err != nil {
		t.Fatalf("failed to create test directory: %v", err)
	}

	scanner, err := NewScanner(tempRoot, model.ScanOptions{
		Workers:       2,
		OneFileSystem: true,
	}, nil)
	if err != nil {
		t.Fatalf("NewScanner with OneFileSystem failed: %v", err)
	}

	ctx := context.Background()
	recChan := make(chan model.DirRecord, 10)
	go func() {
		_ = scanner.Stream(ctx, recChan)
	}()

	var records []model.DirRecord
	for r := range recChan {
		records = append(records, r)
	}

	if len(records) < 3 {
		t.Errorf("expected at least 3 records with OneFileSystem: true, got %d", len(records))
	}
}
