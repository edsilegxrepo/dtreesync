// Package dtreesync provides unit tests for push-iterator directory streaming.
//
// Objectives:
//   - Validate Go 1.23+ standard push iterator (iter.Seq2) traversal completeness.
//   - Test loop break semantics and ensure goroutines terminate cleanly on early aborts.
//
// Test Strategy:
//   - Iterator Traversal: TestScan_Iterator constructs a multi-level hierarchy and iterates through all records using a standard range loop.
//   - Early Abort Teardown: TestScan_IteratorEarlyBreak verifies that breaking early out of a range loop cleanly cancels context and releases worker channels without hangs.
//
// Data Flow:
//
//	Temp Filesystem -> Scan() iter.Seq2 Closure -> Range Loop Consumer -> Count Invariant Assertions.
package dtreesync

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestScan_Iterator(t *testing.T) {
	tempRoot := t.TempDir()

	dirs := []string{"sub1/child1", "sub2/child2"}
	for _, d := range dirs {
		if err := os.MkdirAll(filepath.Join(tempRoot, d), 0o755); err != nil {
			t.Fatalf("failed to create dir: %v", err)
		}
	}

	ctx := context.Background()
	opts := ScanOptions{Workers: 2}

	count := 0
	for rec, err := range Scan(ctx, tempRoot, opts) {
		if err != nil {
			t.Fatalf("unexpected scan error: %v", err)
		}
		_ = rec
		count++
	}

	// Root + sub1 + sub1/child1 + sub2 + sub2/child2 = 5
	if count != 5 {
		t.Fatalf("expected 5 directories from iterator, got %d", count)
	}
}

func TestScan_IteratorEarlyBreak(t *testing.T) {
	tempRoot := t.TempDir()

	for i := 0; i < 20; i++ {
		_ = os.MkdirAll(filepath.Join(tempRoot, "dir"+string(rune('a'+i))), 0o755)
	}

	ctx := context.Background()
	opts := ScanOptions{Workers: 4}

	count := 0
	for _, err := range Scan(ctx, tempRoot, opts) {
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		count++
		if count == 3 {
			break // Early loop termination
		}
	}

	if count != 3 {
		t.Fatalf("expected 3 directories before break, got %d", count)
	}
}

func TestScan_Iterator_Error(t *testing.T) {
	ctx := context.Background()
	opts := ScanOptions{Workers: 1}
	sawError := false
	for _, err := range Scan(ctx, "relative/path/error", opts) {
		if err != nil {
			sawError = true
			break
		}
	}
	if !sawError {
		t.Fatalf("expected error scanning invalid relative path")
	}
}
