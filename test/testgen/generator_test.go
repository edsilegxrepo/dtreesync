// Package testgen provides unit tests for synthetic directory generation.
//
// Objectives:
//   - Validate deterministic synthetic tree creation with controllable parameters.
//   - Test default fallback parameters and error handling on unwritable targets.
//
// Test Strategy:
//   - Defaults Verification: TestGenerate_Defaults verifies that zero values trigger appropriate standard defaults.
//   - Topology Verification: TestGenerate_CustomTopology asserts directory and file count invariants against formula.
//   - Error Handling: TestGenerate_InvalidBaseDir validates failure reporting on invalid paths.
package testgen

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGenerate_Defaults(t *testing.T) {
	tempDir := t.TempDir()

	stats, err := Generate(GeneratorConfig{
		BaseDir:         tempDir,
		NumPartners:     0, // triggers default
		SubdirsPerLevel: 0, // triggers default
		Depth:           0, // triggers default
		Seed:            0, // triggers default
		FilesPerDir:     1,
	})
	if err != nil {
		t.Fatalf("Generate with defaults failed: %v", err)
	}
	if stats.TotalDirs == 0 || stats.TotalFiles == 0 {
		t.Errorf("expected non-zero dirs and files, got %+v", stats)
	}
}

func TestGenerate_CustomTopology(t *testing.T) {
	tempDir := t.TempDir()

	stats, err := Generate(GeneratorConfig{
		BaseDir:         tempDir,
		NumPartners:     2,
		SubdirsPerLevel: 2,
		Depth:           2,
		FilesPerDir:     2,
		Seed:            12345,
	})
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	if stats.TotalDirs != 6 { // 2 partners + 2*2 subdirs = 6 dirs
		t.Errorf("expected 6 total dirs, got %d", stats.TotalDirs)
	}
	if stats.TotalFiles != 8 { // 4 subdirs * 2 files = 8 files
		t.Errorf("expected 8 total files, got %d", stats.TotalFiles)
	}
}

func TestGenerate_InvalidBaseDir(t *testing.T) {
	// Provide a file as BaseDir where MkdirAll partner will fail
	tempFile := filepath.Join(t.TempDir(), "not_a_dir")
	_ = os.WriteFile(tempFile, []byte("data"), 0o644)

	_, err := Generate(GeneratorConfig{
		BaseDir: tempFile,
	})
	if err == nil {
		t.Errorf("expected error when BaseDir is a file, got nil")
	}
}
