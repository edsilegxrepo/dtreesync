// Package e2e_test provides end-to-end integration tests across full synchronization lifecycles.
//
// Objectives:
//   - Verify complete multi-format roundtrip fidelity (NDJSON+Zstd, TSV+Zstd, SQLite).
//   - Validate cross-environment base substitution during restoration.
//   - Ensure cryptographic tamper detection catches unauthorized payload alterations.
//
// Test Strategy:
//   - Multi-Format Lifecycle: TestE2E_FullRoundtrip_AllFormats generates a synthetic multi-partner directory mesh,
//     executes Backup, confirms validity with Verify, materializes at a new target via Restore, and proves 100%
//     alignment with zero drift via Diff across NDJSON, TSV, and SQLite.
//   - Base Substitution: TestE2E_BaseSubstitution tests directory re-rooting from source_original to rebased_target.
//   - Tamper Detection: TestE2E_TamperedSnapshotDetection appends an unauthorized record to an existing snapshot and
//     confirms that Verify detects cryptographic SHA-256 hash mismatch.
//
// Data Flow:
//
//	testgen.Generate() -> dtreesync.Backup() -> Snapshot Artifact -> dtreesync.Verify()
//	-> dtreesync.Restore() -> dtreesync.Diff() -> Zero Drift Assertion.
package e2e_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/edsilegxrepo/dtreesync/pkg/dtreesync"
	"github.com/edsilegxrepo/dtreesync/test/testgen"
)

func TestE2E_FullRoundtrip_AllFormats(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	formats := []struct {
		name        string
		format      dtreesync.FormatType
		compression dtreesync.CompressionType
		extension   string
	}{
		{"NDJSON_Zstd", dtreesync.FormatNDJSON, dtreesync.CompressionZstd, ".ndjson.zst"},
		{"TSV_Zstd", dtreesync.FormatTSV, dtreesync.CompressionZstd, ".tsv.zst"},
		{"SQLite", dtreesync.FormatSQLite, dtreesync.CompressionNone, ".sqlite"},
	}

	for _, tc := range formats {
		t.Run(tc.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			sourceDir := filepath.Join(tmpDir, "source")
			restoreDir := filepath.Join(tmpDir, "restored")
			snapshotFile := filepath.Join(tmpDir, "snapshot"+tc.extension)

			// 1. Generate synthetic directory mesh with dummy files
			stats, err := testgen.Generate(testgen.GeneratorConfig{
				BaseDir:         sourceDir,
				NumPartners:     4,
				SubdirsPerLevel: 2,
				Depth:           3,
				FilesPerDir:     2,
				Seed:            12345,
			})
			if err != nil {
				t.Fatalf("Failed to generate test mesh: %v", err)
			}
			if stats.TotalDirs == 0 {
				t.Fatalf("Expected non-zero generated dirs")
			}

			// 2. Execute Backup
			bRes, err := dtreesync.Backup(ctx, dtreesync.BackupConfig{
				BaseFolder:  sourceDir,
				TargetURL:   snapshotFile,
				Format:      tc.format,
				Compression: tc.compression,
				Workers:     4,
			})
			if err != nil {
				t.Fatalf("Backup failed: %v", err)
			}
			// bRes.FolderCount includes root + subdirs
			if bRes.FolderCount < stats.TotalDirs {
				t.Errorf("Expected at least %d dirs, got %d", stats.TotalDirs, bRes.FolderCount)
			}

			// 3. Status - Inspect Snapshot Metadata Header
			f, err := os.Open(snapshotFile)
			if err != nil {
				t.Fatalf("Failed to open snapshot for status inspection: %v", err)
			}
			hdr, err := dtreesync.InspectHeader(ctx, f)
			_ = f.Close()
			if err != nil {
				t.Fatalf("Status inspection failed: %v", err)
			}
			if hdr.FolderCount != bRes.FolderCount {
				t.Errorf("Status folder count mismatch: got %d, want %d", hdr.FolderCount, bRes.FolderCount)
			}
			if hdr.PayloadSHA256 != bRes.SHA256Hash {
				t.Errorf("Status SHA256 mismatch: got %s, want %s", hdr.PayloadSHA256, bRes.SHA256Hash)
			}

			// 4. Verify Snapshot
			vRes, err := dtreesync.Verify(ctx, dtreesync.VerifyConfig{
				SourceURL: snapshotFile,
				Workers:   4,
			})
			if err != nil {
				t.Fatalf("Verify failed: %v", err)
			}
			if !vRes.ChecksumValid || !vRes.FramesValid || !vRes.SyntaxValid {
				t.Errorf("Verification failed: %+v", vRes)
			}

			// 5. Execute Restore
			rRes, err := dtreesync.Restore(ctx, dtreesync.RestoreConfig{
				SourceURL:    snapshotFile,
				TargetFolder: restoreDir,
				Workers:      4,
			})
			if err != nil {
				t.Fatalf("Restore failed: %v", err)
			}
			if rRes.CreatedFolders != bRes.FolderCount {
				t.Errorf("Created folders mismatch: got %d, want %d", rRes.CreatedFolders, bRes.FolderCount)
			}

			// 6. Diff Live vs Snapshot
			dRes, err := dtreesync.Diff(ctx, dtreesync.DiffConfig{
				SnapshotURL: snapshotFile,
				LiveFolder:  restoreDir,
				Workers:     4,
			})
			if err != nil {
				t.Fatalf("Diff failed: %v", err)
			}
			if dRes.TotalDrift != 0 {
				t.Errorf("Expected 0 drift on clean restore, got %d items: %+v", dRes.TotalDrift, dRes.DriftItems)
			}
		})
	}
}

func TestE2E_BaseSubstitution(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmpDir := t.TempDir()
	sourceDir := filepath.Join(tmpDir, "source_original")
	rebasedDir := filepath.Join(tmpDir, "rebased_target")
	snapshotFile := filepath.Join(tmpDir, "snapshot.ndjson.zst")

	if err := os.MkdirAll(filepath.Join(sourceDir, "apps", "conf"), 0o755); err != nil {
		t.Fatalf("Failed to create source dirs: %v", err)
	}

	// Backup
	_, err := dtreesync.Backup(ctx, dtreesync.BackupConfig{
		BaseFolder: sourceDir,
		TargetURL:  snapshotFile,
		Workers:    2,
	})
	if err != nil {
		t.Fatalf("Backup failed: %v", err)
	}

	// Restore with base substitution
	subArg := sourceDir + "," + rebasedDir
	rRes, err := dtreesync.Restore(ctx, dtreesync.RestoreConfig{
		SourceURL:      snapshotFile,
		TargetFolder:   rebasedDir,
		BaseSubstitute: subArg,
		Workers:        2,
	})
	if err != nil {
		t.Fatalf("Restore with base substitution failed: %v", err)
	}
	if rRes.CreatedFolders != 3 {
		t.Errorf("Expected 3 folders restored under rebased root, got %d", rRes.CreatedFolders)
	}
	if _, err := os.Stat(filepath.Join(rebasedDir, "apps", "conf")); err != nil {
		t.Errorf("Expected rebased folder apps/conf to exist: %v", err)
	}
}

func TestE2E_TamperedSnapshotDetection(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	tmpDir := t.TempDir()
	sourceDir := filepath.Join(tmpDir, "source")
	snapshotFile := filepath.Join(tmpDir, "tampered.tsv")

	if err := os.MkdirAll(filepath.Join(sourceDir, "test_dir"), 0o755); err != nil {
		t.Fatalf("Failed to create dir: %v", err)
	}

	// Create uncompressed TSV snapshot
	_, err := dtreesync.Backup(ctx, dtreesync.BackupConfig{
		BaseFolder:  sourceDir,
		TargetURL:   snapshotFile,
		Format:      dtreesync.FormatTSV,
		Compression: dtreesync.CompressionNone,
		Workers:     1,
	})
	if err != nil {
		t.Fatalf("Backup failed: %v", err)
	}

	// Tamper with file by appending an extra record without updating header hash
	f, err := os.OpenFile(snapshotFile, os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		t.Fatalf("Failed to open snapshot: %v", err)
	}
	_, _ = f.WriteString("tampered_entity\ttampered_path\t0755\t1000\t1000\t-\t-\t-\t-\t-\t-\t-\t0\n")
	_ = f.Close()

	// Verify must catch cryptographic tamper
	vRes, err := dtreesync.Verify(ctx, dtreesync.VerifyConfig{
		SourceURL: snapshotFile,
		Workers:   1,
	})
	if err == nil {
		t.Fatalf("Expected Verify to fail on tampered snapshot, but it succeeded: %+v", vRes)
	}
	if vRes.ChecksumValid {
		t.Errorf("Expected ChecksumValid to be false")
	}
}
