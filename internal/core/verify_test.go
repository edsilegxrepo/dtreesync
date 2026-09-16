// Package core provides unit tests for zero-disk cryptographic snapshot verification.
//
// Objectives:
//   - Validate three-tier verification (Zstandard framing, syntax parsing, and SHA-256 payload integrity).
//   - Test verification across all storage engines (TSV, NDJSON, SQLite).
//   - Ensure tampering, truncation, framing corruption, and count mismatches fail fast with ErrVerificationFailed.
//
// Test Strategy:
//   - Success Paths: Backs up live trees into TSV, NDJSON, and SQLite formats, asserting all tiers pass.
//   - Cryptographic Integrity: Mutates bytes in payload bodies to assert Tier 3 checksum mismatch rejection.
//   - Framing Integrity: Feeds truncated/malformed compression frames to assert Tier 1 failure.
//   - Syntax Integrity: Injects invalid JSON/TSV line records to assert Tier 2 syntax rejection.
//   - SQLite Integrity: Validates PRAGMA integrity_check and row count validation.
//
// Data Flow:
//
//	Snapshot Archive / Stream -> Verify() -> Tier 1 / Tier 2 / Tier 3 -> Result Assertions.
package core

import (
	"bytes"
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/edsilegxrepo/dtreesync/internal/model"
)

func TestVerify_TSV_Zstd_Success(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	sourceDir := filepath.Join(tmpDir, "source")
	snapFile := filepath.Join(tmpDir, "snapshot.tsv.zst")

	if err := os.MkdirAll(filepath.Join(sourceDir, "a", "b"), 0o755); err != nil {
		t.Fatalf("failed to create dirs: %v", err)
	}

	_, err := Backup(ctx, model.BackupConfig{
		BaseFolder:  sourceDir,
		TargetURL:   snapFile,
		Format:      model.FormatTSV,
		Compression: model.CompressionZstd,
		Workers:     2,
	}, nil)
	if err != nil {
		t.Fatalf("Backup failed: %v", err)
	}

	res, err := Verify(ctx, model.VerifyConfig{
		SourceURL: snapFile,
		Workers:   2,
	}, nil)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if !res.ChecksumValid || !res.FramesValid || !res.SyntaxValid {
		t.Errorf("expected all verification tiers to pass: %+v", res)
	}
	if res.RecordCount != 3 { // root, a, a/b
		t.Errorf("expected 3 records, got %d", res.RecordCount)
	}
}

func TestVerify_NDJSON_None_Success(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	sourceDir := filepath.Join(tmpDir, "source")
	snapFile := filepath.Join(tmpDir, "snapshot.ndjson")

	if err := os.MkdirAll(filepath.Join(sourceDir, "dir1"), 0o755); err != nil {
		t.Fatalf("failed to create dirs: %v", err)
	}

	_, err := Backup(ctx, model.BackupConfig{
		BaseFolder:  sourceDir,
		TargetURL:   snapFile,
		Format:      model.FormatNDJSON,
		Compression: model.CompressionNone,
		Workers:     1,
	}, nil)
	if err != nil {
		t.Fatalf("Backup failed: %v", err)
	}

	res, err := Verify(ctx, model.VerifyConfig{
		SourceURL: snapFile,
		Workers:   1,
	}, nil)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if !res.ChecksumValid || !res.FramesValid || !res.SyntaxValid {
		t.Errorf("expected all tiers to pass: %+v", res)
	}
}

func TestVerify_SQLite_SuccessAndErrors(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	sourceDir := filepath.Join(tmpDir, "source")
	dbFile := filepath.Join(tmpDir, "snapshot.db")

	if err := os.MkdirAll(filepath.Join(sourceDir, "sub1"), 0o755); err != nil {
		t.Fatalf("failed to create dir: %v", err)
	}

	_, err := Backup(ctx, model.BackupConfig{
		BaseFolder:  sourceDir,
		TargetURL:   dbFile,
		Format:      model.FormatSQLite,
		Compression: model.CompressionNone,
		Workers:     1,
	}, nil)
	if err != nil {
		t.Fatalf("Backup SQLite failed: %v", err)
	}

	// 1. Valid SQLite
	res, err := Verify(ctx, model.VerifyConfig{
		SourceURL: dbFile,
	}, nil)
	if err != nil {
		t.Fatalf("Verify SQLite failed: %v", err)
	}
	if !res.ChecksumValid || !res.FramesValid || !res.SyntaxValid {
		t.Errorf("expected valid SQLite verification: %+v", res)
	}
	if res.RecordCount != 2 {
		t.Errorf("expected 2 records in SQLite, got %d", res.RecordCount)
	}

	// 2. Corrupted SQLite file (non-sqlite bytes)
	corruptFile := filepath.Join(tmpDir, "corrupt.db")
	_ = os.WriteFile(corruptFile, []byte("not a valid sqlite file data here"), 0o644)
	resCorrupt, err := Verify(ctx, model.VerifyConfig{
		SourceURL: corruptFile,
	}, nil)
	if err == nil {
		t.Errorf("expected error on corrupt sqlite, got nil (res: %+v)", resCorrupt)
	}
}

func TestVerify_ChecksumTampering(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	sourceDir := filepath.Join(tmpDir, "source")
	snapFile := filepath.Join(tmpDir, "snapshot.tsv")

	if err := os.MkdirAll(filepath.Join(sourceDir, "alpha", "beta"), 0o755); err != nil {
		t.Fatalf("failed to create dirs: %v", err)
	}

	_, err := Backup(ctx, model.BackupConfig{
		BaseFolder:  sourceDir,
		TargetURL:   snapFile,
		Format:      model.FormatTSV,
		Compression: model.CompressionNone,
		Workers:     1,
	}, nil)
	if err != nil {
		t.Fatalf("Backup failed: %v", err)
	}

	// Read file and tamper with a payload byte in record section
	data, err := os.ReadFile(snapFile)
	if err != nil {
		t.Fatalf("failed to read snapFile: %v", err)
	}
	// Replace 'beta' with 'gamma' in payload data rows
	tamperedData := bytes.Replace(data, []byte("beta"), []byte("gamma"), 1)
	tamperedFile := filepath.Join(tmpDir, "tampered.tsv")
	_ = os.WriteFile(tamperedFile, tamperedData, 0o644)

	res, err := Verify(ctx, model.VerifyConfig{
		SourceURL: tamperedFile,
		Format:    model.FormatTSV,
	}, nil)
	if err == nil {
		t.Errorf("expected verification failure on tampered payload, got nil")
	}
	if res != nil && res.ChecksumValid {
		t.Errorf("expected ChecksumValid to be false")
	}
}

func TestVerify_CorruptZstdFraming(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	badZstdFile := filepath.Join(tmpDir, "bad.tsv.zst")

	// Zstd magic bytes followed by truncated garbage
	corruptZstd := []byte{0x28, 0xb5, 0x2f, 0xfd, 0x01, 0x02, 0x03}
	_ = os.WriteFile(badZstdFile, corruptZstd, 0o644)

	res, err := Verify(ctx, model.VerifyConfig{
		SourceURL: badZstdFile,
	}, nil)
	if err == nil {
		t.Errorf("expected error on corrupt zstd framing, got nil")
	}
	if res != nil && res.FramesValid {
		t.Errorf("expected FramesValid to be false")
	}
}

func TestVerify_NDJSON_SyntaxError(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	syntaxErrFile := filepath.Join(tmpDir, "bad_syntax.ndjson")

	// Line 1: valid header envelope
	// Line 2: broken json
	content := "{\"version\":\"dev\",\"format\":\"ndjson\",\"records\":1,\"sha256\":\"abc\"}\n{not-valid-json\n"
	_ = os.WriteFile(syntaxErrFile, []byte(content), 0o644)

	res, err := Verify(ctx, model.VerifyConfig{
		SourceURL:   syntaxErrFile,
		Format:      model.FormatNDJSON,
		Compression: model.CompressionNone,
	}, nil)
	if err == nil {
		t.Errorf("expected verification failure on invalid json syntax, got nil")
	}
	if res != nil && res.SyntaxValid {
		t.Errorf("expected SyntaxValid to be false")
	}
}

func TestVerify_DirectReaderInput(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	sourceDir := filepath.Join(tmpDir, "source")

	if err := os.MkdirAll(filepath.Join(sourceDir, "test"), 0o755); err != nil {
		t.Fatalf("failed to create dir: %v", err)
	}

	var buf bytes.Buffer
	_, err := Backup(ctx, model.BackupConfig{
		BaseFolder:  sourceDir,
		Writer:      &buf,
		Format:      model.FormatNDJSON,
		Compression: model.CompressionNone,
		Workers:     1,
	}, nil)
	if err != nil {
		t.Fatalf("Backup to buffer failed: %v", err)
	}

	// Verify from io.Reader
	res, err := Verify(ctx, model.VerifyConfig{
		Reader:      bytes.NewReader(buf.Bytes()),
		Format:      model.FormatNDJSON,
		Compression: model.CompressionNone,
	}, nil)
	if err != nil {
		t.Fatalf("Verify on Reader failed: %v", err)
	}
	if !res.ChecksumValid || !res.SyntaxValid {
		t.Errorf("expected valid verification from reader: %+v", res)
	}
}

func TestVerify_AuditTelemetryAndErrors(t *testing.T) {
	ctx := context.Background()
	var auditBuf bytes.Buffer
	al := model.NewAuditLogger(&auditBuf, 100)
	defer func() { _ = al.Close() }()

	// Empty sourceURL and nil reader
	_, err := Verify(ctx, model.VerifyConfig{
		SourceURL: "",
	}, al)
	if err == nil {
		t.Errorf("expected error for empty SourceURL, got nil")
	}

	// Invalid relative path
	_, err = Verify(ctx, model.VerifyConfig{
		SourceURL: "relative/path/snap.tsv",
	}, al)
	if err == nil {
		t.Errorf("expected error for relative path, got nil")
	}
}

func TestVerify_CountMismatchAndSQLiteValidation(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	sourceDir := filepath.Join(tmpDir, "source")
	_ = os.MkdirAll(filepath.Join(sourceDir, "sub"), 0o755)

	dbPath := filepath.Join(tmpDir, "test.db")
	_, err := Backup(ctx, model.BackupConfig{
		BaseFolder:  sourceDir,
		TargetURL:   dbPath,
		Format:      model.FormatSQLite,
		Compression: model.CompressionNone,
		Workers:     1,
	}, nil)
	if err != nil {
		t.Fatalf("Backup to SQLite failed: %v", err)
	}

	// 1. Relative path to SQLite returns error
	_, err = Verify(ctx, model.VerifyConfig{
		SourceURL: "relative/path.db",
		Format:    model.FormatSQLite,
	}, nil)
	if err == nil {
		t.Errorf("expected error for relative SQLite path")
	}

	// 2. Count mismatch in SQLite
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("failed to open sqlite db: %v", err)
	}
	_, err = db.Exec("INSERT INTO directories (rel_path, entity, meta_json) VALUES ('extra_dir', 'extra', '{}')")
	_ = db.Close()
	if err != nil {
		t.Fatalf("failed to insert extra row: %v", err)
	}

	res, err := Verify(ctx, model.VerifyConfig{
		SourceURL: dbPath,
		Format:    model.FormatSQLite,
	}, nil)
	if err == nil {
		t.Errorf("expected count mismatch error for SQLite, got nil (res: %+v)", res)
	}
}

func TestVerify_NDJSON_CountMismatch(t *testing.T) {
	ctx := context.Background()
	// Line 1 has records: 10, but payload only has 1 record
	content := []byte("{\"version\":\"dev\",\"format\":\"ndjson\",\"records\":10}\n{\"rel_path\":\"dir1\",\"entity\":\"dir1\"}\n")
	res, err := Verify(ctx, model.VerifyConfig{
		Reader:      bytes.NewReader(content),
		Format:      model.FormatNDJSON,
		Compression: model.CompressionNone,
	}, nil)
	if err == nil {
		t.Errorf("expected error on count mismatch, got nil")
	}
	if res == nil || len(res.Errors) == 0 {
		t.Errorf("expected error recorded in res.Errors")
	}
}
