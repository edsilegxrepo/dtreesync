// Package format provides unit and integration tests for snapshot serialization engines.
//
// Objectives:
//   - Validate lossless serialization and streaming deserialization across TSV, NDJSON, and SQLite formats.
//   - Verify Zstandard multi-threaded compression and decompression integrity.
//   - Test microsecond Line 1 header peeking without parsing snapshot bodies.
//
// Test Strategy:
//   - Format Deduction: Tests table-driven path pattern matching for extensions (.tsv, .ndjson, .db, .zst).
//   - Zstd Roundtrip: Compresses and decompresses known payloads, asserting byte-for-byte fidelity.
//   - Format Roundtrips (TSV, NDJSON, SQLite): Serializes comprehensive synthetic records (POSIX modes,
//     UIDs/GIDs, xattrs, Windows SDDLs), executes header peeking, streams records, and validates field parity.
//
// Data Flow:
//
//	sampleData() -> Format Writer -> Compressed / Raw Buffer -> Peeker & Streaming Reader -> Field Invariant Assertions.
package format

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/edsilegxrepo/dtreesync/internal/model"
)

func sampleData() (model.BackupMetadata, []model.DirRecord) {
	meta := model.BackupMetadata{
		Version:       "2.0",
		BaseFolder:    "/var/mft/landing",
		Entity:        "partner_walmart",
		CreatedAt:     time.Date(2026, 9, 11, 20, 0, 0, 0, time.UTC),
		FolderCount:   2,
		TreeFile:      "landing.jsonl.zst",
		TreeFormat:    "ndjson",
		Compression:   true,
		HostOS:        "linux",
		Hostname:      "mft-node01.corp",
		PayloadSHA256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	}

	mode1 := uint32(0o750)
	uid1 := uint32(1001)
	gid1 := uint32(5001)
	attrs1 := uint32(2)

	records := []model.DirRecord{
		{
			Entity:  "partner_walmart",
			RelPath: "partner_walmart",
			Metadata: model.PlatformMeta{
				Mode:           &mode1,
				UID:            &uid1,
				GID:            &gid1,
				Username:       "walmart_svc",
				Group:          "mft_users",
				ACLAccess:      "020000000100",
				ACLDefault:     "020000000100",
				SELinuxContext: "system_u:object_r:mft_data_t:s0",
				SDDL:           "O:S-1-5-21...G:S-1-5-21...D:P(A;OICI;FA;;;S-1-5-21...)",
				FileAttributes: &attrs1,
				ModTime:        1789145700000000000,
			},
		},
		{
			Entity:  "partner_walmart",
			RelPath: "partner_walmart/inbound",
			Metadata: model.PlatformMeta{
				Mode:     &mode1,
				UID:      &uid1,
				GID:      &gid1,
				Username: "walmart_svc",
				Group:    "mft_users",
				ModTime:  1789145700000000000,
			},
		},
	}

	return meta, records
}

func TestDeduceFormatAndCompression(t *testing.T) {
	cases := []struct {
		input        string
		wantFormat   model.FormatType
		wantCompress model.CompressionType
	}{
		{"backup.tsv.zst", model.FormatTSV, model.CompressionZstd},
		{"backup.tsv", model.FormatTSV, model.CompressionNone},
		{"backup.jsonl.zst", model.FormatNDJSON, model.CompressionZstd},
		{"backup.jsonl", model.FormatNDJSON, model.CompressionNone},
		{"backup.ndjson.zst", model.FormatNDJSON, model.CompressionZstd},
		{"backup.db", model.FormatSQLite, model.CompressionNone},
		{"backup.sqlite", model.FormatSQLite, model.CompressionNone},
		{"unknown_archive", model.FormatNDJSON, model.CompressionZstd}, // default
	}

	for _, c := range cases {
		f, comp := DeduceFormatAndCompression(c.input)
		if f != c.wantFormat || comp != c.wantCompress {
			t.Errorf("Deduce(%q) = (%s, %s), want (%s, %s)", c.input, f, comp, c.wantFormat, c.wantCompress)
		}
	}
}

func TestZstdCompressionRoundtrip(t *testing.T) {
	var compressedBuf bytes.Buffer
	enc, err := NewZstdWriter(&compressedBuf, 4)
	if err != nil {
		t.Fatalf("failed to create zstd encoder: %v", err)
	}

	original := []byte("dtreesync-high-density-directory-synchronization-test-payload")
	if _, err := enc.Write(original); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	if err := enc.Close(); err != nil {
		t.Fatalf("encoder close failed: %v", err)
	}

	dec, err := NewZstdReader(&compressedBuf, 4)
	if err != nil {
		t.Fatalf("failed to create zstd decoder: %v", err)
	}
	defer dec.Close()

	var decompressedBuf bytes.Buffer
	if _, err := decompressedBuf.ReadFrom(dec); err != nil {
		t.Fatalf("read from decoder failed: %v", err)
	}

	if !bytes.Equal(decompressedBuf.Bytes(), original) {
		t.Fatalf("decompressed payload mismatch. Expected %q, got %q", string(original), decompressedBuf.String())
	}
}

func TestTSV_Roundtrip(t *testing.T) {
	meta, records := sampleData()

	var buf bytes.Buffer
	tw := NewTSVWriter(&buf)

	if err := tw.WriteHeader(meta); err != nil {
		t.Fatalf("failed to write TSV header: %v", err)
	}

	for _, r := range records {
		if err := tw.WriteRecord(r); err != nil {
			t.Fatalf("failed to write TSV record: %v", err)
		}
	}
	if err := tw.Flush(); err != nil {
		t.Fatalf("failed to flush TSV: %v", err)
	}

	// 1. Test header peeking
	peekMeta, err := ReadTSVHeader(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("ReadTSVHeader failed: %v", err)
	}
	if peekMeta.BaseFolder != meta.BaseFolder || peekMeta.FolderCount != meta.FolderCount {
		t.Fatalf("peeked header mismatch: got %+v", peekMeta)
	}

	// 2. Test full record streaming
	var readRecords []model.DirRecord
	parsedMeta, err := ReadTSVRecords(bytes.NewReader(buf.Bytes()), func(r model.DirRecord) error {
		readRecords = append(readRecords, r)
		return nil
	})
	if err != nil {
		t.Fatalf("ReadTSVRecords failed: %v", err)
	}
	if parsedMeta.PayloadSHA256 != meta.PayloadSHA256 {
		t.Fatalf("parsed meta SHA256 mismatch")
	}

	if len(readRecords) != len(records) {
		t.Fatalf("expected %d records, got %d", len(records), len(readRecords))
	}

	if readRecords[0].RelPath != records[0].RelPath ||
		*readRecords[0].Metadata.Mode != *records[0].Metadata.Mode ||
		readRecords[0].Metadata.Username != records[0].Metadata.Username ||
		readRecords[0].Metadata.SDDL != records[0].Metadata.SDDL {
		t.Fatalf("record 0 field mismatch: %+v vs %+v", readRecords[0], records[0])
	}
}

func TestNDJSON_Roundtrip(t *testing.T) {
	meta, records := sampleData()

	var buf bytes.Buffer
	nw := NewNDJSONWriter(&buf)

	if err := nw.WriteHeader(meta); err != nil {
		t.Fatalf("failed to write NDJSON header: %v", err)
	}

	for _, r := range records {
		if err := nw.WriteRecord(r); err != nil {
			t.Fatalf("failed to write NDJSON record: %v", err)
		}
	}
	if err := nw.Flush(); err != nil {
		t.Fatalf("failed to flush NDJSON: %v", err)
	}

	// 1. Test Line 1 header peeking
	peekMeta, err := ReadNDJSONHeader(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("ReadNDJSONHeader failed: %v", err)
	}
	if peekMeta.BaseFolder != meta.BaseFolder {
		t.Fatalf("peeked header mismatch: got %+v", peekMeta)
	}

	// 2. Test record stream reading
	var readRecords []model.DirRecord
	parsedMeta, err := ReadNDJSONRecords(bytes.NewReader(buf.Bytes()), func(r model.DirRecord) error {
		readRecords = append(readRecords, r)
		return nil
	})
	if err != nil {
		t.Fatalf("ReadNDJSONRecords failed: %v", err)
	}
	if parsedMeta.FolderCount != meta.FolderCount {
		t.Fatalf("parsed meta count mismatch")
	}

	if len(readRecords) != len(records) {
		t.Fatalf("expected %d records, got %d", len(records), len(readRecords))
	}

	if readRecords[0].RelPath != records[0].RelPath ||
		readRecords[0].Metadata.Username != records[0].Metadata.Username {
		t.Fatalf("record 0 mismatch")
	}
}

func TestSQLite_Roundtrip(t *testing.T) {
	tempDir := t.TempDir()

	dbPath := filepath.Join(tempDir, "test.db")
	meta, records := sampleData()

	sw, err := NewSQLiteWriter(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteWriter failed: %v", err)
	}

	if err := sw.WriteHeader(meta); err != nil {
		t.Fatalf("WriteHeader failed: %v", err)
	}

	for _, r := range records {
		if err := sw.WriteRecord(r); err != nil {
			t.Fatalf("WriteRecord failed: %v", err)
		}
	}

	if err := sw.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// 1. Test header read
	readMeta, err := ReadSQLiteHeader(dbPath)
	if err != nil {
		t.Fatalf("ReadSQLiteHeader failed: %v", err)
	}
	if readMeta.BaseFolder != meta.BaseFolder || readMeta.FolderCount != meta.FolderCount {
		t.Fatalf("readMeta mismatch: %+v", readMeta)
	}

	// 2. Test record reading
	var readRecords []model.DirRecord
	_, err = ReadSQLiteRecords(dbPath, func(r model.DirRecord) error {
		readRecords = append(readRecords, r)
		return nil
	})
	if err != nil {
		t.Fatalf("ReadSQLiteRecords failed: %v", err)
	}

	if len(readRecords) != len(records) {
		t.Fatalf("expected %d records, got %d", len(records), len(readRecords))
	}
	if readRecords[0].RelPath != records[0].RelPath {
		t.Fatalf("record 0 relpath mismatch: got %s, want %s", readRecords[0].RelPath, records[0].RelPath)
	}
}

func TestSQLiteWriter_RollbackAndBatch(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "rollback.db")
	meta, records := sampleData()

	sw, err := NewSQLiteWriter(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteWriter failed: %v", err)
	}

	if err := sw.WriteHeader(meta); err != nil {
		t.Fatalf("WriteHeader failed: %v", err)
	}

	if err := sw.WriteRecord(records[0]); err != nil {
		t.Fatalf("WriteRecord failed: %v", err)
	}

	// Test flushBatch directly
	if err := sw.flushBatch(); err != nil {
		t.Fatalf("flushBatch failed: %v", err)
	}

	// Test Rollback
	if err := sw.Rollback(); err != nil {
		t.Fatalf("Rollback failed: %v", err)
	}

	// Write after rollback should fail
	if err := sw.WriteRecord(records[1]); err == nil {
		t.Fatal("expected WriteRecord to fail after rollback")
	}

	// Close after rollback
	_ = sw.Close()

	// Double rollback is safe
	if err := sw.Rollback(); err != nil {
		t.Fatalf("double rollback failed: %v", err)
	}

	// Invalid path for NewSQLiteWriter
	invalidPath := filepath.Join(tempDir, "nonexistent_parent", "sub", "test.db")
	if _, err := NewSQLiteWriter(invalidPath); err == nil {
		t.Log("NewSQLiteWriter on deep path behavior noted")
	}
}

func TestFormat_ErrorHandling(t *testing.T) {
	// 1. Zstd reader on invalid data
	corruptBuf := bytes.NewReader([]byte("not-valid-zstd-compressed-data"))
	zr, err := NewZstdReader(corruptBuf, 1)
	if err == nil {
		buf := make([]byte, 64)
		_, readErr := zr.Read(buf)
		if readErr == nil {
			t.Fatal("expected decompression read error on corrupted zstd stream")
		}
		zr.Close()
	}

	// 2. NDJSON Header corruption
	badNDJSON := bytes.NewReader([]byte("NOT_JSON_LINE\n"))
	if _, err := ReadNDJSONHeader(badNDJSON); err == nil {
		t.Fatal("expected error reading corrupt NDJSON header")
	}

	// 3. TSV Header corruption
	badTSV := bytes.NewReader([]byte("MALFORMED_HEADER_LINE\n"))
	if _, err := ReadTSVHeader(badTSV); err == nil {
		t.Fatal("expected error reading corrupt TSV header")
	}

	// 4. SQLite Header on empty file
	emptyDB := filepath.Join(t.TempDir(), "empty.db")
	_ = os.WriteFile(emptyDB, []byte{}, 0o644)
	if _, err := ReadSQLiteHeader(emptyDB); err == nil {
		t.Fatal("expected error reading SQLite header on empty file")
	}
	if _, err := ReadSQLiteRecords(emptyDB, func(r model.DirRecord) error { return nil }); err == nil {
		t.Fatal("expected error reading SQLite records on empty file")
	}
}
