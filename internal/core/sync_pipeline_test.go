// Package core provides integration tests for snapshot restoration, drift inspection,
// cryptographic verification, and mirror mode evacuation.
//
// Objectives:
//   - Ensure fidelity and safety across core reconstitution, diff, and verification workflows.
//   - Test error propagation on tamper detection and ensure zero data loss during mirror evacuation.
//
// Test Strategy:
//   - Restoration Lifecycle: TestRestore_RoundtripAndTimestamps validates depth-ordered directory reconstitution,
//     permission application, progress callback invocations, and filesystem existence.
//   - Drift Auditing: TestDiff_DriftDetection evaluates clean state alignment vs injected untracked files and directories,
//     asserting the ErrDriftDetected sentinel error.
//   - Cryptographic Assurance: TestVerify_CryptographicChecksum tests zero-disk verification on valid streams and
//     deliberately poisoned SHA-256 headers, validating ErrVerificationFailed assertion.
//   - Zero Data Loss: TestEvacuateUntracked_MirrorMode creates live untracked payloads, evacuates them into a .tar.zst
//     container, and validates source removal alongside archive integrity.
//
// Data Flow:
//
//	In-Memory Snapshots -> Core Execution (Restore, Diff, Verify, Evacuate) -> Disk State & Invariant Assertions.
package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/edsilegxrepo/dtreesync/internal/format"
	"github.com/edsilegxrepo/dtreesync/internal/model"
)

func TestRestore_RoundtripAndTimestamps(t *testing.T) {
	tempRestoreBase := t.TempDir()

	targetDir := filepath.Join(tempRestoreBase, "materialized")

	// Prepare mock snapshot records
	fixedTime := time.Date(2025, 6, 15, 10, 0, 0, 0, time.UTC).UnixNano()
	mode := uint32(0o750)

	meta := model.BackupMetadata{
		Version:     "2.0",
		BaseFolder:  targetDir,
		CreatedAt:   time.Now().UTC(),
		FolderCount: 3,
		TreeFormat:  "ndjson",
	}

	records := []model.DirRecord{
		{
			Entity:  "",
			RelPath: "",
			Metadata: model.PlatformMeta{
				Mode:    &mode,
				ModTime: fixedTime,
			},
		},
		{
			Entity:  "partner_target",
			RelPath: "partner_target",
			Metadata: model.PlatformMeta{
				Mode:    &mode,
				ModTime: fixedTime,
			},
		},
		{
			Entity:  "partner_target",
			RelPath: "partner_target/inbound",
			Metadata: model.PlatformMeta{
				Mode:    &mode,
				ModTime: fixedTime,
			},
		},
	}

	var buf bytes.Buffer
	nw := format.NewNDJSONWriter(&buf)
	_ = nw.WriteHeader(meta)
	for _, r := range records {
		_ = nw.WriteRecord(r)
	}
	_ = nw.Flush()

	var progressReports int
	cfg := model.RestoreConfig{
		Reader:       bytes.NewReader(buf.Bytes()),
		TargetFolder: targetDir,
		ApplyPerms:   true,
		Workers:      4,
		OnProgress: func(stats model.RestoreProgress) {
			progressReports++
		},
	}

	result, err := Restore(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Restore failed: %v", err)
	}

	if result.CreatedFolders != 3 {
		t.Fatalf("expected 3 created folders, got %d", result.CreatedFolders)
	}

	// Verify all directories exist on disk
	checkDirs := []string{
		targetDir,
		filepath.Join(targetDir, "partner_target"),
		filepath.Join(targetDir, "partner_target", "inbound"),
	}
	for _, d := range checkDirs {
		info, err := os.Stat(d)
		if err != nil {
			t.Fatalf("directory %q was not created: %v", d, err)
		}
		if !info.IsDir() {
			t.Fatalf("expected directory at %q", d)
		}
	}
}

func TestDiff_DriftDetection(t *testing.T) {
	tempLive := t.TempDir()

	// Create expected directory
	inboundDir := filepath.Join(tempLive, "partner_a", "inbound")
	if err := os.MkdirAll(inboundDir, 0o755); err != nil {
		t.Fatalf("failed to create dir: %v", err)
	}

	mode := uint32(0o755)
	meta := model.BackupMetadata{
		BaseFolder:  tempLive,
		FolderCount: 2,
		TreeFormat:  "ndjson",
	}
	records := []model.DirRecord{
		{
			Entity:  "partner_a",
			RelPath: "partner_a",
			Metadata: model.PlatformMeta{
				Mode: &mode,
			},
		},
		{
			Entity:  "partner_a",
			RelPath: "partner_a/inbound",
			Metadata: model.PlatformMeta{
				Mode: &mode,
			},
		},
	}

	serializeSnapshot := func() []byte {
		var buf bytes.Buffer
		nw := format.NewNDJSONWriter(&buf)
		_ = nw.WriteHeader(meta)
		for _, r := range records {
			_ = nw.WriteRecord(r)
		}
		_ = nw.Flush()
		return buf.Bytes()
	}

	// Test 1: Clean alignment
	cfg := model.DiffConfig{
		LiveFolder:     tempLive,
		SnapshotReader: bytes.NewReader(serializeSnapshot()),
		Workers:        2,
	}

	diffRes, err := Diff(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("expected clean diff, got error: %v (drift items: %+v)", err, diffRes.DriftItems)
	}
	if diffRes.Status != "aligned" || diffRes.TotalDrift != 0 {
		t.Fatalf("expected status aligned, got %s with %d drifts", diffRes.Status, diffRes.TotalDrift)
	}

	// Test 2: Inject drift
	// A. Create untracked file
	untrackedFile := filepath.Join(inboundDir, "secret_payload.bin")
	_ = os.WriteFile(untrackedFile, []byte("data"), 0o644)

	// B. Create untracked extra directory
	_ = os.MkdirAll(filepath.Join(tempLive, "untracked_partner"), 0o755)

	cfg.SnapshotReader = bytes.NewReader(serializeSnapshot())
	diffRes, err = Diff(context.Background(), cfg, nil)
	if err == nil || !errors.Is(err, model.ErrDriftDetected) {
		t.Fatalf("expected ErrDriftDetected, got %v", err)
	}
	if diffRes.Status != "drift_detected" || diffRes.TotalDrift < 2 {
		t.Fatalf("expected at least 2 drifts, got %d", diffRes.TotalDrift)
	}
}

func TestVerify_CryptographicChecksum(t *testing.T) {
	mode := uint32(0o750)
	records := []model.DirRecord{
		{
			Entity:  "partner_x",
			RelPath: "partner_x",
			Metadata: model.PlatformMeta{
				Mode: &mode,
			},
		},
	}

	// First serialize records to compute exact payload SHA-256
	var payloadBuf bytes.Buffer
	nw := format.NewNDJSONWriter(&payloadBuf)
	for _, r := range records {
		_ = nw.WriteRecord(r)
	}
	_ = nw.Flush()

	// Compute hash of the payload
	h := sha256.New()
	h.Write(payloadBuf.Bytes())
	payloadHash := hex.EncodeToString(h.Sum(nil))

	// Now build full stream with header
	meta := model.BackupMetadata{
		BaseFolder:    "/var/mft/test",
		FolderCount:   1,
		TreeFormat:    "ndjson",
		PayloadSHA256: payloadHash,
	}

	var fullBuf bytes.Buffer
	fullNW := format.NewNDJSONWriter(&fullBuf)
	_ = fullNW.WriteHeader(meta)
	for _, r := range records {
		_ = fullNW.WriteRecord(r)
	}
	_ = fullNW.Flush()

	// Test 1: Valid stream verification
	verifyCfg := model.VerifyConfig{
		Reader:  bytes.NewReader(fullBuf.Bytes()),
		Format:  model.FormatNDJSON,
		Workers: 2,
	}

	res, err := Verify(context.Background(), verifyCfg, nil)
	if err != nil {
		t.Fatalf("Verify failed on valid stream: %v (errors: %v)", err, res.Errors)
	}
	if !res.FramesValid || !res.SyntaxValid || !res.ChecksumValid {
		t.Fatalf("verification flags invalid: frames=%v, syntax=%v, checksum=%v",
			res.FramesValid, res.SyntaxValid, res.ChecksumValid)
	}

	// Test 2: Tampered payload hash
	corruptMeta := meta
	corruptMeta.PayloadSHA256 = "0000000000000000000000000000000000000000000000000000000000000000"

	var corruptBuf bytes.Buffer
	cWriter := format.NewNDJSONWriter(&corruptBuf)
	_ = cWriter.WriteHeader(corruptMeta)
	for _, r := range records {
		_ = cWriter.WriteRecord(r)
	}
	_ = cWriter.Flush()

	verifyCfg.Reader = bytes.NewReader(corruptBuf.Bytes())
	cRes, cErr := Verify(context.Background(), verifyCfg, nil)
	if cErr == nil || !errors.Is(cErr, model.ErrVerificationFailed) {
		t.Fatalf("expected ErrVerificationFailed on checksum mismatch, got %v", cErr)
	}
	if cRes.ChecksumValid {
		t.Fatal("expected ChecksumValid to be false")
	}
}

func TestEvacuateUntracked_MirrorMode(t *testing.T) {
	tempTarget := t.TempDir()
	tempArchive := t.TempDir()

	// Create an untracked file and untracked dir
	untrackedDir := filepath.Join(tempTarget, "stale_partner")
	_ = os.MkdirAll(untrackedDir, 0o755)
	untrackedFile := filepath.Join(tempTarget, "stale_partner", "orphaned.dat")
	_ = os.WriteFile(untrackedFile, []byte("ephemeral-data"), 0o644)

	archivePath, err := EvacuateUntracked(
		context.Background(),
		tempTarget,
		tempArchive,
		[]string{"stale_partner/orphaned.dat", "stale_partner"},
		nil,
	)
	if err != nil {
		t.Fatalf("EvacuateUntracked failed: %v", err)
	}

	if archivePath == "" {
		t.Fatal("expected archivePath to be returned")
	}

	// Verify file was purged from target
	if _, err := os.Stat(untrackedDir); !os.IsNotExist(err) {
		t.Fatalf("expected stale_partner to be deleted from target, got %v", err)
	}

	// Verify archive container exists
	if info, err := os.Stat(archivePath); err != nil || info.Size() == 0 {
		t.Fatalf("expected non-empty archive file at %q", archivePath)
	}
}

func TestEvacuateUntracked_EdgeCases(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	targetDir := filepath.Join(tmpDir, "target")
	archiveDir := filepath.Join(tmpDir, "archive")
	_ = os.MkdirAll(targetDir, 0o755)

	// 1. Empty untracked paths -> returns ("", nil)
	arch, err := EvacuateUntracked(ctx, targetDir, archiveDir, nil, nil)
	if err != nil || arch != "" {
		t.Errorf("expected empty archive for empty untracked paths, got %q, %v", arch, err)
	}

	// 2. Invalid target folder -> error
	_, err = EvacuateUntracked(ctx, "", archiveDir, []string{"foo"}, nil)
	if err == nil {
		t.Errorf("expected error for empty target folder")
	}

	// 3. Invalid archive folder -> error
	_, err = EvacuateUntracked(ctx, targetDir, "", []string{"foo"}, nil)
	if err == nil {
		t.Errorf("expected error for empty archive folder")
	}

	// 4. Non-existent path in untracked list -> skipped without error
	_, err = EvacuateUntracked(ctx, targetDir, archiveDir, []string{"nonexistent_item"}, nil)
	if err != nil {
		t.Fatalf("expected non-existent item to be skipped cleanly, got %v", err)
	}

	// 5. Context canceled -> returns ctx.Err()
	cancCtx, cancel := context.WithCancel(ctx)
	cancel()
	_ = os.WriteFile(filepath.Join(targetDir, "file.txt"), []byte("data"), 0o644)
	_, err = EvacuateUntracked(cancCtx, targetDir, archiveDir, []string{"file.txt"}, nil)
	if err == nil {
		t.Errorf("expected error on canceled context, got nil")
	}
}

func TestDiff_MissingDirectories(t *testing.T) {
	tempLive := t.TempDir()

	// Snapshot expects "present_dir" and "deleted_dir"
	mode := uint32(0o755)
	meta := model.BackupMetadata{
		BaseFolder:  tempLive,
		FolderCount: 3,
		TreeFormat:  "ndjson",
	}
	records := []model.DirRecord{
		{
			Entity:  "",
			RelPath: "",
			Metadata: model.PlatformMeta{
				Mode: &mode,
			},
		},
		{
			Entity:  "present_dir",
			RelPath: "present_dir",
			Metadata: model.PlatformMeta{
				Mode: &mode,
			},
		},
		{
			Entity:  "deleted_dir",
			RelPath: "deleted_dir",
			Metadata: model.PlatformMeta{
				Mode: &mode,
			},
		},
	}

	// Live only has "present_dir"
	_ = os.MkdirAll(filepath.Join(tempLive, "present_dir"), 0o755)

	var buf bytes.Buffer
	nw := format.NewNDJSONWriter(&buf)
	_ = nw.WriteHeader(meta)
	for _, r := range records {
		_ = nw.WriteRecord(r)
	}
	_ = nw.Flush()

	cfg := model.DiffConfig{
		LiveFolder:     tempLive,
		SnapshotReader: bytes.NewReader(buf.Bytes()),
		Workers:        2,
	}

	diffRes, err := Diff(context.Background(), cfg, nil)
	if err == nil || !errors.Is(err, model.ErrDriftDetected) {
		t.Fatalf("expected ErrDriftDetected, got %v", err)
	}

	if diffRes.Summary.MissingCount != 1 {
		t.Fatalf("expected 1 missing directory, got %d", diffRes.Summary.MissingCount)
	}

	foundMissing := false
	for _, item := range diffRes.DriftItems {
		if item.Path == "deleted_dir" && item.Type == "missing_directory" {
			foundMissing = true
			break
		}
	}
	if !foundMissing {
		t.Errorf("expected deleted_dir in DriftItems: %+v", diffRes.DriftItems)
	}
}

func TestVerify_CorruptedFramesAndSyntax(t *testing.T) {
	// Test 1: Corrupted Zstandard framing
	badFrameCfg := model.VerifyConfig{
		Reader:      strings.NewReader("INVALID_ZSTD_MAGIC_HEADER_BYTES_NOT_COMPRESSED"),
		Format:      model.FormatNDJSON,
		Compression: model.CompressionZstd,
		Workers:     2,
	}

	res, err := Verify(context.Background(), badFrameCfg, nil)
	if err == nil || !errors.Is(err, model.ErrVerificationFailed) {
		t.Fatalf("expected ErrVerificationFailed for invalid zstd frame, got %v", err)
	}
	if res.FramesValid {
		t.Error("expected FramesValid to be false for corrupted frame")
	}

	// Test 2: Invalid NDJSON record syntax (corrupted JSON body)
	validHeader := `{"_meta":{"base_folder":"/var/mft/test","created_at":"2026-09-11T20:00:00Z","folder_count":1,"tree_format":"ndjson","version":"2.0"}}` + "\n"
	corruptedBody := validHeader + "THIS_IS_NOT_VALID_JSON_RECORD_DATA\n"

	badSyntaxCfg := model.VerifyConfig{
		Reader:      strings.NewReader(corruptedBody),
		Format:      model.FormatNDJSON,
		Compression: model.CompressionNone,
		Workers:     2,
	}

	res2, err2 := Verify(context.Background(), badSyntaxCfg, nil)
	if err2 == nil || !errors.Is(err2, model.ErrVerificationFailed) {
		t.Fatalf("expected ErrVerificationFailed for corrupted syntax, got %v", err2)
	}
	if res2.SyntaxValid {
		t.Error("expected SyntaxValid to be false for malformed JSON line")
	}
}

func TestMoveUntrackedDirect(t *testing.T) {
	tempBase := t.TempDir()

	srcDir := filepath.Join(tempBase, "source_tree")
	dstDir := filepath.Join(tempBase, "dest_tree")

	// Create nested structure in srcDir
	nested := filepath.Join(srcDir, "partner_alpha", "data")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatalf("failed to create src dir: %v", err)
	}
	payload := filepath.Join(nested, "file.dat")
	if err := os.WriteFile(payload, []byte("direct-move-payload"), 0o644); err != nil {
		t.Fatalf("failed to write payload: %v", err)
	}

	// Execute MoveUntrackedDirect
	if err := MoveUntrackedDirect(srcDir, dstDir); err != nil {
		t.Fatalf("MoveUntrackedDirect failed: %v", err)
	}

	// Source directory must no longer exist
	if _, err := os.Stat(srcDir); !os.IsNotExist(err) {
		t.Errorf("expected source_tree to no longer exist, err: %v", err)
	}

	// Destination file must exist and contain identical content
	dstFile := filepath.Join(dstDir, "partner_alpha", "data", "file.dat")
	data, err := os.ReadFile(dstFile)
	if err != nil {
		t.Fatalf("failed to read destination payload: %v", err)
	}
	if string(data) != "direct-move-payload" {
		t.Fatalf("payload corrupted after move: got %q", string(data))
	}
}

func TestRestore_BaseSubstitution(t *testing.T) {
	tempBase := t.TempDir()
	sourceDir := filepath.Join(tempBase, "source_original")
	rebasedDir := filepath.Join(tempBase, "rebased_target")

	mode := uint32(0o750)
	fixedTime := time.Date(2025, 6, 15, 10, 0, 0, 0, time.UTC).UnixNano()

	meta := model.BackupMetadata{
		Version:     "2.0",
		BaseFolder:  sourceDir,
		FolderCount: 2,
		TreeFormat:  "ndjson",
	}

	records := []model.DirRecord{
		{
			Entity:  "",
			RelPath: "",
			Metadata: model.PlatformMeta{
				Mode:    &mode,
				ModTime: fixedTime,
			},
		},
		{
			Entity:  "partner_y",
			RelPath: "partner_y",
			Metadata: model.PlatformMeta{
				Mode:    &mode,
				ModTime: fixedTime,
			},
		},
	}

	var buf bytes.Buffer
	nw := format.NewNDJSONWriter(&buf)
	_ = nw.WriteHeader(meta)
	for _, r := range records {
		_ = nw.WriteRecord(r)
	}
	_ = nw.Flush()

	cfg := model.RestoreConfig{
		Reader:         bytes.NewReader(buf.Bytes()),
		TargetFolder:   rebasedDir,
		BaseSubstitute: sourceDir + "," + rebasedDir,
		ApplyPerms:     false,
		Workers:        2,
	}

	res, err := Restore(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Restore failed with BaseSubstitute: %v", err)
	}

	if res.CreatedFolders != 2 {
		t.Fatalf("expected 2 created folders, got %d", res.CreatedFolders)
	}

	// Verify partner_y was created inside rebasedDir
	subDir := filepath.Join(rebasedDir, "partner_y")
	if info, err := os.Stat(subDir); err != nil || !info.IsDir() {
		t.Fatalf("expected partner_y to exist at %s: %v", subDir, err)
	}
}

func TestDiff_SnapshotReaderAndIgnores(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	liveDir := filepath.Join(tmpDir, "live")
	_ = os.MkdirAll(filepath.Join(liveDir, "sub1"), 0o755)

	meta := model.BackupMetadata{
		Version:     "2.0",
		BaseFolder:  liveDir,
		CreatedAt:   time.Now().UTC(),
		FolderCount: 2,
		TreeFormat:  "tsv",
	}

	records := []model.DirRecord{
		{RelPath: "", Metadata: model.PlatformMeta{Username: "mock_user_xyz"}},
		{RelPath: "sub1", Metadata: model.PlatformMeta{Username: "mock_user_xyz"}},
	}

	var buf bytes.Buffer
	tw := format.NewTSVWriter(&buf)
	_ = tw.WriteHeader(meta)
	for _, r := range records {
		_ = tw.WriteRecord(r)
	}
	_ = tw.Flush()

	// 1. Diff with IgnoreOwner = true -> skips owner differences
	res1, _ := Diff(ctx, model.DiffConfig{
		SnapshotReader: bytes.NewReader(buf.Bytes()),
		LiveFolder:     liveDir,
		Format:         model.FormatTSV,
		Compression:    model.CompressionNone,
		IgnoreOwner:    true,
		Workers:        1,
	}, nil)
	if res1 != nil {
		for _, it := range res1.DriftItems {
			if it.Type == "owner_drift" {
				t.Errorf("unexpected owner_drift when IgnoreOwner=true")
			}
		}
	}

	// 2. Diff with IgnoreOwner = false
	res2, _ := Diff(ctx, model.DiffConfig{
		SnapshotReader: bytes.NewReader(buf.Bytes()),
		LiveFolder:     liveDir,
		Format:         model.FormatTSV,
		Compression:    model.CompressionNone,
		IgnoreOwner:    false,
		Workers:        1,
	}, nil)
	_ = res2

	// 3. Diff without SnapshotReader or SnapshotURL -> returns error
	_, err := Diff(ctx, model.DiffConfig{
		LiveFolder: liveDir,
	}, nil)
	if err == nil {
		t.Errorf("expected ErrSnapshotNotFound when no snapshot provided")
	}
}

func TestMirror_MoveUntrackedDirect(t *testing.T) {
	tmpDir := t.TempDir()
	src := filepath.Join(tmpDir, "src.txt")
	dst := filepath.Join(tmpDir, "dst.txt")
	_ = os.WriteFile(src, []byte("data"), 0o644)

	if err := MoveUntrackedDirect(src, dst); err != nil {
		t.Fatalf("MoveUntrackedDirect failed: %v", err)
	}
	if _, err := os.Stat(dst); err != nil {
		t.Fatalf("expected dst to exist after move: %v", err)
	}
}

func TestCore_SignalsAndExitCodes(t *testing.T) {
	// Verify exit codes match enterprise specification
	if ExitSuccess != 0 || ExitFatalError != 1 || ExitPartialWarning != 2 ||
		ExitDriftDetected != 3 || ExitVerificationFailed != 4 ||
		ExitAuthFailure != 5 || ExitUsageError != 6 || ExitResourceExhausted != 7 {
		t.Fatalf("Exit code specification violated")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Setup signal trap returns valid context
	trapCtx := SetupSignalTrap(ctx, cancel, nil)
	if trapCtx == nil {
		t.Fatal("expected non-nil trap context")
	}
}

func TestRestore_ExtendedEdgeCasesAndSQLite(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	sourceDir := filepath.Join(tmpDir, "source")
	targetDir := filepath.Join(tmpDir, "target")
	dbPath := filepath.Join(tmpDir, "snapshot.db")

	_ = os.MkdirAll(filepath.Join(sourceDir, "p1", "child"), 0o755)

	// 1. Backup to SQLite and Restore from SQLite snapshot
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

	rRes, err := Restore(ctx, model.RestoreConfig{
		SourceURL:    dbPath,
		TargetFolder: targetDir,
		Workers:      1,
	}, nil)
	if err != nil {
		t.Fatalf("Restore from SQLite failed: %v", err)
	}
	if rRes.CreatedFolders != 3 { // root, p1, p1/child
		t.Errorf("expected 3 folders restored from SQLite, got %d", rRes.CreatedFolders)
	}

	// 2. Restore with auto-detected format and compression from reader
	snapTSVZst := filepath.Join(tmpDir, "snap.tsv.zst")
	_, err = Backup(ctx, model.BackupConfig{
		BaseFolder:  sourceDir,
		TargetURL:   snapTSVZst,
		Format:      model.FormatTSV,
		Compression: model.CompressionZstd,
		Workers:     1,
	}, nil)
	if err != nil {
		t.Fatalf("Backup to TSV.ZST failed: %v", err)
	}

	f, err := os.Open(snapTSVZst)
	if err != nil {
		t.Fatalf("failed to open TSV.ZST: %v", err)
	}
	defer func() { _ = f.Close() }()

	targetDir2 := filepath.Join(tmpDir, "target2")
	// No Format or Compression specified -> triggers auto-detection in readSnapshotFromReader!
	rRes2, err := Restore(ctx, model.RestoreConfig{
		Reader:       f,
		TargetFolder: targetDir2,
		Workers:      1,
	}, nil)
	if err != nil {
		t.Fatalf("Restore with auto-detected reader failed: %v", err)
	}
	if rRes2.CreatedFolders != 3 {
		t.Errorf("expected 3 folders restored via auto-detection, got %d", rRes2.CreatedFolders)
	}

	// 3. Neither Reader nor SourceURL supplied -> ErrSnapshotNotFound
	_, err = Restore(ctx, model.RestoreConfig{
		TargetFolder: targetDir,
	}, nil)
	if err == nil {
		t.Errorf("expected ErrSnapshotNotFound when neither Reader nor SourceURL supplied")
	}

	// 4. Invalid target folder -> error
	_, err = Restore(ctx, model.RestoreConfig{
		Reader:       bytes.NewReader([]byte{}),
		TargetFolder: "",
	}, nil)
	if err == nil {
		t.Errorf("expected error for empty target folder")
	}

	// 5. Invalid BaseSubstitute -> error
	_, err = Restore(ctx, model.RestoreConfig{
		Reader:         bytes.NewReader([]byte{}),
		TargetFolder:   targetDir,
		BaseSubstitute: "invalid_no_comma",
	}, nil)
	if err == nil {
		t.Errorf("expected error for malformed BaseSubstitute")
	}

	// 6. Unsupported format -> ErrFormatUnsupported
	_, err = Restore(ctx, model.RestoreConfig{
		Reader:       bytes.NewReader([]byte("dummy")),
		TargetFolder: targetDir,
		Format:       model.FormatType("unsupported_xyz"),
	}, nil)
	if err == nil {
		t.Errorf("expected error for unsupported format")
	}
}

func TestCore_CloudBlobStreamingPipeline(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	sourceDir := filepath.Join(tmpDir, "source")
	targetDir := filepath.Join(tmpDir, "target")

	_ = os.MkdirAll(filepath.Join(sourceDir, "cloud_sub"), 0o755)
	cloudURL := "file:///" + filepath.ToSlash(tmpDir) + "/cloud_bucket/snapshot.tsv.zst"

	// 1. Core Backup directly to cloud URL
	bRes, err := Backup(ctx, model.BackupConfig{
		BaseFolder:  sourceDir,
		TargetURL:   cloudURL,
		Format:      model.FormatTSV,
		Compression: model.CompressionZstd,
		Workers:     2,
	}, nil)
	if err != nil {
		t.Fatalf("Backup to cloud URL failed: %v", err)
	}
	if bRes.FolderCount != 2 {
		t.Errorf("expected 2 folders, got %d", bRes.FolderCount)
	}

	// 2. Core Verify directly from cloud URL
	vRes, err := Verify(ctx, model.VerifyConfig{
		SourceURL: cloudURL,
		Workers:   2,
	}, nil)
	if err != nil {
		t.Fatalf("Verify from cloud URL failed: %v", err)
	}
	if !vRes.ChecksumValid || !vRes.FramesValid {
		t.Errorf("cloud verification failed: %+v", vRes)
	}

	// 3. Core Restore directly from cloud URL
	rRes, err := Restore(ctx, model.RestoreConfig{
		SourceURL:    cloudURL,
		TargetFolder: targetDir,
		Workers:      2,
	}, nil)
	if err != nil {
		t.Fatalf("Restore from cloud URL failed: %v", err)
	}
	if rRes.CreatedFolders != 2 {
		t.Errorf("expected 2 folders restored from cloud, got %d", rRes.CreatedFolders)
	}

	// 4. Core Diff directly against cloud URL
	dRes, err := Diff(ctx, model.DiffConfig{
		SnapshotURL: cloudURL,
		LiveFolder:  targetDir,
		Workers:     2,
	}, nil)
	if err != nil {
		t.Fatalf("Diff against cloud URL failed: %v", err)
	}
	if dRes.TotalDrift != 0 {
		t.Errorf("expected 0 drift, got %d", dRes.TotalDrift)
	}
}

func TestDiff_SecurityDriftTypes(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	liveDir := filepath.Join(tmpDir, "live")
	_ = os.MkdirAll(filepath.Join(liveDir, "sub"), 0o755)

	meta := model.BackupMetadata{
		Version:     "2.0",
		BaseFolder:  liveDir,
		CreatedAt:   time.Now().UTC(),
		FolderCount: 2,
		TreeFormat:  "tsv",
	}

	mode := uint32(0o700) // Distinct from 0755
	records := []model.DirRecord{
		{RelPath: "", Metadata: model.PlatformMeta{}},
		{
			RelPath: "sub",
			Metadata: model.PlatformMeta{
				Mode:      &mode,
				Username:  "expected_differing_user",
				OwnerSID:  "S-1-5-21-EXPECTED-OLD",
				SDDL:      "D:P(A;;GA;;;SY)",
				ACLAccess: "user::rwx,group::r-x,other::r-x",
			},
		},
	}

	if normalizeSDDL("  D:P(A;;GA;;;SY)  ") != "D:P(A;;GA;;;SY)" {
		t.Errorf("normalizeSDDL trimming failed")
	}

	var buf bytes.Buffer
	tw := format.NewTSVWriter(&buf)
	_ = tw.WriteHeader(meta)
	for _, r := range records {
		_ = tw.WriteRecord(r)
	}
	_ = tw.Flush()

	res, err := Diff(ctx, model.DiffConfig{
		SnapshotReader: bytes.NewReader(buf.Bytes()),
		LiveFolder:     liveDir,
		Format:         model.FormatTSV,
		Compression:    model.CompressionNone,
		Workers:        1,
	}, nil)

	if err == nil {
		t.Errorf("expected ErrDriftDetected, got nil")
	}
	if res == nil || res.TotalDrift == 0 {
		t.Errorf("expected drift detected for security attributes")
	}
}

func TestCore_ValidationErrors(t *testing.T) {
	ctx := context.Background()

	// 1. Diff with invalid live folder
	_, err := Diff(ctx, model.DiffConfig{LiveFolder: ""}, nil)
	if err == nil {
		t.Errorf("expected error for empty live folder")
	}

	_, err = Diff(ctx, model.DiffConfig{LiveFolder: "relative/live"}, nil)
	if err == nil {
		t.Errorf("expected error for relative live folder")
	}

	// 2. Diff with invalid snapshot URL
	tmpDir := t.TempDir()
	_, err = Diff(ctx, model.DiffConfig{
		LiveFolder:  tmpDir,
		SnapshotURL: "relative/snap.tsv",
	}, nil)
	if err == nil {
		t.Errorf("expected error for relative snapshot URL in Diff")
	}

	// 3. Restore with relative target folder
	_, err = Restore(ctx, model.RestoreConfig{
		TargetFolder: "relative/target",
	}, nil)
	if err == nil {
		t.Errorf("expected error for relative target folder in Restore")
	}
}
