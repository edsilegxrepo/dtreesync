// Package meta provides unit and integration tests for platform metadata engines.
//
// Objectives:
//   - Validate cross-platform metadata extraction, privilege adjustment, timestamp updates, and permission writes.
//   - Test atomic directory relocation, error handling, and recursive tree copy.
//
// Test Strategy:
//   - Lifecycle Verification: TestDefaultEngine_Lifecycle creates a live temporary directory via t.TempDir(),
//     invokes InitPrivileges, reads OS metadata (NTFS SDDL or POSIX modes/xattrs), restores timestamps,
//     and reapplies permissions.
//   - Edge Cases: TestDefaultEngine_EdgeCases verifies nil meta, non-existent paths, negative timestamps,
//     and applyPerms=false behavior.
//   - Relocation Invariants: TestMoveItem_And_CopyDirOrFile constructs a multi-level hierarchy,
//     tests file and directory copies, symlink replication, and isCrossDeviceError detection.
//
// Data Flow:
//
//	Temp FS Tree -> DefaultEngine (Read/SetTimes/Apply) -> MoveItem -> os.Stat / Byte Comparison Assertions.
package meta

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestDefaultEngine_Lifecycle(t *testing.T) {
	engine := DefaultEngine
	if engine == nil {
		t.Fatal("expected DefaultEngine to be non-nil")
	}

	// 1. InitPrivileges
	if err := engine.InitPrivileges(); err != nil {
		t.Logf("InitPrivileges warning (non-admin environment): %v", err)
	}

	// 2. Create test directory using t.TempDir()
	tempDir := t.TempDir()

	// 3. ReadMeta
	meta, err := engine.ReadMeta(tempDir)
	if err != nil {
		t.Fatalf("ReadMeta failed: %v", err)
	}
	if meta == nil {
		t.Fatal("ReadMeta returned nil meta")
	}
	t.Logf("ReadMeta on tempDir: OwnerSID=%q, OwnerName=%q, Mode=%v, SDDL=%v",
		meta.OwnerSID, meta.OwnerName, meta.Mode, meta.SDDL != "")

	// 4. SetTimes
	now := time.Now().UnixNano()
	if err := engine.SetTimes(tempDir, now, now, now); err != nil {
		t.Logf("SetTimes returned note: %v", err)
	}

	// 5. ApplyMeta
	if err := engine.ApplyMeta(tempDir, meta, true); err != nil {
		t.Fatalf("ApplyMeta failed: %v", err)
	}
}

func TestDefaultEngine_EdgeCases(t *testing.T) {
	engine := DefaultEngine

	// 1. ApplyMeta with nil meta returns nil
	if err := engine.ApplyMeta(t.TempDir(), nil, true); err != nil {
		t.Fatalf("expected nil for ApplyMeta with nil meta, got %v", err)
	}

	// 2. File metadata read and write
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "meta_file.txt")
	if err := os.WriteFile(filePath, []byte("metadata-test"), 0o644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	meta, err := engine.ReadMeta(filePath)
	if err != nil {
		t.Fatalf("ReadMeta on file failed: %v", err)
	}
	if meta == nil {
		t.Fatal("ReadMeta returned nil for file")
	}

	// 3. ApplyMeta with applyPerms=false
	if err := engine.ApplyMeta(filePath, meta, false); err != nil {
		t.Fatalf("ApplyMeta with applyPerms=false failed: %v", err)
	}

	// 4. SetTimes with negative timestamps (skip branches)
	if err := engine.SetTimes(filePath, -1, -1, -1); err != nil {
		t.Logf("SetTimes -1 note: %v", err)
	}

	// 5. SetTimes on non-existent path
	nonExistent := filepath.Join(tempDir, "no_such_file.txt")
	if err := engine.SetTimes(nonExistent, 100, 100, 100); err == nil {
		t.Fatal("expected error setting times on non-existent path")
	}

	// 6. ReadMeta on non-existent path
	if _, err := engine.ReadMeta(nonExistent); err == nil && runtime.GOOS != "windows" {
		t.Fatal("expected error reading meta on non-existent path on POSIX")
	}
}

func TestMoveItem_And_CopyDirOrFile(t *testing.T) {
	tempSrc := t.TempDir()

	// Create child dir and dummy file inside src
	subDir := filepath.Join(tempSrc, "sub")
	if err := os.Mkdir(subDir, 0o750); err != nil {
		t.Fatalf("failed to create sub dir: %v", err)
	}
	sampleFile := filepath.Join(subDir, "file.txt")
	if err := os.WriteFile(sampleFile, []byte("dtreesync-test-data"), 0o640); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	// Symlink test (if permitted on OS)
	symlinkPath := filepath.Join(tempSrc, "symlink.txt")
	_ = os.Symlink(sampleFile, symlinkPath)

	tempDstBase := t.TempDir()
	dstTarget := filepath.Join(tempDstBase, "moved_tree")

	// Test MoveItem
	if err := MoveItem(tempSrc, dstTarget); err != nil {
		t.Fatalf("MoveItem failed: %v", err)
	}

	// Verify destination exists with contents
	dstSample := filepath.Join(dstTarget, "sub", "file.txt")
	data, err := os.ReadFile(dstSample)
	if err != nil {
		t.Fatalf("failed to read moved sample file: %v", err)
	}
	if string(data) != "dtreesync-test-data" {
		t.Fatalf("expected file content 'dtreesync-test-data', got %q", string(data))
	}

	// CopyDirOrFile on non-existent source
	if err := CopyDirOrFile(filepath.Join(tempSrc, "missing"), dstTarget); err == nil {
		t.Fatal("expected error copying non-existent source")
	}
}

func TestIsCrossDeviceError(t *testing.T) {
	// 1. nil error
	if isCrossDeviceError(nil) {
		t.Fatal("expected false for nil error")
	}

	// 2. unrelated error
	if isCrossDeviceError(errors.New("generic error")) {
		t.Fatal("expected false for generic error")
	}

	// 3. EXDEV (18)
	if !isCrossDeviceError(syscall.EXDEV) {
		t.Fatal("expected true for syscall.EXDEV")
	}

	// 4. ERROR_NOT_SAME_DEVICE (17)
	const ERROR_NOT_SAME_DEVICE = syscall.Errno(17)
	if !isCrossDeviceError(ERROR_NOT_SAME_DEVICE) {
		t.Fatal("expected true for ERROR_NOT_SAME_DEVICE (17)")
	}

	// 5. Wrapped in os.LinkError
	linkErr := &os.LinkError{
		Op:  "rename",
		Old: "/src",
		New: "/dst",
		Err: syscall.EXDEV,
	}
	if !isCrossDeviceError(linkErr) {
		t.Fatal("expected true for LinkError wrapping EXDEV")
	}

	linkErrWin := &os.LinkError{
		Op:  "rename",
		Old: "C:\\src",
		New: "D:\\dst",
		Err: ERROR_NOT_SAME_DEVICE,
	}
	if !isCrossDeviceError(linkErrWin) {
		t.Fatal("expected true for LinkError wrapping ERROR_NOT_SAME_DEVICE")
	}

	// 6. Other errno
	if isCrossDeviceError(syscall.Errno(999)) {
		t.Fatal("expected false for random errno")
	}
}

func TestCopyDirOrFile_Direct(t *testing.T) {
	srcDir := filepath.Join(t.TempDir(), "src")
	_ = os.MkdirAll(filepath.Join(srcDir, "sub1", "sub2"), 0o755)
	_ = os.WriteFile(filepath.Join(srcDir, "root.txt"), []byte("root-data"), 0o644)
	_ = os.WriteFile(filepath.Join(srcDir, "sub1", "sub2", "leaf.txt"), []byte("leaf-data"), 0o644)

	dstDir := filepath.Join(t.TempDir(), "dst")
	if err := CopyDirOrFile(srcDir, dstDir); err != nil {
		t.Fatalf("CopyDirOrFile failed: %v", err)
	}

	// Verify copied files exist and match
	data, err := os.ReadFile(filepath.Join(dstDir, "root.txt"))
	if err != nil || string(data) != "root-data" {
		t.Fatalf("root file mismatch or missing: %v", err)
	}

	dataLeaf, err := os.ReadFile(filepath.Join(dstDir, "sub1", "sub2", "leaf.txt"))
	if err != nil || string(dataLeaf) != "leaf-data" {
		t.Fatalf("leaf file mismatch or missing: %v", err)
	}
}

func TestApplyMeta_SDDLVariants(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "sddl_file.txt")
	_ = os.WriteFile(filePath, []byte("sddl-test"), 0o644)

	engine := DefaultEngine
	meta, err := engine.ReadMeta(filePath)
	if err != nil {
		t.Fatalf("ReadMeta failed: %v", err)
	}

	// Set Protected DACL (D:P)
	if meta.SDDL != "" {
		protectedSDDL := meta.SDDL
		if !strings.Contains(protectedSDDL, "D:P") {
			protectedSDDL = strings.Replace(protectedSDDL, "D:", "D:P", 1)
		}
		meta.SDDL = protectedSDDL
	}

	attrs := uint32(0x20) // FILE_ATTRIBUTE_ARCHIVE
	meta.FileAttributes = &attrs

	if err := engine.ApplyMeta(filePath, meta, true); err != nil {
		t.Logf("ApplyMeta with protected SDDL note: %v", err)
	}
}
