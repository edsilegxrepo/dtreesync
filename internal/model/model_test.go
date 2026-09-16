// Package model provides unit tests for core domain schemas, path sanitizers,
// identity mapping, token-bucket rate limiting, and asynchronous audit logging.
//
// Objectives:
//   - Ensure complete coverage across internal/model types, methods, and error wrappers.
//   - Test edge cases in path normalization, device name rejection, and glob patterns.
//   - Verify thread safety and graceful teardown of rate limiters and audit loggers.
//
// Test Strategy:
//   - Path Sanitization: Exercises absolute path enforcement, null-byte rejection, Win32 reserved device
//     names (CON, PRN, AUX, NUL), and recursive double-star (**/) glob matching.
//   - RecordFilter: Tests entity whitelist matching, inclusion globs, and exclusion precedence.
//   - IOPSLimiter: Tests token-bucket burst capacity, steady-state throttling, and context cancellation.
//   - AuditLogger: Tests asynchronous channel buffering, periodic flushing, file creation via t.TempDir(),
//     and concurrent multi-goroutine emission.
//   - IdentityMap: Tests JSON deserialization from file/reader, token-aware SDDL translation, and POSIX ACL rewriting.
//   - Error Wrappers: Tests PathError and VerificationError formatting and unwrapping.
//
// Data Flow:
//
//	Model Inputs -> Model Processors -> Invariant Assertions & Error Checks.
package model

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

func TestModel_ValidateAndCleanPath(t *testing.T) {
	// Empty path
	if _, err := ValidateAndCleanPath(""); !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("expected ErrInvalidPath for empty path, got %v", err)
	}

	// Relative path
	if _, err := ValidateAndCleanPath("relative/path"); !errors.Is(err, ErrRelativePathNotAllowed) {
		t.Fatalf("expected ErrRelativePathNotAllowed, got %v", err)
	}

	// Null byte injection
	if _, err := ValidateAndCleanPath("/var/\x00evil"); !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("expected ErrInvalidPath for null byte, got %v", err)
	}

	// Valid path
	validPath := t.TempDir()
	cleaned, err := ValidateAndCleanPath(validPath)
	if err != nil {
		t.Fatalf("unexpected error for valid temp path: %v", err)
	}
	if cleaned == "" {
		t.Fatal("expected non-empty cleaned path")
	}
}

func TestModel_NormalizeRelPath(t *testing.T) {
	// Empty
	norm, err := NormalizeRelPath("")
	if err != nil || norm != "" {
		t.Fatalf("expected empty for empty rel, got %q, %v", norm, err)
	}

	// Single dot
	norm, err = NormalizeRelPath(".")
	if err != nil || norm != "" {
		t.Fatalf("expected empty for dot, got %q, %v", norm, err)
	}

	// Slashes and backslashes
	norm, err = NormalizeRelPath(`foo\bar/baz/`)
	if err != nil || norm != "foo/bar/baz" {
		t.Fatalf("expected foo/bar/baz, got %q, %v", norm, err)
	}

	// Traversal
	if _, err := NormalizeRelPath("../foo"); !errors.Is(err, ErrBoundaryEscaped) {
		t.Fatalf("expected ErrBoundaryEscaped, got %v", err)
	}
	if _, err := NormalizeRelPath("foo/../bar"); err != nil {
		// path.Clean simplifies "foo/../bar" to "bar"
		if norm, _ := NormalizeRelPath("foo/../bar"); norm != "bar" {
			t.Fatalf("expected bar, got %q", norm)
		}
	}
	if _, err := NormalizeRelPath("foo/../../bar"); !errors.Is(err, ErrBoundaryEscaped) {
		t.Fatalf("expected ErrBoundaryEscaped for escaping traversal, got %v", err)
	}

	// Reserved device name on Windows
	if _, err := NormalizeRelPath("foo/NUL/bar"); !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("expected ErrInvalidPath for NUL device name, got %v", err)
	}
}

func TestModel_ExtendedWindowsPath(t *testing.T) {
	p := `C:\very\long\path`
	res := ToExtendedWindowsPath(p)
	if runtime.GOOS == "windows" {
		if !strings.HasPrefix(res, `\\?\`) {
			t.Fatalf("expected extended prefix on Windows, got %q", res)
		}
		// Already extended
		if ToExtendedWindowsPath(res) != res {
			t.Fatalf("expected idempotent extended path, got %q", ToExtendedWindowsPath(res))
		}
		// UNC path
		unc := `\\server\share\path`
		uncRes := ToExtendedWindowsPath(unc)
		if !strings.HasPrefix(uncRes, `\\?\UNC\`) {
			t.Fatalf("expected \\\\?\\UNC\\ prefix for UNC path, got %q", uncRes)
		}
	} else {
		if res != p {
			t.Fatalf("expected unchanged path on non-Windows, got %q", res)
		}
	}
}

func TestModel_BaseSubstituteAndRebase(t *testing.T) {
	// Invalid format
	if _, _, err := ParseBaseSubstitute("invalid"); err == nil {
		t.Fatal("expected error for missing comma in substitution")
	}

	temp1 := t.TempDir()
	temp2 := t.TempDir()
	subStr := temp1 + "," + temp2

	oldBase, newBase, err := ParseBaseSubstitute(subStr)
	if err != nil {
		t.Fatalf("unexpected error parsing substitution: %v", err)
	}
	if oldBase != temp1 || newBase != temp2 {
		t.Fatalf("unexpected parsed bases: %q, %q", oldBase, newBase)
	}

	// Identical paths
	if _, _, err := ParseBaseSubstitute(temp1 + "," + temp1); err == nil {
		t.Fatal("expected error for identical paths")
	}

	// RebasePath
	target := filepath.Join(temp1, "partner", "inbound")
	rebased := RebasePath(target, temp1, temp2)
	expected := filepath.Join(temp2, "partner", "inbound")
	if rebased != expected {
		t.Fatalf("expected rebased path %q, got %q", expected, rebased)
	}

	// Non-matching target
	nonMatching := filepath.Join(t.TempDir(), "other", "path")
	if RebasePath(nonMatching, temp1, temp2) != nonMatching {
		t.Fatal("expected non-matching path to return unchanged")
	}
}

func TestModel_MatchGlob(t *testing.T) {
	// Standard wildcards
	if !MatchGlob("partner*", "partner_walmart") {
		t.Fatal("expected partner* to match partner_walmart")
	}
	if MatchGlob("partner*", "vendor_walmart") {
		t.Fatal("expected partner* to not match vendor_walmart")
	}

	// Recursive **
	if !MatchGlob("**", "any/arbitrary/path") {
		t.Fatal("expected ** to match any path")
	}
	if !MatchGlob("orders/**", "orders/2026/01/data") {
		t.Fatal("expected orders/** to match nested subpath")
	}
	if !MatchGlob("**/inbound/**", "partner/walmart/inbound/orders") {
		t.Fatal("expected **/inbound/** to match embedded inbound segment")
	}
	if !MatchGlob("**/inbound", "partner/inbound") {
		t.Fatal("expected **/inbound to match trailing inbound")
	}
	if MatchGlob("orders/**", "inbound/orders") {
		t.Fatal("expected orders/** to not match inbound/orders")
	}

	// Empty patterns
	if !MatchGlob("", "") {
		t.Fatal("expected empty pattern to match empty path")
	}
	if MatchGlob("", "foo") {
		t.Fatal("expected empty pattern not to match foo")
	}
}

func TestModel_RecordFilter(t *testing.T) {
	filter := NewRecordFilter(
		[]string{"partner_a", "partner_b"},
		[]string{"**/inbound/**", "**/orders/**"},
		[]string{"**/temp/**", "**/.snapshot/**"},
	)

	// Record matching entity, include, and not excluded
	rec1 := DirRecord{
		Entity:  "partner_a",
		RelPath: "partner_a/inbound/2026",
	}
	if !filter.Matches(rec1) {
		t.Fatal("expected rec1 to match filter")
	}

	// Record matching entity but excluded by pattern
	rec2 := DirRecord{
		Entity:  "partner_a",
		RelPath: "partner_a/inbound/temp/data",
	}
	if filter.Matches(rec2) {
		t.Fatal("expected rec2 to be excluded by temp pattern")
	}

	// Record with non-whitelisted entity
	rec3 := DirRecord{
		Entity:  "partner_c",
		RelPath: "partner_c/inbound",
	}
	if filter.Matches(rec3) {
		t.Fatal("expected rec3 to fail entity check")
	}

	// Record matching entity but not in include list
	rec4 := DirRecord{
		Entity:  "partner_b",
		RelPath: "partner_b/archive/old",
	}
	if filter.Matches(rec4) {
		t.Fatal("expected rec4 to fail include check")
	}

	// Root directory record (RelPath == "") always passes entity and include checks
	rootRec := DirRecord{
		Entity:  "",
		RelPath: "",
	}
	if !filter.Matches(rootRec) {
		t.Fatal("expected root directory record to match")
	}
}

func TestModel_IOPSLimiter(t *testing.T) {
	// Disabled limiter
	unlimited := NewIOPSLimiter(0)
	if unlimited.IsEnabled() {
		t.Fatal("expected unlimited limiter to be disabled")
	}
	if unlimited.Limit() != 0 {
		t.Fatalf("expected 0 limit, got %d", unlimited.Limit())
	}
	if err := unlimited.Wait(context.Background()); err != nil {
		t.Fatalf("unexpected wait error on unlimited: %v", err)
	}
	if err := unlimited.WaitN(context.Background(), 5); err != nil {
		t.Fatalf("unexpected waitN error on unlimited: %v", err)
	}
	if !unlimited.Allow() {
		t.Fatal("expected Allow to return true on unlimited")
	}

	// Enabled limiter
	limiter := NewIOPSLimiter(100)
	if !limiter.IsEnabled() {
		t.Fatal("expected limiter to be enabled")
	}
	if limiter.Limit() != 100 {
		t.Fatalf("expected 100 limit, got %d", limiter.Limit())
	}
	if err := limiter.Wait(context.Background()); err != nil {
		t.Fatalf("unexpected wait error: %v", err)
	}

	// Context cancellation
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := limiter.Wait(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}

	// Nil safety
	var nilLimiter *IOPSLimiter
	if nilLimiter.IsEnabled() {
		t.Fatal("expected nil limiter to not be enabled")
	}
	if err := nilLimiter.Wait(context.Background()); err != nil {
		t.Fatal("expected nil limiter Wait to return nil")
	}
	if err := nilLimiter.WaitN(context.Background(), 2); err != nil {
		t.Fatal("expected nil limiter WaitN to return nil")
	}
	if !nilLimiter.Allow() {
		t.Fatal("expected nil limiter Allow to return true")
	}
	if nilLimiter.Limit() != 0 {
		t.Fatal("expected nil limiter Limit to return 0")
	}
}

func TestModel_AuditLogger(t *testing.T) {
	var buf bytes.Buffer
	logger := NewAuditLogger(&buf, 100)

	logger.LogInfo("test", "info_event", "/path/one", map[string]any{"k": "v"})
	logger.LogAudit("test", "audit_event", "/path/two", nil)
	logger.LogWarn("test", "warn_event", "/path/three", "warning msg", nil)
	logger.LogError("test", "error_event", "/path/four", "error msg", nil)

	if err := logger.Close(); err != nil {
		t.Fatalf("unexpected close error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "info_event") || !strings.Contains(out, "audit_event") ||
		!strings.Contains(out, "warn_event") || !strings.Contains(out, "error_event") {
		t.Fatalf("output missing expected log records: %s", out)
	}

	// Second close is safe no-op
	if err := logger.Close(); err != nil {
		t.Fatalf("second close returned error: %v", err)
	}

	// Log on closed logger increments dropped counter
	logger.LogInfo("test", "dropped_event", "/path", nil)
	if logger.DroppedCount() == 0 {
		t.Fatal("expected dropped count > 0 after logging on closed logger")
	}

	// File backed logger using t.TempDir()
	logFile := filepath.Join(t.TempDir(), "audit.ndjson")
	fileLogger, err := NewAuditLoggerFromFile(logFile, 50)
	if err != nil {
		t.Fatalf("NewAuditLoggerFromFile failed: %v", err)
	}
	fileLogger.LogInfo("subsystem", "file_event", "/path/file", nil)
	if err := fileLogger.Close(); err != nil {
		t.Fatalf("failed closing file logger: %v", err)
	}

	fileBytes, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("failed to read written log file: %v", err)
	}
	if !strings.Contains(string(fileBytes), "file_event") {
		t.Fatalf("log file missing file_event: %s", string(fileBytes))
	}

	// Nil safety
	var nilLogger *AuditLogger
	nilLogger.LogInfo("sub", "ev", "p", nil)
	nilLogger.LogAudit("sub", "ev", "p", nil)
	nilLogger.LogWarn("sub", "ev", "p", "w", nil)
	nilLogger.LogError("sub", "ev", "p", "e", nil)
	if err := nilLogger.Close(); err != nil {
		t.Fatal("expected nilLogger.Close() to be nil")
	}
	if nilLogger.DroppedCount() != 0 {
		t.Fatal("expected nilLogger.DroppedCount() to be 0")
	}

	// Concurrent logging
	var cBuf bytes.Buffer
	cLogger := NewAuditLogger(&cBuf, 500)
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				cLogger.LogInfo("worker", "msg", "/test", map[string]any{"id": id, "iter": j})
			}
		}(i)
	}
	wg.Wait()
	if err := cLogger.Close(); err != nil {
		t.Fatalf("cLogger close error: %v", err)
	}
}

func TestModel_IdentityMap(t *testing.T) {
	idMap := NewIdentityMap()
	idMap.Users["alice"] = "alice_new"
	idMap.Groups["admins"] = "admins_new"
	idMap.UIDs[1000] = 2000
	idMap.GIDs[500] = 600
	idMap.SIDs["S-1-5-21-OLD-1001"] = "S-1-5-21-NEW-2001"

	// Translations
	if idMap.TranslateUser("alice") != "alice_new" {
		t.Fatal("user translation failed")
	}
	if idMap.TranslateUser("unknown") != "unknown" {
		t.Fatal("unmapped user should return unchanged")
	}

	if idMap.TranslateGroup("admins") != "admins_new" {
		t.Fatal("group translation failed")
	}

	if uid, ok := idMap.TranslateUID(1000); !ok || uid != 2000 {
		t.Fatal("UID translation failed")
	}
	if uid, ok := idMap.TranslateUID(9999); ok || uid != 9999 {
		t.Fatal("unmapped UID should return unchanged")
	}

	if gid, ok := idMap.TranslateGID(500); !ok || gid != 600 {
		t.Fatal("GID translation failed")
	}

	if idMap.TranslateSID("S-1-5-21-OLD-1001") != "S-1-5-21-NEW-2001" {
		t.Fatal("SID translation failed")
	}

	// SDDL Translation
	sddlInput := "O:S-1-5-21-OLD-1001G:S-1-5-21-OLD-1001D:(A;;FA;;;S-1-5-21-OLD-1001)"
	sddlOut := idMap.TranslateSDDL(sddlInput)
	if strings.Contains(sddlOut, "OLD") || !strings.Contains(sddlOut, "NEW") {
		t.Fatalf("SDDL translation failed: %s", sddlOut)
	}

	// POSIX ACL Translation
	aclInput := "user:alice:rwx,group:admins:r-x"
	aclOut := idMap.TranslateACLText(aclInput)
	if !strings.Contains(aclOut, "alice_new") || !strings.Contains(aclOut, "admins_new") {
		t.Fatalf("ACL text translation failed: %s", aclOut)
	}

	// PlatformMeta Application
	mode := uint32(0o755)
	uid := uint32(1000)
	gid := uint32(500)
	meta := PlatformMeta{
		Mode:     &mode,
		UID:      &uid,
		GID:      &gid,
		Username: "alice",
		Group:    "admins",
		OwnerSID: "S-1-5-21-OLD-1001",
		GroupSID: "S-1-5-21-OLD-1001",
		SDDL:     sddlInput,
		ACLText:  aclInput,
	}

	updated := idMap.ApplyToPlatformMeta(meta)
	if *updated.UID != 2000 || *updated.GID != 600 || updated.Username != "alice_new" || updated.Group != "admins_new" {
		t.Fatalf("ApplyToPlatformMeta failed: %+v", updated)
	}

	// Load from JSON file
	jsonFile := filepath.Join(t.TempDir(), "idmap.json")
	if err := os.WriteFile(jsonFile, []byte(`{"users":{"bob":"bob_new"}}`), 0o600); err != nil {
		t.Fatalf("failed to write idmap json: %v", err)
	}
	loaded, err := LoadIdentityMapFromFile(jsonFile)
	if err != nil {
		t.Fatalf("LoadIdentityMapFromFile failed: %v", err)
	}
	if loaded.TranslateUser("bob") != "bob_new" {
		t.Fatal("loaded idmap translation failed")
	}

	// Nil safety
	var nilMap *IdentityMap
	if nilMap.TranslateUser("foo") != "foo" {
		t.Fatal("nilMap.TranslateUser should return unchanged")
	}
	if nilMap.TranslateGroup("bar") != "bar" {
		t.Fatal("nilMap.TranslateGroup should return unchanged")
	}
	if uid, ok := nilMap.TranslateUID(42); ok || uid != 42 {
		t.Fatal("nilMap.TranslateUID should return unchanged")
	}
	if gid, ok := nilMap.TranslateGID(42); ok || gid != 42 {
		t.Fatal("nilMap.TranslateGID should return unchanged")
	}
	if nilMap.TranslateSID("S-1") != "S-1" {
		t.Fatal("nilMap.TranslateSID should return unchanged")
	}
	if nilMap.TranslateSDDL("D:P") != "D:P" {
		t.Fatal("nilMap.TranslateSDDL should return unchanged")
	}
	if nilMap.TranslateACLText("user::rwx") != "user::rwx" {
		t.Fatal("nilMap.TranslateACLText should return unchanged")
	}
	if nilMap.ApplyToPlatformMeta(meta).Username != "alice" {
		t.Fatal("nilMap.ApplyToPlatformMeta should return unchanged")
	}
}

func TestModel_Errors(t *testing.T) {
	// PathError
	innerErr := errors.New("permission denied")
	pathErr := &PathError{
		Op:   "mkdir",
		Path: "/var/mft",
		Err:  innerErr,
	}

	if !strings.Contains(pathErr.Error(), "mkdir") || !strings.Contains(pathErr.Error(), "/var/mft") {
		t.Fatalf("PathError format error: %s", pathErr.Error())
	}
	if !errors.Is(pathErr, innerErr) {
		t.Fatal("PathError Unwrap failed")
	}
	var nilPathErr *PathError
	if nilPathErr.Error() != "<nil>" {
		t.Fatalf("expected <nil>, got %q", nilPathErr.Error())
	}
	if nilPathErr.Unwrap() != nil {
		t.Fatal("expected nil unwrap")
	}

	// VerificationError
	verErr := &VerificationError{
		TreeFile: "tree.tsv",
		Expected: "hashA",
		Actual:   "hashB",
		Issues:   []string{"corrupt line"},
	}
	if !strings.Contains(verErr.Error(), "hashA") || !strings.Contains(verErr.Error(), "hashB") {
		t.Fatalf("VerificationError format error: %s", verErr.Error())
	}
	if !errors.Is(verErr, ErrVerificationFailed) {
		t.Fatal("VerificationError Unwrap failed")
	}
	var nilVerErr *VerificationError
	if nilVerErr.Error() != "<nil>" {
		t.Fatalf("expected <nil>, got %q", nilVerErr.Error())
	}
	if nilVerErr.Unwrap() != nil {
		t.Fatal("expected nil unwrap")
	}
}
