//go:build linux

// Package meta provides Linux-specific unit tests for the POSIX metadata engine.
//
// Objectives:
//   - Verify Linux account resolution caches (UID/GID <-> Name).
//   - Test xattr buffer pool handling and POSIX ACL / SELinux attribute application.
//   - Ensure permission degradation and syscall errno parsing behave deterministically.
package meta

import (
	"errors"
	"os"
	"syscall"
	"testing"

	"github.com/edsilegxrepo/dtreesync/internal/model"
)

func TestPosix_AccountLookupAndCaches(t *testing.T) {
	currentUID := uint32(os.Getuid())
	currentGID := uint32(os.Getgid())

	// 1. UID to Name and caching
	name1 := lookupUsername(currentUID)
	if name1 == "" {
		t.Logf("lookupUsername(%d) returned empty, skipping name check", currentUID)
	} else {
		// Second lookup hits cache
		name2 := lookupUsername(currentUID)
		if name1 != name2 {
			t.Errorf("expected cached name %q, got %q", name1, name2)
		}

		// Lookup by name back to UID
		uid, ok := lookupNameToUID(name1)
		if !ok || uid != currentUID {
			t.Errorf("lookupNameToUID(%q) = (%d, %v), expected %d", name1, uid, ok, currentUID)
		}
	}

	// 2. GID to Name and caching
	gName1 := lookupGroupName(currentGID)
	if gName1 != "" {
		gName2 := lookupGroupName(currentGID)
		if gName1 != gName2 {
			t.Errorf("expected cached group %q, got %q", gName1, gName2)
		}

		gid, ok := lookupNameToGID(gName1)
		if !ok || gid != currentGID {
			t.Errorf("lookupNameToGID(%q) = (%d, %v), expected %d", gName1, gid, ok, currentGID)
		}
	}

	// 3. Non-existent account lookups
	_ = lookupUsername(9999999)
	_ = lookupGroupName(9999999)
	_, _ = lookupNameToUID("nonexistent_user_99999999")
	_, _ = lookupNameToGID("nonexistent_group_99999999")
}

func TestPosix_PermissionAndErrnoHandling(t *testing.T) {
	if !isPermissionDenied(syscall.EPERM) {
		t.Error("expected EPERM to be permission denied")
	}
	if !isPermissionDenied(syscall.EACCES) {
		t.Error("expected EACCES to be permission denied")
	}
	if !isPermissionDenied(os.ErrPermission) {
		t.Error("expected os.ErrPermission to be permission denied")
	}
	if isPermissionDenied(nil) {
		t.Error("nil error should not be permission denied")
	}
	if isPermissionDenied(syscall.ENOENT) {
		t.Error("ENOENT should not be permission denied")
	}

	var errno syscall.Errno
	if !errorsAsErrno(syscall.EPERM, &errno) || errno != syscall.EPERM {
		t.Error("errorsAsErrno failed on syscall.EPERM")
	}
	if errorsAsErrno(errors.New("generic error"), &errno) {
		t.Error("errorsAsErrno should return false on non-errno error")
	}
}

func TestPosix_ApplyPosixXattrsAndEngineTimes(t *testing.T) {
	tempDir := t.TempDir()

	// Test applyPosixXattrs
	meta := &model.PlatformMeta{
		ACLAccess:      "01020304", // hex dummy
		ACLDefault:     "05060708",
		SELinuxContext: "system_u:object_r:default_t:s0",
	}
	applyPosixXattrs(tempDir, meta)

	// Test SetTimes with <= 0 values (falls back to time.Now())
	engine := newPlatformEngine()
	if err := engine.SetTimes(tempDir, 0, -1, 0); err != nil {
		t.Errorf("SetTimes with fallback to Now failed: %v", err)
	}

	// Test ApplyMeta with applyPerms = true
	mode := uint32(0o755)
	uid := uint32(os.Getuid())
	gid := uint32(os.Getgid())
	permMeta := &model.PlatformMeta{
		Mode:     &mode,
		UID:      &uid,
		GID:      &gid,
		Username: lookupUsername(uid),
		Group:    lookupGroupName(gid),
	}
	if err := engine.ApplyMeta(tempDir, permMeta, true); err != nil {
		t.Errorf("ApplyMeta failed: %v", err)
	}
}
