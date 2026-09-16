// Package dtreesync provides unit tests for cross-domain identity mapping and SDDL/ACL translation.
//
// Objectives:
//   - Ensure accurate translation across accounts, groups, numeric UIDs/GIDs, Windows SIDs, SDDL, and POSIX ACL texts.
//   - Verify nil-safety and zero data corruption during metadata transformation.
//
// Test Strategy:
//   - Granular Translation: TestIdentityMap_Translation tests user, group, UID, GID, SID, SDDL, and comma/newline ACL texts.
//   - Metadata Transformation: TestIdentityMap_ApplyToPlatformMeta asserts that all fields of PlatformMeta are cleanly updated.
//   - Nil Safety: TestIdentityMap_NilSafe verifies that a nil *IdentityMap behaves as a safe passthrough without panicking.
//
// Data Flow:
//
//	JSON Identity Spec -> LoadIdentityMapFromReader() -> IdentityMap -> ApplyToPlatformMeta() -> Invariant Assertions.
package dtreesync

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIdentityMap_Translation(t *testing.T) {
	jsonConfig := `{
		"users": {
			"alice@legacycorp.local": "alice@newcorp.com",
			"mft_svc_prod": "mft_svc_stage"
		},
		"groups": {
			"mft_admins@legacycorp.local": "mft_admins@newcorp.com",
			"legacy_partners": "cloud_partners"
		},
		"uids": {
			"10042": 20042,
			"10050": 20050
		},
		"gids": {
			"5001": 6001
		},
		"sids": {
			"S-1-5-21-1111111111-2222222222-3333333333-1001": "S-1-5-21-9999999999-8888888888-7777777777-2001",
			"S-1-5-21-1111111111-2222222222-3333333333-513": "S-1-5-21-9999999999-8888888888-7777777777-513"
		}
	}`

	idMap, err := LoadIdentityMapFromReader(strings.NewReader(jsonConfig))
	if err != nil {
		t.Fatalf("unexpected load error: %v", err)
	}

	// User translation
	if res := idMap.TranslateUser("alice@legacycorp.local"); res != "alice@newcorp.com" {
		t.Fatalf("expected alice@newcorp.com, got %q", res)
	}
	if res := idMap.TranslateUser("bob@legacycorp.local"); res != "bob@legacycorp.local" {
		t.Fatalf("expected unmapped bob to remain unchanged, got %q", res)
	}

	// Group translation
	if res := idMap.TranslateGroup("legacy_partners"); res != "cloud_partners" {
		t.Fatalf("expected cloud_partners, got %q", res)
	}

	// UID translation
	if uid, ok := idMap.TranslateUID(10042); !ok || uid != 20042 {
		t.Fatalf("expected 20042/true, got %d/%v", uid, ok)
	}
	if uid, ok := idMap.TranslateUID(9999); ok || uid != 9999 {
		t.Fatalf("expected unmapped 9999/false, got %d/%v", uid, ok)
	}

	// GID translation
	if gid, ok := idMap.TranslateGID(5001); !ok || gid != 6001 {
		t.Fatalf("expected 6001/true, got %d/%v", gid, ok)
	}

	// SID translation
	oldSID := "S-1-5-21-1111111111-2222222222-3333333333-1001"
	expectedSID := "S-1-5-21-9999999999-8888888888-7777777777-2001"
	if res := idMap.TranslateSID(oldSID); res != expectedSID {
		t.Fatalf("expected %q, got %q", expectedSID, res)
	}

	// SDDL translation
	oldSDDL := "O:S-1-5-21-1111111111-2222222222-3333333333-1001G:S-1-5-21-1111111111-2222222222-3333333333-513D:P(A;OICI;FA;;;S-1-5-21-1111111111-2222222222-3333333333-1001)"
	expectedSDDL := "O:S-1-5-21-9999999999-8888888888-7777777777-2001G:S-1-5-21-9999999999-8888888888-7777777777-513D:P(A;OICI;FA;;;S-1-5-21-9999999999-8888888888-7777777777-2001)"
	translatedSDDL := idMap.TranslateSDDL(oldSDDL)
	if translatedSDDL != expectedSDDL {
		t.Fatalf("SDDL translation mismatch.\nExpected: %s\nGot:      %s", expectedSDDL, translatedSDDL)
	}

	// POSIX ACL text translation (comma separated)
	oldACLComma := "u:alice@legacycorp.local:rwx,g:legacy_partners:r-x,default:u:alice@legacycorp.local:rwx"
	expectedACLComma := "u:alice@newcorp.com:rwx,g:cloud_partners:r-x,default:u:alice@newcorp.com:rwx"
	if res := idMap.TranslateACLText(oldACLComma); res != expectedACLComma {
		t.Fatalf("ACL comma translation mismatch.\nExpected: %s\nGot:      %s", expectedACLComma, res)
	}

	// POSIX ACL text translation (newline separated)
	oldACLNL := "u:alice@legacycorp.local:rwx\ng:legacy_partners:r-x\n"
	expectedACLNL := "u:alice@newcorp.com:rwx\ng:cloud_partners:r-x\n"
	if res := idMap.TranslateACLText(oldACLNL); res != expectedACLNL {
		t.Fatalf("ACL newline translation mismatch.\nExpected: %q\nGot:      %q", expectedACLNL, res)
	}
}

func TestIdentityMap_ApplyToPlatformMeta(t *testing.T) {
	idMap := NewIdentityMap()
	idMap.Users["alice"] = "alice_new"
	idMap.Groups["staff"] = "staff_new"
	idMap.UIDs[1001] = 2001
	idMap.GIDs[1001] = 2001
	idMap.SIDs["S-1-5-111"] = "S-1-5-222"

	uid := uint32(1001)
	gid := uint32(1001)

	orig := PlatformMeta{
		Username: "alice",
		Group:    "staff",
		UID:      &uid,
		GID:      &gid,
		OwnerSID: "S-1-5-111",
		SDDL:     "O:S-1-5-111D:P(A;;FA;;;S-1-5-111)",
		ACLText:  "u:alice:rwx,g:staff:r-x",
	}

	applied := idMap.ApplyToPlatformMeta(orig)

	if applied.Username != "alice_new" {
		t.Errorf("expected Username alice_new, got %s", applied.Username)
	}
	if applied.Group != "staff_new" {
		t.Errorf("expected Group staff_new, got %s", applied.Group)
	}
	if applied.UID == nil || *applied.UID != 2001 {
		t.Errorf("expected UID 2001, got %v", applied.UID)
	}
	if applied.GID == nil || *applied.GID != 2001 {
		t.Errorf("expected GID 2001, got %v", applied.GID)
	}
	if applied.OwnerSID != "S-1-5-222" {
		t.Errorf("expected OwnerSID S-1-5-222, got %s", applied.OwnerSID)
	}
	if applied.SDDL != "O:S-1-5-222D:P(A;;FA;;;S-1-5-222)" {
		t.Errorf("expected translated SDDL, got %s", applied.SDDL)
	}
	if applied.ACLText != "u:alice_new:rwx,g:staff_new:r-x" {
		t.Errorf("expected translated ACLText, got %s", applied.ACLText)
	}
}

func TestIdentityMap_NilSafe(t *testing.T) {
	var idMap *IdentityMap
	if res := idMap.TranslateUser("alice"); res != "alice" {
		t.Fatalf("expected alice, got %s", res)
	}
	if res := idMap.TranslateGroup("staff"); res != "staff" {
		t.Fatalf("expected staff, got %s", res)
	}
	if uid, ok := idMap.TranslateUID(100); ok || uid != 100 {
		t.Fatalf("expected 100/false, got %d/%v", uid, ok)
	}
	if res := idMap.TranslateSID("S-1-1"); res != "S-1-1" {
		t.Fatalf("expected S-1-1, got %s", res)
	}
	if res := idMap.TranslateSDDL("O:S-1-1"); res != "O:S-1-1" {
		t.Fatalf("expected O:S-1-1, got %s", res)
	}
	if res := idMap.TranslateACLText("u:alice:rwx"); res != "u:alice:rwx" {
		t.Fatalf("expected u:alice:rwx, got %s", res)
	}
}

func TestIdentityMap_LoadFromFile(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "idmap.json")
	_ = os.WriteFile(tmpFile, []byte(`{"users":{"alice":"bob"}}`), 0o600)

	idMap, err := LoadIdentityMapFromFile(tmpFile)
	if err != nil {
		t.Fatalf("LoadIdentityMapFromFile failed: %v", err)
	}
	if idMap.TranslateUser("alice") != "bob" {
		t.Fatalf("user mapping mismatch: got %s, want bob", idMap.TranslateUser("alice"))
	}
}
