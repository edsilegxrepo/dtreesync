// Package model provides cross-domain and cross-system identity mapping.
//
// Objectives:
//   - Enable seamless migration of filesystems across Active Directory domains, POSIX namespaces, or cloud tenants.
//   - Rewrite usernames, group names, numeric UIDs/GIDs, Windows SIDs, and embedded SDDL/ACL strings.
//   - Guarantee string replacement safety (e.g. descending length ordering in SDDL to prevent partial prefix collisions).
//
// Core Components:
//   - IdentityMap: Core structure holding translation tables for accounts, groups, UIDs, GIDs, and SIDs.
//   - Loaders: LoadIdentityMapFromFile and LoadIdentityMapFromReader for parsing JSON identity definition files.
//   - TranslateSDDL: Token-aware SID replacement across complex Windows Security Descriptor Definition Language strings.
//   - TranslateACLText: Parser and rewriter for portable POSIX getfacl text entries.
//   - ApplyToPlatformMeta: Comprehensive translator updating all security attributes within a PlatformMeta snapshot.
//
// Data Flow:
//
//	Snapshot PlatformMeta -> IdentityMap.ApplyToPlatformMeta() -> Rewritten Security Descriptors -> OS Restore API.
package model

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
)

// NewIdentityMap creates an initialized IdentityMap with empty lookup tables.
func NewIdentityMap() *IdentityMap {
	return &IdentityMap{
		Users:  make(map[string]string),
		Groups: make(map[string]string),
		UIDs:   make(map[uint32]uint32),
		GIDs:   make(map[uint32]uint32),
		SIDs:   make(map[string]string),
	}
}

// LoadIdentityMapFromFile reads and parses an IdentityMap JSON file at an absolute path.
func LoadIdentityMapFromFile(filePath string) (*IdentityMap, error) {
	cleanPath, err := ValidateAndCleanPath(filePath)
	if err != nil {
		return nil, fmt.Errorf("invalid identity map path: %w", err)
	}

	// #nosec G304 -- Identity map configuration file path is validated and sanitized via ValidateAndCleanPath.
	data, err := os.ReadFile(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read identity map file %q: %w", cleanPath, err)
	}

	idMap := NewIdentityMap()
	if err := json.Unmarshal(data, idMap); err != nil {
		return nil, fmt.Errorf("failed to parse identity map JSON: %w", err)
	}

	return idMap, nil
}

// LoadIdentityMapFromReader parses an IdentityMap from an io.Reader stream.
func LoadIdentityMapFromReader(r io.Reader) (*IdentityMap, error) {
	if r == nil {
		return NewIdentityMap(), nil
	}

	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read identity map stream: %w", err)
	}

	idMap := NewIdentityMap()
	if len(data) == 0 {
		return idMap, nil
	}

	if err := json.Unmarshal(data, idMap); err != nil {
		return nil, fmt.Errorf("failed to parse identity map JSON: %w", err)
	}

	return idMap, nil
}

// TranslateUser returns the mapped username, or original if unmapped.
func (m *IdentityMap) TranslateUser(u string) string {
	if m == nil || len(m.Users) == 0 || u == "" {
		return u
	}
	if target, ok := m.Users[u]; ok && target != "" {
		return target
	}
	return u
}

// TranslateGroup returns the mapped groupname, or original if unmapped.
func (m *IdentityMap) TranslateGroup(g string) string {
	if m == nil || len(m.Groups) == 0 || g == "" {
		return g
	}
	if target, ok := m.Groups[g]; ok && target != "" {
		return target
	}
	return g
}

// TranslateUID returns the mapped UID if present.
func (m *IdentityMap) TranslateUID(uid uint32) (uint32, bool) {
	if m == nil || len(m.UIDs) == 0 {
		return uid, false
	}
	if target, ok := m.UIDs[uid]; ok {
		return target, true
	}
	return uid, false
}

// TranslateGID returns the mapped GID if present.
func (m *IdentityMap) TranslateGID(gid uint32) (uint32, bool) {
	if m == nil || len(m.GIDs) == 0 {
		return gid, false
	}
	if target, ok := m.GIDs[gid]; ok {
		return target, true
	}
	return gid, false
}

// TranslateSID returns the mapped SID, or original if unmapped.
func (m *IdentityMap) TranslateSID(sid string) string {
	if m == nil || len(m.SIDs) == 0 || sid == "" {
		return sid
	}
	if target, ok := m.SIDs[sid]; ok && target != "" {
		return target
	}
	return sid
}

// TranslateSDDL executes token-guided replacement of mapped SIDs in an SDDL string.
func (m *IdentityMap) TranslateSDDL(sddl string) string {
	if m == nil || len(m.SIDs) == 0 || sddl == "" {
		return sddl
	}

	sids := make([]string, 0, len(m.SIDs))
	for s := range m.SIDs {
		sids = append(sids, s)
	}
	slices.SortFunc(sids, func(a, b string) int {
		return len(b) - len(a)
	})

	result := sddl
	for _, oldSID := range sids {
		newSID := m.SIDs[oldSID]
		if newSID != "" && oldSID != newSID {
			result = strings.ReplaceAll(result, oldSID, newSID)
		}
	}
	return result
}

// TranslateACLText rewrites POSIX getfacl text entries by replacing mapped users and groups.
func (m *IdentityMap) TranslateACLText(aclText string) string {
	if m == nil || aclText == "" {
		return aclText
	}
	if len(m.Users) == 0 && len(m.Groups) == 0 {
		return aclText
	}

	delimiter := "\n"
	if strings.Contains(aclText, ",") && !strings.Contains(aclText, "\n") {
		delimiter = ","
	}

	lines := strings.Split(aclText, delimiter)
	rebuilt := make([]string, 0, len(lines))

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			rebuilt = append(rebuilt, line)
			continue
		}

		parts := strings.Split(trimmed, ":")
		isDefault := false
		idx := 0
		if len(parts) >= 4 && (parts[0] == "d" || parts[0] == "default") {
			isDefault = true
			idx = 1
		}

		if idx < len(parts)-2 {
			tag := parts[idx]
			name := parts[idx+1]

			if (tag == "u" || tag == "user") && name != "" {
				parts[idx+1] = m.TranslateUser(name)
			} else if (tag == "g" || tag == "group") && name != "" {
				parts[idx+1] = m.TranslateGroup(name)
			}
		}

		if isDefault {
			rebuilt = append(rebuilt, strings.Join(parts, ":"))
		} else {
			rebuilt = append(rebuilt, strings.Join(parts, ":"))
		}
	}

	return strings.Join(rebuilt, delimiter)
}

// ApplyToPlatformMeta returns a copy of PlatformMeta with all mapped identities translated.
func (m *IdentityMap) ApplyToPlatformMeta(meta PlatformMeta) PlatformMeta {
	if m == nil {
		return meta
	}

	cloned := meta

	if cloned.Username != "" {
		cloned.Username = m.TranslateUser(cloned.Username)
	}
	if cloned.Group != "" {
		cloned.Group = m.TranslateGroup(cloned.Group)
	}
	if cloned.UID != nil {
		if newUID, ok := m.TranslateUID(*cloned.UID); ok {
			cloned.UID = &newUID
		}
	}
	if cloned.GID != nil {
		if newGID, ok := m.TranslateGID(*cloned.GID); ok {
			cloned.GID = &newGID
		}
	}
	if cloned.ACLText != "" {
		cloned.ACLText = m.TranslateACLText(cloned.ACLText)
	}

	if cloned.OwnerSID != "" {
		cloned.OwnerSID = m.TranslateSID(cloned.OwnerSID)
	}
	if cloned.GroupSID != "" {
		cloned.GroupSID = m.TranslateSID(cloned.GroupSID)
	}
	if cloned.OwnerName != "" {
		cloned.OwnerName = m.TranslateUser(cloned.OwnerName)
	}
	if cloned.GroupName != "" {
		cloned.GroupName = m.TranslateGroup(cloned.GroupName)
	}
	if cloned.SDDL != "" {
		cloned.SDDL = m.TranslateSDDL(cloned.SDDL)
	}

	return cloned
}
