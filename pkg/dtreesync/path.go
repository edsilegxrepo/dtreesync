// Package dtreesync provides public path sanitization and boundary verification functions.
//
// Objectives:
//   - Expose path validation, extended namespace conversion, and relative path normalization.
//   - Facilitate directory tree re-rooting during cross-environment reconstitution.
//
// Core Components:
//   - ValidateAndCleanPath: Strictly enforces absolute paths and sanitizes separators and null bytes.
//   - ToExtendedWindowsPath: Prepends Win32 extended length namespaces (\\?\).
//   - NormalizeRelPath: Normalizes relative paths to forward slashes and prevents directory traversal.
//   - ParseBaseSubstitute / RebasePath: Splits and applies base re-rooting pairs.
//
// Data Flow:
//
//	Caller Path -> ValidateAndCleanPath() / NormalizeRelPath() -> Sanitized Canonical Path String.
package dtreesync

import (
	"github.com/edsilegxrepo/dtreesync/internal/model"
)

// ValidateAndCleanPath validates that a path is non-empty, contains no null bytes,
// is strictly an absolute path (per Section 5.10), and returns the sanitized canonical path.
func ValidateAndCleanPath(p string) (string, error) {
	return model.ValidateAndCleanPath(p)
}

// ToExtendedWindowsPath converts a Windows path to an extended-length prefix path (\\?\ or \\?\UNC\).
func ToExtendedWindowsPath(p string) string {
	return model.ToExtendedWindowsPath(p)
}

// NormalizeRelPath validates and normalizes a relative directory path stored in DirRecord.RelPath.
func NormalizeRelPath(rel string) (string, error) {
	return model.NormalizeRelPath(rel)
}

// ParseBaseSubstitute parses and validates the --base-substitute parameter formatted as "<old_base>,<new_base>".
func ParseBaseSubstitute(sub string) (oldBase, newBase string, err error) {
	return model.ParseBaseSubstitute(sub)
}

// RebasePath re-roots a path from oldBase to newBase.
func RebasePath(targetPath, oldBase, newBase string) string {
	return model.RebasePath(targetPath, oldBase, newBase)
}

// MatchGlob tests whether relPath matches pattern, supporting standard wildcards (*, ?)
// as well as recursive multi-directory wildcards (**).
func MatchGlob(pattern, relPath string) bool {
	return model.MatchGlob(pattern, relPath)
}
