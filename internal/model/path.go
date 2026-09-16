// Package model provides path sanitization and boundary enforcement utilities.
//
// Objectives:
//   - Ensure path safety by strictly validating absolute root paths and normalized relative paths.
//   - Prevent path traversal attacks ("../"), null byte injection, and Windows reserved DOS device collisions.
//   - Facilitate cross-platform path translation and re-rooting (rebasing) between Linux and Windows.
//
// Core Components:
//   - ValidateAndCleanPath: Enforces absolute paths, null-byte absence, and OS-specific root conventions.
//   - ToExtendedWindowsPath: Transparently converts Windows paths to \\?\ or \\?\UNC\ prefixes for 32,767 char MAX_PATH support.
//   - NormalizeRelPath: Produces portable forward-slash relative paths, rejecting traversal escapes.
//   - ParseBaseSubstitute / RebasePath: Parses and executes cross-environment directory tree re-rooting.
//
// Data Flow:
//
//	User Input / Snapshot Record -> Path Sanitizer -> Normalized Path -> Filesystem / Snapshot Engine.
package model

import (
	"fmt"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

// ValidateAndCleanPath validates that a path is non-empty, contains no null bytes,
// is strictly an absolute path (per Section 5.10), and returns the sanitized canonical path.
func ValidateAndCleanPath(p string) (string, error) {
	if p == "" {
		return "", fmt.Errorf("%w: empty path provided", ErrInvalidPath)
	}

	// 1. Null-byte rejection
	if strings.ContainsRune(p, 0) {
		return "", fmt.Errorf("%w: path contains null bytes", ErrInvalidPath)
	}

	// 2. Fail-fast absolute path check
	if !filepath.IsAbs(p) {
		return "", fmt.Errorf("%w: relative path prohibited: %q. You must provide a fully-qualified absolute path (e.g. /var/mft/landing on Linux, C:\\mft\\landing or \\\\server\\share\\landing on Windows)", ErrRelativePathNotAllowed, p)
	}

	// 3. Platform-specific validation
	cleaned := filepath.Clean(p)

	if runtime.GOOS == "windows" {
		// Verify Windows root: drive letter (e.g. C:\) or UNC share (\\server\share) or extended prefix (\\?\)
		if !isWindowsAbsolute(cleaned) {
			return "", fmt.Errorf("%w: path %q is not a valid Windows absolute drive or UNC path", ErrInvalidPath, p)
		}
		parts := strings.Split(cleaned, string(filepath.Separator))
		for _, part := range parts {
			if isReservedWindowsDeviceName(part) {
				return "", fmt.Errorf("%w: path contains reserved device name %q", ErrInvalidPath, part)
			}
		}
	} else {
		// POSIX: must start with "/"
		if !strings.HasPrefix(cleaned, "/") {
			return "", fmt.Errorf("%w: path %q must begin with '/'", ErrRelativePathNotAllowed, p)
		}
	}

	return cleaned, nil
}

// isWindowsAbsolute checks if the path has a Windows drive root (e.g. "C:\"), UNC prefix ("\\server\share"),
// or extended-length prefix ("\\?\").
func isWindowsAbsolute(p string) bool {
	if len(p) >= 3 && isAlpha(p[0]) && p[1] == ':' && (p[2] == '\\' || p[2] == '/') {
		return true
	}
	if strings.HasPrefix(p, `\\?\`) || strings.HasPrefix(p, `\\.\`) {
		return true
	}
	if strings.HasPrefix(p, `\\`) && len(p) > 2 {
		parts := strings.Split(strings.TrimPrefix(p, `\\`), `\`)
		return len(parts) >= 2 && parts[0] != "" && parts[1] != ""
	}
	return false
}

func isAlpha(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// ToExtendedWindowsPath converts a Windows path to an extended-length prefix path (\\?\ or \\?\UNC\)
// if executing on Windows and path length approaches or exceeds Win32 MAX_PATH (260 characters).
func ToExtendedWindowsPath(p string) string {
	if runtime.GOOS != "windows" {
		return p
	}

	cleaned := filepath.Clean(p)
	if strings.HasPrefix(cleaned, `\\?\`) {
		return cleaned
	}

	if strings.HasPrefix(cleaned, `\\`) {
		return `\\?\UNC\` + strings.TrimPrefix(cleaned, `\\`)
	}

	return `\\?\` + cleaned
}

// NormalizeRelPath validates and normalizes a relative directory path stored in DirRecord.RelPath.
func NormalizeRelPath(rel string) (string, error) {
	if rel == "" {
		return "", nil
	}

	if strings.ContainsRune(rel, 0) {
		return "", fmt.Errorf("%w: relative path contains null bytes", ErrInvalidPath)
	}

	slashed := strings.ReplaceAll(rel, "\\", "/")
	slashed = strings.Trim(slashed, "/")

	if slashed == "" || slashed == "." {
		return "", nil
	}

	cleaned := path.Clean(slashed)

	if cleaned == ".." || strings.HasPrefix(cleaned, "../") || strings.Contains(cleaned, "/../") {
		return "", fmt.Errorf("%w: relative path %q attempts directory traversal outside root", ErrBoundaryEscaped, rel)
	}

	// Reject Windows DOS reserved device names (e.g. CON, PRN, AUX, NUL, COM1-9, LPT1-9)
	for _, seg := range strings.Split(cleaned, "/") {
		if isReservedWindowsDeviceName(seg) {
			return "", fmt.Errorf("%w: relative path segment %q is a reserved device name", ErrInvalidPath, seg)
		}
	}

	return cleaned, nil
}

// isReservedWindowsDeviceName checks if a path segment is a Windows reserved DOS device name.
func isReservedWindowsDeviceName(segment string) bool {
	base := segment
	if idx := strings.IndexByte(base, '.'); idx != -1 {
		base = base[:idx]
	}
	switch strings.ToUpper(base) {
	case "CON", "PRN", "AUX", "NUL",
		"COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
		"LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9":
		return true
	}
	return false
}

// ParseBaseSubstitute parses and validates the --base-substitute parameter formatted as "<old_base>,<new_base>".
func ParseBaseSubstitute(sub string) (oldBase, newBase string, err error) {
	if sub == "" {
		return "", "", nil
	}

	parts := strings.Split(sub, ",")
	if len(parts) != 2 {
		return "", "", fmt.Errorf("%w: base-substitute must be formatted as '<old_path>,<new_path>', got %q", ErrInvalidPath, sub)
	}

	oldCleaned, err := ValidateAndCleanPath(strings.TrimSpace(parts[0]))
	if err != nil {
		return "", "", fmt.Errorf("invalid old base path in substitution: %w", err)
	}

	newCleaned, err := ValidateAndCleanPath(strings.TrimSpace(parts[1]))
	if err != nil {
		return "", "", fmt.Errorf("invalid new base path in substitution: %w", err)
	}

	isIdentical := oldCleaned == newCleaned
	if runtime.GOOS == "windows" && strings.EqualFold(oldCleaned, newCleaned) {
		isIdentical = true
	}
	if isIdentical {
		return "", "", fmt.Errorf("%w: old base and new base in substitution are identical: %q", ErrInvalidPath, oldCleaned)
	}

	return oldCleaned, newCleaned, nil
}

// RebasePath re-roots a path from oldBase to newBase.
func RebasePath(targetPath, oldBase, newBase string) string {
	if oldBase == "" || newBase == "" {
		return targetPath
	}

	cleanTarget := filepath.Clean(targetPath)
	cleanOld := filepath.Clean(oldBase)
	cleanNew := filepath.Clean(newBase)

	var matches bool
	if runtime.GOOS == "windows" {
		matches = strings.EqualFold(cleanTarget, cleanOld) ||
			strings.HasPrefix(strings.ToLower(cleanTarget), strings.ToLower(cleanOld)+string(filepath.Separator))
	} else {
		matches = cleanTarget == cleanOld ||
			strings.HasPrefix(cleanTarget, cleanOld+string(filepath.Separator))
	}

	if !matches {
		return targetPath
	}

	rel := cleanTarget[len(cleanOld):]
	rel = strings.TrimPrefix(rel, string(filepath.Separator))
	if rel == "" {
		return cleanNew
	}
	return filepath.Join(cleanNew, rel)
}

// MatchGlob tests whether relPath matches pattern, supporting standard wildcards (*, ?)
// as well as recursive multi-directory wildcards (**).
func MatchGlob(pattern, relPath string) bool {
	// Normalize separators to forward slashes
	pattern = filepath.ToSlash(pattern)
	relPath = filepath.ToSlash(relPath)

	// Clean leading/trailing slashes for uniform matching
	pattern = strings.Trim(pattern, "/")
	relPath = strings.Trim(relPath, "/")

	if pattern == "**" {
		return true
	}
	if pattern == "" || relPath == "" {
		return pattern == relPath
	}

	// Fast path: if no double-star, standard path.Match is fast and sufficient
	if !strings.Contains(pattern, "**") {
		matched, _ := path.Match(pattern, relPath)
		if matched {
			return true
		}
		// Also test against leaf directory/file name
		leaf := path.Base(relPath)
		matchedLeaf, _ := path.Match(pattern, leaf)
		return matchedLeaf
	}

	// Handle ** patterns by converting glob to regex
	var sb strings.Builder
	sb.WriteString("^")
	i := 0
	n := len(pattern)
	for i < n {
		// Context 1: Trailing "/**" at the end of pattern
		if pattern[i:] == "/**" {
			sb.WriteString("(?:/.*)?")
			break
		}
		// Context 2: Leading "**/" at the beginning of pattern
		if i == 0 && strings.HasPrefix(pattern, "**/") {
			sb.WriteString("(?:.*/)?")
			i += 3
			continue
		}
		// Context 3: Middle "/**/"
		if strings.HasPrefix(pattern[i:], "/**/") {
			sb.WriteString("/(?:.*/)?")
			i += 4
			continue
		}
		// Context 4: Double-star "**"
		if i+1 < n && pattern[i] == '*' && pattern[i+1] == '*' {
			sb.WriteString(".*")
			i += 2
			continue
		}
		c := pattern[i]
		switch c {
		case '*':
			sb.WriteString("[^/]*")
		case '?':
			sb.WriteString("[^/]")
		case '.', '+', '(', ')', '|', '{', '}', '[', ']', '^', '$', '\\':
			sb.WriteByte('\\')
			sb.WriteByte(c)
		default:
			sb.WriteByte(c)
		}
		i++
	}
	sb.WriteString("$")

	re, err := regexp.Compile(sb.String())
	if err != nil {
		return false
	}
	return re.MatchString(relPath)
}

// RecordFilter encapsulates entity, inclusion, and exclusion rules for DirRecord items.
type RecordFilter struct {
	Entities []string // Whitelist of top-level tenant entity names (empty permits all)
	Include  []string // Glob patterns for directories to include
	Exclude  []string // Glob patterns for directories to omit
}

// NewRecordFilter creates a filter from lists of entities, include patterns, and exclude patterns.
func NewRecordFilter(entities, include, exclude []string) RecordFilter {
	return RecordFilter{
		Entities: entities,
		Include:  include,
		Exclude:  exclude,
	}
}

// Matches returns true if the record satisfies entity, include, and exclude criteria.
func (f RecordFilter) Matches(rec DirRecord) bool {
	// Entity check: if entities are specified, record must match one
	if len(f.Entities) > 0 && rec.RelPath != "" {
		matched := false
		for _, e := range f.Entities {
			if rec.Entity == e {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Include check: if include patterns specified, record must match at least one
	if len(f.Include) > 0 && rec.RelPath != "" {
		matched := false
		for _, pat := range f.Include {
			if MatchGlob(pat, rec.RelPath) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Exclude check: if exclude patterns specified, matching records are rejected
	if len(f.Exclude) > 0 {
		for _, pat := range f.Exclude {
			if MatchGlob(pat, rec.RelPath) {
				return false
			}
		}
	}

	return true
}
