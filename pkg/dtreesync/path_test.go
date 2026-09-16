// Package dtreesync provides unit tests for path sanitization, boundary checking, and normalization.
//
// Objectives:
//   - Ensure complete immunity to directory traversal attacks, null-byte injections, and Windows DOS device collisions.
//   - Verify cross-platform path rebasing and base substitution parsing.
//
// Test Strategy:
//   - Table-Driven Path Cleaning: TestValidateAndCleanPath and TestValidateAndCleanPath_PlatformSpecific test
//     absolute path enforcement, UNC roots, drive prefixes, and relative path rejection.
//   - Traversal & Normalization: TestNormalizeRelPath verifies forward-slash conversion, parent escape ("../") blocking,
//     and redundant slash stripping.
//   - Reserved Device Blocking: TestNormalizeRelPath_ReservedDeviceNames asserts strict rejection of CON, PRN, AUX, NUL,
//     COM1-9, and LPT1-9 device names.
//   - Re-rooting: TestParseBaseSubstitute and TestRebasePath validate path prefix rewriting across different base folders.
//
// Data Flow:
//
//	Path Strings -> Sanitizers & Rebasers -> Clean Slashed Paths / Sentinel Error Assertions.
package dtreesync

import (
	"errors"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestValidateAndCleanPath(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantErr   error
		mustPass  bool
		skipOnWin bool
		skipOnPos bool
	}{
		{
			name:     "empty path",
			input:    "",
			wantErr:  ErrInvalidPath,
			mustPass: false,
		},
		{
			name:     "relative dot-slash",
			input:    "./landing",
			wantErr:  ErrRelativePathNotAllowed,
			mustPass: false,
		},
		{
			name:     "relative simple name",
			input:    "landing",
			wantErr:  ErrRelativePathNotAllowed,
			mustPass: false,
		},
		{
			name:     "null byte injection",
			input:    "/var/mft/\x00evil",
			wantErr:  ErrInvalidPath,
			mustPass: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ValidateAndCleanPath(tt.input)
			if tt.wantErr != nil {
				if err == nil {
					t.Fatalf("expected error containing %v, got nil", tt.wantErr)
				}
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("expected error to wrap %v, got %v", tt.wantErr, err)
				}
			}
		})
	}
}

func TestValidateAndCleanPath_PlatformSpecific(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Run("Windows valid drive path", func(t *testing.T) {
			cleaned, err := ValidateAndCleanPath(`C:\var\mft\..\mft\landing`)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			expected := `C:\var\mft\landing`
			if cleaned != expected {
				t.Fatalf("expected %q, got %q", expected, cleaned)
			}
		})

		t.Run("Windows valid UNC path", func(t *testing.T) {
			cleaned, err := ValidateAndCleanPath(`\\server\share\landing\sub`)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			expected := `\\server\share\landing\sub`
			if cleaned != expected {
				t.Fatalf("expected %q, got %q", expected, cleaned)
			}
		})

		t.Run("Windows relative drive-relative path", func(t *testing.T) {
			_, err := ValidateAndCleanPath(`C:landing`)
			if err == nil || !errors.Is(err, ErrRelativePathNotAllowed) {
				t.Fatalf("expected ErrRelativePathNotAllowed for drive-relative path, got %v", err)
			}
		})
	} else {
		t.Run("POSIX valid root path", func(t *testing.T) {
			cleaned, err := ValidateAndCleanPath("/var/mft/../mft/landing")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			expected := "/var/mft/landing"
			if cleaned != expected {
				t.Fatalf("expected %q, got %q", expected, cleaned)
			}
		})
	}
}

func TestNormalizeRelPath(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
		wantErr  error
	}{
		{name: "empty", input: "", expected: "", wantErr: nil},
		{name: "single dot", input: ".", expected: "", wantErr: nil},
		{name: "simple dir", input: "walmart", expected: "walmart", wantErr: nil},
		{name: "nested with backslashes", input: `walmart\inbound\orders`, expected: "walmart/inbound/orders", wantErr: nil},
		{name: "nested with forward slashes", input: "walmart/inbound/orders", expected: "walmart/inbound/orders", wantErr: nil},
		{name: "leading and trailing slashes", input: "/walmart/inbound/", expected: "walmart/inbound", wantErr: nil},
		{name: "redundant slashes", input: "walmart//inbound///orders", expected: "walmart/inbound/orders", wantErr: nil},
		{name: "null byte", input: "walmart/\x00evil", expected: "", wantErr: ErrInvalidPath},
		{name: "parent directory escape", input: "../secret", expected: "", wantErr: ErrBoundaryEscaped},
		{name: "nested directory escape", input: "walmart/../../secret", expected: "", wantErr: ErrBoundaryEscaped},
		{name: "subpath escape", input: "walmart/inbound/../../../etc", expected: "", wantErr: ErrBoundaryEscaped},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := NormalizeRelPath(tt.input)
			if tt.wantErr != nil {
				if err == nil {
					t.Fatalf("expected error wrapping %v, got nil", tt.wantErr)
				}
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("expected error wrapping %v, got %v", tt.wantErr, err)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if result != tt.expected {
					t.Fatalf("expected %q, got %q", tt.expected, result)
				}
			}
		})
	}
}

func TestParseBaseSubstitute(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Run("valid Windows substitution", func(t *testing.T) {
			oldB, newB, err := ParseBaseSubstitute(`C:\old\base,D:\new\base`)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if oldB != `C:\old\base` || newB != `D:\new\base` {
				t.Fatalf("unexpected result: old=%q, new=%q", oldB, newB)
			}
		})

		t.Run("identical paths error", func(t *testing.T) {
			_, _, err := ParseBaseSubstitute(`C:\same\path,c:\same\path`)
			if err == nil || !errors.Is(err, ErrInvalidPath) {
				t.Fatalf("expected ErrInvalidPath for identical base paths, got %v", err)
			}
		})

		t.Run("relative path in substitution", func(t *testing.T) {
			_, _, err := ParseBaseSubstitute(`C:\old\base,relative\base`)
			if err == nil || !errors.Is(err, ErrRelativePathNotAllowed) {
				t.Fatalf("expected ErrRelativePathNotAllowed, got %v", err)
			}
		})
	} else {
		t.Run("valid POSIX substitution", func(t *testing.T) {
			oldB, newB, err := ParseBaseSubstitute("/var/old,/data/new")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if oldB != "/var/old" || newB != "/data/new" {
				t.Fatalf("unexpected result: old=%q, new=%q", oldB, newB)
			}
		})

		t.Run("identical POSIX paths error", func(t *testing.T) {
			_, _, err := ParseBaseSubstitute("/var/data,/var/data")
			if err == nil || !errors.Is(err, ErrInvalidPath) {
				t.Fatalf("expected ErrInvalidPath for identical base paths, got %v", err)
			}
		})
	}

	t.Run("malformed substitution format", func(t *testing.T) {
		_, _, err := ParseBaseSubstitute("no_comma_here")
		if err == nil || !errors.Is(err, ErrInvalidPath) {
			t.Fatalf("expected ErrInvalidPath for missing comma, got %v", err)
		}
	})
}

func TestRebasePath(t *testing.T) {
	if runtime.GOOS == "windows" {
		oldBase := `C:\mft\legacy`
		newBase := `D:\mft\rehosted`

		// Exact match
		if res := RebasePath(`C:\mft\legacy`, oldBase, newBase); res != `D:\mft\rehosted` {
			t.Fatalf("expected %q, got %q", `D:\mft\rehosted`, res)
		}

		// Child path
		expected := filepath.Join(newBase, "partner_walmart", "inbound")
		target := filepath.Join(oldBase, "partner_walmart", "inbound")
		if res := RebasePath(target, oldBase, newBase); !strings.EqualFold(res, expected) {
			t.Fatalf("expected %q, got %q", expected, res)
		}

		// Unrelated path
		unrelated := `E:\other\folder`
		if res := RebasePath(unrelated, oldBase, newBase); res != unrelated {
			t.Fatalf("expected %q, got %q", unrelated, res)
		}
	} else {
		oldBase := "/mft/legacy"
		newBase := "/mft/rehosted"

		// Exact match
		if res := RebasePath("/mft/legacy", oldBase, newBase); res != "/mft/rehosted" {
			t.Fatalf("expected %q, got %q", "/mft/rehosted", res)
		}

		// Child path
		if res := RebasePath("/mft/legacy/partner/inbound", oldBase, newBase); res != "/mft/rehosted/partner/inbound" {
			t.Fatalf("expected %q, got %q", "/mft/rehosted/partner/inbound", res)
		}
	}
}

func TestNormalizeRelPath_ReservedDeviceNames(t *testing.T) {
	deviceNames := []string{"con", "CON", "prn", "aux", "nul", "NUL", "com1", "COM9", "lpt1", "LPT9", "aux.tar", "nul.txt"}
	for _, dev := range deviceNames {
		testPath := "partner/inbound/" + dev
		_, err := NormalizeRelPath(testPath)
		if err == nil {
			t.Errorf("expected error for reserved device name %q in %q, got nil", dev, testPath)
		}
		if !errors.Is(err, ErrInvalidPath) {
			t.Errorf("expected error to wrap ErrInvalidPath, got %v", err)
		}
	}
}

func TestMatchGlob(t *testing.T) {
	tests := []struct {
		pattern  string
		relPath  string
		expected bool
	}{
		// Exact matches
		{"partner/inbound", "partner/inbound", true},
		{"partner/inbound", "partner/outbound", false},

		// Single level wildcards
		{"partner/*", "partner/inbound", true},
		{"partner/*", "partner/inbound/orders", false},
		{"partner/*/orders", "partner/walmart/orders", true},
		{"partner/*/orders", "partner/walmart/inbound/orders", false},
		{"partner?", "partner1", true},
		{"partner?", "partner12", false},

		// Recursive multi-directory wildcards (**)
		{"**/.snapshot/**", "partner/.snapshot/daily", true},
		{"**/.snapshot/**", ".snapshot/hourly", true},
		{"**/.snapshot/**", "partner/inbound/.snapshot/2026-01-01/file", true},
		{"**/.snapshot/**", "partner/inbound/data", false},
		{"**/lost+found/**", "lost+found", true},
		{"**/lost+found/**", "lost+found/data", true},
		{"**/lost+found/**", "sub/lost+found/file", true},
		{"**/lost+found/**", "sub/lost/file", false},
		{"partner_*/inbound/**", "partner_walmart/inbound", true},
		{"partner_*/inbound/**", "partner_walmart/inbound/2026/01/data", true},
		{"partner_*/inbound/**", "partner_target/inbound/data", true},
		{"partner_*/inbound/**", "partner_target/outbound/data", false},
		{"**", "any/path/whatsoever", true},
		{"**", "", true},
		{"orders/**", "orders", true},
		{"orders/**", "orders/2026/01", true},
		{"orders/**", "other/orders", false},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"_"+tt.relPath, func(t *testing.T) {
			matched := MatchGlob(tt.pattern, tt.relPath)
			if matched != tt.expected {
				t.Errorf("MatchGlob(%q, %q) = %v, want %v", tt.pattern, tt.relPath, matched, tt.expected)
			}
		})
	}
}

func TestToExtendedWindowsPath(t *testing.T) {
	ext := ToExtendedWindowsPath(`C:\data\file.txt`)
	if ext == "" {
		t.Fatal("expected non-empty extended path")
	}
}
