// Package model defines canonical error types and sentinel values for dtreesync.
//
// Objectives:
//   - Establish predictable, typed errors across scanner, format, storage, and restore engines.
//   - Provide unwrappable error wrappers carrying contextual path and verification telemetry.
//   - Support standard errors.Is and errors.As assertions for programmatic caller error handling.
//
// Core Components:
//   - Sentinel Errors: Predefined errors representing drift, corruption, privilege deficits, and bounds escapes.
//   - PathError: Contextual wrapper attaching operation name ("mkdir", "chmod", "xattr") and filesystem path.
//   - VerificationError: Diagnostic wrapper reporting cryptographic hash deviations and framing faults.
//
// Data Flow:
//
//	Subsystem Error -> Wrapped as PathError or VerificationError -> Inspected via errors.Is -> Mapped to CLI Exit Code.
package model

import (
	"errors"
	"fmt"
)

// Typed Sentinel Errors defined by dtreesync specification.
var (
	ErrDriftDetected          = errors.New("dtreesync: live directory state differs from snapshot")
	ErrSnapshotCorrupted      = errors.New("dtreesync: malformed header or payload checksum mismatch")
	ErrVerificationFailed     = errors.New("dtreesync: cryptographic checksum mismatch or corrupt archive framing")
	ErrPrivilegeRequired      = errors.New("dtreesync: operation requires elevated administrator/root privileges")
	ErrBoundaryEscaped        = errors.New("dtreesync: directory traversal outside target root prevented by os.Root sandbox")
	ErrSnapshotNotFound       = errors.New("dtreesync: specified snapshot source could not be resolved")
	ErrRelativePathNotAllowed = errors.New("dtreesync: relative paths are strictly prohibited; path must be absolute and sanitized")
	ErrInvalidPath            = errors.New("dtreesync: path contains null bytes, invalid characters, or escapes root")
	ErrSignalInterrupted      = errors.New("dtreesync: operation interrupted by signal")
	ErrFormatUnsupported      = errors.New("dtreesync: unsupported serialization format")
	ErrCompressionUnsupported = errors.New("dtreesync: unsupported compression format")
	ErrIOPSLimitExceeded      = errors.New("dtreesync: IOPS rate limit exceeded")
	ErrSchemaMismatch         = errors.New("dtreesync: snapshot schema version mismatch")
)

// PathError records an error associated with a specific file or directory path.
type PathError struct {
	Op   string
	Path string
	Err  error
}

func (e *PathError) Error() string {
	if e == nil {
		return "<nil>"
	}
	return fmt.Sprintf("dtreesync %s %q: %v", e.Op, e.Path, e.Err)
}

func (e *PathError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// VerificationError encapsulates detailed reasons for cryptographic verification failure.
type VerificationError struct {
	TreeFile string
	Expected string
	Actual   string
	Issues   []string
}

func (e *VerificationError) Error() string {
	if e == nil {
		return "<nil>"
	}
	if len(e.Issues) > 0 {
		return fmt.Sprintf("verification failed for %q: expected %s, got %s (issues: %v)", e.TreeFile, e.Expected, e.Actual, e.Issues)
	}
	return fmt.Sprintf("verification failed for %q: expected SHA-256 %s, got %s", e.TreeFile, e.Expected, e.Actual)
}

func (e *VerificationError) Unwrap() error {
	if e == nil {
		return nil
	}
	return ErrVerificationFailed
}
