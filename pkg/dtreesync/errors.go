// Package dtreesync provides public typed sentinel errors and error structures.
//
// Objectives:
//   - Provide public sentinel error references for standard errors.Is and errors.As assertions.
//   - Enable programmatic inspection of path errors and cryptographic verification issues.
//
// Core Components:
//   - Sentinel Errors: Re-exports ErrDriftDetected, ErrSnapshotCorrupted, ErrVerificationFailed, etc.
//   - Error Wrappers: PathError (operation and path context) and VerificationError (hash/framing diagnostic).
//
// Data Flow:
//
//	Engine Error -> Re-exported Error Sentinels -> Caller errors.Is() / errors.As() Matchers.
package dtreesync

import (
	"github.com/edsilegxrepo/dtreesync/internal/model"
)

// Typed Sentinel Errors defined by dtreesync specification.
var (
	ErrDriftDetected          = model.ErrDriftDetected
	ErrSnapshotCorrupted      = model.ErrSnapshotCorrupted
	ErrVerificationFailed     = model.ErrVerificationFailed
	ErrPrivilegeRequired      = model.ErrPrivilegeRequired
	ErrBoundaryEscaped        = model.ErrBoundaryEscaped
	ErrSnapshotNotFound       = model.ErrSnapshotNotFound
	ErrRelativePathNotAllowed = model.ErrRelativePathNotAllowed
	ErrInvalidPath            = model.ErrInvalidPath
	ErrSignalInterrupted      = model.ErrSignalInterrupted
	ErrFormatUnsupported      = model.ErrFormatUnsupported
	ErrCompressionUnsupported = model.ErrCompressionUnsupported
	ErrIOPSLimitExceeded      = model.ErrIOPSLimitExceeded
	ErrSchemaMismatch         = model.ErrSchemaMismatch
)

// PathError records an error associated with a specific file or directory path.
type PathError = model.PathError

// VerificationError encapsulates detailed reasons for cryptographic verification failure.
type VerificationError = model.VerificationError
