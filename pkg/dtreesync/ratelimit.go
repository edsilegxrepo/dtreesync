// Package dtreesync provides public token-bucket filesystem IOPS rate limiting.
//
// Objectives:
//   - Expose the rate limiting interface to external callers to throttle filesystem calls.
//
// Core Components:
//   - IOPSLimiter: Token bucket rate regulator.
//   - NewIOPSLimiter: Constructor accepting maxIOPS operations per second.
//
// Data Flow:
//
//	Configured IOPS Limit -> NewIOPSLimiter() -> IOPSLimiter -> Passed to Scan/Backup/Restore.
package dtreesync

import (
	"github.com/edsilegxrepo/dtreesync/internal/model"
)

// IOPSLimiter provides token-bucket filesystem IOPS throttling to protect storage arrays.
type IOPSLimiter = model.IOPSLimiter

// NewIOPSLimiter creates an IOPS limiter. If maxIOPS <= 0, rate limiting is disabled (no-op).
func NewIOPSLimiter(maxIOPS int) *IOPSLimiter {
	return model.NewIOPSLimiter(maxIOPS)
}
