// Package model provides filesystem I/O rate limiting capabilities.
//
// Objectives:
//   - Protect production storage arrays (SAN/NAS/NVMe) from I/O starvation during intensive scans or restores.
//   - Provide token-bucket rate limiting with microsecond precision and zero-allocation no-op bypass.
//
// Core Components:
//   - IOPSLimiter: Thread-safe token-bucket controller wrapping x/time/rate.Limiter.
//   - Wait / WaitN: Context-aware blocking acquisition points for filesystem operations.
//   - Allow: Non-blocking token consumption check.
//
// Data Flow:
//
//	Worker Goroutine -> IOPSLimiter.Wait(ctx) -> Token Bucket Evaluation -> Filesystem Syscall Execution.
package model

import (
	"context"

	"golang.org/x/time/rate"
)

// IOPSLimiter provides token-bucket filesystem IOPS throttling to protect storage arrays.
type IOPSLimiter struct {
	limiter *rate.Limiter
	enabled bool
	maxIOPS int
}

// NewIOPSLimiter creates an IOPS limiter. If maxIOPS <= 0, rate limiting is disabled (no-op).
func NewIOPSLimiter(maxIOPS int) *IOPSLimiter {
	if maxIOPS <= 0 {
		return &IOPSLimiter{
			enabled: false,
			maxIOPS: 0,
		}
	}

	burst := maxIOPS
	if burst < 1 {
		burst = 1
	}

	return &IOPSLimiter{
		limiter: rate.NewLimiter(rate.Limit(maxIOPS), burst),
		enabled: true,
		maxIOPS: maxIOPS,
	}
}

// Wait blocks until 1 IOPS token is available or until ctx is cancelled.
func (l *IOPSLimiter) Wait(ctx context.Context) error {
	if l == nil || !l.enabled || l.limiter == nil {
		return nil
	}
	return l.limiter.Wait(ctx)
}

// WaitN blocks until n IOPS tokens are available or until ctx is cancelled.
func (l *IOPSLimiter) WaitN(ctx context.Context, n int) error {
	if l == nil || !l.enabled || l.limiter == nil || n <= 0 {
		return nil
	}
	return l.limiter.WaitN(ctx, n)
}

// Allow reports whether 1 IOPS token may be consumed immediately without blocking.
func (l *IOPSLimiter) Allow() bool {
	if l == nil || !l.enabled || l.limiter == nil {
		return true
	}
	return l.limiter.Allow()
}

// IsEnabled returns true if rate limiting is active.
func (l *IOPSLimiter) IsEnabled() bool {
	if l == nil {
		return false
	}
	return l.enabled
}

// Limit returns the configured operations per second limit.
func (l *IOPSLimiter) Limit() int {
	if l == nil {
		return 0
	}
	return l.maxIOPS
}
