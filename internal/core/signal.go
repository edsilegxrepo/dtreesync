// Package core implements process signal management and standardized exit codes.
//
// Objectives:
//   - Provide deterministic exit codes strictly mapped to enterprise compliance states.
//   - Implement a two-tier signal handler: graceful context cancellation with a 500ms drain deadline on first signal,
//     followed by immediate hard exit (code 130) on a second signal.
//
// Core Components:
//   - Exit Code Constants: Standardized exit codes (0..7) covering success, warnings, drift, corruption, auth, and quota exhaustion.
//   - SetupSignalTrap: Two-tier SIGINT/SIGTERM listener initiating context cancellation and timeouts.
//
// Data Flow:
//
//	OS Signal (SIGINT / SIGTERM) -> Signal Channel -> Tier 1: cancel() & 500ms Drain Timer -> Tier 2: os.Exit(130).
package core

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"
)

// Exit codes strictly enforced by dtreesync specification.
const (
	ExitSuccess            = 0 // Operation completed cleanly without warnings
	ExitFatalError         = 1 // Critical failure, permission denial, or unrecoverable error
	ExitPartialWarning     = 2 // Operation completed with non-fatal warnings
	ExitDriftDetected      = 3 // Discrepancies found between live filesystem and baseline snapshot
	ExitVerificationFailed = 4 // Archive corruption, invalid framing, or checksum mismatch
	ExitAuthFailure        = 5 // Git SSH/token or Cloud IAM credential failure
	ExitUsageError         = 6 // Invalid flags, illegal path combinations, or unparsable syntax
	ExitResourceExhausted  = 7 // Memory limit or IOPS quota reached
)

// SetupSignalTrap sets up the two-tier signal handling mechanism per Section 5.10.
// Tier 1 (First SIGINT/SIGTERM): Cancels the root context to stop enqueuing tasks,
// initiates a 500ms drain deadline for in-flight writes, and calls onDrainTimeout.
// Tier 2 (Second SIGINT/SIGTERM): Triggers immediate hard exit (code 130).
func SetupSignalTrap(ctx context.Context, cancel context.CancelFunc, onDrainTimeout func()) context.Context {
	sigChan := make(chan os.Signal, 2)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	var signalCount atomic.Int32

	go func() {
		for sig := range sigChan {
			count := signalCount.Add(1)
			if count == 1 {
				fmt.Fprintf(os.Stderr, "\n[dtreesync] Received termination signal (%v). Initiating graceful 500ms drain deadline...\n", sig)
				cancel()

				time.AfterFunc(500*time.Millisecond, func() {
					if onDrainTimeout != nil {
						onDrainTimeout()
					}
					fmt.Fprintln(os.Stderr, "[dtreesync] Drain deadline expired. Exiting.")
					os.Exit(ExitFatalError)
				})
			} else {
				fmt.Fprintln(os.Stderr, "\n[dtreesync] Received second termination signal. Forcing immediate termination.")
				os.Exit(130)
			}
		}
	}()

	return ctx
}
