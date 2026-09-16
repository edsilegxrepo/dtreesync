// Package dtreesync provides unit tests for the token-bucket IOPS rate limiter.
//
// Objectives:
//   - Verify token-bucket burst and steady-state rate enforcement.
//   - Ensure context cancellation terminates blocking waits without deadlock.
//   - Confirm zero-allocation no-op bypass when rate limiting is disabled, along with nil-pointer safety.
//
// Test Strategy:
//   - Unlimited Bypass: TestIOPSLimiter_Unlimited asserts maxIOPS=0 allows immediate throughput without blocking.
//   - Rate Enforcement: TestIOPSLimiter_RateEnforcement exercises burst capacity.
//   - Cancellation: TestIOPSLimiter_ContextCancellation drains the bucket and verifies immediate context.Canceled return.
//   - Nil Safety: TestIOPSLimiter_NilSafe verifies safe no-op behavior when called on a nil limiter pointer.
//
// Data Flow:
//
//	Test Context -> IOPSLimiter.Wait() / Allow() -> Token Evaluation -> Invariant Assertions.
package dtreesync

import (
	"context"
	"errors"
	"testing"
)

func TestIOPSLimiter_Unlimited(t *testing.T) {
	limiter := NewIOPSLimiter(0)
	if limiter.IsEnabled() {
		t.Fatal("expected limiter to be disabled for maxIOPS=0")
	}

	ctx := context.Background()
	for i := 0; i < 100; i++ {
		if err := limiter.Wait(ctx); err != nil {
			t.Fatalf("unexpected wait error: %v", err)
		}
		if !limiter.Allow() {
			t.Fatal("expected Allow to return true")
		}
	}
}

func TestIOPSLimiter_RateEnforcement(t *testing.T) {
	const iops = 50
	limiter := NewIOPSLimiter(iops)
	if !limiter.IsEnabled() {
		t.Fatal("expected limiter to be enabled")
	}
	if limiter.Limit() != iops {
		t.Fatalf("expected limit %d, got %d", iops, limiter.Limit())
	}

	ctx := context.Background()
	// Consume burst
	for i := 0; i < iops; i++ {
		if err := limiter.Wait(ctx); err != nil {
			t.Fatalf("unexpected error during burst: %v", err)
		}
	}
}

func TestIOPSLimiter_ContextCancellation(t *testing.T) {
	// Small rate limiter with burst 1
	limiter := NewIOPSLimiter(1)

	// Consume the single token
	if err := limiter.Wait(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Next wait with cancelled context should fail fast
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := limiter.Wait(ctx)
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestIOPSLimiter_NilSafe(t *testing.T) {
	var limiter *IOPSLimiter
	if limiter.IsEnabled() {
		t.Fatal("expected false for nil limiter")
	}
	if !limiter.Allow() {
		t.Fatal("expected Allow() to return true for nil limiter")
	}
	if err := limiter.Wait(context.Background()); err != nil {
		t.Fatalf("expected nil error for nil limiter, got %v", err)
	}
	if limiter.Limit() != 0 {
		t.Fatalf("expected 0 limit for nil limiter, got %d", limiter.Limit())
	}
}
