// Package dtreesync provides unit tests for the asynchronous audit logging engine.
//
// Objectives:
//   - Verify thread-safe asynchronous logging, queue draining, JSON formatting, and shutdown guarantees.
//
// Test Strategy:
//   - Drain & Format: TestAuditLogger_BufferAndDrain writes discrete severity levels (INFO, AUDIT, WARN, ERROR),
//     closes the logger, and asserts valid NDJSON schema and line counts.
//   - Nil Safety: TestAuditLogger_NilSafe confirms that nil logger references execute gracefully without panics.
//   - Concurrency Stress: TestAuditLogger_ConcurrentLogging spawns 10 concurrent goroutines emitting 1,000 log
//     events simultaneously to verify race-free synchronization and lossless channel draining.
//
// Data Flow:
//
//	Concurrent Goroutines -> AuditLogger.Log() -> Background Serialization Worker -> Output Buffer -> Invariant Assertions.
package dtreesync

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestAuditLogger_BufferAndDrain(t *testing.T) {
	var buf bytes.Buffer
	logger := NewAuditLogger(&buf, 100)

	logger.LogInfo("core", "job_start", "/var/mft/landing", map[string]any{
		"workers": 16,
		"format":  "ndjson",
	})

	logger.LogAudit("scanner", "dir_scanned", "/var/mft/landing/partner", map[string]any{
		"mode": "0750",
	})

	logger.LogWarn("diff", "drift_detected", "/var/mft/landing/partner/inbound", "permission drift", map[string]any{
		"expected": "0750",
		"actual":   "0777",
	})

	logger.LogError("restore", "perm_failed", "/var/mft/landing/partner/archive", "access denied", nil)

	// Close logger to drain and flush
	err := logger.Close()
	if err != nil {
		t.Fatalf("unexpected error closing audit logger: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 4 {
		t.Fatalf("expected 4 NDJSON lines, got %d. Output:\n%s", len(lines), buf.String())
	}

	expectedLevels := []string{"INFO", "AUDIT", "WARN", "ERROR"}
	expectedEvents := []string{"job_start", "dir_scanned", "drift_detected", "perm_failed"}

	for i, line := range lines {
		var rec AuditLogRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("line %d is not valid JSON: %v. Line: %s", i, err, line)
		}

		if rec.Level != expectedLevels[i] {
			t.Errorf("line %d: expected level %s, got %s", i, expectedLevels[i], rec.Level)
		}
		if rec.Event != expectedEvents[i] {
			t.Errorf("line %d: expected event %s, got %s", i, expectedEvents[i], rec.Event)
		}
		if rec.Timestamp.IsZero() {
			t.Errorf("line %d: timestamp should not be zero", i)
		}
	}
}

func TestAuditLogger_NilSafe(t *testing.T) {
	var logger *AuditLogger

	// None of these should panic
	logger.Log(AuditLogRecord{})
	logger.LogInfo("sub", "ev", "path", nil)
	logger.LogWarn("sub", "ev", "path", "err", nil)
	logger.LogError("sub", "ev", "path", "err", nil)
	logger.LogAudit("sub", "ev", "path", nil)
	if err := logger.Sync(); err != nil {
		t.Fatalf("nil logger Sync error: %v", err)
	}
	if err := logger.Close(); err != nil {
		t.Fatalf("nil logger Close error: %v", err)
	}
	if drops := logger.DroppedCount(); drops != 0 {
		t.Fatalf("expected 0 drops, got %d", drops)
	}
}

func TestAuditLogger_NewFromFile_InvalidPath(t *testing.T) {
	_, err := NewAuditLoggerFromFile("./relative/audit.jsonl", 10)
	if err == nil {
		t.Fatal("expected error for relative log file path, got nil")
	}
}

func TestAuditLogger_ConcurrentLogging(t *testing.T) {
	var buf bytes.Buffer
	logger := NewAuditLogger(&buf, 5000)

	start := time.Now()
	done := make(chan struct{})

	const numGoroutines = 10
	const msgsPerGoroutine = 100

	for g := 0; g < numGoroutines; g++ {
		go func(id int) {
			for i := 0; i < msgsPerGoroutine; i++ {
				logger.LogInfo("core", "test_event", "/path", map[string]any{
					"worker_id": id,
					"seq":       i,
				})
			}
			done <- struct{}{}
		}(g)
	}

	for g := 0; g < numGoroutines; g++ {
		<-done
	}

	if err := logger.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != numGoroutines*msgsPerGoroutine {
		t.Fatalf("expected %d lines, got %d in %v", numGoroutines*msgsPerGoroutine, len(lines), time.Since(start))
	}
}
