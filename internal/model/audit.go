// Package model provides asynchronous machine-readable audit logging.
//
// Objectives:
//   - Emit structured, non-blocking NDJSON telemetry records for compliance and auditability.
//   - Decouple filesystem scanning and restoration throughput from disk logging latency.
//   - Ensure zero race conditions and zero panics during concurrent logging and shutdown.
//
// Core Components:
//   - AuditLogger: Concurrency-safe logger managing a channel buffer, background worker, and buffered I/O.
//   - Worker Loop: Consumes audit records, serializes NDJSON lines, and flushes periodically (250ms ticker).
//   - Concurrency Guards: closeMu (sync.RWMutex) guards channel sends during teardown; syncMu serializes buffer flushes.
//
// Data Flow:
//
//	Subsystem Event -> AuditLogger.Log() -> Buffered Channel -> Worker Goroutine -> JSON Marshal -> 64KB bufio.Writer -> Storage Sync.
package model

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

const DefaultAuditQueueCapacity = 100000

type syncer interface {
	Sync() error
}

type AuditLogger struct {
	writer      io.Writer
	bufferedW   *bufio.Writer
	closer      io.Closer
	queue       chan AuditLogRecord
	done        chan struct{}
	wg          sync.WaitGroup
	closed      atomic.Bool
	seq         atomic.Uint64
	droppedLogs atomic.Uint64
	syncMu      sync.Mutex
	closeMu     sync.RWMutex
}

func NewAuditLogger(w io.Writer, queueCap int) *AuditLogger {
	if queueCap <= 0 {
		queueCap = DefaultAuditQueueCapacity
	}

	bufW := bufio.NewWriterSize(w, 64*1024)

	al := &AuditLogger{
		writer:    w,
		bufferedW: bufW,
		queue:     make(chan AuditLogRecord, queueCap),
		done:      make(chan struct{}),
	}

	if c, ok := w.(io.Closer); ok {
		al.closer = c
	}

	al.wg.Add(1)
	go al.worker()

	return al
}

func NewAuditLoggerFromFile(logPath string, queueCap int) (*AuditLogger, error) {
	cleanPath, err := ValidateAndCleanPath(logPath)
	if err != nil {
		return nil, fmt.Errorf("audit log path invalid: %w", err)
	}

	// #nosec G304 -- Audit log destination path is validated and cleaned via ValidateAndCleanPath.
	f, err := os.OpenFile(cleanPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("failed to open audit log file %q: %w", cleanPath, err)
	}

	return NewAuditLogger(f, queueCap), nil
}

func (al *AuditLogger) worker() {
	defer al.wg.Done()

	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case rec, ok := <-al.queue:
			if !ok {
				for r := range al.queue {
					al.writeRecord(r)
				}
				al.flushBuffer()
				return
			}
			al.writeRecord(rec)

		case <-ticker.C:
			al.flushBuffer()
		}
	}
}

func (al *AuditLogger) writeRecord(rec AuditLogRecord) {
	if rec.Timestamp.IsZero() {
		rec.Timestamp = time.Now().UTC()
	} else {
		rec.Timestamp = rec.Timestamp.UTC()
	}

	data, err := json.Marshal(rec)
	if err != nil {
		return
	}

	al.syncMu.Lock()
	_, _ = al.bufferedW.Write(data)
	_ = al.bufferedW.WriteByte('\n')
	al.syncMu.Unlock()
}

func (al *AuditLogger) flushBuffer() {
	al.syncMu.Lock()
	defer al.syncMu.Unlock()
	_ = al.bufferedW.Flush()
}

func (al *AuditLogger) Log(rec AuditLogRecord) {
	if al == nil {
		return
	}

	al.closeMu.RLock()
	defer al.closeMu.RUnlock()

	if al.closed.Load() {
		al.droppedLogs.Add(1)
		return
	}

	al.seq.Add(1)

	select {
	case al.queue <- rec:
	default:
		select {
		case al.queue <- rec:
		case <-time.After(50 * time.Millisecond):
			al.droppedLogs.Add(1)
		}
	}
}

func (al *AuditLogger) LogInfo(subsystem, event, path string, details map[string]any) {
	al.Log(AuditLogRecord{
		Level:     "INFO",
		Subsystem: subsystem,
		Event:     event,
		Path:      path,
		Details:   details,
	})
}

func (al *AuditLogger) LogWarn(subsystem, event, path, errStr string, details map[string]any) {
	al.Log(AuditLogRecord{
		Level:     "WARN",
		Subsystem: subsystem,
		Event:     event,
		Path:      path,
		Error:     errStr,
		Details:   details,
	})
}

func (al *AuditLogger) LogError(subsystem, event, path, errStr string, details map[string]any) {
	al.Log(AuditLogRecord{
		Level:     "ERROR",
		Subsystem: subsystem,
		Event:     event,
		Path:      path,
		Error:     errStr,
		Details:   details,
	})
}

func (al *AuditLogger) LogAudit(subsystem, event, path string, details map[string]any) {
	al.Log(AuditLogRecord{
		Level:     "AUDIT",
		Subsystem: subsystem,
		Event:     event,
		Path:      path,
		Details:   details,
	})
}

func (al *AuditLogger) Sync() error {
	if al == nil {
		return nil
	}

	al.flushBuffer()

	al.syncMu.Lock()
	defer al.syncMu.Unlock()

	if s, ok := al.writer.(syncer); ok {
		return s.Sync()
	}
	return nil
}

func (al *AuditLogger) Close() error {
	if al == nil {
		return nil
	}

	al.closeMu.Lock()
	if !al.closed.CompareAndSwap(false, true) {
		al.closeMu.Unlock()
		return nil
	}
	close(al.queue)
	al.closeMu.Unlock()

	al.wg.Wait()

	al.flushBuffer()

	al.syncMu.Lock()
	defer al.syncMu.Unlock()

	var err error
	if s, ok := al.writer.(syncer); ok {
		_ = s.Sync()
	}
	if al.closer != nil {
		err = al.closer.Close()
	}
	return err
}

func (al *AuditLogger) DroppedCount() uint64 {
	if al == nil {
		return 0
	}
	return al.droppedLogs.Load()
}
