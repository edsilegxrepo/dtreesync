// Package dtreesync provides public constructors for asynchronous audit logging.
//
// Objectives:
//   - Expose the asynchronous NDJSON audit logger to programmatic consumers.
//   - Enable decoupled compliance logging with minimal overhead.
//
// Core Components:
//   - AuditLogger: Concurrency-safe telemetry recorder.
//   - NewAuditLogger / NewAuditLoggerFromFile: Constructors for stream or file-backed loggers.
//
// Data Flow:
//
//	Application Events -> AuditLogger.Log() -> Asynchronous Channel Queue -> NDJSON Stream.
package dtreesync

import (
	"io"

	"github.com/edsilegxrepo/dtreesync/internal/model"
)

// DefaultAuditQueueCapacity is the default buffer size for the in-memory audit log channel.
const DefaultAuditQueueCapacity = model.DefaultAuditQueueCapacity

// AuditLogger provides high-throughput, non-blocking asynchronous NDJSON audit logging.
type AuditLogger = model.AuditLogger

// NewAuditLogger initializes an asynchronous audit logger that serializes records to w.
func NewAuditLogger(w io.Writer, queueCap int) *AuditLogger {
	return model.NewAuditLogger(w, queueCap)
}

// NewAuditLoggerFromFile opens an absolute log path in append mode and initializes the audit logger.
func NewAuditLoggerFromFile(logPath string, queueCap int) (*AuditLogger, error) {
	return model.NewAuditLoggerFromFile(logPath, queueCap)
}
