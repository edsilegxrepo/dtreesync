// Package dtreesync provides the primary public API surface for directory synchronization.
//
// Objectives:
//   - Expose clean, idiomatic Go functions for Backup, Restore, Diff, Verify, and Header Inspection.
//   - Unify audit logger lifecycle management across all entry points.
//   - Deliver transparent decompression and format parsing for streaming snapshot consumers.
//
// Core Components:
//   - Backup: Master backup facade dispatching to core.Backup.
//   - Restore: Master reconstitution facade dispatching to core.Restore.
//   - Diff: Master compliance comparison facade dispatching to core.Diff.
//   - Verify: Master zero-disk cryptographic verification facade dispatching to core.Verify.
//   - InspectHeader: Microsecond Line 1 peeker detecting Zstandard magic bytes (0xFD2FB528) and SQLite headers.
//   - initAuditLogger: Factory resolving direct writers or log files with deferred cleanup closures.
//
// Data Flow:
//
//	Client Call -> BackupConfig / RestoreConfig / DiffConfig / VerifyConfig -> initAuditLogger()
//	-> core Engine Invocation -> Result Container Returned.
package dtreesync

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/edsilegxrepo/dtreesync/internal/core"
	"github.com/edsilegxrepo/dtreesync/internal/format"
)

// Backup scans a directory tree and serializes structure and security metadata into a snapshot archive.
func Backup(ctx context.Context, cfg BackupConfig) (*BackupResult, error) {
	al, cleanup, err := initAuditLogger(cfg.AuditLogWriter, cfg.LogFile)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	return core.Backup(ctx, cfg, al)
}

// Restore materializes a directory tree from a snapshot archive with depth-sorted ordering and timestamp fidelity.
func Restore(ctx context.Context, cfg RestoreConfig) (*RestoreResult, error) {
	al, cleanup, err := initAuditLogger(cfg.AuditLogWriter, cfg.LogFile)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	return core.Restore(ctx, cfg, al)
}

// Diff compares a live directory tree against a baseline snapshot and reports any structural or permission drift.
func Diff(ctx context.Context, cfg DiffConfig) (*DiffResult, error) {
	al, cleanup, err := initAuditLogger(cfg.AuditLogWriter, cfg.LogFile)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	return core.Diff(ctx, cfg, al)
}

// Verify validates cryptographic SHA-256 payload integrity, Zstandard frame framing, and schema syntax with zero disk writes.
func Verify(ctx context.Context, cfg VerifyConfig) (*VerifyResult, error) {
	al, cleanup, err := initAuditLogger(cfg.AuditLogWriter, cfg.LogFile)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	return core.Verify(ctx, cfg, al)
}

func initAuditLogger(w io.Writer, logFile string) (*AuditLogger, func(), error) {
	if w != nil {
		al := NewAuditLogger(w, 10000)
		return al, func() { _ = al.Close() }, nil
	}
	if logFile != "" {
		al, err := NewAuditLoggerFromFile(logFile, 10000)
		if err != nil {
			return nil, nil, err
		}
		return al, func() { _ = al.Close() }, nil
	}
	return nil, func() {}, nil
}

// InspectHeader reads Line 1 of a snapshot stream (handling Zstandard decompression transparently) in microseconds.
func InspectHeader(ctx context.Context, r io.Reader) (*BackupMetadata, error) {
	bufR := bufio.NewReader(r)

	// Check for SQLite format header ("SQLite format 3\x00")
	if peekSQLite, err := bufR.Peek(16); err == nil {
		if string(peekSQLite) == "SQLite format 3\x00" {
			if f, ok := r.(*os.File); ok {
				return format.ReadSQLiteHeader(f.Name())
			}
			tmp, err := os.CreateTemp("", "dtreesync_peek_sqlite_*.db")
			if err != nil {
				return nil, err
			}
			tmpName := tmp.Name()
			defer func() { _ = os.Remove(tmpName) }()
			if _, err := io.Copy(tmp, bufR); err != nil {
				_ = tmp.Close()
				return nil, err
			}
			_ = tmp.Close()
			return format.ReadSQLiteHeader(tmpName)
		}
	}

	peekMagic, err := bufR.Peek(4)
	if err != nil {
		return nil, fmt.Errorf("failed to peek stream magic bytes: %w", err)
	}

	lineReader := bufR

	// Zstandard magic header: 0xFD2FB528 (little-endian: 0x28, 0xb5, 0x2f, 0xfd)
	if peekMagic[0] == 0x28 && peekMagic[1] == 0xb5 && peekMagic[2] == 0x2f && peekMagic[3] == 0xfd {
		dec, err := format.NewZstdReader(bufR, 1)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize zstd decoder: %w", err)
		}
		defer dec.Close()
		lineReader = bufio.NewReader(dec)
	}

	// Read line 1
	line1, err := lineReader.ReadString('\n')
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("failed to read line 1 from stream: %w", err)
	}

	if len(line1) > 0 && line1[0] == '#' {
		return format.ReadTSVHeader(strings.NewReader(line1))
	}

	return format.ReadNDJSONHeader(strings.NewReader(line1))
}
