// Package dtreesync provides public type aliases for all domain structures.
//
// Objectives:
//   - Expose the complete internal model domain type system to external callers without conversion overhead.
//   - Provide consistent type signatures across the public package boundary.
//
// Core Components:
//   - Format and Compression Identifiers: FormatTSV, FormatNDJSON, FormatSQLite, CompressionZstd, CompressionNone.
//   - Domain Schemas: BackupMetadata, PlatformMeta, DirRecord, NDJSONHeader.
//   - Configuration & Result Types: BackupConfig/Result, RestoreConfig/Result, DiffConfig/Result, VerifyConfig/Result.
//
// Data Flow:
//
//	Public API Callers <-> Type Aliases <-> internal/model Data Structures.
package dtreesync

import (
	"github.com/edsilegxrepo/dtreesync/internal/model"
)

// Public Format and Compression Identifiers.
type FormatType = model.FormatType

const (
	FormatTSV    = model.FormatTSV
	FormatNDJSON = model.FormatNDJSON
	FormatSQLite = model.FormatSQLite
)

type CompressionType = model.CompressionType

const (
	CompressionZstd = model.CompressionZstd
	CompressionNone = model.CompressionNone
)

// Public sort order constants.
const (
	SortOrderPath  = model.SortOrderPath
	SortOrderDepth = model.SortOrderDepth
	SortOrderNone  = model.SortOrderNone
)

// Public type aliases mapping directly to internal/model representations.
type (
	BackupMetadata  = model.BackupMetadata
	PlatformMeta    = model.PlatformMeta
	DirRecord       = model.DirRecord
	NDJSONHeader    = model.NDJSONHeader
	TreePayload     = model.TreePayload
	AuditLogRecord  = model.AuditLogRecord
	VerifyResult    = model.VerifyResult
	BackupConfig    = model.BackupConfig
	BackupResult    = model.BackupResult
	RestoreConfig   = model.RestoreConfig
	RestoreProgress = model.RestoreProgress
	RestoreResult   = model.RestoreResult
	DiffConfig      = model.DiffConfig
	DiffResult      = model.DiffResult
	DiffSummary     = model.DiffSummary
	DriftItem       = model.DriftItem
	VerifyConfig    = model.VerifyConfig
	ScanOptions     = model.ScanOptions
	RecordFilter    = model.RecordFilter
)
