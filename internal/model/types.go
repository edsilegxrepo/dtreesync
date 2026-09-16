// Package model defines the core domain models, serialization schemas, configuration
// contracts, telemetry structures, and identity mapping definitions for dtreesync.
//
// Objectives:
//   - Establish a cross-platform data model capturing NTFS and POSIX filesystem metadata.
//   - Provide serialization-agnostic schemas for streaming snapshot headers and directory records.
//   - Define structured configuration and result containers for backup, restore, diff, and verify operations.
//
// Core Components:
//   - BackupMetadata: Snapshot header embedding provenance, timestamps, format, and payload SHA-256.
//   - PlatformMeta: Unified security descriptor containing POSIX (UID/GID/mode/xattr/ACL/SELinux)
//     and Windows (SID/SDDL/attributes) attributes, plus nanosecond timestamps.
//   - DirRecord: Single directory snapshot unit pairing an entity identifier with normalized relative path and metadata.
//   - AuditLogRecord: Machine-readable telemetry record emitted across engine subsystems.
//   - Configuration & Result Structs: Types defining execution parameters and metrics for all engine actions.
//
// Data Flow:
//
//	Scanner (Live FS) -> PlatformMeta -> DirRecord -> Format Encoder -> Storage/Stream
//	Storage/Stream -> Format Decoder -> DirRecord -> IdentityMap / Submitter -> Restore / Diff Engine.
package model

import (
	"io"
	"log/slog"
	"time"
)

// Public Format and Compression Identifiers.
type FormatType string

const (
	FormatTSV    FormatType = "tsv"
	FormatNDJSON FormatType = "ndjson"
	FormatSQLite FormatType = "sqlite"
)

type CompressionType string

const (
	CompressionZstd CompressionType = "zstd"
	CompressionNone CompressionType = "none"
)

// Supported sort orders for directory records during backup.
const (
	SortOrderPath  = "path"
	SortOrderDepth = "depth"
	SortOrderNone  = "none"
)

// BackupMetadata defines the self-contained audit header embedded in every snapshot.
type BackupMetadata struct {
	Version       string    `json:"version"`                  // Schema specification version (e.g. "2.0")
	BaseFolder    string    `json:"base_folder"`              // Canonical source base path
	Entity        string    `json:"entity,omitempty"`         // Filtered entity or empty for all
	CreatedAt     time.Time `json:"created_at"`               // Snapshot creation timestamp in UTC
	FolderCount   int64     `json:"folder_count"`             // Total directory nodes recorded
	TreeFile      string    `json:"tree_file"`                // Output artifact name
	TreeFormat    string    `json:"tree_format"`              // Serialization engine: "tsv", "ndjson", "sqlite"
	Compression   bool      `json:"compression"`              // Zstandard compression flag
	HostOS        string    `json:"host_os"`                  // runtime.GOOS ("linux" or "windows")
	Hostname      string    `json:"hostname"`                 // FQDN or hostname of scanner node
	PayloadSHA256 string    `json:"payload_sha256,omitempty"` // SHA-256 hash of uncompressed data payload
	SortOrder     string    `json:"sort_order,omitempty"`     // Sort order: "path", "depth", "none"
}

// PlatformMeta encapsulates cross-platform filesystem permissions and security attributes.
type PlatformMeta struct {
	// POSIX / Enterprise Linux (NSS, SSSD, PAM, Kerberos, OpenLDAP)
	UID            *uint32 `json:"uid,omitempty"`         // Numeric POSIX User ID
	GID            *uint32 `json:"gid,omitempty"`         // Numeric POSIX Group ID
	Username       string  `json:"username,omitempty"`    // Canonical name (e.g. alice@corp.local)
	Group          string  `json:"group,omitempty"`       // Canonical group (e.g. domain admins@corp.local)
	Mode           *uint32 `json:"mode,omitempty"`        // Standard chmod bitmask (e.g. 0755, 02775)
	ACLAccess      string  `json:"acl_access,omitempty"`  // Hex-encoded binary system.posix_acl_access
	ACLDefault     string  `json:"acl_default,omitempty"` // Hex-encoded binary system.posix_acl_default
	ACLText        string  `json:"acl_text,omitempty"`    // Canonical portable POSIX text representation (getfacl format)
	SELinuxContext string  `json:"selinux,omitempty"`     // Raw string security.selinux context

	// Windows NTFS / Active Directory
	OwnerSID       string  `json:"owner_sid,omitempty"`  // Owner Security Identifier (e.g. S-1-5-21-...)
	GroupSID       string  `json:"group_sid,omitempty"`  // Primary Group Security Identifier
	OwnerName      string  `json:"owner_name,omitempty"` // DOMAIN\User account string
	GroupName      string  `json:"group_name,omitempty"` // DOMAIN\Group account string
	SDDL           string  `json:"sddl,omitempty"`       // Security Descriptor Definition Language string (with D:P)
	FileAttributes *uint32 `json:"file_attrs,omitempty"` // Win32 bitmask (Hidden, ReadOnly, System, etc.)

	// Timestamps
	BirthTime  int64 `json:"btime,omitempty"` // Epoch nanoseconds of creation time (NTFS btime)
	ModTime    int64 `json:"mtime"`           // Epoch nanoseconds of modification time
	AccessTime int64 `json:"atime,omitempty"` // Epoch nanoseconds of access time
	ChangeTime int64 `json:"ctime,omitempty"` // Epoch nanoseconds of metadata change time
}

// DirRecord represents a single discovered directory in the snapshot stream.
type DirRecord struct {
	Entity   string       `json:"entity"`   // Immediate root subfolder (partner ID) or assigned entity
	RelPath  string       `json:"rel_path"` // Normalized relative path using forward slashes ("/")
	Metadata PlatformMeta `json:"meta"`     // Platform-specific security descriptors and timestamps
}

// NDJSONHeader defines Line 1 of an NDJSON (.jsonl) snapshot stream.
type NDJSONHeader struct {
	Meta BackupMetadata `json:"_meta"`
}

// TreePayload defines legacy single-document JSON envelope (if raw array requested).
type TreePayload struct {
	Metadata BackupMetadata `json:"metadata"`
	Records  []DirRecord    `json:"records"`
}

// AuditLogRecord represents a single machine-readable NDJSON entry emitted to --log <file>.
type AuditLogRecord struct {
	Timestamp time.Time      `json:"timestamp"`         // RFC3339 timestamp in UTC
	Level     string         `json:"level"`             // Severity: "INFO", "WARN", "ERROR", "AUDIT"
	Subsystem string         `json:"subsystem"`         // "scanner", "restore", "mirror", "diff", "retention", "verify", "core"
	Event     string         `json:"event"`             // Lifecycle event: "job_start", "dir_scanned", "dir_created", "perm_applied", "drift_detected", "evacuated", "retention_purged", "verify_pass", "verify_fail", "job_complete", "job_error", "memory_limit_adjusted"
	Path      string         `json:"path,omitempty"`    // Sanitized absolute path
	Details   map[string]any `json:"details,omitempty"` // Contextual telemetry metrics
	Error     string         `json:"error,omitempty"`   // Error message if level is WARN or ERROR
}

// IdentityMap specifies translation tables for migrating across domains, accounts, or UID/GID spaces.
type IdentityMap struct {
	Users  map[string]string `json:"users,omitempty"`  // Source username -> Target username (e.g. "alice@old.local": "alice@new.local")
	Groups map[string]string `json:"groups,omitempty"` // Source groupname -> Target groupname
	UIDs   map[uint32]uint32 `json:"uids,omitempty"`   // Source numeric UID -> Target numeric UID
	GIDs   map[uint32]uint32 `json:"gids,omitempty"`   // Source numeric GID -> Target numeric GID
	SIDs   map[string]string `json:"sids,omitempty"`   // Source Windows SID -> Target Windows SID
}

// VerifyResult encapsulates the outcome of a zero-disk-write cryptographic stream verification.
type VerifyResult struct {
	TreeFile       string        `json:"tree_file"`
	Format         string        `json:"format"`
	Compression    bool          `json:"compression"`
	RecordCount    int64         `json:"record_count"`
	PayloadSHA256  string        `json:"payload_sha256"`
	ExpectedSHA256 string        `json:"expected_sha256,omitempty"`
	ChecksumValid  bool          `json:"checksum_valid"`
	FramesValid    bool          `json:"frames_valid"`
	SyntaxValid    bool          `json:"syntax_valid"`
	Duration       time.Duration `json:"duration"`
	Errors         []string      `json:"errors,omitempty"`
}

// BackupConfig defines configuration parameters for a programmatic backup session.
type BackupConfig struct {
	BaseFolder      string          // Required: sanitized absolute path to the source root directory
	Entity          string          // Optional: restricts scanning to a single immediate top-level partner/tenant folder
	TargetURL       string          // Target destination: absolute path, s3://, gs://, azblob://, git://
	Writer          io.Writer       // Direct stream writer (takes precedence over TargetURL if non-nil)
	LogFile         string          // Optional: absolute path to NDJSON audit log file
	AuditLogWriter  io.Writer       // Optional: direct stream writer for machine-readable NDJSON audit log
	Format          FormatType      // Target format (default: FormatNDJSON)
	Compression     CompressionType // Target compression (default: CompressionZstd)
	Workers         int             // Concurrent scanning workers (default: min(NumCPU * 2, 32), clamped 1..32)
	MaxIOPS         int             // Token-bucket filesystem IOPS limit (0 for unlimited)
	MaxMemoryMB     int             // Runtime soft memory limit via debug.SetMemoryLimit (0 for unlimited)
	Include         []string        // Glob filter patterns to include
	Exclude         []string        // Glob filter patterns to exclude
	OneFileSystem   bool            // Confine scan to the initial filesystem mount point
	RetentionDays   int             // FIFO retention window in days (0 to disable)
	RetentionCount  int             // FIFO retention count (0 to disable)
	RetentionPrefix string          // Optional: filter snapshots by filename prefix during retention
	Logger          *slog.Logger    // Pluggable structured logger (default: slog.Default())
	SecretKey       string          // Optional: direct SecretProtector AES-256-GCM master key (hex or raw)
	SecretKeyFile   string          // Optional: path to file containing SecretProtector master key
	SortOrder       string          // Optional: record sort order: "path" (default), "depth", "none"
}

// BackupResult returns execution statistics upon backup completion.
type BackupResult struct {
	FolderCount  int64         `json:"folder_count"`
	PayloadBytes int64         `json:"payload_bytes"`
	Duration     time.Duration `json:"duration"`
	SHA256Hash   string        `json:"sha256_hash,omitempty"`
	ArtifactURL  string        `json:"artifact_url,omitempty"`
}

// RestoreConfig defines configuration parameters for a directory reconstitution session.
type RestoreConfig struct {
	SourceURL          string                      // Snapshot source: absolute path, s3://, gs://, azblob://, git://
	Reader             io.Reader                   // Direct stream reader (takes precedence over SourceURL if non-nil)
	TargetFolder       string                      // Required: sanitized absolute destination directory root
	BaseSubstitute     string                      // Optional: "<old_abs_path>,<new_abs_path>" to re-root snapshot and rewrite base paths
	IdentityMap        *IdentityMap                // Optional: cross-domain user/group/UID/GID/SID translation table
	Entities           []string                    // Optional: selective restore scoping to specified tenant entities
	Include            []string                    // Glob filter patterns to include
	Exclude            []string                    // Glob filter patterns to exclude
	LogFile            string                      // Optional: absolute path to NDJSON audit log file
	AuditLogWriter     io.Writer                   // Optional: direct stream writer for machine-readable NDJSON audit log
	Format             FormatType                  // Format override (auto-deduced if empty)
	Compression        CompressionType             // Compression override (auto-deduced if empty)
	Type               string                      // Synchronization mode: "incremental" (default) or "mirror"
	ArchiveExtraFolder string                      // Mirror mode: destination path for .tar.zst archive of evacuated extra items
	ApplyPerms         bool                        // Apply owner, group, mode, ACLs, and SDDL (default: true)
	Workers            int                         // Concurrent restoration workers (default: min(NumCPU * 2, 32), clamped 1..32)
	MaxIOPS            int                         // Token-bucket filesystem IOPS limit (0 for unlimited)
	MaxMemoryMB        int                         // Runtime soft memory limit via debug.SetMemoryLimit (0 for unlimited)
	Logger             *slog.Logger                // Pluggable structured logger (default: slog.Default())
	OnProgress         func(stats RestoreProgress) // Real-time progress callback
	SecretKey          string                      // Optional: direct SecretProtector AES-256-GCM master key (hex or raw)
	SecretKeyFile      string                      // Optional: path to file containing SecretProtector master key
}

// RestoreProgress provides progress metrics during live restoration.
type RestoreProgress struct {
	CreatedDirs  int64         `json:"created_dirs"`
	AppliedPerms int64         `json:"applied_perms"`
	CurrentDepth int           `json:"current_depth"`
	ElapsedTime  time.Duration `json:"elapsed_time"`
}

// RestoreResult returns execution metrics upon restore completion.
type RestoreResult struct {
	CreatedFolders   int64         `json:"created_folders"`
	AppliedPerms     int64         `json:"applied_perms"`
	EvacuatedArchive string        `json:"evacuated_archive,omitempty"`
	Warnings         []string      `json:"warnings,omitempty"`
	Duration         time.Duration `json:"duration"`
}

// DiffConfig defines configuration parameters for a live verification session.
type DiffConfig struct {
	LiveFolder     string          // Required: sanitized absolute live directory root to inspect
	SnapshotURL    string          // Absolute path or cloud URL to baseline snapshot
	SnapshotReader io.Reader       // Direct stream reader (takes precedence over SnapshotURL if non-nil)
	IdentityMap    *IdentityMap    // Optional: cross-domain translation table for entity comparisons
	Entities       []string        // Optional: selective diff scoping to specified tenant entities
	Include        []string        // Glob filter patterns to include
	Exclude        []string        // Glob filter patterns to exclude
	LogFile        string          // Optional: absolute path to NDJSON audit log file
	AuditLogWriter io.Writer       // Optional: direct stream writer for machine-readable NDJSON audit log
	Format         FormatType      // Format override (auto-deduced if empty)
	Compression    CompressionType // Compression override (auto-deduced if empty)
	Workers        int             // Concurrent verification workers (default: min(NumCPU * 2, 32), clamped 1..32)
	MaxIOPS        int             // Token-bucket filesystem IOPS limit (0 for unlimited)
	MaxMemoryMB    int             // Runtime soft memory limit via debug.SetMemoryLimit (0 for unlimited)
	IgnoreBTime    bool            // Ignore Windows birth time differences
	IgnoreOwner    bool            // Ignore UID / SID ownership shifts
	Logger         *slog.Logger    // Pluggable structured logger
	SecretKey      string          // Optional: direct SecretProtector AES-256-GCM master key (hex or raw)
	SecretKeyFile  string          // Optional: path to file containing SecretProtector master key
}

// DiffResult encapsulates full drift evaluation results.
type DiffResult struct {
	Status       string        `json:"status"`
	BaseFolder   string        `json:"base_folder"`
	TreeFile     string        `json:"tree_file"`
	TimestampUTC time.Time     `json:"timestamp_utc"`
	Summary      DiffSummary   `json:"summary"`
	TotalDrift   int           `json:"total_drift"`
	DriftItems   []DriftItem   `json:"drift_items"`
	Duration     time.Duration `json:"duration"`
}

// DiffSummary provides numerical aggregate statistics for detected drift.
type DiffSummary struct {
	ExpectedDirectories int64 `json:"expected_directories"`
	ScannedDirectories  int64 `json:"scanned_directories"`
	MissingCount        int64 `json:"missing_count"`
	ExtraCount          int64 `json:"extra_count"`
	DriftCount          int64 `json:"drift_count"`
}

// DriftItem defines an individual drift violation detected during comparison.
type DriftItem struct {
	Path     string `json:"path"`
	Type     string `json:"type"`  // e.g. "permission_drift", "missing_directory", "untracked_directory", "untracked_file", "owner_drift"
	Field    string `json:"field"` // e.g. "mode", "acl", "sddl", "owner", "group", "existence"
	Expected string `json:"expected"`
	Actual   string `json:"actual"`
}

// VerifyConfig defines parameters for zero-disk-write cryptographic stream verification.
type VerifyConfig struct {
	SourceURL      string          // Snapshot source: absolute path, s3://, gs://, azblob://, git://
	Reader         io.Reader       // Direct stream reader (takes precedence over SourceURL if non-nil)
	LogFile        string          // Optional: absolute path to NDJSON audit log file
	AuditLogWriter io.Writer       // Optional: direct stream writer for machine-readable NDJSON audit log
	Format         FormatType      // Format override (auto-deduced if empty)
	Compression    CompressionType // Compression override (auto-deduced if empty)
	Workers        int             // Concurrent parsing workers (default: min(NumCPU * 2, 32), clamped 1..32)
	MaxMemoryMB    int             // Runtime soft memory limit via debug.SetMemoryLimit (0 for unlimited)
	Logger         *slog.Logger    // Pluggable structured logger (default: slog.Default())
	SecretKey      string          // Optional: direct SecretProtector AES-256-GCM master key (hex or raw)
	SecretKeyFile  string          // Optional: path to file containing SecretProtector master key
}

// ScanOptions configures real-time directory traversal without snapshot serialization.
type ScanOptions struct {
	Workers       int                  // Concurrency level (default: min(NumCPU * 2, 32), clamped 1..32)
	MaxIOPS       int                  // Token-bucket filesystem IOPS limit (0 for unlimited)
	Entity        string               // Restricts scanning to a single immediate top-level partner/tenant folder
	Include       []string             // Inclusion glob patterns
	Exclude       []string             // Exclusion glob patterns
	OneFileSystem bool                 // Confine traversal to single mount device
	Logger        *slog.Logger         // Pluggable structured logger
	OnFile        func(relPath string) // Optional callback for live payload file detection without extra disk pass
}
