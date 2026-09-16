// Package dtreesync provides high-performance directory tree synchronization,
// baseline snapshot creation, and deep enterprise metadata preservation.
//
// Objectives:
//   - High-throughput discovery, backup, restore, diff, and verification of enterprise directory hierarchies.
//   - Lossless cross-platform preservation of Windows NTFS SDDLs and Linux POSIX ACLs / SELinux contexts.
//   - Zero-payload file I/O overhead processing millions of directories without touching file contents.
//
// Core Components:
//   - Public API Facades: Backup, Restore, Diff, Verify, and ScanDir entry points.
//   - Streaming Iterators: Push-based (RecordIter) and pull-based Go 1.23 standard iterators (IterRecords).
//   - Re-exported Models & Sentinel Errors: Unified types, path validation, rate limiters, and audit loggers.
//
// Data Flow:
//
//	Public API Entry -> Parameter Sanitization -> Internal Engine (Core / Meta / Format / Storage) -> Public Result Types.
//
// Designed specifically for high-density Managed File Transfer (MFT) landing arrays,
// high-security regulated filesystems, and multi-tenant cloud storage meshes,
// dtreesync delivers zero payload file I/O, nanosecond-level timestamp preservation,
// and full enterprise security fidelity across Linux and Windows environments.
//
// Key Capabilities:
//
//   - Zero Payload File Overhead: Inspects and archives directory structures and security
//     metadata exclusively, ignoring file payloads to process millions of nodes in seconds.
//   - Deep Platform Metadata: Preserves POSIX ACLs, SELinux security contexts, and Linux mode
//     on POSIX; preserves Windows NT SDDL security descriptors, inheritance flags (D:P),
//     creation birth times (btime), and Win32 file attributes on NTFS.
//   - Cryptographic Zero-Disk-Write Verification: Cryptographically reconciles streaming
//     snapshots (TSV, NDJSON, SQLite) and validates Zstandard frame integrity without disk spooling.
//   - Cross-Domain Identity Mapping: Declarative translation table for user, group, UID, GID,
//     and SID migrations across disparate Active Directory forests or SSSD domains.
//   - Token-Bucket IOPS Rate Limiter: Bounded disk operations per second to eliminate SAN/NAS
//     saturation during large sweeps.
//   - Two-Tier Signal Handling: Bounded 500ms graceful drain on first SIGINT/SIGTERM, followed
//     by instantaneous fail-safe termination on second signal to eliminate hung processes.
//   - Runtime Soft Memory Guard: Dynamically regulates heap footprint via debug.SetMemoryLimit.
//   - Strict Absolute Path Enforcement: Strict validation rejects any relative path to prevent
//     accidental mutations or security boundary escapes.
package dtreesync
