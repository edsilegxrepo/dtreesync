# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v0.1.0] - 2026-09-15

Initial release of `dtreesync`, a high-performance directory tree synchronization, restoration, and compliance auditing engine for enterprise MFT and cloud infrastructure.

### Added
- **Zero File Payload I/O Scanner:** High-throughput concurrent discovery engine discarding regular files at the kernel boundary via `f.ReadDir(-1)` and Linux `unix.Getdents64`.
- **Forensic Security & ACL Fidelity:** Full fidelity capture and restoration of Linux POSIX ACLs, SSSD/NSS identity caches, SELinux contexts, and Windows NTFS SDDL (`D:P` protected) with creation timestamps (`btime`).
- **Topological Two-Pass Restoration:** Top-down directory hierarchy creation followed by bottom-up reverse-depth timestamp and permission application ($D_{\max} \to 0$).
- **Streaming Wire Formats:** High-density TSV (`#META:`), streaming NDJSON (`_meta`), and pure-Go SQLite snapshot serialization backed by multi-threaded Zstandard compression.
- **Storage & Git Compliance:** Direct streaming to AWS S3, GCS, Azure Blob (`gocloud.dev`), in-memory Git compliance commits (`go-git/v5`), and SecretProtector credential integration.
- **Audit & Verification Engines:** Non-destructive `diff` drift detection engine, zero-disk cryptographic `verify` command (SHA-256 payload and Zstd frame checking), and SIEM-ready NDJSON audit logging (`--log`).
- **Public Go SDK:** First-class programmatic Go library (`pkg/dtreesync`) featuring Go 1.27+ range-over-func streaming iterators (`iter.Seq2[DirRecord, error]`).
- **Runtime Guardrails:** Kernel sandboxing via `os.OpenRoot`, strict absolute path validation, token-bucket IOPS rate limiting, runtime soft memory limits (`debug.SetMemoryLimit`), and two-tier signal handling.
