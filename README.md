# dtreesync

**High-Performance Enterprise Directory Synchronization, Metadata Preservation, and Compliance Auditing**

[![Go Version](https://img.shields.io/badge/Go-1.27%2B-blue.svg)](https://go.dev/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Audit Status](https://img.shields.io/badge/Audit-PASSED-brightgreen.svg)](./TESTING.md)
[![Statement Coverage](https://img.shields.io/badge/Coverage-84.1%25-success.svg)](./TESTING.md#6-code-coverage-report)

---

## Technical Specifications & Documentation Links

- **[Architecture & Design Specification (`ARCHITECTURE.md`)](./ARCHITECTURE.md)**: Detailed system design, topological two-pass restoration, work-stealing concurrency model, multi-cloud storage abstractions, and Mermaid sequence/dependency/security diagrams.
- **[Test Suite & Verification Specification (`TESTING.md`)](./TESTING.md)**: Test harness architecture, positive and negative test matrix, live MinIO Docker integration, statement coverage report (84.1%), and troubleshooting workflows.
- **[Release History & Changelog (`CHANGELOG.md`)](./CHANGELOG.md)**: Version history, release notes, and milestone deliverables.

---

## 1. Application Overview & Objectives

In large-scale enterprise environments—including Managed File Transfer (MFT) gateways, electronic data interchanges (EDI), distributed NAS/SAN clusters, and hybrid cloud migrations—administrators routinely face directory trees containing **hundreds of thousands of folders and millions of files**. Standard synchronization tools (such as `rsync`, `robocopy`, or generic backup agents) traverse and stat every single payload file, inducing severe disk thrashing, saturated storage controller IOPS, memory exhaustion, and prolonged maintenance windows.

`dtreesync` is an enterprise-grade utility engineered to solve this problem:

1. **Zero Payload File I/O:** Directory hierarchies are scanned via batched kernel directory reads (`f.ReadDir(-1)`), discarding non-directory payload entries directly at the user-kernel boundary. The tool captures directory metadata, ACLs, and structure without reading file data or touching payload file contents.
2. **Dual Consumption Model:** Functions as both an autonomous production CLI binary ([`cmd/dtreesync`](./cmd/dtreesync/main.go)) and an embeddable, thread-safe Go library ([`pkg/dtreesync`](./pkg/dtreesync/api.go)) utilizing Go 1.27 range-over-func iterators (`iter.Seq2[DirRecord, error]`).
3. **Topological Two-Pass Reconstitution:** Restores directory hierarchies top-down with staging permissions (`0o700`), followed by a bottom-up attribute and timestamp application pass ($D_{\max} \to 0$). This guarantees that setting parent directory timestamps or restrictive permissions never invalidates child directories.
4. **Forensic Identity & Permission Fidelity:** Preserves Linux POSIX ACLs, SELinux security contexts, extended attributes (`user.*`), and Windows NTFS Security Descriptors (SDDL) with explicit DACL inheritance protection (`D:P`).
5. **Multi-Target Storage & Streaming Formats:** Serializes to TSV, NDJSON, and indexed SQLite formats with streaming parallel Zstandard (`.zst`) compression, writing to local disks, cloud object storage (AWS S3, GCP GCS, Azure Blob), or directly committing immutable compliance snapshots to Git repositories.

---

## 2. Security Assessment

### 2.1 Encryption in Transit
- **Strict TLS 1.3 / 1.2:** All network communications with cloud object storage providers (AWS S3, Google Cloud Storage, Azure Blob Storage) and remote Git remotes enforce TLS encryption.
- **Strict Verification Invariant:** Disabling certificate verification (`InsecureSkipVerify = true`) is **strictly prohibited across all environments and tests**.
- **Enterprise Trust Stores:** Supports custom enterprise CA trust bundles via standard environment variables (`AWS_CA_BUNDLE`, `SSL_CERT_FILE`).

### 2.2 Secret Management & Memory Safety
- **Zero-Knowledge AEAD Encryption:** Integrated with `github.com/edsilegxrepo/secretprotector` using authenticated AES-256-GCM and ChaCha20-Poly1305 encryption.
- **Memory Zeroing:** All plaintext secrets, decrypted tokens, and sensitive key buffers are cryptographically sanitized from memory immediately after consumption using `libsecsecrets.ZeroBuffer`.
- **Credential Storage Masks:** All on-disk snapshots, encryption keys, and credentials enforce restricted POSIX permissions (`0o600` on files, `0o750` on directories).

### 2.3 Authentication Configuration
- **AWS S3:** Authenticated via AWS IAM Roles, EC2 Instance Metadata Service (IMDSv2), or SecretProtector-encrypted credentials in `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`.
- **Google Cloud Storage (GCS):** Authenticated via Workload Identity or `GOOGLE_APPLICATION_CREDENTIALS`. If the credentials JSON file is encrypted with SecretProtector, `dtreesync` decrypts it dynamically into a private, temporary file (`0o600`), points the client to it, and securely unlinks and wipes it upon exit.
- **Azure Blob Storage:** Authenticated via Azure Managed Identity, Azure Key Vault, or encrypted connection strings (`AZURE_STORAGE_KEY`).
- **Git Repositories:** Supports passwordless SSH keys (with encrypted passphrases) and HTTPS Personal Access Tokens (PAT).

### 2.4 Role-Based Access Control (RBAC) & OS Privileges
- **Windows Token Privilege Elevation:** When running with administrative privileges, `dtreesync` dynamically opens the process token and acquires:
  - `SeBackupPrivilege`: Bypasses file and folder read security checks for comprehensive metadata capture.
  - `SeRestorePrivilege`: Bypasses write security checks, permitting exact SID owner restoration.
  - `SeSecurityPrivilege`: Enables reading and writing SACLs (System Access Control Lists).
- **Explicit DACL Protection (`D:P`):** Restores Windows NTFS DACLs with the protected inheritance bit set (`D:P`), preventing parent folders from mutating child security boundaries.
- **Linux Security Contexts:** Restores POSIX ACL masks and SELinux file contexts (`security.selinux`). Cross-domain identity mapping (`--id-map`) enables seamless translation of UIDs, GIDs, and SIDs between disjoint directory domains.

### 2.5 Current & Non-Vulnerable Libraries Used
All dependencies are actively audited, free from known vulnerabilities, and verified clean via `govulncheck` and `grype`:

| Package | Version | Purpose | Vulnerability Status |
| :--- | :---: | :--- | :---: |
| `github.com/edsilegxrepo/secretprotector` | `v0.0.4` | AEAD secret encryption & memory wiping | Clean (0 CVEs) |
| `gocloud.dev` | `v0.46.0` | Cloud blob storage abstraction (S3, GCS, Azure) | Clean (0 CVEs) |
| `github.com/go-git/go-git/v5` | `v5.19.2` | Pure-Go Git snapshotting engine | Clean (0 CVEs) |
| `github.com/klauspost/compress` | `v1.20.0` | Parallel Zstandard compression/decompression | Clean (0 CVEs) |
| `golang.org/x/sys` | `v0.48.0` | Native OS syscalls (Win32 API & Linux POSIX) | Clean (0 CVEs) |
| `golang.org/x/time` | `v0.16.0` | Token-bucket IOPS rate limiter | Clean (0 CVEs) |
| `modernc.org/sqlite` | `v1.58.0` | Pure-Go (CGO-free) embedded SQLite driver | Clean (0 CVEs) |

### 2.6 Unprivileged Context / Least Privilege Execution
- **Non-System Context:** For routine backups, drift checks, and restorations, `dtreesync` does **not** require root or administrative privileges. It executes safely under unprivileged service accounts or container UIDs.
- **Graceful Permission Degradation:** If executed without elevated privileges, the tool captures and restores standard permissions (`chmod`), issuing structured non-fatal warnings for restricted SACLs or privileged extended attributes while continuing directory operations.

---

## 3. Code Quality Assessment & Best Practices

The codebase adheres strictly to enterprise standards and has been audited against corporate quality controls:

1. **Automated Code Audit Status (`code_audit.sh`):**
   - **Gofumpt:** 100% compliant with strict Go formatting standards.
   - **GolangCI Meta-Linter:** 0 defects across 46 linters (including `errcheck`, `govet`, `staticcheck`, `unused`, `gosec`).
   - **Semgrep & ast-grep:** 0 security pattern violations.
   - **Gosec Security Scanner:** 0 security vulnerabilities (all path lookups sanitized via [`model.ValidateAndCleanPath`](./internal/model/path.go#L30); PRNG test generators annotated).
   - **TruffleHog:** 0 hardcoded credentials or private keys detected.
   - **Grype & GoVulnCheck:** 0 affected third-party vulnerabilities.
2. **High Test Coverage:**
   - **84.1% Global Statement Coverage** across the repository, with every package exceeding 80.0%.
   - Full end-to-end coverage using live ephemeral MinIO S3 containers and bare Git repositories.
3. **Robust Resource Management:**
   - No resource leaks: all database handles, transaction rollbacks, file descriptors, and HTTP response bodies are guaranteed closed immediately via deterministic error handling.
   - Directory walk loops close files immediately rather than piling up on `defer`.
4. **Signal Interception & Controlled Shutdown:**
   - Two-tier signal handler ([`internal/core/signal.go`](./internal/core/signal.go)): First `SIGINT`/`SIGTERM` cancels context, allows running workers 500ms to drain queues, flushes Zstandard buffers and audit logs, and exits code `1`. A second signal invokes immediate hard termination.

---

## 4. Command Line Arguments

`dtreesync` exposes 6 subcommands: `backup`, `restore`, `diff`, `status` (alias: `inspect`), `verify`, and `version`.

### 4.1 Exit Codes

| Exit Code | Constant | Meaning |
| :---: | :--- | :--- |
| `0` | `ExitSuccess` | Operation completed successfully with zero defects or drift. |
| `1` | `ExitUsageError` | Command-line usage error, flag parsing failure, or invalid path. |
| `2` | `ExitAuthFailure` | Authentication or privilege elevation failure. |
| `3` | `ExitDriftDetected` | `diff` command detected directory or permission drift. |
| `4` | `ExitVerifyFailed` | `verify` command detected checksum mismatch or corrupted payload. |
| `5` | `ExitPartialWarning` | Operation succeeded with non-fatal warnings (e.g. skipped unreadable directory). |

---

### 4.2 `backup` Subcommand

Scans a source directory hierarchy without touching payload files, compiles canonical metadata records, and writes a compressed snapshot.

| Flag Name | Type | Default | Description |
| :--- | :---: | :---: | :--- |
| `--base-folder` | `string` | *Required* | Absolute path to the source directory root to scan. |
| `--tree-file` | `string` | `""` | Destination path or cloud URL (`s3://`, `gs://`, `azblob://`) for snapshot file. |
| `--format`, `--tree-format` | `string` | `tsv` | Serialization format: `tsv`, `ndjson`, `sqlite`. |
| `--compression` | `string` | `zstd` | Compression codec: `zstd` or `none`. |
| `--backup-compress` | `bool` | `true` | Enable Zstandard compression on output snapshot. |
| `--sort` | `string` | `path` | Output sort order: `path` (canonical lexicographical), `depth` (topological), or `none`. |
| `--threads` | `int` | `auto` | Concurrent scanner worker goroutines (1..32, default: $\min(N_{\text{CPU}} \times 2, 32)$). |
| `--max-iops` | `int` | `0` | Token-bucket rate limiter for filesystem syscalls (0 for unlimited). |
| `--max-memory-mb` | `int` | `0` | Soft memory heap limit via Go runtime `debug.SetMemoryLimit` (0 for unlimited). |
| `--one-file-system` | `bool` | `false` | Confine scan to root filesystem mount (crosses no mount points or drives). |
| `--entity` | `string` | `""` | Restrict scan to a specific top-level partner or tenant directory. |
| `--include` | `string` | `""` | Comma-separated glob include patterns. |
| `--exclude` | `string` | `""` | Comma-separated glob exclude patterns. |
| `--dry-run` | `bool` | `false` | Traverse tree and report projected folder counts without writing snapshot. |
| `--retention-days`, `--backup-retention` | `int` | `0` | FIFO retention window in days to prune older snapshots (0 to disable). |
| `--retention-count` | `int` | `0` | FIFO retention count to keep newest $N$ snapshots (0 to disable). |
| `--log`, `--log-file` | `string` | `""` | Absolute path for structured NDJSON SIEM audit telemetry log. |
| `--output` | `string` | `table` | Console output format: `table`, `json`, `yaml`. |
| `--json` | `bool` | `false` | Shorthand alias for `--output=json`. |
| `--git-repo` | `string` | `""` | Git repository URL or path to commit snapshot directly. |
| `--git-branch` | `string` | `main` | Target branch for Git snapshot commit. |
| `--git-tag` | `string` | `""` | Create an immutable tag for Git compliance commits. |
| `--git-username` | `string` | `""` | Username for remote Git HTTP authentication. |
| `--git-token` | `string` | `""` | Personal access token for Git HTTP authentication (supports SecretProtector). |
| `--git-ssh-key` | `string` | `""` | Path to private SSH key for Git authentication. |
| `--git-passphrase` | `string` | `""` | Passphrase for private SSH key (supports SecretProtector). |
| `--secret-key` | `string` | `""` | SecretProtector 32-byte master key (hex string or raw). |
| `--secret-key-file` | `string` | `""` | Path to file containing SecretProtector master key. |

---

### 4.3 `restore` Subcommand

Materializes directory trees from a snapshot archive using topological two-pass reconstitution.

| Flag Name | Type | Default | Description |
| :--- | :---: | :---: | :--- |
| `--tree-file` | `string` | *Required* | Path or cloud URL to source snapshot archive. |
| `--base-folder` | `string` | *Required* | Absolute path to destination directory root. |
| `--type` | `string` | `incremental` | Restoration mode: `incremental` (preserves existing) or `mirror` (purges untracked). |
| `--archive-extra-folder` | `string` | `""` | Mirror mode: destination directory to evacuate untracked subtrees into a `.tar.zst` archive. |
| `--base-substitute` | `string` | `""` | Base path rewrite mapping in `<old_abs>,<new_abs>` format. |
| `--id-map` | `string` | `""` | Path to JSON file containing user, group, and SID identity translation rules. |
| `--apply-perms` | `bool` | `true` | Apply permissions, modes, timestamps, POSIX ACLs, and Windows SDDLs. |
| `--threads` | `int` | `auto` | Concurrent restoration workers (1..32). |
| `--max-iops` | `int` | `0` | Token-bucket rate limiter for filesystem operations (0 for unlimited). |
| `--max-memory-mb` | `int` | `0` | Soft memory heap limit in MB (0 for unlimited). |
| `--entity` | `string` | `""` | Comma-separated list of tenant entities to selectively restore. |
| `--include` | `string` | `""` | Comma-separated glob include patterns. |
| `--exclude` | `string` | `""` | Comma-separated glob exclude patterns. |
| `--progress` | `bool` | `true` | Display real-time progress counter in terminal. |
| `--dry-run` | `bool` | `false` | Simulate restoration without modifying the destination filesystem. |
| `--log`, `--log-file` | `string` | `""` | Path for structured NDJSON audit log. |
| `--output` | `string` | `table` | Console output format: `table`, `json`, `yaml`. |
| `--git-repo`, `--git-ref` | `string` | `""` | Pull snapshot directly from Git repository and branch/tag/ref. |
| `--secret-key`, `--secret-key-file`| `string` | `""` | SecretProtector master key for decrypting credentials. |

---

### 4.4 `diff` Subcommand

Compares a live directory tree against a baseline snapshot and reports structural, permission, and timestamp discrepancies. Returns exit code `0` (clean) or `3` (drift detected).

| Flag Name | Type | Default | Description |
| :--- | :---: | :---: | :--- |
| `--base-folder` | `string` | *Required* | Absolute path to live directory root to inspect. |
| `--tree-file` | `string` | *Required* | Path or cloud URL to baseline snapshot archive. |
| `--id-map` | `string` | `""` | Path to identity mapping JSON file for cross-domain comparison. |
| `--ignore-btime` | `bool` | `false` | Ignore birth time (creation time) discrepancies. |
| `--ignore-owner` | `bool` | `false` | Ignore UID/SID ownership discrepancies. |
| `--threads` | `int` | `auto` | Concurrent comparison threads (1..32). |
| `--max-iops` | `int` | `0` | Rate limiter for directory stat calls (0 for unlimited). |
| `--entity`, `--include`, `--exclude` | `string` | `""` | Filters to scope verification to specific subtrees. |
| `--log`, `--output`, `--json` | - | - | Standard logging and format options (`table`, `json`, `yaml`). |

---

### 4.5 `verify` Subcommand

Performs zero-disk-write cryptographic integrity verification on a snapshot. Returns exit code `0` (valid) or `4` (corrupted).

| Flag Name | Type | Default | Description |
| :--- | :---: | :---: | :--- |
| `--tree-file` | `string` | *Required* | Snapshot file or cloud URL to verify. |
| `--threads` | `int` | `auto` | Decompression worker threads. |
| `--max-memory-mb` | `int` | `0` | Soft memory heap limit in MB. |
| `--log`, `--output`, `--json` | - | - | Logging and output formatting options. |

---

### 4.6 `status` / `inspect` Subcommand

Reads and displays snapshot header envelope metadata in microseconds without reading directory records.

| Flag Name | Type | Default | Description |
| :--- | :---: | :---: | :--- |
| `--tree-file` | `string` | `""` | Path or cloud URL to inspect a single snapshot file. |
| `--tree-path` | `string` | `""` | Path to a folder of snapshots to render a catalog summary table. |
| `--output`, `--json` | `string` | `table` | Output format: `table`, `json`, `yaml`. |

---

## 5. Detailed Usage & Deployment Examples

### Scenario 1: High-Performance Snapshot to Local Disk & Cloud S3

Create a compressed TSV snapshot of an enterprise MFT transfer directory, emitting audit logs to a SIEM forwarder.

```bash
# Execute backup
dtreesync backup \
  --base-folder="/data/mft/partners" \
  --tree-file="/snapshots/mft_partners_$(date +%Y%m%d).tsv.zst" \
  --format="tsv" \
  --backup-compress=true \
  --threads=16 \
  --max-iops=5000 \
  --log="/var/log/dtreesync/audit.ndjson" \
  --output="table"
```

**Output:**
```
Snapshot creation completed successfully.
  Base Folder     : /data/mft/partners
  Folders Scanned : 142850
  Duration        : 3.412s
  Throughput      : 41867 dirs/sec
  Payload Size    : 4.82 MB (compressed)
  Payload SHA256  : e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
  Output File     : /snapshots/mft_partners_20260915.tsv.zst
```

---

### Scenario 2: Two-Pass Disaster Recovery Reconstitution with Mirror Evacuation

Restore a directory structure into a target volume. Using `--type=mirror` and `--archive-extra-folder`, any untracked directories in the target are archived into a compressed `.tar.zst` file and evacuated before the snapshot is applied.

```bash
dtreesync restore \
  --tree-file="s3://enterprise-dr-vault/snapshots/mft_partners_20260915.tsv.zst" \
  --base-folder="/mnt/dr_recovery/partners" \
  --type="mirror" \
  --archive-extra-folder="/mnt/evacuation_archive" \
  --apply-perms=true \
  --threads=8 \
  --log="/var/log/dtreesync/restore.ndjson" \
  --output="json"
```

**Output:**
```json
{
  "status": "success",
  "created_folders": 142850,
  "applied_perms": 142850,
  "warnings": [],
  "evacuated_archive": "/mnt/evacuation_archive/evacuated_untracked_20260915_213000.tar.zst",
  "duration_ns": 5892104000,
  "duration": "5.892s"
}
```

---

### Scenario 3: Real-Time Audit Drift Inspection (`diff`)

Inspect a live directory against an approved baseline snapshot to detect unauthorized folders or permission drift.

```bash
dtreesync diff \
  --base-folder="/data/mft/partners" \
  --tree-file="/snapshots/mft_partners_baseline.tsv.zst" \
  --output="table"
```

**Output (Exit Code `3`):**
```
Drift Evaluation: DRIFT_DETECTED
  Expected Dirs : 142850
  Scanned Dirs  : 142852
  Missing Dirs  : 0
  Extra Items   : 1
  Perm Drifts   : 1
  Total Drift   : 2
  Duration      : 2.104s

Discrepancies:
  [EXTRA] /data/mft/partners/finance/unauthorized_export (path: expected "", actual "present")
  [DRIFT] /data/mft/partners/partner_a/inbound (mode: expected "0770", actual "0777")
```

---

### Scenario 4: Cryptographic Zero-Disk-Write Integrity Verification

Verify snapshot framing, record schema syntax, and payload checksums directly in memory:

```bash
dtreesync verify \
  --tree-file="/snapshots/mft_partners_20260915.tsv.zst" \
  --output="table"
```

**Output (Exit Code `0`):**
```
Verification completed successfully.
  Snapshot File   : /snapshots/mft_partners_20260915.tsv.zst
  Header SHA256   : e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
  Computed SHA256 : e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
  Integrity Check : PASSED (Valid Zstandard stream & verified payload)
  Record Count    : 142850 valid directory records
  Duration        : 0.485s
```

---

### Scenario 5: GitOps Compliance Snapshot with SecretProtector Encryption

Commit a compliance snapshot directly to an enterprise Git audit repository using encrypted tokens:

```bash
export SECRETPROTECTOR_MASTER_KEY="a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"

dtreesync backup \
  --base-folder="/data/secure/compliance_tree" \
  --git-repo="https://github.com/my-org/audit-records.git" \
  --git-branch="audit-2026" \
  --git-tag="audit-q3-2026" \
  --git-username="audit-bot" \
  --git-token="enc:secprot:v1:aes256gcm:9f8e7d...[encrypted_token]" \
  --format="tsv" \
  --output="table"
```

---

### Scenario 6: Production Deployment Configurations

#### 1. Linux Systemd Timer & Service (`/etc/systemd/system/dtreesync.service`)
```ini
[Unit]
Description=dtreesync Daily Directory Topology Snapshot
After=network.target local-fs.target

[Service]
Type=oneshot
User=dtreesync
Group=dtreesync
ExecStart=/usr/local/bin/dtreesync backup \
  --base-folder="/srv/mft/transfers" \
  --tree-file="s3://corp-mft-backups/daily/transfers_%Y%m%d.tsv.zst" \
  --max-iops=3000 \
  --max-memory-mb=512 \
  --log="/var/log/dtreesync/audit.ndjson"
StandardError=journal
```

#### 2. Kubernetes CronJob Manifest
```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: dtreesync-compliance-backup
  namespace: mft-gateway
spec:
  schedule: "0 2 * * *"
  successfulJobsHistoryLimit: 3
  failedJobsHistoryLimit: 5
  jobTemplate:
    spec:
      template:
        spec:
          securityContext:
            runAsNonRoot: true
            runAsUser: 10001
            readOnlyRootFilesystem: true
          containers:
          - name: dtreesync
            image: ghcr.io/edsilegxrepo/dtreesync:latest
            command:
            - /bin/dtreesync
            - backup
            - --base-folder=/data/storage
            - --tree-file=s3://k8s-mft-vault/snapshots/cluster_tree.tsv.zst
            - --max-memory-mb=256
            - --log=/tmp/audit.ndjson
            resources:
              limits:
                memory: "384Mi"
                cpu: "1000m"
              requests:
                memory: "128Mi"
                cpu: "250m"
            volumeMounts:
            - name: data-vol
              mountPath: /data/storage
              readOnly: true
            - name: tmp-vol
              mountPath: /tmp
          volumes:
          - name: data-vol
            persistentVolumeClaim:
              claimName: mft-storage-pvc
          - name: tmp-vol
            emptyDir: {}
          restartPolicy: OnFailure
```

---

## 6. Verification and Testing

To execute all fast unit and cross-platform verification tests:
```bash
go test -v -race ./internal/... ./pkg/...
```

To execute the live integration suite (with local MinIO S3 Docker containers and bare Git repositories):
```powershell
# In PowerShell:
$env:ENABLE_LIVE_INTEGRATION="1"
go test -v -tags=integration ./test/integration/...
```

For complete instructions, refer to **[`TESTING.md`](./TESTING.md)**.
