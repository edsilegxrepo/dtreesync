// Package core implements directory snapshot backup orchestration.
//
// Objectives:
//   - Execute high-performance directory tree discovery, metadata capture, and snapshot creation.
//   - Ensure deterministic, reproducible snapshot artifacts through lexicographical relative path sorting.
//   - Compute cryptographic uncompressed payload SHA-256 hashes embedded directly in snapshot headers.
//   - Stream snapshot artifacts directly to local files, cloud storage (S3/GCS/Azure), or custom writers.
//   - Automatically apply FIFO snapshot retention policies upon completion.
//
// Core Components:
//   - Backup: Master pipeline coordinator driving scanning, sorting, serialization, hashing, and writing.
//   - Canonical Sorter: Orders DirRecord entries strictly by RelPath for Git compliance and consistent hashing.
//   - Dual-Stage Serialization: Computes payload SHA-256 hash across serialized records prior to header streaming.
//   - Destination Router: Routes uncompressed or Zstandard-compressed streams to local disk or cloud blob targets.
//
// Data Flow:
//
//	Live Filesystem -> Scanner -> []DirRecord -> Canonical Sort -> MultiWriter (Payload Buffer + SHA-256)
//	-> Format Header (with SHA-256) -> Streaming Compressor (Zstandard) -> Cloud / Disk Destination.
package core

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/edsilegxrepo/dtreesync/internal/format"
	"github.com/edsilegxrepo/dtreesync/internal/model"
	"github.com/edsilegxrepo/dtreesync/internal/storage"
)

// Backup executes directory discovery, canonical sorting, and streaming serialization.
func Backup(ctx context.Context, cfg model.BackupConfig, al *model.AuditLogger) (*model.BackupResult, error) {
	start := time.Now()

	cleanBase, err := model.ValidateAndCleanPath(cfg.BaseFolder)
	if err != nil {
		return nil, fmt.Errorf("base folder invalid: %w", err)
	}

	// 1. Resolve format & compression
	formatType := cfg.Format
	compType := cfg.Compression
	targetURL := cfg.TargetURL

	if formatType == "" || compType == "" {
		if targetURL != "" {
			deducedFmt, deducedComp := format.DeduceFormatAndCompression(targetURL)
			if formatType == "" {
				formatType = deducedFmt
			}
			if compType == "" {
				compType = deducedComp
			}
		} else {
			if formatType == "" {
				formatType = model.FormatNDJSON
			}
			if compType == "" {
				compType = model.CompressionZstd
			}
		}
	}

	// 2. Discover directory tree
	scanOpts := model.ScanOptions{
		Workers:       cfg.Workers,
		MaxIOPS:       cfg.MaxIOPS,
		Entity:        cfg.Entity,
		Include:       cfg.Include,
		Exclude:       cfg.Exclude,
		OneFileSystem: cfg.OneFileSystem,
	}

	scanner, err := NewScanner(cleanBase, scanOpts, al)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize scanner: %w", err)
	}

	recChan := make(chan model.DirRecord, 2048)
	errChan := make(chan error, 1)
	go func() {
		errChan <- scanner.Stream(ctx, recChan)
	}()

	var records []model.DirRecord
	for rec := range recChan {
		records = append(records, rec)
	}
	if scanErr := <-errChan; scanErr != nil {
		return nil, fmt.Errorf("directory scan failed: %w", scanErr)
	}

	// 3. Record sorting: path (canonical lexicographical), depth (topological), or none (discovery order)
	sortMode := strings.ToLower(strings.TrimSpace(cfg.SortOrder))
	if sortMode == "" || sortMode == "canonical" {
		sortMode = model.SortOrderPath
	}
	switch sortMode {
	case model.SortOrderPath:
		slices.SortFunc(records, func(a, b model.DirRecord) int {
			return cmp.Compare(a.RelPath, b.RelPath)
		})
	case model.SortOrderDepth:
		slices.SortFunc(records, func(a, b model.DirRecord) int {
			da, db := dirDepth(a.RelPath), dirDepth(b.RelPath)
			if da != db {
				return cmp.Compare(da, db)
			}
			return cmp.Compare(a.RelPath, b.RelPath)
		})
	case model.SortOrderNone:
		// No sorting: preserve discovery order
	default:
		return nil, fmt.Errorf("invalid sort order %q: must be 'path', 'depth', or 'none'", cfg.SortOrder)
	}

	hostname, _ := os.Hostname()
	folderCount := int64(len(records))

	meta := model.BackupMetadata{
		Version:     "2.0",
		BaseFolder:  cleanBase,
		Entity:      cfg.Entity,
		CreatedAt:   time.Now().UTC(),
		FolderCount: folderCount,
		TreeFile:    filepath.Base(targetURL),
		TreeFormat:  string(formatType),
		Compression: compType == model.CompressionZstd,
		HostOS:      runtime.GOOS,
		Hostname:    hostname,
		SortOrder:   sortMode,
	}

	var (
		payloadBytes int64
		sha256Hash   string
	)

	// 4. Handle SQLite serialization
	if formatType == model.FormatSQLite {
		if targetURL == "" {
			return nil, fmt.Errorf("sqlite format requires a destination file path in TargetURL")
		}
		cleanTarget, err := model.ValidateAndCleanPath(targetURL)
		if err != nil {
			return nil, err
		}
		if err := os.MkdirAll(filepath.Dir(cleanTarget), 0o750); err != nil {
			return nil, err
		}

		sw, err := format.NewSQLiteWriter(cleanTarget)
		if err != nil {
			return nil, err
		}
		if err := sw.WriteHeader(meta); err != nil {
			_ = sw.Rollback()
			_ = sw.Close()
			return nil, err
		}
		for _, rec := range records {
			if err := sw.WriteRecord(rec); err != nil {
				_ = sw.Rollback()
				_ = sw.Close()
				return nil, err
			}
		}
		if err := sw.Close(); err != nil {
			return nil, err
		}

		if fi, err := os.Stat(cleanTarget); err == nil {
			payloadBytes = fi.Size()
		}
	} else {
		// 5. Serialize payload to hybrid buffer (RAM with temp file spillover) to calculate SHA-256 and payload size
		payloadBuf := newHybridBuffer(16 * 1024 * 1024)
		defer func() { _ = payloadBuf.Close() }()
		hasher := sha256.New()
		tee := io.MultiWriter(payloadBuf, hasher)

		if formatType == model.FormatTSV {
			tw := format.NewTSVWriter(tee)
			for _, rec := range records {
				if err := tw.WriteRecord(rec); err != nil {
					return nil, err
				}
			}
			_ = tw.Flush()
		} else {
			nw := format.NewNDJSONWriter(tee)
			for _, rec := range records {
				if err := nw.WriteRecord(rec); err != nil {
					return nil, err
				}
			}
			_ = nw.Flush()
		}

		sha256Hash = hex.EncodeToString(hasher.Sum(nil))
		meta.PayloadSHA256 = sha256Hash
		payloadBytes = payloadBuf.Size()

		// Open destination writer
		var destWriter io.Writer
		var destCloser io.Closer

		if cfg.Writer != nil {
			destWriter = cfg.Writer
		} else if targetURL != "" {
			if storage.IsCloudURL(targetURL) {
				cw, err := storage.NewCloudWriter(ctx, targetURL)
				if err != nil {
					return nil, fmt.Errorf("failed to open cloud destination %q: %w", targetURL, err)
				}
				destWriter = cw
				destCloser = cw
			} else {
				cleanTarget, err := model.ValidateAndCleanPath(targetURL)
				if err != nil {
					return nil, err
				}
				if err := os.MkdirAll(filepath.Dir(cleanTarget), 0o750); err != nil {
					return nil, err
				}
				// #nosec G304 -- Backup destination path is validated and sanitized via ValidateAndCleanPath.
				f, err := os.OpenFile(cleanTarget, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
				if err != nil {
					return nil, fmt.Errorf("failed to create destination file %q: %w", cleanTarget, err)
				}
				destWriter = f
				destCloser = f
			}
		} else {
			return nil, fmt.Errorf("%w: neither Writer nor TargetURL provided", model.ErrInvalidPath)
		}

		// Apply Zstandard compression if requested
		finalWriter := destWriter
		var zstdCloser io.Closer
		if compType == model.CompressionZstd {
			enc, err := format.NewZstdWriter(destWriter, cfg.Workers)
			if err != nil {
				if destCloser != nil {
					_ = destCloser.Close()
				}
				return nil, err
			}
			finalWriter = enc
			zstdCloser = enc
		}

		// Write Header
		if formatType == model.FormatTSV {
			tw := format.NewTSVWriter(finalWriter)
			if err := tw.WriteHeader(meta); err != nil {
				return nil, err
			}
			_ = tw.Flush()
		} else {
			nw := format.NewNDJSONWriter(finalWriter)
			if err := nw.WriteHeader(meta); err != nil {
				return nil, err
			}
			_ = nw.Flush()
		}

		// Write payload bytes
		var writeErr error
		payloadReader, rErr := payloadBuf.Reader()
		if rErr != nil {
			writeErr = fmt.Errorf("failed to get payload reader: %w", rErr)
		} else if _, err := io.Copy(finalWriter, payloadReader); err != nil {
			writeErr = fmt.Errorf("failed to write payload to destination: %w", err)
		}

		if zstdCloser != nil {
			if err := zstdCloser.Close(); err != nil && writeErr == nil {
				writeErr = err
			}
		}
		if destCloser != nil {
			if err := destCloser.Close(); err != nil && writeErr == nil {
				writeErr = err
			}
		}
		if writeErr != nil {
			return nil, writeErr
		}
	}

	// 6. Apply FIFO retention if configured (local filesystem only)
	if targetURL != "" && !storage.IsCloudURL(targetURL) && (cfg.RetentionDays > 0 || cfg.RetentionCount > 0) {
		targetDir := filepath.Dir(targetURL)
		if cfg.RetentionPrefix != "" {
			_, _ = ApplyRetention(targetDir, cfg.RetentionDays, cfg.RetentionCount, al, cfg.RetentionPrefix)
		} else {
			_, _ = ApplyRetention(targetDir, cfg.RetentionDays, cfg.RetentionCount, al)
		}
	}

	duration := time.Since(start)
	if al != nil {
		al.LogInfo("core", "job_complete", cleanBase, map[string]any{
			"folder_count":  folderCount,
			"payload_bytes": payloadBytes,
			"sha256":        sha256Hash,
			"duration_ms":   duration.Milliseconds(),
		})
	}

	return &model.BackupResult{
		FolderCount:  folderCount,
		PayloadBytes: payloadBytes,
		Duration:     duration,
		SHA256Hash:   sha256Hash,
		ArtifactURL:  targetURL,
	}, nil
}

// hybridBuffer buffers data in memory up to maxMem bytes, spilling over to an anonymous
// temporary file if the threshold is exceeded.
type hybridBuffer struct {
	maxMem int64
	buf    bytes.Buffer
	file   *os.File
	size   int64
}

// newHybridBuffer constructs a hybridBuffer with a maximum in-memory threshold.
func newHybridBuffer(maxMem int64) *hybridBuffer {
	if maxMem <= 0 {
		maxMem = 16 * 1024 * 1024 // 16MB default RAM limit
	}
	return &hybridBuffer{maxMem: maxMem}
}

// Write appends bytes to the buffer, transparently creating and spilling over
// to an anonymous temporary disk file if maxMem is exceeded.
func (h *hybridBuffer) Write(p []byte) (n int, err error) {
	h.size += int64(len(p))
	if h.file != nil {
		return h.file.Write(p)
	}
	if int64(h.buf.Len()+len(p)) > h.maxMem {
		tmp, err := os.CreateTemp("", "dtreesync_spool_*")
		if err != nil {
			return 0, fmt.Errorf("failed to create spool file: %w", err)
		}
		if h.buf.Len() > 0 {
			if _, err := tmp.Write(h.buf.Bytes()); err != nil {
				_ = tmp.Close()
				_ = os.Remove(tmp.Name())
				return 0, err
			}
			h.buf.Reset()
		}
		h.file = tmp
		return h.file.Write(p)
	}
	return h.buf.Write(p)
}

// Size returns the cumulative number of bytes written to the buffer.
func (h *hybridBuffer) Size() int64 {
	return h.size
}

// Reader prepares the buffer for reading. If the buffer has spilled to disk,
// the file pointer is rewound to the beginning (SeekStart).
func (h *hybridBuffer) Reader() (io.Reader, error) {
	if h.file != nil {
		if _, err := h.file.Seek(0, io.SeekStart); err != nil {
			return nil, err
		}
		return h.file, nil
	}
	return bytes.NewReader(h.buf.Bytes()), nil
}

// Close releases resources, closing and unlinking any spilled temporary file.
func (h *hybridBuffer) Close() error {
	if h.file != nil {
		name := h.file.Name()
		_ = h.file.Close()
		_ = os.Remove(name)
		h.file = nil
	}
	return nil
}

func dirDepth(p string) int {
	clean := filepath.ToSlash(filepath.Clean(p))
	if clean == "" || clean == "." {
		return 0
	}
	return strings.Count(clean, "/") + 1
}
