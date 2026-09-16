// Package core implements zero-disk cryptographic snapshot verification.
//
// Objectives:
//   - Provide high-assurance validation of snapshot archives without writing temporary files to disk.
//   - Execute a three-tier verification strategy:
//     1. Tier 1 (Framing): Verifies Zstandard framing and decompressor integrity.
//     2. Tier 2 (Syntax): Validates Line 1 metadata envelope and record syntax (JSON/TSV).
//     3. Tier 3 (Checksum): Reconciles live uncompressed streaming SHA-256 hash against expected metadata hash.
//   - Support SQLite verification via PRAGMA integrity_check and row count validation.
//
// Core Components:
//   - Verify: Master verification orchestrator driving streaming tiers.
//   - Streaming Hasher: io.TeeReader concurrently computing SHA-256 while feeding syntax validators.
//   - verifySQLite: Executes embedded SQLite database consistency and integrity checks.
//
// Data Flow:
//
//	Snapshot Stream -> Zstandard Decompressor (Tier 1) -> TeeReader -> Syntax Checker (Tier 2)
//	& Cryptographic Hasher -> SHA-256 Comparison (Tier 3) -> VerifyResult.
package core

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/edsilegxrepo/dtreesync/internal/format"
	"github.com/edsilegxrepo/dtreesync/internal/model"
	"github.com/edsilegxrepo/dtreesync/internal/storage"
)

// Verify executes zero-disk-write cryptographic verification of a snapshot archive.
func Verify(ctx context.Context, cfg model.VerifyConfig, al *model.AuditLogger) (*model.VerifyResult, error) {
	start := time.Now()

	// 1. Resolve format & compression
	formatType := cfg.Format
	compType := cfg.Compression
	sourceURL := cfg.SourceURL

	if sourceURL != "" && (formatType == "" || compType == "") {
		deducedFmt, deducedComp := format.DeduceFormatAndCompression(sourceURL)
		if formatType == "" {
			formatType = deducedFmt
		}
		if compType == "" {
			compType = deducedComp
		}
	}

	result := &model.VerifyResult{
		TreeFile:      sourceURL,
		Format:        string(formatType),
		Compression:   compType == model.CompressionZstd,
		FramesValid:   true,
		SyntaxValid:   true,
		ChecksumValid: true,
	}

	// Handle SQLite verification
	if formatType == model.FormatSQLite {
		return verifySQLite(ctx, sourceURL, result, al, start)
	}

	// 2. Open input stream
	var inputReader io.Reader
	if cfg.Reader != nil {
		inputReader = cfg.Reader
	} else if sourceURL != "" {
		if storage.IsCloudURL(sourceURL) {
			cr, err := storage.NewCloudReader(ctx, sourceURL)
			if err != nil {
				return nil, fmt.Errorf("failed to open cloud snapshot %q: %w", sourceURL, err)
			}
			defer func() { _ = cr.Close() }()
			inputReader = cr
		} else {
			cleanPath, err := model.ValidateAndCleanPath(sourceURL)
			if err != nil {
				return nil, err
			}
			// #nosec G304 -- Snapshot source path is validated and sanitized via ValidateAndCleanPath.
			f, err := os.Open(cleanPath)
			if err != nil {
				return nil, fmt.Errorf("failed to open snapshot file: %w", err)
			}
			defer func() { _ = f.Close() }()
			inputReader = f
		}
	} else {
		return nil, fmt.Errorf("%w: neither Reader nor SourceURL supplied", model.ErrSnapshotNotFound)
	}

	bufInput := bufio.NewReader(inputReader)

	// Auto-detect Zstandard compression if not explicitly specified
	if compType == "" {
		if peekMagic, err := bufInput.Peek(4); err == nil && len(peekMagic) >= 4 {
			if peekMagic[0] == 0x28 && peekMagic[1] == 0xb5 && peekMagic[2] == 0x2f && peekMagic[3] == 0xfd {
				compType = model.CompressionZstd
			} else {
				compType = model.CompressionNone
			}
		} else {
			compType = model.CompressionNone
		}
	}
	result.Compression = compType == model.CompressionZstd

	// 3. Tier 1: Streaming Decompressor
	var streamReader io.Reader
	if compType == model.CompressionZstd {
		dec, err := format.NewZstdReader(bufInput, cfg.Workers)
		if err != nil {
			result.FramesValid = false
			result.Errors = append(result.Errors, fmt.Sprintf("zstd initialization failed: %v", err))
			result.Duration = time.Since(start)
			return result, model.ErrVerificationFailed
		}
		defer dec.Close()
		streamReader = dec
	} else {
		streamReader = bufInput
	}

	bufReader := bufio.NewReaderSize(streamReader, 64*1024)

	// Auto-detect format from first non-empty byte if not specified
	if formatType == "" {
		if peekBytes, err := bufReader.Peek(16); err == nil && len(peekBytes) > 0 {
			peekStr := string(peekBytes)
			if strings.HasPrefix(peekStr, "#") || strings.HasPrefix(peekStr, "entity\t") {
				formatType = model.FormatTSV
			} else if strings.HasPrefix(strings.TrimSpace(peekStr), "{") {
				formatType = model.FormatNDJSON
			} else {
				formatType = model.FormatNDJSON
			}
		} else {
			formatType = model.FormatNDJSON
		}
	}
	result.Format = string(formatType)

	// 4. Tier 2: Stream Syntax & Invariant Validation
	var (
		headerMeta  *model.BackupMetadata
		recordCount int64
		syntaxErrs  []string
	)

	hasher := sha256.New()

	if formatType == model.FormatTSV {
		// Read line 1: #META:
		line1, err := bufReader.ReadString('\n')
		if err != nil {
			result.FramesValid = false
			result.Errors = append(result.Errors, fmt.Sprintf("failed to read TSV header: %v", err))
			result.Duration = time.Since(start)
			return result, model.ErrVerificationFailed
		}
		hdr, err := format.ReadTSVHeader(strings.NewReader(line1))
		if err != nil {
			result.SyntaxValid = false
			result.Errors = append(result.Errors, fmt.Sprintf("invalid TSV header: %v", err))
			result.Duration = time.Since(start)
			return result, model.ErrVerificationFailed
		}
		headerMeta = hdr

		// Consume initial comment lines (#...) and column header (entity\t...) before data rows
		for {
			peek, err := bufReader.Peek(1)
			if err != nil {
				break
			}
			if peek[0] == '#' {
				_, _ = bufReader.ReadString('\n')
				continue
			}
			peekHeader, err := bufReader.Peek(7)
			if err == nil && string(peekHeader) == "entity\t" {
				_, _ = bufReader.ReadString('\n')
				continue
			}
			break
		}

		// Hash remaining lines (the payload)
		payloadReader := io.TeeReader(bufReader, hasher)
		scanner := bufio.NewScanner(payloadReader)
		buf := make([]byte, 1024*1024)
		scanner.Buffer(buf, 16*1024*1024)

		for scanner.Scan() {
			line := scanner.Text()
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}
			cols := strings.Split(trimmed, "\t")
			if len(cols) < 13 {
				syntaxErrs = append(syntaxErrs, fmt.Sprintf("line %d: expected 13 columns, got %d", recordCount+1, len(cols)))
				continue
			}
			recordCount++
			relPath := cols[1]
			if relPath != "-" && relPath != "" {
				if norm, err := model.NormalizeRelPath(relPath); err != nil || norm != relPath {
					syntaxErrs = append(syntaxErrs, fmt.Sprintf("invalid relative path %q: %v", relPath, err))
				}
			}
		}
		if err := scanner.Err(); err != nil {
			syntaxErrs = append(syntaxErrs, fmt.Sprintf("TSV stream error: %v", err))
		}
	} else {
		// NDJSON format
		line1, err := bufReader.ReadBytes('\n')
		if err != nil {
			result.FramesValid = false
			result.Errors = append(result.Errors, fmt.Sprintf("failed to read NDJSON line 1: %v", err))
			result.Duration = time.Since(start)
			return result, model.ErrVerificationFailed
		}
		hdr, err := format.ReadNDJSONHeader(bytes.NewReader(line1))
		if err != nil {
			result.SyntaxValid = false
			result.Errors = append(result.Errors, fmt.Sprintf("invalid NDJSON header: %v", err))
			result.Duration = time.Since(start)
			return result, model.ErrVerificationFailed
		}
		headerMeta = hdr

		// Hash remaining lines (the payload)
		payloadReader := io.TeeReader(bufReader, hasher)
		scanner := bufio.NewScanner(payloadReader)
		buf := make([]byte, 1024*1024)
		scanner.Buffer(buf, 16*1024*1024)

		for scanner.Scan() {
			line := scanner.Bytes()
			if len(line) == 0 {
				continue
			}
			recordCount++
			var rec model.DirRecord
			if err := json.Unmarshal(line, &rec); err != nil {
				syntaxErrs = append(syntaxErrs, fmt.Sprintf("line %d syntax error: %v", recordCount+1, err))
				continue
			}
			if rec.RelPath != "" {
				if norm, err := model.NormalizeRelPath(rec.RelPath); err != nil || norm != rec.RelPath {
					syntaxErrs = append(syntaxErrs, fmt.Sprintf("invalid relative path %q: %v", rec.RelPath, err))
				}
			}
		}
		if err := scanner.Err(); err != nil {
			syntaxErrs = append(syntaxErrs, fmt.Sprintf("NDJSON stream error: %v", err))
		}
	}

	// 5. Tier 3: SHA-256 Reconciliation
	computedHash := hex.EncodeToString(hasher.Sum(nil))
	result.PayloadSHA256 = computedHash
	result.RecordCount = recordCount
	result.Duration = time.Since(start)

	if len(syntaxErrs) > 0 {
		result.SyntaxValid = false
		result.Errors = append(result.Errors, syntaxErrs...)
	}

	if headerMeta != nil {
		result.ExpectedSHA256 = headerMeta.PayloadSHA256
		if headerMeta.PayloadSHA256 != "" {
			result.ChecksumValid = strings.EqualFold(computedHash, headerMeta.PayloadSHA256)
			if !result.ChecksumValid {
				result.Errors = append(result.Errors, fmt.Sprintf("SHA-256 checksum mismatch: expected %s, computed %s", headerMeta.PayloadSHA256, computedHash))
			}
		} else {
			result.ChecksumValid = true // No baseline recorded
		}

		if headerMeta.FolderCount > 0 && headerMeta.FolderCount != recordCount {
			result.Errors = append(result.Errors, fmt.Sprintf("directory count mismatch: header records %d, parsed %d", headerMeta.FolderCount, recordCount))
		}
	} else {
		result.ChecksumValid = true
	}

	// Audit log telemetry
	if al != nil {
		if result.ChecksumValid && result.FramesValid && result.SyntaxValid {
			al.LogInfo("verify", "verify_pass", sourceURL, map[string]any{
				"record_count":   result.RecordCount,
				"payload_sha256": result.PayloadSHA256,
				"duration_ms":    result.Duration.Milliseconds(),
			})
		} else {
			al.LogError("verify", "verify_fail", sourceURL, strings.Join(result.Errors, "; "), map[string]any{
				"record_count": result.RecordCount,
			})
		}
	}

	if !result.ChecksumValid || !result.FramesValid || !result.SyntaxValid {
		return result, model.ErrVerificationFailed
	}

	return result, nil
}

func verifySQLite(ctx context.Context, sourceURL string, result *model.VerifyResult, al *model.AuditLogger, start time.Time) (*model.VerifyResult, error) {
	cleanPath, err := model.ValidateAndCleanPath(sourceURL)
	if err != nil {
		return nil, err
	}

	meta, err := format.ReadSQLiteHeader(cleanPath)
	if err != nil {
		result.SyntaxValid = false
		result.Errors = append(result.Errors, fmt.Sprintf("failed to read sqlite metadata: %v", err))
		result.Duration = time.Since(start)
		return result, model.ErrVerificationFailed
	}

	db, err := sql.Open("sqlite", cleanPath)
	if err != nil {
		result.FramesValid = false
		result.Errors = append(result.Errors, err.Error())
		return result, model.ErrVerificationFailed
	}
	defer func() { _ = db.Close() }()

	// PRAGMA integrity_check
	var checkResult string
	if err := db.QueryRow("PRAGMA integrity_check;").Scan(&checkResult); err != nil || checkResult != "ok" {
		result.FramesValid = false
		result.Errors = append(result.Errors, fmt.Sprintf("PRAGMA integrity_check failed: %s (%v)", checkResult, err))
	} else {
		result.FramesValid = true
	}

	var count int64
	_ = db.QueryRow("SELECT COUNT(*) FROM directories;").Scan(&count)
	result.RecordCount = count
	result.SyntaxValid = true
	result.ChecksumValid = true
	result.ExpectedSHA256 = meta.PayloadSHA256
	result.Duration = time.Since(start)

	if meta.FolderCount > 0 && meta.FolderCount != count {
		result.Errors = append(result.Errors, fmt.Sprintf("count mismatch: header %d, db %d", meta.FolderCount, count))
		return result, model.ErrVerificationFailed
	}

	return result, nil
}
