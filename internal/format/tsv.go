// Package format provides Tab-Separated Values (TSV) streaming serialization and parsing.
//
// Objectives:
//   - Implement a compact, columnar 13-field relational text format.
//   - Embed self-contained JSON provenance metadata in Line 1 via the "#META:" prefix.
//   - Provide microsecond header parsing and high-throughput streaming record iteration.
//
// Core Components:
//   - TSVWriter: 64KB buffered encoder emitting #META: JSON header, compliance comments, and tab-delimited records.
//   - ReadTSVHeader: Fast single-line peeker for inspecting snapshot metadata without reading table rows.
//   - ReadTSVRecords: High-speed streaming parser parsing 13-column rows into typed DirRecord structures.
//   - sanitizeTSVField / unnull: Null-value ("-") handlers and tab/newline sanitizers.
//
// Data Flow:
//
//	DirRecord -> Field Formatter -> Tab-Separated Line -> Buffered Stream
//	Stream -> Line 1 (#META:) -> TSV Row Parser -> Column Unmarshaler -> Callback(DirRecord).
package format

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/edsilegxrepo/dtreesync/internal/model"
)

const (
	tsvMetaPrefix   = "#META:"
	tsvColumnHeader = "entity\trel_path\tmode\tuid\tgid\tuser\tgroup\tacl_access\tacl_default\tselinux\tsddl\tattrs\tmtime"
	tsvNullValue    = "-"
)

// TSVWriter writes snapshots in canonical TSV format with an embedded JSON metadata header.
type TSVWriter struct {
	w *bufio.Writer
}

// NewTSVWriter constructs a TSVWriter wrapping w.
func NewTSVWriter(w io.Writer) *TSVWriter {
	return &TSVWriter{w: bufio.NewWriterSize(w, 64*1024)}
}

// WriteHeader serializes the #META: header and compliance comments.
func (tw *TSVWriter) WriteHeader(meta model.BackupMetadata) error {
	metaJSON, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("failed to marshal TSV metadata header: %w", err)
	}

	// Line 1: #META: JSON envelope
	if _, err := tw.w.WriteString(tsvMetaPrefix + string(metaJSON) + "\n"); err != nil {
		return err
	}

	// Compliance headers
	if _, err := tw.w.WriteString("# COMPLIANCE AUDIT RECORD: dtreesync\n"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(tw.w, "# SOURCE_BASE: %s\n", meta.BaseFolder); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(tw.w, "# TIMESTAMP_UTC: %s\n", meta.CreatedAt.UTC().Format(time.RFC3339)); err != nil {
		return err
	}

	// Canonical column names
	if _, err := tw.w.WriteString(tsvColumnHeader + "\n"); err != nil {
		return err
	}
	return nil
}

// WriteRecord serializes a single DirRecord as a tab-delimited row.
func (tw *TSVWriter) WriteRecord(rec model.DirRecord) error {
	entity := sanitizeTSVField(rec.Entity)
	relPath := sanitizeTSVField(rec.RelPath)

	modeStr := tsvNullValue
	if rec.Metadata.Mode != nil {
		modeStr = fmt.Sprintf("%04o", *rec.Metadata.Mode)
	}

	uidStr := tsvNullValue
	if rec.Metadata.UID != nil {
		uidStr = strconv.FormatUint(uint64(*rec.Metadata.UID), 10)
	}

	gidStr := tsvNullValue
	if rec.Metadata.GID != nil {
		gidStr = strconv.FormatUint(uint64(*rec.Metadata.GID), 10)
	}

	userStr := sanitizeTSVField(rec.Metadata.Username)
	groupStr := sanitizeTSVField(rec.Metadata.Group)
	aclAccessStr := sanitizeTSVField(rec.Metadata.ACLAccess)
	aclDefaultStr := sanitizeTSVField(rec.Metadata.ACLDefault)
	selinuxStr := sanitizeTSVField(rec.Metadata.SELinuxContext)
	sddlStr := sanitizeTSVField(rec.Metadata.SDDL)

	attrsStr := tsvNullValue
	if rec.Metadata.FileAttributes != nil {
		attrsStr = strconv.FormatUint(uint64(*rec.Metadata.FileAttributes), 10)
	}

	mtimeStr := strconv.FormatInt(rec.Metadata.ModTime, 10)

	line := fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
		entity, relPath, modeStr, uidStr, gidStr, userStr, groupStr,
		aclAccessStr, aclDefaultStr, selinuxStr, sddlStr, attrsStr, mtimeStr)

	_, err := tw.w.WriteString(line)
	return err
}

// Flush flushes any buffered data to the underlying writer.
func (tw *TSVWriter) Flush() error {
	return tw.w.Flush()
}

func sanitizeTSVField(val string) string {
	if val == "" {
		return tsvNullValue
	}
	// Tabs and newlines should never exist in paths/attributes, but safeguard against them
	s := strings.ReplaceAll(val, "\t", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}

// ReadTSVHeader peeks and parses Line 1 of a TSV stream without consuming downstream records.
func ReadTSVHeader(r io.Reader) (*model.BackupMetadata, error) {
	bufR := bufio.NewReader(r)
	line, err := bufR.ReadString('\n')
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("failed to read TSV header line: %w", err)
	}

	trimmed := strings.TrimSpace(line)
	if !strings.HasPrefix(trimmed, tsvMetaPrefix) {
		return nil, fmt.Errorf("%w: missing #META: prefix in TSV header line 1", model.ErrSnapshotCorrupted)
	}

	jsonBytes := []byte(strings.TrimPrefix(trimmed, tsvMetaPrefix))
	var meta model.BackupMetadata
	if err := json.Unmarshal(jsonBytes, &meta); err != nil {
		return nil, fmt.Errorf("%w: failed to parse TSV #META: JSON: %v", model.ErrSnapshotCorrupted, err)
	}

	return &meta, nil
}

// ReadTSVRecords streams DirRecords from a TSV input reader.
func ReadTSVRecords(r io.Reader, onRecord func(rec model.DirRecord) error) (*model.BackupMetadata, error) {
	scanner := bufio.NewScanner(r)
	buf := make([]byte, 1024*1024)
	scanner.Buffer(buf, 16*1024*1024) // Up to 16MB lines for massive SDDLs

	var meta *model.BackupMetadata
	headerParsed := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Parse line 1 #META:
		if strings.HasPrefix(line, tsvMetaPrefix) {
			metaBytes := []byte(strings.TrimPrefix(line, tsvMetaPrefix))
			meta = &model.BackupMetadata{}
			if err := json.Unmarshal(metaBytes, meta); err != nil {
				return nil, fmt.Errorf("%w: invalid #META: json: %v", model.ErrSnapshotCorrupted, err)
			}
			headerParsed = true
			continue
		}

		// Skip comments and column headers
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, "entity\trel_path") {
			continue
		}

		// Data row: 13 columns
		cols := strings.Split(line, "\t")
		if len(cols) < 13 {
			return nil, fmt.Errorf("%w: TSV row contains %d columns, expected 13", model.ErrSnapshotCorrupted, len(cols))
		}

		rec := model.DirRecord{
			Entity:  unnull(cols[0]),
			RelPath: unnull(cols[1]),
		}

		// mode
		if mStr := unnull(cols[2]); mStr != "" {
			if mVal, err := strconv.ParseUint(mStr, 8, 32); err == nil {
				u := uint32(mVal)
				rec.Metadata.Mode = &u
			}
		}

		// uid
		if uStr := unnull(cols[3]); uStr != "" {
			if uVal, err := strconv.ParseUint(uStr, 10, 32); err == nil {
				u := uint32(uVal)
				rec.Metadata.UID = &u
			}
		}

		// gid
		if gStr := unnull(cols[4]); gStr != "" {
			if gVal, err := strconv.ParseUint(gStr, 10, 32); err == nil {
				g := uint32(gVal)
				rec.Metadata.GID = &g
			}
		}

		rec.Metadata.Username = unnull(cols[5])
		rec.Metadata.Group = unnull(cols[6])
		rec.Metadata.ACLAccess = unnull(cols[7])
		rec.Metadata.ACLDefault = unnull(cols[8])
		rec.Metadata.SELinuxContext = unnull(cols[9])
		rec.Metadata.SDDL = unnull(cols[10])

		// attrs
		if aStr := unnull(cols[11]); aStr != "" {
			if aVal, err := strconv.ParseUint(aStr, 10, 32); err == nil {
				a := uint32(aVal)
				rec.Metadata.FileAttributes = &a
			}
		}

		// mtime
		if mtStr := unnull(cols[12]); mtStr != "" {
			if mtVal, err := strconv.ParseInt(mtStr, 10, 64); err == nil {
				rec.Metadata.ModTime = mtVal
			}
		}

		if err := onRecord(rec); err != nil {
			return meta, err
		}
	}

	if err := scanner.Err(); err != nil {
		return meta, fmt.Errorf("error reading TSV stream: %w", err)
	}

	if !headerParsed {
		return nil, fmt.Errorf("%w: missing #META: header line in TSV stream", model.ErrSnapshotCorrupted)
	}

	return meta, nil
}

func unnull(val string) string {
	trimmed := strings.TrimSpace(val)
	if trimmed == tsvNullValue {
		return ""
	}
	return trimmed
}
