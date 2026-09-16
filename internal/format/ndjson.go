// Package format provides Newline-Delimited JSON (NDJSON) serialization and streaming.
//
// Objectives:
//   - Implement the canonical Line 1 metadata envelope ("_meta") specification.
//   - Stream directory records with zero in-memory full-snapshot buffering.
//   - Support microsecond header peeking (ReadNDJSONHeader) for rapid metadata queries without body parsing.
//
// Core Components:
//   - NDJSONWriter: 64KB buffered encoder emitting Line 1 header and discrete DirRecord lines.
//   - ReadNDJSONHeader: Extracts Line 1 metadata in isolation for status and pre-flight checks.
//   - ReadNDJSONRecords: Low-allocation scanner reading Line 1 header and streaming records to a callback.
//
// Data Flow:
//
//	Live Directory Walk -> NDJSONWriter.WriteRecord() -> Line-by-Line JSON -> Stream / File
//	Snapshot Stream -> ReadNDJSONRecords() -> NDJSONHeader (Line 1) -> Callback(DirRecord) -> Restore / Diff Engine.
package format

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/edsilegxrepo/dtreesync/internal/model"
)

// NDJSONWriter streams metadata envelopes and directory records in Newline Delimited JSON format.
type NDJSONWriter struct {
	w *bufio.Writer
}

// NewNDJSONWriter constructs an NDJSONWriter wrapping w.
func NewNDJSONWriter(w io.Writer) *NDJSONWriter {
	return &NDJSONWriter{w: bufio.NewWriterSize(w, 64*1024)}
}

// WriteHeader serializes Line 1: {"_meta": {...}}.
func (nw *NDJSONWriter) WriteHeader(meta model.BackupMetadata) error {
	hdr := model.NDJSONHeader{Meta: meta}
	data, err := json.Marshal(hdr)
	if err != nil {
		return fmt.Errorf("failed to marshal NDJSON header: %w", err)
	}

	if _, err := nw.w.Write(data); err != nil {
		return err
	}
	return nw.w.WriteByte('\n')
}

// WriteRecord serializes a single DirRecord as a discrete JSON line.
func (nw *NDJSONWriter) WriteRecord(rec model.DirRecord) error {
	data, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("failed to marshal DirRecord: %w", err)
	}

	if _, err := nw.w.Write(data); err != nil {
		return err
	}
	return nw.w.WriteByte('\n')
}

// Flush flushes buffered data to the underlying stream.
func (nw *NDJSONWriter) Flush() error {
	return nw.w.Flush()
}

// ReadNDJSONHeader peeks and deserializes Line 1 of an NDJSON stream in microseconds.
func ReadNDJSONHeader(r io.Reader) (*model.BackupMetadata, error) {
	bufR := bufio.NewReader(r)
	line, err := bufR.ReadBytes('\n')
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("failed to read line 1 from NDJSON stream: %w", err)
	}

	trimmed := strings.TrimSpace(string(line))
	if trimmed == "" {
		return nil, fmt.Errorf("%w: empty line 1 in NDJSON stream", model.ErrSnapshotCorrupted)
	}

	var hdr model.NDJSONHeader
	if err := json.Unmarshal([]byte(trimmed), &hdr); err != nil {
		return nil, fmt.Errorf("%w: failed to parse NDJSON header: %v", model.ErrSnapshotCorrupted, err)
	}

	if hdr.Meta.BaseFolder == "" && hdr.Meta.Version == "" {
		return nil, fmt.Errorf("%w: line 1 does not contain a valid '_meta' object", model.ErrSnapshotCorrupted)
	}

	return &hdr.Meta, nil
}

// ReadNDJSONRecords reads the Line 1 header and streams subsequent records to onRecord.
func ReadNDJSONRecords(r io.Reader, onRecord func(rec model.DirRecord) error) (*model.BackupMetadata, error) {
	scanner := bufio.NewScanner(r)
	buf := make([]byte, 1024*1024)
	scanner.Buffer(buf, 16*1024*1024)

	var meta *model.BackupMetadata
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		if lineNum == 1 {
			var hdr model.NDJSONHeader
			if err := json.Unmarshal(line, &hdr); err != nil {
				return nil, fmt.Errorf("%w: line 1 is not valid NDJSON header: %v", model.ErrSnapshotCorrupted, err)
			}
			meta = &hdr.Meta
			continue
		}

		var rec model.DirRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			return meta, fmt.Errorf("%w: line %d is not a valid DirRecord: %v", model.ErrSnapshotCorrupted, lineNum, err)
		}

		if err := onRecord(rec); err != nil {
			return meta, err
		}
	}

	if err := scanner.Err(); err != nil {
		return meta, fmt.Errorf("error reading NDJSON stream: %w", err)
	}

	if meta == nil {
		return nil, fmt.Errorf("%w: missing header line in NDJSON stream", model.ErrSnapshotCorrupted)
	}

	return meta, nil
}
