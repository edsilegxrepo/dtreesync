// Package format implements snapshot serialization, parsing, and compression engines.
//
// Objectives:
//   - Provide high-throughput streaming encoders and decoders for TSV, NDJSON, and SQLite formats.
//   - Seamlessly support streaming Zstandard compression and transparent format deduction.
//   - Maintain strict format specifications, schema verification, and canonical representations.
//
// Core Components:
//   - DeduceFormatAndCompression: Heuristically resolves format (TSV, NDJSON, SQLite) and compression (Zstd, None)
//     based on artifact naming conventions and URL suffixes.
//
// Data Flow:
//
//	Artifact Path / URI -> DeduceFormatAndCompression() -> FormatType & CompressionType -> Engine Selector.
package format

import (
	"strings"

	"github.com/edsilegxrepo/dtreesync/internal/model"
)

// DeduceFormatAndCompression resolves format and compression types based on file path extension suffixes.
func DeduceFormatAndCompression(pathOrURL string) (model.FormatType, model.CompressionType) {
	lower := strings.ToLower(pathOrURL)
	if idx := strings.IndexAny(lower, "?#"); idx != -1 {
		lower = lower[:idx]
	}

	// Check compression
	comp := model.CompressionNone
	if strings.HasSuffix(lower, ".zst") || strings.HasSuffix(lower, ".zstd") {
		comp = model.CompressionZstd
		lower = strings.TrimSuffix(lower, ".zst")
		lower = strings.TrimSuffix(lower, ".zstd")
	}

	// Check format
	switch {
	case strings.HasSuffix(lower, ".tsv"):
		return model.FormatTSV, comp
	case strings.HasSuffix(lower, ".jsonl") || strings.HasSuffix(lower, ".ndjson"):
		return model.FormatNDJSON, comp
	case strings.HasSuffix(lower, ".db") || strings.HasSuffix(lower, ".sqlite") || strings.HasSuffix(lower, ".sqlite3"):
		return model.FormatSQLite, model.CompressionNone // SQLite is uncompressed
	default:
		// Default to NDJSON with Zstandard per design specification
		return model.FormatNDJSON, model.CompressionZstd
	}
}
