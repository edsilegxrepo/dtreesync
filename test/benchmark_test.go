// Package test provides performance micro-benchmarks for dtreesync critical execution paths.
//
// Objectives:
//   - Quantify directory discovery throughput, serialization speed, and zero-disk cryptographic verification latency.
//   - Detect performance regressions and memory allocation hotspots across engine versions.
//
// Test Strategy:
//   - Scanner Discovery Throughput: BenchmarkScanner_DiscoveryThroughput measures crawl rate over 5,000 synthetic
//     directory nodes with payload files using 16 concurrent workers.
//   - NDJSON Serialization Rate: BenchmarkSerialization_NDJSON measures throughput across 10,000 memory records.
//   - TSV Tabular Rate: BenchmarkSerialization_TSV measures high-speed 13-column tab-delimited formatting.
//   - Zero-Disk Verification Throughput: BenchmarkVerification_ZeroDiskWrite benchmarks multi-threaded Zstandard
//     decompression and streaming SHA-256 hashing.
//
// Data Flow:
//
//	Synthetic Meshes & Record Slices -> Core Engines -> Go Benchmark Framework Metrics (ns/op, B/op, allocs/op).
package test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/edsilegxrepo/dtreesync/internal/core"
	"github.com/edsilegxrepo/dtreesync/internal/format"
	"github.com/edsilegxrepo/dtreesync/internal/model"
	"github.com/edsilegxrepo/dtreesync/pkg/dtreesync"
	"github.com/edsilegxrepo/dtreesync/test/testgen"
)

func BenchmarkScanner_DiscoveryThroughput(b *testing.B) {
	tmpDir := b.TempDir()
	sourceDir := filepath.Join(tmpDir, "bench_mesh")

	// Pre-generate 5,000 directories with dummy files
	_, err := testgen.Generate(testgen.GeneratorConfig{
		BaseDir:         sourceDir,
		NumPartners:     50,
		SubdirsPerLevel: 3,
		Depth:           3,
		FilesPerDir:     2,
		Seed:            99,
	})
	if err != nil {
		b.Fatalf("Failed to generate benchmark mesh: %v", err)
	}

	opts := model.ScanOptions{
		Workers: 16,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scanner, err := core.NewScanner(sourceDir, opts, nil)
		if err != nil {
			b.Fatalf("Scanner init failed: %v", err)
		}
		ch := make(chan model.DirRecord, 2048)
		var count int64
		go func() {
			for range ch {
				count++
			}
		}()
		if err := scanner.Stream(context.Background(), ch); err != nil {
			b.Fatalf("Scanner stream failed: %v", err)
		}
	}
}

func BenchmarkSerialization_NDJSON(b *testing.B) {
	mode := uint32(0o755)
	records := make([]model.DirRecord, 10000)
	for i := 0; i < len(records); i++ {
		records[i] = model.DirRecord{
			Entity:  fmt.Sprintf("partner_%04d", i%100),
			RelPath: fmt.Sprintf("partner_%04d/inbound/batch_%d", i%100, i),
			Metadata: model.PlatformMeta{
				Mode:     &mode,
				Username: "mft_service",
				Group:    "mft_users",
			},
		}
	}

	meta := model.BackupMetadata{
		Version:     "2.0",
		BaseFolder:  "/var/mft/bench",
		FolderCount: int64(len(records)),
		TreeFormat:  "ndjson",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		nw := format.NewNDJSONWriter(&buf)
		_ = nw.WriteHeader(meta)
		for _, r := range records {
			_ = nw.WriteRecord(r)
		}
		_ = nw.Flush()
	}
}

func BenchmarkSerialization_TSV(b *testing.B) {
	mode := uint32(0o755)
	records := make([]model.DirRecord, 10000)
	for i := 0; i < len(records); i++ {
		records[i] = model.DirRecord{
			Entity:  fmt.Sprintf("partner_%04d", i%100),
			RelPath: fmt.Sprintf("partner_%04d/inbound/batch_%d", i%100, i),
			Metadata: model.PlatformMeta{
				Mode:     &mode,
				Username: "mft_service",
				Group:    "mft_users",
			},
		}
	}

	meta := model.BackupMetadata{
		Version:     "2.0",
		BaseFolder:  "/var/mft/bench",
		FolderCount: int64(len(records)),
		TreeFormat:  "tsv",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		tw := format.NewTSVWriter(&buf)
		_ = tw.WriteHeader(meta)
		for _, r := range records {
			_ = tw.WriteRecord(r)
		}
		_ = tw.Flush()
	}
}

func BenchmarkVerification_ZeroDiskWrite(b *testing.B) {
	tmpDir := b.TempDir()
	sourceDir := filepath.Join(tmpDir, "source")
	snapFile := filepath.Join(tmpDir, "bench_snap.tsv.zst")

	for i := 0; i < 50; i++ {
		_ = os.MkdirAll(filepath.Join(sourceDir, fmt.Sprintf("p_%d", i), "inbound"), 0o755)
	}

	_, err := dtreesync.Backup(context.Background(), dtreesync.BackupConfig{
		BaseFolder:  sourceDir,
		TargetURL:   snapFile,
		Format:      dtreesync.FormatTSV,
		Compression: dtreesync.CompressionZstd,
		Workers:     4,
	})
	if err != nil {
		b.Fatalf("Backup failed: %v", err)
	}

	cfg := dtreesync.VerifyConfig{
		SourceURL: snapFile,
		Workers:   4,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		res, err := dtreesync.Verify(context.Background(), cfg)
		if err != nil || !res.ChecksumValid {
			b.Fatalf("Verify failed: %v", err)
		}
	}
}
