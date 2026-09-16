// Package format provides Zstandard stream compression and decompression.
//
// Objectives:
//   - Deliver ultra-fast streaming compression using klauspost/compress/zstd.
//   - Clamp worker concurrency strictly within 1..32 to prevent thread and memory exhaustion.
//
// Core Components:
//   - NewZstdWriter: Initializes a multi-threaded streaming Zstandard compressor.
//   - NewZstdReader: Initializes a streaming Zstandard decompressor with frame validation.
//
// Data Flow:
//
//	Payload Bytes -> NewZstdWriter -> Zstandard Frames -> Destination Writer
//	Compressed Stream -> NewZstdReader -> Decompressed Snapshot Data -> Record Parser.
package format

import (
	"fmt"
	"io"
	"runtime"

	"github.com/klauspost/compress/zstd"
)

// NewZstdWriter creates a streaming Zstandard encoder with bounded concurrency.
func NewZstdWriter(w io.Writer, concurrency int) (*zstd.Encoder, error) {
	if concurrency <= 0 {
		concurrency = min(runtime.NumCPU()*2, 32)
	}
	if concurrency < 1 {
		concurrency = 1
	}
	if concurrency > 32 {
		concurrency = 32
	}

	enc, err := zstd.NewWriter(
		w,
		zstd.WithEncoderConcurrency(concurrency),
		zstd.WithEncoderLevel(zstd.SpeedDefault),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create zstd encoder: %w", err)
	}
	return enc, nil
}

// NewZstdReader creates a streaming Zstandard decoder with bounded concurrency.
func NewZstdReader(r io.Reader, concurrency int) (*zstd.Decoder, error) {
	if concurrency <= 0 {
		concurrency = min(runtime.NumCPU()*2, 32)
	}
	if concurrency < 1 {
		concurrency = 1
	}
	if concurrency > 32 {
		concurrency = 32
	}

	dec, err := zstd.NewReader(
		r,
		zstd.WithDecoderConcurrency(concurrency),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create zstd decoder: %w", err)
	}
	return dec, nil
}
