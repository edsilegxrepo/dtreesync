// Package dtreesync provides modern standard Go push-iterator interfaces.
//
// Objectives:
//   - Provide idiomatic, zero-allocation directory tree streaming using Go standard iter.Seq2 range loops.
//   - Ensure clean goroutine teardown and channel drainage on early break/abort conditions.
//
// Core Components:
//   - Scan: Returns an iter.Seq2[DirRecord, error] pushing directory records directly into caller range loops.
//
// Data Flow:
//
//	Caller Range Loop -> Scan(ctx, root, opts) -> core.Scanner -> Channel Stream -> yield(record, err).
package dtreesync

import (
	"context"
	"errors"
	"iter"

	"github.com/edsilegxrepo/dtreesync/internal/core"
)

// Scan returns a push iterator (iter.Seq2[DirRecord, error]) that enables zero-allocation
// streaming over discovered directories using Go 1.27 range loops:
//
//	for record, err := range dtreesync.Scan(ctx, "/var/mft/landing", dtreesync.ScanOptions{Workers: 16}) {
//	    if err != nil { ... }
//	    process(record)
//	}
func Scan(ctx context.Context, root string, opts ScanOptions) iter.Seq2[DirRecord, error] {
	return func(yield func(DirRecord, error) bool) {
		cleanRoot, err := ValidateAndCleanPath(root)
		if err != nil {
			yield(DirRecord{}, err)
			return
		}

		scanner, err := core.NewScanner(cleanRoot, opts, nil)
		if err != nil {
			yield(DirRecord{}, err)
			return
		}

		scanCtx, cancel := context.WithCancel(ctx)
		defer cancel()

		recChan := make(chan DirRecord, 2048)
		errChan := make(chan error, 1)

		go func() {
			errChan <- scanner.Stream(scanCtx, recChan)
		}()

		for rec := range recChan {
			if !yield(rec, nil) {
				cancel()
				// Drain channel to allow scanner goroutine to exit
				for range recChan {
				}
				return
			}
		}

		streamErr := <-errChan
		if streamErr != nil && !errors.Is(streamErr, context.Canceled) {
			yield(DirRecord{}, streamErr)
		}
	}
}
