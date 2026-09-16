// Package core implements directory drift detection and compliance auditing.
//
// Objectives:
//   - Audit live filesystem topologies against baseline snapshots for configuration drift and tampering.
//   - Detect missing directories, untracked directories, unauthorized payload files, mode changes,
//     ownership deviations, and SDDL / POSIX ACL modifications.
//   - Execute live scanning and payload file discovery in a single pass without extra disk traversal.
//
// Core Components:
//   - Diff: Master audit driver comparing baseline in-memory map against live filesystem state.
//   - Single-Pass Scanner: Traverses live trees capturing directory metadata and logging untracked files via OnFile.
//   - Drift Evaluator: Evaluates field-by-field equality with support for identity mapping and ignore flags.
//
// Data Flow:
//
//	Snapshot Stream -> In-Memory Snapshot Map (snapMap)
//	Live Filesystem -> Single-Pass Scanner -> Live Map (liveMap) & Untracked Files
//	Map Difference & Attribute Comparator -> DiffSummary & []DriftItem -> DiffResult (ErrDriftDetected).
package core

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/edsilegxrepo/dtreesync/internal/model"
)

// Diff compares a live directory hierarchy against a baseline snapshot and identifies discrepancies.
func Diff(ctx context.Context, cfg model.DiffConfig, al *model.AuditLogger) (*model.DiffResult, error) {
	start := time.Now()

	cleanLive, err := model.ValidateAndCleanPath(cfg.LiveFolder)
	if err != nil {
		return nil, fmt.Errorf("live folder invalid: %w", err)
	}

	// 1. Read baseline snapshot records into map
	snapMap := make(map[string]model.DirRecord)
	filter := model.NewRecordFilter(cfg.Entities, cfg.Include, cfg.Exclude)
	snapCollector := func(rec model.DirRecord) error {
		if cfg.IdentityMap != nil {
			rec.Metadata = cfg.IdentityMap.ApplyToPlatformMeta(rec.Metadata)
		}

		// Apply unified entity, inclusion, and exclusion filtering
		if !filter.Matches(rec) {
			return nil
		}

		snapMap[rec.RelPath] = rec
		return nil
	}

	var snapshotMeta *model.BackupMetadata
	if cfg.SnapshotReader != nil {
		snapshotMeta, err = readSnapshotFromReader(cfg.SnapshotReader, cfg.Format, cfg.Compression, snapCollector)
	} else if cfg.SnapshotURL != "" {
		snapshotMeta, err = readSnapshotFromSource(ctx, cfg.SnapshotURL, cfg.Format, cfg.Compression, snapCollector)
	} else {
		return nil, fmt.Errorf("%w: neither SnapshotReader nor SnapshotURL provided", model.ErrSnapshotNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read baseline snapshot: %w", err)
	}
	_ = snapshotMeta

	// 2. Scan live directory tree with unified payload file discovery
	var (
		untrackedFiles []string
		filesMu        sync.Mutex
	)

	singleEntity := ""
	if len(cfg.Entities) == 1 {
		singleEntity = cfg.Entities[0]
	}

	scanOpts := model.ScanOptions{
		Workers: cfg.Workers,
		MaxIOPS: cfg.MaxIOPS,
		Entity:  singleEntity,
		Include: cfg.Include,
		Exclude: cfg.Exclude,
		OnFile: func(rel string) {
			filesMu.Lock()
			untrackedFiles = append(untrackedFiles, rel)
			filesMu.Unlock()
		},
	}
	scanner, err := NewScanner(cleanLive, scanOpts, al)
	if err != nil {
		return nil, fmt.Errorf("failed to create live scanner: %w", err)
	}

	liveRecChan := make(chan model.DirRecord, 2048)
	errChan := make(chan error, 1)
	go func() {
		errChan <- scanner.Stream(ctx, liveRecChan)
	}()

	liveMap := make(map[string]model.DirRecord)
	for rec := range liveRecChan {
		if !filter.Matches(rec) {
			continue
		}
		liveMap[rec.RelPath] = rec
	}
	if scanErr := <-errChan; scanErr != nil {
		return nil, fmt.Errorf("live directory scan failed: %w", scanErr)
	}

	// 4. Compare baseline snapshot against live state
	var driftItems []model.DriftItem
	var (
		missingCount int64
		extraCount   int64
		driftCount   int64
	)

	// Check missing directories (in snapshot, absent from live)
	for relPath, snapRec := range snapMap {
		liveRec, exists := liveMap[relPath]
		if !exists {
			missingCount++
			driftItems = append(driftItems, model.DriftItem{
				Path:     relPath,
				Type:     "missing_directory",
				Field:    "existence",
				Expected: "present",
				Actual:   "absent",
			})
			if al != nil {
				al.LogWarn("diff", "drift_detected", relPath, "missing directory", map[string]any{
					"drift_type": "missing_directory",
				})
			}
			continue
		}

		// Compare permissions & metadata
		// A. Mode
		if snapRec.Metadata.Mode != nil && liveRec.Metadata.Mode != nil {
			if *snapRec.Metadata.Mode != *liveRec.Metadata.Mode {
				driftCount++
				driftItems = append(driftItems, model.DriftItem{
					Path:     relPath,
					Type:     "permission_drift",
					Field:    "mode",
					Expected: fmt.Sprintf("%04o", *snapRec.Metadata.Mode),
					Actual:   fmt.Sprintf("%04o", *liveRec.Metadata.Mode),
				})
			}
		}

		// B. Owner / Group (if not ignored)
		if !cfg.IgnoreOwner {
			if snapRec.Metadata.Username != "" && liveRec.Metadata.Username != "" && snapRec.Metadata.Username != liveRec.Metadata.Username {
				driftCount++
				driftItems = append(driftItems, model.DriftItem{
					Path:     relPath,
					Type:     "owner_drift",
					Field:    "user",
					Expected: snapRec.Metadata.Username,
					Actual:   liveRec.Metadata.Username,
				})
			}

			if snapRec.Metadata.OwnerSID != "" && liveRec.Metadata.OwnerSID != "" && snapRec.Metadata.OwnerSID != liveRec.Metadata.OwnerSID {
				driftCount++
				driftItems = append(driftItems, model.DriftItem{
					Path:     relPath,
					Type:     "owner_drift",
					Field:    "owner_sid",
					Expected: snapRec.Metadata.OwnerSID,
					Actual:   liveRec.Metadata.OwnerSID,
				})
			}
		}

		// C. SDDL / ACLs
		if snapRec.Metadata.SDDL != "" && liveRec.Metadata.SDDL != "" {
			if normalizeSDDL(snapRec.Metadata.SDDL) != normalizeSDDL(liveRec.Metadata.SDDL) {
				driftCount++
				driftItems = append(driftItems, model.DriftItem{
					Path:     relPath,
					Type:     "acl_drift",
					Field:    "sddl",
					Expected: snapRec.Metadata.SDDL,
					Actual:   liveRec.Metadata.SDDL,
				})
			}
		}

		if snapRec.Metadata.ACLAccess != "" && liveRec.Metadata.ACLAccess != "" && snapRec.Metadata.ACLAccess != liveRec.Metadata.ACLAccess {
			driftCount++
			driftItems = append(driftItems, model.DriftItem{
				Path:     relPath,
				Type:     "acl_drift",
				Field:    "acl_access",
				Expected: snapRec.Metadata.ACLAccess,
				Actual:   liveRec.Metadata.ACLAccess,
			})
		}
	}

	// Check untracked directories (in live, absent from snapshot)
	for relPath := range liveMap {
		if relPath == "" {
			continue // Root directory itself is the base folder, not an untracked child
		}
		if _, inSnap := snapMap[relPath]; !inSnap {
			extraCount++
			driftItems = append(driftItems, model.DriftItem{
				Path:     relPath,
				Type:     "untracked_directory",
				Field:    "existence",
				Expected: "absent",
				Actual:   "present",
			})
		}
	}

	// Record untracked files
	for _, f := range untrackedFiles {
		extraCount++
		driftItems = append(driftItems, model.DriftItem{
			Path:     f,
			Type:     "untracked_file",
			Field:    "payload_file",
			Expected: "absent",
			Actual:   "present",
		})
	}

	totalDrift := len(driftItems)
	status := "aligned"
	if totalDrift > 0 {
		status = "drift_detected"
	}

	summary := model.DiffSummary{
		ExpectedDirectories: int64(len(snapMap)),
		ScannedDirectories:  int64(len(liveMap)),
		MissingCount:        missingCount,
		ExtraCount:          extraCount,
		DriftCount:          driftCount,
	}

	result := &model.DiffResult{
		Status:       status,
		BaseFolder:   cleanLive,
		TreeFile:     cfg.SnapshotURL,
		TimestampUTC: time.Now().UTC(),
		Summary:      summary,
		TotalDrift:   totalDrift,
		DriftItems:   driftItems,
		Duration:     time.Since(start),
	}

	if totalDrift > 0 {
		return result, model.ErrDriftDetected
	}

	return result, nil
}

func normalizeSDDL(s string) string {
	return strings.TrimSpace(s)
}
