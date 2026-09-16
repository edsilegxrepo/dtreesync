// Package core implements snapshot lifecycle management and retention pruning.
//
// Objectives:
//   - Prevent unbounded disk storage growth through automated snapshot lifecycle rotation.
//   - Support dual-policy FIFO pruning combining maximum retention count and maximum age windows.
//
// Core Components:
//   - ApplyRetention: Discovers snapshot artifacts, sorts by modTime descending, and prunes expired files.
//
// Data Flow:
//
//	Target Directory -> File Discovery & Snapshot Extension Filter -> Sort By ModTime (Newest First)
//	-> Age & Count Policy Evaluation -> os.Remove() -> Audit Log Telemetry.
package core

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/edsilegxrepo/dtreesync/internal/model"
)

// ApplyRetention purges expired snapshot files in targetDir based on age and count policies.
// If prefix is specified, only snapshot files matching the prefix are considered.
func ApplyRetention(targetDir string, retentionDays, retentionCount int, al *model.AuditLogger, prefix ...string) ([]string, error) {
	if retentionDays <= 0 && retentionCount <= 0 {
		return nil, nil
	}

	cleanDir, err := model.ValidateAndCleanPath(targetDir)
	if err != nil {
		return nil, err
	}

	entries, err := os.ReadDir(cleanDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory for retention cleanup: %w", err)
	}

	type fileMeta struct {
		name    string
		path    string
		modTime time.Time
	}

	var snapshots []fileMeta
	now := time.Now()

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if len(prefix) > 0 && prefix[0] != "" && !strings.HasPrefix(name, prefix[0]) {
			continue
		}
		// Only consider snapshot file patterns
		if strings.HasSuffix(name, ".zst") || strings.HasSuffix(name, ".tsv") ||
			strings.HasSuffix(name, ".jsonl") || strings.HasSuffix(name, ".ndjson") ||
			strings.HasSuffix(name, ".db") {
			info, err := entry.Info()
			if err != nil {
				continue
			}
			snapshots = append(snapshots, fileMeta{
				name:    name,
				path:    filepath.Join(cleanDir, name),
				modTime: info.ModTime(),
			})
		}
	}

	// Sort newest first
	slices.SortFunc(snapshots, func(a, b fileMeta) int {
		if a.modTime.After(b.modTime) {
			return -1
		}
		if a.modTime.Before(b.modTime) {
			return 1
		}
		return 0
	})

	var purged []string

	for idx, snap := range snapshots {
		shouldPurge := false
		reason := ""

		// Count-based eviction
		if retentionCount > 0 && idx >= retentionCount {
			shouldPurge = true
			reason = fmt.Sprintf("exceeded retention count %d (rank %d)", retentionCount, idx+1)
		}

		// Age-based eviction
		if retentionDays > 0 {
			age := now.Sub(snap.modTime)
			if age > time.Duration(retentionDays)*24*time.Hour {
				shouldPurge = true
				reason = fmt.Sprintf("exceeded retention window %d days (age %.1f days)", retentionDays, age.Hours()/24.0)
			}
		}

		if shouldPurge {
			if err := os.Remove(snap.path); err == nil {
				purged = append(purged, snap.path)
				if al != nil {
					al.LogInfo("retention", "retention_purged", snap.path, map[string]any{
						"purged_snapshot": snap.name,
						"policy":          reason,
					})
				}
			}
		}
	}

	return purged, nil
}
