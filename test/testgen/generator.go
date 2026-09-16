// Package testgen provides deterministic synthetic filesystem hierarchy generation.
//
// Objectives:
//   - Produce realistic, highly parameterized directory topologies with controllable depth, fanout, and file payloads.
//   - Provide reproducible test environments driven by pseudo-random number generator (PRNG) seeds.
//
// Core Components:
//   - GeneratorConfig: Topology parameters (BaseDir, NumPartners, SubdirsPerLevel, Depth, FilesPerDir, Seed).
//   - GeneratorStats: Aggregate directory and payload file generation metrics.
//   - Generate: Recursive filesystem generator creating partner subtrees and dummy payload files.
//
// Data Flow:
//
//	GeneratorConfig -> PRNG Seed -> Recursive Directory Creation (os.MkdirAll) -> Dummy File Creation (os.WriteFile) -> GeneratorStats.
package testgen

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
)

// GeneratorConfig configures synthetic directory topology generation.
type GeneratorConfig struct {
	BaseDir         string // Root directory to populate
	NumPartners     int    // Number of top-level partner entities
	SubdirsPerLevel int    // Branching factor
	Depth           int    // Max depth of folder tree
	FilesPerDir     int    // Number of dummy payload files per folder
	WithACLs        bool   // Synthesize realistic permissions / ACLs
	Seed            int64  // Deterministic PRNG seed
}

// GeneratorStats records summary counts from generation.
type GeneratorStats struct {
	TotalDirs  int64
	TotalFiles int64
}

// Generate creates a realistic, deterministic multi-level directory mesh.
func Generate(cfg GeneratorConfig) (*GeneratorStats, error) {
	if cfg.NumPartners <= 0 {
		cfg.NumPartners = 5
	}
	if cfg.SubdirsPerLevel <= 0 {
		cfg.SubdirsPerLevel = 3
	}
	if cfg.Depth <= 0 {
		cfg.Depth = 3
	}
	if cfg.Seed == 0 {
		cfg.Seed = 42
	}

	// #nosec G404 -- Deterministic pseudo-random generation is required for reproducible test directory tree generation.
	rng := rand.New(rand.NewSource(cfg.Seed))
	stats := &GeneratorStats{}

	standardSubfolders := []string{
		"inbound", "outbound", "archive", "processing", "quarantine",
		"errors", "temp", "2026", "q1", "q2", "audit", "reports",
	}

	var createTree func(currentPath string, currentDepth int) error
	createTree = func(currentPath string, currentDepth int) error {
		if currentDepth >= cfg.Depth {
			return nil
		}

		for i := 0; i < cfg.SubdirsPerLevel; i++ {
			subName := standardSubfolders[(int(rng.Int63())+i)%len(standardSubfolders)]
			folderName := fmt.Sprintf("%s_%d", subName, i+1)
			folderPath := filepath.Join(currentPath, folderName)

			if err := os.MkdirAll(folderPath, 0o750); err != nil {
				return fmt.Errorf("failed to create dir %q: %w", folderPath, err)
			}
			stats.TotalDirs++

			// Create dummy payload files to verify scanner zero file I/O overhead
			for f := 0; f < cfg.FilesPerDir; f++ {
				fileName := fmt.Sprintf("payload_%d.dat", f+1)
				filePath := filepath.Join(folderPath, fileName)
				payload := []byte(fmt.Sprintf("test data payload %d in %s", f, folderName))
				if err := os.WriteFile(filePath, payload, 0o600); err != nil {
					return fmt.Errorf("failed to write payload file %q: %w", filePath, err)
				}
				stats.TotalFiles++
			}

			if err := createTree(folderPath, currentDepth+1); err != nil {
				return err
			}
		}
		return nil
	}

	for p := 0; p < cfg.NumPartners; p++ {
		partnerDir := filepath.Join(cfg.BaseDir, fmt.Sprintf("partner_%03d", p+1))
		if err := os.MkdirAll(partnerDir, 0o750); err != nil {
			return nil, err
		}
		stats.TotalDirs++

		if err := createTree(partnerDir, 1); err != nil {
			return nil, err
		}
	}

	return stats, nil
}
