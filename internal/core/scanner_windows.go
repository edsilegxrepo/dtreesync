//go:build windows

// Package core provides Windows filesystem volume containment checks.
//
// Objectives:
//   - Confine scans to a single drive volume or UNC share when --one-file-system is enabled.
//
// Core Components:
//   - initRootDevice: Flags the scanner as enforcing volume isolation.
//   - isSameDevice: Compares uppercase Win32 volume names (e.g., "C:" vs "D:") to detect mount point crossings.
//
// Data Flow:
//
//	Discovered Child Path -> filepath.VolumeName() -> Case-Insensitive Equality Check against Root Volume.
package core

import (
	"path/filepath"
	"strings"
)

// initRootDevice registers the root volume on Windows to enforce drive boundary confinement.
func (s *Scanner) initRootDevice() {
	s.hasRootDev = true
	_ = s.rootDev
}

// isSameDevice evaluates whether childAbs belongs to the same Windows drive volume
// or UNC share as the root scan directory, preventing traversals across volumes.
func (s *Scanner) isSameDevice(childAbs string) bool {
	if !s.hasRootDev {
		return true
	}
	rootVol := strings.ToUpper(filepath.VolumeName(s.rootAbs))
	childVol := strings.ToUpper(filepath.VolumeName(childAbs))
	return rootVol == childVol
}
