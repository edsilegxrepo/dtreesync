//go:build !windows

// Package core provides POSIX filesystem device containment checks.
//
// Objectives:
//   - Confine directory traversal to the root filesystem mount point when --one-file-system is enabled.
//
// Core Components:
//   - initRootDevice: Queries syscall.Stat_t on the root path and captures stat.Dev.
//   - isSameDevice: Compares candidate path stat.Dev against the root device ID to prevent crossing into foreign mounts.
//
// Data Flow:
//
//	Discovered Child Path -> syscall.Stat() -> Device Number (stat.Dev) Comparison.
package core

import (
	"syscall"
)

// initRootDevice queries the st_dev field of the root directory to establish
// the device ID baseline for --one-file-system boundary enforcement.
func (s *Scanner) initRootDevice() {
	var stat syscall.Stat_t
	if err := syscall.Stat(s.rootAbs, &stat); err == nil {
		s.rootDev = uint64(stat.Dev)
		s.hasRootDev = true
	}
}

// isSameDevice determines whether candidate child path resides on the same
// physical filesystem device as the root traversal directory.
func (s *Scanner) isSameDevice(childAbs string) bool {
	if !s.hasRootDev {
		return true
	}
	var stat syscall.Stat_t
	if err := syscall.Stat(childAbs, &stat); err != nil {
		return false
	}
	return uint64(stat.Dev) == s.rootDev
}
