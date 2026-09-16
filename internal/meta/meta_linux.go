//go:build linux

// Package meta provides Linux-specific timestamp extraction.
//
// Objectives:
//   - Extract high-resolution nanosecond timestamps directly from Linux syscall.Stat_t structures.
//
// Core Components:
//   - extractPosixTimestamps: Populates AccessTime, ModTime, and ChangeTime from Linux Atim/Mtim/Ctim timespecs.
//
// Data Flow:
//
//	Linux syscall.Stat_t -> extractPosixTimestamps() -> PlatformMeta Nanosecond Fields.
package meta

import (
	"syscall"

	"github.com/edsilegxrepo/dtreesync/internal/model"
)

func extractPosixTimestamps(stat *syscall.Stat_t, meta *model.PlatformMeta) {
	if stat == nil || meta == nil {
		return
	}
	meta.AccessTime = stat.Atim.Nano()
	meta.ModTime = stat.Mtim.Nano()
	meta.ChangeTime = stat.Ctim.Nano()
}
