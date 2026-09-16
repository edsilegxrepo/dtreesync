// Package meta provides cross-platform filesystem metadata, security descriptor, and permission operations.
//
// Objectives:
//   - Abstract OS-specific permission and ACL mechanisms behind a unified PlatformEngine interface.
//   - Ensure lossless capture and restoration of NTFS Security Descriptors (SDDL) on Windows
//     and POSIX ACLs, SELinux contexts, and file modes on Linux.
//   - Provide cross-device safe file and directory movement and replication utilities.
//
// Core Components:
//   - PlatformEngine: The central contract for reading/applying metadata, privileges, and timestamps.
//   - DefaultEngine: Active OS-specific engine implementation instantiated at runtime.
//   - MoveItem: Robust atomic rename with automatic fallback to recursive copy-then-delete across filesystem boundaries.
//   - CopyDirOrFile: Recursive directory tree copy helper.
//
// Data Flow:
//
//	Local Filesystem Path -> PlatformEngine.ReadMeta() -> PlatformMeta
//	PlatformMeta -> PlatformEngine.ApplyMeta() / SetTimes() -> Kernel Filesystem Calls.
package meta

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/edsilegxrepo/dtreesync/internal/model"
)

// PlatformEngine defines cross-platform capability operations for metadata extraction and application.
type PlatformEngine interface {
	// InitPrivileges performs startup privilege acquisition (e.g. NT privileges on Windows).
	InitPrivileges() error

	// ReadMeta extracts platform-specific security descriptors, attributes, and timestamps for an absolute path.
	ReadMeta(absPath string) (*model.PlatformMeta, error)

	// ApplyMeta applies permissions, ACLs, SDDL, attributes, and ownership to an absolute path.
	ApplyMeta(absPath string, meta *model.PlatformMeta, applyPerms bool) error

	// SetTimes restores nanosecond-precision timestamps (btime, mtime, atime) on an absolute path.
	SetTimes(absPath string, btime, mtime, atime int64) error
}

// DefaultEngine returns the active platform engine for the host operating system.
var DefaultEngine = newPlatformEngine()

// MoveItem attempts an atomic rename. If os.Rename fails due to cross-device link (EXDEV),
// it falls back to recursive copy and subsequent removal of the source item.
func MoveItem(src, dst string) error {
	err := os.Rename(src, dst)
	if err == nil {
		return nil
	}

	// Check for cross-device relocation failure (EXDEV / ERROR_NOT_SAME_DEVICE)
	if isCrossDeviceError(err) {
		if copyErr := CopyDirOrFile(src, dst); copyErr != nil {
			return fmt.Errorf("cross-device copy failed from %q to %q: %w", src, dst, copyErr)
		}
		// Source removed only after verified copy completes
		if remErr := os.RemoveAll(src); remErr != nil {
			return fmt.Errorf("failed to remove source %q after cross-device copy: %w", src, remErr)
		}
		return nil
	}

	return err
}

// isCrossDeviceError detects whether an error represents a cross-filesystem or cross-volume link failure.
func isCrossDeviceError(err error) bool {
	if err == nil {
		return false
	}
	var linkErr *os.LinkError
	if errors.As(err, &linkErr) {
		err = linkErr.Err
	}

	var errno syscall.Errno
	if errors.As(err, &errno) {
		// POSIX: EXDEV is 18
		if errno == syscall.EXDEV {
			return true
		}
		// Windows: ERROR_NOT_SAME_DEVICE is 17
		const ERROR_NOT_SAME_DEVICE = syscall.Errno(17)
		if errno == ERROR_NOT_SAME_DEVICE {
			return true
		}
	}
	return false
}

// CopyDirOrFile copies a file or directory tree recursively from src to dst.
func CopyDirOrFile(src, dst string) error {
	info, err := os.Lstat(src)
	if err != nil {
		return err
	}

	if info.IsDir() {
		if err := os.MkdirAll(dst, info.Mode().Perm()); err != nil {
			return err
		}
		entries, err := os.ReadDir(src)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			srcChild := filepath.Join(src, entry.Name())
			dstChild := filepath.Join(dst, entry.Name())
			if err := CopyDirOrFile(srcChild, dstChild); err != nil {
				return err
			}
		}
		return nil
	}

	// Symlink replication
	if info.Mode()&os.ModeSymlink != 0 {
		linkTarget, err := os.Readlink(src)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
			return err
		}
		_ = os.Remove(dst)
		return os.Symlink(linkTarget, dst)
	}

	// Regular file copy
	cleanSrc := filepath.Clean(src)
	// #nosec G304 -- Source file path is an internal copy operand cleaned with filepath.Clean.
	in, err := os.Open(cleanSrc)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()

	cleanDst := filepath.Clean(dst)
	if err := os.MkdirAll(filepath.Dir(cleanDst), 0o750); err != nil {
		return err
	}

	// #nosec G304 -- Destination file path is an internal copy operand cleaned with filepath.Clean.
	out, err := os.OpenFile(cleanDst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode().Perm())
	if err != nil {
		return err
	}
	defer func() { _ = out.Close() }()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Sync()
}
