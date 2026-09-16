//go:build linux

// Package meta provides the Linux POSIX platform implementation.
//
// Objectives:
//   - High-throughput capture and restoration of Linux file modes, ownerships, POSIX ACLs, and SELinux contexts.
//   - Eliminate NSS/PAM/LDAP/SSSD lookup latency bottlenecks through bidirectional in-memory sync.Map caches.
//   - Eliminate heap allocations during xattr extraction using a pooled 1024-byte buffer pool (xattrBufPool).
//
// Core Components:
//   - posixEngine: Implements PlatformEngine for Linux systems.
//   - NSS Caches: Bidirectional mapping between numeric UID/GID and account names.
//   - xattrBufPool: Recycled buffer pool for system.posix_acl_* and security.selinux xattrs.
//   - extractPosixXattrs / applyPosixXattrs: Hex-encoded serialization and restoration of binary ACL and SELinux attributes.
//
// Data Flow:
//
//	POSIX Filesystem Path -> stat/xattr Syscalls -> PlatformMeta (UID/GID, Names, ACLs, SELinux) -> Engine.
package meta

import (
	"encoding/hex"
	"fmt"
	"os"
	"os/user"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/edsilegxrepo/dtreesync/internal/model"
	"golang.org/x/sys/unix"
)

var (
	uidToNameCache sync.Map // uint32 -> string
	gidToNameCache sync.Map // uint32 -> string
	nameToUIDCache sync.Map // string -> uint32
	nameToGIDCache sync.Map // string -> uint32

	xattrBufPool = sync.Pool{
		New: func() any {
			b := make([]byte, 1024)
			return &b
		},
	}
)

type posixEngine struct{}

func newPlatformEngine() PlatformEngine {
	return &posixEngine{}
}

func (e *posixEngine) InitPrivileges() error {
	// Superuser or CAP_CHOWN checks can be logged here if needed
	return nil
}

func (e *posixEngine) ReadMeta(absPath string) (*model.PlatformMeta, error) {
	fi, err := os.Lstat(absPath)
	if err != nil {
		return nil, err
	}

	stat, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, fmt.Errorf("unable to cast FileInfo.Sys() to syscall.Stat_t on %q", absPath)
	}

	uid := uint32(stat.Uid)
	gid := uint32(stat.Gid)
	mode := uint32(fi.Mode().Perm())

	meta := &model.PlatformMeta{
		UID:     &uid,
		GID:     &gid,
		Mode:    &mode,
		ModTime: fi.ModTime().UnixNano(),
	}

	// Resolve username and groupname with sync.Map caching
	meta.Username = lookupUsername(uid)
	meta.Group = lookupGroupName(gid)

	// Timestamps from Stat_t (platform specific timespec)
	extractPosixTimestamps(stat, meta)

	// Extract Linux xattrs (POSIX ACLs and SELinux)
	extractPosixXattrs(absPath, meta)

	return meta, nil
}

func (e *posixEngine) ApplyMeta(absPath string, meta *model.PlatformMeta, applyPerms bool) error {
	if meta == nil {
		return nil
	}

	// 1. Chmod
	if meta.Mode != nil {
		_ = os.Chmod(absPath, os.FileMode(*meta.Mode))
	}

	// 2. Chown (non-fatal CAP_CHOWN degradation)
	if applyPerms && (meta.UID != nil || meta.GID != nil) {
		targetUID := -1
		targetGID := -1

		// Priority 1: resolve by name if present
		if meta.Username != "" {
			if u, ok := lookupNameToUID(meta.Username); ok {
				targetUID = int(u)
			}
		}
		if targetUID == -1 && meta.UID != nil {
			targetUID = int(*meta.UID)
		}

		if meta.Group != "" {
			if g, ok := lookupNameToGID(meta.Group); ok {
				targetGID = int(g)
			}
		}
		if targetGID == -1 && meta.GID != nil {
			targetGID = int(*meta.GID)
		}

		if err := os.Chown(absPath, targetUID, targetGID); err != nil {
			// Catch EPERM / CAP_CHOWN error non-fatally
			if !isPermissionDenied(err) {
				return fmt.Errorf("chown failed on %q: %w", absPath, err)
			}
		}
	}

	// 3. Apply xattrs (ACLs and SELinux)
	if applyPerms {
		applyPosixXattrs(absPath, meta)
	}

	return nil
}

func (e *posixEngine) SetTimes(absPath string, btime, mtime, atime int64) error {
	var aTime, mTime time.Time
	if atime > 0 {
		aTime = time.Unix(0, atime)
	} else {
		aTime = time.Now()
	}

	if mtime > 0 {
		mTime = time.Unix(0, mtime)
	} else {
		mTime = time.Now()
	}

	return os.Chtimes(absPath, aTime, mTime)
}

func lookupUsername(uid uint32) string {
	if val, ok := uidToNameCache.Load(uid); ok {
		return val.(string)
	}
	u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err == nil && u != nil && u.Username != "" {
		uidToNameCache.Store(uid, u.Username)
		nameToUIDCache.Store(u.Username, uid)
		return u.Username
	}
	return ""
}

func lookupGroupName(gid uint32) string {
	if val, ok := gidToNameCache.Load(gid); ok {
		return val.(string)
	}
	g, err := user.LookupGroupId(strconv.FormatUint(uint64(gid), 10))
	if err == nil && g != nil && g.Name != "" {
		gidToNameCache.Store(gid, g.Name)
		nameToGIDCache.Store(g.Name, gid)
		return g.Name
	}
	return ""
}

func lookupNameToUID(name string) (uint32, bool) {
	if val, ok := nameToUIDCache.Load(name); ok {
		return val.(uint32), true
	}
	u, err := user.Lookup(name)
	if err == nil && u != nil {
		if parsed, err := strconv.ParseUint(u.Uid, 10, 32); err == nil {
			uid := uint32(parsed)
			nameToUIDCache.Store(name, uid)
			uidToNameCache.Store(uid, name)
			return uid, true
		}
	}
	return 0, false
}

func lookupNameToGID(name string) (uint32, bool) {
	if val, ok := nameToGIDCache.Load(name); ok {
		return val.(uint32), true
	}
	g, err := user.LookupGroup(name)
	if err == nil && g != nil {
		if parsed, err := strconv.ParseUint(g.Gid, 10, 32); err == nil {
			gid := uint32(parsed)
			nameToGIDCache.Store(name, gid)
			gidToNameCache.Store(gid, name)
			return gid, true
		}
	}
	return 0, false
}

func extractPosixXattrs(path string, meta *model.PlatformMeta) {
	bufPtr := xattrBufPool.Get().(*[]byte)
	defer xattrBufPool.Put(bufPtr)
	buf := *bufPtr

	// 1. Access ACL
	n, err := unix.Getxattr(path, "system.posix_acl_access", buf)
	if err == nil && n > 0 {
		meta.ACLAccess = hex.EncodeToString(buf[:n])
	}

	// 2. Default ACL
	n, err = unix.Getxattr(path, "system.posix_acl_default", buf)
	if err == nil && n > 0 {
		meta.ACLDefault = hex.EncodeToString(buf[:n])
	}

	// 3. SELinux Context
	n, err = unix.Getxattr(path, "security.selinux", buf)
	if err == nil && n > 0 {
		// Strip null terminator if present
		ctx := string(buf[:n])
		if len(ctx) > 0 && ctx[len(ctx)-1] == 0 {
			ctx = ctx[:len(ctx)-1]
		}
		meta.SELinuxContext = ctx
	}
}

func applyPosixXattrs(path string, meta *model.PlatformMeta) {
	if meta.ACLAccess != "" {
		if raw, err := hex.DecodeString(meta.ACLAccess); err == nil {
			_ = unix.Setxattr(path, "system.posix_acl_access", raw, 0)
		}
	}
	if meta.ACLDefault != "" {
		if raw, err := hex.DecodeString(meta.ACLDefault); err == nil {
			_ = unix.Setxattr(path, "system.posix_acl_default", raw, 0)
		}
	}
	if meta.SELinuxContext != "" {
		raw := []byte(meta.SELinuxContext + "\x00")
		_ = unix.Setxattr(path, "security.selinux", raw, 0)
	}
}

func isPermissionDenied(err error) bool {
	if err == nil {
		return false
	}
	if os.IsPermission(err) {
		return true
	}
	var errno syscall.Errno
	if ok := errorsAsErrno(err, &errno); ok {
		return errno == syscall.EPERM || errno == syscall.EACCES
	}
	return false
}

func errorsAsErrno(err error, target *syscall.Errno) bool {
	if err == nil {
		return false
	}
	if e, ok := err.(syscall.Errno); ok {
		*target = e
		return true
	}
	return false
}
