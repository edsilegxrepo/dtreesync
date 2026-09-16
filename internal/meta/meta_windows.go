//go:build windows

// Package meta provides the Windows NTFS platform implementation.
//
// Objectives:
//   - Acquire NT privileges (SeBackupPrivilege, SeRestorePrivilege, SeSecurityPrivilege) to bypass file locks and ACL blocks.
//   - Extract and restore NTFS Security Descriptors (SDDL), Win32 file attributes, and nanosecond timestamps (including btime).
//   - Maximize performance using extended namespaces (\\?\) and an in-memory Active Directory SID-to-name sync.Map cache.
//
// Core Components:
//   - sidToNameCache: Thread-safe cache preventing repetitive LSA/Active Directory RPC queries during scans.
//   - InitPrivileges: Adjusts process access token privileges at engine startup.
//   - ReadMeta / ApplyMeta: Interacts with Win32 APIs (GetNamedSecurityInfo, SetNamedSecurityInfo, GetFileAttributes).
//   - SetTimes: Updates FILE_FLAG_BACKUP_SEMANTICS handle timestamps with nanosecond precision.
//
// Data Flow:
//
//	NTFS Path -> Extended Path Prefix (\\?\) -> Win32 API -> PlatformMeta (SDDL, SID, Attrs, Timestamps) -> Engine.
package meta

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"syscall"

	"github.com/edsilegxrepo/dtreesync/internal/model"
	"golang.org/x/sys/windows"
)

var sidToNameCache sync.Map // string -> string

func lookupSIDAccount(sid *windows.SID) (string, string) {
	sidStr := sid.String()
	if val, ok := sidToNameCache.Load(sidStr); ok {
		return sidStr, val.(string)
	}
	account, domain, _, err := sid.LookupAccount("")
	if err == nil {
		fullName := account
		if domain != "" {
			fullName = domain + `\` + account
		}
		sidToNameCache.Store(sidStr, fullName)
		return sidStr, fullName
	}
	return sidStr, ""
}

const (
	secInfoAll = windows.OWNER_SECURITY_INFORMATION |
		windows.GROUP_SECURITY_INFORMATION |
		windows.DACL_SECURITY_INFORMATION
)

type windowsEngine struct{}

func newPlatformEngine() PlatformEngine {
	return &windowsEngine{}
}

// InitPrivileges elevates the current process token with SeBackupPrivilege,
// SeRestorePrivilege, and SeSecurityPrivilege.
func (e *windowsEngine) InitPrivileges() error {
	privileges := []string{
		"SeBackupPrivilege",
		"SeRestorePrivilege",
		"SeSecurityPrivilege",
	}

	var token windows.Token
	err := windows.OpenProcessToken(
		windows.CurrentProcess(),
		windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY,
		&token,
	)
	if err != nil {
		return fmt.Errorf("failed to open process token: %w", err)
	}
	defer func() { _ = token.Close() }()

	for _, privName := range privileges {
		var luid windows.LUID
		privPtr, err := windows.UTF16PtrFromString(privName)
		if err != nil {
			continue
		}
		if err := windows.LookupPrivilegeValue(nil, privPtr, &luid); err != nil {
			continue
		}

		tp := windows.Tokenprivileges{
			PrivilegeCount: 1,
			Privileges: [1]windows.LUIDAndAttributes{
				{
					Luid:       luid,
					Attributes: windows.SE_PRIVILEGE_ENABLED,
				},
			},
		}

		_ = windows.AdjustTokenPrivileges(token, false, &tp, 0, nil, nil)
	}

	return nil
}

// ReadMeta extracts Windows NTFS attributes, SDDL security descriptors, and nanosecond timestamps.
func (e *windowsEngine) ReadMeta(absPath string) (*model.PlatformMeta, error) {
	extPath := model.ToExtendedWindowsPath(absPath)
	pathPtr, err := windows.UTF16PtrFromString(extPath)
	if err != nil {
		return nil, fmt.Errorf("invalid path for utf16: %w", err)
	}

	meta := &model.PlatformMeta{}

	// 1. Win32 File Attributes
	rawAttrs, err := windows.GetFileAttributes(pathPtr)
	if err == nil && rawAttrs != windows.INVALID_FILE_ATTRIBUTES {
		// Mask out FILE_ATTRIBUTE_DIRECTORY to capture non-inherited attributes
		cleanAttrs := rawAttrs &^ windows.FILE_ATTRIBUTE_DIRECTORY
		meta.FileAttributes = &cleanAttrs
	}

	// 2. Timestamps via GetFileTime
	h, err := windows.CreateFile(
		pathPtr,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if err == nil {
		var cTime, aTime, wTime windows.Filetime
		if err := windows.GetFileTime(h, &cTime, &aTime, &wTime); err == nil {
			meta.BirthTime = cTime.Nanoseconds()
			meta.AccessTime = aTime.Nanoseconds()
			meta.ModTime = wTime.Nanoseconds()
			meta.ChangeTime = wTime.Nanoseconds()
		}
		_ = windows.CloseHandle(h)
	}

	// 3. SDDL and Owner/Group SID extraction via GetNamedSecurityInfo
	sd, err := windows.GetNamedSecurityInfo(extPath, windows.SE_FILE_OBJECT, secInfoAll)
	if err == nil && sd != nil {
		meta.SDDL = sd.String()

		if owner, _, err := sd.Owner(); err == nil && owner != nil {
			meta.OwnerSID, meta.OwnerName = lookupSIDAccount(owner)
		}

		if group, _, err := sd.Group(); err == nil && group != nil {
			meta.GroupSID, meta.GroupName = lookupSIDAccount(group)
		}
	}

	return meta, nil
}

// ApplyMeta applies attributes, SDDL permissions, and ownership on Windows.
func (e *windowsEngine) ApplyMeta(absPath string, meta *model.PlatformMeta, applyPerms bool) error {
	if meta == nil {
		return nil
	}

	extPath := model.ToExtendedWindowsPath(absPath)
	pathPtr, err := windows.UTF16PtrFromString(extPath)
	if err != nil {
		return fmt.Errorf("invalid path for utf16: %w", err)
	}

	// 1. Apply Win32 File Attributes
	if meta.FileAttributes != nil {
		attrs := *meta.FileAttributes | windows.FILE_ATTRIBUTE_DIRECTORY
		_ = windows.SetFileAttributes(pathPtr, attrs)
	}

	// 2. Apply SDDL Security Descriptor
	if applyPerms && meta.SDDL != "" {
		sd, err := windows.SecurityDescriptorFromString(meta.SDDL)
		if err == nil && sd != nil {
			secFlags := windows.DACL_SECURITY_INFORMATION

			owner, _, _ := sd.Owner()
			if owner != nil {
				secFlags |= windows.OWNER_SECURITY_INFORMATION
			} else if meta.OwnerSID != "" {
				if sid, err := windows.StringToSid(meta.OwnerSID); err == nil {
					owner = sid
					secFlags |= windows.OWNER_SECURITY_INFORMATION
				}
			}

			group, _, _ := sd.Group()
			if group != nil {
				secFlags |= windows.GROUP_SECURITY_INFORMATION
			} else if meta.GroupSID != "" {
				if sid, err := windows.StringToSid(meta.GroupSID); err == nil {
					group = sid
					secFlags |= windows.GROUP_SECURITY_INFORMATION
				}
			}

			dacl, _, _ := sd.DACL()

			// Check if SDDL contains protected DACL (D:P)
			if strings.Contains(meta.SDDL, "D:P") {
				secFlags |= windows.PROTECTED_DACL_SECURITY_INFORMATION
			}

			setErr := windows.SetNamedSecurityInfo(
				extPath,
				windows.SE_FILE_OBJECT,
				windows.SECURITY_INFORMATION(secFlags),
				owner,
				group,
				dacl,
				nil,
			)
			if setErr != nil && !isPrivilegeError(setErr) {
				return fmt.Errorf("failed to apply SDDL on %q: %w", absPath, setErr)
			}
		}
	}

	return nil
}

// SetTimes restores nanosecond-precision timestamps on Windows NTFS (btime, mtime, atime).
func (e *windowsEngine) SetTimes(absPath string, btime, mtime, atime int64) error {
	extPath := model.ToExtendedWindowsPath(absPath)
	pathPtr, err := windows.UTF16PtrFromString(extPath)
	if err != nil {
		return err
	}

	h, err := windows.CreateFile(
		pathPtr,
		windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if err != nil {
		return fmt.Errorf("failed to open handle for SetFileTime on %q: %w", absPath, err)
	}
	defer func() { _ = windows.CloseHandle(h) }()

	var (
		cTimePtr *windows.Filetime
		aTimePtr *windows.Filetime
		wTimePtr *windows.Filetime
	)

	if btime > 0 {
		c := windows.NsecToFiletime(btime)
		cTimePtr = &c
	}
	if atime > 0 {
		a := windows.NsecToFiletime(atime)
		aTimePtr = &a
	}
	if mtime > 0 {
		w := windows.NsecToFiletime(mtime)
		wTimePtr = &w
	}

	return windows.SetFileTime(h, cTimePtr, aTimePtr, wTimePtr)
}

func isPrivilegeError(err error) bool {
	if err == nil {
		return false
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		// ERROR_ACCESS_DENIED (5), ERROR_PRIVILEGE_NOT_HELD (1314)
		return errno == 5 || errno == 1314
	}
	return false
}
