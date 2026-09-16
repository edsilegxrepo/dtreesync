// Package core implements mirror evacuation and data safety mechanisms.
//
// Objectives:
//   - Prevent irreversible data loss during mirror-mode directory synchronization.
//   - Safely package unexpected files and directory subtrees into a compressed .tar.zst archive.
//   - Guarantee recursive packaging of all nested child items before source directory purging.
//
// Core Components:
//   - EvacuateUntracked: Orchestrates the creation of a timestamped evacuation archive (.tar.zst) and safe removal.
//   - addFileToTar: Low-level tar serializer with recursive child directory walking and content streaming.
//   - MoveUntrackedDirect: Relocates untracked items directly across filesystem mounts using meta.MoveItem.
//
// Data Flow:
//
//	Live Target Folder -> Untracked Path Discovery -> Tar Header & Body Serializer -> Zstandard Compressor
//	-> Evacuation Archive File (.tar.zst) -> os.RemoveAll() on Source Path.
package core

import (
	"archive/tar"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/edsilegxrepo/dtreesync/internal/format"
	"github.com/edsilegxrepo/dtreesync/internal/meta"
	"github.com/edsilegxrepo/dtreesync/internal/model"
)

// EvacuateUntracked relocates unexpected files and directories found in mirror mode to an archive .tar.zst container.
func EvacuateUntracked(
	ctx context.Context,
	targetFolder, archiveFolder string,
	untrackedPaths []string,
	al *model.AuditLogger,
) (string, error) {
	if len(untrackedPaths) == 0 {
		return "", nil
	}

	cleanTarget, err := model.ValidateAndCleanPath(targetFolder)
	if err != nil {
		return "", fmt.Errorf("target folder invalid: %w", err)
	}

	cleanArchive, err := model.ValidateAndCleanPath(archiveFolder)
	if err != nil {
		return "", fmt.Errorf("archive folder invalid: %w", err)
	}

	if err := os.MkdirAll(cleanArchive, 0o750); err != nil {
		return "", fmt.Errorf("failed to create archive destination directory: %w", err)
	}

	// Archive filename: dtreesync_<timestamp>.tar.zst
	timestampStr := time.Now().UTC().Format("20060102T150405Z")
	archiveFile := filepath.Join(cleanArchive, fmt.Sprintf("dtreesync_%s.tar.zst", timestampStr))

	// #nosec G304 -- Archive file path is generated within validated and cleaned directory.
	outFile, err := os.OpenFile(archiveFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return "", fmt.Errorf("failed to create evacuation archive file %q: %w", archiveFile, err)
	}
	defer func() { _ = outFile.Close() }()

	zstdEnc, err := format.NewZstdWriter(outFile, 4)
	if err != nil {
		return "", fmt.Errorf("failed to create zstd compressor for evacuation: %w", err)
	}
	defer func() { _ = zstdEnc.Close() }()

	tarWriter := tar.NewWriter(zstdEnc)
	defer func() { _ = tarWriter.Close() }()

	// Pack untracked paths into tar archive, then safely remove them
	for _, relPath := range untrackedPaths {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}

		itemAbs := filepath.Join(cleanTarget, filepath.FromSlash(relPath))
		info, err := os.Lstat(itemAbs)
		if err != nil {
			continue // Already removed or inaccessible
		}

		if err := addFileToTar(tarWriter, itemAbs, relPath, info); err != nil {
			return "", fmt.Errorf("failed to pack %q into evacuation archive: %w", itemAbs, err)
		}

		// Remove from live target folder
		if err := os.RemoveAll(itemAbs); err != nil {
			// If permission issue, log warning
			if al != nil {
				al.LogWarn("mirror", "evacuate_remove_failed", itemAbs, err.Error(), nil)
			}
		} else if al != nil {
			al.LogInfo("mirror", "evacuated", itemAbs, map[string]any{
				"archive_tar": archiveFile,
				"action":      "relocated_and_purged",
			})
		}
	}

	if err := tarWriter.Close(); err != nil {
		return "", err
	}
	if err := zstdEnc.Close(); err != nil {
		return "", err
	}

	return archiveFile, nil
}

// addFileToTar serializes a single file, symlink, or recursively walks and archives
// an entire directory subtree into the target tar.Writer with normalized portable forward slashes.
func addFileToTar(tw *tar.Writer, absPath, relPath string, info os.FileInfo) error {
	linkTarget := ""
	if info.Mode()&os.ModeSymlink != 0 {
		var err error
		linkTarget, err = os.Readlink(absPath)
		if err != nil {
			return err
		}
	}

	header, err := tar.FileInfoHeader(info, linkTarget)
	if err != nil {
		return err
	}
	header.Name = strings.ReplaceAll(relPath, "\\", "/")
	if info.IsDir() && !strings.HasSuffix(header.Name, "/") {
		header.Name += "/"
	}

	if err := tw.WriteHeader(header); err != nil {
		return err
	}

	// Symlinks in tar only have header with Linkname, zero body bytes
	if info.Mode()&os.ModeSymlink != 0 {
		return nil
	}

	if !info.IsDir() {
		cleanAbs := filepath.Clean(absPath)
		// #nosec G304 -- File path is verified untracked item located within target root.
		file, err := os.Open(cleanAbs)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(tw, file)
		closeErr := file.Close()
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	}

	// Recursively archive nested items within untracked directory before removal
	return filepath.WalkDir(absPath, func(subAbs string, d os.DirEntry, walkErr error) error {
		if walkErr != nil || subAbs == absPath {
			return walkErr
		}

		relChild, err := filepath.Rel(absPath, subAbs)
		if err != nil {
			return err
		}
		tarChildPath := strings.ReplaceAll(relPath+"/"+filepath.ToSlash(relChild), "\\", "/")

		childInfo, err := d.Info()
		if err != nil {
			return err
		}

		childLinkTarget := ""
		if childInfo.Mode()&os.ModeSymlink != 0 {
			var err error
			childLinkTarget, err = os.Readlink(subAbs)
			if err != nil {
				return err
			}
		}

		childHdr, err := tar.FileInfoHeader(childInfo, childLinkTarget)
		if err != nil {
			return err
		}
		childHdr.Name = tarChildPath
		if d.IsDir() && !strings.HasSuffix(childHdr.Name, "/") {
			childHdr.Name += "/"
		}

		if err := tw.WriteHeader(childHdr); err != nil {
			return err
		}

		if d.IsDir() || childInfo.Mode()&os.ModeSymlink != 0 {
			return nil
		}

		cleanSub := filepath.Clean(subAbs)
		// #nosec G122,G304 -- Symlinks are filtered above at line 198; target file is non-symlink within validated archive walk.
		childFile, err := os.Open(cleanSub)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(tw, childFile)
		closeErr := childFile.Close()
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	})
}

// MoveUntrackedDirect relocates untracked items to a directory tree preserving hierarchy.
func MoveUntrackedDirect(srcAbs, dstAbs string) error {
	return meta.MoveItem(srcAbs, dstAbs)
}
