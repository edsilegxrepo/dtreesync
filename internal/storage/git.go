// Package storage provides in-memory Git commit and retrieval operations.
//
// Objectives:
//   - Enable GitOps and Infrastructure-as-Code workflows by storing filesystem snapshots in Git repositories.
//   - Execute clones, commits, tags, and pushes entirely in memory (via memfs and go-git) with zero disk footprint.
//   - Guarantee cross-platform path safety by strictly normalizing all memfs filenames to forward slashes.
//
// Core Components:
//   - IsGitURL: Determines if a destination target references a remote Git repository.
//   - GitCommitConfig: Encapsulates repository URL, branch, tag, commit author, message, and snapshot payload.
//   - CommitSnapshotToGit: Clones shallow depth=1, stages artifact in memfs, creates commit & tag, and pushes.
//   - ReadSnapshotFromGit: Pulls snapshot files from specific branches or tags into memory.
//
// Data Flow:
//
//	Snapshot Payload Bytes -> memfs File Creation -> Git Index Staging -> Commit & Tag -> Remote Push.
//	Remote Git Repo -> In-Memory Shallow Clone -> memfs File Read -> Snapshot Payload Bytes.
package storage

import (
	"context"
	"fmt"
	"io"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-git/go-billy/v5/memfs"
	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/storage/memory"
)

// IsGitURL checks if a target URL references a remote Git repository.
func IsGitURL(rawURL string) bool {
	lower := strings.ToLower(rawURL)
	return strings.HasPrefix(lower, "git://") ||
		strings.HasPrefix(lower, "git@") ||
		strings.HasPrefix(lower, "ssh://git@") ||
		(strings.HasPrefix(lower, "http://") && strings.HasSuffix(lower, ".git")) ||
		(strings.HasPrefix(lower, "https://") && strings.HasSuffix(lower, ".git"))
}

// GitCommitConfig contains options for in-memory Git snapshot commits and pushes.
type GitCommitConfig struct {
	RepoURL          string
	Branch           string
	Tag              string
	AuthorName       string
	AuthorEmail      string
	CommitMessage    string
	AuthOpts         GitAuthOptions
	SnapshotFilename string
	SnapshotData     []byte
	SkipPush         bool
}

// CommitSnapshotToGit clones a Git repository in memory, writes the snapshot file,
// creates an immutable point-in-time commit and optional tag, and pushes to remote.
func CommitSnapshotToGit(ctx context.Context, cfg GitCommitConfig) (string, error) {
	if cfg.Branch == "" {
		cfg.Branch = "main"
	}
	if cfg.AuthorName == "" {
		cfg.AuthorName = "dtreesync"
	}
	if cfg.AuthorEmail == "" {
		cfg.AuthorEmail = "dtreesync@edsilegx.internal"
	}
	if cfg.CommitMessage == "" {
		cfg.CommitMessage = fmt.Sprintf("dtreesync snapshot %s", time.Now().UTC().Format(time.RFC3339))
	}
	if cfg.SnapshotFilename == "" {
		cfg.SnapshotFilename = "tree.ndjson.zst"
	}

	isSSH := strings.HasPrefix(cfg.RepoURL, "git@") || strings.HasPrefix(cfg.RepoURL, "ssh://")
	auth, err := ResolveGitAuthContext(ctx, cfg.AuthOpts, isSSH)
	if err != nil {
		return "", fmt.Errorf("git auth resolution failed: %w", err)
	}

	fs := memfs.New()
	storer := memory.NewStorage()

	branchRef := plumbing.NewBranchReferenceName(cfg.Branch)
	r, err := git.CloneContext(ctx, storer, fs, &git.CloneOptions{
		URL:           cfg.RepoURL,
		ReferenceName: branchRef,
		SingleBranch:  true,
		Depth:         1,
		Auth:          auth,
	})
	if err != nil {
		// Try cloning default branch if specific branch wasn't found
		fs = memfs.New()
		storer = memory.NewStorage()
		r, err = git.CloneContext(ctx, storer, fs, &git.CloneOptions{
			URL:          cfg.RepoURL,
			SingleBranch: true,
			Depth:        1,
			Auth:         auth,
		})
		if err != nil {
			// If remote repo is completely empty, initialize new
			fs = memfs.New()
			storer = memory.NewStorage()
			r, err = git.Init(storer, fs)
			if err != nil {
				return "", fmt.Errorf("failed to initialize in-memory git repository: %w", err)
			}
			_, err = r.CreateRemote(&config.RemoteConfig{
				Name: "origin",
				URLs: []string{cfg.RepoURL},
			})
			if err != nil {
				return "", fmt.Errorf("failed to create remote origin: %w", err)
			}
		}
	}

	w, err := r.Worktree()
	if err != nil {
		return "", fmt.Errorf("failed to acquire git worktree: %w", err)
	}

	head, err := r.Head()
	if err == nil && head.Name() != branchRef {
		_ = w.Checkout(&git.CheckoutOptions{
			Branch: branchRef,
			Create: true,
		})
	}

	// Write snapshot data to in-memory filesystem
	cleanFile := path.Clean(filepath.ToSlash(cfg.SnapshotFilename))
	if dir := path.Dir(cleanFile); dir != "." && dir != "/" {
		_ = fs.MkdirAll(dir, 0o755)
	}
	f, err := fs.Create(cleanFile)
	if err != nil {
		return "", fmt.Errorf("failed to create snapshot file %q in memfs: %w", cleanFile, err)
	}
	if _, err := f.Write(cfg.SnapshotData); err != nil {
		_ = f.Close()
		return "", fmt.Errorf("failed to write snapshot data to memfs: %w", err)
	}
	if err := f.Close(); err != nil {
		return "", err
	}

	// Stage file
	if _, err := w.Add(cleanFile); err != nil {
		return "", fmt.Errorf("failed to add snapshot file to git index: %w", err)
	}

	// Commit
	commitHash, err := w.Commit(cfg.CommitMessage, &git.CommitOptions{
		Author: &object.Signature{
			Name:  cfg.AuthorName,
			Email: cfg.AuthorEmail,
			When:  time.Now().UTC(),
		},
	})
	if err != nil {
		return "", fmt.Errorf("failed to commit snapshot to git: %w", err)
	}

	// Tag if requested
	if cfg.Tag != "" {
		_, err = r.CreateTag(cfg.Tag, commitHash, &git.CreateTagOptions{
			Tagger: &object.Signature{
				Name:  cfg.AuthorName,
				Email: cfg.AuthorEmail,
				When:  time.Now().UTC(),
			},
			Message: fmt.Sprintf("dtreesync release tag %s", cfg.Tag),
		})
		if err != nil {
			return "", fmt.Errorf("failed to create git tag %q: %w", cfg.Tag, err)
		}
	}

	// Push to remote if requested
	if !cfg.SkipPush && cfg.RepoURL != "" {
		pushOpts := &git.PushOptions{
			RemoteName: "origin",
			Auth:       auth,
		}
		if cfg.Tag != "" {
			pushOpts.RefSpecs = []config.RefSpec{
				config.RefSpec(fmt.Sprintf("refs/heads/%s:refs/heads/%s", cfg.Branch, cfg.Branch)),
				config.RefSpec(fmt.Sprintf("refs/tags/%s:refs/tags/%s", cfg.Tag, cfg.Tag)),
			}
		}
		if err := r.PushContext(ctx, pushOpts); err != nil && err != git.NoErrAlreadyUpToDate {
			return "", fmt.Errorf("failed to push git commit to remote %q: %w", cfg.RepoURL, err)
		}
	}

	return commitHash.String(), nil
}

// ReadSnapshotFromGit pulls a snapshot file from a remote Git repository branch or tag into memory.
func ReadSnapshotFromGit(ctx context.Context, repoURL, branch, tag, filename string, authOpts GitAuthOptions) ([]byte, error) {
	if branch == "" {
		branch = "main"
	}
	if filename == "" {
		filename = "tree.ndjson.zst"
	}

	isSSH := strings.HasPrefix(repoURL, "git@") || strings.HasPrefix(repoURL, "ssh://")
	auth, err := ResolveGitAuthContext(ctx, authOpts, isSSH)
	if err != nil {
		return nil, fmt.Errorf("git auth resolution failed: %w", err)
	}

	fs := memfs.New()
	storer := memory.NewStorage()

	cloneOpts := &git.CloneOptions{
		URL:          repoURL,
		SingleBranch: true,
		Depth:        1,
		Auth:         auth,
	}
	if tag != "" {
		cloneOpts.ReferenceName = plumbing.NewTagReferenceName(tag)
	} else {
		cloneOpts.ReferenceName = plumbing.NewBranchReferenceName(branch)
	}

	_, err = git.CloneContext(ctx, storer, fs, cloneOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to clone git repository %q: %w", repoURL, err)
	}

	cleanFile := path.Clean(filepath.ToSlash(filename))
	f, err := fs.Open(cleanFile)
	if err != nil {
		return nil, fmt.Errorf("snapshot file %q not found in git repository: %w", cleanFile, err)
	}
	defer func() { _ = f.Close() }()

	return io.ReadAll(f)
}
