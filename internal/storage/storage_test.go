// Package storage provides unit and integration tests for storage drivers and cloud transports.
//
// Objectives:
//   - Verify scheme detection, URI parsing, and bucket/key extraction for cloud and Git targets.
//   - Test streaming read and write pipelines against blob storage (using local fileblob driver).
//   - Validate end-to-end in-memory Git commits, branch checkout, tagging, and remote artifact reads.
//
// Test Strategy:
//   - Scheme Validation: TestCloudURL_Parsing and TestGitURL_Detection verify URL recognition across S3, GCS,
//     Azure Blob, HTTPS, SSH, and fileblob formats.
//   - Direct Blob Streaming: TestCloudBlob_FileDriverRoundtrip executes live streaming writes via NewCloudWriter,
//     reads back via NewCloudReader, and asserts byte-for-byte equality.
//   - In-Memory GitOps: TestGit_CommitAndReadRoundtrip creates a bare repository fixture, writes a snapshot via
//     memfs, creates a signed tag, pushes to remote, and verifies extraction via ReadSnapshotFromGit.
//
// Data Flow:
//
//	Test Fixture -> NewCloudWriter / CommitSnapshotToGit -> Fileblob / Bare Git Repo -> NewCloudReader / ReadSnapshotFromGit -> Assertions.
package storage

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/edsilegxrepo/secretprotector/pkg/libsecsecrets"
	git "github.com/go-git/go-git/v5"
	gitconfig "github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing/object"
)

func TestCloudURL_Parsing(t *testing.T) {
	tests := []struct {
		url       string
		isCloud   bool
		bucketURL string
		key       string
		wantErr   bool
	}{
		{
			url:       "s3://my-backup-bucket/tree_2026.tsv.zst",
			isCloud:   true,
			bucketURL: "s3://my-backup-bucket",
			key:       "tree_2026.tsv.zst",
			wantErr:   false,
		},
		{
			url:       "gs://production-backups/daily/snapshot.ndjson",
			isCloud:   true,
			bucketURL: "gs://production-backups",
			key:       "daily/snapshot.ndjson",
			wantErr:   false,
		},
		{
			url:       "azblob://company-container/archives/tree.sqlite",
			isCloud:   true,
			bucketURL: "azblob://company-container",
			key:       "archives/tree.sqlite",
			wantErr:   false,
		},
		{
			url:     "ftp://server.example.com/tree.tsv",
			isCloud: false,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		if got := IsCloudURL(tt.url); got != tt.isCloud {
			t.Errorf("IsCloudURL(%q) = %v; want %v", tt.url, got, tt.isCloud)
		}
		bURL, key, err := ParseCloudURL(tt.url)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParseCloudURL(%q) error = %v; wantErr %v", tt.url, err, tt.wantErr)
			continue
		}
		if !tt.wantErr {
			if bURL != tt.bucketURL {
				t.Errorf("ParseCloudURL(%q) bucketURL = %q; want %q", tt.url, bURL, tt.bucketURL)
			}
			if key != tt.key {
				t.Errorf("ParseCloudURL(%q) key = %q; want %q", tt.url, key, tt.key)
			}
		}
	}
}

func TestGitURL_Detection(t *testing.T) {
	valid := []string{
		"git@github.com:edsilegxrepo/dtreesync.git",
		"ssh://git@github.com/edsilegxrepo/dtreesync.git",
		"https://github.com/edsilegxrepo/dtreesync.git",
		"git://github.com/edsilegxrepo/dtreesync.git",
	}
	for _, u := range valid {
		if !IsGitURL(u) {
			t.Errorf("Expected IsGitURL(%q) to be true", u)
		}
	}

	invalid := []string{
		"s3://bucket/key",
		"https://example.com/archive.tar.gz",
		"/var/local/tree.tsv",
	}
	for _, u := range invalid {
		if IsGitURL(u) {
			t.Errorf("Expected IsGitURL(%q) to be false", u)
		}
	}
}

func TestCloudBlob_FileDriverRoundtrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tmpDir := t.TempDir()
	bucketDir := filepath.Join(tmpDir, "bucket")
	if err := os.MkdirAll(bucketDir, 0o755); err != nil {
		t.Fatalf("Failed to create bucket dir: %v", err)
	}

	// Normalized forward slash path for fileblob URL
	cleanBucketDir := filepath.ToSlash(bucketDir)
	if !strings.HasPrefix(cleanBucketDir, "/") {
		cleanBucketDir = "/" + cleanBucketDir
	}
	fileURL := "file://" + cleanBucketDir + "/test_snapshot.ndjson"

	// 1. Write via CloudWriter
	cw, err := NewCloudWriter(ctx, fileURL)
	if err != nil {
		t.Fatalf("NewCloudWriter failed: %v", err)
	}
	testData := []byte("{\"_meta\":{\"version\":\"2.0\"}}\n")
	if _, err := cw.Write(testData); err != nil {
		t.Fatalf("CloudWriter Write failed: %v", err)
	}
	if err := cw.Close(); err != nil {
		t.Fatalf("CloudWriter Close failed: %v", err)
	}

	// 2. Read via CloudReader
	cr, err := NewCloudReader(ctx, fileURL)
	if err != nil {
		t.Fatalf("NewCloudReader failed: %v", err)
	}
	gotData, err := io.ReadAll(cr)
	if err != nil {
		t.Fatalf("CloudReader Read failed: %v", err)
	}
	if err := cr.Close(); err != nil {
		t.Fatalf("CloudReader Close failed: %v", err)
	}

	if !bytes.Equal(gotData, testData) {
		t.Errorf("Data mismatch: got %q, want %q", string(gotData), string(testData))
	}
}

func TestGit_CommitAndReadRoundtrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Ensure git-receive-pack is discoverable on Windows test environments
	for _, p := range []string{`d:\dev\git\cmd`, `d:\dev\git\mingw64\bin`} {
		if fi, err := os.Stat(p); err == nil && fi.IsDir() {
			t.Setenv("PATH", os.Getenv("PATH")+string(os.PathListSeparator)+p)
		}
	}

	// Create a bare git repository on local disk to serve as remote
	tmpDir := t.TempDir()
	bareRepoDir := filepath.Join(tmpDir, "remote.git")
	r, err := git.PlainInit(bareRepoDir, true)
	if err != nil {
		t.Fatalf("Failed to init bare repo: %v", err)
	}

	// Seed initial commit so HEAD points to main
	workDir := filepath.Join(tmpDir, "seed")
	seedRepo, err := git.PlainInit(workDir, false)
	if err != nil {
		t.Fatalf("Failed to init seed repo: %v", err)
	}
	seedFile := filepath.Join(workDir, "README.md")
	if err := os.WriteFile(seedFile, []byte("seed"), 0o644); err != nil {
		t.Fatalf("Failed to write seed file: %v", err)
	}
	w, err := seedRepo.Worktree()
	if err != nil {
		t.Fatalf("Failed to get worktree: %v", err)
	}
	if _, err := w.Add("README.md"); err != nil {
		t.Fatalf("Failed to add seed file: %v", err)
	}
	commit, err := w.Commit("Initial commit", &git.CommitOptions{
		Author: &object.Signature{
			Name:  "Test",
			Email: "test@example.com",
			When:  time.Now(),
		},
	})
	if err != nil {
		t.Fatalf("Failed to commit seed: %v", err)
	}
	_ = commit

	// Push initial commit to bare repo as main
	_, err = seedRepo.CreateRemote(&gitconfig.RemoteConfig{
		Name: "origin",
		URLs: []string{filepath.ToSlash(bareRepoDir)},
	})
	if err == nil {
		_ = seedRepo.Push(&git.PushOptions{
			RemoteName: "origin",
			RefSpecs:   []gitconfig.RefSpec{"refs/heads/master:refs/heads/main"},
		})
	}
	_ = r

	remoteURL := filepath.ToSlash(bareRepoDir)
	snapshotPayload := []byte("#META:{\"version\":\"2.0\"}\nentity\trel_path\n")

	commitHash, err := CommitSnapshotToGit(ctx, GitCommitConfig{
		RepoURL:          remoteURL,
		Branch:           "main",
		Tag:              "v1.0.0",
		SnapshotFilename: "tree.tsv",
		SnapshotData:     snapshotPayload,
	})
	if err != nil {
		t.Fatalf("CommitSnapshotToGit failed: %v", err)
	}
	if commitHash == "" {
		t.Fatalf("Expected non-empty commit hash")
	}

	// Read snapshot back from Git via tag
	readData, err := ReadSnapshotFromGit(ctx, remoteURL, "main", "v1.0.0", "tree.tsv", GitAuthOptions{})
	if err != nil {
		t.Fatalf("ReadSnapshotFromGit failed: %v", err)
	}
	if !bytes.Equal(readData, snapshotPayload) {
		t.Errorf("Git roundtrip mismatch: got %q, want %q", string(readData), string(snapshotPayload))
	}
}

func TestResolveGitAuth(t *testing.T) {
	ctx := context.Background()

	// 1. HTTPS Auth with explicit username and password
	auth, err := ResolveGitAuthContext(ctx, GitAuthOptions{
		Username: "alice",
		Password: "plain_password_123",
	}, false)
	if err != nil {
		t.Fatalf("ResolveGitAuthContext HTTPS failed: %v", err)
	}
	if auth == nil {
		t.Fatal("expected non-nil auth for HTTPS")
	}

	// 2. HTTPS Auth with GIT_TOKEN env
	t.Setenv("GIT_TOKEN", "mock_env_token")
	authEnv, err := ResolveGitAuthContext(ctx, GitAuthOptions{}, false)
	if err != nil {
		t.Fatalf("ResolveGitAuthContext with GIT_TOKEN failed: %v", err)
	}
	if authEnv == nil {
		t.Fatal("expected non-nil auth for GIT_TOKEN")
	}

	// 3. HTTPS Auth with no credentials
	t.Setenv("GIT_TOKEN", "")
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GITLAB_TOKEN", "")
	authNone, err := ResolveGitAuthContext(ctx, GitAuthOptions{}, false)
	if err != nil || authNone != nil {
		t.Fatalf("expected nil auth without credentials, got %v (err: %v)", authNone, err)
	}

	// 4. GITHUB_TOKEN fallback
	t.Setenv("GITHUB_TOKEN", "mock_gh_token")
	authGH, err := ResolveGitAuthContext(ctx, GitAuthOptions{}, false)
	if err != nil || authGH == nil {
		t.Fatalf("expected auth for GITHUB_TOKEN, got %v (err: %v)", authGH, err)
	}

	// 5. GITLAB_TOKEN fallback
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GITLAB_TOKEN", "mock_gl_token")
	authGL, err := ResolveGitAuthContext(ctx, GitAuthOptions{}, false)
	if err != nil || authGL == nil {
		t.Fatalf("expected auth for GITLAB_TOKEN, got %v (err: %v)", authGL, err)
	}

	// 6. SSH Auth with non-existent key file
	_, err = ResolveGitAuthContext(ctx, GitAuthOptions{
		SSHKeyPath: filepath.Join(t.TempDir(), "nonexistent_key"),
	}, true)
	if err == nil {
		t.Fatal("expected error for non-existent SSH key file")
	}

	// 7. Public ResolveGitAuth wrapper
	_, _ = ResolveGitAuth(GitAuthOptions{Username: "test"}, false)
}

func TestCloudStreaming_ErrorCases(t *testing.T) {
	ctx := context.Background()

	// Invalid Cloud Writer URLs
	invalidURLs := []string{
		"http://example.com/file",
		"ftp://host/bucket/file",
		"s3:///missing_bucket",
		"s3://bucket_only_no_key",
		"gs:///missing_bucket",
		"gs://bucket_only_no_key",
		"azblob:///missing_bucket",
		"azblob://bucket_only_no_key",
		"file:///",
		"file:///nodir",
	}
	for _, u := range invalidURLs {
		if _, err := NewCloudWriter(ctx, u); err == nil {
			t.Errorf("expected NewCloudWriter error for %q", u)
		}
		if _, err := NewCloudReader(ctx, u); err == nil {
			t.Errorf("expected NewCloudReader error for %q", u)
		}
	}
}

func TestResolveGitAuth_EncryptedSecret(t *testing.T) {
	ctx := context.Background()
	masterKey := []byte("01234567890123456789012345678901") // 32 bytes
	masterKeyHex := hex.EncodeToString(masterKey)

	encToken, err := libsecsecrets.Encrypt(ctx, "ghp_my_secret_token", masterKey)
	if err != nil {
		t.Fatalf("EncryptString failed: %v", err)
	}

	auth, err := ResolveGitAuthContext(ctx, GitAuthOptions{
		Password:  encToken,
		MasterKey: masterKeyHex,
	}, false)
	if err != nil {
		t.Fatalf("ResolveGitAuthContext with encrypted token failed: %v", err)
	}
	if auth == nil {
		t.Fatal("expected non-nil BasicAuth for decrypted token")
	}

	// Bad master key returns error
	badKeyHex := hex.EncodeToString([]byte("badbadbadbadbadbadbadbadbadbadba"))
	_, err = ResolveGitAuthContext(ctx, GitAuthOptions{
		Password:  encToken,
		MasterKey: badKeyHex,
	}, false)
	if err == nil {
		t.Fatal("expected error with bad master key")
	}
}

func TestCloudStreaming_WithKey(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tmpDir := t.TempDir()
	bucketDir := filepath.Join(tmpDir, "key_bucket")
	_ = os.MkdirAll(bucketDir, 0o755)

	cleanBucketDir := filepath.ToSlash(bucketDir)
	if !strings.HasPrefix(cleanBucketDir, "/") {
		cleanBucketDir = "/" + cleanBucketDir
	}
	fileURL := "file://" + cleanBucketDir + "/key_snapshot.ndjson"

	masterKey := []byte("01234567890123456789012345678901")

	// Writer with key
	cw, err := NewCloudWriterWithKey(ctx, fileURL, masterKey)
	if err != nil {
		t.Fatalf("NewCloudWriterWithKey failed: %v", err)
	}
	testData := []byte("payload with master key\n")
	if _, err := cw.Write(testData); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	if err := cw.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}

	// Reader with key
	cr, err := NewCloudReaderWithKey(ctx, fileURL, masterKey)
	if err != nil {
		t.Fatalf("NewCloudReaderWithKey failed: %v", err)
	}
	gotData, err := io.ReadAll(cr)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if err := cr.Close(); err != nil {
		t.Fatalf("reader close failed: %v", err)
	}
	if !bytes.Equal(gotData, testData) {
		t.Fatalf("data mismatch: got %q, want %q", string(gotData), string(testData))
	}
}

func TestProtectedSecret_EdgeCases(t *testing.T) {
	// 1. Nil safety
	var nilPS *ProtectedSecret
	if _, err := nilPS.Reveal(); err == nil {
		t.Fatal("expected error on nilPS.Reveal()")
	}
	nilPS.Destroy() // should not panic

	// 2. Lifecycle and Destroy
	ps, err := NewProtectedSecret("confidential_credential")
	if err != nil {
		t.Fatalf("NewProtectedSecret failed: %v", err)
	}
	revealed, err := ps.Reveal()
	if err != nil || string(revealed) != "confidential_credential" {
		t.Fatalf("Reveal failed or mismatch: %s (err: %v)", string(revealed), err)
	}
	libsecsecrets.ZeroBuffer(revealed)

	ps.Destroy()
	// Reveal after Destroy should error
	if _, err := ps.Reveal(); err == nil {
		t.Fatal("expected error revealing destroyed secret")
	}
	// Second Destroy should be safe
	ps.Destroy()
}

func TestDecryptSecretBytes_EdgeCases(t *testing.T) {
	ctx := context.Background()

	// 1. Empty/nil data
	res, err := DecryptSecretBytes(ctx, nil, nil)
	if err != nil || res != nil {
		t.Fatalf("expected nil for nil input, got %v", res)
	}

	// 2. Plaintext bytes (not encrypted)
	plain := []byte("plain text data")
	res, err = DecryptSecretBytes(ctx, plain, nil)
	if err != nil || !bytes.Equal(res, plain) {
		t.Fatalf("expected unchanged plain bytes, got %s", string(res))
	}

	// 3. Encrypted bytes without 32-byte master key
	masterKey := []byte("01234567890123456789012345678901")
	encBytes, err := libsecsecrets.EncryptBytes(ctx, plain, masterKey)
	if err != nil {
		t.Fatalf("EncryptBytes failed: %v", err)
	}
	if _, err := DecryptSecretBytes(ctx, encBytes, []byte("short_key")); err == nil {
		t.Fatal("expected error with invalid master key length")
	}

	// 4. Encrypted bytes with correct master key
	dec, err := DecryptSecretBytes(ctx, encBytes, masterKey)
	if err != nil || !bytes.Equal(dec, plain) {
		t.Fatalf("expected successful decryption, got %s (err: %v)", string(dec), err)
	}
}

func TestGit_ErrorBranches(t *testing.T) {
	ctx := context.Background()

	// 1. Commit to invalid Git URL
	_, err := CommitSnapshotToGit(ctx, GitCommitConfig{
		RepoURL:          "http://invalid.local/repo.git",
		SnapshotData:     []byte("test"),
		SnapshotFilename: "tree.tsv",
	})
	if err == nil {
		t.Fatal("expected error committing to invalid repo URL")
	}

	// 2. Read from invalid Git URL
	_, err = ReadSnapshotFromGit(ctx, "http://invalid.local/repo.git", "main", "v1.0.0", "tree.tsv", GitAuthOptions{})
	if err == nil {
		t.Fatal("expected error reading from invalid repo URL")
	}
}

func TestPrepareCloudAuth_FullDecryptionLifecycle(t *testing.T) {
	ctx := context.Background()
	masterKey := []byte("01234567890123456789012345678901")

	// 1. Encrypted AWS_SECRET_ACCESS_KEY and AZURE_STORAGE_KEY
	rawAWS := "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	encAWS, err := libsecsecrets.Encrypt(ctx, rawAWS, masterKey)
	if err != nil {
		t.Fatalf("Encrypt AWS failed: %v", err)
	}
	t.Setenv("AWS_SECRET_ACCESS_KEY", encAWS)

	rawAzure := "mock_azure_account_key"
	encAzure, err := libsecsecrets.Encrypt(ctx, rawAzure, masterKey)
	if err != nil {
		t.Fatalf("Encrypt Azure failed: %v", err)
	}
	t.Setenv("AZURE_STORAGE_KEY", encAzure)

	// Set master key via env to test automatic master key resolution in PrepareCloudAuth
	t.Setenv("SECRETPROTECTOR_MASTER_KEY", hex.EncodeToString(masterKey))

	// 2. Encrypted GCP service account file
	tmpDir := t.TempDir()
	rawGCP := []byte(`{"type":"service_account","project_id":"my-project"}`)
	encGCPBytes, err := libsecsecrets.EncryptBytes(ctx, rawGCP, masterKey)
	if err != nil {
		t.Fatalf("EncryptBytes GCP failed: %v", err)
	}
	gcpFile := filepath.Join(tmpDir, "gcp_enc.json")
	if err := os.WriteFile(gcpFile, encGCPBytes, 0o600); err != nil {
		t.Fatalf("write GCP file failed: %v", err)
	}
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", gcpFile)

	// Execute PrepareCloudAuth passing nil for masterKey to test env resolution
	cleanup, err := PrepareCloudAuth(ctx, nil)
	if err != nil {
		t.Fatalf("PrepareCloudAuth failed: %v", err)
	}

	// Verify decrypted environment variables
	if os.Getenv("AWS_SECRET_ACCESS_KEY") != rawAWS {
		t.Fatalf("AWS key not decrypted: got %s", os.Getenv("AWS_SECRET_ACCESS_KEY"))
	}
	if os.Getenv("AZURE_STORAGE_KEY") != rawAzure {
		t.Fatalf("Azure key not decrypted: got %s", os.Getenv("AZURE_STORAGE_KEY"))
	}
	decGCPFile := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")
	if decGCPFile == gcpFile || decGCPFile == "" {
		t.Fatalf("expected decrypted temp file for GCP credentials, got %s", decGCPFile)
	}
	decData, err := os.ReadFile(decGCPFile)
	if err != nil || !bytes.Equal(decData, rawGCP) {
		t.Fatalf("GCP credential file content mismatch: %s (err: %v)", string(decData), err)
	}

	// Execute cleanup
	cleanup()

	// Verify environment variables restored
	if os.Getenv("AWS_SECRET_ACCESS_KEY") != encAWS {
		t.Fatalf("expected AWS env restored to encrypted value, got %s", os.Getenv("AWS_SECRET_ACCESS_KEY"))
	}
	if os.Getenv("GOOGLE_APPLICATION_CREDENTIALS") != gcpFile {
		t.Fatalf("expected GCP env restored, got %s", os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"))
	}
	// Verify temp file was wiped and deleted
	if _, err := os.Stat(decGCPFile); !os.IsNotExist(err) {
		t.Fatalf("expected temp decrypted GCP file to be deleted after cleanup, got err: %v", err)
	}
}

func TestGit_BranchReadAndNestedPath(t *testing.T) {
	ctx := context.Background()

	tmpDir := t.TempDir()
	bareRepoDir := filepath.Join(tmpDir, "bare.git")
	_, err := git.PlainInit(bareRepoDir, true)
	if err != nil {
		t.Fatalf("Failed to init bare repo: %v", err)
	}

	// Seed initial commit
	workDir := filepath.Join(tmpDir, "seed")
	seedRepo, _ := git.PlainInit(workDir, false)
	seedFile := filepath.Join(workDir, "init.txt")
	_ = os.WriteFile(seedFile, []byte("init"), 0o644)
	w, _ := seedRepo.Worktree()
	_, _ = w.Add("init.txt")
	_, _ = w.Commit("init", &git.CommitOptions{
		Author: &object.Signature{Name: "test", Email: "t@e.com", When: time.Now()},
	})
	_, _ = seedRepo.CreateRemote(&gitconfig.RemoteConfig{Name: "origin", URLs: []string{filepath.ToSlash(bareRepoDir)}})
	_ = seedRepo.Push(&git.PushOptions{RemoteName: "origin", RefSpecs: []gitconfig.RefSpec{"refs/heads/master:refs/heads/main"}})

	remoteURL := filepath.ToSlash(bareRepoDir)
	snapshotPayload := []byte("nested snapshot content\n")

	// Commit with nested path, no tag, custom author
	commitHash, err := CommitSnapshotToGit(ctx, GitCommitConfig{
		RepoURL:          remoteURL,
		Branch:           "main",
		SnapshotFilename: "snapshots/daily/tree.tsv",
		SnapshotData:     snapshotPayload,
		AuthorName:       "Custom Auditor",
		AuthorEmail:      "auditor@corp.local",
		CommitMessage:    "nested commit test",
	})
	if err != nil {
		t.Fatalf("CommitSnapshotToGit nested failed: %v", err)
	}
	if commitHash == "" {
		t.Fatal("expected non-empty commit hash")
	}

	// Read directly from branch (tag is "")
	readData, err := ReadSnapshotFromGit(ctx, remoteURL, "main", "", "snapshots/daily/tree.tsv", GitAuthOptions{})
	if err != nil {
		t.Fatalf("ReadSnapshotFromGit from branch failed: %v", err)
	}
	if !bytes.Equal(readData, snapshotPayload) {
		t.Fatalf("data mismatch from branch: got %q, want %q", string(readData), string(snapshotPayload))
	}

	// Test Commit with SkipPush = true
	_, err = CommitSnapshotToGit(ctx, GitCommitConfig{
		RepoURL:          remoteURL,
		Branch:           "main",
		SnapshotFilename: "local_only.tsv",
		SnapshotData:     snapshotPayload,
		SkipPush:         true,
	})
	if err != nil {
		t.Fatalf("CommitSnapshotToGit with SkipPush failed: %v", err)
	}
}

func TestResolveGitAuth_SSHKeys(t *testing.T) {
	ctx := context.Background()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	pemBlock, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("MarshalPrivateKey failed: %v", err)
	}
	keyBytes := pem.EncodeToMemory(pemBlock)

	tmpDir := t.TempDir()
	plainKeyFile := filepath.Join(tmpDir, "id_ed25519")
	_ = os.WriteFile(plainKeyFile, keyBytes, 0o600)

	// 1. Plaintext SSH key from file
	auth, err := ResolveGitAuthContext(ctx, GitAuthOptions{
		Username:   "git",
		SSHKeyPath: plainKeyFile,
	}, true)
	if err != nil {
		t.Fatalf("ResolveGitAuthContext plain SSH failed: %v", err)
	}
	if auth == nil {
		t.Fatal("expected non-nil SSH auth")
	}

	// 2. Encrypted SSH key from file with secretprotector
	masterKey := []byte("01234567890123456789012345678901")
	encKeyBytes, err := libsecsecrets.EncryptBytes(ctx, keyBytes, masterKey)
	if err != nil {
		t.Fatalf("EncryptBytes failed: %v", err)
	}
	encKeyFile := filepath.Join(tmpDir, "id_ed25519.enc")
	_ = os.WriteFile(encKeyFile, encKeyBytes, 0o600)

	authEnc, err := ResolveGitAuthContext(ctx, GitAuthOptions{
		Username:   "git",
		SSHKeyPath: encKeyFile,
		MasterKey:  hex.EncodeToString(masterKey),
	}, true)
	if err != nil {
		t.Fatalf("ResolveGitAuthContext encrypted SSH failed: %v", err)
	}
	if authEnc == nil {
		t.Fatal("expected non-nil encrypted SSH auth")
	}

	// 3. SSH key via GIT_SSH_KEY env
	t.Setenv("GIT_SSH_KEY", plainKeyFile)
	authEnv, err := ResolveGitAuthContext(ctx, GitAuthOptions{Username: "git"}, true)
	if err != nil {
		t.Fatalf("ResolveGitAuthContext GIT_SSH_KEY failed: %v", err)
	}
	if authEnv == nil {
		t.Fatal("expected non-nil SSH auth from env")
	}
}

func TestStorage_ExtendedGitAndCloudEdgeCases(t *testing.T) {
	ctx := context.Background()

	// 1. Test IsGitURL
	validGit := []string{
		"git://github.com/org/repo",
		"git@github.com:org/repo.git",
		"ssh://git@github.com/org/repo",
		"https://github.com/org/repo.git",
		"http://github.com/org/repo.git",
	}
	for _, u := range validGit {
		if !IsGitURL(u) {
			t.Errorf("expected IsGitURL(%q) == true", u)
		}
	}
	invalidGit := []string{
		"https://github.com/org/repo",
		"s3://bucket/key",
		"file:///local/path",
	}
	for _, u := range invalidGit {
		if IsGitURL(u) {
			t.Errorf("expected IsGitURL(%q) == false", u)
		}
	}

	// 2. Test IsCloudURL
	validCloud := []string{
		"s3://bucket/key",
		"gs://bucket/key",
		"azblob://account/container/key",
		"file:///tmp/bucket/key",
	}
	for _, u := range validCloud {
		if !IsCloudURL(u) {
			t.Errorf("expected IsCloudURL(%q) == true", u)
		}
	}
	if IsCloudURL("ftp://bucket/key") {
		t.Errorf("expected IsCloudURL(ftp://) == false")
	}

	// 3. Test CommitSnapshotToGit with defaults and tag pushing to bare repo
	tmpDir := t.TempDir()
	bareRepoDir := filepath.Join(tmpDir, "bare.git")
	_, err := git.PlainInit(bareRepoDir, true)
	if err != nil {
		t.Fatalf("failed to init bare repo: %v", err)
	}

	// Commit with tag and push to bare repo
	tag := "v1.2.3"
	payload := []byte("snap_data_v1.2.3")
	hash, err := CommitSnapshotToGit(ctx, GitCommitConfig{
		RepoURL:      filepath.ToSlash(bareRepoDir),
		Tag:          tag,
		SnapshotData: payload,
	})
	if err != nil {
		t.Fatalf("CommitSnapshotToGit with tag failed: %v", err)
	}
	if hash == "" {
		t.Errorf("expected non-empty commit hash")
	}

	// Read snapshot back by tag
	readData, err := ReadSnapshotFromGit(ctx, filepath.ToSlash(bareRepoDir), "", tag, "", GitAuthOptions{})
	if err != nil {
		t.Fatalf("ReadSnapshotFromGit by tag failed: %v", err)
	}
	if string(readData) != string(payload) {
		t.Fatalf("expected payload %q, got %q", string(payload), string(readData))
	}

	// Read non-existent file
	_, err = ReadSnapshotFromGit(ctx, filepath.ToSlash(bareRepoDir), "", tag, "nonexistent.file", GitAuthOptions{})
	if err == nil {
		t.Errorf("expected error reading nonexistent file from git, got nil")
	}

	// 4. Test NewCloudReader on non-existent object in file://
	fileURL := "file:///" + filepath.ToSlash(tmpDir) + "/bucket/missing_key.txt"
	_, err = NewCloudReader(ctx, fileURL)
	if err == nil {
		t.Errorf("expected error opening reader on missing file blob, got nil")
	}
}
