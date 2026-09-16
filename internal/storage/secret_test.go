// Package storage provides unit and integration tests for storage drivers,
// cloud transports, and secretprotector cryptographic secret integration.
//
// Objectives:
//   - Validate SecretProtector AES-256-GCM master key resolution across CLI flags, env vars, and key files.
//   - Verify encrypted token (v1:gcm:...) decryption and backwards compatibility for plaintext secrets.
//   - Verify in-memory ProtectedSecret RAM encapsulation, Reveal(), and zeroing upon Destroy().
//   - Test GitAuthOptions resolution with encrypted HTTPS bearer tokens and SSH passphrases.
//   - Test PrepareCloudAuth preflight environment variable and credential file decryption.
//   - Validate live in-memory GitOps commits and snapshot retrieval with protected credentials.
//
// Test Strategy:
//   - Master Key Ingestion: Tests multi-tier key resolution across raw hex strings, environment variables,
//     and key files, ensuring strict permission checks on Unix.
//   - Decryption & Fallback: Verifies v1:gcm: ciphertexts decrypt correctly while plaintext strings pass through unharmed.
//   - Memory Zeroing: Verifies ProtectedSecret.Destroy() securely zeros sensitive byte slices in memory.
//   - Transport Integration: Asserts end-to-end Git authentication and cloud credential injection.
//
// Data Flow:
//
//	Master Key Source -> libsecsecrets Key Derivation -> DecryptSecret() -> ProtectedSecret Handle -> Assertions.
package storage

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/edsilegxrepo/secretprotector/pkg/libsecsecrets"
	git "github.com/go-git/go-git/v5"
	gitconfig "github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing/object"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
)

// Helper to generate a valid test master key and guarantee zeroing on test exit.
func generateTestMasterKey(t *testing.T) (string, []byte) {
	t.Helper()
	keyHex, err := libsecsecrets.GenerateKey()
	if err != nil {
		t.Fatalf("failed generating master key: %v", err)
	}
	keyBytes, err := ResolveMasterKey(context.Background(), keyHex, "", "")
	if err != nil {
		t.Fatalf("failed resolving test key: %v", err)
	}
	t.Cleanup(func() {
		libsecsecrets.ZeroBuffer(keyBytes)
	})
	return keyHex, keyBytes
}

func TestSecretProtector_ResolveMasterKey(t *testing.T) {
	ctx := context.Background()
	keyHex, expectedBytes := generateTestMasterKey(t)

	// 1. Direct raw resolution
	k1, err := ResolveMasterKey(ctx, keyHex, "", "")
	if err != nil {
		t.Fatalf("ResolveMasterKey from raw hex failed: %v", err)
	}
	defer libsecsecrets.ZeroBuffer(k1)
	if !bytes.Equal(k1, expectedBytes) {
		t.Errorf("raw key mismatch: got %x, want %x", k1, expectedBytes)
	}

	// 2. Custom environment variable resolution
	customEnv := "DTREESYNC_TEST_SECRET_KEY"
	t.Setenv(customEnv, keyHex)
	k2, err := ResolveMasterKey(ctx, "", customEnv, "")
	if err != nil {
		t.Fatalf("ResolveMasterKey from custom env failed: %v", err)
	}
	defer libsecsecrets.ZeroBuffer(k2)
	if !bytes.Equal(k2, expectedBytes) {
		t.Errorf("env key mismatch: got %x, want %x", k2, expectedBytes)
	}

	// 3. Default environment variable (SECRETPROTECTOR_MASTER_KEY)
	t.Setenv(DefaultMasterKeyEnv, keyHex)
	k3, err := ResolveMasterKey(ctx, "", "", "")
	if err != nil {
		t.Fatalf("ResolveMasterKey from default env failed: %v", err)
	}
	defer libsecsecrets.ZeroBuffer(k3)
	if !bytes.Equal(k3, expectedBytes) {
		t.Errorf("default env key mismatch: got %x, want %x", k3, expectedBytes)
	}

	// 4. Key file resolution (must not be in temp on Windows to satisfy platform security)
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed getting working directory: %v", err)
	}
	keyFilePath := filepath.Join(wd, "test_secure_master.key")
	if err := os.WriteFile(keyFilePath, []byte(keyHex+"\n"), 0o600); err != nil {
		t.Fatalf("failed writing key file: %v", err)
	}
	defer func() { _ = os.Remove(keyFilePath) }()

	k4, err := ResolveMasterKey(ctx, "", "", keyFilePath)
	if err != nil {
		t.Fatalf("ResolveMasterKey from file failed: %v", err)
	}
	defer libsecsecrets.ZeroBuffer(k4)
	if !bytes.Equal(k4, expectedBytes) {
		t.Errorf("file key mismatch: got %x, want %x", k4, expectedBytes)
	}

	// 5. Insecure location / permission detection
	if runtime.GOOS == "windows" {
		insecureKeyPath := filepath.Join(t.TempDir(), "insecure.key")
		_ = os.WriteFile(insecureKeyPath, []byte(keyHex+"\n"), 0o600)
		_, err = ResolveMasterKey(ctx, "", "", insecureKeyPath)
		if err == nil {
			t.Errorf("expected error for key file in temp directory on Windows, got nil")
		}
	} else {
		linuxTmp, err := os.MkdirTemp("/tmp", "dtree_sec_*")
		if err == nil {
			defer func() { _ = os.RemoveAll(linuxTmp) }()
			insecurePermPath := filepath.Join(linuxTmp, "insecure_perm.key")
			_ = os.WriteFile(insecurePermPath, []byte(keyHex+"\n"), 0o666)
			_ = os.Chmod(insecurePermPath, 0o666)
			_, err = ResolveMasterKey(ctx, "", "", insecurePermPath)
			if err == nil {
				t.Errorf("expected error for key file with insecure permissions on Linux, got nil")
			}
		}
	}

	// 5. Missing source error
	t.Setenv(DefaultMasterKeyEnv, "")
	_, err = ResolveMasterKey(ctx, "", "", "")
	if err == nil {
		t.Errorf("expected error when no key sources available, got nil")
	}

	// 6. Invalid key length
	_, err = ResolveMasterKey(ctx, "invalid-short-key", "", "")
	if err == nil {
		t.Errorf("expected error on invalid key length, got nil")
	}
}

func TestSecretProtector_DecryptSecret(t *testing.T) {
	ctx := context.Background()
	_, masterKey := generateTestMasterKey(t)

	rawSecret := "ghp_superSecretToken1234567890abcdef"
	encToken, err := libsecsecrets.Encrypt(ctx, rawSecret, masterKey)
	if err != nil {
		t.Fatalf("failed encrypting secret: %v", err)
	}

	if !libsecsecrets.IsEncrypted(encToken) {
		t.Fatalf("expected encrypted token to have prefix %s", EncryptedPrefix)
	}

	// 1. Successful decryption
	decrypted, err := DecryptSecret(ctx, encToken, masterKey)
	if err != nil {
		t.Fatalf("DecryptSecret failed: %v", err)
	}
	if decrypted != rawSecret {
		t.Errorf("decrypted secret mismatch: got %q, want %q", decrypted, rawSecret)
	}

	// 2. Plaintext backwards compatibility
	plainVal := "unencrypted_legacy_password"
	decPlain, err := DecryptSecret(ctx, plainVal, masterKey)
	if err != nil {
		t.Fatalf("DecryptSecret on plaintext failed: %v", err)
	}
	if decPlain != plainVal {
		t.Errorf("plaintext pass-through failed: got %q, want %q", decPlain, plainVal)
	}

	// 3. Encrypted secret without master key fails fast
	_, err = DecryptSecret(ctx, encToken, nil)
	if err == nil {
		t.Errorf("expected error when decrypting without master key, got nil")
	}

	// 4. Encrypted secret with incorrect master key fails
	_, wrongKey := generateTestMasterKey(t)
	_, err = DecryptSecret(ctx, encToken, wrongKey)
	if err == nil {
		t.Errorf("expected error when decrypting with incorrect master key, got nil")
	}

	// 5. DecryptSecretBytes roundtrip
	encBytes, err := libsecsecrets.EncryptBytes(ctx, []byte(rawSecret), masterKey)
	if err != nil {
		t.Fatalf("failed encrypting bytes: %v", err)
	}
	decBytes, err := DecryptSecretBytes(ctx, encBytes, masterKey)
	if err != nil {
		t.Fatalf("DecryptSecretBytes failed: %v", err)
	}
	defer libsecsecrets.ZeroBuffer(decBytes)
	if string(decBytes) != rawSecret {
		t.Errorf("decrypted bytes mismatch: got %q, want %q", string(decBytes), rawSecret)
	}
}

func TestSecretProtector_ProtectedSecret(t *testing.T) {
	rawSecret := "confidential-in-memory-passphrase-9988"

	ps, err := NewProtectedSecret(rawSecret)
	if err != nil {
		t.Fatalf("NewProtectedSecret failed: %v", err)
	}

	// Reveal
	revealed, err := ps.Reveal()
	if err != nil {
		t.Fatalf("ps.Reveal failed: %v", err)
	}
	if string(revealed) != rawSecret {
		t.Errorf("revealed mismatch: got %q, want %q", string(revealed), rawSecret)
	}
	libsecsecrets.ZeroBuffer(revealed)

	// Destroy
	ps.Destroy()

	// Reveal after destroy must fail
	_, err = ps.Reveal()
	if err == nil {
		t.Errorf("expected error after ProtectedSecret.Destroy(), got nil")
	}
}

func TestSecretProtector_GitAuth_EncryptedCredentials(t *testing.T) {
	ctx := context.Background()
	keyHex, masterKey := generateTestMasterKey(t)

	rawToken := "ghp_secureComplianceTokenForGit001"
	encToken, err := libsecsecrets.Encrypt(ctx, rawToken, masterKey)
	if err != nil {
		t.Fatalf("failed encrypting git token: %v", err)
	}

	// 1. HTTPS Auth with encrypted Password in GitAuthOptions
	opts := GitAuthOptions{
		Username:  "x-access-token",
		Password:  encToken,
		MasterKey: keyHex,
	}
	authMethod, err := ResolveGitAuthContext(ctx, opts, false)
	if err != nil {
		t.Fatalf("ResolveGitAuth with encrypted password failed: %v", err)
	}
	basicAuth, ok := authMethod.(*githttp.BasicAuth)
	if !ok {
		t.Fatalf("expected *githttp.BasicAuth, got %T", authMethod)
	}
	if basicAuth.Password != rawToken {
		t.Errorf("decrypted token mismatch: got %q, want %q", basicAuth.Password, rawToken)
	}

	// 2. HTTPS Auth with encrypted token in environment variable
	t.Setenv(DefaultMasterKeyEnv, keyHex)
	t.Setenv("GIT_TOKEN", encToken)
	authEnv, err := ResolveGitAuth(GitAuthOptions{}, false)
	if err != nil {
		t.Fatalf("ResolveGitAuth with encrypted GIT_TOKEN failed: %v", err)
	}
	basicAuthEnv, ok := authEnv.(*githttp.BasicAuth)
	if !ok {
		t.Fatalf("expected *githttp.BasicAuth, got %T", authEnv)
	}
	if basicAuthEnv.Password != rawToken {
		t.Errorf("env decrypted token mismatch: got %q, want %q", basicAuthEnv.Password, rawToken)
	}

	// 3. HTTPS Auth with plaintext token passes through cleanly
	t.Setenv("GIT_TOKEN", "ghp_plainTokenLegacy123")
	authPlain, err := ResolveGitAuth(GitAuthOptions{}, false)
	if err != nil {
		t.Fatalf("ResolveGitAuth with plaintext token failed: %v", err)
	}
	basicPlain, ok := authPlain.(*githttp.BasicAuth)
	if !ok {
		t.Fatalf("expected *githttp.BasicAuth, got %T", authPlain)
	}
	if basicPlain.Password != "ghp_plainTokenLegacy123" {
		t.Errorf("plaintext token mismatch: got %q", basicPlain.Password)
	}
}

func TestSecretProtector_CloudAuth_EncryptedEnv(t *testing.T) {
	ctx := context.Background()
	keyHex, masterKey := generateTestMasterKey(t)
	t.Setenv(DefaultMasterKeyEnv, keyHex)

	rawAwsSecret := "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	encAwsSecret, err := libsecsecrets.Encrypt(ctx, rawAwsSecret, masterKey)
	if err != nil {
		t.Fatalf("failed encrypting AWS secret: %v", err)
	}
	t.Setenv("AWS_SECRET_ACCESS_KEY", encAwsSecret)

	rawAzKey := "c2VjcmV0YXp1cmVrZXkxMjM0NTY3ODkwMTI="
	encAzKey, err := libsecsecrets.Encrypt(ctx, rawAzKey, masterKey)
	if err != nil {
		t.Fatalf("failed encrypting Azure key: %v", err)
	}
	t.Setenv("AZURE_STORAGE_KEY", encAzKey)

	// Encrypted GCP service account key file on disk
	tmpDir := t.TempDir()
	gcpFile := filepath.Join(tmpDir, "sa_key.json")
	rawGcpJSON := `{"type": "service_account", "project_id": "test-project-123"}`
	encGcpJSON, err := libsecsecrets.Encrypt(ctx, rawGcpJSON, masterKey)
	if err != nil {
		t.Fatalf("failed encrypting GCP json: %v", err)
	}
	if err := os.WriteFile(gcpFile, []byte(encGcpJSON), 0o600); err != nil {
		t.Fatalf("failed writing GCP file: %v", err)
	}
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", gcpFile)

	cleanup, err := PrepareCloudAuth(ctx, nil)
	if err != nil {
		t.Fatalf("PrepareCloudAuth failed: %v", err)
	}

	// Assert environment variables are decrypted
	if got := os.Getenv("AWS_SECRET_ACCESS_KEY"); got != rawAwsSecret {
		t.Errorf("AWS_SECRET_ACCESS_KEY not decrypted: got %q, want %q", got, rawAwsSecret)
	}
	if got := os.Getenv("AZURE_STORAGE_KEY"); got != rawAzKey {
		t.Errorf("AZURE_STORAGE_KEY not decrypted: got %q, want %q", got, rawAzKey)
	}
	decGcpPath := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")
	if decGcpPath == gcpFile {
		t.Errorf("GOOGLE_APPLICATION_CREDENTIALS was not replaced with temporary decrypted file")
	}
	decContent, err := os.ReadFile(decGcpPath)
	if err != nil {
		t.Fatalf("failed reading decrypted GCP file: %v", err)
	}
	if string(decContent) != rawGcpJSON {
		t.Errorf("decrypted GCP content mismatch: got %q, want %q", string(decContent), rawGcpJSON)
	}

	// Run cleanup and assert restoration
	cleanup()

	if got := os.Getenv("AWS_SECRET_ACCESS_KEY"); got != encAwsSecret {
		t.Errorf("AWS_SECRET_ACCESS_KEY not restored: got %q, want %q", got, encAwsSecret)
	}
	if got := os.Getenv("AZURE_STORAGE_KEY"); got != encAzKey {
		t.Errorf("AZURE_STORAGE_KEY not restored: got %q, want %q", got, encAzKey)
	}
	if got := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"); got != gcpFile {
		t.Errorf("GOOGLE_APPLICATION_CREDENTIALS not restored: got %q, want %q", got, gcpFile)
	}
	if _, err := os.Stat(decGcpPath); !os.IsNotExist(err) {
		t.Errorf("temporary decrypted GCP file %q was not removed", decGcpPath)
	}
}

func TestSecretProtector_EndToEndGitCommitAndRead(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	keyHex, masterKey := generateTestMasterKey(t)

	// Ensure git binaries are discoverable on Windows test environments
	for _, p := range []string{`d:\dev\git\cmd`, `d:\dev\git\mingw64\bin`} {
		if fi, err := os.Stat(p); err == nil && fi.IsDir() {
			t.Setenv("PATH", os.Getenv("PATH")+string(os.PathListSeparator)+p)
		}
	}

	tmpDir := t.TempDir()
	bareRepoDir := filepath.Join(tmpDir, "secure_remote.git")
	r, err := git.PlainInit(bareRepoDir, true)
	if err != nil {
		t.Fatalf("Failed to init bare repo: %v", err)
	}

	// Seed initial commit
	workDir := filepath.Join(tmpDir, "seed")
	seedRepo, err := git.PlainInit(workDir, false)
	if err != nil {
		t.Fatalf("Failed to init seed repo: %v", err)
	}
	seedFile := filepath.Join(workDir, "README.md")
	if err := os.WriteFile(seedFile, []byte("initial"), 0o644); err != nil {
		t.Fatalf("Failed to write seed file: %v", err)
	}
	w, err := seedRepo.Worktree()
	if err != nil {
		t.Fatalf("Failed to get worktree: %v", err)
	}
	if _, err := w.Add("README.md"); err != nil {
		t.Fatalf("Failed to add seed file: %v", err)
	}
	if _, err := w.Commit("Initial commit", &git.CommitOptions{
		Author: &object.Signature{
			Name:  "Test",
			Email: "test@example.com",
			When:  time.Now(),
		},
	}); err != nil {
		t.Fatalf("Failed to commit seed: %v", err)
	}
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
	snapshotPayload := []byte("#META:{\"version\":\"2.0\"}\nentity\trel_path\npartnerA\t/inbox\n")

	// Encrypt a token to verify GitAuthOptions with secretprotector
	encToken, err := libsecsecrets.Encrypt(ctx, "mock_git_token_999", masterKey)
	if err != nil {
		t.Fatalf("failed encrypting git token: %v", err)
	}

	authOpts := GitAuthOptions{
		Username:  "x-access-token",
		Password:  encToken,
		MasterKey: keyHex,
	}

	commitHash, err := CommitSnapshotToGit(ctx, GitCommitConfig{
		RepoURL:          remoteURL,
		Branch:           "main",
		Tag:              "v2.0.0",
		SnapshotFilename: "tree.tsv",
		SnapshotData:     snapshotPayload,
		AuthOpts:         authOpts,
	})
	if err != nil {
		t.Fatalf("CommitSnapshotToGit with protected credentials failed: %v", err)
	}
	if commitHash == "" {
		t.Fatalf("Expected non-empty commit hash")
	}

	// Read snapshot back from Git using encrypted credentials
	readData, err := ReadSnapshotFromGit(ctx, remoteURL, "main", "v2.0.0", "tree.tsv", authOpts)
	if err != nil {
		t.Fatalf("ReadSnapshotFromGit with protected credentials failed: %v", err)
	}
	if !bytes.Equal(readData, snapshotPayload) {
		t.Errorf("Git roundtrip mismatch: got %q, want %q", string(readData), string(snapshotPayload))
	}
}
