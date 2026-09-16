//go:build integration

// Package integration_test implements live production end-to-end integration tests with real endpoints.
//
// Objectives:
//   - Execute full production lifecycle testing against real unmocked services (MinIO S3 container via Docker,
//     bare Git repositories via go-git, and local filesystems).
//   - Validate zero-disk direct streaming to remote cloud object storage with SecretProtector-encrypted credentials.
//   - Guarantee integrity across complex enterprise topologies: deep paths (>260 chars), unicode directories,
//     and mixed payload files adhering strictly to the Zero-Payload File I/O invariant.
//   - Verify complete enterprise lifecycle across all 5 primary operations: Backup -> Status -> Verify -> Restore -> Diff.
//
// Test Strategy:
//   - S3 Live Production: TestLiveE2E_FullProductionLifecycle spins up an ephemeral MinIO S3 container via WSL/Docker,
//     encrypts AWS credentials with SecretProtector AES-256-GCM, creates an S3 bucket over TLS, streams backup archives
//     directly into S3 over HTTPS wire, inspects header status metadata in microseconds, validates remote checksums with Verify,
//     restores onto fresh disk, audits drift with Diff, injects rogue files, executes mirror mode evacuation, and applies retention.
//   - GitOps Production: TestLiveE2E_GitOpsProductionLifecycle creates a bare Git repository fixture,
//     commits snapshots directly to Git branch and tag in-memory, inspects header status, retrieves snapshots by tag,
//     verifies framing, and restores with zero drift.
//
// Data Flow:
//
//	Complex Live Tree -> S3 Direct Streaming (NewCloudWriter) -> MinIO Container -> Status Peek (InspectHeader)
//	-> Zero-Disk Verify (NewCloudReader) -> Materialize Target Tree (Restore) -> Single-Pass Diff -> Zero Drift Assertion.
package integration_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/edsilegxrepo/dtreesync/internal/core"
	"github.com/edsilegxrepo/dtreesync/internal/storage"
	"github.com/edsilegxrepo/dtreesync/pkg/dtreesync"
	"github.com/edsilegxrepo/dtreesync/test/testutil"
	"github.com/edsilegxrepo/secretprotector/pkg/libsecsecrets"
	git "github.com/go-git/go-git/v5"
	gitconfig "github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing/object"
)

func startMinIO(t *testing.T) (endpoint, accessKey, secretKey string, cleanup func()) {
	return testutil.EnsureMinIORunning(t)
}

func createS3Bucket(ctx context.Context, endpoint, bucketName, accessKey, secretKey string, httpClient *http.Client) error {
	return testutil.CreateS3Bucket(ctx, endpoint, bucketName, accessKey, secretKey, httpClient)
}

func seedComplexTree(t *testing.T, baseDir string) int {
	// Deep path (>260 chars)
	deepSegment := "deep_subfolder_level_padding_segment_0123456789_abcdefghij"
	deepPath := filepath.Join(baseDir, "finance", deepSegment, deepSegment, deepSegment, deepSegment)
	if err := os.MkdirAll(deepPath, 0o755); err != nil {
		t.Fatalf("failed to create deep path: %v", err)
	}

	// Unicode directory paths
	unicodeDirs := []string{
		filepath.Join(baseDir, "engineering", "日本語_プロジェクト"),
		filepath.Join(baseDir, "hr", "données_français_2026"),
		filepath.Join(baseDir, "legal", "münchen_berlin_öäü"),
		filepath.Join(baseDir, "partner_001", "inbound", "orders"),
		filepath.Join(baseDir, "partner_001", "outbound", "archive"),
	}
	for _, u := range unicodeDirs {
		if err := os.MkdirAll(u, 0o755); err != nil {
			t.Fatalf("failed to create unicode dir %s: %v", u, err)
		}
	}

	// Dummy files in directories (which must NOT leak into directory records)
	dummyFiles := []string{
		filepath.Join(baseDir, "finance", "q1_balance.csv"),
		filepath.Join(baseDir, "engineering", "日本語_プロジェクト", "spec.pdf"),
		filepath.Join(baseDir, "partner_001", "inbound", "payload_1.dat"),
	}
	for _, df := range dummyFiles {
		if err := os.WriteFile(df, []byte("production dummy payload"), 0o644); err != nil {
			t.Fatalf("failed to create dummy file %s: %v", df, err)
		}
	}

	count := 0
	_ = filepath.WalkDir(baseDir, func(path string, d os.DirEntry, err error) error {
		if err == nil && d.IsDir() {
			count++
		}
		return nil
	})
	return count
}

func TestLiveE2E_FullProductionLifecycle(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	// 1. Start live unmocked MinIO S3 container via Docker
	rawEndpoint, accessKey, rawSecretKey, _ := startMinIO(t)
	bucketName := "dtreesync-prod-live"

	// 2. Setup TLS/SSL proxy termination fronting MinIO to ensure full wire encryption (SSL enabled)
	minioTargetURL, err := url.Parse("http://" + rawEndpoint)
	if err != nil {
		t.Fatalf("failed to parse minio URL: %v", err)
	}
	proxy := httputil.NewSingleHostReverseProxy(minioTargetURL)
	tlsServer := httptest.NewTLSServer(proxy)
	t.Cleanup(tlsServer.Close)

	tlsEndpoint := tlsServer.Listener.Addr().String()

	// Configure system and AWS SDK CA trust pool for the TLS server certificate
	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlsServer.Certificate().Raw})
	if err := os.WriteFile(caFile, certPEM, 0o644); err != nil {
		t.Fatalf("failed to write CA bundle: %v", err)
	}
	t.Setenv("AWS_CA_BUNDLE", caFile)
	t.Setenv("SSL_CERT_FILE", caFile)

	oldTransport := http.DefaultTransport
	customTransport := http.DefaultTransport.(*http.Transport).Clone()
	certPool := x509.NewCertPool()
	certPool.AddCert(tlsServer.Certificate())
	customTransport.TLSClientConfig = &tls.Config{
		RootCAs: certPool,
	}
	http.DefaultTransport = customTransport
	t.Cleanup(func() {
		http.DefaultTransport = oldTransport
	})

	if err := createS3Bucket(ctx, tlsEndpoint, bucketName, accessKey, rawSecretKey, tlsServer.Client()); err != nil {
		t.Fatalf("failed to create live S3 bucket over TLS: %v", err)
	}

	// 3. Setup SecretProtector AES-256 encrypted credentials
	masterKey := []byte("01234567890123456789012345678901") // 32 bytes
	masterKeyHex := hex.EncodeToString(masterKey)
	t.Setenv(storage.DefaultMasterKeyEnv, masterKeyHex)

	encSecretKey, err := libsecsecrets.Encrypt(ctx, rawSecretKey, masterKey)
	if err != nil {
		t.Fatalf("failed to encrypt AWS secret access key: %v", err)
	}

	t.Setenv("AWS_ACCESS_KEY_ID", accessKey)
	t.Setenv("AWS_SECRET_ACCESS_KEY", encSecretKey)
	t.Setenv("AWS_REGION", "us-east-1")
	t.Setenv("AWS_ENDPOINT_URL", "https://"+tlsEndpoint)

	// 4. Seed realistic complex tree
	sourceDir := filepath.Join(tmpDir, "source_tree")
	restoredDir := filepath.Join(tmpDir, "restored_tree")
	archiveDir := filepath.Join(tmpDir, "evacuation_archive")

	expectedDirCount := seedComplexTree(t, sourceDir)
	if expectedDirCount < 10 {
		t.Fatalf("expected at least 10 directories in complex tree, got %d", expectedDirCount)
	}

	// 5. Stage 1: Backup directly to S3 cloud storage with SSL / TLS wire encryption (SSL NOT DISABLED)
	s3SnapshotURL := fmt.Sprintf("s3://%s/snapshots/prod.tsv.zst?endpoint=%s&s3ForcePathStyle=true&region=us-east-1", bucketName, url.QueryEscape(tlsServer.URL))

	var auditBuf bytes.Buffer
	bRes, err := dtreesync.Backup(ctx, dtreesync.BackupConfig{
		BaseFolder:     sourceDir,
		TargetURL:      s3SnapshotURL,
		Format:         dtreesync.FormatTSV,
		Compression:    dtreesync.CompressionZstd,
		Workers:        4,
		AuditLogWriter: &auditBuf,
	})
	if err != nil {
		t.Fatalf("Backup to live S3 failed: %v", err)
	}
	if bRes.FolderCount != int64(expectedDirCount) {
		t.Fatalf("Backup folder count mismatch: expected %d, got %d", expectedDirCount, bRes.FolderCount)
	}
	if bRes.SHA256Hash == "" {
		t.Fatal("expected non-empty SHA256 cryptographic hash")
	}

	// 6. Stage 2: Status - inspect snapshot metadata directly from remote S3 with microsecond zero-payload peek
	cloudReader, err := storage.NewCloudReader(ctx, s3SnapshotURL)
	if err != nil {
		t.Fatalf("failed to open cloud reader for status inspection: %v", err)
	}
	hdr, err := dtreesync.InspectHeader(ctx, cloudReader)
	_ = cloudReader.Close()
	if err != nil {
		t.Fatalf("Status inspection on remote S3 snapshot failed: %v", err)
	}
	if hdr.Version == "" {
		t.Fatal("expected non-empty version in snapshot status header")
	}
	if hdr.FolderCount != int64(expectedDirCount) {
		t.Fatalf("Status folder count mismatch: expected %d, got %d", expectedDirCount, hdr.FolderCount)
	}
	if hdr.PayloadSHA256 != bRes.SHA256Hash {
		t.Fatalf("Status SHA256 mismatch: expected %s, got %s", bRes.SHA256Hash, hdr.PayloadSHA256)
	}
	if hdr.TreeFormat != "tsv" {
		t.Fatalf("Status format mismatch: expected tsv, got %s", hdr.TreeFormat)
	}
	if !hdr.Compression {
		t.Fatal("Status compression mismatch: expected true")
	}

	// 7. Stage 3: Verify zero-disk verification of remote S3 snapshot
	vRes, err := dtreesync.Verify(ctx, dtreesync.VerifyConfig{
		SourceURL: s3SnapshotURL,
		Workers:   4,
	})
	if err != nil {
		t.Fatalf("Verify on live S3 snapshot failed: %v (errors: %v)", err, vRes.Errors)
	}
	if !vRes.ChecksumValid || !vRes.FramesValid || !vRes.SyntaxValid {
		t.Fatalf("expected remote S3 snapshot to pass all tiers: %+v", vRes)
	}
	if vRes.RecordCount != int64(expectedDirCount) {
		t.Fatalf("Verify record count mismatch: expected %d, got %d", expectedDirCount, vRes.RecordCount)
	}

	// 6. Stage 3: Restore directly from remote S3 snapshot into fresh target
	rRes, err := dtreesync.Restore(ctx, dtreesync.RestoreConfig{
		SourceURL:    s3SnapshotURL,
		TargetFolder: restoredDir,
		Workers:      4,
	})
	if err != nil {
		t.Fatalf("Restore from live S3 failed: %v", err)
	}
	if rRes.CreatedFolders != int64(expectedDirCount) {
		t.Fatalf("Restore folder count mismatch: expected %d, got %d", expectedDirCount, rRes.CreatedFolders)
	}

	// 7. Stage 4: Diff restored directory against S3 snapshot (proves 100% compliance alignment)
	dRes, err := dtreesync.Diff(ctx, dtreesync.DiffConfig{
		SnapshotURL: s3SnapshotURL,
		LiveFolder:  restoredDir,
		Workers:     4,
	})
	if err != nil {
		t.Fatalf("Diff against S3 snapshot failed: %v", err)
	}
	if dRes.TotalDrift != 0 {
		t.Fatalf("expected 0 drift after restore, got %d items: %+v", dRes.TotalDrift, dRes.DriftItems)
	}

	// 8. Stage 5: Tamper injection, Mirror Evacuation, and Retention
	rogueDir := filepath.Join(restoredDir, "unauthorized_rogue_dir")
	if err := os.MkdirAll(rogueDir, 0o755); err != nil {
		t.Fatalf("failed to create rogue dir: %v", err)
	}
	rogueFile := filepath.Join(rogueDir, "unauthorized_rogue_file.txt")
	if err := os.WriteFile(rogueFile, []byte("tamper data"), 0o644); err != nil {
		t.Fatalf("failed to create rogue file: %v", err)
	}

	// Diff detects the rogue items
	dResTamper, err := dtreesync.Diff(ctx, dtreesync.DiffConfig{
		SnapshotURL: s3SnapshotURL,
		LiveFolder:  restoredDir,
		Workers:     2,
	})
	if err == nil {
		t.Fatal("expected ErrDriftDetected after injecting rogue items, got nil")
	}
	if dResTamper.TotalDrift == 0 {
		t.Fatal("expected non-zero drift items for rogue items")
	}

	// Evacuate untracked items into compressed archive container
	var untrackedPaths []string
	for _, it := range dResTamper.DriftItems {
		untrackedPaths = append(untrackedPaths, it.Path)
	}
	archiveFile, err := core.EvacuateUntracked(ctx, restoredDir, archiveDir, untrackedPaths, nil)
	if err != nil {
		t.Fatalf("EvacuateUntracked failed: %v", err)
	}
	if archiveFile == "" {
		t.Fatal("expected non-empty archive file path from evacuation")
	}

	// Verify rogue dir and file were purged from restored tree
	if _, err := os.Stat(rogueDir); !os.IsNotExist(err) {
		t.Errorf("expected rogue dir to be purged from restored directory")
	}

	// Diff now reports 0 drift and 100% clean alignment
	dResClean, err := dtreesync.Diff(ctx, dtreesync.DiffConfig{
		SnapshotURL: s3SnapshotURL,
		LiveFolder:  restoredDir,
		Workers:     2,
	})
	if err != nil {
		t.Fatalf("Diff after evacuation failed: %v", err)
	}
	if dResClean.TotalDrift != 0 {
		t.Errorf("expected 0 drift after evacuation, got %d", dResClean.TotalDrift)
	}

	// Apply retention lifecycle on evacuation archives
	purged, err := core.ApplyRetention(archiveDir, 0, 1, nil)
	if err != nil {
		t.Fatalf("ApplyRetention failed: %v", err)
	}
	_ = purged

	// 9. Stage 6: Multi-Tenant Selective Entity Filtering over Live S3
	// Restore ONLY "partner_001" tenant from the remote S3 snapshot
	tenantTargetDir := filepath.Join(tmpDir, "tenant_partner_001")
	tRes, err := dtreesync.Restore(ctx, dtreesync.RestoreConfig{
		SourceURL:    s3SnapshotURL,
		TargetFolder: tenantTargetDir,
		Entities:     []string{"partner_001"},
		Workers:      2,
	})
	if err != nil {
		t.Fatalf("Selective entity restore from live S3 failed: %v", err)
	}
	if tRes.CreatedFolders == 0 {
		t.Fatal("expected non-zero folders restored for partner_001 entity")
	}
	// Verify tenant isolation: partner_001 directories exist, but finance/legal/engineering DO NOT exist
	if _, err := os.Stat(filepath.Join(tenantTargetDir, "partner_001")); err != nil {
		t.Errorf("expected partner_001 folder to exist in tenant target")
	}
	if _, err := os.Stat(filepath.Join(tenantTargetDir, "finance")); !os.IsNotExist(err) {
		t.Errorf("tenant isolation breached: finance folder leaked into partner_001 restore")
	}

	// Diff with tenant scope against remote S3 snapshot
	tDiffRes, err := dtreesync.Diff(ctx, dtreesync.DiffConfig{
		SnapshotURL: s3SnapshotURL,
		LiveFolder:  tenantTargetDir,
		Entities:    []string{"partner_001"},
		Workers:     2,
	})
	if err != nil {
		t.Fatalf("Scoped entity diff failed: %v", err)
	}
	if tDiffRes.TotalDrift != 0 {
		t.Errorf("expected 0 drift for scoped partner_001 diff, got %d", tDiffRes.TotalDrift)
	}

	// 10. Stage 7: Remote S3 Tamper Detection over TLS Wire
	// Read remote S3 snapshot bytes, tamper with payload, upload tampered object back to S3, and assert Verify failure
	tamperedURL := fmt.Sprintf("s3://%s/snapshots/tampered.tsv.zst?endpoint=%s&s3ForcePathStyle=true&region=us-east-1", bucketName, url.QueryEscape(tlsServer.URL))

	// Create legitimate baseline snapshot for tamper test
	_, err = dtreesync.Backup(ctx, dtreesync.BackupConfig{
		BaseFolder:  filepath.Join(sourceDir, "partner_001"),
		TargetURL:   tamperedURL,
		Format:      dtreesync.FormatTSV,
		Compression: dtreesync.CompressionZstd,
		Workers:     2,
	})
	if err != nil {
		t.Fatalf("Backup for tamper baseline failed: %v", err)
	}

	// Read object directly from live S3 over TLS
	s3Client := s3.New(s3.Options{
		BaseEndpoint: aws.String("https://" + tlsEndpoint),
		Region:       "us-east-1",
		Credentials:  credentials.NewStaticCredentialsProvider(accessKey, rawSecretKey, ""),
		UsePathStyle: true,
		HTTPClient:   tlsServer.Client(),
	})
	getObj, err := s3Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String("snapshots/tampered.tsv.zst"),
	})
	if err != nil {
		t.Fatalf("failed to get object from S3 for tampering: %v", err)
	}
	snapBytes, err := io.ReadAll(getObj.Body)
	_ = getObj.Body.Close()
	if err != nil {
		t.Fatalf("failed to read S3 object bytes: %v", err)
	}

	// Corrupt middle byte of compressed payload in memory
	if len(snapBytes) > 20 {
		snapBytes[len(snapBytes)-10] ^= 0xFF
	}

	// Overwrite object directly in S3 with tampered bytes over TLS
	_, err = s3Client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String("snapshots/tampered.tsv.zst"),
		Body:   bytes.NewReader(snapBytes),
	})
	if err != nil {
		t.Fatalf("failed to overwrite S3 object with tampered payload: %v", err)
	}

	// Assert remote Verify over TLS detects the tampering with ErrVerificationFailed
	tamperVRes, err := dtreesync.Verify(ctx, dtreesync.VerifyConfig{
		SourceURL: tamperedURL,
		Workers:   2,
	})
	if err == nil || !errors.Is(err, dtreesync.ErrVerificationFailed) {
		t.Fatalf("expected ErrVerificationFailed when verifying tampered remote S3 snapshot, got: %v (result: %+v)", err, tamperVRes)
	}
	if tamperVRes.ChecksumValid && tamperVRes.FramesValid {
		t.Errorf("expected ChecksumValid or FramesValid to be false on tampered S3 snapshot")
	}
}

func TestLiveE2E_GitOpsProductionLifecycle(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Ensure git binaries (e.g. git-receive-pack) are discoverable in PATH across Windows/Linux
	for _, p := range []string{`d:\dev\git\cmd`, `d:\dev\git\mingw64\bin`} {
		if fi, err := os.Stat(p); err == nil && fi.IsDir() {
			os.Setenv("PATH", os.Getenv("PATH")+string(os.PathListSeparator)+p)
		}
	}
	if execOut, err := exec.Command("git", "--exec-path").Output(); err == nil {
		p := strings.TrimSpace(string(execOut))
		if fi, err := os.Stat(p); err == nil && fi.IsDir() {
			os.Setenv("PATH", os.Getenv("PATH")+string(os.PathListSeparator)+p)
		}
	}

	tmpDir := t.TempDir()
	bareRepoDir := filepath.Join(tmpDir, "bare.git")
	_, err := git.PlainInit(bareRepoDir, true)
	if err != nil {
		t.Fatalf("failed to initialize bare git repo: %v", err)
	}

	// Seed initial commit so bare repo has a valid default branch HEAD
	seedDir := filepath.Join(tmpDir, "seed")
	seedRepo, err := git.PlainInit(seedDir, false)
	if err != nil {
		t.Fatalf("failed to init seed repo: %v", err)
	}
	seedFile := filepath.Join(seedDir, "README.md")
	if err := os.WriteFile(seedFile, []byte("# GitOps Repository\n"), 0o644); err != nil {
		t.Fatalf("failed to write seed file: %v", err)
	}
	sw, err := seedRepo.Worktree()
	if err != nil {
		t.Fatalf("failed to get seed worktree: %v", err)
	}
	if _, err := sw.Add("README.md"); err != nil {
		t.Fatalf("failed to add seed file: %v", err)
	}
	_, err = sw.Commit("Initial repository bootstrap", &git.CommitOptions{
		Author: &object.Signature{
			Name:  "CI Bootstrap",
			Email: "bootstrap@edsilegx.internal",
			When:  time.Now().UTC(),
		},
	})
	if err != nil {
		t.Fatalf("failed to commit seed: %v", err)
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

	sourceDir := filepath.Join(tmpDir, "source")
	_ = os.MkdirAll(filepath.Join(sourceDir, "partner_alpha", "orders"), 0o755)
	_ = os.MkdirAll(filepath.Join(sourceDir, "partner_beta", "inbound"), 0o755)
	_ = os.WriteFile(filepath.Join(sourceDir, "partner_alpha", "orders", "sample.dat"), []byte("payload"), 0o644)

	// Step 1: Backup directly into buffer
	var buf bytes.Buffer
	bRes, err := dtreesync.Backup(ctx, dtreesync.BackupConfig{
		BaseFolder:  sourceDir,
		Writer:      &buf,
		Format:      dtreesync.FormatTSV,
		Compression: dtreesync.CompressionZstd,
		Workers:     2,
	})
	if err != nil {
		t.Fatalf("Backup failed: %v", err)
	}
	if bRes.FolderCount != 5 { // root, partner_alpha, partner_alpha/orders, partner_beta, partner_beta/inbound
		t.Errorf("expected 5 folders, got %d", bRes.FolderCount)
	}

	// Step 2: Commit directly to bare Git repository with tag
	repoURL := filepath.ToSlash(bareRepoDir)
	commitTag := "v1.0.0-release"
	commitHash, err := storage.CommitSnapshotToGit(ctx, storage.GitCommitConfig{
		RepoURL:          repoURL,
		Branch:           "main",
		Tag:              commitTag,
		AuthorName:       "CI Bot",
		AuthorEmail:      "ci@edsilegx.internal",
		CommitMessage:    "Automated topology snapshot v1.0.0-release",
		SnapshotFilename: "topologies/network.tsv.zst",
		SnapshotData:     buf.Bytes(),
	})
	if err != nil {
		t.Fatalf("CommitSnapshotToGit failed: %v", err)
	}
	if commitHash == "" {
		t.Fatal("expected non-empty commit hash")
	}

	// Step 3: Read snapshot back from bare Git repo by tag
	gitData, err := storage.ReadSnapshotFromGit(ctx, repoURL, "", commitTag, "topologies/network.tsv.zst", storage.GitAuthOptions{})
	if err != nil {
		t.Fatalf("ReadSnapshotFromGit by tag failed: %v", err)
	}
	if !bytes.Equal(gitData, buf.Bytes()) {
		t.Fatal("retrieved git snapshot data does not match original backup")
	}

	// Step 4: Status - inspect snapshot metadata directly from Git artifact with microsecond zero-payload peek
	gitHdr, err := dtreesync.InspectHeader(ctx, bytes.NewReader(gitData))
	if err != nil {
		t.Fatalf("Status inspection on Git snapshot failed: %v", err)
	}
	if gitHdr.FolderCount != 5 {
		t.Fatalf("Status git folder count mismatch: expected 5, got %d", gitHdr.FolderCount)
	}
	if gitHdr.PayloadSHA256 != bRes.SHA256Hash {
		t.Fatalf("Status git SHA256 mismatch: expected %s, got %s", bRes.SHA256Hash, gitHdr.PayloadSHA256)
	}
	if gitHdr.TreeFormat != "tsv" {
		t.Fatalf("Status git format mismatch: expected tsv, got %s", gitHdr.TreeFormat)
	}
	if !gitHdr.Compression {
		t.Fatal("Status git compression mismatch: expected true")
	}

	// Step 5: Verify snapshot retrieved from Git
	vRes, err := dtreesync.Verify(ctx, dtreesync.VerifyConfig{
		Reader:  bytes.NewReader(gitData),
		Workers: 2,
	})
	if err != nil {
		t.Fatalf("Verify on Git snapshot failed: %v", err)
	}
	if !vRes.ChecksumValid || !vRes.FramesValid || !vRes.SyntaxValid {
		t.Fatalf("Git snapshot failed verification: %+v", vRes)
	}

	// Step 6: Restore from Git snapshot to fresh target
	targetDir := filepath.Join(tmpDir, "restored_from_git")
	rRes, err := dtreesync.Restore(ctx, dtreesync.RestoreConfig{
		Reader:       bytes.NewReader(gitData),
		TargetFolder: targetDir,
		Workers:      2,
	})
	if err != nil {
		t.Fatalf("Restore from Git snapshot failed: %v", err)
	}
	if rRes.CreatedFolders != 5 {
		t.Errorf("expected 5 folders restored from Git snapshot, got %d", rRes.CreatedFolders)
	}

	// Step 7: Diff restored folder against snapshot
	dRes, err := dtreesync.Diff(ctx, dtreesync.DiffConfig{
		SnapshotReader: bytes.NewReader(gitData),
		LiveFolder:     targetDir,
		Workers:        2,
	})
	if err != nil {
		t.Fatalf("Diff against Git snapshot failed: %v", err)
	}
	if dRes.TotalDrift != 0 {
		t.Errorf("expected 0 drift, got %d", dRes.TotalDrift)
	}
}
