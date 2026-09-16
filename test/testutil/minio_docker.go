// Package testutil provides robust test utilities for live and e2e integration testing,
// including container lifecycle management and TLS proxying for cloud object storage.
package testutil

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
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
)

// ResolveDockerCommand detects whether native Docker or WSL Docker is available and operational.
func ResolveDockerCommand() (dockerBin string, prefixArgs []string, err error) {
	// 1. Try host native docker
	if _, lookErr := exec.LookPath("docker"); lookErr == nil {
		cmd := exec.Command("docker", "info")
		if err := cmd.Run(); err == nil {
			return "docker", nil, nil
		}
	}

	// 2. Try WSL docker
	if _, lookErr := exec.LookPath("wsl"); lookErr == nil {
		cmd := exec.Command("wsl", "docker", "info")
		if err := cmd.Run(); err == nil {
			return "wsl", []string{"docker"}, nil
		}
	}

	return "", nil, errors.New("neither native docker nor WSL docker is accessible or operational")
}

// EnsureMinIORunning ensures that a MinIO container is running and healthy on 127.0.0.1:9000.
// It handles:
// 1. Checking if MinIO is already running and healthy (reusing the instance).
// 2. Checking if an existing MinIO container is stopped in Docker/WSL Docker, and starting it.
// 3. Removing stale dead containers holding port 9000.
// 4. Starting a new MinIO container via Docker or WSL Docker.
// 5. Polling until MinIO health check succeeds.
func EnsureMinIORunning(t *testing.T) (endpoint, accessKey, secretKey string, cleanup func()) {
	t.Helper()

	endpoint = "127.0.0.1:9000"
	accessKey = "minioadmin"
	secretKey = "minioadmin"
	healthURL := fmt.Sprintf("http://%s/minio/health/live", endpoint)

	// 1. Check if MinIO is ALREADY running and healthy
	if isHealthy(healthURL) {
		t.Logf("MinIO container is already running and healthy at %s", endpoint)
		return endpoint, accessKey, secretKey, func() {}
	}

	// 2. Resolve Docker / WSL Docker command
	dockerBin, prefixArgs, err := ResolveDockerCommand()
	if err != nil {
		t.Fatalf("cannot ensure MinIO is running: %v", err)
	}

	// 3. Check if an existing MinIO container is stopped and can be started
	// #nosec G204 -- Test utility dynamically targets native docker or wsl CLI to control MinIO test container.
	psCmd := exec.Command(dockerBin, append(prefixArgs, "ps", "-a", "--filter", "name=minio", "--format", "{{.Names}}\t{{.Status}}")...)
	if out, err := psCmd.CombinedOutput(); err == nil {
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		for _, line := range lines {
			parts := strings.Split(line, "\t")
			if len(parts) >= 1 && strings.TrimSpace(parts[0]) != "" {
				cName := strings.TrimSpace(parts[0])
				// Attempt to start existing container
				// #nosec G204 -- Test utility dynamically targets native docker or wsl CLI to control MinIO test container.
				startCmd := exec.Command(dockerBin, append(prefixArgs, "start", cName)...)
				if err := startCmd.Run(); err == nil {
					if pollHealth(healthURL, 5*time.Second) {
						t.Logf("Successfully started existing container %s in %s", cName, dockerBin)
						return endpoint, accessKey, secretKey, func() {}
					}
				}
			}
		}
	}

	// 4. Clean up any stale container binding port 9000
	// #nosec G204 -- Test utility dynamically targets native docker or wsl CLI to control MinIO test container.
	portCmd := exec.Command(dockerBin, append(prefixArgs, "ps", "-a", "--filter", "publish=9000", "--format", "{{.ID}}")...)
	if portOut, err := portCmd.CombinedOutput(); err == nil && len(strings.TrimSpace(string(portOut))) > 0 {
		for _, id := range strings.Fields(string(portOut)) {
			// #nosec G204 -- Test utility dynamically targets native docker or wsl CLI to control MinIO test container.
			_ = exec.Command(dockerBin, append(prefixArgs, "rm", "-f", id)...).Run()
		}
	}

	// 5. Start a new MinIO container
	containerName := fmt.Sprintf("minio-live-e2e-%d", time.Now().UnixNano())
	args := append(prefixArgs, "run", "-d", "--name", containerName,
		"-p", "9000:9000",
		"-e", "MINIO_ROOT_USER=minioadmin",
		"-e", "MINIO_ROOT_PASSWORD=minioadmin",
		"alpine/minio:latest-release", "server", "/tmp/data",
	)

	// #nosec G204 -- Test utility dynamically targets native docker or wsl CLI to control MinIO test container.
	cmd := exec.Command(dockerBin, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to start minio container via %s: %v, out: %s", dockerBin, err, string(out))
	}

	clean := func() {
		stopArgs := append(prefixArgs, "rm", "-f", containerName)
		// #nosec G204 -- Test utility dynamically targets native docker or wsl CLI to control MinIO test container.
		_ = exec.Command(dockerBin, stopArgs...).Run()
	}
	t.Cleanup(clean)

	// 6. Poll until healthy
	if !pollHealth(healthURL, 20*time.Second) {
		t.Fatalf("MinIO container failed to become healthy within 20 seconds")
	}

	return endpoint, accessKey, secretKey, clean
}

// isHealthy checks if the health URL responds with 200 OK.
func isHealthy(healthURL string) bool {
	client := http.Client{Timeout: 1 * time.Second}
	resp, err := client.Get(healthURL)
	if err == nil && resp.StatusCode == http.StatusOK {
		_ = resp.Body.Close()
		return true
	}
	if resp != nil {
		_ = resp.Body.Close()
	}
	return false
}

// pollHealth repeatedly polls healthURL until it returns 200 OK or timeout expires.
func pollHealth(healthURL string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if isHealthy(healthURL) {
			return true
		}
		time.Sleep(300 * time.Millisecond)
	}
	return false
}

// SetupMinIOTLSProxy sets up an authentic TLS/HTTPS reverse proxy fronting MinIO.
// It enforces wire encryption (DO NOT DISABLE SSL constraint) and registers CA certs in
// environment variables AWS_CA_BUNDLE, SSL_CERT_FILE, and process http.DefaultTransport.
func SetupMinIOTLSProxy(t *testing.T, rawEndpoint string) (tlsServer *httptest.Server, tlsEndpoint, caFile string) {
	t.Helper()

	minioTargetURL, err := url.Parse("http://" + rawEndpoint)
	if err != nil {
		t.Fatalf("failed to parse minio URL: %v", err)
	}
	proxy := httputil.NewSingleHostReverseProxy(minioTargetURL)
	tlsServer = httptest.NewTLSServer(proxy)
	t.Cleanup(tlsServer.Close)

	tlsEndpoint = tlsServer.Listener.Addr().String()

	// Configure system and AWS SDK CA trust pool for the TLS server certificate
	tmpDir := t.TempDir()
	caFile = filepath.Join(tmpDir, "ca.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlsServer.Certificate().Raw})
	if err := os.WriteFile(caFile, certPEM, 0o600); err != nil {
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

	return tlsServer, tlsEndpoint, caFile
}

// CreateS3Bucket initializes an S3 bucket over TLS with static credentials.
func CreateS3Bucket(ctx context.Context, endpoint, bucketName, accessKey, secretKey string, httpClient *http.Client) error {
	s3Client := s3.New(s3.Options{
		BaseEndpoint: aws.String("https://" + endpoint),
		Region:       "us-east-1",
		Credentials:  credentials.NewStaticCredentialsProvider(accessKey, secretKey, ""),
		UsePathStyle: true,
		HTTPClient:   httpClient,
	})

	_, err := s3Client.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket: aws.String(bucketName),
	})
	return err
}
