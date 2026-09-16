// Package storage provides direct cloud blob streaming implementations.
//
// Objectives:
//   - Enable zero-disk-write direct streaming to and from multi-cloud object storage (AWS S3, GCS, Azure Blob).
//   - Support file:// scheme for local blob testing and emulation.
//   - Automatically manage bucket opening, multipart uploads, and lifecycle closure.
//
// Core Components:
//   - IsCloudURL / ParseCloudURL: Validates and splits cloud URIs into root bucket identifiers and object keys.
//   - NewCloudWriter: Creates an authenticated streaming WriteCloser connected directly to the cloud blob provider.
//   - NewCloudReader: Creates an authenticated streaming ReadCloser downloading from cloud object storage.
//   - bucketWriterWrapper / bucketReaderWrapper: Ensures underlying blob.Bucket resources close cleanly on stream finish.
//
// Data Flow:
//
//	Engine Output Stream -> NewCloudWriter -> Go Cloud Development Kit (blob.Writer) -> Cloud Storage (S3/GCS/Azure).
//	Cloud Storage (S3/GCS/Azure) -> Go Cloud Development Kit (blob.Reader) -> NewCloudReader -> Engine Input Stream.
package storage

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"strings"

	"gocloud.dev/blob"
	_ "gocloud.dev/blob/azureblob"
	_ "gocloud.dev/blob/fileblob"
	_ "gocloud.dev/blob/gcsblob"
	_ "gocloud.dev/blob/s3blob"
)

// Supported cloud URL schemes.
const (
	SchemeS3     = "s3"
	SchemeGCS    = "gs"
	SchemeAzBlob = "azblob"
	SchemeFile   = "file"
)

// IsCloudURL determines if the specified target string represents a cloud blob URI.
func IsCloudURL(rawURL string) bool {
	lower := strings.ToLower(rawURL)
	return strings.HasPrefix(lower, "s3://") ||
		strings.HasPrefix(lower, "gs://") ||
		strings.HasPrefix(lower, "azblob://") ||
		strings.HasPrefix(lower, "file://")
}

// ParseCloudURL extracts the bucket URL and relative object key from a full cloud URI.
func ParseCloudURL(rawURL string) (bucketURL, key string, err error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", "", fmt.Errorf("invalid cloud URL %q: %w", rawURL, err)
	}

	scheme := strings.ToLower(u.Scheme)
	if scheme != SchemeS3 && scheme != SchemeGCS && scheme != SchemeAzBlob && scheme != SchemeFile {
		return "", "", fmt.Errorf("unsupported cloud storage scheme: %q", u.Scheme)
	}

	if scheme == SchemeFile {
		// file:///abs/path/to/bucket/key
		path := u.Path
		idx := strings.LastIndex(path, "/")
		if idx <= 0 {
			return "", "", fmt.Errorf("invalid file URL for blob storage: %q", rawURL)
		}
		bucketPath := path[:idx]
		key = path[idx+1:]
		bucketURL = "file://" + bucketPath + "?create_dir=true"
		return bucketURL, key, nil
	}

	if u.Host == "" {
		return "", "", fmt.Errorf("missing bucket name in cloud URL %q", rawURL)
	}

	bucketURL = fmt.Sprintf("%s://%s", scheme, u.Host)
	if u.RawQuery != "" {
		bucketURL += "?" + u.RawQuery
	}
	key = strings.TrimPrefix(u.Path, "/")
	if key == "" {
		return "", "", fmt.Errorf("missing object key in cloud URL %q", rawURL)
	}

	return bucketURL, key, nil
}

type bucketWriterWrapper struct {
	w       *blob.Writer
	bucket  *blob.Bucket
	cleanup func()
}

func (b *bucketWriterWrapper) Write(p []byte) (int, error) {
	return b.w.Write(p)
}

func (b *bucketWriterWrapper) Close() error {
	defer func() {
		if b.cleanup != nil {
			b.cleanup()
		}
	}()
	writeErr := b.w.Close()
	bucketErr := b.bucket.Close()
	if writeErr != nil {
		return writeErr
	}
	return bucketErr
}

// NewCloudWriter establishes an authenticated streaming multipart upload pipeline
// directly into AWS S3, Google Cloud Storage, or Azure Blob Storage without local disk spooling.
func NewCloudWriter(ctx context.Context, rawURL string) (io.WriteCloser, error) {
	return NewCloudWriterWithKey(ctx, rawURL, nil)
}

// NewCloudWriterWithKey establishes an authenticated streaming multipart upload pipeline
// directly into AWS S3, Google Cloud Storage, or Azure Blob Storage, decrypting any
// secretprotector-encrypted credentials using the provided masterKey (or DefaultMasterKeyEnv).
func NewCloudWriterWithKey(ctx context.Context, rawURL string, masterKey []byte) (io.WriteCloser, error) {
	cleanup, err := PrepareCloudAuth(ctx, masterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare cloud authentication: %w", err)
	}

	bucketURL, key, err := ParseCloudURL(rawURL)
	if err != nil {
		if cleanup != nil {
			cleanup()
		}
		return nil, err
	}

	b, err := blob.OpenBucket(ctx, bucketURL)
	if err != nil {
		if cleanup != nil {
			cleanup()
		}
		return nil, fmt.Errorf("failed to open cloud bucket %q: %w", bucketURL, err)
	}

	w, err := b.NewWriter(ctx, key, nil)
	if err != nil {
		_ = b.Close()
		if cleanup != nil {
			cleanup()
		}
		return nil, fmt.Errorf("failed to initialize cloud blob writer for key %q: %w", key, err)
	}

	return &bucketWriterWrapper{
		w:       w,
		bucket:  b,
		cleanup: cleanup,
	}, nil
}

type bucketReaderWrapper struct {
	r       *blob.Reader
	bucket  *blob.Bucket
	cleanup func()
}

func (b *bucketReaderWrapper) Read(p []byte) (int, error) {
	return b.r.Read(p)
}

func (b *bucketReaderWrapper) Close() error {
	defer func() {
		if b.cleanup != nil {
			b.cleanup()
		}
	}()
	readErr := b.r.Close()
	bucketErr := b.bucket.Close()
	if readErr != nil {
		return readErr
	}
	return bucketErr
}

// NewCloudReader establishes an authenticated streaming read pipeline
// directly from AWS S3, Google Cloud Storage, or Azure Blob Storage.
func NewCloudReader(ctx context.Context, rawURL string) (io.ReadCloser, error) {
	return NewCloudReaderWithKey(ctx, rawURL, nil)
}

// NewCloudReaderWithKey establishes an authenticated streaming read pipeline
// directly from AWS S3, Google Cloud Storage, or Azure Blob Storage, decrypting any
// secretprotector-encrypted credentials using the provided masterKey (or DefaultMasterKeyEnv).
func NewCloudReaderWithKey(ctx context.Context, rawURL string, masterKey []byte) (io.ReadCloser, error) {
	cleanup, err := PrepareCloudAuth(ctx, masterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare cloud authentication: %w", err)
	}

	bucketURL, key, err := ParseCloudURL(rawURL)
	if err != nil {
		if cleanup != nil {
			cleanup()
		}
		return nil, err
	}

	b, err := blob.OpenBucket(ctx, bucketURL)
	if err != nil {
		if cleanup != nil {
			cleanup()
		}
		return nil, fmt.Errorf("failed to open cloud bucket %q: %w", bucketURL, err)
	}

	r, err := b.NewReader(ctx, key, nil)
	if err != nil {
		_ = b.Close()
		if cleanup != nil {
			cleanup()
		}
		return nil, fmt.Errorf("failed to open cloud blob reader for key %q: %w", key, err)
	}

	return &bucketReaderWrapper{
		r:       r,
		bucket:  b,
		cleanup: cleanup,
	}, nil
}
