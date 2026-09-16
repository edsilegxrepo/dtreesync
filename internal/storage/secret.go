// Package storage provides cloud blob, Git repository, and filesystem transport abstractions,
// including cryptographically authenticated secret resolution via secretprotector.
//
// Objectives:
//   - Ensure sensitive credentials (Git personal access tokens, SSH passphrases, and cloud keys)
//     are protected using AES-256-GCM encryption via secretprotector (libsecsecrets).
//   - Resolve master keys transparently across CLI flags, environment variables, and protected key files.
//   - Provide in-memory ProtectedSecret handles with strict RAM zeroing to prevent credential leakage.
//   - Decrypt cloud storage credentials transparently so multi-cloud pipelines (S3, GCS, Azure)
//     seamlessly interoperate with encrypted environment variables.
//
// Core Components:
//   - ResolveMasterKey: Multi-tier key resolution (CLI flag > Env Var > Key File) with platform security audits.
//   - DecryptSecret / DecryptSecretBytes: Authenticated AES-256-GCM token decryption with backwards compatibility.
//   - ProtectedSecret: In-memory RAM credential encapsulation with deferred ZeroBuffer wiping.
//   - PrepareCloudAuth: Pre-flight cloud environment resolution decrypting cloud credentials on-demand.
//
// Data Flow:
//
//	Encrypted Tokens / Passwords (v1:gcm:...) -> ResolveMasterKey() -> DecryptSecret() ->
//	Protected RAM Execution -> ZeroBuffer Memory Wiping.
package storage

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/edsilegxrepo/secretprotector/pkg/libsecsecrets"
)

// DefaultMasterKeyEnv is the canonical environment variable name for the SecretProtector master key.
const DefaultMasterKeyEnv = libsecsecrets.DefaultKeyEnv

// EncryptedPrefix identifies ciphertexts encrypted via secretprotector (v1:gcm:).
const EncryptedPrefix = libsecsecrets.EncryptedPrefix

// ResolveMasterKey resolves the 32-byte AES master key from raw input, environment variable, or key file.
// If all inputs are empty, it defaults to checking the standard SECRETPROTECTOR_MASTER_KEY environment variable.
// Callers must invoke libsecsecrets.ZeroBuffer on the returned byte slice when done.
func ResolveMasterKey(ctx context.Context, rawKey, envName, filePath string) ([]byte, error) {
	if rawKey == "" && envName == "" && filePath == "" {
		envName = DefaultMasterKeyEnv
	}
	key, err := libsecsecrets.ResolveKey(ctx, rawKey, envName, filePath)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// DecryptSecret decrypts a credential string if it has the v1:gcm: secretprotector prefix.
// If the string is not encrypted, it is returned unchanged for backwards compatibility.
// If the string is encrypted but masterKey is empty, an error is returned.
func DecryptSecret(ctx context.Context, val string, masterKey []byte) (string, error) {
	cleanVal := strings.TrimSpace(val)
	if cleanVal == "" {
		return "", nil
	}

	if libsecsecrets.IsEncrypted(cleanVal) {
		if len(masterKey) != 32 {
			return "", fmt.Errorf("secret is encrypted with secretprotector (%s) but no valid 32-byte master key was provided", EncryptedPrefix)
		}
		decrypted, err := libsecsecrets.Decrypt(ctx, cleanVal, masterKey)
		if err != nil {
			return "", fmt.Errorf("secretprotector decryption failed: %w", err)
		}
		return decrypted, nil
	}

	// Plaintext fallback for backwards compatibility
	return val, nil
}

// DecryptSecretBytes decrypts a byte slice if it has the v1:gcm: secretprotector prefix.
// If the byte slice is not encrypted, it is returned unchanged.
func DecryptSecretBytes(ctx context.Context, data, masterKey []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, nil
	}

	if libsecsecrets.IsEncryptedBytes(data) {
		if len(masterKey) != 32 {
			return nil, fmt.Errorf("secret bytes are encrypted with secretprotector but no valid 32-byte master key was provided")
		}
		decrypted, err := libsecsecrets.DecryptBytes(ctx, data, masterKey)
		if err != nil {
			return nil, fmt.Errorf("secretprotector byte decryption failed: %w", err)
		}
		return decrypted, nil
	}

	return data, nil
}

// ProtectedSecret encapsulates sensitive credential material in RAM using AES-256-GCM
// via libsecsecrets and enforces strict memory zeroing upon destruction.
type ProtectedSecret struct {
	mu        sync.RWMutex
	key       []byte
	encrypted []byte
}

// NewProtectedSecret encrypts rawSecret into RAM using an ephemeral CSPRNG key.
func NewProtectedSecret(rawSecret string) (*ProtectedSecret, error) {
	ctx := context.Background()
	keyHex, err := libsecsecrets.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("failed generating ephemeral master key: %w", err)
	}
	key, err := libsecsecrets.ResolveKey(ctx, keyHex, "", "")
	if err != nil {
		return nil, fmt.Errorf("failed resolving ephemeral key: %w", err)
	}

	encBytes, err := libsecsecrets.EncryptBytes(ctx, []byte(rawSecret), key)
	if err != nil {
		libsecsecrets.ZeroBuffer(key)
		return nil, fmt.Errorf("failed encrypting secret in RAM: %w", err)
	}

	return &ProtectedSecret{
		key:       key,
		encrypted: encBytes,
	}, nil
}

// Reveal decrypts and returns the plaintext secret bytes.
// Callers MUST invoke libsecsecrets.ZeroBuffer on the returned byte slice immediately after use.
func (ps *ProtectedSecret) Reveal() ([]byte, error) {
	if ps == nil {
		return nil, fmt.Errorf("protected secret is nil")
	}
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	if len(ps.key) == 0 || len(ps.encrypted) == 0 {
		return nil, fmt.Errorf("protected secret unavailable or already destroyed")
	}
	return libsecsecrets.DecryptBytes(context.Background(), ps.encrypted, ps.key)
}

// Destroy zeroes all ephemeral cryptographic keys and encrypted payloads in RAM via ZeroBuffer.
func (ps *ProtectedSecret) Destroy() {
	if ps == nil {
		return
	}
	ps.mu.Lock()
	defer ps.mu.Unlock()

	if len(ps.key) > 0 {
		libsecsecrets.ZeroBuffer(ps.key)
		ps.key = nil
	}
	if len(ps.encrypted) > 0 {
		libsecsecrets.ZeroBuffer(ps.encrypted)
		ps.encrypted = nil
	}
}

// PrepareCloudAuth checks for encrypted cloud credentials in environment variables
// (AWS_SECRET_ACCESS_KEY, AZURE_STORAGE_KEY, AZURE_STORAGE_SAS_TOKEN, GOOGLE_APPLICATION_CREDENTIALS)
// and decrypts them using SecretProtector.
// It returns a cleanup function that restores original environment variables and deletes
// any temporary decrypted credential files.
func PrepareCloudAuth(ctx context.Context, masterKey []byte) (func(), error) {
	// Attempt master key resolution if not explicitly passed
	resolvedKey := masterKey
	var keyNeedsZero bool
	if len(resolvedKey) == 0 {
		k, err := ResolveMasterKey(ctx, "", DefaultMasterKeyEnv, "")
		if err == nil && len(k) == 32 {
			resolvedKey = k
			keyNeedsZero = true
		}
	}

	type envRestore struct {
		key      string
		oldVal   string
		existed  bool
		tempFile string
	}
	var restores []envRestore

	cleanup := func() {
		for _, r := range restores {
			if r.tempFile != "" {
				// Secure wipe temporary file before removal
				// #nosec G703,G304 -- Path originates from os.CreateTemp owned by the current process.
				if data, err := os.ReadFile(r.tempFile); err == nil {
					libsecsecrets.ZeroBuffer(data)
					_ = os.WriteFile(r.tempFile, data, 0o600)
				}
				_ = os.Remove(r.tempFile)
			}
			if r.existed {
				_ = os.Setenv(r.key, r.oldVal)
			} else {
				_ = os.Unsetenv(r.key)
			}
		}
		if keyNeedsZero && len(resolvedKey) > 0 {
			libsecsecrets.ZeroBuffer(resolvedKey)
		}
	}

	// Helper to inspect and decrypt an environment variable
	checkAndDecryptEnv := func(envKey string) error {
		val, exists := os.LookupEnv(envKey)
		if !exists || val == "" {
			return nil
		}
		if libsecsecrets.IsEncrypted(val) {
			if len(resolvedKey) != 32 {
				return fmt.Errorf("environment variable %s is encrypted with secretprotector, but no master key was found", envKey)
			}
			decrypted, err := libsecsecrets.Decrypt(ctx, val, resolvedKey)
			if err != nil {
				return fmt.Errorf("failed to decrypt environment variable %s: %w", envKey, err)
			}
			restores = append(restores, envRestore{key: envKey, oldVal: val, existed: true})
			_ = os.Setenv(envKey, decrypted)
		}
		return nil
	}

	// 1. Check AWS and Azure environment variables
	for _, envKey := range []string{
		"AWS_SECRET_ACCESS_KEY",
		"AWS_SESSION_TOKEN",
		"AZURE_STORAGE_KEY",
		"AZURE_STORAGE_SAS_TOKEN",
	} {
		if err := checkAndDecryptEnv(envKey); err != nil {
			cleanup()
			return nil, err
		}
	}

	// 2. Check GOOGLE_APPLICATION_CREDENTIALS
	if gcpCreds, exists := os.LookupEnv("GOOGLE_APPLICATION_CREDENTIALS"); exists && gcpCreds != "" {
		if libsecsecrets.IsEncrypted(gcpCreds) {
			// Environment variable itself contains the encrypted path or token
			if len(resolvedKey) != 32 {
				cleanup()
				return nil, fmt.Errorf("GOOGLE_APPLICATION_CREDENTIALS is encrypted with secretprotector, but no master key was found")
			}
			decrypted, err := libsecsecrets.Decrypt(ctx, gcpCreds, resolvedKey)
			if err != nil {
				cleanup()
				return nil, fmt.Errorf("failed to decrypt GOOGLE_APPLICATION_CREDENTIALS: %w", err)
			}
			restores = append(restores, envRestore{key: "GOOGLE_APPLICATION_CREDENTIALS", oldVal: gcpCreds, existed: true})
			_ = os.Setenv("GOOGLE_APPLICATION_CREDENTIALS", decrypted)
		} else if _, statErr := os.Stat(gcpCreds); statErr == nil {
			// Credential file exists on disk: inspect if its JSON payload is secretprotector encrypted
			cleanCreds := filepath.Clean(gcpCreds)
			// #nosec G304 -- Google application credentials path is user-configured via environment variable.
			data, err := os.ReadFile(cleanCreds)
			if err == nil && libsecsecrets.IsEncryptedBytes(data) {
				if len(resolvedKey) != 32 {
					cleanup()
					return nil, fmt.Errorf("GOOGLE_APPLICATION_CREDENTIALS file %q is encrypted with secretprotector, but no master key was found", gcpCreds)
				}
				decrypted, err := libsecsecrets.DecryptBytes(ctx, data, resolvedKey)
				if err != nil {
					cleanup()
					return nil, fmt.Errorf("failed to decrypt GOOGLE_APPLICATION_CREDENTIALS file: %w", err)
				}
				defer libsecsecrets.ZeroBuffer(decrypted)

				// Write to secure temporary file with 0600 permissions
				tmpFile, err := os.CreateTemp("", "dtreesync_gcp_cred_*.json")
				if err != nil {
					cleanup()
					return nil, fmt.Errorf("failed to create temporary decrypted credentials file: %w", err)
				}
				tmpPath := tmpFile.Name()
				if _, err := tmpFile.Write(decrypted); err != nil {
					_ = tmpFile.Close()
					_ = os.Remove(tmpPath)
					cleanup()
					return nil, fmt.Errorf("failed to write decrypted credentials file: %w", err)
				}
				_ = tmpFile.Close()
				_ = os.Chmod(tmpPath, 0o600)

				restores = append(restores, envRestore{
					key:      "GOOGLE_APPLICATION_CREDENTIALS",
					oldVal:   gcpCreds,
					existed:  true,
					tempFile: filepath.Clean(tmpPath),
				})
				_ = os.Setenv("GOOGLE_APPLICATION_CREDENTIALS", tmpPath)
			}
		}
	}

	return cleanup, nil
}
