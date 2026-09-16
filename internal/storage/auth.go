// Package storage provides cloud blob, Git repository, and filesystem transport abstractions.
//
// Objectives:
//   - Provide secure credential resolution for Git transports (SSH keys, SSH agent, HTTPS bearer tokens).
//   - Enable zero-disk streaming of snapshot artifacts to S3, Google Cloud Storage, and Azure Blob Storage.
//   - Maintain in-memory Git commit pipelines for Configuration-as-Code directory topology tracking.
//
// Core Components:
//   - GitAuthOptions: Configuration structure holding credential settings.
//   - ResolveGitAuth: Determines the appropriate go-git transport authentication mechanism (SSH vs HTTPS).
//
// Data Flow:
//
//	CLI Flags / Environment Variables -> ResolveGitAuth() -> transport.AuthMethod -> Git Remote Handshake.
package storage

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/edsilegxrepo/secretprotector/pkg/libsecsecrets"
	"github.com/go-git/go-git/v5/plumbing/transport"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
	gitssh "github.com/go-git/go-git/v5/plumbing/transport/ssh"
)

// GitAuthOptions holds credentials and authentication parameters for remote Git operations.
type GitAuthOptions struct {
	Username      string // Optional: Git username (defaults to "git" for SSH)
	Password      string // Optional: password or personal access token (may be plaintext or encrypted via secretprotector)
	SSHKeyPath    string // Optional: path to private key (file may be plaintext or encrypted via secretprotector)
	SSHPassphrase string // Optional: passphrase for private key (may be plaintext or encrypted via secretprotector)
	UseSSHAgent   bool   // Optional: attempt ssh-agent discovery
	MasterKey     string // Optional: SecretProtector AES-256-GCM master key (hex or raw)
	MasterKeyEnv  string // Optional: environment variable containing master key (defaults to SECRETPROTECTOR_MASTER_KEY)
	MasterKeyFile string // Optional: path to file containing master key
}

// ResolveGitAuth resolves the appropriate transport.AuthMethod based on environment variables or explicit options,
// automatically decrypting secretprotector-encrypted credentials.
func ResolveGitAuth(opts GitAuthOptions, isSSH bool) (transport.AuthMethod, error) {
	return ResolveGitAuthContext(context.Background(), opts, isSSH)
}

// ResolveGitAuthContext resolves the appropriate transport.AuthMethod within the given context.
func ResolveGitAuthContext(ctx context.Context, opts GitAuthOptions, isSSH bool) (transport.AuthMethod, error) {
	// Attempt master key resolution
	masterKey, _ := ResolveMasterKey(ctx, opts.MasterKey, opts.MasterKeyEnv, opts.MasterKeyFile)
	if len(masterKey) > 0 {
		defer libsecsecrets.ZeroBuffer(masterKey)
	}

	if isSSH {
		user := opts.Username
		if user == "" {
			user = "git"
		}

		// Resolve and decrypt SSH passphrase
		passphrase := opts.SSHPassphrase
		if passphrase == "" {
			passphrase = os.Getenv("GIT_SSH_PASSPHRASE")
		}
		decryptedPassphrase, err := DecryptSecret(ctx, passphrase, masterKey)
		if err != nil {
			return nil, fmt.Errorf("failed resolving SSH passphrase: %w", err)
		}

		// 1. Direct SSH Key path
		keyPath := opts.SSHKeyPath
		if keyPath == "" {
			keyPath = os.Getenv("GIT_SSH_KEY")
		}

		if keyPath != "" {
			cleanKeyPath := filepath.Clean(keyPath)
			// #nosec G304,G703 -- SSH private key path is user-supplied configuration verified via filepath.Clean.
			if data, readErr := os.ReadFile(cleanKeyPath); readErr == nil {
				if libsecsecrets.IsEncryptedBytes(data) {
					decBytes, decErr := DecryptSecretBytes(ctx, data, masterKey)
					if decErr != nil {
						return nil, fmt.Errorf("failed decrypting SSH private key file %q: %w", keyPath, decErr)
					}
					defer libsecsecrets.ZeroBuffer(decBytes)
					auth, err := gitssh.NewPublicKeys(user, decBytes, decryptedPassphrase)
					if err != nil {
						return nil, fmt.Errorf("failed loading decrypted SSH key from %q: %w", keyPath, err)
					}
					return auth, nil
				}
				auth, err := gitssh.NewPublicKeysFromFile(user, keyPath, decryptedPassphrase)
				if err != nil {
					return nil, fmt.Errorf("failed to load SSH key from %q: %w", keyPath, err)
				}
				return auth, nil
			} else if libsecsecrets.IsEncrypted(keyPath) {
				decKey, decErr := DecryptSecret(ctx, keyPath, masterKey)
				if decErr != nil {
					return nil, fmt.Errorf("failed decrypting SSH private key string: %w", decErr)
				}
				keyBytes := []byte(decKey)
				defer libsecsecrets.ZeroBuffer(keyBytes)
				auth, err := gitssh.NewPublicKeys(user, keyBytes, decryptedPassphrase)
				if err != nil {
					return nil, fmt.Errorf("failed loading decrypted SSH key: %w", err)
				}
				return auth, nil
			}

			auth, err := gitssh.NewPublicKeysFromFile(user, keyPath, decryptedPassphrase)
			if err != nil {
				return nil, fmt.Errorf("failed to load SSH key from %q: %w", keyPath, err)
			}
			return auth, nil
		}

		// 2. Default ~/.ssh/id_rsa or ~/.ssh/id_ed25519
		home, err := os.UserHomeDir()
		if err == nil {
			for _, candidate := range []string{"id_ed25519", "id_rsa"} {
				candidatePath := filepath.Join(home, ".ssh", candidate)
				if _, err := os.Stat(candidatePath); err == nil {
					auth, err := gitssh.NewPublicKeysFromFile(user, candidatePath, decryptedPassphrase)
					if err == nil {
						return auth, nil
					}
				}
			}
		}

		// 3. Try SSH agent
		auth, err := gitssh.NewSSHAgentAuth(user)
		if err == nil {
			return auth, nil
		}

		return nil, fmt.Errorf("no valid SSH credentials found for user %q", user)
	}

	// HTTPS Auth
	user := opts.Username
	token := opts.Password

	if token == "" {
		token = os.Getenv("GIT_TOKEN")
		if token == "" {
			token = os.Getenv("GITHUB_TOKEN")
			if token == "" {
				token = os.Getenv("GITLAB_TOKEN")
			}
		}
	}

	if token != "" {
		decryptedToken, err := DecryptSecret(ctx, token, masterKey)
		if err != nil {
			return nil, fmt.Errorf("failed resolving Git token: %w", err)
		}
		if user == "" {
			user = "x-access-token"
		}
		return &githttp.BasicAuth{
			Username: user,
			Password: decryptedToken,
		}, nil
	}

	return nil, nil
}
