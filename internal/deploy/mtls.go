package deploy

import (
	"bytes"
	"cmp"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"singctl/internal/constant"
)

var allowedMtlsFiles = []string{"ca.crt", "client.p12", "client.crt", "client.key"}

var initDefaultCaddyMtlsCACert = constant.CaddyMtlsCACert

// MtlsVaultDir returns the persistent root-only directory holding mTLS certificates and keys.
func MtlsVaultDir() string {
	return cmp.Or(strings.TrimSpace(constant.SingctlMtlsDir), "/etc/singctl/mtls")
}

// VaultMtlsFilePath returns the vault path for an allowlisted mTLS artifact name.
func VaultMtlsFilePath(name string) string {
	return filepath.Join(MtlsVaultDir(), filepath.Base(name))
}

// DefaultCaddyMtlsCACertPath returns the runtime Caddy CA trust_pool path, respecting test overrides.
func DefaultCaddyMtlsCACertPath() string {
	if constant.CaddyMtlsCACert != "" && constant.CaddyMtlsCACert != initDefaultCaddyMtlsCACert {
		return constant.CaddyMtlsCACert
	}
	if dir := strings.TrimSpace(constant.CaddyMtlsDir); dir != "" {
		return filepath.Join(dir, "ca.crt")
	}
	return cmp.Or(constant.CaddyMtlsCACert, "/etc/caddy/mtls/ca.crt")
}

func caddyMtlsDir() string {
	return cmp.Or(strings.TrimSpace(constant.CaddyMtlsDir), "/etc/caddy/mtls")
}

func caddyConfigDir() string {
	return cmp.Or(strings.TrimSpace(constant.CaddyConfigDir), "/etc/caddy")
}

// MigrateLegacyCaddyMtlsToVault copies any existing legacy mTLS artifacts from Caddy's directory
// into the persistent 0700/0600 vault and strips private key material from Caddy's directory.
func MigrateLegacyCaddyMtlsToVault() error {
	legacyDir := filepath.Clean(caddyMtlsDir())
	vaultDir := filepath.Clean(MtlsVaultDir())

	// Only touch the vault directory if either legacy artifacts exist or vault already exists.
	hasLegacy := false
	for _, name := range allowedMtlsFiles {
		if info, err := os.Stat(filepath.Join(legacyDir, name)); err == nil && !info.IsDir() && info.Size() > 0 {
			hasLegacy = true
			break
		}
	}
	if _, err := os.Stat(vaultDir); err == nil {
		if chErr := ensureVaultDir(vaultDir); chErr != nil {
			return chErr
		}
	} else if !hasLegacy {
		return nil
	} else if mkErr := ensureVaultDir(vaultDir); mkErr != nil {
		return mkErr
	}

	if hasLegacy {
		for _, name := range allowedMtlsFiles {
			vaultPath := filepath.Join(vaultDir, name)
			legacyPath := filepath.Join(legacyDir, name)

			vInfo, vErr := os.Stat(vaultPath)
			needCopy := vErr != nil || vInfo.Size() == 0
			if needCopy {
				data, rErr := os.ReadFile(legacyPath)
				if rErr == nil && len(data) > 0 {
					if wErr := writeFileAtomicWithMode(vaultPath, data, 0600); wErr != nil {
						return fmt.Errorf("migrate mTLS artifact %s to vault: %w", name, wErr)
					}
					vInfo, vErr = os.Stat(vaultPath)
				}
			}

			// Strip private/client keys from Caddy's directory once safely stored in vault.
			if name != "ca.crt" && legacyDir != vaultDir && vErr == nil && vInfo.Size() > 0 {
				_ = os.Remove(legacyPath)
			}
		}
	}

	// Enforce 0600 on all existing vault artifacts.
	for _, name := range allowedMtlsFiles {
		vaultPath := filepath.Join(vaultDir, name)
		if info, err := os.Stat(vaultPath); err == nil && !info.IsDir() {
			_ = os.Chmod(vaultPath, 0600)
		}
	}
	return nil
}

// SaveMtlsBundleToVault validates and atomically writes allowlisted mTLS artifacts with 0700/0600 modes.
func SaveMtlsBundleToVault(files map[string][]byte) error {
	if len(files) == 0 {
		return nil
	}
	vaultDir := MtlsVaultDir()
	if err := ensureVaultDir(vaultDir); err != nil {
		return err
	}
	for rawName, data := range files {
		name := strings.TrimSpace(rawName)
		if name == "" || !slices.Contains(allowedMtlsFiles, name) {
			return fmt.Errorf("disallowed mTLS artifact name: %q", rawName)
		}
		if len(data) == 0 {
			continue
		}
		if err := writeFileAtomicWithMode(filepath.Join(vaultDir, name), data, 0600); err != nil {
			return fmt.Errorf("save mTLS artifact %s: %w", name, err)
		}
	}
	return nil
}

// LoadMtlsBundleFromVault returns all allowlisted mTLS files currently stored in the persistent vault.
func LoadMtlsBundleFromVault() map[string][]byte {
	_ = MigrateLegacyCaddyMtlsToVault()
	vaultDir := MtlsVaultDir()
	out := make(map[string][]byte)
	for _, name := range allowedMtlsFiles {
		data, err := os.ReadFile(filepath.Join(vaultDir, name))
		if err == nil && len(data) > 0 {
			out[name] = data
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// EnsureCaddyMtlsTrustPool ensures the public mTLS CA cert exists and is readable by the Caddy process.
// It restores missing ca.crt from the persistent vault when available.
func EnsureCaddyMtlsTrustPool(configuredCAPath string) (resolvedCAPath string, ready bool, err error) {
	resolvedCAPath = cmp.Or(strings.TrimSpace(configuredCAPath), DefaultCaddyMtlsCACertPath())
	if mErr := MigrateLegacyCaddyMtlsToVault(); mErr != nil {
		return resolvedCAPath, false, mErr
	}

	targetDir := filepath.Dir(resolvedCAPath)
	managedCaddyMtlsDir := filepath.Clean(targetDir) == filepath.Clean(caddyMtlsDir())

	existingData, rErr := os.ReadFile(resolvedCAPath)
	if rErr != nil || len(bytes.TrimSpace(existingData)) == 0 {
		vaultCA := filepath.Join(MtlsVaultDir(), "ca.crt")
		vaultData, vErr := os.ReadFile(vaultCA)
		if vErr != nil || len(bytes.TrimSpace(vaultData)) == 0 {
			return resolvedCAPath, false, nil
		}

		if err := applyCaddyReadableDir(targetDir); err != nil {
			return resolvedCAPath, false, fmt.Errorf("prepare caddy mTLS dir %s: %w", targetDir, err)
		}
		if err := writeFileAtomicWithMode(resolvedCAPath, vaultData, 0644); err != nil {
			return resolvedCAPath, false, fmt.Errorf("project mTLS ca.crt to %s: %w", resolvedCAPath, err)
		}
		if err := applyCaddyReadableFile(resolvedCAPath); err != nil {
			return resolvedCAPath, false, fmt.Errorf("set permissions on %s: %w", resolvedCAPath, err)
		}
		return resolvedCAPath, true, nil
	}

	if managedCaddyMtlsDir {
		if err := applyCaddyReadableDir(targetDir); err != nil {
			return resolvedCAPath, false, fmt.Errorf("update permissions on %s: %w", targetDir, err)
		}
	}
	if err := applyCaddyReadableFile(resolvedCAPath); err != nil {
		return resolvedCAPath, false, fmt.Errorf("update permissions on %s: %w", resolvedCAPath, err)
	}
	return resolvedCAPath, true, nil
}

// RemoveMtlsAll removes both the persistent mTLS vault and Caddy's projected mTLS directory.
func RemoveMtlsAll() error {
	err1 := os.RemoveAll(MtlsVaultDir())
	err2 := os.RemoveAll(caddyMtlsDir())
	if err1 != nil {
		return err1
	}
	return err2
}

func ensureVaultDir(dir string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create mTLS vault %s: %w", dir, err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return fmt.Errorf("chmod mTLS vault %s: %w", dir, err)
	}
	return nil
}

func applyCaddyReadableDir(dir string) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	if os.Geteuid() == 0 {
		if gid, err := lookupCaddyGID(); err == nil {
			if err := os.Chown(dir, 0, gid); err != nil {
				return err
			}
			return os.Chmod(dir, 0750)
		}
	}
	return os.Chmod(dir, 0755)
}

func applyCaddyReadableFile(path string) error {
	if os.Geteuid() == 0 {
		if gid, err := lookupCaddyGID(); err == nil {
			if err := os.Chown(path, 0, gid); err != nil {
				return err
			}
			return ensureFilePermissions(path, 0640)
		}
	}
	return ensureFilePermissions(path, 0644)
}

func writeFileAtomicWithMode(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp.*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()

	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	cleanup = false
	return ensureFilePermissions(path, perm)
}
