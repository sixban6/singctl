package deploy

import (
	"bytes"
	"cmp"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"singctl/internal/config"
	"singctl/internal/constant"
)

const LegacyCaddyMtlsCACert = "/etc/caddy/mtls/ca.crt"

var allowedMtlsFiles = []string{"ca.crt", "client.p12", "client.crt", "client.key"}

var initDefaultCaddyMtlsCACert = constant.CaddyMtlsCACert

// MtlsVaultDir returns the persistent directory holding mTLS certificates and keys (/etc/singctl/mtls).
func MtlsVaultDir() string {
	return cmp.Or(strings.TrimSpace(constant.SingctlMtlsDir), "/etc/singctl/mtls")
}

// VaultMtlsFilePath returns the vault path for an allowlisted mTLS artifact name.
func VaultMtlsFilePath(name string) string {
	return filepath.Join(MtlsVaultDir(), filepath.Base(name))
}

// DefaultCaddyMtlsCACertPath returns the canonical mTLS CA trust_pool path (/etc/singctl/mtls/ca.crt),
// respecting test overrides.
func DefaultCaddyMtlsCACertPath() string {
	if constant.CaddyMtlsCACert != "" && constant.CaddyMtlsCACert != initDefaultCaddyMtlsCACert {
		return constant.CaddyMtlsCACert
	}
	return filepath.Join(MtlsVaultDir(), "ca.crt")
}

// IsLegacyCaddyMtlsCAPath reports whether raw points to the deprecated /etc/caddy/mtls/ca.crt location.
func IsLegacyCaddyMtlsCAPath(raw string) bool {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return false
	}
	clean := filepath.Clean(trimmed)
	if clean == LegacyCaddyMtlsCACert {
		return true
	}
	legacyDir := filepath.Clean(caddyMtlsDir())
	return legacyDir != "" && clean == filepath.Join(legacyDir, "ca.crt")
}

// NormalizeMtlsCAPath resolves empty or legacy /etc/caddy/mtls/ca.crt paths to /etc/singctl/mtls/ca.crt,
// while preserving any explicit custom CA path configured by the operator.
func NormalizeMtlsCAPath(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || IsLegacyCaddyMtlsCAPath(trimmed) {
		return DefaultCaddyMtlsCACertPath()
	}
	return trimmed
}

// UpgradeLegacyMtlsConfig rewrites deprecated /etc/caddy/mtls/ca.crt in cfg to /etc/singctl/mtls/ca.crt.
func UpgradeLegacyMtlsConfig(cfg *config.Config) bool {
	if cfg == nil {
		return false
	}
	cur := strings.TrimSpace(cfg.Server.WebTerminal.MtlsCA)
	if cur != "" && IsLegacyCaddyMtlsCAPath(cur) {
		cfg.Server.WebTerminal.MtlsCA = DefaultCaddyMtlsCACertPath()
		return true
	}
	return false
}

func caddyMtlsDir() string {
	return cmp.Or(strings.TrimSpace(constant.CaddyMtlsDir), "/etc/caddy/mtls")
}

func caddyConfigDir() string {
	return cmp.Or(strings.TrimSpace(constant.CaddyConfigDir), "/etc/caddy")
}

// MigrateLegacyCaddyMtlsToVault rescues any legacy mTLS artifacts from /etc/caddy/mtls into
// /etc/singctl/mtls, enforces strict least-privilege traversal/read permissions, and strips legacy files.
func MigrateLegacyCaddyMtlsToVault() error {
	legacyDir := filepath.Clean(caddyMtlsDir())
	vaultDir := filepath.Clean(MtlsVaultDir())

	hasLegacy := false
	if legacyDir != vaultDir {
		for _, name := range allowedMtlsFiles {
			if info, err := os.Stat(filepath.Join(legacyDir, name)); err == nil && !info.IsDir() && info.Size() > 0 {
				hasLegacy = true
				break
			}
		}
	}

	vaultExists := false
	if st, err := os.Stat(vaultDir); err == nil && st.IsDir() {
		vaultExists = true
	}
	if !vaultExists && !hasLegacy {
		return nil
	}
	if err := ensureVaultDir(vaultDir); err != nil {
		return err
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
					perm := os.FileMode(0600)
					if name == "ca.crt" {
						perm = 0640
					}
					if wErr := writeFileAtomicWithMode(vaultPath, data, perm); wErr != nil {
						return fmt.Errorf("migrate mTLS artifact %s to vault: %w", name, wErr)
					}
					vInfo, vErr = os.Stat(vaultPath)
				}
			}

			// Always strip private/client keys from legacy Caddy directory immediately.
			if name != "ca.crt" && legacyDir != vaultDir && vErr == nil && vInfo.Size() > 0 {
				_ = os.Remove(legacyPath)
			}
		}

		// Remove legacy /etc/caddy/mtls immediately if Caddyfile does not currently reference it.
		if !activeCaddyfileReferencesDir(legacyDir) {
			_ = os.RemoveAll(legacyDir)
		}
	}

	return applyVaultArtifactPermissions(vaultDir)
}

// CleanupLegacyCaddyMtlsDir migrates any leftover artifacts and removes the deprecated /etc/caddy/mtls directory.
func CleanupLegacyCaddyMtlsDir() {
	legacyDir := filepath.Clean(caddyMtlsDir())
	vaultDir := filepath.Clean(MtlsVaultDir())
	if legacyDir == "" || legacyDir == "/" || legacyDir == "." || legacyDir == vaultDir {
		return
	}
	_ = MigrateLegacyCaddyMtlsToVault()
	_ = os.RemoveAll(legacyDir)
}

func activeCaddyfileReferencesDir(dir string) bool {
	data, err := os.ReadFile(filepath.Join(caddyConfigDir(), "Caddyfile"))
	if err != nil || len(data) == 0 {
		return false
	}
	return strings.Contains(string(data), dir)
}

// SaveMtlsBundleToVault validates and atomically writes allowlisted mTLS artifacts into /etc/singctl/mtls.
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
		perm := os.FileMode(0600)
		if name == "ca.crt" {
			perm = 0640
		}
		if err := writeFileAtomicWithMode(filepath.Join(vaultDir, name), data, perm); err != nil {
			return fmt.Errorf("save mTLS artifact %s: %w", name, err)
		}
	}
	return applyVaultArtifactPermissions(vaultDir)
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

// EnsureCaddyMtlsTrustPool ensures the mTLS CA cert exists in /etc/singctl/mtls/ca.crt (or an explicit custom path)
// and enforces traversal/read permissions so the caddy user can read ca.crt while private keys stay 0600 root-only.
func EnsureCaddyMtlsTrustPool(configuredCAPath string) (resolvedCAPath string, ready bool, err error) {
	resolvedCAPath = NormalizeMtlsCAPath(configuredCAPath)
	if mErr := MigrateLegacyCaddyMtlsToVault(); mErr != nil {
		return resolvedCAPath, false, mErr
	}

	vaultDir := filepath.Clean(MtlsVaultDir())
	vaultCA := filepath.Join(vaultDir, "ca.crt")

	existingData, rErr := os.ReadFile(resolvedCAPath)
	if rErr != nil || len(bytes.TrimSpace(existingData)) == 0 {
		if filepath.Clean(resolvedCAPath) == vaultCA {
			return resolvedCAPath, false, nil
		}
		vaultData, vErr := os.ReadFile(vaultCA)
		if vErr != nil || len(bytes.TrimSpace(vaultData)) == 0 {
			return resolvedCAPath, false, nil
		}
		if err := applyCaddyReadableDir(filepath.Dir(resolvedCAPath)); err != nil {
			return resolvedCAPath, false, fmt.Errorf("prepare custom mTLS dir %s: %w", filepath.Dir(resolvedCAPath), err)
		}
		if err := writeFileAtomicWithMode(resolvedCAPath, vaultData, 0640); err != nil {
			return resolvedCAPath, false, fmt.Errorf("write custom mTLS ca.crt %s: %w", resolvedCAPath, err)
		}
		if err := applyCaddyReadableFile(resolvedCAPath); err != nil {
			return resolvedCAPath, false, fmt.Errorf("set permissions on %s: %w", resolvedCAPath, err)
		}
		return resolvedCAPath, true, nil
	}

	if filepath.Clean(filepath.Dir(resolvedCAPath)) == vaultDir {
		if err := ensureVaultDir(vaultDir); err != nil {
			return resolvedCAPath, false, err
		}
		if err := applyVaultArtifactPermissions(vaultDir); err != nil {
			return resolvedCAPath, false, err
		}
		return resolvedCAPath, true, nil
	}

	if err := applyCaddyReadableFile(resolvedCAPath); err != nil {
		return resolvedCAPath, false, fmt.Errorf("update permissions on %s: %w", resolvedCAPath, err)
	}
	return resolvedCAPath, true, nil
}

// RemoveMtlsAll removes the persistent mTLS vault and any deprecated /etc/caddy/mtls directory.
func RemoveMtlsAll() error {
	err1 := os.RemoveAll(MtlsVaultDir())
	legacyDir := filepath.Clean(caddyMtlsDir())
	var err2 error
	if legacyDir != "" && legacyDir != "/" && legacyDir != "." && legacyDir != filepath.Clean(MtlsVaultDir()) {
		err2 = os.RemoveAll(legacyDir)
	}
	if err1 != nil {
		return err1
	}
	return err2
}

// ensureVaultDir ensures /etc/singctl has traversal bits (e.g. 0711 so non-root cannot ls it, while caddy can traverse)
// and sets /etc/singctl/mtls to 0710 root:caddy when running as root with a caddy group (otherwise 0700).
func ensureVaultDir(dir string) error {
	parent := filepath.Dir(filepath.Clean(dir))
	if parent != "" && parent != "/" && parent != "." {
		if err := os.MkdirAll(parent, 0711); err != nil {
			return fmt.Errorf("create parent dir %s: %w", parent, err)
		}
		if pInfo, err := os.Stat(parent); err == nil && pInfo.IsDir() {
			perm := pInfo.Mode().Perm()
			if perm&0111 != 0111 {
				_ = os.Chmod(parent, perm|0111)
			}
		}
	}

	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create mTLS vault %s: %w", dir, err)
	}
	if os.Geteuid() == 0 {
		if gid, err := lookupCaddyGID(); err == nil {
			if err := os.Chown(dir, 0, gid); err != nil {
				return fmt.Errorf("chown mTLS vault %s: %w", dir, err)
			}
			if err := os.Chmod(dir, 0710); err != nil {
				return fmt.Errorf("chmod mTLS vault %s: %w", dir, err)
			}
			return nil
		}
		if err := os.Chmod(dir, 0711); err != nil {
			return fmt.Errorf("chmod mTLS vault %s: %w", dir, err)
		}
		return nil
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return fmt.Errorf("chmod mTLS vault %s: %w", dir, err)
	}
	return nil
}

func applyVaultArtifactPermissions(vaultDir string) error {
	for _, name := range allowedMtlsFiles {
		p := filepath.Join(vaultDir, name)
		info, err := os.Stat(p)
		if err != nil || info.IsDir() {
			continue
		}
		if name == "ca.crt" {
			if err := applyCaddyReadableFile(p); err != nil {
				return err
			}
			continue
		}
		if os.Geteuid() == 0 {
			_ = os.Chown(p, 0, 0)
		}
		if err := ensureFilePermissions(p, 0600); err != nil {
			return err
		}
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
		return ensureFilePermissions(path, 0644)
	}
	return ensureFilePermissions(path, 0640)
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
