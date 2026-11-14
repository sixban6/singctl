package deploy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"singctl/internal/config"
	"singctl/internal/constant"
)

func withTempMtlsEnv(t *testing.T) (parentSingctlDir, vaultDir, caddyConfDir, caddyMtlsDir string) {
	t.Helper()
	base := t.TempDir()
	parentSingctlDir = filepath.Join(base, "singctl")
	vaultDir = filepath.Join(parentSingctlDir, "mtls")
	caddyConfDir = filepath.Join(base, "caddy")
	caddyMtlsDir = filepath.Join(caddyConfDir, "mtls")

	origVault := constant.SingctlMtlsDir
	origCaddyConf := constant.CaddyConfigDir
	origCaddyMtls := constant.CaddyMtlsDir
	origCaddyCA := constant.CaddyMtlsCACert
	t.Cleanup(func() {
		constant.SingctlMtlsDir = origVault
		constant.CaddyConfigDir = origCaddyConf
		constant.CaddyMtlsDir = origCaddyMtls
		constant.CaddyMtlsCACert = origCaddyCA
	})

	constant.SingctlMtlsDir = vaultDir
	constant.CaddyConfigDir = caddyConfDir
	constant.CaddyMtlsDir = caddyMtlsDir
	constant.CaddyMtlsCACert = filepath.Join(vaultDir, "ca.crt")
	return parentSingctlDir, vaultDir, caddyConfDir, caddyMtlsDir
}

func newTestWebTerminalConfig() *config.Config {
	return &config.Config{
		Server: config.ServerConfig{
			NodeDomain: "node.example.com",
			CFDNSKey:   "cf-test-token",
			Sni:        "swdist.apple.com",
			WebTerminal: config.WebTerminalConfig{
				Enabled:       true,
				Port:          18080,
				Path:          "/term-test",
				SSHTunnelPort: 18081,
				SSHTunnelPath: "/ssh-ws",
				SSHPort:       2222,
			},
		},
	}
}

func TestMigrateLegacyCaddyMtlsToVault(t *testing.T) {
	parentSingctlDir, vaultDir, _, caddyMtlsDir := withTempMtlsEnv(t)

	// Simulate legacy 0700 /etc/singctl directory that previously blocked caddy user traversal.
	if err := os.MkdirAll(parentSingctlDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parentSingctlDir, 0700); err != nil {
		t.Fatal(err)
	}

	if err := os.MkdirAll(caddyMtlsDir, 0755); err != nil {
		t.Fatal(err)
	}
	legacy := map[string]string{
		"ca.crt":     "-----BEGIN CERTIFICATE-----\nTEST-CA\n-----END CERTIFICATE-----\n",
		"client.p12": "TEST-P12-BINARY",
		"client.crt": "-----BEGIN CERTIFICATE-----\nTEST-CLIENT\n-----END CERTIFICATE-----\n",
		"client.key": "-----BEGIN PRIVATE KEY-----\nTEST-CLIENT-KEY\n-----END PRIVATE KEY-----\n",
	}
	for name, content := range legacy {
		if err := os.WriteFile(filepath.Join(caddyMtlsDir, name), []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}

	if err := MigrateLegacyCaddyMtlsToVault(); err != nil {
		t.Fatalf("MigrateLegacyCaddyMtlsToVault failed: %v", err)
	}

	pInfo, err := os.Stat(parentSingctlDir)
	if err != nil {
		t.Fatalf("stat parent dir: %v", err)
	}
	if pInfo.Mode().Perm() != 0711 {
		t.Fatalf("expected parent /etc/singctl perm upgraded from 0700 to 0711, got %o", pInfo.Mode().Perm())
	}

	for name, want := range legacy {
		vPath := filepath.Join(vaultDir, name)
		data, rErr := os.ReadFile(vPath)
		if rErr != nil {
			t.Fatalf("expected migrated file %s in vault: %v", vPath, rErr)
		}
		if string(data) != want {
			t.Fatalf("content mismatch for %s: got %q want %q", name, string(data), want)
		}
		fi, sErr := os.Stat(vPath)
		if sErr != nil {
			t.Fatalf("stat %s: %v", vPath, sErr)
		}
		wantPerm := os.FileMode(0600)
		if name == "ca.crt" {
			wantPerm = 0640
		}
		if fi.Mode().Perm() != wantPerm {
			t.Fatalf("expected %o on %s, got %o", wantPerm, vPath, fi.Mode().Perm())
		}
	}

	// Since no active Caddyfile referenced caddyMtlsDir, the deprecated directory must be removed completely.
	if _, err := os.Stat(caddyMtlsDir); !os.IsNotExist(err) {
		t.Fatalf("expected legacy %s removed completely, stat err=%v", caddyMtlsDir, err)
	}
}

func TestEnsureCaddyMtlsTrustPool_NormalizesLegacyAndSingleSource(t *testing.T) {
	_, vaultDir, _, caddyMtlsDir := withTempMtlsEnv(t)

	const caPEM = "-----BEGIN CERTIFICATE-----\nVAULT-CA\n-----END CERTIFICATE-----\n"
	if err := SaveMtlsBundleToVault(map[string][]byte{
		"ca.crt":     []byte(caPEM),
		"client.p12": []byte("VAULT-P12"),
		"client.crt": []byte("VAULT-CRT"),
		"client.key": []byte("VAULT-KEY"),
	}); err != nil {
		t.Fatalf("SaveMtlsBundleToVault failed: %v", err)
	}

	resolved, ready, err := EnsureCaddyMtlsTrustPool("/etc/caddy/mtls/ca.crt")
	if err != nil {
		t.Fatalf("EnsureCaddyMtlsTrustPool failed: %v", err)
	}
	if !ready {
		t.Fatal("expected ready=true when vault contains ca.crt")
	}
	wantCA := filepath.Join(vaultDir, "ca.crt")
	if resolved != wantCA {
		t.Fatalf("expected legacy /etc/caddy/mtls/ca.crt normalized to %s, got %s", wantCA, resolved)
	}
	if _, err := os.Stat(caddyMtlsDir); !os.IsNotExist(err) {
		t.Fatalf("deprecated %s must NOT be created", caddyMtlsDir)
	}
}

func TestPrepareRuntimeCaddyConfig_DegradesWithoutCA(t *testing.T) {
	withTempMtlsEnv(t)

	cfg := newTestWebTerminalConfig()
	eff := prepareRuntimeCaddyConfig(cfg)
	if eff.Server.WebTerminal.Enabled {
		t.Fatal("expected effective runtime config to disable WebTerminal when CA is missing")
	}
	if !cfg.Server.WebTerminal.Enabled {
		t.Fatal("caller config WebTerminal.Enabled must NOT be mutated")
	}

	rendered, err := PreviewCaddyfile(eff)
	if err != nil {
		t.Fatalf("PreviewCaddyfile failed: %v", err)
	}
	if strings.Contains(rendered, "trust_pool") || strings.Contains(rendered, "client_auth") {
		t.Fatalf("expected degraded Caddyfile without mTLS directives, got:\n%s", rendered)
	}
}

func TestSyncCaddyfile_AtomicValidationRollbackAndLegacyCleanup(t *testing.T) {
	_, vaultDir, caddyConfDir, caddyMtlsDir := withTempMtlsEnv(t)
	if err := os.MkdirAll(caddyMtlsDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(caddyMtlsDir, "ca.crt"), []byte("-----BEGIN CERTIFICATE-----\nLEGACY-CA\n-----END CERTIFICATE-----\n"), 0640); err != nil {
		t.Fatal(err)
	}

	caddyfile := filepath.Join(caddyConfDir, "Caddyfile")
	initialContent := "trust_pool file " + filepath.Join(caddyMtlsDir, "ca.crt") + "\n"
	if err := os.WriteFile(caddyfile, []byte(initialContent), 0640); err != nil {
		t.Fatal(err)
	}

	binDir := t.TempDir()
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	writeStub := func(name, script string) {
		t.Helper()
		p := filepath.Join(binDir, name)
		if err := os.WriteFile(p, []byte(script), 0755); err != nil {
			t.Fatal(err)
		}
	}

	cfg := newTestWebTerminalConfig()
	cfg.Server.WebTerminal.MtlsCA = "/etc/caddy/mtls/ca.crt"

	// 1. Failing caddy validate must reject replacement cleanly before overwriting Caddyfile or deleting legacy CA.
	writeStub("caddy", "#!/bin/sh\necho 'invalid syntax' >&2\nexit 1\n")
	writeStub("systemctl", "#!/bin/sh\nexit 0\n")
	if err := SyncCaddyfile(cfg); err == nil {
		t.Fatal("expected SyncCaddyfile to fail when caddy validate returns non-zero")
	}
	gotAfterValidateFail, _ := os.ReadFile(caddyfile)
	if string(gotAfterValidateFail) != initialContent {
		t.Fatalf("Caddyfile mutated despite validation failure: %q", string(gotAfterValidateFail))
	}
	bakData, err := os.ReadFile(caddyfile + ".bak")
	if err != nil || string(bakData) != initialContent {
		t.Fatalf("expected .bak containing initial Caddyfile, got %q err=%v", string(bakData), err)
	}

	// 2. Passing validate + failing reload/restart must roll back Caddyfile to initialContent.
	writeStub("caddy", "#!/bin/sh\nexit 0\n")
	writeStub("systemctl", "#!/bin/sh\nexit 1\n")
	if err := SyncCaddyfile(cfg); err == nil {
		t.Fatal("expected SyncCaddyfile to fail when systemctl reload/restart fails")
	}
	gotAfterRollback, _ := os.ReadFile(caddyfile)
	if string(gotAfterRollback) != initialContent {
		t.Fatalf("expected Caddyfile rolled back to %q, got %q", initialContent, string(gotAfterRollback))
	}

	// 3. Passing validate + passing systemctl -> Caddyfile points to /etc/singctl/mtls/ca.crt and legacy /etc/caddy/mtls is deleted.
	writeStub("systemctl", "#!/bin/sh\nexit 0\n")
	if err := SyncCaddyfile(cfg); err != nil {
		t.Fatalf("expected SyncCaddyfile to succeed: %v", err)
	}
	finalCaddyfile, err := os.ReadFile(caddyfile)
	if err != nil {
		t.Fatal(err)
	}
	wantTrustPool := "trust_pool file " + filepath.Join(vaultDir, "ca.crt")
	if !strings.Contains(string(finalCaddyfile), wantTrustPool) {
		t.Fatalf("expected unified trust_pool %q in Caddyfile, got:\n%s", wantTrustPool, string(finalCaddyfile))
	}
	if _, err := os.Stat(caddyMtlsDir); !os.IsNotExist(err) {
		t.Fatalf("expected deprecated %s deleted after successful Caddy reload, stat err=%v", caddyMtlsDir, err)
	}
}
