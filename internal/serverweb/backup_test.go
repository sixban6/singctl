package serverweb

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"singctl/internal/constant"
	"singctl/internal/deploy"
)

func TestBackupMtlsBundleRoundTripAndLegacyCompat(t *testing.T) {
	base := t.TempDir()
	vaultDir := filepath.Join(base, "singctl", "mtls")
	caddyConfDir := filepath.Join(base, "caddy")
	caddyMtlsDir := filepath.Join(caddyConfDir, "mtls")

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

	mtlsFixtures := map[string][]byte{
		"ca.crt":     []byte("-----BEGIN CERTIFICATE-----\nBACKUP-CA\n-----END CERTIFICATE-----\n"),
		"client.p12": []byte("BACKUP-P12-BYTES"),
		"client.crt": []byte("-----BEGIN CERTIFICATE-----\nBACKUP-CLIENT\n-----END CERTIFICATE-----\n"),
		"client.key": []byte("-----BEGIN PRIVATE KEY-----\nBACKUP-KEY\n-----END PRIVATE KEY-----\n"),
	}
	if err := deploy.SaveMtlsBundleToVault(mtlsFixtures); err != nil {
		t.Fatalf("SaveMtlsBundleToVault failed: %v", err)
	}

	srcDir := t.TempDir()
	srcCfg := filepath.Join(srcDir, "singctl.yaml")
	srcSbCfg := filepath.Join(srcDir, "singbox.json")
	srcSubDir := filepath.Join(srcDir, "sub-store")
	srcFleet := filepath.Join(srcDir, "fleet.yaml")
	srcYAML := "server:\n  node_domain: \"src.example.com\"\n  cf_dns_key: \"cf-test-token\"\n  web_terminal:\n    enabled: true\n    mtls_ca: \"/etc/caddy/mtls/ca.crt\"\n  web_admin:\n    username: \"opsadmin\"\n    password: \"Password123\"\n"
	_ = os.WriteFile(srcCfg, []byte(srcYAML), 0600)
	_ = os.WriteFile(srcSbCfg, []byte(`{"inbounds":[]}`), 0600)

	srcSrv := New(Options{
		ConfigPath:        srcCfg,
		SingBoxConfigPath: srcSbCfg,
		SubStoreDir:       srcSubDir,
		FleetFilePath:     srcFleet,
		Username:          "opsadmin",
		Password:          "Password123",
	})

	payload := srcSrv.buildBackupPayload()
	if len(payload.MtlsFiles) != len(mtlsFixtures) {
		t.Fatalf("expected %d mtls files in backup payload, got %d", len(mtlsFixtures), len(payload.MtlsFiles))
	}
	for name, want := range mtlsFixtures {
		if string(payload.MtlsFiles[name]) != string(want) {
			t.Fatalf("backup payload mismatch for %s", name)
		}
	}

	envBytes, err := EncryptBackupBundle("StrongPass#2026", payload)
	if err != nil {
		t.Fatalf("EncryptBackupBundle failed: %v", err)
	}
	decPayload, err := DecryptBackupBundle("StrongPass#2026", envBytes)
	if err != nil {
		t.Fatalf("DecryptBackupBundle failed: %v", err)
	}
	if len(decPayload.MtlsFiles) != len(mtlsFixtures) {
		t.Fatalf("decrypted mtls files count mismatch: got %d", len(decPayload.MtlsFiles))
	}

	// Simulate fresh target machine with wiped vault.
	_ = os.RemoveAll(vaultDir)

	dstDir := t.TempDir()
	dstCfg := filepath.Join(dstDir, "singctl.yaml")
	dstSbCfg := filepath.Join(dstDir, "singbox.json")
	dstSubDir := filepath.Join(dstDir, "sub-store")
	dstFleet := filepath.Join(dstDir, "fleet.yaml")
	_ = os.WriteFile(dstCfg, []byte("server:\n  node_domain: \"placeholder.example.com\"\n"), 0600)
	_ = os.WriteFile(dstSbCfg, []byte(`{"inbounds":[]}`), 0600)

	dstSrv := New(Options{
		ConfigPath:        dstCfg,
		SingBoxConfigPath: dstSbCfg,
		SubStoreDir:       dstSubDir,
		FleetFilePath:     dstFleet,
		Username:          "opsadmin",
		Password:          "Password123",
	})

	doRestore := func(data []byte) *httptest.ResponseRecorder {
		reqBody, _ := json.Marshal(map[string]string{
			"passphrase": "StrongPass#2026",
			"data":       string(data),
		})
		req := httptest.NewRequest(http.MethodPost, "/api/server/backup/restore", strings.NewReader(string(reqBody)))
		req.SetBasicAuth("opsadmin", "Password123")
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		dstSrv.Mux.ServeHTTP(rec, req)
		return rec
	}

	if rec := doRestore(envBytes); rec.Code != http.StatusOK {
		t.Fatalf("restore with mTLS bundle failed: %d %s", rec.Code, rec.Body.String())
	}

	for name, want := range mtlsFixtures {
		p := filepath.Join(vaultDir, name)
		got, rErr := os.ReadFile(p)
		if rErr != nil || string(got) != string(want) {
			t.Fatalf("expected restored vault file %s with matching content, got err=%v", p, rErr)
		}
		st, _ := os.Stat(p)
		wantPerm := os.FileMode(0600)
		if name == "ca.crt" {
			wantPerm = 0640
		}
		if st.Mode().Perm() != wantPerm {
			t.Fatalf("expected %o mode on restored vault file %s, got %o", wantPerm, p, st.Mode().Perm())
		}
	}

	if _, err := os.Stat(caddyMtlsDir); !os.IsNotExist(err) {
		t.Fatalf("deprecated Caddy mTLS dir %s must not be created on restore", caddyMtlsDir)
	}

	restoredCfgBytes, _ := os.ReadFile(dstCfg)
	if !strings.Contains(string(restoredCfgBytes), filepath.Join(vaultDir, "ca.crt")) {
		t.Fatalf("expected restored singctl.yaml mtls_ca auto-upgraded to %s, got:\n%s", filepath.Join(vaultDir, "ca.crt"), string(restoredCfgBytes))
	}

	// Legacy backup payload without MtlsFiles must still restore cleanly.
	legacyEnv, err := EncryptBackupBundle("StrongPass#2026", backupPayload{
		SingctlYAML: "server:\n  node_domain: \"legacy.example.com\"\n  web_admin:\n    username: \"opsadmin\"\n    password: \"Password123\"\n",
	})
	if err != nil {
		t.Fatalf("encrypt legacy payload: %v", err)
	}
	if rec := doRestore(legacyEnv); rec.Code != http.StatusOK {
		t.Fatalf("expected legacy backup without MtlsFiles to restore cleanly, got %d %s", rec.Code, rec.Body.String())
	}
}
