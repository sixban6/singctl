// 文件职责：覆盖服务端 AES-256-GCM 加密灾备快照导出、恢复、mTLS 证书保险库往返、0600 权限与舰队密钥路径重写单测。
package serverweb_test

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
	"singctl/internal/fleet"
	"singctl/internal/serverweb"
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
		"client.key": []byte("MOCK-MTLS-BACKUP-KEY-MATERIAL\n"),
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

	srcSrv := serverweb.New(serverweb.Options{
		ConfigPath:        srcCfg,
		SingBoxConfigPath: srcSbCfg,
		SubStoreDir:       srcSubDir,
		FleetFilePath:     srcFleet,
		Username:          "opsadmin",
		Password:          "Password123",
	})
	defer srcSrv.Limiter().Close()

	payload := srcSrv.BuildBackupPayload()
	if len(payload.MtlsFiles) != len(mtlsFixtures) {
		t.Fatalf("expected %d mtls files in backup payload, got %d", len(mtlsFixtures), len(payload.MtlsFiles))
	}
	for name, want := range mtlsFixtures {
		if string(payload.MtlsFiles[name]) != string(want) {
			t.Fatalf("backup payload mismatch for %s", name)
		}
	}

	envBytes, err := serverweb.EncryptBackupBundle("StrongPass#2026", payload)
	if err != nil {
		t.Fatalf("EncryptBackupBundle failed: %v", err)
	}
	decPayload, err := serverweb.DecryptBackupBundle("StrongPass#2026", envBytes)
	if err != nil {
		t.Fatalf("DecryptBackupBundle failed: %v", err)
	}
	if len(decPayload.MtlsFiles) != len(mtlsFixtures) {
		t.Fatalf("decrypted mtls files count mismatch: got %d", len(decPayload.MtlsFiles))
	}

	_ = os.RemoveAll(vaultDir)

	dstDir := t.TempDir()
	dstCfg := filepath.Join(dstDir, "singctl.yaml")
	dstSbCfg := filepath.Join(dstDir, "singbox.json")
	dstSubDir := filepath.Join(dstDir, "sub-store")
	dstFleet := filepath.Join(dstDir, "fleet.yaml")
	_ = os.WriteFile(dstCfg, []byte("server:\n  node_domain: \"placeholder.example.com\"\n"), 0600)
	_ = os.WriteFile(dstSbCfg, []byte(`{"inbounds":[]}`), 0600)

	dstSrv := serverweb.New(serverweb.Options{
		ConfigPath:        dstCfg,
		SingBoxConfigPath: dstSbCfg,
		SubStoreDir:       dstSubDir,
		FleetFilePath:     dstFleet,
		Username:          "opsadmin",
		Password:          "Password123",
	})
	defer dstSrv.Limiter().Close()

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

	legacyEnv, err := serverweb.EncryptBackupBundle("StrongPass#2026", serverweb.BackupPayload{
		SingctlYAML: "server:\n  node_domain: \"legacy.example.com\"\n  web_admin:\n    username: \"opsadmin\"\n    password: \"Password123\"\n",
	})
	if err != nil {
		t.Fatalf("encrypt legacy payload: %v", err)
	}
	if rec := doRestore(legacyEnv); rec.Code != http.StatusOK {
		t.Fatalf("expected legacy backup without MtlsFiles to restore cleanly, got %d %s", rec.Code, rec.Body.String())
	}
}

func TestServerWeb_BackupExportAndRestore(t *testing.T) {
	srcDir := t.TempDir()
	srcCfg := filepath.Join(srcDir, "singctl.yaml")
	srcSbCfg := filepath.Join(srcDir, "singbox.json")
	srcSubDir := filepath.Join(srcDir, "sub-store")
	srcFleet := filepath.Join(srcDir, "fleet.yaml")
	srcKeysDir := filepath.Join(srcDir, "fleet_keys")

	if err := os.MkdirAll(srcSubDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(srcKeysDir, 0700); err != nil {
		t.Fatal(err)
	}

	origSingctlYAML := `server:
  node_domain: "master.example.com"
  cf_dns_key: "cf-test-token"
  sni: "swdist.apple.com"
  web_admin:
    username: "opsadmin"
    password: "Password123"
`
	origFleetYAML := `nodes:
  - id: jp1
    name: 日本东京
    host: 198.51.100.20
    port: 2222
    user: root
    auth_type: key_file
    key_path: ` + filepath.Join(srcKeysDir, "jp1.key") + `
    domain: jp1.example.com
    auto_sync: true
`
	dummyKeyContent := []byte("TEST-SSH-KEY-MATERIAL-JP1\n")

	_ = os.WriteFile(srcCfg, []byte(origSingctlYAML), 0600)
	_ = os.WriteFile(srcSbCfg, []byte(`{"inbounds":[]}`), 0600)
	_ = os.WriteFile(filepath.Join(srcSubDir, "sub-store.json"), []byte(`{"subs":[{"name":"auto_generated_hy2","content":"hysteria2://11111111-1111-1111-1111-111111111111@jp1.example.com:443/#JP1"}]}`), 0600)
	_ = os.WriteFile(filepath.Join(srcSubDir, "key"), []byte("subkey-example-123456"), 0600)
	_ = os.WriteFile(srcFleet, []byte(origFleetYAML), 0600)
	_ = os.WriteFile(filepath.Join(srcKeysDir, "jp1.key"), dummyKeyContent, 0600)

	srcSrv := serverweb.New(serverweb.Options{
		ConfigPath:        srcCfg,
		SingBoxConfigPath: srcSbCfg,
		SubStoreDir:       srcSubDir,
		FleetFilePath:     srcFleet,
		Username:          "opsadmin",
		Password:          "Password123",
	})
	defer srcSrv.Limiter().Close()

	doReq := func(s *serverweb.Server, method, target, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, target, strings.NewReader(body))
		req.SetBasicAuth("opsadmin", "Password123")
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		s.Mux.ServeHTTP(rec, req)
		return rec
	}

	if rec := doReq(srcSrv, http.MethodPost, "/api/server/backup/export", `{"passphrase":"short"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for short passphrase, got %d", rec.Code)
	}

	recExp := doReq(srcSrv, http.MethodPost, "/api/server/backup/export", `{"passphrase":"StrongPass#2026"}`)
	if recExp.Code != http.StatusOK {
		t.Fatalf("export backup failed: %d %s", recExp.Code, recExp.Body.String())
	}
	var expResp struct {
		Filename      string `json:"filename"`
		Data          string `json:"data"`
		HasSingctlCfg bool   `json:"hasSingctlCfg"`
		HasFleet      bool   `json:"hasFleet"`
		FleetKeyCount int    `json:"fleetKeyCount"`
		HasSubStore   bool   `json:"hasSubStore"`
	}
	if err := json.Unmarshal(recExp.Body.Bytes(), &expResp); err != nil {
		t.Fatalf("unmarshal export response: %v", err)
	}
	if expResp.Data == "" || !expResp.HasSingctlCfg || !expResp.HasFleet || expResp.FleetKeyCount != 1 || !expResp.HasSubStore {
		t.Fatalf("unexpected export payload: %+v", expResp)
	}

	rawEnvelope := []byte(expResp.Data)
	if strings.Contains(string(rawEnvelope), "master.example.com") || strings.Contains(string(rawEnvelope), "cf-test-token") {
		t.Fatalf("encrypted envelope leaked plaintext sensitive fields!")
	}
	if _, err := serverweb.DecryptBackupBundle("WrongPass#2026", rawEnvelope); err == nil {
		t.Fatalf("expected error decrypting with wrong passphrase")
	}

	dstDir := t.TempDir()
	dstCfg := filepath.Join(dstDir, "singctl.yaml")
	dstSbCfg := filepath.Join(dstDir, "singbox.json")
	dstSubDir := filepath.Join(dstDir, "sub-store")
	dstFleet := filepath.Join(dstDir, "fleet.yaml")

	_ = os.WriteFile(dstCfg, []byte("server:\n  node_domain: \"placeholder.example.com\"\n"), 0600)
	_ = os.WriteFile(dstSbCfg, []byte(`{"inbounds":[]}`), 0600)

	dstSrv := serverweb.New(serverweb.Options{
		ConfigPath:        dstCfg,
		SingBoxConfigPath: dstSbCfg,
		SubStoreDir:       dstSubDir,
		FleetFilePath:     dstFleet,
		Username:          "opsadmin",
		Password:          "Password123",
	})
	defer dstSrv.Limiter().Close()

	restoreReqBody, _ := json.Marshal(map[string]string{
		"passphrase": "StrongPass#2026",
		"data":       expResp.Data,
	})
	recRes := doReq(dstSrv, http.MethodPost, "/api/server/backup/restore", string(restoreReqBody))
	if recRes.Code != http.StatusOK {
		t.Fatalf("restore backup failed: %d %s", recRes.Code, recRes.Body.String())
	}

	restoredKeyPath := filepath.Join(dstDir, "fleet_keys", "jp1.key")
	gotKey, err := os.ReadFile(restoredKeyPath)
	if err != nil {
		t.Fatalf("expected restored fleet key at %s: %v", restoredKeyPath, err)
	}
	if string(gotKey) != string(dummyKeyContent) {
		t.Fatalf("restored key content mismatch: %q", string(gotKey))
	}

	for _, checkFile := range []string{
		dstCfg,
		dstFleet,
		restoredKeyPath,
		filepath.Join(dstSubDir, "sub-store.json"),
		filepath.Join(dstSubDir, "key"),
	} {
		st, err := os.Stat(checkFile)
		if err != nil {
			t.Fatalf("stat restored file %s: %v", checkFile, err)
		}
		if st.Mode().Perm() != 0600 {
			t.Fatalf("expected 0600 perm on %s, got %o", checkFile, st.Mode().Perm())
		}
	}

	restoredFleetRaw, _ := os.ReadFile(dstFleet)
	if !strings.Contains(string(restoredFleetRaw), restoredKeyPath) {
		t.Fatalf("expected fleet.yaml key_path rewritten to %s, got:\n%s", restoredKeyPath, string(restoredFleetRaw))
	}

	if _, err := fleet.SanitizeKeyFilename("../../etc/passwd"); err == nil {
		t.Fatalf("expected path traversal rejection")
	}
}
