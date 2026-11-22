// 文件职责：验证客户端网关配置加密灾备导出与原子恢复回滚契约。
package webui_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"singctl/internal/webui"
	"slices"
	"strings"
	"testing"

	"singctl/internal/config"
	"singctl/internal/singbox"
)

func TestClientBackupCrypto_RoundTripAndTamperRejection(t *testing.T) {
	payload := webui.ClientBackupPayload{
		Version:     "1.14.142",
		ExportedAt:  "2026-11-19T17:00:00Z",
		SingctlYAML: "subs:\n  - name: main\n    url: https://sub.example.com/api?token=testtoken\n",
		GroupsYAML:  "version: 1\nmode: merge\ngroups:\n  - name: \"#HK\"\n    type: urltest\n    match: [\"@hk\"]\n",
	}

	if _, err := webui.EncryptClientBackupBundle("1234567", payload); err == nil {
		t.Fatal("expected passphrase < 8 chars to fail")
	}

	envBytes, err := webui.EncryptClientBackupBundle("GatewayPass#2026", payload)
	if err != nil {
		t.Fatalf("webui.EncryptClientBackupBundle failed: %v", err)
	}
	if strings.Contains(string(envBytes), "sub.example.com") || strings.Contains(string(envBytes), "testtoken") {
		t.Fatalf("encrypted envelope leaked plaintext secret")
	}

	if _, err := webui.DecryptClientBackupBundle("WrongPass#2026", envBytes); err == nil {
		t.Fatal("expected wrong passphrase to fail GCM auth")
	}

	// 验证篡改密文会被 GCM 认证拦截
	var envMap map[string]any
	if err := json.Unmarshal(envBytes, &envMap); err != nil {
		t.Fatal(err)
	}
	ct, _ := envMap["ciphertext"].(string)
	envMap["ciphertext"] = "AAAA" + ct[4:]
	tamperedBytes, _ := json.Marshal(envMap)
	if _, err := webui.DecryptClientBackupBundle("GatewayPass#2026", tamperedBytes); err == nil {
		t.Fatal("expected tampered ciphertext to fail")
	}

	// 验证不接受服务端格式的备份信封 ("SINGCTL-BAK-V1")
	serverFmtBytes, _ := json.Marshal(map[string]any{
		"format":     "SINGCTL-BAK-V1",
		"iterations": 210000,
		"salt":       envMap["salt"],
		"nonce":      envMap["nonce"],
		"ciphertext": envMap["ciphertext"],
	})
	if _, err := webui.DecryptClientBackupBundle("GatewayPass#2026", serverFmtBytes); err == nil {
		t.Fatal("expected non-client backup format version to be rejected")
	}

	decoded, err := webui.DecryptClientBackupBundle("GatewayPass#2026", envBytes)
	if err != nil {
		t.Fatalf("webui.DecryptClientBackupBundle failed: %v", err)
	}
	if decoded.SingctlYAML != payload.SingctlYAML || decoded.GroupsYAML != payload.GroupsYAML {
		t.Fatalf("decrypted payload mismatch")
	}
}

func TestHandleClientBackup_ExportRestoreFreshAndLiveReconcile(t *testing.T) {
	srcDir := t.TempDir()
	srcCfgPath := filepath.Join(srcDir, "singctl.yaml")
	srcGroupsPath := filepath.Join(srcDir, "groups.yaml")
	srcAghPath := filepath.Join(srcDir, "AdGuardHome.yaml")
	srcSBPath := filepath.Join(srcDir, "config.json")

	srcYAML := `subs:
  - name: main
    url: https://sub.example.com/client?token=testtoken123
traffic_routing:
  presets:
    netflix:
      enabled: true
      outbound: "#HK"
`
	srcGroups := `version: 1
mode: merge
groups:
  - name: "#HK"
    type: urltest
    match: ["@hk"]
`
	srcAGH := "dns:\n  port: 5353\nuser_rules:\n  - '||ads.example.com^'\n"

	baseSB := buildValidTestSingBoxJSON(t, srcDir)
	var sbDoc map[string]any
	if err := json.Unmarshal([]byte(baseSB), &sbDoc); err != nil {
		t.Fatal(err)
	}
	obs := sbDoc["outbounds"].([]any)
	obs = append(obs, map[string]any{"type": "socks", "tag": "香港-01", "server": "198.51.100.41", "server_port": 1080})
	sbDoc["outbounds"] = obs
	srcSBBytes, _ := json.MarshalIndent(sbDoc, "", "  ")

	for p, data := range map[string][]byte{
		srcCfgPath:    []byte(srcYAML),
		srcGroupsPath: []byte(srcGroups),
		srcAghPath:    []byte(srcAGH),
		srcSBPath:     srcSBBytes,
	} {
		if err := os.WriteFile(p, data, 0600); err != nil {
			t.Fatal(err)
		}
	}

	srcSrv := webui.New(webui.Options{
		ConfigPath:              srcCfgPath,
		SingBoxConfigPath:       srcSBPath,
		AdGuardConfigPath:       srcAghPath,
		SkipAdGuardProbeForTest: true,
		Version:                 "v1.14.142",
		Listen:                  "127.0.0.1:0",
	})

	doPost := func(srv *webui.Server, path string, payload any) *httptest.ResponseRecorder {
		b, _ := json.Marshal(payload)
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Requested-With", "SingCtlWebUI")
		rec := httptest.NewRecorder()
		srv.Mux.ServeHTTP(rec, req)
		return rec
	}

	// 短口令应返回 400
	if recShort := doPost(srcSrv, "/api/backup/export", map[string]any{"passphrase": "short"}); recShort.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for short passphrase, got %d", recShort.Code)
	}

	// 1. 导出加密快照
	recExp := doPost(srcSrv, "/api/backup/export", map[string]any{"passphrase": "StrongGateway#2026"})
	if recExp.Code != http.StatusOK {
		t.Fatalf("export failed: code=%d body=%s", recExp.Code, recExp.Body.String())
	}
	var expResp struct {
		OK       bool   `json:"ok"`
		Filename string `json:"filename"`
		Data     string `json:"data"`
		Summary  struct {
			HasSingctlCfg bool `json:"hasSingctlCfg"`
			HasGroups     bool `json:"hasGroups"`
			HasAdGuard    bool `json:"hasAdGuard"`
			HasSingBox    bool `json:"hasSingBox"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(recExp.Body.Bytes(), &expResp); err != nil {
		t.Fatal(err)
	}
	if !expResp.OK || !expResp.Summary.HasSingctlCfg || !expResp.Summary.HasGroups || !expResp.Summary.HasAdGuard || !expResp.Summary.HasSingBox {
		t.Fatalf("unexpected export response summary: %+v", expResp)
	}
	if strings.Contains(expResp.Data, "testtoken123") || strings.Contains(expResp.Data, "ads.example.com") {
		t.Fatalf("exported envelope contains plaintext data")
	}

	// 2. 还原至全新目标网关目录（无预设文件）
	freshDir := t.TempDir()
	freshCfg := filepath.Join(freshDir, "singctl.yaml")
	freshAgh := filepath.Join(freshDir, "agh", "AdGuardHome.yaml")
	freshSB := filepath.Join(freshDir, "sb", "config.json")
	freshSrv := webui.New(webui.Options{
		ConfigPath:              freshCfg,
		SingBoxConfigPath:       freshSB,
		AdGuardConfigPath:       freshAgh,
		SkipAdGuardProbeForTest: true,
		Listen:                  "127.0.0.1:0",
	})

	recFreshRes := doPost(freshSrv, "/api/backup/restore", map[string]any{
		"passphrase": "StrongGateway#2026",
		"data":       expResp.Data,
	})
	if recFreshRes.Code != http.StatusOK {
		t.Fatalf("fresh restore failed: code=%d body=%s", recFreshRes.Code, recFreshRes.Body.String())
	}
	for _, fpath := range []string{freshCfg, config.GroupsPathForConfig(freshCfg), freshAgh, freshSB} {
		st, statErr := os.Stat(fpath)
		if statErr != nil || st.Mode().Perm() != 0600 {
			t.Fatalf("expected restored file %s with 0600 perm, got %v (err=%v)", fpath, st, statErr)
		}
	}

	// 3. 还原至已运行实例（live config.json 含本机运行态 Clash API secret），验证重编译注入 #HK 且保留运行态 secret
	liveDir := t.TempDir()
	liveCfg := filepath.Join(liveDir, "singctl.yaml")
	liveAgh := filepath.Join(liveDir, "AdGuardHome.yaml")
	liveSB := filepath.Join(liveDir, "config.json")
	if err := os.WriteFile(liveCfg, []byte("subs:\n  - name: old\n    url: https://old.example.com/sub\n"), 0600); err != nil {
		t.Fatal(err)
	}
	liveBase := buildValidTestSingBoxJSON(t, liveDir)
	var liveDoc map[string]any
	_ = json.Unmarshal([]byte(liveBase), &liveDoc)
	liveObs := liveDoc["outbounds"].([]any)
	liveObs = append(liveObs, map[string]any{"type": "socks", "tag": "香港-99", "server": "198.51.100.99", "server_port": 1080})
	liveDoc["outbounds"] = liveObs
	liveDoc["experimental"] = map[string]any{
		"clash_api": map[string]any{
			"external_controller": "127.0.0.1:9090",
			"secret":              "live-secret-keep",
		},
		"cache_file": map[string]any{
			"enabled": true,
			"path":    filepath.Join(liveDir, "cache.db"),
		},
	}
	liveBytes, _ := json.MarshalIndent(liveDoc, "", "  ")
	if err := os.WriteFile(liveSB, liveBytes, 0600); err != nil {
		t.Fatal(err)
	}

	liveSrv := webui.New(webui.Options{
		ConfigPath:              liveCfg,
		SingBoxConfigPath:       liveSB,
		AdGuardConfigPath:       liveAgh,
		SkipAdGuardProbeForTest: true,
		Listen:                  "127.0.0.1:0",
	})
	recLiveRes := doPost(liveSrv, "/api/backup/restore", map[string]any{
		"passphrase": "StrongGateway#2026",
		"data":       expResp.Data,
	})
	if recLiveRes.Code != http.StatusOK {
		t.Fatalf("live reconcile restore failed: code=%d body=%s", recLiveRes.Code, recLiveRes.Body.String())
	}

	reconciledBytes, err := os.ReadFile(liveSB)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(reconciledBytes), "live-secret-keep") {
		t.Fatalf("expected live Clash secret preserved during restore reconcile")
	}
	liveGroups, _ := singbox.InspectClientRoutingOutbounds(string(reconciledBytes))
	var tags []string
	for _, g := range liveGroups {
		tags = append(tags, g.Tag)
	}
	if !slices.Contains(tags, "#HK") {
		t.Fatalf("expected restored groups.yaml (#HK) compiled into live config.json, got %v", tags)
	}
}
