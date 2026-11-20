package webui

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"singctl/configs"
	"singctl/internal/config"
	"singctl/internal/singbox"
)

func TestWebUI_AuditPCDNBlockToggleAPI(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "singctl.yaml")
	if err := os.WriteFile(cfgPath, configs.ClientConfigYAML, 0600); err != nil {
		t.Fatal(err)
	}
	sbPath := filepath.Join(tmpDir, "config.json")
	if err := os.WriteFile(sbPath, []byte(`{"dns":{"servers":[{"tag":"dns_local","type":"udp","server":"127.0.0.1"}],"rules":[{"clash_mode":"Direct","server":"dns_local"}]},"route":{"rules":[{"action":"sniff"},{"ip_is_private":true,"outbound":"#DC"}]}}`), 0600); err != nil {
		t.Fatal(err)
	}

	srv := New(Options{
		ConfigPath:        cfgPath,
		SingBoxConfigPath: sbPath,
		Listen:            "127.0.0.1:0",
		Password:          "secret-pcdn-test",
		Version:           "v1.14.147",
	})
	ts := httptest.NewServer(srv.Mux)
	defer ts.Close()
	token := srv.SessionToken()

	postToggle := func(enabled bool) map[string]any {
		body, _ := json.Marshal(map[string]bool{"enabled": enabled})
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/audit/pcdn-block", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("POST /api/audit/pcdn-block(%v) status=%d", enabled, resp.StatusCode)
		}
		var out map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatal(err)
		}
		return out
	}

	// 1. 先关闭 -> 持久化 pcdn_block: false 并确保 sing-box 无 block-builtin-pcdn
	offResp := postToggle(false)
	if offResp["pcdnBlockEnabled"] != false {
		t.Fatalf("expected pcdnBlockEnabled=false, got %+v", offResp)
	}
	cfgOff, err := config.Load(cfgPath)
	if err != nil || cfgOff.Audit.IsPCDNBlockEnabled() {
		t.Fatalf("expected persisted PCDNBlock=false, got %v (err=%v)", cfgOff.Audit.PCDNBlock, err)
	}

	// 2. 再重新开启 -> 恢复 default true 并向 sbPath 注入 block-builtin-pcdn
	onResp := postToggle(true)
	if onResp["pcdnBlockEnabled"] != true || onResp["singboxSynced"] != true {
		t.Fatalf("expected pcdnBlockEnabled=true & singboxSynced=true, got %+v", onResp)
	}
	cfgOn, err := config.Load(cfgPath)
	if err != nil || !cfgOn.Audit.IsPCDNBlockEnabled() {
		t.Fatalf("expected persisted PCDNBlockEnabled=true, err=%v", err)
	}
	sbAfter, _ := os.ReadFile(sbPath)
	if !strings.Contains(string(sbAfter), singbox.BuiltinPCDNRuleSetTag) {
		t.Fatalf("expected %s injected into sing-box config, got:\n%s", singbox.BuiltinPCDNRuleSetTag, string(sbAfter))
	}
}
