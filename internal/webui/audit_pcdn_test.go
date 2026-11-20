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

func TestAuditThrottleAPI_SetAndRemove(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "singctl.yaml")
	if err := os.WriteFile(cfgPath, configs.ClientConfigYAML, 0600); err != nil {
		t.Fatal(err)
	}

	srv := New(Options{
		ConfigPath: cfgPath,
		Listen:     "127.0.0.1:0",
		Password:   "secret-throttle-test",
		Version:    "v1.14.148",
	})
	ts := httptest.NewServer(srv.Mux)
	defer ts.Close()
	token := srv.SessionToken()

	doThrottle := func(payload map[string]any) (*http.Response, map[string]any) {
		body, _ := json.Marshal(payload)
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/audit/throttle", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		resp.Body.Close()
		return resp, out
	}

	// 1. 设置限速 -> 成功持久化 0600
	resp1, out1 := doThrottle(map[string]any{
		"target":   "iot-cloud.example.com",
		"port":     443,
		"rateKbps": 5,
		"comment":  "IoT 心跳限速",
	})
	if resp1.StatusCode != http.StatusOK || out1["action"] != "throttled" {
		t.Fatalf("POST /api/audit/throttle add failed: status=%d body=%+v", resp1.StatusCode, out1)
	}
	cfgLoaded, err := config.Load(cfgPath)
	if err != nil || len(cfgLoaded.Audit.Throttles) != 1 || cfgLoaded.Audit.Throttles[0].RateKBps != 5 {
		t.Fatalf("expected persisted throttle rule, got err=%v throttles=%+v", err, cfgLoaded.Audit.Throttles)
	}
	if fi, statErr := os.Stat(cfgPath); statErr != nil || fi.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 mode on %s, got %v err=%v", cfgPath, fi.Mode().Perm(), statErr)
	}

	// 2. 核心保护 IP (8.8.8.8) 必须拒绝
	respBad, _ := doThrottle(map[string]any{"target": "8.8.8.8", "port": 443, "rateKbps": 5})
	if respBad.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 rejecting protected DNS IP 8.8.8.8, got %d", respBad.StatusCode)
	}

	// 3. rateKbps <= 0 解除限速并清理持久化字段
	resp2, out2 := doThrottle(map[string]any{
		"target":   "iot-cloud.example.com",
		"port":     443,
		"rateKbps": 0,
	})
	if resp2.StatusCode != http.StatusOK || out2["action"] != "removed" {
		t.Fatalf("POST /api/audit/throttle remove failed: status=%d body=%+v", resp2.StatusCode, out2)
	}
	cfgCleared, err := config.Load(cfgPath)
	if err != nil || len(cfgCleared.Audit.Throttles) != 0 {
		t.Fatalf("expected throttles cleared, got err=%v throttles=%+v", err, cfgCleared.Audit.Throttles)
	}
}
