// 文件职责：测试 WebUI POST /api/audit/device-access 单设备允许/禁止外网分流开关与 ConfigStore 即时同步及越权入参拦截。
package webui_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"singctl/internal/audit"
	"singctl/internal/config"
	"singctl/internal/webui"
)

func TestAuditDeviceAccessAPI(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "singctl.yaml")
	sbPath := filepath.Join(tmpDir, "config.json")
	if err := config.Save(cfgPath, &config.Config{}); err != nil {
		t.Fatal(err)
	}
	seedSB := `{"outbounds":[{"tag":"#DC","type":"direct"}],"dns":{"servers":[{"tag":"dns_local","type":"udp","server":"223.5.5.5"}],"rules":[]},"route":{"rules":[{"action":"sniff"}]}}`
	if err := os.WriteFile(sbPath, []byte(seedSB), 0600); err != nil {
		t.Fatal(err)
	}

	srv := webui.New(webui.Options{
		ConfigPath:        cfgPath,
		SingBoxConfigPath: sbPath,
		AdGuardConfigPath: filepath.Join(tmpDir, "missing-agh.yaml"),
	})

	postJSON := func(path string, body any) *httptest.ResponseRecorder {
		var buf bytes.Buffer
		_ = json.NewEncoder(&buf).Encode(body)
		req := httptest.NewRequest(http.MethodPost, path, &buf)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		srv.Mux.ServeHTTP(rec, req)
		return rec
	}

	// 1. Missing allowOverseas or unsafe IP -> 400
	if rec := postJSON("/api/audit/device-access", map[string]any{"deviceIp": "192.168.1.50"}); rec.Code != http.StatusBadRequest {
		t.Fatalf("missing allowOverseas got %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if rec := postJSON("/api/audit/device-access", map[string]any{"deviceIp": "127.0.0.1", "allowOverseas": false}); rec.Code != http.StatusBadRequest {
		t.Fatalf("loopback IP got %d, want 400", rec.Code)
	}
	if rec := postJSON("/api/audit/device-access", map[string]any{"deviceIp": "8.8.8.8", "allowOverseas": false}); rec.Code != http.StatusBadRequest {
		t.Fatalf("public IP got %d, want 400", rec.Code)
	}

	// 2. Disable overseas -> 200, persists config.Store, updates sing-box config.json
	rec := postJSON("/api/audit/device-access", map[string]any{"deviceIp": "192.168.1.50", "allowOverseas": false})
	if rec.Code != http.StatusOK {
		t.Fatalf("disable overseas failed: code=%d body=%s", rec.Code, rec.Body.String())
	}
	var res audit.DeviceAccessResult
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if !res.OK || res.AllowOverseas || len(res.DirectDevices) != 1 || res.DirectDevices[0] != "192.168.1.50" || !res.SingBoxSynced {
		t.Fatalf("unexpected disable response: %+v", res)
	}
	if srv.ConfigStore().Get().Audit.IsDeviceOverseasAllowed("192.168.1.50") {
		t.Fatalf("expected ConfigStore updated immediately to disallow overseas for 192.168.1.50")
	}

	// 3. Re-enable overseas -> 200, clears config and sing-box rule
	rec2 := postJSON("/api/audit/device-access", map[string]any{"deviceIp": "192.168.1.50", "allowOverseas": true})
	if rec2.Code != http.StatusOK {
		t.Fatalf("enable overseas failed: code=%d body=%s", rec2.Code, rec2.Body.String())
	}
	if err := json.Unmarshal(rec2.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if !res.OK || !res.AllowOverseas || len(res.DirectDevices) != 0 {
		t.Fatalf("unexpected enable response: %+v", res)
	}
	sbAfter, _ := os.ReadFile(sbPath)
	if strings.Contains(string(sbAfter), "192.168.1.50") {
		t.Fatalf("expected 192.168.1.50 removed from sing-box config.json, got:\n%s", string(sbAfter))
	}
}
