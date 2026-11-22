// 文件职责：验证客户端 WebUI 防火墙加固概览、封禁/解封与信任白名单接口。
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
	"sync"
	"testing"

	"singctl/configs"
	"singctl/internal/config"
	"singctl/internal/firewall"
)

func TestWebUI_FirewallAPI_OverviewLogsWhitelistAndBan(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "singctl.yaml")
	if err := os.WriteFile(cfgPath, configs.ClientConfigYAML, 0o600); err != nil {
		t.Fatal(err)
	}

	srv := webui.New(webui.Options{
		ConfigPath: cfgPath,
		Listen:     "127.0.0.1:0",
		Password:   "secret-fw-test",
		Version:    "v1.14.149",
	})
	ts := httptest.NewServer(srv.Mux)
	defer ts.Close()
	token := srv.SessionToken()

	doJSON := func(method, path string, body any) (int, []byte) {
		var r *http.Request
		var err error
		if body != nil {
			raw, _ := json.Marshal(body)
			r, err = http.NewRequest(method, ts.URL+path, bytes.NewReader(raw))
			r.Header.Set("Content-Type", "application/json")
		} else {
			r, err = http.NewRequest(method, ts.URL+path, nil)
		}
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(resp.Body)
		return resp.StatusCode, buf.Bytes()
	}

	// 1. Unauthorized without token should return 401
	unauthResp, err := http.Get(ts.URL + "/api/firewall/overview")
	if err != nil {
		t.Fatal(err)
	}
	unauthResp.Body.Close()
	if unauthResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 without token, got %d", unauthResp.StatusCode)
	}

	// 2. GET /api/firewall/overview
	code, ovRaw := doJSON(http.MethodGet, "/api/firewall/overview?page=1&pageSize=10&scope=all", nil)
	if code != http.StatusOK {
		t.Fatalf("GET /api/firewall/overview status=%d body=%s", code, ovRaw)
	}
	var ov firewall.OverviewResponse
	if err := json.Unmarshal(ovRaw, &ov); err != nil {
		t.Fatalf("decode overview: %v", err)
	}
	if len(ov.PortCatalog) == 0 || len(ov.Whitelist.Builtin) == 0 {
		t.Fatalf("expected populated PortCatalog and Builtin whitelist, got %+v", ov)
	}

	// 3. GET /api/firewall/logs
	code, logsRaw := doJSON(http.MethodGet, "/api/firewall/logs?limit=10", nil)
	if code != http.StatusOK {
		t.Fatalf("GET /api/firewall/logs status=%d body=%s", code, logsRaw)
	}
	var logsOut struct {
		OK     bool                   `json:"ok"`
		Events []firewall.NFTLogEvent `json:"events"`
	}
	if err := json.Unmarshal(logsRaw, &logsOut); err != nil || !logsOut.OK {
		t.Fatalf("unexpected logs payload: %s err=%v", logsRaw, err)
	}

	// 4. POST /api/firewall/whitelist add & remove, plus rejecting builtin removal
	code, wBody := doJSON(http.MethodPost, "/api/firewall/whitelist", map[string]string{
		"action": "add",
		"target": "203.0.113.10",
	})
	if code != http.StatusOK {
		t.Fatalf("POST /api/firewall/whitelist add status=%d body=%s", code, wBody)
	}
	cfgAfterAdd, err := config.Load(cfgPath)
	if err != nil || !slices.Contains(cfgAfterAdd.Firewall.Whitelist, "203.0.113.10") {
		t.Fatalf("expected persisted whitelist 203.0.113.10, got %v err=%v", cfgAfterAdd, err)
	}
	if st, err := os.Stat(cfgPath); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("expected singctl.yaml mode 0600, got %v err=%v", st.Mode().Perm(), err)
	}

	for _, builtinTarget := range []string{"10.0.0.0/8", "100.64.0.0/10"} {
		code, _ = doJSON(http.MethodPost, "/api/firewall/whitelist", map[string]string{
			"action": "remove",
			"target": builtinTarget,
		})
		if code != http.StatusBadRequest {
			t.Fatalf("expected 400 removing builtin whitelist %s, got %d", builtinTarget, code)
		}
	}

	code, wRemBody := doJSON(http.MethodPost, "/api/firewall/whitelist", map[string]string{
		"action": "remove",
		"target": "203.0.113.10",
	})
	if code != http.StatusOK {
		t.Fatalf("POST /api/firewall/whitelist remove status=%d body=%s", code, wRemBody)
	}
	cfgAfterRem, err := config.Load(cfgPath)
	if err != nil || slices.Contains(cfgAfterRem.Firewall.Whitelist, "203.0.113.10") {
		t.Fatalf("expected 203.0.113.10 removed, got %v err=%v", cfgAfterRem.Firewall.Whitelist, err)
	}

	// 5. POST /api/firewall/ban self-lock rejections -> 400
	for _, bad := range []struct {
		target string
		scope  string
	}{
		{"192.168.1.50", "dynamic"},
		{"8.8.8.8", "dynamic"},
		{"203.0.0.0/8", "forever"},
		{"127.0.0.1", "dynamic"}, // matches caller RemoteAddr on loopback
	} {
		code, _ = doJSON(http.MethodPost, "/api/firewall/ban", bad)
		if code != http.StatusBadRequest {
			t.Fatalf("expected 400 for forbidden ban %+v, got %d", bad, code)
		}
	}

	// 6. POST /api/firewall/ban forever CIDR -> persisted 0600, then unban removes it
	code, banBody := doJSON(http.MethodPost, "/api/firewall/ban", map[string]string{
		"target": "203.0.113.0/24",
		"scope":  "forever",
	})
	if code != http.StatusOK {
		t.Fatalf("POST /api/firewall/ban forever status=%d body=%s", code, banBody)
	}
	cfgAfterBan, err := config.Load(cfgPath)
	if err != nil || !slices.Contains(cfgAfterBan.Firewall.ExtraForeverBan, "203.0.113.0/24") {
		t.Fatalf("expected persisted ExtraForeverBan 203.0.113.0/24, got %v err=%v", cfgAfterBan, err)
	}
	if st, err := os.Stat(cfgPath); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("expected singctl.yaml mode 0600 after ban save, got %v err=%v", st.Mode().Perm(), err)
	}

	code, unbanBody := doJSON(http.MethodPost, "/api/firewall/unban", map[string]string{
		"target": "203.0.113.0/24",
		"scope":  "forever",
	})
	if code != http.StatusOK {
		t.Fatalf("POST /api/firewall/unban forever status=%d body=%s", code, unbanBody)
	}
	cfgAfterUnban, err := config.Load(cfgPath)
	if err != nil || slices.Contains(cfgAfterUnban.Firewall.ExtraForeverBan, "203.0.113.0/24") {
		t.Fatalf("expected ExtraForeverBan removed after unban, got %v err=%v", cfgAfterUnban.Firewall.ExtraForeverBan, err)
	}
}

func TestWebUI_StatusEndpoint_ConcurrentSafe(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "singctl.yaml")
	if err := os.WriteFile(cfgPath, configs.ClientConfigYAML, 0o600); err != nil {
		t.Fatal(err)
	}

	srv := webui.New(webui.Options{
		ConfigPath: cfgPath,
		Listen:     "127.0.0.1:0",
		Version:    "v1.14.149",
	})
	ts := httptest.NewServer(srv.Mux)
	defer ts.Close()

	var wg sync.WaitGroup
	errs := make(chan error, 5)
	for range 5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := http.Get(ts.URL + "/api/status")
			if err != nil {
				errs <- err
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				errs <- os.ErrInvalid
				return
			}
			var decoded map[string]any
			if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
				errs <- err
				return
			}
			for _, k := range []string{"host", "singbox", "daemon", "adguard", "tailscale", "firewall", "gateway", "config"} {
				if _, ok := decoded[k]; !ok {
					errs <- os.ErrNotExist
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent GET /api/status error: %v", err)
	}
}
