package webui

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"singctl/internal/daemon"
)

func TestHandleSbProxies_SwitchDelayModeTrafficAndAuth(t *testing.T) {
	dir := t.TempDir()
	daemon.StateFilePathOverride = filepath.Join(dir, "daemon.state")
	t.Cleanup(func() { daemon.StateFilePathOverride = "" })

	daemon.UpdateRuntimeState(func(snap *daemon.DaemonRuntimeSnapshot) {
		snap.ActiveFailovers = []daemon.FailoverActiveItem{
			{
				Group:   "Proxy",
				Origin:  "#Auto",
				Current: "#Auto",
				Since:   "2026-11-14 01:00:00",
			},
		}
	})

	var (
		mu         sync.Mutex
		mode       = "rule"
		proxyNow   = "#Auto"
		vpsNow     = "🇸🇬 SG-VPS"
		seenSecret = "mocksecret123"
	)

	mockClash := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+seenSecret {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		mu.Lock()
		curMode := mode
		curProxyNow := proxyNow
		curVPSNow := vpsNow
		mu.Unlock()

		switch {
		case r.URL.Path == "/version":
			_, _ = w.Write([]byte(`{"version":"1.14.4","meta":true}`))
		case r.URL.Path == "/configs" && r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(map[string]any{"mode": curMode})
		case r.URL.Path == "/configs" && r.Method == http.MethodPatch:
			var body struct {
				Mode string `json:"mode"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			mu.Lock()
			mode = body.Mode
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == "/proxies" && r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"proxies": map[string]any{
					"GLOBAL": map[string]any{
						"type": "Selector",
						"now":  "Proxy",
						"all":  []string{"Proxy", "#VPS", "DIRECT"},
					},
					"Proxy": map[string]any{
						"type": "Selector",
						"now":  curProxyNow,
						"all":  []string{"#Auto", "#VPS", "🇭🇰 HK-01", "#DC"},
					},
					"#VPS": map[string]any{
						"type": "Selector",
						"now":  curVPSNow,
						"all":  []string{"🇸🇬 SG-VPS", "🇺🇸 US-VPS"},
					},
					"#Auto": map[string]any{
						"type": "URLTest",
						"now":  "🇭🇰 HK-01",
						"all":  []string{"🇭🇰 HK-01", "🇯🇵 JP-02"},
						"history": []map[string]any{
							{"delay": 62},
						},
					},
					"🇭🇰 HK-01": map[string]any{
						"type": "VLESS",
						"udp":  true,
						"history": []map[string]any{
							{"delay": 62},
						},
					},
					"🇯🇵 JP-02": map[string]any{
						"type": "Hysteria2",
						"udp":  true,
						"history": []map[string]any{
							{"delay": 0},
						},
					},
					"🇸🇬 SG-VPS": map[string]any{
						"type": "VLESS",
						"udp":  true,
						"history": []map[string]any{
							{"delay": 45},
						},
					},
					"🇺🇸 US-VPS": map[string]any{
						"type": "VLESS",
						"udp":  true,
					},
					"#DC": map[string]any{
						"type": "Direct",
					},
				},
			})
		case strings.HasPrefix(r.URL.Path, "/proxies/") && strings.HasSuffix(r.URL.Path, "/delay") && r.Method == http.MethodGet:
			raw := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/proxies/"), "/delay")
			name, _ := url.PathUnescape(raw)
			switch name {
			case "🇭🇰 HK-01":
				_, _ = w.Write([]byte(`{"delay":58}`))
			case "🇸🇬 SG-VPS":
				_, _ = w.Write([]byte(`{"delay":41}`))
			case "🇯🇵 JP-02":
				http.Error(w, `{"message":"timeout"}`, http.StatusGatewayTimeout)
			default:
				_, _ = w.Write([]byte(`{"delay":120}`))
			}
		case strings.HasPrefix(r.URL.Path, "/proxies/") && r.Method == http.MethodPut:
			raw := strings.TrimPrefix(r.URL.Path, "/proxies/")
			group, _ := url.PathUnescape(raw)
			var body struct {
				Name string `json:"name"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			mu.Lock()
			if group == "Proxy" {
				proxyNow = body.Name
			} else if group == "#VPS" {
				vpsNow = body.Name
			}
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == "/connections":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"uploadTotal":   102400,
				"downloadTotal": 2048000,
				"connections":   []map[string]any{{"id": "1"}, {"id": "2"}, {"id": "3"}},
			})
		case r.URL.Path == "/traffic":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte("{\"up\":12345,\"down\":67890}\n"))
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		case r.URL.Path == "/memory":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte("{\"inuse\":33554432,\"oslimit\":0}\n"))
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer mockClash.Close()

	cfgPath := filepath.Join(dir, "singctl.yaml")
	sbPath := filepath.Join(dir, "singbox.json")
	if err := os.WriteFile(cfgPath, []byte("mode: router\n"), 0600); err != nil {
		t.Fatal(err)
	}
	ctrl := strings.TrimPrefix(mockClash.URL, "http://")
	sbJSON := fmt.Sprintf(`{
  "experimental": {"clash_api": {"external_controller": %q, "secret": %q}},
  "outbounds": [
    {"type": "selector", "tag": "Proxy", "outbounds": ["#Auto", "#VPS", "🇭🇰 HK-01", "#DC"]},
    {"type": "selector", "tag": "#VPS", "outbounds": ["🇸🇬 SG-VPS", "🇺🇸 US-VPS"]},
    {"type": "urltest", "tag": "#Auto", "outbounds": ["🇭🇰 HK-01", "🇯🇵 JP-02"]},
    {"type": "direct", "tag": "#DC"}
  ],
  "route": {"rules": []}
}`, ctrl, seenSecret)
	if err := os.WriteFile(sbPath, []byte(sbJSON), 0600); err != nil {
		t.Fatal(err)
	}

	srv := New(Options{
		ConfigPath:        cfgPath,
		SingBoxConfigPath: sbPath,
		Password:          "testpass",
	})
	ts := httptest.NewServer(srv.Mux)
	defer ts.Close()

	doReq := func(method, path string, body any, authed bool) (int, string) {
		var rBody *bytes.Reader
		if body != nil {
			raw, _ := json.Marshal(body)
			rBody = bytes.NewReader(raw)
		} else {
			rBody = bytes.NewReader(nil)
		}
		req, _ := http.NewRequest(method, ts.URL+path, rBody)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if authed {
			req.SetBasicAuth("admin", "testpass")
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(resp.Body)
		return resp.StatusCode, buf.String()
	}

	// 1. 未鉴权访问均被拦截（包括已下线的 /clash/* 旧路径）
	for _, p := range []string{"/api/sb/proxies", "/clash/version", "/proxies", "/connections"} {
		if code, _ := doReq(http.MethodGet, p, nil, false); code != http.StatusUnauthorized {
			t.Fatalf("expected 401 for unauthenticated %s, got %d", p, code)
		}
	}

	// 2. 获取原生策略组视图：验证顺序、嵌套链路解析、分流反查及容灾状态
	code, raw := doReq(http.MethodGet, "/api/sb/proxies", nil, true)
	if code != http.StatusOK {
		t.Fatalf("GET /api/sb/proxies failed: %d %s", code, raw)
	}
	var snap SbProxiesSnapshot
	if err := json.Unmarshal([]byte(raw), &snap); err != nil {
		t.Fatalf("unmarshal snapshot: %v", err)
	}
	if !snap.Running || snap.Mode != "rule" {
		t.Fatalf("unexpected running/mode: %+v", snap)
	}
	if len(snap.Groups) != 3 || snap.Groups[0].Name != "Proxy" || snap.Groups[1].Name != "#VPS" || snap.Groups[2].Name != "#Auto" {
		t.Fatalf("unexpected groups order (GLOBAL should be hidden in rule mode): %+v", snap.Groups)
	}
	if snap.PrimaryGroup != "Proxy" || snap.PrimaryNode != "🇭🇰 HK-01" || snap.PrimaryDelay != 62 {
		t.Fatalf("unexpected resolved primary: group=%s node=%s delay=%d", snap.PrimaryGroup, snap.PrimaryNode, snap.PrimaryDelay)
	}
	if !snap.Groups[0].FailedOver || snap.Groups[0].UsedByCount == 0 {
		t.Fatalf("expected Proxy group failedOver=true and usedBy populated, got %+v", snap.Groups[0])
	}
	if snap.Groups[2].CanSelect {
		t.Fatalf("#Auto URLTest group should have CanSelect=false")
	}

	// 3. 手动切换 Selector 分组节点应成功并清除过时的看门狗容灾标记
	code, raw = doReq(http.MethodPut, "/api/sb/proxies/switch", map[string]string{
		"group":  "Proxy",
		"target": "#VPS",
	}, true)
	if code != http.StatusOK {
		t.Fatalf("PUT /api/sb/proxies/switch failed: %d %s", code, raw)
	}
	if len(daemon.LoadRuntimeSnapshot().ActiveFailovers) != 0 {
		t.Fatalf("expected manual switch to clear stale failover snapshot, got %+v", daemon.LoadRuntimeSnapshot().ActiveFailovers)
	}

	// 4. 禁止手动固定 URLTest 分组
	if code, _ := doReq(http.MethodPut, "/api/sb/proxies/switch", map[string]string{
		"group":  "#Auto",
		"target": "🇭🇰 HK-01",
	}, true); code != http.StatusBadRequest {
		t.Fatalf("expected 400 switching URLTest group, got %d", code)
	}

	// 5. 并发批量测速 + 单节点测速
	code, raw = doReq(http.MethodPost, "/api/sb/proxies/delay", map[string]any{
		"group": "__all__",
	}, true)
	if code != http.StatusOK {
		t.Fatalf("POST /api/sb/proxies/delay failed: %d %s", code, raw)
	}
	var delayResp struct {
		OK     bool           `json:"ok"`
		Delays map[string]int `json:"delays"`
	}
	if err := json.Unmarshal([]byte(raw), &delayResp); err != nil {
		t.Fatal(err)
	}
	if !delayResp.OK || delayResp.Delays["🇭🇰 HK-01"] != 58 || delayResp.Delays["🇸🇬 SG-VPS"] != 41 {
		t.Fatalf("unexpected delay response: %+v", delayResp)
	}
	if _, testedDirect := delayResp.Delays["#DC"]; testedDirect {
		t.Fatalf("#DC direct outbound must not be delay-probed")
	}

	// 6. 切换至 global 模式后，GLOBAL 策略组应顶置显示
	code, raw = doReq(http.MethodPut, "/api/sb/mode", map[string]string{"mode": "global"}, true)
	if code != http.StatusOK {
		t.Fatalf("PUT /api/sb/mode failed: %d %s", code, raw)
	}
	if code, _ := doReq(http.MethodPut, "/api/sb/mode", map[string]string{"mode": "invalid"}, true); code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid mode, got %d", code)
	}
	_, raw = doReq(http.MethodGet, "/api/sb/proxies", nil, true)
	var globalSnap SbProxiesSnapshot
	_ = json.Unmarshal([]byte(raw), &globalSnap)
	if globalSnap.Mode != "global" || len(globalSnap.Groups) == 0 || globalSnap.Groups[0].Name != "GLOBAL" {
		t.Fatalf("expected GLOBAL first in global mode, got %+v", globalSnap.Groups)
	}

	// 7. 轻量速率/连接数接口
	code, raw = doReq(http.MethodGet, "/api/sb/traffic", nil, true)
	if code != http.StatusOK {
		t.Fatalf("GET /api/sb/traffic failed: %d %s", code, raw)
	}
	var traffic sbTrafficResponse
	_ = json.Unmarshal([]byte(raw), &traffic)
	if !traffic.Running || traffic.Up != 12345 || traffic.Down != 67890 || traffic.Connections != 3 || traffic.Memory != 33554432 {
		t.Fatalf("unexpected traffic payload: %+v", traffic)
	}
}
