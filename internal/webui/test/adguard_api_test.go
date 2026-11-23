// 文件职责：验证客户端 WebUI AdGuard Home 状态、凭据重置、上游探测与白名单规则接口契约。
package webui_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"singctl/internal/webui"
	"slices"
	"strings"
	"sync"
	"testing"

	"singctl/internal/adguard"
	"singctl/internal/common/sysinfo"
	"singctl/internal/config"
)

func TestAdGuardWebUIAPI_EndToEnd(t *testing.T) {
	var mu sync.Mutex
	protectionEnabled := true
	disabledDurationMs := int64(0)
	cacheCleared := false
	rewrites := []adguard.RewriteEntry{
		{Domain: "router.lan", Answer: "192.168.1.1"},
	}
	userRules := []string{
		"@@||sub.example.com^$important",
		"! >>> singctl-audit-blocklist start >>>",
		"||tracker.example.com^$important",
		"! <<< singctl-audit-blocklist end <<<",
	}
	filters := []map[string]any{
		{
			"id":          1,
			"enabled":     true,
			"name":        "AdGuard DNS filter",
			"url":         "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt",
			"rules_count": 61234,
		},
	}

	mockAGH := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "root" || pass != "TestSecretPass12" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		mu.Lock()
		defer mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/control/status":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"version":                      "v0.107.59",
				"running":                      true,
				"protection_enabled":           protectionEnabled,
				"protection_disabled_duration": disabledDurationMs,
			})
		case "/control/stats":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"num_dns_queries":       1000,
				"num_blocked_filtering": 185,
				"avg_processing_time":   0.0115,
				"top_blocked_domains": []map[string]int64{
					{"ad.example.com": 88},
				},
				"top_queried_domains": []map[string]int64{
					{"qq.com": 210},
				},
			})
		case "/control/filtering/status":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"enabled":    true,
				"filters":    filters,
				"user_rules": userRules,
			})
		case "/control/filtering/set_rules":
			var body struct {
				Rules []string `json:"rules"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			userRules = body.Rules
			w.WriteHeader(http.StatusOK)
		case "/control/filtering/add_url":
			var body struct {
				Name string `json:"name"`
				URL  string `json:"url"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			filters = append(filters, map[string]any{
				"id":          2,
				"enabled":     true,
				"name":        body.Name,
				"url":         body.URL,
				"rules_count": 32000,
			})
			w.WriteHeader(http.StatusOK)
		case "/control/protection":
			var body struct {
				Enabled  bool  `json:"enabled"`
				Duration int64 `json:"duration"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			protectionEnabled = body.Enabled
			disabledDurationMs = body.Duration
			w.WriteHeader(http.StatusOK)
		case "/control/cache_clear":
			cacheCleared = true
			w.WriteHeader(http.StatusOK)
		case "/control/rewrite/list":
			_ = json.NewEncoder(w).Encode(rewrites)
		case "/control/rewrite/add":
			var entry adguard.RewriteEntry
			_ = json.NewDecoder(r.Body).Decode(&entry)
			rewrites = append(rewrites, entry)
			w.WriteHeader(http.StatusOK)
		case "/control/rewrite/delete":
			var entry adguard.RewriteEntry
			_ = json.NewDecoder(r.Body).Decode(&entry)
			rewrites = slices.DeleteFunc(rewrites, func(e adguard.RewriteEntry) bool {
				return e.Domain == entry.Domain && e.Answer == entry.Answer
			})
			w.WriteHeader(http.StatusOK)
		case "/control/dns_info":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"upstream_dns":  []string{"https://223.5.5.5/dns-query", "https://1.12.12.12/dns-query"},
				"upstream_mode": "parallel",
			})
		case "/control/dns_config":
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer mockAGH.Close()

	parsedURL, err := url.Parse(mockAGH.URL)
	if err != nil {
		t.Fatal(err)
	}

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "AdGuardHome")
	if err := os.WriteFile(fakeBin, []byte("#!/bin/sh\necho 'AdGuard Home, version v0.107.59'\n"), 0755); err != nil {
		t.Fatal(err)
	}

	hash, err := config.HashPassword("TestSecretPass12")
	if err != nil {
		t.Fatal(err)
	}
	aghCfgPath := filepath.Join(tmpDir, "AdGuardHome.yaml")
	yamlContent := "http:\n  address: " + parsedURL.Host + "\nusers:\n  - name: root\n    password: " + hash + "\ndns:\n  bind_hosts:\n    - 127.0.0.1\n  port: 5353\n"
	if err := os.WriteFile(aghCfgPath, []byte(yamlContent), 0600); err != nil {
		t.Fatal(err)
	}

	sbCfgPath := filepath.Join(tmpDir, "singbox.json")
	if err := os.WriteFile(sbCfgPath, []byte(`{"dns":{"servers":[{"tag":"dns_local","type":"udp","server":"127.0.0.1","server_port":5353}]}}`), 0600); err != nil {
		t.Fatal(err)
	}

	singctlCfgPath := filepath.Join(tmpDir, "singctl.yaml")
	cfg := &config.Config{
		Subs: []config.Subscription{{Name: "Main", URL: "https://sub.example.com/api/v1"}},
		DNS: config.ClientDNSConfig{
			DNSPort:  5353,
			WebPort:  3000,
			Username: "root",
			Password: "TestSecretPass12",
		},
	}
	if err := config.Save(singctlCfgPath, cfg); err != nil {
		t.Fatal(err)
	}

	srv := webui.New(webui.Options{
		ConfigPath:              singctlCfgPath,
		SingBoxConfigPath:       sbCfgPath,
		AdGuardBinPath:          fakeBin,
		AdGuardConfigPath:       aghCfgPath,
		SkipAdGuardProbeForTest: true,
	})

	doJSON := func(method, path string, payload any) *httptest.ResponseRecorder {
		t.Helper()
		var body *bytes.Reader
		if payload != nil {
			b, _ := json.Marshal(payload)
			body = bytes.NewReader(b)
		} else {
			body = bytes.NewReader(nil)
		}
		req := httptest.NewRequest(method, path, body)
		if method != http.MethodGet {
			req.Header.Set("Content-Type", "application/json")
		}
		rec := httptest.NewRecorder()
		srv.Mux.ServeHTTP(rec, req)
		return rec
	}

	// 1. Overview
	rec := doJSON(http.MethodGet, "/api/adguard", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/adguard code=%d body=%s", rec.Code, rec.Body.String())
	}
	var snap adguard.OverviewSnapshot
	if err := json.Unmarshal(rec.Body.Bytes(), &snap); err != nil {
		t.Fatal(err)
	}
	if !snap.Installed || !snap.SingBoxLinked || snap.Stats.NumDNSQueries != 1000 || snap.AuditManagedCount != 1 {
		t.Fatalf("unexpected overview snapshot: %+v", snap)
	}

	// 2. Pause protection for 5 minutes
	rec = doJSON(http.MethodPost, "/api/adguard/protection", map[string]any{"enabled": false, "durationMinutes": 5})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/adguard/protection failed: %s", rec.Body.String())
	}
	if protectionEnabled || disabledDurationMs != 300000 {
		t.Fatalf("expected protection paused for 300000ms, got enabled=%v duration=%d", protectionEnabled, disabledDurationMs)
	}

	// 3. One-click whitelist domain (preserving audit blocklist markers)
	rec = doJSON(http.MethodPost, "/api/adguard/whitelist", map[string]any{"domain": "ad.example.com", "action": "add"})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/adguard/whitelist failed: %s", rec.Body.String())
	}
	if !slices.Contains(userRules, "@@||ad.example.com^$important") || !slices.Contains(userRules, "||tracker.example.com^$important") {
		t.Fatalf("unexpected userRules after whitelist: %v", userRules)
	}

	// 4. Add & delete LAN DNS Rewrite
	rec = doJSON(http.MethodPost, "/api/adguard/rewrites", map[string]any{"action": "add", "domain": "nas.lan", "answer": "192.168.1.10"})
	if rec.Code != http.StatusOK {
		t.Fatalf("add rewrite failed: %s", rec.Body.String())
	}
	if len(rewrites) != 2 {
		t.Fatalf("expected 2 rewrites, got %v", rewrites)
	}

	// 5. Enable Anti-AD curated preset & clear cache
	rec = doJSON(http.MethodPost, "/api/adguard/filters", map[string]any{
		"action":  "toggle",
		"url":     "https://anti-ad.net/easylist.txt",
		"name":    "Anti-AD 中文增强过滤",
		"enabled": true,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("toggle filter failed: %s", rec.Body.String())
	}
	rec = doJSON(http.MethodPost, "/api/adguard/cache/clear", map[string]any{})
	if rec.Code != http.StatusOK || !cacheCleared {
		t.Fatalf("cache clear failed: code=%d cleared=%v", rec.Code, cacheCleared)
	}

	// 6. Update encrypted DNS upstreams: pure-IP + domain succeeds, domain-only & loopback rejected
	rec = doJSON(http.MethodPost, "/api/adguard/upstreams", map[string]any{
		"upstreams":    []string{"https://dns.alidns.com/dns-query", "tls://1.12.12.12", "tls://dot.onedns.net"},
		"upstreamMode": "parallel",
	})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "https://223.5.5.5/dns-query") || !strings.Contains(rec.Body.String(), "tls://dot.onedns.net") || !strings.Contains(rec.Body.String(), "OneDNS") {
		t.Fatalf("POST /api/adguard/upstreams hybrid domain failed: code=%d body=%s", rec.Code, rec.Body.String())
	}
	rec = doJSON(http.MethodPost, "/api/adguard/upstreams", map[string]any{
		"upstreams": []string{"tls://dot.onedns.net"},
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 rejecting domain-only upstream list without pure-IP fallback, got code=%d body=%s", rec.Code, rec.Body.String())
	}
	rec = doJSON(http.MethodPost, "/api/adguard/upstreams", map[string]any{
		"upstreams": []string{"https://127.0.0.1/dns-query"},
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 rejecting loopback upstream, got code=%d", rec.Code)
	}

	// 7. Status endpoint includes adguard summary
	rec = doJSON(http.MethodGet, "/api/status", nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"adguard"`) {
		t.Fatalf("GET /api/status missing adguard summary: %s", rec.Body.String())
	}
}

func TestAuditAIModels_AutoFetchAndFallback(t *testing.T) {
	mockLLM := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/models" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer sk-test-key" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"object": "list",
			"data": []map[string]any{
				{"id": "antigravity/gemini-3.8-flash"},
				{"id": "claude-sonnet-4-6"},
			},
		})
	}))
	defer mockLLM.Close()

	tmpDir := t.TempDir()
	singctlCfgPath := filepath.Join(tmpDir, "singctl.yaml")
	if err := config.Save(singctlCfgPath, &config.Config{}); err != nil {
		t.Fatal(err)
	}
	srv := webui.New(webui.Options{ConfigPath: singctlCfgPath})

	// 1. 拉取成功场景
	reqBody, _ := json.Marshal(map[string]any{
		"baseUrl": mockLLM.URL,
		"apiKey":  "sk-test-key",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/audit/ai-models", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.Mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/audit/ai-models status=%d body=%s", rec.Code, rec.Body.String())
	}
	var okResp struct {
		OK     bool     `json:"ok"`
		Models []string `json:"models"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &okResp); err != nil {
		t.Fatal(err)
	}
	if !okResp.OK || len(okResp.Models) != 2 || okResp.Models[0] != "antigravity/gemini-3.8-flash" {
		t.Fatalf("unexpected fetched models: %+v", okResp)
	}

	// 2. 网关不可达或密钥错误时优雅降级返回 ok:false 供前端切换手动填写
	badBody, _ := json.Marshal(map[string]any{
		"baseUrl": mockLLM.URL,
		"apiKey":  "wrong-key",
	})
	badReq := httptest.NewRequest(http.MethodPost, "/api/audit/ai-models", bytes.NewReader(badBody))
	badReq.Header.Set("Content-Type", "application/json")
	badRec := httptest.NewRecorder()
	srv.Mux.ServeHTTP(badRec, badReq)
	if badRec.Code != http.StatusOK || strings.Contains(badRec.Body.String(), `"ok":true`) {
		t.Fatalf("expected graceful fallback ok:false, got code=%d body=%s", badRec.Code, badRec.Body.String())
	}
}

func TestAdGuardWebUI_LowMemoryGuardPassThrough(t *testing.T) {
	const mib = 1024 * 1024
	cases := []struct {
		name        string
		mem         sysinfo.MemInfo
		wantBlocked bool
		wantSubstr  string
	}{
		{
			name:        "ultra_low_224mb_router_blocked",
			mem:         sysinfo.MemInfo{TotalBytes: 224 * mib, AvailableBytes: 120 * mib},
			wantBlocked: true,
			wantSubstr:  "sing-box 纯 IP DoH + geosite-ad1",
		},
		{
			name:        "n60pro_480mb_total_205mb_avail_blocked",
			mem:         sysinfo.MemInfo{TotalBytes: 491040 * 1024, AvailableBytes: 210260 * 1024},
			wantBlocked: true,
			wantSubstr:  "可用内存不足",
		},
		{
			name:        "ample_2gb_ram_allowed",
			mem:         sysinfo.MemInfo{TotalBytes: 2048 * mib, AvailableBytes: 1500 * mib},
			wantBlocked: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			cfgPath := filepath.Join(tmpDir, "singctl.yaml")
			if err := config.Save(cfgPath, &config.Config{}); err != nil {
				t.Fatal(err)
			}
			fakeExe := filepath.Join(tmpDir, "fake-singctl.sh")
			argsOut := filepath.Join(tmpDir, "invoked-args.txt")
			script := "#!/bin/sh\necho \"$@\" > " + argsOut + "\nexit 0\n"
			if err := os.WriteFile(fakeExe, []byte(script), 0755); err != nil {
				t.Fatal(err)
			}

			srv := webui.New(webui.Options{
				ConfigPath:              cfgPath,
				AdGuardBinPath:          filepath.Join(tmpDir, "missing-AdGuardHome"),
				AdGuardConfigPath:       filepath.Join(tmpDir, "missing-AdGuardHome.yaml"),
				SingBoxConfigPath:       filepath.Join(tmpDir, "missing-singbox.json"),
				ExecutablePath:          fakeExe,
				SkipAdGuardProbeForTest: true,
				AdGuardMemInfoForTest: func() sysinfo.MemInfo {
					return tc.mem
				},
			})

			// 1. GET /api/adguard exposes lowMemoryBlocked & lowMemoryWarning
			ovReq := httptest.NewRequest(http.MethodGet, "/api/adguard", nil)
			ovRec := httptest.NewRecorder()
			srv.Mux.ServeHTTP(ovRec, ovReq)
			if ovRec.Code != http.StatusOK {
				t.Fatalf("GET /api/adguard status=%d body=%s", ovRec.Code, ovRec.Body.String())
			}
			var ov map[string]any
			if err := json.Unmarshal(ovRec.Body.Bytes(), &ov); err != nil {
				t.Fatal(err)
			}
			gotBlocked, _ := ov["lowMemoryBlocked"].(bool)
			gotWarn, _ := ov["lowMemoryWarning"].(string)
			if gotBlocked != tc.wantBlocked {
				t.Fatalf("GET /api/adguard lowMemoryBlocked=%v, want %v (body=%s)", gotBlocked, tc.wantBlocked, ovRec.Body.String())
			}
			if tc.wantBlocked && !strings.Contains(gotWarn, tc.wantSubstr) {
				t.Fatalf("GET /api/adguard lowMemoryWarning=%q missing %q", gotWarn, tc.wantSubstr)
			}

			// 2. GET /api/status exposes adguard.lowMemoryBlocked & lowMemoryWarning
			stReq := httptest.NewRequest(http.MethodGet, "/api/status", nil)
			stRec := httptest.NewRecorder()
			srv.Mux.ServeHTTP(stRec, stReq)
			var stPayload struct {
				AdGuard map[string]any `json:"adguard"`
			}
			if err := json.Unmarshal(stRec.Body.Bytes(), &stPayload); err != nil {
				t.Fatal(err)
			}
			if b, _ := stPayload.AdGuard["lowMemoryBlocked"].(bool); b != tc.wantBlocked {
				t.Fatalf("GET /api/status adguard.lowMemoryBlocked=%v, want %v", b, tc.wantBlocked)
			}

			// 3. POST /api/action {"name":"dns-install"} intercepts low-memory without spawning subprocess unless forceLowMemory=true
			actBody, _ := json.Marshal(map[string]any{"name": "dns-install"})
			actReq := httptest.NewRequest(http.MethodPost, "/api/action", bytes.NewReader(actBody))
			actReq.Header.Set("Content-Type", "application/json")
			actRec := httptest.NewRecorder()
			srv.Mux.ServeHTTP(actRec, actReq)
			if actRec.Code != http.StatusOK {
				t.Fatalf("POST /api/action status=%d body=%s", actRec.Code, actRec.Body.String())
			}
			ndjson := actRec.Body.String()
			if tc.wantBlocked {
				if !strings.Contains(ndjson, tc.wantSubstr) || !strings.Contains(ndjson, `"code":1`) {
					t.Fatalf("expected NDJSON low-memory guard failure containing %q, got:\n%s", tc.wantSubstr, ndjson)
				}
				if _, err := os.Stat(argsOut); !os.IsNotExist(err) {
					t.Fatal("expected fake executable NOT to be spawned when low-memory guard blocks install")
				}

				// Explicit forceLowMemory:true passes --force-low-memory through to CLI
				forceBody, _ := json.Marshal(map[string]any{
					"name":   "dns-install",
					"params": map[string]any{"forceLowMemory": true},
				})
				forceReq := httptest.NewRequest(http.MethodPost, "/api/action", bytes.NewReader(forceBody))
				forceReq.Header.Set("Content-Type", "application/json")
				forceRec := httptest.NewRecorder()
				srv.Mux.ServeHTTP(forceRec, forceReq)
				invokedBytes, err := os.ReadFile(argsOut)
				if err != nil {
					t.Fatalf("expected fake executable spawned when forceLowMemory=true: %v", err)
				}
				if !strings.Contains(string(invokedBytes), "--force-low-memory") {
					t.Fatalf("expected --force-low-memory passed to CLI, got %q", string(invokedBytes))
				}
			} else {
				if !strings.Contains(ndjson, `"code":0`) {
					t.Fatalf("expected normal RAM dns-install to succeed, got:\n%s", ndjson)
				}
			}
		})
	}
}
