package webui

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"singctl/internal/adguard"
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

	srv := New(Options{
		ConfigPath:        singctlCfgPath,
		SingBoxConfigPath: sbCfgPath,
		AdGuardBinPath:    fakeBin,
		AdGuardConfigPath: aghCfgPath,
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

	// 6. Status endpoint includes adguard summary
	rec = doJSON(http.MethodGet, "/api/status", nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"adguard"`) {
		t.Fatalf("GET /api/status missing adguard summary: %s", rec.Body.String())
	}
}
