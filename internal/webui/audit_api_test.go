package webui

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"singctl/internal/config"
)

func TestAuditRateLimiterScopeIsolationAndBotBlock(t *testing.T) {
	limiter := newAuditRateLimiter()

	// Simulate hitting read and AI limits from the same client IP (different ephemeral ports).
	for i := range 200 {
		req := httptest.NewRequest(http.MethodGet, "/api/audit", nil)
		req.RemoteAddr = "192.0.2.10:40000"
		req.Header.Set("User-Agent", "Mozilla/5.0")
		allowed := limiter.allow(req, "read", 180)
		if i < 180 && !allowed {
			t.Fatalf("read request %d should be allowed", i)
		}
		if i >= 180 && allowed {
			t.Fatalf("read request %d should be rate-limited", i)
		}
	}

	for i := range 310 {
		req := httptest.NewRequest(http.MethodPost, "/api/audit/ai-review", nil)
		req.RemoteAddr = "192.0.2.10:40001"
		req.Header.Set("User-Agent", "Mozilla/5.0")
		allowed := limiter.allow(req, "ai", 300)
		if i < 300 && !allowed {
			t.Fatalf("ai request %d should be allowed", i)
		}
		if i >= 300 && allowed {
			t.Fatalf("ai request %d should be rate-limited", i)
		}
	}

	// Interactive write operations (whitelist/block/unblock) must retain full independent quota.
	for i := range 120 {
		req := httptest.NewRequest(http.MethodPost, "/api/audit/whitelist", nil)
		req.RemoteAddr = "192.0.2.10:40002"
		req.Header.Set("User-Agent", "Mozilla/5.0")
		if !limiter.allow(req, "write", 120) {
			t.Fatalf("write request %d should remain unaffected by read/ai bursts", i)
		}
	}

	botReq := httptest.NewRequest(http.MethodPost, "/api/audit/whitelist", nil)
	botReq.RemoteAddr = "192.0.2.99:50000"
	botReq.Header.Set("User-Agent", "sqlmap/1.7.2")
	if limiter.allow(botReq, "write", 120) {
		t.Fatal("expected scraper user-agent to be blocked")
	}
}

func TestAuditWhitelistUnaffectedByAuditGetBurst(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "singctl.yaml")
	if err := os.WriteFile(cfgPath, []byte("mode: router\n"), 0600); err != nil {
		t.Fatal(err)
	}

	srv := New(Options{
		ConfigPath: cfgPath,
		Listen:     "127.0.0.1:0",
		Password:   "test-pass-123",
		Version:    "v1.14.105",
	})
	token := srv.SessionToken()

	// Exhaust the read rate limit completely on the server's limiter.
	for i := range 180 {
		probeReq := httptest.NewRequest(http.MethodGet, "/api/audit", nil)
		probeReq.RemoteAddr = "192.0.2.20:51000"
		probeReq.Header.Set("User-Agent", "Mozilla/5.0")
		if !srv.auditLimiter.allow(probeReq, "read", 180) {
			t.Fatalf("expected read probe %d to be allowed", i)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/api/audit", nil)
	req.RemoteAddr = "192.0.2.20:51000"
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	rec := httptest.NewRecorder()
	srv.Mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 once read bucket is exhausted, got %d", rec.Code)
	}

	// Whitelist click from the same client IP must still succeed immediately.
	body, _ := json.Marshal(map[string]string{
		"target": "whitelist.example.com",
		"reason": "test whitelist",
	})
	wlReq := httptest.NewRequest(http.MethodPost, "/api/audit/whitelist", bytes.NewReader(body))
	wlReq.RemoteAddr = "192.0.2.20:51001"
	wlReq.Header.Set("Authorization", "Bearer "+token)
	wlReq.Header.Set("Content-Type", "application/json")
	wlReq.Header.Set("User-Agent", "Mozilla/5.0")
	wlRec := httptest.NewRecorder()
	srv.Mux.ServeHTTP(wlRec, wlReq)
	if wlRec.Code != http.StatusOK {
		t.Fatalf("expected POST /api/audit/whitelist 200 after read burst, got %d: %s", wlRec.Code, wlRec.Body.String())
	}

	loaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(loaded.Audit.Whitelist, "whitelist.example.com") {
		t.Fatalf("expected whitelist entry persisted in audit.whitelist, got %+v", loaded.Audit.Whitelist)
	}
}
