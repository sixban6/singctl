package webui

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"singctl/internal/config"
)

func seedDomainConfigYAML(t *testing.T, dir string) string {
	t.Helper()
	cfgPath := filepath.Join(dir, "singctl.yaml")
	seed := `subs:
  - name: "main"
    url: "https://example.com/sub1"
    skip_tls_verify: false
    remove_emoji: true
    include: "HK|JP"
hy2:
  up: 20
  down: 200
github:
  mirror_url: "https://gh-proxy.example.com"
tailscale:
  auth_key: "tskey-auth-testsecret-9876zyxw"
  use_build: false
  subnets: "192.168.180.0/24"
  p2p_assist:
    enabled: true
    jit_window_sec: 6
    peers:
      - name: "peer-home"
        tailscale_ip: "100.64.200.2"
        jit_enabled: true
        access_mode: "outbound_only"
server:
  sb_domain: "node.example.com"
  cf_dns_key: "cf-test-token"
  sni: "swdist.apple.com"
`
	if err := os.WriteFile(cfgPath, []byte(seed), 0600); err != nil {
		t.Fatal(err)
	}
	return cfgPath
}

func TestTailscaleConfigAPI_GetMaskedPutPreserveClearAndValidation(t *testing.T) {
	dir := t.TempDir()
	cfgPath := seedDomainConfigYAML(t, dir)
	srv := New(Options{ConfigPath: cfgPath, Version: "v1.14.146-test"})

	// 1. GET /api/tailscale/config returns masked hint and NEVER leaks full raw auth_key
	reqGet := httptest.NewRequest(http.MethodGet, "/api/tailscale/config", nil)
	recGet := httptest.NewRecorder()
	srv.Mux.ServeHTTP(recGet, reqGet)
	if recGet.Code != http.StatusOK {
		t.Fatalf("GET /api/tailscale/config status=%d body=%s", recGet.Code, recGet.Body.String())
	}
	if strings.Contains(recGet.Body.String(), "tskey-auth-testsecret-9876zyxw") {
		t.Fatalf("GET /api/tailscale/config leaked raw auth_key: %s", recGet.Body.String())
	}
	var gotCfg struct {
		AuthKeySet  bool   `json:"authKeySet"`
		AuthKeyHint string `json:"authKeyHint"`
		Subnets     string `json:"subnets"`
		UseBuild    bool   `json:"useBuild"`
	}
	if err := json.Unmarshal(recGet.Body.Bytes(), &gotCfg); err != nil {
		t.Fatal(err)
	}
	if !gotCfg.AuthKeySet || gotCfg.AuthKeyHint == "" || gotCfg.Subnets != "192.168.180.0/24" || gotCfg.UseBuild {
		t.Fatalf("unexpected GET tailscale config: %+v", gotCfg)
	}

	// 2. Reject invalid subnet CIDR
	reqBad := httptest.NewRequest(http.MethodPut, "/api/tailscale/config", bytes.NewBufferString(`{"subnets":"not-a-cidr"}`))
	reqBad.Header.Set("Content-Type", "application/json")
	recBad := httptest.NewRecorder()
	srv.Mux.ServeHTTP(recBad, reqBad)
	if recBad.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid CIDR, got %d body=%s", recBad.Code, recBad.Body.String())
	}

	// 3. Blank authKey preserves existing key, updates subnets, and preserves all unrelated sections
	reqPres := httptest.NewRequest(http.MethodPut, "/api/tailscale/config", bytes.NewBufferString(`{"authKey":"","subnets":"192.168.10.0/24, 192.168.20.0/24","useBuild":true}`))
	reqPres.Header.Set("Content-Type", "application/json")
	recPres := httptest.NewRecorder()
	srv.Mux.ServeHTTP(recPres, reqPres)
	if recPres.Code != http.StatusOK {
		t.Fatalf("PUT preserve status=%d body=%s", recPres.Code, recPres.Body.String())
	}

	afterPres, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if afterPres.Tailscale.AuthKey != "tskey-auth-testsecret-9876zyxw" {
		t.Fatalf("expected existing auth_key preserved on blank input, got %q", afterPres.Tailscale.AuthKey)
	}
	if afterPres.Tailscale.Subnets != "192.168.10.0/24,192.168.20.0/24" || !afterPres.Tailscale.UseBuild {
		t.Fatalf("unexpected updated tailscale fields: %+v", afterPres.Tailscale)
	}
	if len(afterPres.Subs) != 1 || afterPres.Subs[0].Include != "HK|JP" || afterPres.Server.CFDNSKey != "cf-test-token" || !afterPres.Tailscale.P2PAssist.Enabled {
		t.Fatalf("unrelated config sections were mutated: %+v", afterPres)
	}
	if info, err := os.Stat(cfgPath); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 permissions after save, perm=%v err=%v", info, err)
	}

	// 4. clearAuthKey clears existing key explicitly
	reqClr := httptest.NewRequest(http.MethodPut, "/api/tailscale/config", bytes.NewBufferString(`{"clearAuthKey":true,"subnets":"192.168.10.0/24","useBuild":false}`))
	reqClr.Header.Set("Content-Type", "application/json")
	recClr := httptest.NewRecorder()
	srv.Mux.ServeHTTP(recClr, reqClr)
	if recClr.Code != http.StatusOK {
		t.Fatalf("PUT clearAuthKey status=%d body=%s", recClr.Code, recClr.Body.String())
	}
	afterClr, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if afterClr.Tailscale.AuthKey != "" {
		t.Fatalf("expected auth_key cleared, got %q", afterClr.Tailscale.AuthKey)
	}
}

func TestSbSubsAPI_PutValidationAndPreservesOtherSections(t *testing.T) {
	dir := t.TempDir()
	cfgPath := seedDomainConfigYAML(t, dir)
	srv := New(Options{ConfigPath: cfgPath})

	// 1. Invalid sub without URL -> 400
	reqBad := httptest.NewRequest(http.MethodPut, "/api/sb/subs", bytes.NewBufferString(`{"subs":[{"name":"empty","url":""}],"hy2":{"up":10,"down":100}}`))
	reqBad.Header.Set("Content-Type", "application/json")
	recBad := httptest.NewRecorder()
	srv.Mux.ServeHTTP(recBad, reqBad)
	if recBad.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on missing sub url, got %d body=%s", recBad.Code, recBad.Body.String())
	}

	// 2. Valid update preserves matched sub's include filter AND tailscale/github/server sections
	reqOK := httptest.NewRequest(http.MethodPut, "/api/sb/subs", bytes.NewBufferString(`{"subs":[{"name":"main","url":"https://example.com/sub2","skip_tls_verify":true,"remove_emoji":false}],"hy2":{"up":50,"down":500}}`))
	reqOK.Header.Set("Content-Type", "application/json")
	recOK := httptest.NewRecorder()
	srv.Mux.ServeHTTP(recOK, reqOK)
	if recOK.Code != http.StatusOK {
		t.Fatalf("PUT /api/sb/subs status=%d body=%s", recOK.Code, recOK.Body.String())
	}

	after, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(after.Subs) != 1 || after.Subs[0].URL != "https://example.com/sub2" || after.Subs[0].Include != "HK|JP" || after.Hy2.Up != 50 || after.Hy2.Down != 500 {
		t.Fatalf("unexpected subs/hy2 after save: %+v hy2=%+v", after.Subs, after.Hy2)
	}
	if after.Tailscale.AuthKey != "tskey-auth-testsecret-9876zyxw" || after.GitHub.MirrorURL != "https://gh-proxy.example.com" || after.Server.SBDomain != "node.example.com" {
		t.Fatalf("PUT /api/sb/subs modified unrelated sections: %+v", after)
	}
}

func TestSystemMirrorAPI_PutValidationAndPreservation(t *testing.T) {
	dir := t.TempDir()
	cfgPath := seedDomainConfigYAML(t, dir)
	srv := New(Options{ConfigPath: cfgPath})

	for _, bad := range []string{`{"mirrorUrl":"ftp://example.com"}`, `{"mirrorUrl":"javascript:alert(1)"}`, `{"mirrorUrl":"https://bad host"}`} {
		req := httptest.NewRequest(http.MethodPut, "/api/system/mirror", bytes.NewBufferString(bad))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		srv.Mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for invalid mirror %s, got %d body=%s", bad, rec.Code, rec.Body.String())
		}
	}

	reqOK := httptest.NewRequest(http.MethodPut, "/api/system/mirror", bytes.NewBufferString(`{"mirrorUrl":"https://mirror.example.com/"}`))
	reqOK.Header.Set("Content-Type", "application/json")
	recOK := httptest.NewRecorder()
	srv.Mux.ServeHTTP(recOK, reqOK)
	if recOK.Code != http.StatusOK {
		t.Fatalf("PUT /api/system/mirror status=%d body=%s", recOK.Code, recOK.Body.String())
	}
	after, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if after.GitHub.MirrorURL != "https://mirror.example.com/" {
		t.Fatalf("unexpected mirrorUrl: %q", after.GitHub.MirrorURL)
	}
	if after.Tailscale.AuthKey != "tskey-auth-testsecret-9876zyxw" || len(after.Subs) != 1 {
		t.Fatalf("PUT /api/system/mirror mutated unrelated sections: %+v", after)
	}
}

func TestTsStartArgs_ReconfigureAndExplicitAcceptRoutesFalse(t *testing.T) {
	if got := TsStartArgs(map[string]any{"mode": "client", "acceptRoutes": false, "reconfigure": true}); !slices.Equal(got, []string{"ts", "start", "--mode", "client", "--accept-routes=false", "--reconfigure"}) {
		t.Fatalf("unexpected TsStartArgs(reconfigure+false): %v", got)
	}
	if got := TsStartArgs(map[string]any{"mode": "gateway", "acceptRoutes": true, "reconfigure": true}); !slices.Equal(got, []string{"ts", "start", "--mode", "gateway", "--accept-routes", "--reconfigure"}) {
		t.Fatalf("unexpected TsStartArgs(reconfigure+true): %v", got)
	}
}
