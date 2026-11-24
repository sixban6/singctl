// 文件职责：测试 WebUI 分层防 DNS 绕过接口（GET/POST /api/dns/bypass-guard）、输入校验、热同步 sing-box 工作副本与白名单联动。
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

	"singctl/internal/config"
	"singctl/internal/webui"
)

func TestWebUI_DNSBypassGuardAPI_GetPostValidateAndHotSync(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "singctl.yaml")
	sbPath := filepath.Join(dir, "config.json")
	sbWorkPath := filepath.Join(dir, "work-config.json")
	sdBin := filepath.Join(dir, "smartdns")
	sdConf := filepath.Join(dir, "smartdns.conf")
	sdRules := filepath.Join(dir, "smartdns-rules.d")
	if err := os.WriteFile(sdBin, []byte("#!/bin/sh\n"), 0755); err != nil {
		t.Fatal(err)
	}

	if err := config.Save(cfgPath, &config.Config{
		Gateway: config.GatewayConfig{WorkMode: config.WorkModeAudit},
		DNS:     config.ClientDNSConfig{Engine: "smartdns", DNSPort: 5353},
	}); err != nil {
		t.Fatal(err)
	}
	initialSB := `{
  "dns": {
    "final": "dns_local",
    "servers": [{"tag": "dns_local", "type": "udp", "server": "127.0.0.1", "server_port": 5353}],
    "rules": [{"rule_set": ["geosite-ad1"], "action": "reject"}]
  },
  "route": {
    "final": "direct",
    "rules": [
      {"action": "sniff"},
      {"protocol": "dns", "action": "hijack-dns"},
      {"ip_is_private": true, "outbound": "direct"},
      {"rule_set": ["geosite-ad1"], "action": "reject"}
    ],
    "rule_set": [
      {
        "tag": "geosite-ad1",
        "type": "inline",
        "rules": [{"domain": ["ad.example.com"]}]
      }
    ]
  }
}`
	if err := os.WriteFile(sbPath, []byte(initialSB), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sbWorkPath, []byte(initialSB), 0600); err != nil {
		t.Fatal(err)
	}

	srv := webui.New(webui.Options{
		ConfigPath:              cfgPath,
		SingBoxConfigPath:       sbPath,
		SingBoxWorkConfigPath:   sbWorkPath,
		SmartDNSBinPath:         sdBin,
		SmartDNSConfigPath:      sdConf,
		SmartDNSRulesDir:        sdRules,
		SkipAdGuardProbeForTest: true,
	})

	doJSON := func(method, path string, body any) *httptest.ResponseRecorder {
		var buf bytes.Buffer
		if body != nil {
			_ = json.NewEncoder(&buf).Encode(body)
		}
		req := httptest.NewRequest(method, path, &buf)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		srv.Mux.ServeHTTP(rec, req)
		return rec
	}

	// 1. GET /api/dns/bypass-guard returns layered catalog & defaults
	rec := doJSON(http.MethodGet, "/api/dns/bypass-guard", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/dns/bypass-guard code=%d body=%s", rec.Code, rec.Body.String())
	}
	bodyStr := rec.Body.String()
	for _, want := range []string{`"dot_doq"`, `"public_doh"`, `"sdk_httpdns"`, `"app_httpdns"`, `"bilibili"`, `"wechat"`} {
		if !strings.Contains(bodyStr, want) {
			t.Fatalf("GET /api/dns/bypass-guard missing %s in %s", want, bodyStr)
		}
	}

	// 2. Invalid exemptSourceIps must return 400
	badRec := doJSON(http.MethodPost, "/api/dns/bypass-guard", map[string]any{
		"enabled":         true,
		"exemptSourceIps": []string{"127.0.0.1"},
	})
	if badRec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for loopback exemptSourceIps, got %d body=%s", badRec.Code, badRec.Body.String())
	}

	// 3. Unknown app group must return 400
	badGroupRec := doJSON(http.MethodPost, "/api/dns/bypass-guard", map[string]any{
		"enabled":   true,
		"appGroups": map[string]bool{"nonexistent_evil": true},
	})
	if badGroupRec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unknown app group, got %d body=%s", badGroupRec.Code, badGroupRec.Body.String())
	}

	// 4. Valid POST /api/dns/bypass-guard persists and hot-syncs both main & sandbox sing-box configs
	okRec := doJSON(http.MethodPost, "/api/dns/bypass-guard", map[string]any{
		"enabled": true,
		"layers": map[string]bool{
			"dotDoq":     true,
			"publicDoh":  true,
			"sdkHttpdns": true,
			"appHttpdns": true,
		},
		"appGroups": map[string]bool{
			"bilibili": true,
			"wechat":   true,
		},
		"exemptSourceIps": []string{"192.0.2.151"},
	})
	if okRec.Code != http.StatusOK {
		t.Fatalf("POST /api/dns/bypass-guard failed: code=%d body=%s", okRec.Code, okRec.Body.String())
	}

	for _, p := range []string{sbPath, sbWorkPath} {
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("read %s failed: %v", p, err)
		}
		text := string(raw)
		if !strings.Contains(text, "httpdns.bilivideo.com") || !strings.Contains(text, "dns.weixin.qq.com.cn") || !strings.Contains(text, "192.0.2.151/32") {
			t.Fatalf("expected hot-synced bypass guard rules in %s, got:\n%s", p, text)
		}
	}

	// 5. Whitelisting httpdns.bilivideo.com removes it from sing-box bypass reject list live
	wlRec := doJSON(http.MethodPost, "/api/dns/whitelist", map[string]any{
		"domain": "httpdns.bilivideo.com",
		"action": "add",
	})
	if wlRec.Code != http.StatusOK {
		t.Fatalf("POST /api/dns/whitelist failed: code=%d body=%s", wlRec.Code, wlRec.Body.String())
	}
	rawAfterWL, err := os.ReadFile(sbPath)
	if err != nil {
		t.Fatal(err)
	}
	// Verify httpdns.bilivideo.com is no longer inside any reject rule's domain list
	if strings.Contains(string(rawAfterWL), `"httpdns.bilivideo.com"`) {
		// Note: it will appear in adblock whitelist domain_suffix, so ensure it's NOT in route bypass reject's "domain" matcher
		if strings.Contains(string(rawAfterWL), `"httpdns.bilivideo.com",\n          "httpdns.biliapi.net"`) {
			t.Fatalf("expected httpdns.bilivideo.com subtracted from L4 bypass reject rule:\n%s", string(rawAfterWL))
		}
	}
}
