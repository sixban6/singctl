// 文件职责：验证 Caddyfile mTLS 缺失优雅降级、只读分享链接提取与 WARP 服务端配置编译闭环。
package deploy_test

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"singctl/internal/config"
	"singctl/internal/deploy"
)

func TestPreviewCaddyfile_GracefulMtlsDegradation_And_InspectShareLinks(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			NodeTag:        "us1",
			NodeDomain:     "us1.example.com",
			SubstoreDomain: "sub.example.com",
			ServerIP:       "2001:db8::10",
			CFDNSKey:       "cf-test-token",
			Sni:            "www.apple.com",
			Hy2Port:        8443,
			VlessPort:      443,
			WebAdmin: config.WebAdminConfig{
				Enabled: true,
				Port:    8092,
				Path:    "/sr/TestAdminToken12345678",
			},
			WebTerminal: config.WebTerminalConfig{
				Enabled:       true,
				Port:          18080,
				Path:          "ops-shell",
				SSHTunnelPort: 18081,
				SSHTunnelPath: "ssh-ws",
				MtlsCA:        "/nonexistent/mtls/ca.crt",
			},
		},
	}

	rawCaddy, err := deploy.PreviewCaddyfile(cfg)
	if err != nil {
		t.Fatalf("PreviewCaddyfile failed: %v", err)
	}
	wantToken := config.DeriveGatewayToken("/sr/TestAdminToken12345678")
	if !strings.Contains(rawCaddy, wantToken) || !strings.Contains(rawCaddy, "[2001:db8::10]") {
		t.Fatalf("expected gateway token and bracketed IPv6 in Caddyfile:\n%s", rawCaddy)
	}

	degraded := deploy.PrepareRuntimeCaddyConfig(cfg)
	if degraded.Server.WebTerminal.Enabled {
		t.Fatal("expected PrepareRuntimeCaddyConfig to disable WebTerminal when mTLS CA is missing")
	}

	ephemeralKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privB64 := base64.RawURLEncoding.EncodeToString(ephemeralKey.Bytes())

	dir := t.TempDir()
	sbCfgPath := filepath.Join(dir, "config.json")
	sbJSON := `{
		"inbounds": [
			{
				"type": "hysteria2",
				"users": [{"password": "11111111-1111-1111-1111-111111111111"}]
			},
			{
				"type": "vless",
				"users": [{"uuid": "11111111-1111-1111-1111-111111111111"}],
				"tls": {
					"server_name": "www.apple.com",
					"reality": {
						"private_key": "` + privB64 + `",
						"short_id": ["01020304"]
					}
				}
			}
		]
	}`
	if err := os.WriteFile(sbCfgPath, []byte(sbJSON), 0600); err != nil {
		t.Fatal(err)
	}
	hy2Link, vrLink, hy2Port, vlessPort := deploy.InspectExistingShareLinks(cfg, sbCfgPath)
	if !strings.HasPrefix(hy2Link, "hysteria2://11111111-1111-1111-1111-111111111111@us1.example.com:8443") || hy2Port != 8443 {
		t.Fatalf("unexpected hy2 share link (%q, port=%d)", hy2Link, hy2Port)
	}
	if !strings.HasPrefix(vrLink, "vless://11111111-1111-1111-1111-111111111111@us1.example.com:443") || vlessPort != 443 {
		t.Fatalf("unexpected vless share link (%q, port=%d)", vrLink, vlessPort)
	}

	wr := config.WarpRoutingConfig{
		Mode:          "split",
		Presets:       map[string]bool{"openai": true, "netflix": false},
		WarpDomains:   []string{"custom-ai.example.com"},
		WarpCIDRs:     []string{"198.51.100.0/24"},
		DirectDomains: []string{"direct.example.com"},
		DirectCIDRs:   []string{"203.0.113.0/24"},
	}
	presets := deploy.BuildPresetStateList(wr)
	if len(presets) == 0 {
		t.Fatal("expected non-empty WARP preset state list")
	}

	baseSrvJSON := `{"outbounds":[{"type":"direct","tag":"direct"}],"route":{"rules":[],"final":"direct"}}`
	if _, err := deploy.ApplyWarpRoutingToServerConfigJSON([]byte(baseSrvJSON), config.WarpRoutingConfig{Mode: "invalid"}); err == nil {
		t.Fatal("expected invalid WARP mode to be rejected")
	}
	appliedJSON, err := deploy.ApplyWarpRoutingToServerConfigJSON([]byte(baseSrvJSON), wr)
	if err != nil {
		t.Fatalf("ApplyWarpRoutingToServerConfigJSON split failed: %v", err)
	}
	if !strings.Contains(string(appliedJSON), `"WARP"`) || !strings.Contains(string(appliedJSON), "custom-ai.example.com") {
		t.Fatalf("expected WARP outbound and custom domain in server config:\n%s", string(appliedJSON))
	}

	globalJSON, err := deploy.ApplyWarpRoutingToServerConfigJSON(appliedJSON, config.WarpRoutingConfig{Mode: "global_warp"})
	if err != nil || (!strings.Contains(string(globalJSON), `"final": "WARP"`) && !strings.Contains(string(globalJSON), `"final":"WARP"`)) {
		t.Fatalf("ApplyWarpRoutingToServerConfigJSON global_warp failed: err=%v json=%s", err, string(globalJSON))
	}

	offJSON, err := deploy.ApplyWarpRoutingToServerConfigJSON(globalJSON, config.WarpRoutingConfig{Mode: "bypass"})
	if err != nil || strings.Contains(string(offJSON), "custom-ai.example.com") {
		t.Fatalf("ApplyWarpRoutingToServerConfigJSON off failed to clean rules: err=%v json=%s", err, string(offJSON))
	}
}
