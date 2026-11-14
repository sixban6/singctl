package test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/deploy"
	"singctl/internal/deploy/masksite"
	"singctl/internal/scripts"
	"singctl/internal/util/github"
	"strings"
	"testing"
)

func TestNormalizeVersion(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"v1.14.3", "1.14.3"},
		{"1.14.3", "1.14.3"},
		{"  v2.11.7\n", "2.11.7"},
		{"v0.0.1-rc.1", "0.0.1-rc.1"},
		{"", ""},
	}

	for _, tt := range tests {
		got := deploy.NormalizeVersion(tt.input)
		if got != tt.expected {
			t.Errorf("NormalizeVersion(%q) = %q, expected %q", tt.input, got, tt.expected)
		}
	}
}

func TestParseCaddyVersion(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{
			input:    "v2.11.7 h1:yj0Y4fYZGPkSvibBJ1sTWE33xC0fxztVyXEW5iIdUT4=\n",
			expected: "2.11.7",
		},
		{
			input:    "v2.8.4",
			expected: "2.8.4",
		},
		{
			input:    "caddy v2.9.1 h1:xxxx\n",
			expected: "2.9.1",
		},
		{
			input:    "2.11.7",
			expected: "2.11.7",
		},
	}

	for _, tt := range tests {
		got, err := deploy.ParseCaddyVersion(tt.input)
		if err != nil {
			t.Errorf("ParseCaddyVersion(%q) unexpected error: %v", tt.input, err)
		}
		if got != tt.expected {
			t.Errorf("ParseCaddyVersion(%q) = %q, expected %q", tt.input, got, tt.expected)
		}
	}

	// Test invalid input
	if _, err := deploy.ParseCaddyVersion(""); err == nil {
		t.Error("expected error on empty input, got nil")
	}
}

func TestParseWireproxyVersion(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{
			input:    "wireproxy, version 1.1.3\n",
			expected: "1.1.3",
		},
		{
			input:    "wireproxy, version v1.1.3",
			expected: "1.1.3",
		},
		{
			input:    "wireproxy v1.0.8-dev",
			expected: "1.0.8-dev",
		},
		{
			input:    "1.1.3",
			expected: "1.1.3",
		},
	}

	for _, tt := range tests {
		got, err := deploy.ParseWireproxyVersion(tt.input)
		if err != nil {
			t.Errorf("ParseWireproxyVersion(%q) unexpected error: %v", tt.input, err)
		}
		if got != tt.expected {
			t.Errorf("ParseWireproxyVersion(%q) = %q, expected %q", tt.input, got, tt.expected)
		}
	}

	// Test invalid input
	if _, err := deploy.ParseWireproxyVersion(""); err == nil {
		t.Error("expected error on empty input, got nil")
	}
}

type mockRewriteTransport struct {
	targetURL string
	base      http.RoundTripper
}

func (m *mockRewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	rewritten, err := http.NewRequestWithContext(req.Context(), req.Method, m.targetURL+req.URL.RequestURI(), req.Body)
	if err != nil {
		return nil, err
	}
	rewritten.Header = clone.Header
	return m.base.RoundTrip(rewritten)
}

func TestCheckComponentVersion_MockServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		rel := github.Release{TagName: "v2.11.7"}
		_ = json.NewEncoder(w).Encode(rel)
	}))
	defer server.Close()

	// Inject hermetic test client so CI runners with direct Google/GitHub access still hit the mock server.
	baseClient := server.Client()
	deploy.ReleaseClient = &http.Client{
		Transport: &mockRewriteTransport{
			targetURL: server.URL,
			base:      baseClient.Transport,
		},
	}
	defer func() { deploy.ReleaseClient = nil }()

	cfg := &config.Config{}

	info, err := deploy.CheckComponentUpdate("caddy", cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Component != "caddy" {
		t.Errorf("expected info.Component 'caddy', got %q", info.Component)
	}
	if info.LatestVersion != "2.11.7" {
		t.Errorf("expected LatestVersion '2.11.7', got %q", info.LatestVersion)
	}
}

func TestEmbeddedScripts(t *testing.T) {
	// Test getting script content
	startScript := scripts.GetStartScript()
	if startScript == "" {
		t.Error("Start script content is empty")
	}

	stopScript := scripts.GetStopScript()
	if stopScript == "" {
		t.Error("Stop script content is empty")
	}

	hasValidShebang := func(s string) bool {
		return strings.HasPrefix(s, "#!/bin/sh") || strings.HasPrefix(s, "#!/bin/bash")
	}

	// Test OS-specific script selection
	switch runtime.GOOS {
	case "darwin":
		if !hasValidShebang(startScript) || !hasValidShebang(stopScript) {
			t.Error("macOS scripts should start with #!/bin/sh or #!/bin/bash")
		}
		if !strings.Contains(startScript, "macOS sing-box TUN模式") {
			t.Error("macOS start script should contain TUN mode description")
		}
		if !strings.Contains(stopScript, "macOS sing-box TUN模式") {
			t.Error("macOS stop script should contain TUN mode description")
		}
	case "windows":
		if !strings.Contains(strings.ToLower(startScript), "sing-box") {
			t.Error("Windows start script should reference sing-box")
		}
	default:
		if !hasValidShebang(startScript) {
			t.Error("Linux start script doesn't contain valid shebang (#!/bin/sh or #!/bin/bash)")
		}
		if !hasValidShebang(stopScript) {
			t.Error("Linux stop script doesn't contain valid shebang (#!/bin/sh or #!/bin/bash)")
		}
		if !strings.Contains(startScript, "OpenWrt sing-box TProxy模式") && !strings.Contains(startScript, "Debian sing-box TProxy模式") {
			t.Error("Linux start script should contain TProxy mode description")
		}
	}
}

func TestWriteScripts(t *testing.T) {
	tempDir := t.TempDir()

	// Test writing start script
	startPath := filepath.Join(tempDir, "test_start.sh")
	if err := scripts.WriteStartScript(startPath); err != nil {
		t.Fatalf("Failed to write start script: %v", err)
	}

	// Verify file exists and is executable
	info, err := os.Stat(startPath)
	if err != nil {
		t.Fatalf("Start script file not found: %v", err)
	}
	if info.Mode()&0111 == 0 {
		t.Error("Start script is not executable")
	}

	// Test writing stop script
	stopPath := filepath.Join(tempDir, "test_stop.sh")
	if err := scripts.WriteStopScript(stopPath); err != nil {
		t.Fatalf("Failed to write stop script: %v", err)
	}

	// Verify file exists and is executable
	info, err = os.Stat(stopPath)
	if err != nil {
		t.Fatalf("Stop script file not found: %v", err)
	}
	if info.Mode()&0111 == 0 {
		t.Error("Stop script is not executable")
	}
}

func TestPreviewCaddyfile_SeparatedDomainsAndFallback(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			NodeDomain:     "node.example.com",
			SubstoreDomain: "sub.example.com",
			CFDNSKey:       "dummy_cf_key",
			Sni:            "swdist.apple.com",
		},
	}

	content, err := deploy.PreviewCaddyfile(cfg)
	if err != nil {
		t.Fatalf("PreviewCaddyfile failed: %v", err)
	}

	// 1. Layer 4 fallback to 9445
	if !strings.Contains(content, "proxy 127.0.0.1:9445") {
		t.Errorf("expected fallback route to 9445, got:\n%s", content)
	}

	// 2. Both domains in Layer 4
	if !strings.Contains(content, "sni sub.example.com node.example.com") {
		t.Errorf("expected both domains in SNI matcher, got:\n%s", content)
	}

	// 3. Layer 7 site blocks
	if !strings.Contains(content, "https://sub.example.com:9443") || !strings.Contains(content, "reverse_proxy http://127.0.0.1:3001") {
		t.Errorf("expected substore domain to reverse proxy to 3001, got:\n%s", content)
	}
	if !strings.Contains(content, "https://node.example.com:9443") {
		t.Errorf("expected node domain block in layer 7, got:\n%s", content)
	}

	// 4. Fallback site block on 9445
	if !strings.Contains(content, ":9445") || !strings.Contains(content, "tls internal") {
		t.Errorf("expected :9445 with tls internal, got:\n%s", content)
	}

	// 5. Mask site root
	if !strings.Contains(content, "root * /var/www/mask-site") {
		t.Errorf("expected root * /var/www/mask-site, got:\n%s", content)
	}

	// 6. Double CA fallback (Let's Encrypt + ZeroSSL)
	if !strings.Contains(content, "https://acme.zerossl.com/v2/DV90") {
		t.Errorf("expected ZeroSSL fallback issuer in Caddyfile, got:\n%s", content)
	}
	if !strings.Contains(content, "email admin@example.com") {
		t.Errorf("expected ZeroSSL email admin@example.com in Caddyfile, got:\n%s", content)
	}
}

func TestPreviewCaddyfile_BackwardCompatibility(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			SBDomain: "legacy.example.com",
			CFDNSKey: "dummy_cf_key",
			Sni:      "swdist.apple.com",
		},
	}

	content, err := deploy.PreviewCaddyfile(cfg)
	if err != nil {
		t.Fatalf("PreviewCaddyfile failed: %v", err)
	}

	if !strings.Contains(content, "https://legacy.example.com:9443") {
		t.Errorf("expected legacy domain in layer 7, got:\n%s", content)
	}

	if !strings.Contains(content, "proxy 127.0.0.1:9445") {
		t.Errorf("expected fallback route to 9445, got:\n%s", content)
	}
}

func TestPreviewCaddyfile_PublicIPv4ShortlivedCert(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			NodeDomain:     "node.example.com",
			SubstoreDomain: "sub.example.com",
			ServerIP:       "203.0.113.10",
			CFDNSKey:       "dummy_cf_key",
			Sni:            "swdist.apple.com",
		},
	}

	content, err := deploy.PreviewCaddyfile(cfg)
	if err != nil {
		t.Fatalf("PreviewCaddyfile failed: %v", err)
	}

	// 1. Global default_sni and fallback_sni
	if !strings.Contains(content, "default_sni 203.0.113.10") || !strings.Contains(content, "fallback_sni 203.0.113.10") {
		t.Errorf("expected default_sni and fallback_sni for IP, got:\n%s", content)
	}

	// 2. Port 80 listener for HTTP-01 challenge and 301 redirect to HTTPS with method filtering
	if !strings.Contains(content, ":80 {") || !strings.Contains(content, "redir https://{host}{uri} 301") {
		t.Errorf("expected :80 listener with 301 redirect, got:\n%s", content)
	}
	if !strings.Contains(content, "@validMethods method GET POST HEAD OPTIONS") || !strings.Contains(content, "respond \"Method Not Allowed\" 405") {
		t.Errorf("expected :80 listener with RFC 7231 method filtering, got:\n%s", content)
	}

	// 3. Public IP shortlived ACME profile block on 9445
	if !strings.Contains(content, "https://203.0.113.10:9445") {
		t.Errorf("expected https://203.0.113.10:9445 block, got:\n%s", content)
	}
	if !strings.Contains(content, "profile shortlived") {
		t.Errorf("expected profile shortlived in ACME issuer, got:\n%s", content)
	}
}

func TestPreviewCaddyfile_PublicIPv6ShortlivedCert(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			NodeDomain:     "node.example.com",
			SubstoreDomain: "sub.example.com",
			ServerIP:       "2001:db8::1",
			CFDNSKey:       "dummy_cf_key",
			Sni:            "swdist.apple.com",
		},
	}

	content, err := deploy.PreviewCaddyfile(cfg)
	if err != nil {
		t.Fatalf("PreviewCaddyfile failed: %v", err)
	}

	// 1. Global default_sni without brackets
	if !strings.Contains(content, "default_sni 2001:db8::1") || !strings.Contains(content, "fallback_sni 2001:db8::1") {
		t.Errorf("expected unbracketed default_sni for IPv6, got:\n%s", content)
	}

	// 2. Site block with brackets for IPv6
	if !strings.Contains(content, "https://[2001:db8::1]:9445") {
		t.Errorf("expected bracketed IPv6 site block https://[2001:db8::1]:9445, got:\n%s", content)
	}
	if !strings.Contains(content, "profile shortlived") {
		t.Errorf("expected profile shortlived, got:\n%s", content)
	}
}

func TestPreviewCaddyfile_Udp443Hy2Only(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			NodeDomain:     "node.example.com",
			SubstoreDomain: "sub.example.com",
			CFDNSKey:       "dummy_cf_key",
		},
	}

	content, err := deploy.PreviewCaddyfile(cfg)
	if err != nil {
		t.Fatalf("PreviewCaddyfile failed: %v", err)
	}

	if strings.Contains(content, "@tuic quic") {
		t.Errorf("expected no @tuic quic in Caddyfile, got:\n%s", content)
	}
	if strings.Contains(content, "proxy udp/127.0.0.1:52023") {
		t.Errorf("expected no proxy to TUIC 52023, got:\n%s", content)
	}
	if !strings.Contains(content, "proxy udp/127.0.0.1:52021") {
		t.Errorf("expected proxy to Hysteria 2 on 52021, got:\n%s", content)
	}
}

func TestPreviewCaddyfile_WebTerminal(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			NodeDomain:     "node.example.com",
			SubstoreDomain: "sub.example.com",
			CFDNSKey:       "dummy_cf_key",
			WebTerminal: config.WebTerminalConfig{
				Enabled: true,
				Path:    "/ops-shell-test123",
				Port:    18080,
				MtlsCA:  "/etc/caddy/mtls/ca.crt",
			},
		},
	}

	content, err := deploy.PreviewCaddyfile(cfg)
	if err != nil {
		t.Fatalf("PreviewCaddyfile failed: %v", err)
	}

	// 1. Verify mTLS client_auth under NodeDomain
	if !strings.Contains(content, "client_auth {") || !strings.Contains(content, "mode verify_if_given") || !strings.Contains(content, "trust_pool file /etc/caddy/mtls/ca.crt") {
		t.Errorf("expected mTLS client_auth block, got:\n%s", content)
	}

	// 2. Verify terminal route on NodeDomain
	if !strings.Contains(content, "redir /ops-shell-test123 /ops-shell-test123/") {
		t.Errorf("expected redir for terminal, got:\n%s", content)
	}
	if !strings.Contains(content, "handle /ops-shell-test123/* {") {
		t.Errorf("expected handle /ops-shell-test123/*, got:\n%s", content)
	}
	if !strings.Contains(content, "expression {http.request.tls.client.subject} == ''") {
		t.Errorf("expected client subject empty check, got:\n%s", content)
	}
	if !strings.Contains(content, "respond @unauth 404") {
		t.Errorf("expected respond @unauth 404, got:\n%s", content)
	}
	if !strings.Contains(content, "reverse_proxy 127.0.0.1:18080") {
		t.Errorf("expected reverse_proxy 127.0.0.1:18080, got:\n%s", content)
	}

	// 3. Verify native SSH-over-WSS route
	if !strings.Contains(content, "handle /ssh-ws* {") {
		t.Errorf("expected handle /ssh-ws*, got:\n%s", content)
	}
	if !strings.Contains(content, "reverse_proxy 127.0.0.1:18081") {
		t.Errorf("expected reverse_proxy 127.0.0.1:18081, got:\n%s", content)
	}
}

func TestPreviewCaddyfile_WebAdmin(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			NodeDomain:     "node.example.com",
			SubstoreDomain: "sub.example.com",
			CFDNSKey:       "dummy_cf_key",
			Sni:            "swdist.apple.com",
			WebAdmin: config.WebAdminConfig{
				Enabled:  true,
				Port:     8092,
				Path:     "/admin_sec9988",
				Username: "admin",
				Password: "testpassword",
			},
		},
	}

	content, err := deploy.PreviewCaddyfile(cfg)
	if err != nil {
		t.Fatalf("PreviewCaddyfile failed: %v", err)
	}

	if !strings.Contains(content, "redir /admin_sec9988 /admin_sec9988/ 308") {
		t.Errorf("expected redir for WebAdmin, got:\n%s", content)
	}
	if !strings.Contains(content, "handle_path /admin_sec9988/* {") {
		t.Errorf("expected handle_path /admin_sec9988/*, got:\n%s", content)
	}
	if !strings.Contains(content, "reverse_proxy http://127.0.0.1:8092") {
		t.Errorf("expected reverse_proxy http://127.0.0.1:8092, got:\n%s", content)
	}
	if !strings.Contains(content, "header_up X-Real-IP {client_ip}") {
		t.Errorf("expected Caddy to overwrite X-Real-IP, got:\n%s", content)
	}
	if !strings.Contains(content, "header_up X-Geo-Country {header.CF-IPCountry}") {
		t.Errorf("expected Caddy to pass X-Geo-Country, got:\n%s", content)
	}
	expectedGateway := "header_up X-Singctl-Gateway " + config.DeriveGatewayToken("/admin_sec9988")
	if !strings.Contains(content, expectedGateway) {
		t.Errorf("expected Caddy to inject %q, got:\n%s", expectedGateway, content)
	}
	if !strings.Contains(content, "header_up -X-Forwarded-For") || !strings.Contains(content, "header_up -CF-Connecting-IP") {
		t.Errorf("expected Caddy to drop client forwarding headers, got:\n%s", content)
	}

	// 验证 PROXY Protocol v2 与真实访客 IP 透传配置
	if !strings.Contains(content, "servers 127.0.0.1:9443") || !strings.Contains(content, "proxy_protocol v2") {
		t.Errorf("expected proxy_protocol v2 and servers 127.0.0.1:9443 configuration in Caddyfile, got:\n%s", content)
	}
	if !strings.Contains(content, "listener_wrappers") || !strings.Contains(content, "trusted_proxies static") {
		t.Errorf("expected listener_wrappers and trusted_proxies in Caddyfile, got:\n%s", content)
	}
	if !strings.Contains(content, "client_ip_headers CF-Connecting-IP X-Forwarded-For") {
		t.Errorf("expected client_ip_headers in Caddyfile, got:\n%s", content)
	}
}

func TestPreviewCaddyfile_SubHubMaskFallback(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			NodeDomain:     "node.example.com",
			SubstoreDomain: "sub.example.com",
			CFDNSKey:       "dummy_cf_key",
			Sni:            "swdist.apple.com",
		},
	}

	content, err := deploy.PreviewCaddyfile(cfg)
	if err != nil {
		t.Fatalf("PreviewCaddyfile failed: %v", err)
	}

	if !strings.Contains(content, "@subhub path ") {
		t.Errorf("expected @subhub path matcher on SubstoreDomain, got:\n%s", content)
	}
	if strings.Count(content, "root * /var/www/mask-site") < 3 {
		t.Errorf("expected mask-site fallback on SubstoreDomain, NodeDomain, and :9445, got:\n%s", content)
	}
}

func TestPreviewCaddyfile_EmptySubstoreDomainFallsBackToNodeDomain(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			NodeDomain:     "sg.example.com",
			SubstoreDomain: "",
			CFDNSKey:       "dummy_cf_key",
			Sni:            "swdist.apple.com",
		},
	}

	content, err := deploy.PreviewCaddyfile(cfg)
	if err != nil {
		t.Fatalf("PreviewCaddyfile failed: %v", err)
	}
	if strings.Contains(content, "https://:9443") {
		t.Fatalf("Caddyfile must never render empty hostname site block https://:9443, got:\n%s", content)
	}
	if !strings.Contains(content, "https://sg.example.com:9443") {
		t.Fatalf("expected https://sg.example.com:9443 when SubstoreDomain is empty, got:\n%s", content)
	}
	for _, hdr := range []string{
		"-Server",
		`Strict-Transport-Security "max-age=31536000"`,
		`X-Content-Type-Options "nosniff"`,
		`X-Frame-Options "SAMEORIGIN"`,
		`Referrer-Policy "strict-origin-when-cross-origin"`,
	} {
		if !strings.Contains(content, hdr) {
			t.Errorf("expected hardened security header %q in Caddyfile, got:\n%s", hdr, content)
		}
	}
}

func TestPreviewCaddyfileAndSingBox_CustomHy2AndVlessPortsAndRealitySelfSteal(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			NodeTag:    "nat1",
			NodeDomain: "nat1.cdn.example.com",
			Hy2Port:    11501,
			VlessPort:  11502,
			CFDNSKey:   "cf-test-token",
			Sni:        "nat1.cdn.example.com",
		},
	}

	caddyContent, err := deploy.PreviewCaddyfile(cfg)
	if err != nil {
		t.Fatalf("PreviewCaddyfile failed: %v", err)
	}
	if !strings.Contains(caddyContent, ":443 :11502 {") {
		t.Errorf("expected Caddy Layer4 TCP to listen on :443 :11502, got:\n%s", caddyContent)
	}
	if !strings.Contains(caddyContent, "udp/:443 udp/:11501 {") {
		t.Errorf("expected Caddy Layer4 UDP to listen on udp/:443 udp/:11501, got:\n%s", caddyContent)
	}

	sbs, err := deploy.NewSingBoxServer(cfg)
	if err != nil {
		t.Fatalf("NewSingBoxServer failed: %v", err)
	}
	if !strings.Contains(sbs.ShareLinkHy2, "@nat1.cdn.example.com:11501/") {
		t.Errorf("expected ShareLinkHy2 to use port 11501, got %q", sbs.ShareLinkHy2)
	}
	if !strings.Contains(sbs.ShareLinkVless, "@nat1.cdn.example.com:11502?") {
		t.Errorf("expected ShareLinkVless to use port 11502, got %q", sbs.ShareLinkVless)
	}

	sbConfig, err := sbs.PreviewServerConfig()
	if err != nil {
		t.Fatalf("PreviewServerConfig failed: %v", err)
	}
	if !strings.Contains(sbConfig, `"server": "127.0.0.1"`) || !strings.Contains(sbConfig, `"server_port": 9443`) {
		t.Errorf("expected Reality self-steal mode (SNI == NodeDomain) to point handshake to 127.0.0.1:9443, got:\n%s", sbConfig)
	}
}

func TestGenerateSite(t *testing.T) {
	html, meta, err := masksite.GenerateSite()
	if err != nil {
		t.Fatalf("GenerateSite failed: %v", err)
	}

	if html == "" {
		t.Fatalf("Expected non-empty HTML")
	}
	if meta.BlogTitle == "" {
		t.Errorf("Expected non-empty BlogTitle")
	}
	if meta.AuthorName == "" {
		t.Errorf("Expected non-empty AuthorName")
	}
	if meta.Category == "" {
		t.Errorf("Expected non-empty Category")
	}
	if len(meta.Articles) < 3 {
		t.Errorf("Expected at least 3 articles, got %d", len(meta.Articles))
	}

	if !strings.Contains(html, meta.BlogTitle) {
		t.Errorf("HTML should contain blog title %q", meta.BlogTitle)
	}
	if !strings.Contains(html, meta.AuthorName) {
		t.Errorf("HTML should contain author name %q", meta.AuthorName)
	}
	if !strings.Contains(html, "modal-overlay") {
		t.Errorf("HTML should contain modal overlay reader")
	}
	if !strings.Contains(html, "data-theme") {
		t.Errorf("HTML should contain theme toggle")
	}
}

func TestGenerateAndWrite(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "masksite-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	meta, err := masksite.GenerateAndWrite(tmpDir)
	if err != nil {
		t.Fatalf("GenerateAndWrite failed: %v", err)
	}

	indexPath := tmpDir + "/index.html"
	content, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatalf("Failed to read index.html: %v", err)
	}

	if !strings.Contains(string(content), meta.BlogTitle) {
		t.Errorf("index.html should contain blog title")
	}

	existingMeta := masksite.ReadExistingMeta(tmpDir)
	if existingMeta == "" || !strings.Contains(existingMeta, meta.BlogTitle) {
		t.Errorf("mask_meta.json should contain blog title")
	}
}

func TestHighEntropy(t *testing.T) {
	titles := make(map[string]bool)
	for i := 0; i < 10; i++ {
		_, meta, err := masksite.GenerateSite()
		if err != nil {
			t.Fatalf("GenerateSite failed at iteration %d: %v", i, err)
		}
		titles[meta.BlogTitle+"-"+meta.AuthorName] = true
	}
	// Across 10 generations, we should definitely have multiple unique combinations
	if len(titles) < 3 {
		t.Errorf("Expected high diversity, but only got %d unique combinations across 10 generations", len(titles))
	}
}

func TestServerConfigTemplate_RejectsPrivateIPs(t *testing.T) {
	raw, err := deploy.TemplateFiles.ReadFile("templates/server_config.json")
	if err != nil {
		t.Fatalf("read server_config.json: %v", err)
	}

	var parsed struct {
		Route struct {
			Rules []map[string]any `json:"rules"`
		} `json:"route"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("server_config.json is invalid JSON: %v", err)
	}

	foundPrivateReject := false
	for _, rule := range parsed.Route.Rules {
		ipPrivate, ok := rule["ip_is_private"].(bool)
		if !ok || !ipPrivate {
			continue
		}
		if rule["outbound"] != nil {
			t.Fatalf("ip_is_private rule must not route to outbound %v (SSRF/loopback bypass risk)", rule["outbound"])
		}
		if rule["action"] != "reject" {
			t.Fatalf("expected ip_is_private rule action='reject', got %v", rule["action"])
		}
		foundPrivateReject = true
	}

	if !foundPrivateReject {
		t.Fatal("server_config.json must include an ip_is_private reject rule")
	}
}

func TestMergeNodeContent_EmptyExisting(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			SBDomain: "hk.example.com",
			Sni:      "swdist.apple.com",
		},
	}
	sbs, err := deploy.NewSingBoxServer(cfg)
	if err != nil {
		t.Fatalf("NewSingBoxServer failed: %v", err)
	}

	res := deploy.MergeNodeContent("", sbs.ShareLinkHy2, sbs, "hysteria2")
	if res != sbs.ShareLinkHy2 {
		t.Errorf("expected %q, got %q", sbs.ShareLinkHy2, res)
	}
}

func TestMergeNodeContent_OverwriteCurrentServer(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			SBDomain: "hk.example.com",
			Sni:      "swdist.apple.com",
		},
	}
	sbs, err := deploy.NewSingBoxServer(cfg)
	if err != nil {
		t.Fatalf("NewSingBoxServer failed: %v", err)
	}

	oldLink := "hysteria2://old-uuid@hk.example.com/?sni=hk.example.com&alpn=h3&insecure=0#sec_hk_hy2"
	res := deploy.MergeNodeContent(oldLink, sbs.ShareLinkHy2, sbs, "hysteria2")

	if res != sbs.ShareLinkHy2 {
		t.Errorf("expected %q, got %q", sbs.ShareLinkHy2, res)
	}
}

func TestMergeNodeContent_PreserveOtherServerAndAppend(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			SBDomain: "hk.example.com",
			Sni:      "swdist.apple.com",
		},
	}
	sbs, err := deploy.NewSingBoxServer(cfg)
	if err != nil {
		t.Fatalf("NewSingBoxServer failed: %v", err)
	}

	otherVPSLink := "hysteria2://other-uuid@us.example.com/?sni=us.example.com&alpn=h3&insecure=0#sec_us_hy2"
	res := deploy.MergeNodeContent(otherVPSLink, sbs.ShareLinkHy2, sbs, "hysteria2")

	lines := strings.Split(res, "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d: %q", len(lines), res)
	}

	if lines[0] != otherVPSLink {
		t.Errorf("expected line 0 to be preserved %q, got %q", otherVPSLink, lines[0])
	}
	if lines[1] != sbs.ShareLinkHy2 {
		t.Errorf("expected line 1 to be new link %q, got %q", sbs.ShareLinkHy2, lines[1])
	}
}

func TestMergeNodeContent_PreserveOtherServerAndUpdateCurrent(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			SBDomain: "hk.example.com",
			Sni:      "swdist.apple.com",
		},
	}
	sbs, err := deploy.NewSingBoxServer(cfg)
	if err != nil {
		t.Fatalf("NewSingBoxServer failed: %v", err)
	}

	vps1 := "hysteria2://uuid1@jp.example.com/?sni=jp.example.com&alpn=h3#sec_jp_hy2"
	oldCurrent := "hysteria2://old-uuid@hk.example.com/?sni=hk.example.com&alpn=h3#sec_hk_hy2"
	vps3 := "hysteria2://uuid3@us.example.com/?sni=us.example.com&alpn=h3#sec_us_hy2"

	existing := strings.Join([]string{vps1, oldCurrent, vps3}, "\n")
	res := deploy.MergeNodeContent(existing, sbs.ShareLinkHy2, sbs, "hysteria2")

	lines := strings.Split(res, "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d: %q", len(lines), res)
	}

	if lines[0] != vps1 {
		t.Errorf("line 0 should be preserved vps1, got %q", lines[0])
	}
	if lines[1] != sbs.ShareLinkHy2 {
		t.Errorf("line 1 should be updated current link, got %q", lines[1])
	}
	if lines[2] != vps3 {
		t.Errorf("line 2 should be preserved vps3, got %q", lines[2])
	}
}

func TestMergeNodeContent_VlessReality(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			SBDomain: "hk.example.com",
			Sni:      "swdist.apple.com",
		},
	}
	sbs, err := deploy.NewSingBoxServer(cfg)
	if err != nil {
		t.Fatalf("NewSingBoxServer failed: %v", err)
	}

	vps1Vless := "vless://uuid-vps1@us.example.com:443?type=tcp&security=reality&sni=swdist.apple.com#sec_us_vr"
	oldHkVless := "vless://old-hk-uuid@hk.example.com:443?type=tcp&security=reality&sni=swdist.apple.com#sec_hk_vr"

	existing := vps1Vless + "\n" + oldHkVless
	res := deploy.MergeNodeContent(existing, sbs.ShareLinkVless, sbs, "vless")

	lines := strings.Split(res, "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d: %q", len(lines), res)
	}

	if lines[0] != vps1Vless {
		t.Errorf("vps1 vless should be preserved, got %q", lines[0])
	}
	if lines[1] != sbs.ShareLinkVless {
		t.Errorf("current hk vless should be updated, got %q", lines[1])
	}
}

func TestMergeNodeContent_DeduplicateCurrent(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			SBDomain: "hk.example.com",
			Sni:      "swdist.apple.com",
		},
	}
	sbs, err := deploy.NewSingBoxServer(cfg)
	if err != nil {
		t.Fatalf("NewSingBoxServer failed: %v", err)
	}

	dup1 := "hysteria2://dup1@hk.example.com/?sni=hk.example.com#sec_hk_hy2"
	vpsOther := "hysteria2://other@us.example.com/?sni=us.example.com#sec_us_hy2"
	dup2 := "hysteria2://dup2@hk.example.com/?sni=hk.example.com#sec_hk_hy2"

	existing := strings.Join([]string{dup1, vpsOther, dup2}, "\n")
	res := deploy.MergeNodeContent(existing, sbs.ShareLinkHy2, sbs, "hysteria2")

	lines := strings.Split(res, "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines (deduplicated), got %d: %q", len(lines), res)
	}

	if lines[0] != sbs.ShareLinkHy2 {
		t.Errorf("line 0 should be updated current, got %q", lines[0])
	}
	if lines[1] != vpsOther {
		t.Errorf("line 1 should be other server, got %q", lines[1])
	}
}

func TestMergeNodeContent_DeduplicateIdentical(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			SBDomain: "hk.example.com",
			Sni:      "swdist.apple.com",
		},
	}
	sbs, err := deploy.NewSingBoxServer(cfg)
	if err != nil {
		t.Fatalf("NewSingBoxServer failed: %v", err)
	}

	// Repeatedly merging the exact same link must NEVER duplicate it
	res := deploy.MergeNodeContent(sbs.ShareLinkHy2, sbs.ShareLinkHy2, sbs, "hysteria2")
	lines := strings.Split(res, "\n")
	if len(lines) != 1 {
		t.Fatalf("expected 1 line after merging identical, got %d: %q", len(lines), res)
	}

	// Multiple duplicates in existing content should be strictly cleaned up
	existing := strings.Join([]string{sbs.ShareLinkHy2, sbs.ShareLinkHy2, sbs.ShareLinkHy2}, "\n")
	res2 := deploy.MergeNodeContent(existing, sbs.ShareLinkHy2, sbs, "hysteria2")
	lines2 := strings.Split(res2, "\n")
	if len(lines2) != 1 {
		t.Fatalf("expected 1 line after deduplicating multiple identical, got %d: %q", len(lines2), res2)
	}
}

func TestSubstore_URLs(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			NodeDomain:     "node.example.com",
			SubstoreDomain: "sub.example.com",
			WebAdmin: config.WebAdminConfig{
				Enabled: true,
				Path:    "/sr/testadminpath123",
			},
		},
	}
	sb := deploy.NewSubstore(cfg, "testkey123456")

	subURL := sb.GetSubscriptionURL()
	if subURL != "https://sub.example.com/testkey123456/download/collection/all" {
		t.Fatalf("unexpected subscription URL: %q", subURL)
	}

	adminURL, err := sb.GetAdminURL()
	if err != nil {
		t.Fatalf("GetAdminURL failed: %v", err)
	}
	if adminURL != "https://sub.example.com/sr/testadminpath123/" {
		t.Fatalf("unexpected admin URL: %q", adminURL)
	}
}

func TestSingBoxServer_NodeTag(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			NodeTag:    "los",
			NodeDomain: "cdn.l1.example.com",
			Sni:        "swdist.apple.com",
		},
	}
	sbs, err := deploy.NewSingBoxServer(cfg)
	if err != nil {
		t.Fatalf("NewSingBoxServer failed: %v", err)
	}

	if sbs.VrTag() != "sec_los_vr" {
		t.Errorf("expected VrTag to be %q, got %q", "sec_los_vr", sbs.VrTag())
	}
	if sbs.Hy2Tag() != "sec_los_hy2" {
		t.Errorf("expected Hy2Tag to be %q, got %q", "sec_los_hy2", sbs.Hy2Tag())
	}

	if !strings.HasSuffix(sbs.ShareLinkVless, "#sec_los_vr") {
		t.Errorf("expected ShareLinkVless to end with #sec_los_vr, got %q", sbs.ShareLinkVless)
	}
	if !strings.HasSuffix(sbs.ShareLinkHy2, "#sec_los_hy2") {
		t.Errorf("expected ShareLinkHy2 to end with #sec_los_hy2, got %q", sbs.ShareLinkHy2)
	}

	// Verify mergeNodeContent replaces an existing node that used old sec_cdn_vr tag
	oldVless := "vless://uuid-test@cdn.l1.example.com:443?type=tcp&security=reality&sni=swdist.apple.com#sec_cdn_vr"
	merged := deploy.MergeNodeContent(oldVless, sbs.ShareLinkVless, sbs, "vless")
	if merged != sbs.ShareLinkVless {
		t.Errorf("expected old sec_cdn_vr node to be replaced by %q, got %q", sbs.ShareLinkVless, merged)
	}
}

func TestSubstore_CleanLegacyAutoCollection(t *testing.T) {
	cols := []interface{}{
		map[string]interface{}{
			"name":          "Auto",
			"displayName":   "Auto",
			"subscriptions": []interface{}{"auto_generated_hy2", "auto_generated_vless"},
		},
	}

	result := deploy.AddToCollection(cols, []string{"auto_generated_hy2", "auto_generated_vless"})

	if len(result) != 1 {
		t.Fatalf("expected exactly 1 collection, got %d", len(result))
	}
	firstCol, ok := result[0].(map[string]interface{})
	if !ok {
		t.Fatalf("expected map in collection, got %T", result[0])
	}
	if firstCol["name"] != "all" {
		t.Errorf("expected collection name 'all', got %v", firstCol["name"])
	}
}

func TestIsNewerVersion(t *testing.T) {
	tests := []struct {
		local    string
		remote   string
		expected bool
	}{
		{"1.14.4", "1.14.4", false},
		{"v1.14.4", "1.14.4", false},
		{"1.14.4", "v1.14.4", false},
		{"1.14.4", "1.14.5", true},
		{"1.14.4", "1.15.0", true},
		{"1.14.4", "2.0.0", true},
		{"1.14.10", "1.14.9", false},
		{"1.14.9", "1.14.10", true},
		{"2.11.7", "2.11.7", false},
		{"2.11.7", "2.12.0", true},
		{"2.34.1", "2.34.2", true},
		{"2.34.2", "2.34.1", false},
		{"", "1.0.0", false},
		{"1.0.0", "", false},
		{"", "", false},
	}

	for _, tt := range tests {
		got := deploy.IsNewerVersion(tt.local, tt.remote)
		if got != tt.expected {
			t.Errorf("isNewerVersion(%q, %q) = %v; want %v", tt.local, tt.remote, got, tt.expected)
		}
	}
}

func TestGenerateWireguardKeypair(t *testing.T) {
	privKey, pubKey, err := deploy.GenerateWireguardKeypair()
	if err != nil {
		t.Fatalf("generateWireguardKeypair failed: %v", err)
	}

	privBytes, err := base64.StdEncoding.DecodeString(privKey)
	if err != nil {
		t.Fatalf("failed to decode privKey: %v", err)
	}
	if len(privBytes) != 32 {
		t.Errorf("expected 32 byte private key, got %d", len(privBytes))
	}

	pubBytes, err := base64.StdEncoding.DecodeString(pubKey)
	if err != nil {
		t.Fatalf("failed to decode pubKey: %v", err)
	}
	if len(pubBytes) != 32 {
		t.Errorf("expected 32 byte public key, got %d", len(pubBytes))
	}
}

func TestBuildAndNormalizeWireproxyConfig(t *testing.T) {
	confV4Only := deploy.BuildWireproxyConfig("172.16.0.2/32", "test-priv", "test-pub", false)
	if !strings.Contains(confV4Only, "Endpoint = 162.159.192.1:2408") {
		t.Fatalf("expected IPv4 endpoint in config: %s", confV4Only)
	}
	if strings.Contains(confV4Only, "PersistentKeepalive") {
		t.Fatalf("did not expect PersistentKeepalive in wireproxy config: %s", confV4Only)
	}
	if !strings.Contains(confV4Only, "ResolveStrategy = ipv4") {
		t.Fatalf("expected ResolveStrategy = ipv4 in config: %s", confV4Only)
	}
	if strings.Contains(confV4Only, "2606:4700:4700::1111") {
		t.Fatalf("did not expect IPv6 DNS on IPv4-only host: %s", confV4Only)
	}

	legacyConf := `[Interface]
Address = 172.16.0.2/32, 2606:4700:110::1/128
MTU = 1420
PrivateKey = dummy
DNS = 1.1.1.1,8.8.8.8

[Peer]
PublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=
Endpoint = engage.cloudflareclient.com:2408
PersistentKeepalive = 25

[Socks5]
BindAddress = 127.0.0.1:40000

[Resolve]
ResolveStrategy = auto
`
	normalized, changed := deploy.NormalizeWireproxyConfigContent(legacyConf)
	if !changed {
		t.Fatalf("expected legacy wireproxy config to be marked changed")
	}
	if !strings.Contains(normalized, "Endpoint = 162.159.192.1:2408") {
		t.Errorf("expected Endpoint normalized to IPv4, got:\n%s", normalized)
	}
	if strings.Contains(normalized, "PersistentKeepalive = 25") {
		t.Errorf("expected PersistentKeepalive = 25 removed, got:\n%s", normalized)
	}
	if !strings.Contains(normalized, "ResolveStrategy = ipv4") {
		t.Errorf("expected ResolveStrategy = ipv4, got:\n%s", normalized)
	}

	// Second pass should be idempotent
	_, changedAgain := deploy.NormalizeWireproxyConfigContent(normalized)
	if changedAgain {
		t.Errorf("expected NormalizeWireproxyConfigContent to be idempotent")
	}
}

func TestSyncCaddyfile_MissingMtlsCAPreservesGateway(t *testing.T) {
	base := t.TempDir()
	vaultDir := filepath.Join(base, "singctl-mtls")
	caddyConfDir := filepath.Join(base, "caddy")
	caddyMtlsDir := filepath.Join(caddyConfDir, "mtls")

	origVault := constant.SingctlMtlsDir
	origCaddyConf := constant.CaddyConfigDir
	origCaddyMtls := constant.CaddyMtlsDir
	origCaddyCA := constant.CaddyMtlsCACert
	t.Cleanup(func() {
		constant.SingctlMtlsDir = origVault
		constant.CaddyConfigDir = origCaddyConf
		constant.CaddyMtlsDir = origCaddyMtls
		constant.CaddyMtlsCACert = origCaddyCA
	})

	constant.SingctlMtlsDir = vaultDir
	constant.CaddyConfigDir = caddyConfDir
	constant.CaddyMtlsDir = caddyMtlsDir
	constant.CaddyMtlsCACert = filepath.Join(caddyMtlsDir, "ca.crt")

	if err := os.MkdirAll(caddyConfDir, 0755); err != nil {
		t.Fatal(err)
	}
	caddyfilePath := filepath.Join(caddyConfDir, "Caddyfile")
	if err := os.WriteFile(caddyfilePath, []byte("placeholder\n"), 0640); err != nil {
		t.Fatal(err)
	}

	binDir := t.TempDir()
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	_ = os.WriteFile(filepath.Join(binDir, "caddy"), []byte("#!/bin/sh\nexit 0\n"), 0755)
	_ = os.WriteFile(filepath.Join(binDir, "systemctl"), []byte("#!/bin/sh\nexit 0\n"), 0755)

	cfg := &config.Config{
		Server: config.ServerConfig{
			NodeDomain: "node.example.com",
			CFDNSKey:   "cf-test-token",
			Sni:        "swdist.apple.com",
			WebTerminal: config.WebTerminalConfig{
				Enabled:       true,
				Port:          18080,
				Path:          "/term-safe",
				SSHTunnelPort: 18081,
				SSHTunnelPath: "/ssh-ws",
				SSHPort:       2222,
			},
		},
	}

	// Verify PreviewCaddyfile remains pure (still emits default trust_pool even without disk files).
	purePreview, err := deploy.PreviewCaddyfile(cfg)
	if err != nil {
		t.Fatalf("PreviewCaddyfile failed: %v", err)
	}
	if !strings.Contains(purePreview, "trust_pool file /etc/caddy/mtls/ca.crt") {
		t.Fatalf("expected PreviewCaddyfile purity to include trust_pool, got:\n%s", purePreview)
	}

	// Verify runtime SyncCaddyfile skips trust_pool when both vault & Caddy CA are missing so Caddy stays up.
	if err := deploy.SyncCaddyfile(cfg); err != nil {
		t.Fatalf("SyncCaddyfile should recover cleanly when CA missing: %v", err)
	}
	if !cfg.Server.WebTerminal.Enabled {
		t.Fatal("SyncCaddyfile must not mutate caller config WebTerminal.Enabled")
	}
	diskCaddyfile, err := os.ReadFile(caddyfilePath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(diskCaddyfile), "trust_pool") || strings.Contains(string(diskCaddyfile), "client_auth") {
		t.Fatalf("expected runtime Caddyfile to strip mTLS trust_pool when CA is absent, got:\n%s", string(diskCaddyfile))
	}
	if !strings.Contains(string(diskCaddyfile), "node.example.com") {
		t.Fatalf("expected runtime Caddyfile to preserve core node domain, got:\n%s", string(diskCaddyfile))
	}
}
