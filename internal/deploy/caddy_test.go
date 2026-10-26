package deploy

import (
	"strings"
	"testing"

	"singctl/internal/config"
)

func TestPreviewCaddyfile_SeparatedDomainsAndFallback(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			NodeDomain:     "node.example.com",
			SubstoreDomain: "sub.example.com",
			CFDNSKey:       "dummy_cf_key",
			Sni:            "swdist.apple.com",
		},
	}

	content, err := PreviewCaddyfile(cfg)
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
}

func TestPreviewCaddyfile_BackwardCompatibility(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			SBDomain: "legacy.example.com",
			CFDNSKey: "dummy_cf_key",
			Sni:      "swdist.apple.com",
		},
	}

	content, err := PreviewCaddyfile(cfg)
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

	content, err := PreviewCaddyfile(cfg)
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

	content, err := PreviewCaddyfile(cfg)
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

	content, err := PreviewCaddyfile(cfg)
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

	content, err := PreviewCaddyfile(cfg)
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
	if !strings.Contains(content, "expression {http.request.tls.client.subject} == \"\"") {
		t.Errorf("expected client subject empty check, got:\n%s", content)
	}
	if !strings.Contains(content, "respond @unauth 404") {
		t.Errorf("expected respond @unauth 404, got:\n%s", content)
	}
	if !strings.Contains(content, "reverse_proxy 127.0.0.1:18080") {
		t.Errorf("expected reverse_proxy 127.0.0.1:18080, got:\n%s", content)
	}
}
