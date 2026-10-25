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
			TuicDomain:     "tuic.example.com",
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
			TuicDomain:     "tuic.example.com",
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

	// 2. Port 80 listener for HTTP-01 challenge
	if !strings.Contains(content, ":80 {") {
		t.Errorf("expected :80 listener for HTTP-01 challenge, got:\n%s", content)
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
			TuicDomain:     "tuic.example.com",
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
