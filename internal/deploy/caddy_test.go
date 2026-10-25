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
	if !strings.Contains(content, "https://sub.example.com:9443, https://node.example.com:9443") {
		t.Errorf("expected both domains in layer 7 site address, got:\n%s", content)
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
