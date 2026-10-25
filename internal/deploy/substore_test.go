package deploy

import (
	"strings"
	"testing"

	"singctl/internal/config"
)

func TestMergeNodeContent_EmptyExisting(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			SBDomain: "hk.example.com",
			Sni:      "swdist.apple.com",
		},
	}
	sbs, err := NewSingBoxServer(cfg)
	if err != nil {
		t.Fatalf("NewSingBoxServer failed: %v", err)
	}

	res := mergeNodeContent("", sbs.ShareLinkHy2, sbs, "hysteria2")
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
	sbs, err := NewSingBoxServer(cfg)
	if err != nil {
		t.Fatalf("NewSingBoxServer failed: %v", err)
	}

	oldLink := "hysteria2://old-uuid@hk.example.com/?sni=hk.example.com&alpn=h3&insecure=0#sec_hk_hy2"
	res := mergeNodeContent(oldLink, sbs.ShareLinkHy2, sbs, "hysteria2")

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
	sbs, err := NewSingBoxServer(cfg)
	if err != nil {
		t.Fatalf("NewSingBoxServer failed: %v", err)
	}

	otherVPSLink := "hysteria2://other-uuid@us.example.com/?sni=us.example.com&alpn=h3&insecure=0#sec_us_hy2"
	res := mergeNodeContent(otherVPSLink, sbs.ShareLinkHy2, sbs, "hysteria2")

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
	sbs, err := NewSingBoxServer(cfg)
	if err != nil {
		t.Fatalf("NewSingBoxServer failed: %v", err)
	}

	vps1 := "hysteria2://uuid1@jp.example.com/?sni=jp.example.com&alpn=h3#sec_jp_hy2"
	oldCurrent := "hysteria2://old-uuid@hk.example.com/?sni=hk.example.com&alpn=h3#sec_hk_hy2"
	vps3 := "hysteria2://uuid3@us.example.com/?sni=us.example.com&alpn=h3#sec_us_hy2"

	existing := strings.Join([]string{vps1, oldCurrent, vps3}, "\n")
	res := mergeNodeContent(existing, sbs.ShareLinkHy2, sbs, "hysteria2")

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
	sbs, err := NewSingBoxServer(cfg)
	if err != nil {
		t.Fatalf("NewSingBoxServer failed: %v", err)
	}

	vps1Vless := "vless://uuid-vps1@us.example.com:443?type=tcp&security=reality&sni=swdist.apple.com#sec_us_vr"
	oldHkVless := "vless://old-hk-uuid@hk.example.com:443?type=tcp&security=reality&sni=swdist.apple.com#sec_hk_vr"

	existing := vps1Vless + "\n" + oldHkVless
	res := mergeNodeContent(existing, sbs.ShareLinkVless, sbs, "vless")

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
	sbs, err := NewSingBoxServer(cfg)
	if err != nil {
		t.Fatalf("NewSingBoxServer failed: %v", err)
	}

	dup1 := "hysteria2://dup1@hk.example.com/?sni=hk.example.com#sec_hk_hy2"
	vpsOther := "hysteria2://other@us.example.com/?sni=us.example.com#sec_us_hy2"
	dup2 := "hysteria2://dup2@hk.example.com/?sni=hk.example.com#sec_hk_hy2"

	existing := strings.Join([]string{dup1, vpsOther, dup2}, "\n")
	res := mergeNodeContent(existing, sbs.ShareLinkHy2, sbs, "hysteria2")

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

func TestMergeNodeContent_Tuic(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			SBDomain:   "hk.example.com",
			TuicDomain: "tuic.hk.example.com",
			Sni:        "swdist.apple.com",
		},
	}
	sbs, err := NewSingBoxServer(cfg)
	if err != nil {
		t.Fatalf("NewSingBoxServer failed: %v", err)
	}

	vps1Tuic := "tuic://uuid-vps1:uuid-vps1@us.example.com:443/?sni=us.example.com&alpn=h3#sec_us_tuic"
	oldHkTuic := "tuic://old-uuid:old-uuid@tuic.hk.example.com:443/?sni=tuic.hk.example.com&alpn=h3#sec_hk_tuic"

	existing := vps1Tuic + "\n" + oldHkTuic
	res := mergeNodeContent(existing, sbs.ShareLinkTuic, sbs, "tuic")

	lines := strings.Split(res, "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d: %q", len(lines), res)
	}

	if lines[0] != vps1Tuic {
		t.Errorf("vps1 tuic should be preserved, got %q", lines[0])
	}
	if lines[1] != sbs.ShareLinkTuic {
		t.Errorf("current hk tuic should be updated, got %q", lines[1])
	}
}

func TestSubstore_GetCorsAllowedOrigins(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			SBDomain:           "sub.example.com",
			TuicDomain:         "tuic.example.com",
			CorsAllowedOrigins: "https://custom.example.com, https://another.example.com",
		},
	}
	sb := NewSubstore(cfg, "testkey")
	origins := sb.getCorsAllowedOrigins()

	expectedOrigins := []string{
		"https://sub.example.com",
		"http://sub.example.com",
		"https://tuic.example.com",
		"http://tuic.example.com",
		"https://custom.example.com",
		"https://another.example.com",
		"https://sub-store.vercel.app",
		"http://substore.stash",
		"https://substore.stash",
		"http://127.0.0.1",
		"http://127.0.0.1:3001",
		"http://localhost",
		"http://localhost:3001",
	}

	for _, expected := range expectedOrigins {
		if !strings.Contains(origins, expected) {
			t.Errorf("expected origins to contain %q, but got %q", expected, origins)
		}
	}
}
