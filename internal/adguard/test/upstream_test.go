// 文件职责：覆盖 AdGuard Home 加密上游归一化校验、RFC 1035 Wireformat 报文编解码与热配置落盘测试。
package adguard_test

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"singctl/internal/adguard"
	"singctl/internal/config"
)

func TestNormalizeAndValidateUpstream(t *testing.T) {
	cases := []struct {
		name      string
		input     string
		wantNorm  string
		wantIP    string
		wantConv  bool
		expectErr bool
	}{
		{
			name:     "standard pure IP DoH",
			input:    "https://223.5.5.5/dns-query",
			wantNorm: "https://223.5.5.5/dns-query",
			wantIP:   "223.5.5.5",
		},
		{
			name:     "pure IP DoH auto补全 /dns-query",
			input:    "https://1.12.12.12",
			wantNorm: "https://1.12.12.12/dns-query",
			wantIP:   "1.12.12.12",
		},
		{
			name:     "standard pure IP DoT",
			input:    "tls://223.6.6.6",
			wantNorm: "tls://223.6.6.6",
			wantIP:   "223.6.6.6",
		},
		{
			name:     "standard pure IP DoQ auto port 853",
			input:    "quic://223.5.5.5",
			wantNorm: "quic://223.5.5.5:853",
			wantIP:   "223.5.5.5",
		},
		{
			name:     "standard pure IP DoQ explicit port 853",
			input:    "quic://223.6.6.6:853",
			wantNorm: "quic://223.6.6.6:853",
			wantIP:   "223.6.6.6",
		},
		{
			name:     "domain DoQ auto port 853",
			input:    "quic://dns.alidns.com",
			wantNorm: "quic://dns.alidns.com:853",
			wantIP:   "",
		},
		{
			name:     "pure IP DoH3 auto /dns-query",
			input:    "h3://223.5.5.5",
			wantNorm: "h3://223.5.5.5/dns-query",
			wantIP:   "223.5.5.5",
		},
		{
			name:     "preserve alidns domain verbatim without IP rewrite",
			input:    "https://dns.alidns.com/dns-query",
			wantNorm: "https://dns.alidns.com/dns-query",
			wantIP:   "",
		},
		{
			name:     "preserve doh.pub domain verbatim without IP rewrite",
			input:    "https://doh.pub/dns-query",
			wantNorm: "https://doh.pub/dns-query",
			wantIP:   "",
		},
		{
			name:     "preserve dot.pub domain verbatim without IP rewrite",
			input:    "tls://dot.pub",
			wantNorm: "tls://dot.pub",
			wantIP:   "",
		},
		{
			name:      "reject plain IP",
			input:     "223.5.5.5",
			expectErr: true,
		},
		{
			name:      "reject loopback self-loop",
			input:     "https://127.0.0.1/dns-query",
			expectErr: true,
		},
		{
			name:      "reject private LAN IP",
			input:     "https://192.168.1.1/dns-query",
			expectErr: true,
		},
		{
			name:      "reject port 53",
			input:     "tls://223.5.5.5:53",
			expectErr: true,
		},
		{
			name:     "valid domain DoT (OneDNS)",
			input:    "tls://dot.onedns.net",
			wantNorm: "tls://dot.onedns.net",
			wantIP:   "",
		},
		{
			name:     "valid domain DoT uppercase trailing dot and explicit port",
			input:    "tls://DOT.OneDNS.NET.:853",
			wantNorm: "tls://dot.onedns.net:853",
			wantIP:   "",
		},
		{
			name:     "valid domain DoH auto path",
			input:    "https://doh.onedns.net",
			wantNorm: "https://doh.onedns.net/dns-query",
			wantIP:   "",
		},
		{
			name:     "valid domain DoH with query",
			input:    "https://dns.example.com/dns-query?profile=clean",
			wantNorm: "https://dns.example.com/dns-query?profile=clean",
			wantIP:   "",
		},
		{
			name:      "reject single-label localhost domain",
			input:     "tls://localhost",
			expectErr: true,
		},
		{
			name:      "reject local LAN suffix domain",
			input:     "tls://router.lan",
			expectErr: true,
		},
		{
			name:      "reject mDNS .local domain",
			input:     "https://nas.local/dns-query",
			expectErr: true,
		},
		{
			name:      "reject home.arpa domain",
			input:     "tls://dns.home.arpa",
			expectErr: true,
		},
		{
			name:      "reject numeric TLD invalid IP",
			input:     "tls://999.999.999.999",
			expectErr: true,
		},
		{
			name:      "reject newline injection in domain upstream",
			input:     "tls://dot.onedns.net\nfoo",
			expectErr: true,
		},
		{
			name:      "reject shell metachar in domain upstream",
			input:     "tls://dot.onedns.net;id",
			expectErr: true,
		},
		{
			name:      "reject userinfo in domain upstream",
			input:     "https://user:pass@dot.onedns.net/dns-query",
			expectErr: true,
		},
		{
			name:      "reject fragment in domain upstream",
			input:     "https://dot.onedns.net/dns-query#frag",
			expectErr: true,
		},
		{
			name:      "reject unsupported http scheme",
			input:     "http://dot.onedns.net/dns-query",
			expectErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			norm, ip, note, err := adguard.NormalizeAndValidateUpstream(tc.input)
			if tc.expectErr {
				if err == nil {
					t.Fatalf("expected error for %q, got norm=%q", tc.input, norm)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tc.input, err)
			}
			if norm != tc.wantNorm {
				t.Fatalf("norm=%q, want %q", norm, tc.wantNorm)
			}
			if ip != tc.wantIP {
				t.Fatalf("ip=%q, want %q", ip, tc.wantIP)
			}
			if tc.wantConv && note == "" {
				t.Fatalf("expected conversion note for %q", tc.input)
			}
			if !tc.wantConv && note != "" {
				t.Fatalf("unexpected conversion note %q for %q", note, tc.input)
			}
		})
	}

	// Missing scheme on bare domain should provide explicit tls:// and https:// examples for that domain.
	_, _, _, err := adguard.NormalizeAndValidateUpstream("dot.pub")
	if err == nil || !strings.Contains(err.Error(), "tls://dot.pub") || !strings.Contains(err.Error(), "https://dot.pub/dns-query") {
		t.Fatalf("expected missing-scheme guidance with tls://dot.pub and https://dot.pub/dns-query, got: %v", err)
	}

	// Curated presets must include primary and backup Alibaba Cloud DoQ presets.
	presets := adguard.CuratedUpstreamPresets()
	wantDoQ := map[string]bool{
		"quic://223.5.5.5:853": false,
		"quic://223.6.6.6:853": false,
	}
	for _, p := range presets {
		if _, ok := wantDoQ[p.Address]; ok && p.Protocol == "DoQ" {
			wantDoQ[p.Address] = true
		}
	}
	for addr, found := range wantDoQ {
		if !found {
			t.Fatalf("CuratedUpstreamPresets missing DoQ preset %q", addr)
		}
	}
}

func TestDNSWireformatBuildAndParseARecord(t *testing.T) {
	query, txid, err := adguard.BuildDNSQueryPacket("qq.com")
	if err != nil {
		t.Fatalf("BuildDNSQueryPacket failed: %v", err)
	}

	var resp []byte
	resp = append(resp, txid[0], txid[1])
	resp = append(resp, 0x81, 0x80)
	resp = append(resp, 0x00, 0x01)
	resp = append(resp, 0x00, 0x02)
	resp = append(resp, 0x00, 0x00, 0x00, 0x00)
	resp = append(resp, query[12:]...)

	// Answer 1: CNAME -> alias (4 bytes dummy RDATA)
	resp = append(resp, 0xC0, 0x0C)
	resp = append(resp, 0x00, 0x05)
	resp = append(resp, 0x00, 0x01)
	resp = append(resp, 0x00, 0x00, 0x00, 0x3C)
	resp = append(resp, 0x00, 0x02, 0xC0, 0x0C)

	// Answer 2: A -> 203.0.113.8
	resp = append(resp, 0xC0, 0x0C)
	resp = append(resp, 0x00, 0x01)
	resp = append(resp, 0x00, 0x01)
	resp = append(resp, 0x00, 0x00, 0x00, 0x3C)
	var rdLen [2]byte
	binary.BigEndian.PutUint16(rdLen[:], 4)
	resp = append(resp, rdLen[:]...)
	resp = append(resp, 203, 0, 113, 8)

	ip, err := adguard.ParseDNSFirstARecord(resp, txid)
	if err != nil {
		t.Fatalf("ParseDNSFirstARecord error: %v", err)
	}
	if ip != "203.0.113.8" {
		t.Fatalf("resolved ip=%q, want 203.0.113.8", ip)
	}
}

func TestSetDNSUpstreams_HotAPIAndYAMLPersistence(t *testing.T) {
	var gotPayload map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/control/dns_config":
			_ = json.NewDecoder(r.Body).Decode(&gotPayload)
			w.WriteHeader(http.StatusOK)
		case "/control/dns_info":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"upstream_dns":  []string{"https://223.5.5.5/dns-query", "tls://1.12.12.12"},
				"upstream_mode": "fastest_addr",
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	u, _ := url.Parse(srv.URL)
	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "AdGuardHome")
	if err := os.WriteFile(fakeBin, []byte("#!/bin/sh\necho v0.107.80\n"), 0755); err != nil {
		t.Fatal(err)
	}
	aghYAML := filepath.Join(tmpDir, "AdGuardHome.yaml")
	initialYAML := "http:\n  address: " + u.Host + "\ndns:\n  port: 5353\n  upstream_dns:\n    - https://223.5.5.5/dns-query\n  upstream_mode: parallel\n"
	if err := os.WriteFile(aghYAML, []byte(initialYAML), 0600); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{}
	cfg.DNS.Username = "root"
	cfg.DNS.Password = "secret123"
	mgr := adguard.NewManager(cfg, "")
	mgr.SetPathsForTest(fakeBin, aghYAML)

	infos, mode, _, err := mgr.SetDNSUpstreams(
		t.Context(),
		[]string{"https://dns.alidns.com/dns-query", "tls://1.12.12.12"},
		"fastest_addr",
		true,
	)
	if err != nil {
		t.Fatalf("SetDNSUpstreams failed: %v", err)
	}
	if mode != "fastest_addr" {
		t.Fatalf("mode=%q, want fastest_addr", mode)
	}
	if len(infos) != 2 || infos[0].Address != "https://dns.alidns.com/dns-query" || infos[1].Address != "tls://1.12.12.12" {
		t.Fatalf("unexpected infos: %+v", infos)
	}
	if gotPayload == nil || gotPayload["upstream_mode"] != "fastest_addr" {
		t.Fatalf("hot API payload not sent properly: %+v", gotPayload)
	}

	st, err := os.Stat(aghYAML)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0600 {
		t.Fatalf("AdGuardHome.yaml perm=%o, want 0600", st.Mode().Perm())
	}
	savedBytes, _ := os.ReadFile(aghYAML)
	if !strings.Contains(string(savedBytes), "tls://1.12.12.12") || !strings.Contains(string(savedBytes), "fastest_addr") {
		t.Fatalf("YAML not updated: %s", string(savedBytes))
	}
}

func TestDescribeUpstream_DomainProviders(t *testing.T) {
	cases := []struct {
		addr         string
		wantProto    string
		wantContains string
	}{
		{"tls://dot.pub", "DoT", "腾讯云 DNSPod"},
		{"https://dns.alidns.com/dns-query", "DoH", "阿里云公共 DNS"},
		{"tls://dot.onedns.net", "DoT", "OneDNS"},
		{"https://doh-pure.onedns.net/dns-query", "DoH", "OneDNS"},
		{"https://doh.360.cn/dns-query", "DoH", "360"},
		{"tls://dns.quad9.net", "DoT", "Quad9"},
		{"https://cloudflare-dns.com/dns-query", "DoH", "Cloudflare"},
		{"tls://dns.google", "DoT", "Google"},
		{"quic://dns.example.com", "DoQ", "自定义加密上游"},
		{"h3://dns.example.com/dns-query", "DoH3", "自定义加密上游"},
	}
	for _, tc := range cases {
		info := adguard.DescribeUpstream(tc.addr)
		if info.Protocol != tc.wantProto || !strings.Contains(info.Name, tc.wantContains) {
			t.Errorf("DescribeUpstream(%q) = %+v, want proto=%q name containing %q", tc.addr, info, tc.wantProto, tc.wantContains)
		}
	}
}

func TestSetDNSUpstreams_DomainSupportFallbackBypassAndSingleProbe(t *testing.T) {
	currentUpstreams := []string{"https://223.5.5.5/dns-query"}
	var gotPayload map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/control/dns_config":
			_ = json.NewDecoder(r.Body).Decode(&gotPayload)
			w.WriteHeader(http.StatusOK)
		case "/control/dns_info":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"upstream_dns":  currentUpstreams,
				"upstream_mode": "parallel",
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	u, _ := url.Parse(srv.URL)
	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "AdGuardHome")
	if err := os.WriteFile(fakeBin, []byte("#!/bin/sh\necho v0.107.80\n"), 0755); err != nil {
		t.Fatal(err)
	}
	aghYAML := filepath.Join(tmpDir, "AdGuardHome.yaml")
	initialYAML := "http:\n  address: " + u.Host + "\ndns:\n  port: 5353\n  upstream_dns:\n    - https://223.5.5.5/dns-query\n  upstream_mode: parallel\n"
	if err := os.WriteFile(aghYAML, []byte(initialYAML), 0600); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{}
	cfg.DNS.Username = "root"
	cfg.DNS.Password = "secret123"
	mgr := adguard.NewManager(cfg, "")
	mgr.SetPathsForTest(fakeBin, aghYAML)

	var bypassedIPs []string
	probeHealthyMap := map[string]bool{
		"https://223.5.5.5/dns-query": true,
		"tls://dot.onedns.net":        false,
	}
	mgr.SetUpstreamHooksForTest(
		func(_ context.Context, upstreams []string, _ string, _ time.Duration) []adguard.UpstreamProbeItem {
			out := make([]adguard.UpstreamProbeItem, 0, len(upstreams))
			for _, addr := range upstreams {
				ok := probeHealthyMap[strings.ToLower(addr)]
				item := adguard.UpstreamProbeItem{Address: addr, Healthy: ok}
				if !ok {
					item.Error = "连接被远端重置（目标端口可能不可达或被拦截）"
				}
				out = append(out, item)
			}
			return out
		},
		func(_ context.Context, host string) ([]net.IP, error) {
			if host == "dot.onedns.net" {
				// Include a private IP and loopback to verify they are strictly filtered out of bypass rules.
				return []net.IP{net.ParseIP("198.51.100.44"), net.ParseIP("127.0.0.1"), net.ParseIP("192.168.1.9")}, nil
			}
			return nil, nil
		},
		func(ips []string) {
			bypassedIPs = slices.Clone(ips)
		},
	)

	// 1. Domain-only list MUST be rejected to prevent cold-boot DNS deadlock.
	if _, _, _, err := mgr.SetDNSUpstreams(t.Context(), []string{"tls://dot.onedns.net"}, "parallel", false); err == nil {
		t.Fatal("expected domain-only upstream list to be rejected without pure-IP fallback")
	}

	// 2. Newly added unreachable domain MUST be rejected even when existing pure-IP upstream is healthy.
	_, _, _, err := mgr.SetDNSUpstreams(t.Context(), []string{"https://223.5.5.5/dns-query", "tls://dot.onedns.net"}, "parallel", false)
	if err == nil || !strings.Contains(err.Error(), "tls://dot.onedns.net") {
		t.Fatalf("expected newly added failing upstream error mentioning tls://dot.onedns.net, got: %v", err)
	}

	// 3. When newly added domain probes healthy, save succeeds, bypasses resolved public IPv4 only, and persists to YAML.
	probeHealthyMap["tls://dot.onedns.net"] = true
	infos, mode, _, err := mgr.SetDNSUpstreams(t.Context(), []string{"https://223.5.5.5/dns-query", "tls://dot.onedns.net"}, "parallel", false)
	if err != nil {
		t.Fatalf("expected healthy hybrid upstreams to succeed, got: %v", err)
	}
	if mode != "parallel" || len(infos) != 2 || infos[1].Address != "tls://dot.onedns.net" {
		t.Fatalf("unexpected infos: mode=%q infos=%+v", mode, infos)
	}
	if !slices.Contains(bypassedIPs, "198.51.100.44") || slices.Contains(bypassedIPs, "127.0.0.1") || slices.Contains(bypassedIPs, "192.168.1.9") {
		t.Fatalf("unexpected bypassedIPs (must include public IPv4 198.51.100.44 and exclude loopback/private): %v", bypassedIPs)
	}
	savedBytes, _ := os.ReadFile(aghYAML)
	if !strings.Contains(string(savedBytes), "tls://dot.onedns.net") {
		t.Fatalf("AdGuardHome.yaml missing tls://dot.onedns.net:\n%s", string(savedBytes))
	}

	// 4. Duplicate addition with no effective change must return an explicit duplicate error instead of silent success.
	currentUpstreams = []string{"https://223.5.5.5/dns-query", "tls://dot.onedns.net"}
	if _, _, _, err := mgr.SetDNSUpstreams(t.Context(), []string{"https://223.5.5.5/dns-query", "tls://dot.onedns.net", "tls://DOT.ONEDNS.NET"}, "parallel", false); err == nil || !strings.Contains(err.Error(), "已在当前列表中") || !strings.Contains(err.Error(), "tls://dot.onedns.net") {
		t.Fatalf("expected explicit duplicate error for tls://dot.onedns.net, got: %v", err)
	}

	// 5. Switching scheduling mode when an *existing* upstream has a transient failure must still succeed if another upstream is healthy.
	probeHealthyMap["tls://dot.onedns.net"] = false
	if _, mode, _, err := mgr.SetDNSUpstreams(t.Context(), currentUpstreams, "fastest_addr", false); err != nil || mode != "fastest_addr" {
		t.Fatalf("switching mode with existing flaky upstream should succeed while pure-IP upstream is healthy: mode=%q err=%v", mode, err)
	}
}

func TestSetDNSUpstreams_QUICAndH3SkipDirectProbeAndSave(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/control/dns_config":
			w.WriteHeader(http.StatusOK)
		case "/control/dns_info":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"upstream_dns":  []string{"https://223.5.5.5/dns-query"},
				"upstream_mode": "parallel",
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	u, _ := url.Parse(srv.URL)
	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "AdGuardHome")
	_ = os.WriteFile(fakeBin, []byte("#!/bin/sh\necho v0.107.80\n"), 0755)
	aghYAML := filepath.Join(tmpDir, "AdGuardHome.yaml")
	_ = os.WriteFile(aghYAML, []byte("http:\n  address: "+u.Host+"\ndns:\n  port: 5353\n  upstream_dns:\n    - https://223.5.5.5/dns-query\n  upstream_mode: parallel\n"), 0600)

	cfg := &config.Config{}
	cfg.DNS.Username = "root"
	cfg.DNS.Password = "secret123"
	mgr := adguard.NewManager(cfg, "")
	mgr.SetPathsForTest(fakeBin, aghYAML)

	probeCalls := 0
	var bypassedIPs []string
	mgr.SetUpstreamHooksForTest(
		func(_ context.Context, upstreams []string, _ string, _ time.Duration) []adguard.UpstreamProbeItem {
			probeCalls++
			out := make([]adguard.UpstreamProbeItem, 0, len(upstreams))
			for _, addr := range upstreams {
				if strings.HasPrefix(addr, "quic://") || strings.HasPrefix(addr, "h3://") {
					t.Errorf("quic/h3 upstream %q should skip direct probe", addr)
				}
				out = append(out, adguard.UpstreamProbeItem{Address: addr, Healthy: true})
			}
			return out
		},
		nil,
		func(ips []string) { bypassedIPs = slices.Clone(ips) },
	)

	infos, _, notes, err := mgr.SetDNSUpstreams(t.Context(), []string{"quic://223.5.5.5", "h3://223.6.6.6"}, "parallel", false)
	if err != nil {
		t.Fatalf("SetDNSUpstreams with QUIC/H3 failed: %v", err)
	}
	if probeCalls != 0 {
		t.Fatalf("expected probeFn skipped when all upstreams are quic/h3, got %d calls", probeCalls)
	}
	if len(infos) != 2 || infos[0].Address != "quic://223.5.5.5:853" || infos[1].Address != "h3://223.6.6.6/dns-query" {
		t.Fatalf("unexpected infos: %+v", infos)
	}
	if !slices.Contains(bypassedIPs, "223.5.5.5") || !slices.Contains(bypassedIPs, "223.6.6.6") {
		t.Fatalf("expected QUIC/H3 public IPs bypassed in firewall, got %v", bypassedIPs)
	}
	if len(notes) == 0 {
		t.Fatalf("expected skip-probe note for quic/h3")
	}
}

func TestProbeSingleUpstream_QUICAndH3(t *testing.T) {
	// Bind an ephemeral TCP listener and close it immediately to guarantee an unused loopback port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	unusedAddr := ln.Addr().String()
	_ = ln.Close()

	// Start a real local TLS server (self-signed cert) to verify h3:// actually performs HTTPS/TLS handshake
	// instead of bailing out with "暂不支持直接探测协议".
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer tlsSrv.Close()
	tlsU, _ := url.Parse(tlsSrv.URL)

	cases := []struct {
		name     string
		upstream string
		wantErr  string
	}{
		{
			name:     "quic_attempts_real_probe",
			upstream: "quic://" + unusedAddr,
			wantErr:  "目标端口拒绝连接",
		},
		{
			name:     "h3_attempts_real_doh_probe",
			upstream: "h3://" + tlsU.Host,
			wantErr:  "TLS 证书",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := adguard.ProbeSingleUpstream(t.Context(), tc.upstream, "qq.com", time.Second)
			if res.Healthy {
				t.Fatalf("expected non-healthy against %s, got healthy: %+v", tc.upstream, res)
			}
			if strings.Contains(res.Error, "暂不支持直接探测协议") {
				t.Fatalf("expected %s to attempt real probe, still got unsupported error: %q", tc.upstream, res.Error)
			}
			if !strings.Contains(res.Error, tc.wantErr) {
				t.Fatalf("expected error containing %q for %s, got %q", tc.wantErr, tc.upstream, res.Error)
			}
		})
	}
}
