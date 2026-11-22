// 文件职责：覆盖 AdGuard Home 加密上游归一化校验、RFC 1035 Wireformat 报文编解码与热配置落盘测试。
package adguard_test

import (
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
			name:     "auto convert alidns domain to pure IP",
			input:    "https://dns.alidns.com/dns-query",
			wantNorm: "https://223.5.5.5/dns-query",
			wantIP:   "223.5.5.5",
			wantConv: true,
		},
		{
			name:     "auto convert doh.pub domain to pure IP",
			input:    "https://doh.pub/dns-query",
			wantNorm: "https://1.12.12.12/dns-query",
			wantIP:   "1.12.12.12",
			wantConv: true,
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
			name:      "reject arbitrary domain name",
			input:     "https://dns.example.com/dns-query",
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
		})
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

	infos, mode, notes, err := mgr.SetDNSUpstreams(
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
	if len(infos) != 2 || infos[0].Address != "https://223.5.5.5/dns-query" {
		t.Fatalf("unexpected infos: %+v", infos)
	}
	if len(notes) == 0 {
		t.Fatalf("expected domain-to-IP conversion note")
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
