// 文件职责：覆盖本地外部 DNS（AdGuard Home / SmartDNS）与应急纯 IP DoH 兜底热切换、彻底关闭乐观缓存（optimistic: false）及 RFC 6303 私网 PTR NXDOMAIN 防环注入测试。
package singbox_test

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"singctl/internal/singbox"
	"singctl/internal/singbox/sboption"
)

func TestPatchDNSLocalJSON_RoundTripNoOptimisticAndSingBoxCheck(t *testing.T) {
	base := `{
  "dns": {
    "servers": [
      {"tag": "dns_proxy", "type": "udp", "server": "8.8.8.8"},
      {"tag": "dns_local", "type": "udp", "server": "223.5.5.5"}
    ],
    "final": "dns_proxy"
  },
  "experimental": {
    "cache_file": {
      "enabled": true,
      "store_dns": true,
      "store_fakeip": true
    }
  }
}`

	toAGH, changed, err := singbox.PatchDNSLocalJSON(base, true, 5353)
	if err != nil {
		t.Fatalf("PatchDNSLocalJSON(useAdGuard=true) failed: %v", err)
	}
	if !changed {
		t.Fatal("expected changed=true when switching to external local DNS")
	}

	docAGH, err := sboption.ParseDocument([]byte(toAGH))
	if err != nil {
		t.Fatal(err)
	}
	if docAGH.DNS.DisableCache == nil || !*docAGH.DNS.DisableCache {
		t.Fatalf("external DNS: expected disable_cache=true, got %v", docAGH.DNS.DisableCache)
	}
	if docAGH.DNS.Optimistic == nil || *docAGH.DNS.Optimistic {
		t.Fatalf("external DNS: expected optimistic=false, got %v", docAGH.DNS.Optimistic)
	}
	if docAGH.Experimental.CacheFile.StoreDNS == nil || *docAGH.Experimental.CacheFile.StoreDNS {
		t.Fatalf("external DNS: expected store_dns=false, got %v", docAGH.Experimental.CacheFile.StoreDNS)
	}
	if docAGH.Experimental.CacheFile.StoreFakeIP == nil || *docAGH.Experimental.CacheFile.StoreFakeIP {
		t.Fatalf("external DNS: expected store_fakeip=false, got %v", docAGH.Experimental.CacheFile.StoreFakeIP)
	}

	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.json")
	if err := os.WriteFile(cfgPath, []byte(toAGH), 0600); err != nil {
		t.Fatal(err)
	}
	linked, port := singbox.InspectSingBoxDNSLocal(cfgPath)
	if !linked || port != 5353 {
		t.Fatalf("expected linked=true port=5353, got linked=%v port=%d", linked, port)
	}

	_, changedAgain, err := singbox.PatchDNSLocalJSON(toAGH, true, 5353)
	if err != nil {
		t.Fatal(err)
	}
	if changedAgain {
		t.Fatal("expected changed=false on idempotent external call")
	}

	// Fallback pure-IP DoH MUST also force disable_cache=true, optimistic=false, store_dns=false!
	toFallback, changedFB, err := singbox.PatchDNSLocalJSON(toAGH, false, 5353)
	if err != nil {
		t.Fatalf("PatchDNSLocalJSON(useAdGuard=false) failed: %v", err)
	}
	if !changedFB {
		t.Fatal("expected changed=true when switching back to encrypted DoH fallback")
	}
	docFB, err := sboption.ParseDocument([]byte(toFallback))
	if err != nil {
		t.Fatal(err)
	}
	if docFB.DNS.DisableCache == nil || !*docFB.DNS.DisableCache {
		t.Fatalf("DoH fallback: expected disable_cache=true, got %v", docFB.DNS.DisableCache)
	}
	if docFB.DNS.Optimistic == nil || *docFB.DNS.Optimistic {
		t.Fatalf("DoH fallback: expected optimistic=false, got %v", docFB.DNS.Optimistic)
	}
	if docFB.Experimental.CacheFile.StoreDNS == nil || *docFB.Experimental.CacheFile.StoreDNS {
		t.Fatalf("DoH fallback: expected store_dns=false, got %v", docFB.Experimental.CacheFile.StoreDNS)
	}

	// Idempotent second fallback call
	_, changedFBAgain, err := singbox.PatchDNSLocalJSON(toFallback, false, 5353)
	if err != nil || changedFBAgain {
		t.Fatalf("expected changed=false on idempotent fallback call, got changed=%v err=%v", changedFBAgain, err)
	}

	if err := os.WriteFile(cfgPath, []byte(toFallback), 0600); err != nil {
		t.Fatal(err)
	}
	linkedFB, _ := singbox.InspectSingBoxDNSLocal(cfgPath)
	if linkedFB {
		t.Fatal("expected linked=false after fallback to pure-IP DoH")
	}

	// Legacy DoH JSON that still has optimistic=true / store_dns=true / disable_cache=false MUST be corrected!
	legacyOptimistic := `{
  "dns": {
    "servers": [
      {"tag": "dns_local", "type": "https", "server": "223.5.5.5", "server_port": 443, "path": "/dns-query"}
    ],
    "disable_cache": false,
    "optimistic": true
  },
  "experimental": {
    "cache_file": {
      "enabled": true,
      "store_dns": true
    }
  }
}`
	healed, healedChanged, err := singbox.PatchDNSLocalJSON(legacyOptimistic, false, 5353)
	if err != nil || !healedChanged {
		t.Fatalf("expected legacy optimistic=true DoH config to be patched, changed=%v err=%v", healedChanged, err)
	}
	docHealed, err := sboption.ParseDocument([]byte(healed))
	if err != nil {
		t.Fatal(err)
	}
	if docHealed.DNS.DisableCache == nil || !*docHealed.DNS.DisableCache ||
		docHealed.DNS.Optimistic == nil || *docHealed.DNS.Optimistic ||
		docHealed.Experimental.CacheFile.StoreDNS == nil || *docHealed.Experimental.CacheFile.StoreDNS {
		t.Fatalf("legacy optimistic config not properly disabled: disable_cache=%v optimistic=%v store_dns=%v",
			docHealed.DNS.DisableCache, docHealed.DNS.Optimistic, docHealed.Experimental.CacheFile.StoreDNS)
	}

	// Concurrent race-safety check
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			if _, _, pErr := singbox.PatchDNSLocalJSON(base, false, 5353); pErr != nil {
				t.Errorf("concurrent PatchDNSLocalJSON failed: %v", pErr)
			}
		})
	}
	wg.Wait()

	if sbBin, err := exec.LookPath("sing-box"); err == nil && sbBin != "" {
		for name, content := range map[string]string{"adguard": toAGH, "fallback_doh": toFallback} {
			checkFile := filepath.Join(tmpDir, name+".json")
			if err := os.WriteFile(checkFile, []byte(content), 0600); err != nil {
				t.Fatal(err)
			}
			if out, err := exec.CommandContext(t.Context(), sbBin, "check", "-c", checkFile).CombinedOutput(); err != nil {
				t.Fatalf("sing-box check failed for %s: %v\n%s", name, err, string(out))
			}
		}
	}
}

func TestInjectPrivatePTRBlockRules_PrecedesClashAndNoWildcardARPA(t *testing.T) {
	base := `{
  "dns": {
    "servers": [
      {"tag": "dns_local", "type": "udp", "server": "127.0.0.1", "server_port": 5353},
      {"tag": "dns_proxy", "type": "udp", "server": "8.8.8.8"}
    ],
    "rules": [
      {"clash_mode": "Direct", "server": "dns_local"},
      {"rule_set": "geosite-private", "server": "dns_local"}
    ],
    "final": "dns_proxy"
  }
}`

	injected, err := singbox.InjectPrivatePTRBlockRules(base)
	if err != nil {
		t.Fatalf("InjectPrivatePTRBlockRules failed: %v", err)
	}

	parsed, err := sboption.ParseDocument([]byte(injected))
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.DNS.Rules) != 4 {
		t.Fatalf("expected 4 rules (2 prepended + 2 existing), got %d: %+v", len(parsed.DNS.Rules), parsed.DNS.Rules)
	}
	r0 := parsed.DNS.Rules[0]
	r1 := parsed.DNS.Rules[1]
	if r0.Action != "predefined" || r0.Rcode != "NXDOMAIN" || !slices.Equal(r0.DomainSuffix.Slice(), singbox.PrivateReverseDNSSuffixes()) {
		t.Fatalf("expected rule[0] to be private PTR predefined NXDOMAIN, got %+v", r0)
	}
	if r1.Action != "predefined" || r1.Rcode != "NXDOMAIN" || !slices.Equal(r1.DomainKeyword.Slice(), []string{singbox.DNSSDBrowseKeyword}) {
		t.Fatalf("expected rule[1] to be DNS-SD keyword predefined NXDOMAIN, got %+v", r1)
	}
	if parsed.DNS.Rules[2].ClashMode != "Direct" {
		t.Fatalf("expected clash_mode=Direct rule preserved after prepended rules, got %+v", parsed.DNS.Rules[2])
	}
	if strings.Contains(injected, `"in-addr.arpa"`) || strings.Contains(injected, `"ip6.arpa"`) {
		t.Fatalf("must not contain bare wildcard in-addr.arpa/ip6.arpa that blocks public rDNS:\n%s", injected)
	}

	again, err := singbox.InjectPrivatePTRBlockRules(injected)
	if err != nil {
		t.Fatalf("second InjectPrivatePTRBlockRules failed: %v", err)
	}
	if again != injected {
		t.Fatalf("expected identical output on idempotent InjectPrivatePTRBlockRules")
	}
}

func TestProbeSafeWANFallbackDNS_StrictAntiLoopMatrix(t *testing.T) {
	writeTempResolv := func(name, content string) string {
		t.Helper()
		p := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(p, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	// Verify IsPublicISPUnicastIPv4 rejects every non-public / local / loop-risk address directly.
	ipCases := []struct {
		ipStr    string
		localIPs map[string]struct{}
		wantOK   bool
	}{
		{"127.0.0.1", nil, false},
		{"127.0.0.53", nil, false},
		{"192.168.1.1", nil, false},
		{"192.168.50.1", nil, false},
		{"10.0.0.1", nil, false},
		{"172.16.0.1", nil, false},
		{"172.31.255.1", nil, false},
		{"100.100.100.100", nil, false},
		{"100.64.0.1", nil, false},
		{"198.18.0.1", nil, false},
		{"198.19.255.254", nil, false},
		{"169.254.1.1", nil, false},
		{"224.0.0.1", nil, false},
		{"0.0.0.0", nil, false},
		{"0.1.2.3", nil, false},
		{"240.0.0.1", nil, false},
		{"255.255.255.255", nil, false},
		{"::1", nil, false},
		{"fe80::1", nil, false},
		{"198.51.100.10", map[string]struct{}{"198.51.100.10": {}}, false},
		{"203.0.113.53", map[string]struct{}{"198.51.100.10": {}}, true},
		{"114.114.114.114", nil, true},
	}
	for _, tc := range ipCases {
		ip := net.ParseIP(tc.ipStr)
		if got := singbox.IsPublicISPUnicastIPv4(ip, tc.localIPs); got != tc.wantOK {
			t.Errorf("IsPublicISPUnicastIPv4(%s) = %v, want %v", tc.ipStr, got, tc.wantOK)
		}
	}

	cases := []struct {
		name     string
		files    []string
		localIPs []string
		want     string
	}{
		{
			name:     "loopback_only_falls_back_to_114",
			files:    []string{"nameserver 127.0.0.1\nnameserver 127.0.0.53\n"},
			localIPs: []string{},
			want:     singbox.DefaultFallbackPlainUDPDNS,
		},
		{
			name:     "private_lan_rfc1918_all_filtered_falls_back_to_114",
			files:    []string{"nameserver 192.168.1.1\nnameserver 192.168.50.1\nnameserver 10.0.0.1\nnameserver 172.16.0.1\nnameserver 172.31.255.1\n"},
			localIPs: []string{},
			want:     singbox.DefaultFallbackPlainUDPDNS,
		},
		{
			name:     "cgnat_and_tailscale_magicdns_filtered",
			files:    []string{"nameserver 100.100.100.100\nnameserver 100.64.0.1\n"},
			localIPs: []string{},
			want:     singbox.DefaultFallbackPlainUDPDNS,
		},
		{
			name:     "fakeip_range_filtered",
			files:    []string{"nameserver 198.18.0.1\nnameserver 198.19.255.254\n"},
			localIPs: []string{},
			want:     singbox.DefaultFallbackPlainUDPDNS,
		},
		{
			name:     "link_local_multicast_unspecified_broadcast_filtered",
			files:    []string{"nameserver 169.254.1.1\nnameserver 224.0.0.1\nnameserver 0.0.0.0\nnameserver 255.255.255.255\nnameserver 240.0.0.1\n"},
			localIPs: []string{},
			want:     singbox.DefaultFallbackPlainUDPDNS,
		},
		{
			name:     "skips_own_public_wan_ip_picks_next_isp_dns",
			files:    []string{"nameserver 198.51.100.10\nnameserver 203.0.113.53\n"},
			localIPs: []string{"198.51.100.10"},
			want:     "203.0.113.53",
		},
		{
			name: "mixed_lan_file1_falls_through_to_isp_dns_file2",
			files: []string{
				"nameserver 127.0.0.1\nnameserver 192.168.50.1\n",
				"# auto\nnameserver 203.0.113.88 # Telecom DNS\n",
			},
			localIPs: []string{},
			want:     "203.0.113.88",
		},
		{
			name:     "empty_comments_and_ipv6_only_falls_back_to_114",
			files:    []string{"# comment\n; semicolon\nnameserver ::1\nnameserver fe80::1\n"},
			localIPs: []string{},
			want:     singbox.DefaultFallbackPlainUDPDNS,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var paths []string
			for i, body := range tc.files {
				paths = append(paths, writeTempResolv(filepath.Base(t.Name())+string(rune('a'+i)), body))
			}
			got := singbox.ProbeSafeWANFallbackDNS(paths, tc.localIPs)
			if got != tc.want {
				t.Fatalf("ProbeSafeWANFallbackDNS = %q, want %q", got, tc.want)
			}
		})
	}

	// Missing paths also return 114.114.114.114
	if got := singbox.ProbeSafeWANFallbackDNS([]string{filepath.Join(t.TempDir(), "nonexistent.conf")}, []string{}); got != "114.114.114.114" {
		t.Fatalf("missing resolv path = %q, want 114.114.114.114", got)
	}

	// Integration with PatchDNSLocalJSONWithFallback + sing-box check
	baseSB := `{
  "dns": {
    "servers": [
      {"tag": "dns_local", "type": "udp", "server": "127.0.0.1", "server_port": 5353}
    ],
    "final": "dns_local"
  },
  "route": {"rules": []}
}`
	ispPath := writeTempResolv("resolv.auto", "nameserver 192.168.1.1\nnameserver 203.0.113.88 # ISP\n")
	lanOnlyPath := writeTempResolv("resolv.lan", "nameserver 127.0.0.1\nnameserver 192.168.50.1\n")

	for _, sc := range []struct {
		label string
		path  string
		want  string
	}{
		{"isp_dns", ispPath, "203.0.113.88"},
		{"lan_fallback_114", lanOnlyPath, "114.114.114.114"},
	} {
		targetIP := singbox.ProbeSafeWANFallbackDNS([]string{sc.path}, []string{})
		if targetIP != sc.want {
			t.Fatalf("%s targetIP=%q want %q", sc.label, targetIP, sc.want)
		}
		patched, changed, err := singbox.PatchDNSLocalJSONWithFallback(baseSB, false, 5353, targetIP)
		if err != nil || !changed {
			t.Fatalf("%s PatchDNSLocalJSONWithFallback failed: changed=%v err=%v", sc.label, changed, err)
		}
		doc, err := sboption.ParseDocument([]byte(patched))
		if err != nil {
			t.Fatal(err)
		}
		if len(doc.DNS.Servers) != 1 || doc.DNS.Servers[0].Type != "udp" || doc.DNS.Servers[0].Server != sc.want || doc.DNS.Servers[0].ServerPort != 53 {
			t.Fatalf("%s unexpected dns_local: %+v", sc.label, doc.DNS.Servers)
		}
		if sbBin, err := exec.LookPath("sing-box"); err == nil && sbBin != "" {
			cfgFile := filepath.Join(t.TempDir(), sc.label+".json")
			if err := os.WriteFile(cfgFile, []byte(patched), 0600); err != nil {
				t.Fatal(err)
			}
			if out, cErr := exec.CommandContext(t.Context(), sbBin, "check", "-c", cfgFile).CombinedOutput(); cErr != nil {
				t.Fatalf("sing-box check failed for %s: %v\n%s", sc.label, cErr, string(out))
			}
		}
	}
}
