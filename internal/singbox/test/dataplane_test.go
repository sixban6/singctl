package singbox_test

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"singctl/internal/config"
	"singctl/internal/platform/rtnl"
	"singctl/internal/singbox"
)

type recordedFWTxCall struct {
	Stdin string
	Name  string
	Args  []string
}

type mockFWTxRunner struct {
	calls []recordedFWTxCall
	fn    func(stdin, name string, args ...string) ([]byte, error)
}

func (m *mockFWTxRunner) RunStdin(_ context.Context, stdin, name string, args ...string) ([]byte, error) {
	m.calls = append(m.calls, recordedFWTxCall{
		Stdin: stdin,
		Name:  name,
		Args:  append([]string(nil), args...),
	})
	if m.fn != nil {
		return m.fn(stdin, name, args...)
	}
	return nil, nil
}

func TestBuildTProxyRouteSpec_DefaultsAndIPv6Prefixes(t *testing.T) {
	in := singbox.DataplaneInput{
		TProxyPort: 7895,
		EnableIPv6: true,
		LANIPv6Prefixes: []netip.Prefix{
			netip.MustParsePrefix("2001:db8:abcd:1::/64"),
		},
	}

	spec := singbox.BuildTProxyRouteSpec(in)
	if spec.ForwardFwMark != 0x1 || spec.ForwardTable != 100 || spec.LocalFwMark != 0x2 || spec.LocalTable != 101 || !spec.EnableIPv6 {
		t.Fatalf("unexpected TProxyRouteSpec header: %+v", spec)
	}
	if !slices.Contains(spec.ThrowV4Prefixes, netip.MustParsePrefix("192.168.0.0/16")) ||
		!slices.Contains(spec.ThrowV4Prefixes, netip.MustParsePrefix("100.64.0.0/10")) {
		t.Fatalf("missing required IPv4 throw prefixes: %v", spec.ThrowV4Prefixes)
	}
	if !slices.Contains(spec.ThrowV6Prefixes, netip.MustParsePrefix("2001:db8:abcd:1::/64")) ||
		!slices.Contains(spec.ThrowV6Prefixes, netip.MustParsePrefix("fd7a:115c:a1e0::/48")) {
		t.Fatalf("missing required IPv6 throw prefixes: %v", spec.ThrowV6Prefixes)
	}
}

func TestRenderSingBoxNFTBatch_SingleTransactionParityAndGuards(t *testing.T) {
	in := singbox.DataplaneInput{
		TProxyPort: 7895,
		EnableIPv6: true,
		LANIPv6Prefixes: []netip.Prefix{
			netip.MustParsePrefix("2001:db8:1234::/64"),
		},
		BypassDNSV4: []netip.Addr{
			netip.MustParseAddr("223.5.5.5"),
			netip.MustParseAddr("198.51.100.53"),
		},
		BypassDNSV6: []netip.Addr{
			netip.MustParseAddr("2001:db8::53"),
		},
		BypassVLANCIDRs: []netip.Prefix{
			netip.MustParsePrefix("192.168.20.0/24"),
		},
	}

	script, err := singbox.RenderSingBoxNFTBatch(in)
	if err != nil {
		t.Fatalf("RenderSingBoxNFTBatch failed: %v", err)
	}

	idxAdd := strings.Index(script, "add table inet sing-box\n")
	idxFlush := strings.Index(script, "flush table inet sing-box\n")
	idxTable := strings.Index(script, "table inet sing-box {")
	if idxAdd < 0 || idxFlush < 0 || idxTable < 0 || !(idxAdd < idxFlush && idxFlush < idxTable) {
		t.Fatalf("missing single-transaction atomic preamble:\n%s", script)
	}

	for _, want := range []string{
		"set LOCAL_IPV4_SET",
		"100.64.0.0/10",
		"set LOCAL_IPV6_SET",
		"2001:db8:1234::/64",
		`fib daddr type local meta l4proto { tcp, udp } th dport 7895 reject with icmpx type host-unreachable`,
		`iifname "lo" meta mark 0x2 meta l4proto { tcp, udp } tproxy to :7895 meta mark set 0x2 accept`,
		`ip saddr { 192.168.20.0/24 } fib daddr type != local accept comment "singctl-vlan-bypass"`,
		`meta l4proto { tcp, udp } th dport 53 tproxy to :7895 meta mark set 0x1 accept comment "DNS透明代理"`,
		`ip daddr { 223.5.5.5, 198.51.100.53 } meta l4proto { tcp, udp } th dport { 443, 853 } accept`,
		`ip6 daddr { 2001:db8::53 } meta l4proto { tcp, udp } th dport { 443, 853 } accept`,
		`meta mark 0x80000 accept`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("nft batch missing %q:\n%s", want, script)
		}
	}

	// Verify DNS proxy redirect comes BEFORE LOCAL_IPV4_SET accept (blocks LAN modem :53 leaks)
	if strings.Index(script, "th dport 53 tproxy") >= strings.Index(script, "ip daddr @LOCAL_IPV4_SET accept") {
		t.Fatalf("DNS 53 tproxy must precede LOCAL_IPV4_SET accept:\n%s", script)
	}

	// Verify downstream Tailscale P2P UDP 41641 (STUN/Disco/WireGuard) bypasses prerouting TProxy
	// AFTER DNS 53 & LOCAL sets and BEFORE catch-all TProxy, without opening WebRTC STUN 3478 globally.
	preroutingStart := strings.Index(script, "chain prerouting {")
	outputStart := strings.Index(script, "chain output {")
	if preroutingStart < 0 || outputStart <= preroutingStart {
		t.Fatalf("missing prerouting/output chains:\n%s", script)
	}
	preroutingBlock := script[preroutingStart:outputStart]
	idxSport := strings.Index(preroutingBlock, `udp sport 41641 accept comment "Bypass downstream Tailscale UDP port"`)
	idxDport := strings.Index(preroutingBlock, `udp dport 41641 accept comment "Bypass downstream Tailscale UDP port"`)
	idxLocal6 := strings.Index(preroutingBlock, "ip6 daddr @LOCAL_IPV6_SET accept")
	idxCatchAll := strings.LastIndex(preroutingBlock, "tproxy to :7895 meta mark set 0x1 accept")
	if idxSport < 0 || idxDport < 0 {
		t.Fatalf("nft prerouting must bypass downstream Tailscale UDP 41641 sport/dport:\n%s", preroutingBlock)
	}
	if !(idxLocal6 < idxSport && idxSport < idxCatchAll && idxLocal6 < idxDport && idxDport < idxCatchAll) {
		t.Fatalf("nft prerouting UDP 41641 bypass must sit after LOCAL_IPV6_SET and before catch-all TProxy:\n%s", preroutingBlock)
	}
	if strings.Contains(preroutingBlock, "3478") {
		t.Fatalf("nft prerouting must not unconditionally bypass UDP 3478 (preserves WebRTC anti-leak):\n%s", preroutingBlock)
	}

	// Reject out-of-range port
	if _, err := singbox.RenderSingBoxNFTBatch(singbox.DataplaneInput{TProxyPort: 0}); err == nil {
		t.Fatal("expected error for invalid TProxyPort=0")
	}
}

func TestRenderSingBoxIPTablesRestore_CapsFallbackAndParity(t *testing.T) {
	in := singbox.DataplaneInput{
		TProxyPort: 7895,
		EnableIPv6: true,
		LocalIPv4s: []netip.Addr{
			netip.MustParseAddr("127.0.0.1"),
			netip.MustParseAddr("192.168.1.1"),
		},
		LANIPv6Prefixes: []netip.Prefix{
			netip.MustParsePrefix("2001:db8:abcd::/64"),
		},
		BypassDNSV4: []netip.Addr{
			netip.MustParseAddr("223.5.5.5"),
		},
		BypassDNSV6: []netip.Addr{
			netip.MustParseAddr("2400:3200::1"),
		},
		BypassVLANCIDRs: []netip.Prefix{
			netip.MustParsePrefix("192.168.30.0/24"),
		},
	}

	// 1. Degraded firmware: no xt_addrtype, no mangle REJECT, no ip6tables TPROXY
	v4Degraded, v6Degraded, err := singbox.RenderSingBoxIPTablesRestore(in, singbox.IPTablesCaps{
		HasAddrType:     false,
		HasMangleReject: false,
		HasIPv6TProxy:   false,
	})
	if err != nil {
		t.Fatalf("degraded RenderSingBoxIPTablesRestore failed: %v", err)
	}
	if v6Degraded != "" {
		t.Fatalf("expected empty v6 batch when HasIPv6TProxy=false, got:\n%s", v6Degraded)
	}
	for _, forbidden := range []string{"-F PREROUTING", "-F OUTPUT", "-m addrtype"} {
		if strings.Contains(v4Degraded, forbidden) {
			t.Fatalf("degraded v4 batch must not contain %q:\n%s", forbidden, v4Degraded)
		}
	}
	for _, want := range []string{
		"*mangle",
		":SING_BOX - [0:0]",
		":SING_BOX_OUTPUT - [0:0]",
		"-F SING_BOX",
		"-F SING_BOX_OUTPUT",
		"-A SING_BOX -d 192.168.1.1 -p tcp --dport 7895 -j DROP",
		"-A SING_BOX -d 192.168.1.1 -j RETURN",
		"-A SING_BOX -s 192.168.30.0/24",
		"-A SING_BOX -p udp --dport 53 -j TPROXY --on-port 7895 --tproxy-mark 1",
		"-A SING_BOX -p udp --sport 41641 -j RETURN",
		"-A SING_BOX -p udp --dport 41641 -j RETURN",
		"-A SING_BOX_OUTPUT -m mark --mark 0x80000 -j RETURN",
		"-A SING_BOX_OUTPUT -d 223.5.5.5 -p tcp --dport 443 -j RETURN",
		"-A SING_BOX_OUTPUT -d 223.5.5.5 -p udp --dport 443 -j RETURN",
		"-A SING_BOX_OUTPUT -d 223.5.5.5 -p tcp --dport 853 -j RETURN",
		"-A SING_BOX_OUTPUT -d 223.5.5.5 -p udp --dport 853 -j RETURN",
		"COMMIT",
	} {
		if !strings.Contains(v4Degraded, want) {
			t.Fatalf("degraded v4 batch missing %q:\n%s", want, v4Degraded)
		}
	}

	// 2. Full dual-stack firmware
	v4Full, v6Full, err := singbox.RenderSingBoxIPTablesRestore(in, singbox.IPTablesCaps{
		HasAddrType:     true,
		HasMangleReject: true,
		HasIPv6TProxy:   true,
	})
	if err != nil {
		t.Fatalf("full RenderSingBoxIPTablesRestore failed: %v", err)
	}
	if !strings.Contains(v4Full, "-m addrtype --dst-type LOCAL -p tcp --dport 7895 -j REJECT") {
		t.Fatalf("full v4 batch missing addrtype REJECT guard:\n%s", v4Full)
	}
	for _, wantV6 := range []string{
		"-A SING_BOX -d 2001:db8:abcd::/64 -j RETURN",
		"-A SING_BOX -p udp --sport 41641 -j RETURN",
		"-A SING_BOX -p udp --dport 41641 -j RETURN",
		"-A SING_BOX_OUTPUT -p icmpv6 -j RETURN",
		"-A SING_BOX_OUTPUT -d 2400:3200::1 -p tcp --dport 443 -j RETURN",
		"-A SING_BOX_OUTPUT -d 2400:3200::1 -p udp --dport 443 -j RETURN",
		"-A SING_BOX_OUTPUT -d 2400:3200::1 -p tcp --dport 853 -j RETURN",
		"-A SING_BOX_OUTPUT -d 2400:3200::1 -p udp --dport 853 -j RETURN",
		"COMMIT",
	} {
		if !strings.Contains(v6Full, wantV6) {
			t.Fatalf("full v6 batch missing %q:\n%s", wantV6, v6Full)
		}
	}
}

func TestApplyDataplane_RollsBackRoutesOnFirewallFailure(t *testing.T) {
	in := singbox.DataplaneInput{
		TProxyPort: 7895,
		EnableIPv6: true,
	}

	mockNL := rtnl.NewMockClient()
	failingRunner := &mockFWTxRunner{
		fn: func(_, name string, args ...string) ([]byte, error) {
			return []byte("mock nft failure"), errors.New("exit status 1")
		},
	}

	err := singbox.ApplyDataplane(t.Context(), in, singbox.IPTablesCaps{}, true, mockNL, failingRunner)
	if err == nil {
		t.Fatal("expected ApplyDataplane to fail when fwtx fails")
	}
	if len(mockNL.ReconciledSpecs()) != 1 {
		t.Fatalf("expected 1 route reconcile call, got %d", len(mockNL.ReconciledSpecs()))
	}
	cleaned := mockNL.CleanedTables()
	if len(cleaned) != 1 || !slices.Equal(cleaned[0], []int{100, 101}) {
		t.Fatalf("expected automatic route rollback on firewall failure, got cleaned=%v", cleaned)
	}

	// Happy path nftables + CleanupDataplane
	okNL := rtnl.NewMockClient()
	okRunner := &mockFWTxRunner{}
	if err := singbox.ApplyDataplane(t.Context(), in, singbox.IPTablesCaps{}, true, okNL, okRunner); err != nil {
		t.Fatalf("ApplyDataplane happy path failed: %v", err)
	}
	if len(okRunner.calls) != 2 || okRunner.calls[0].Name != "nft" {
		t.Fatalf("expected nft check + apply calls, got %+v", okRunner.calls)
	}
	if err := singbox.CleanupDataplane(t.Context(), true, okNL, okRunner); err != nil {
		t.Fatalf("CleanupDataplane failed: %v", err)
	}
	if len(okNL.CleanedTables()) != 1 {
		t.Fatalf("expected CleanupTProxyRoutes call")
	}
}

func TestCollectDataplaneInput_ReadsDNSBypassAndVLANFromFiles(t *testing.T) {
	dir := t.TempDir()
	agh := filepath.Join(dir, "AdGuardHome.yaml")
	sdns := filepath.Join(dir, "smartdns.conf")
	vlan := filepath.Join(dir, "vlan.list")

	_ = os.WriteFile(agh, []byte("dns:\n  upstream_dns:\n    - https://198.51.100.11/dns-query\n    - tls://[2001:db8::11]:853\n"), 0600)
	_ = os.WriteFile(sdns, []byte("server-https https://203.0.113.22/dns-query\nserver-tls [2001:db8::22]:853\n"), 0600)
	_ = os.WriteFile(vlan, []byte("192.168.50.0/24\n127.0.0.0/8\nbad;inject\n"), 0600)

	mockNL := rtnl.NewMockClient()
	mockNL.Addresses = []rtnl.InterfaceAddr{
		{IfIndex: 2, IfName: "br-lan", IsUp: true, Prefix: netip.MustParsePrefix("192.168.1.1/24")},
		{IfIndex: 2, IfName: "br-lan", IsUp: true, Prefix: netip.MustParsePrefix("2001:db8:feed::1/64")},
	}

	cfg := &config.Config{}
	cfg.Gateway.IPv6Mode = "cn_only"
	in := singbox.CollectDataplaneInput(cfg, mockNL, agh, sdns, vlan)

	if !in.EnableIPv6 || in.TProxyPort != 7895 {
		t.Fatalf("unexpected base DataplaneInput: %+v", in)
	}
	if !slices.Contains(in.LocalIPv4s, netip.MustParseAddr("192.168.1.1")) {
		t.Fatalf("expected LocalIPv4 from RTNL, got %v", in.LocalIPv4s)
	}
	if !slices.Contains(in.LANIPv6Prefixes, netip.MustParsePrefix("2001:db8:feed::/64")) {
		t.Fatalf("expected LAN IPv6 prefix from RTNL, got %v", in.LANIPv6Prefixes)
	}
	if !slices.Contains(in.BypassDNSV4, netip.MustParseAddr("198.51.100.11")) ||
		!slices.Contains(in.BypassDNSV4, netip.MustParseAddr("203.0.113.22")) {
		t.Fatalf("missing bypass DNS IPv4 entries: %v", in.BypassDNSV4)
	}
	if !slices.Contains(in.BypassDNSV6, netip.MustParseAddr("2001:db8::11")) ||
		!slices.Contains(in.BypassDNSV6, netip.MustParseAddr("2001:db8::22")) {
		t.Fatalf("missing bypass DNS IPv6 entries: %v", in.BypassDNSV6)
	}
	if !slices.Equal(in.BypassVLANCIDRs, []netip.Prefix{netip.MustParsePrefix("192.168.50.0/24")}) {
		t.Fatalf("unexpected VLAN bypass CIDRs: %v", in.BypassVLANCIDRs)
	}
}

func TestSyncSingBoxFW3Include(t *testing.T) {
	scriptPath := filepath.Join(t.TempDir(), "etc", "sing-box", "singbox.fw3.sh")
	uciPresent := false
	runner := &mockFWTxRunner{
		fn: func(_ string, name string, args ...string) ([]byte, error) {
			line := name + " " + strings.Join(args, " ")
			if line == "uci -q get firewall.singctl_singbox" && !uciPresent {
				return nil, os.ErrNotExist
			}
			if line == "uci set firewall.singctl_singbox=include" {
				uciPresent = true
			}
			if line == "uci delete firewall.singctl_singbox" {
				uciPresent = false
			}
			return nil, nil
		},
	}

	v4Batch := "*mangle\n:SING_BOX - [0:0]\nCOMMIT\n"
	v6Batch := "*mangle\n:SING_BOX - [0:0]\nCOMMIT\n"
	if err := singbox.SyncSingBoxFW3Include(t.Context(), scriptPath, v4Batch, v6Batch, runner); err != nil {
		t.Fatalf("SyncSingBoxFW3Include apply failed: %v", err)
	}

	st, err := os.Stat(scriptPath)
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 script %s, err=%v mode=%v", scriptPath, err, st.Mode().Perm())
	}
	raw, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("read script: %v", err)
	}
	scriptText := string(raw)
	if strings.Contains(scriptText, "exit ") || strings.Contains(scriptText, "\nexit\n") {
		t.Fatalf("fw3 script MUST NOT contain exit:\n%s", scriptText)
	}
	for _, want := range []string{
		"iptables-restore --noflush",
		"SING_BOX",
		"SING_BOX_OUTPUT",
		"ip6tables-restore --noflush",
	} {
		if !strings.Contains(scriptText, want) {
			t.Fatalf("script missing %q:\n%s", want, scriptText)
		}
	}

	var uciLines []string
	for _, c := range runner.calls {
		uciLines = append(uciLines, c.Name+" "+strings.Join(c.Args, " "))
	}
	joinedUCI := strings.Join(uciLines, "\n")
	for _, wantUCI := range []string{
		"uci set firewall.singctl_singbox=include",
		"uci set firewall.singctl_singbox.type=script",
		"uci set firewall.singctl_singbox.path=" + scriptPath,
		"uci set firewall.singctl_singbox.reload=1",
		"uci commit firewall",
	} {
		if !strings.Contains(joinedUCI, wantUCI) {
			t.Fatalf("missing UCI command %q in:\n%s", wantUCI, joinedUCI)
		}
	}

	// Cleanup with empty v4Batch removes script and UCI section idempotently.
	runner.calls = nil
	if err := singbox.SyncSingBoxFW3Include(t.Context(), scriptPath, "", "", runner); err != nil {
		t.Fatalf("SyncSingBoxFW3Include cleanup failed: %v", err)
	}
	if _, statErr := os.Stat(scriptPath); !os.IsNotExist(statErr) {
		t.Fatalf("expected script removed after cleanup, err=%v", statErr)
	}
	var cleanLines []string
	for _, c := range runner.calls {
		cleanLines = append(cleanLines, c.Name+" "+strings.Join(c.Args, " "))
	}
	cleanJoined := strings.Join(cleanLines, "\n")
	if !strings.Contains(cleanJoined, "uci delete firewall.singctl_singbox") || !strings.Contains(cleanJoined, "uci commit firewall") {
		t.Fatalf("expected UCI delete + commit firewall on cleanup, got:\n%s", cleanJoined)
	}
}
