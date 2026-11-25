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
		`ip daddr { 223.5.5.5, 198.51.100.53 } tcp dport { 443, 853 } accept`,
		`ip6 daddr { 2001:db8::53 } tcp dport { 443, 853 } accept`,
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
		"-A SING_BOX_OUTPUT -m mark --mark 0x80000 -j RETURN",
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
		"-A SING_BOX_OUTPUT -p icmpv6 -j RETURN",
		"-A SING_BOX_OUTPUT -d 2400:3200::1 -p tcp --dport 443 -j RETURN",
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
