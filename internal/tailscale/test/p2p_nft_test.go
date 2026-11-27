// 文件职责：覆盖 Tailscale P2P 防线 LAN 目标白名单解析、fw4 drop-in 渲染与 nftables 直写回滚测试。
package tailscale_test

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"singctl/internal/config"
	"singctl/internal/tailscale"
)

func boolPtr(b bool) *bool { return &b }

func TestParseAllowedLANTarget_ValidationAndFormatting(t *testing.T) {
	cases := []struct {
		raw       string
		wantOK    bool
		wantV6    bool
		wantProto string
		wantPort  int
		wantAddr  string
	}{
		{raw: "192.168.180.0/24", wantOK: true, wantAddr: "192.168.180.0/24"},
		{raw: "192.168.180.10", wantOK: true, wantAddr: "192.168.180.10"},
		{raw: "192.168.180.10:8445", wantOK: true, wantPort: 8445, wantAddr: "192.168.180.10"},
		{raw: "tcp/192.168.180.10:8445", wantOK: true, wantProto: "tcp", wantPort: 8445, wantAddr: "192.168.180.10"},
		{raw: "udp/192.168.180.0/24:5353", wantOK: true, wantProto: "udp", wantPort: 5353, wantAddr: "192.168.180.0/24"},
		{raw: "2001:db8:1::/64", wantOK: true, wantV6: true, wantAddr: "2001:db8:1::/64"},
		{raw: "[2001:db8:1::10]:445", wantOK: true, wantV6: true, wantPort: 445, wantAddr: "2001:db8:1::10"},
		{raw: "", wantOK: false},
		{raw: "192.168.180.0/24; counter accept", wantOK: false},
		{raw: "192.168.180.10:0", wantOK: false},
		{raw: "192.168.180.10:70000", wantOK: false},
		{raw: "icmp/192.168.180.10:80", wantOK: false},
		{raw: "192.168.180.10\naccept", wantOK: false},
	}

	for _, tc := range cases {
		got, err := tailscale.ParseAllowedLANTarget(tc.raw)
		if tc.wantOK {
			if err != nil {
				t.Fatalf("ParseAllowedLANTarget(%q) unexpected error: %v", tc.raw, err)
			}
			if got.IsV6 != tc.wantV6 || got.Proto != tc.wantProto || got.Port != tc.wantPort || got.AddrExpr != tc.wantAddr {
				t.Fatalf("ParseAllowedLANTarget(%q) = %+v, want v6=%v proto=%q port=%d addr=%q",
					tc.raw, got, tc.wantV6, tc.wantProto, tc.wantPort, tc.wantAddr)
			}
		} else if err == nil {
			t.Fatalf("ParseAllowedLANTarget(%q) expected error, got %+v", tc.raw, got)
		}
	}
}

func TestRenderFW4DropIns_PayloadFilterAnd3StateACL(t *testing.T) {
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)

	cfg := config.TailscaleP2PAssistConfig{
		Enabled:       true,
		JITWindowSec:  7,
		PayloadFilter: boolPtr(true),
		ListenPort:    41641,
	}
	peers := []tailscale.ResolvedPeerACL{
		{
			Config: config.TailscaleP2PPeerConfig{
				ID:                 "nPeerA",
				Name:               "router-remote-a",
				JITEnabled:         true,
				AccessMode:         config.TailscaleAccessBidirectionalTimed,
				BidirectionalUntil: now.Add(24 * time.Hour).Format(time.RFC3339),
				AllowedLANTargets:  []string{"192.168.180.10:8445"},
			},
			TailscaleIPs:  []string{"100.64.200.2"},
			PrimaryRoutes: []string{"192.168.55.0/24"},
		},
		{
			Config: config.TailscaleP2PPeerConfig{
				ID:         "nPeerB",
				Name:       "router-remote-b",
				JITEnabled: true,
				AccessMode: config.TailscaleAccessOutboundOnly,
			},
			TailscaleIPs:  []string{"100.64.200.3"},
			PrimaryRoutes: []string{"192.168.66.0/24"},
		},
		{
			Config: config.TailscaleP2PPeerConfig{
				ID:                 "nPeerC",
				Name:               "router-remote-expired",
				JITEnabled:         true,
				AccessMode:         config.TailscaleAccessBidirectionalTimed,
				BidirectionalUntil: now.Add(-1 * time.Minute).Format(time.RFC3339),
				AllowedLANTargets:  []string{"192.168.180.20"},
			},
			TailscaleIPs: []string{"100.64.200.4"},
		},
	}

	dropIns, err := tailscale.RenderFW4DropIns(cfg, peers, "192.168.180.0/24", now)
	if err != nil {
		t.Fatalf("RenderFW4DropIns failed: %v", err)
	}

	for _, want := range []string{
		"set TS_JIT_ALLOW4",
		"set TS_JIT_ALLOW6",
		"flags timeout",
		"limit rate over 300/second burst 600 packets counter drop",
		"@th,64,48 0x5453f09f92ac counter accept",
		"@th,64,32 0x01000000 udp length 156 counter accept",
		"@th,64,32 0x02000000 udp length 100 counter accept",
		"@th,64,32 0x03000000 udp length 72 counter accept",
		"@th,64,32 0x04000000 udp length >= 40 counter accept",
		"@th,96,32 0x2112a442 udp length >= 28 counter accept",
		"chain singctl_ts_jit_guard",
		"chain singctl_ts_input_acl",
		"chain singctl_ts_forward_acl",
	} {
		if !strings.Contains(dropIns.TablePre, want) {
			t.Fatalf("TablePre missing %q:\n%s", want, dropIns.TablePre)
		}
	}

	if !strings.Contains(dropIns.InputWANPre, "udp dport 41641 jump singctl_ts_jit_guard") {
		t.Fatalf("unexpected InputWANPre:\n%s", dropIns.InputWANPre)
	}
	if !strings.Contains(dropIns.InputTailscalePre, "jump singctl_ts_input_acl") {
		t.Fatalf("unexpected InputTailscalePre:\n%s", dropIns.InputTailscalePre)
	}
	if !strings.Contains(dropIns.ForwardTailscalePre, "jump singctl_ts_forward_acl") {
		t.Fatalf("unexpected ForwardTailscalePre:\n%s", dropIns.ForwardTailscalePre)
	}

	inputRules := strings.Join(dropIns.InputACLRules, "\n")
	for _, wantDrop := range []string{
		"ip saddr 100.64.200.2 counter drop",
		"ip saddr 192.168.55.0/24 counter drop",
		"ip saddr 100.64.200.3 counter drop",
		"ip saddr 192.168.66.0/24 counter drop",
		"ip saddr 100.64.200.4 counter drop",
	} {
		if !strings.Contains(inputRules, wantDrop) {
			t.Fatalf("InputACLRules missing %q:\n%s", wantDrop, inputRules)
		}
	}

	fwdRules := strings.Join(dropIns.ForwardACLRules, "\n")
	if !strings.Contains(fwdRules, "ip saddr 100.64.200.2 ip daddr 192.168.180.10 meta l4proto { tcp, udp } th dport 8445 counter accept") {
		t.Fatalf("ForwardACLRules missing Peer A TS IP accept rule:\n%s", fwdRules)
	}
	if !strings.Contains(fwdRules, "ip saddr 192.168.55.0/24 ip daddr 192.168.180.10 meta l4proto { tcp, udp } th dport 8445 counter accept") {
		t.Fatalf("ForwardACLRules missing Peer A PrimaryRoute accept rule:\n%s", fwdRules)
	}
	if strings.Contains(fwdRules, "192.168.180.20") {
		t.Fatalf("expired Peer C must NOT emit allow rule:\n%s", fwdRules)
	}
	if !strings.Contains(fwdRules, "ip saddr 100.64.200.4 counter drop") {
		t.Fatalf("expired Peer C must emit drop rule:\n%s", fwdRules)
	}
	if strings.Contains(inputRules+fwdRules, "100.64.200.99") {
		t.Fatalf("unlisted admin IP must never appear in ACL rules")
	}

	cfg.PayloadFilter = boolPtr(false)
	noFilter, err := tailscale.RenderFW4DropIns(cfg, peers, "192.168.180.0/24", now)
	if err != nil {
		t.Fatalf("RenderFW4DropIns(payload_filter=false) failed: %v", err)
	}
	if strings.Contains(noFilter.TablePre, "@th,") {
		t.Fatalf("payload_filter=false must not emit @th rules:\n%s", noFilter.TablePre)
	}
	if !strings.Contains(noFilter.TablePre, "limit rate over 300/second burst 600 packets counter drop") {
		t.Fatalf("payload_filter=false must retain rate limit:\n%s", noFilter.TablePre)
	}
}

func TestFW4Manager_ApplyIdempotentRollbackAndHybridDirectNFT(t *testing.T) {
	ctx := t.Context()
	baseDir := t.TempDir()

	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	dropIns, err := tailscale.RenderFW4DropIns(config.TailscaleP2PAssistConfig{Enabled: true, JITWindowSec: 5}, []tailscale.ResolvedPeerACL{
		{
			Config:       config.TailscaleP2PPeerConfig{ID: "p1", Name: "r1", JITEnabled: true, AccessMode: config.TailscaleAccessOutboundOnly},
			TailscaleIPs: []string{"100.64.200.2"},
		},
	}, "192.168.180.0/24", now)
	if err != nil {
		t.Fatalf("render: %v", err)
	}

	var calls []string
	liveHasChain := false
	mgr := &tailscale.FW4Manager{
		BaseDir: baseDir,
		Runner: func(ctx context.Context, stdin string, name string, args ...string) ([]byte, error) {
			cmdLine := name + " " + strings.Join(args, " ")
			calls = append(calls, cmdLine)
			if name == "nft" && len(args) >= 3 && args[0] == "list" && args[1] == "chain" {
				if !liveHasChain {
					return nil, errors.New("No such file or directory")
				}
				return []byte("chain singctl_ts_jit_guard {}"), nil
			}
			if name == "fw4" && len(args) == 1 && args[0] == "reload" {
				liveHasChain = true
			}
			return nil, nil
		},
	}

	mode, err := mgr.Apply(ctx, dropIns)
	if err != nil || mode != tailscale.ApplyModeFW4Reload {
		t.Fatalf("expected fw4_reload, got mode=%q err=%v", mode, err)
	}
	if _, err := os.Stat(filepath.Join(baseDir, "table-pre", "singctl-ts-jit.nft")); err != nil {
		t.Fatalf("expected drop-in written: %v", err)
	}

	callsBeforeSecond := len(calls)
	mode2, err := mgr.Apply(ctx, dropIns)
	if err != nil || mode2 != tailscale.ApplyModeFW4Reload {
		t.Fatalf("second Apply unexpected: mode=%q err=%v", mode2, err)
	}
	for _, c := range calls[callsBeforeSecond:] {
		if c == "fw4 reload" || strings.HasPrefix(c, "nft -f") {
			t.Fatalf("expected second identical Apply to skip reload, got call %q", c)
		}
	}

	var appliedScript string
	mgrDirect := &tailscale.FW4Manager{
		BaseDir: t.TempDir(),
		Runner: func(ctx context.Context, stdin string, name string, args ...string) ([]byte, error) {
			if name == "fw4" && len(args) > 0 && args[0] == "check" {
				return []byte("Error: broken thirdparty /etc/nftables.d/foo.nft"), errors.New("exit 1")
			}
			if name == "nft" && len(args) >= 4 && args[0] == "-a" && args[1] == "list" && args[2] == "table" {
				return []byte(`table inet fw4 {
	chain input_wan { # handle 10
		udp dport 41641 jump singctl_ts_jit_guard comment "singctl-ts-jit" # handle 101
		jump reject_from_wan # handle 102
	}
	chain input_tailscale { # handle 20
		jump accept_from_tailscale # handle 201
	}
	chain forward_tailscale { # handle 30
		jump singctl_ts_forward_acl comment "singctl-ts-acl" # handle 301
		jump accept_to_lan # handle 302
	}
}`), nil
			}
			if name == "nft" && len(args) >= 2 && args[0] == "-f" && args[1] == "-" {
				appliedScript = stdin
			}
			return nil, nil
		},
	}

	modeDirect, err := mgrDirect.Apply(ctx, dropIns)
	if err != nil || modeDirect != tailscale.ApplyModeNFTDirect {
		t.Fatalf("expected nft_direct fallback, got mode=%q err=%v", modeDirect, err)
	}
	for _, wantStmt := range []string{
		"add set inet fw4 TS_JIT_ALLOW4",
		"add set inet fw4 TS_JIT_ALLOW6",
		"add chain inet fw4 singctl_ts_jit_guard",
		"flush chain inet fw4 singctl_ts_jit_guard",
		"delete rule inet fw4 input_wan handle 101",
		"delete rule inet fw4 forward_tailscale handle 301",
		`insert rule inet fw4 input_wan udp dport 41641 jump singctl_ts_jit_guard comment "singctl-ts-jit"`,
		`insert rule inet fw4 input_tailscale jump singctl_ts_input_acl comment "singctl-ts-acl"`,
		`insert rule inet fw4 forward_tailscale jump singctl_ts_forward_acl comment "singctl-ts-acl"`,
	} {
		if !strings.Contains(appliedScript, wantStmt) {
			t.Fatalf("direct nft patch missing %q:\n%s", wantStmt, appliedScript)
		}
	}

	rbDir := t.TempDir()
	mgrFail := &tailscale.FW4Manager{
		BaseDir: rbDir,
		Runner: func(ctx context.Context, stdin string, name string, args ...string) ([]byte, error) {
			if name == "nft" && len(args) >= 2 && args[0] == "-c" {
				return nil, nil
			}
			if name == "fw4" {
				return nil, errors.New("fw4 broken")
			}
			if name == "nft" && len(args) >= 4 && args[0] == "-a" && args[1] == "list" {
				return nil, errors.New("table fw4 missing")
			}
			return nil, nil
		},
	}
	if _, err := mgrFail.Apply(ctx, dropIns); err == nil {
		t.Fatal("expected Apply to return error when both fw4 and table inet fw4 fail")
	}
	if _, err := os.Stat(filepath.Join(rbDir, "table-pre", "singctl-ts-jit.nft")); !os.IsNotExist(err) {
		t.Fatalf("expected rollback to remove newly written drop-in file, stat err=%v", err)
	}
}

func TestFW4Manager_PinholesAndCountAndRemove(t *testing.T) {
	ctx := t.Context()
	mgr := &tailscale.FW4Manager{
		BaseDir: t.TempDir(),
		Runner: func(ctx context.Context, stdin string, name string, args ...string) ([]byte, error) {
			if len(args) >= 2 && args[0] == "delete" && args[1] == "element" {
				return []byte("Error: Could not process rule: No such file or directory"), errors.New("exit 1")
			}
			if len(args) >= 4 && args[0] == "-j" && args[1] == "list" && args[2] == "set" {
				if args[5] == tailscale.SetTSJITAllow4Name {
					return []byte(`{"nftables":[{"set":{"name":"TS_JIT_ALLOW4","elem":[{"elem":{"val":"198.51.100.10","timeout":5}}]}}]}`), nil
				}
				return []byte(`{"nftables":[{"set":{"name":"TS_JIT_ALLOW6"}}]}`), nil
			}
			return nil, nil
		},
	}

	v4 := []netip.Addr{netip.MustParseAddr("198.51.100.10")}
	v6 := []netip.Addr{netip.MustParseAddr("2001:db8::10")}
	if err := mgr.OpenPinhole(ctx, v4, v6, 5); err != nil {
		t.Fatalf("OpenPinhole failed: %v", err)
	}
	if err := mgr.ClosePinhole(ctx, v4, v6); err != nil {
		t.Fatalf("ClosePinhole should ignore missing element, got: %v", err)
	}

	cnt, ips := mgr.CountOpenPinholes(ctx)
	if cnt != 1 || len(ips) != 1 || ips[0] != "198.51.100.10" {
		t.Fatalf("unexpected CountOpenPinholes: cnt=%d ips=%v", cnt, ips)
	}

	var removeScript string
	rmDir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(rmDir, "table-pre"), 0755)
	_ = os.WriteFile(filepath.Join(rmDir, "table-pre", "singctl-ts-jit.nft"), []byte("x"), 0644)
	mgrRm := &tailscale.FW4Manager{
		BaseDir: rmDir,
		Runner: func(ctx context.Context, stdin string, name string, args ...string) ([]byte, error) {
			if name == "fw4" {
				return nil, errors.New("fw4 broken")
			}
			if name == "nft" && len(args) >= 4 && args[0] == "-a" && args[1] == "list" {
				return []byte(`table inet fw4 {
	set TS_JIT_ALLOW4 { type ipv4_addr; }
	chain singctl_ts_jit_guard { }
	chain input_wan {
		udp dport 41641 jump singctl_ts_jit_guard comment "singctl-ts-jit" # handle 88
	}
}`), nil
			}
			if name == "nft" && len(args) >= 2 && args[0] == "-f" && args[1] == "-" {
				removeScript = stdin
			}
			return nil, nil
		},
	}
	if err := mgrRm.Remove(ctx); err != nil {
		t.Fatalf("Remove failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(rmDir, "table-pre", "singctl-ts-jit.nft")); !os.IsNotExist(err) {
		t.Fatal("expected Remove to delete drop-in file")
	}
	if !strings.Contains(removeScript, "delete rule inet fw4 input_wan handle 88") ||
		!strings.Contains(removeScript, "delete chain inet fw4 singctl_ts_jit_guard") ||
		!strings.Contains(removeScript, "delete set inet fw4 TS_JIT_ALLOW4") {
		t.Fatalf("unexpected direct nft remove script:\n%s", removeScript)
	}
}

func TestRenderFW4DropIns_MultiSubnetAndBidirectionalRouterInput(t *testing.T) {
	now := time.Date(2026, 11, 27, 0, 0, 0, 0, time.UTC)
	cfg := config.TailscaleP2PAssistConfig{
		Enabled:       true,
		JITWindowSec:  5,
		PayloadFilter: boolPtr(true),
		ListenPort:    41641,
	}
	peers := []tailscale.ResolvedPeerACL{
		{
			Config: config.TailscaleP2PPeerConfig{
				ID:         "nHome1",
				Name:       "home-main",
				JITEnabled: true,
				AccessMode: config.TailscaleAccessBidirectional,
			},
			TailscaleIPs:  []string{"100.96.182.83"},
			PrimaryRoutes: []string{"192.168.55.0/24"},
		},
		{
			Config: config.TailscaleP2PPeerConfig{
				ID:                "nNarrow",
				Name:              "guest-gw",
				JITEnabled:        true,
				AccessMode:        config.TailscaleAccessBidirectional,
				AllowedLANTargets: []string{"192.168.31.10:8080"},
			},
			TailscaleIPs: []string{"100.96.182.99"},
		},
	}

	dropIns, err := tailscale.RenderFW4DropIns(cfg, peers, "192.168.31.0/24, 192.168.27.0/24, 0.0.0.0/0, ::/0", now)
	if err != nil {
		t.Fatalf("RenderFW4DropIns failed: %v", err)
	}

	fwdRules := strings.Join(dropIns.ForwardACLRules, "\n")
	for _, want := range []string{
		"ip saddr 100.96.182.83 ip daddr 192.168.31.0/24 counter accept",
		"ip saddr 100.96.182.83 ip daddr 192.168.27.0/24 counter accept",
		"ip saddr 192.168.55.0/24 ip daddr 192.168.31.0/24 counter accept",
		"ip saddr 192.168.55.0/24 ip daddr 192.168.27.0/24 counter accept",
	} {
		if !strings.Contains(fwdRules, want) {
			t.Fatalf("ForwardACLRules missing %q:\n%s", want, fwdRules)
		}
	}
	if strings.Contains(fwdRules, "0.0.0.0/0") || strings.Contains(fwdRules, "::/0") {
		t.Fatalf("ForwardACLRules must ignore exit node routes:\n%s", fwdRules)
	}

	inputRules := strings.Join(dropIns.InputACLRules, "\n")
	for _, want := range []string{
		"ip saddr 100.96.182.83 ip daddr 192.168.31.0/24 counter accept",
		"ip saddr 100.96.182.83 ip daddr 192.168.27.0/24 counter accept",
		"ip saddr 192.168.55.0/24 ip daddr 192.168.31.0/24 counter accept",
		"ip saddr 100.96.182.83 ip daddr 100.64.0.0/10 counter accept",
		"ip saddr 192.168.55.0/24 ip daddr 100.64.0.0/10 counter accept",
		"ip saddr 100.96.182.83 counter drop",
	} {
		if !strings.Contains(inputRules, want) {
			t.Fatalf("InputACLRules missing %q:\n%s", want, inputRules)
		}
	}
	// Accept rules MUST appear before fallback drop for nHome1.
	accIdx := strings.Index(inputRules, "ip saddr 192.168.55.0/24 ip daddr 192.168.31.0/24 counter accept")
	dropIdx := strings.Index(inputRules, "ip saddr 192.168.55.0/24 counter drop")
	if accIdx < 0 || dropIdx < 0 || accIdx >= dropIdx {
		t.Fatalf("accept rule must precede drop rule (acc=%d, drop=%d):\n%s", accIdx, dropIdx, inputRules)
	}
	// Narrow peer must NOT emit broad CGNAT accept.
	if strings.Contains(inputRules, "ip saddr 100.96.182.99 ip daddr 100.64.0.0/10 counter accept") {
		t.Fatalf("narrow AllowedLANTargets peer must not allow broad CGNAT router input:\n%s", inputRules)
	}
}

func TestRenderFW4DropIns_LocalDeviceScopesAndEgressACL(t *testing.T) {
	now := time.Date(2026, 11, 27, 1, 0, 0, 0, time.UTC)
	peers := []tailscale.ResolvedPeerACL{
		{
			Config: config.TailscaleP2PPeerConfig{
				ID:         "nHome1",
				Name:       "ax3000t",
				JITEnabled: true,
				AccessMode: config.TailscaleAccessBidirectional,
			},
			TailscaleIPs:  []string{"100.96.182.83"},
			PrimaryRoutes: []string{"192.168.55.0/24"},
		},
	}

	// 1. Scope=all emits subnet egress accept & reply conntrack & drop tail.
	dropAll, err := tailscale.RenderFW4DropIns(config.TailscaleP2PAssistConfig{
		Enabled:       true,
		RoleMode:      "router",
		PayloadFilter: boolPtr(true),
		LocalRules: []config.TailscaleLocalSubnetRule{
			{CIDR: "192.168.31.0/24", Scope: config.TailscaleScopeAll},
		},
	}, peers, "192.168.31.0/24", now)
	if err != nil {
		t.Fatalf("Scope=all failed: %v", err)
	}
	egressAll := strings.Join(dropAll.EgressACLRules, "\n")
	for _, want := range []string{
		"ct state { established, related } ct direction reply counter accept",
		"ip saddr 100.64.0.0/10 counter accept",
		"ip saddr 192.168.31.0/24 counter accept",
		"counter drop",
	} {
		if !strings.Contains(egressAll, want) {
			t.Fatalf("Scope=all EgressACLRules missing %q:\n%s", want, egressAll)
		}
	}
	if !strings.Contains(dropAll.ForwardEgressPre, `oifname "tailscale*" jump singctl_ts_egress_acl comment "singctl-ts-acl"`) {
		t.Fatalf("unexpected ForwardEgressPre:\n%s", dropAll.ForwardEgressPre)
	}

	// 2. Scope=allowlist restricts BOTH egress and ingress strictly to 192.168.31.88.
	dropAllow, err := tailscale.RenderFW4DropIns(config.TailscaleP2PAssistConfig{
		Enabled:       true,
		RoleMode:      "gateway",
		PayloadFilter: boolPtr(true),
		LocalRules: []config.TailscaleLocalSubnetRule{
			{CIDR: "192.168.31.0/24", Scope: config.TailscaleScopeAllowlist, Devices: []string{"192.168.31.88"}},
		},
	}, peers, "192.168.31.0/24", now)
	if err != nil {
		t.Fatalf("Scope=allowlist failed: %v", err)
	}
	egressAllow := strings.Join(dropAllow.EgressACLRules, "\n")
	if !strings.Contains(egressAllow, "ip saddr 192.168.31.88 counter accept") {
		t.Fatalf("expected allowlisted host in EgressACLRules:\n%s", egressAllow)
	}
	if strings.Contains(egressAllow, "ip saddr 192.168.31.0/24 counter accept") {
		t.Fatalf("allowlist must NOT accept entire 192.168.31.0/24 in EgressACLRules:\n%s", egressAllow)
	}
	fwdAllow := strings.Join(dropAllow.ForwardACLRules, "\n")
	guardRule := "ip daddr 192.168.31.0/24 ip daddr != { 192.168.31.88 } counter drop"
	if !strings.Contains(fwdAllow, guardRule) {
		t.Fatalf("expected allowlist ingress guard %q in ForwardACLRules:\n%s", guardRule, fwdAllow)
	}
	if strings.Index(fwdAllow, guardRule) >= strings.Index(fwdAllow, "ip saddr 192.168.55.0/24") {
		t.Fatalf("allowlist ingress guard must precede peer accept rules:\n%s", fwdAllow)
	}

	// 3. Scope=denylist drops 192.168.31.151 before allowing rest of 192.168.31.0/24.
	dropDeny, err := tailscale.RenderFW4DropIns(config.TailscaleP2PAssistConfig{
		Enabled:       true,
		RoleMode:      "router",
		PayloadFilter: boolPtr(true),
		LocalRules: []config.TailscaleLocalSubnetRule{
			{CIDR: "192.168.31.0/24", Scope: config.TailscaleScopeDenylist, Devices: []string{"192.168.31.151"}},
		},
	}, peers, "192.168.31.0/24", now)
	if err != nil {
		t.Fatalf("Scope=denylist failed: %v", err)
	}
	egressDeny := strings.Join(dropDeny.EgressACLRules, "\n")
	dropIdx := strings.Index(egressDeny, "ip saddr 192.168.31.151 counter drop")
	accIdx := strings.Index(egressDeny, "ip saddr 192.168.31.0/24 counter accept")
	if dropIdx < 0 || accIdx < 0 || dropIdx >= accIdx {
		t.Fatalf("denylist drop must precede subnet accept in EgressACLRules:\n%s", egressDeny)
	}
	fwdDeny := strings.Join(dropDeny.ForwardACLRules, "\n")
	if !strings.Contains(fwdDeny, "ip daddr 192.168.31.151 counter drop") {
		t.Fatalf("denylist must emit ip daddr drop in ForwardACLRules:\n%s", fwdDeny)
	}
}

func TestRenderFW4DropInsWithOptions_DownstreamEdgeJIT_MutualExclusionAndSecurity(t *testing.T) {
	now := time.Date(2026, 11, 27, 4, 0, 0, 0, time.UTC)
	baseCfg := config.TailscaleP2PAssistConfig{
		Enabled:       true,
		JITWindowSec:  5,
		PayloadFilter: boolPtr(true),
		ListenPort:    41641,
	}

	// 1. Local Tailscale stopped + DownstreamAssist default(true): both IPv4 & IPv6 downstream 5s dynamic micro-window active.
	dropDown, err := tailscale.RenderFW4DropInsWithOptions(baseCfg, nil, "", now, tailscale.FW4RenderOptions{
		LocalTailscaleRunning: false,
	})
	if err != nil {
		t.Fatalf("RenderFW4DropInsWithOptions(stopped) failed: %v", err)
	}
	if !dropDown.DownstreamV4Active || !dropDown.DownstreamV6Active {
		t.Fatalf("expected both v4 & v6 downstream active when local tailscale stopped, got v4=%v v6=%v",
			dropDown.DownstreamV4Active, dropDown.DownstreamV6Active)
	}
	for _, want := range []string{
		"map TS_LAN_PUNCH4",
		"type ipv4_addr : ipv4_addr",
		"size 64",
		"flags dynamic, timeout",
		"timeout 5s",
		"set TS_LAN_PUNCH6",
		"type ipv6_addr . ipv6_addr",
		"chain singctl_ts_lan_learn4",
		"udp sport != 41641 return",
		"udp dport 3478 return",
		"ip saddr != { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } return",
		"@th,64,48 0x5453f09f92ac update @TS_LAN_PUNCH4 { ip daddr timeout 5s : ip saddr } return",
		"chain singctl_ts_lan_dnat4",
		"fib daddr type != local return",
		"ip saddr != @TS_LAN_PUNCH4 return",
		"limit rate over 300/second burst 600 packets return",
		"udp dport 41641 @th,64,48 0x5453f09f92ac counter dnat ip to ip saddr map @TS_LAN_PUNCH4 : 41641",
		"chain singctl_ts_lan_learn6",
		"chain singctl_ts_lan_fwd",
		"ct status dnat udp dport 41641 ip saddr @TS_LAN_PUNCH4 counter accept",
	} {
		if !strings.Contains(dropDown.TablePre, want) {
			t.Fatalf("TablePre missing %q:\n%s", want, dropDown.TablePre)
		}
	}
	if !strings.Contains(dropDown.ForwardLanLearnPre, "jump singctl_ts_lan_learn4") {
		t.Fatalf("missing ForwardLanLearnPre jump:\n%s", dropDown.ForwardLanLearnPre)
	}
	if !strings.Contains(dropDown.ForwardLanV6LearnPre, "jump singctl_ts_lan_learn6") {
		t.Fatalf("missing ForwardLanV6LearnPre jump:\n%s", dropDown.ForwardLanV6LearnPre)
	}
	if !strings.Contains(dropDown.DstnatPre, "jump singctl_ts_lan_dnat4") {
		t.Fatalf("missing DstnatPre jump:\n%s", dropDown.DstnatPre)
	}
	if !strings.Contains(dropDown.ForwardWANPre, "jump singctl_ts_lan_fwd") {
		t.Fatalf("missing ForwardWANPre jump:\n%s", dropDown.ForwardWANPre)
	}
	if !strings.Contains(dropDown.SrcnatLanPre, "ct status dnat udp dport 41641 ip saddr @TS_LAN_PUNCH4 return") {
		t.Fatalf("missing SrcnatLanPre bypass rule:\n%s", dropDown.SrcnatLanPre)
	}
	dryRun := dropDown.RenderDryRunCheckScript()
	for _, wantHook := range []string{"chain dstnat", "chain forward_wan", "chain srcnat_lan"} {
		if !strings.Contains(dryRun, wantHook) {
			t.Fatalf("dry-run script missing %q:\n%s", wantHook, dryRun)
		}
	}

	// 2. Local Tailscale RUNNING: strict IPv4 mutual exclusion (no TS_LAN_PUNCH4 / DstnatPre / SrcnatLanPre), IPv6 remains active.
	dropHost, err := tailscale.RenderFW4DropInsWithOptions(baseCfg, nil, "192.168.31.0/24", now, tailscale.FW4RenderOptions{
		LocalTailscaleRunning: true,
	})
	if err != nil {
		t.Fatalf("RenderFW4DropInsWithOptions(running) failed: %v", err)
	}
	if dropHost.DownstreamV4Active || !dropHost.DownstreamV6Active {
		t.Fatalf("expected v4=false v6=true when local tailscale running, got v4=%v v6=%v",
			dropHost.DownstreamV4Active, dropHost.DownstreamV6Active)
	}
	for _, forbidden := range []string{"TS_LAN_PUNCH4", "singctl_ts_lan_dnat4", "singctl_ts_lan_learn4"} {
		if strings.Contains(dropHost.TablePre, forbidden) {
			t.Fatalf("host-running mode must not emit %q:\n%s", forbidden, dropHost.TablePre)
		}
	}
	if dropHost.DstnatPre != "" || dropHost.SrcnatLanPre != "" || dropHost.ForwardLanLearnPre != "" {
		t.Fatalf("host-running mode must leave IPv4 downstream drop-ins empty: dstnat=%q srcnat=%q fwd=%q",
			dropHost.DstnatPre, dropHost.SrcnatLanPre, dropHost.ForwardLanLearnPre)
	}
	if !strings.Contains(dropHost.TablePre, "set TS_LAN_PUNCH6") || !strings.Contains(dropHost.ForwardWANPre, "jump singctl_ts_lan_fwd") {
		t.Fatalf("host-running mode should keep IPv6 downstream assist active")
	}

	// 3. DownstreamAssist explicitly false: both v4 & v6 downstream completely omitted.
	cfgOff := baseCfg
	cfgOff.DownstreamAssist = boolPtr(false)
	dropOff, err := tailscale.RenderFW4DropInsWithOptions(cfgOff, nil, "", now, tailscale.FW4RenderOptions{
		LocalTailscaleRunning: false,
	})
	if err != nil {
		t.Fatalf("RenderFW4DropInsWithOptions(disabled) failed: %v", err)
	}
	if dropOff.DownstreamV4Active || dropOff.DownstreamV6Active {
		t.Fatalf("expected downstream disabled, got v4=%v v6=%v", dropOff.DownstreamV4Active, dropOff.DownstreamV6Active)
	}
	if strings.Contains(dropOff.TablePre, "TS_LAN_PUNCH") || dropOff.ForwardWANPre != "" || dropOff.DstnatPre != "" {
		t.Fatalf("disabled downstream assist must emit zero TS_LAN_PUNCH rules")
	}
}

func TestFW4Manager_DownstreamDropInCleanupOnModeSwitch(t *testing.T) {
	baseDir := t.TempDir()
	mgr := &tailscale.FW4Manager{
		BaseDir: baseDir,
		Runner: func(_ context.Context, _ string, _ string, _ ...string) ([]byte, error) {
			return nil, nil
		},
	}
	now := time.Date(2026, 11, 27, 4, 0, 0, 0, time.UTC)
	cfg := config.TailscaleP2PAssistConfig{Enabled: true, JITWindowSec: 5, PayloadFilter: boolPtr(true)}

	// 1. Apply with local Tailscale stopped -> writes dstnat + srcnat_lan + forward_wan + forward/lan-jit drop-ins.
	dStopped, err := tailscale.RenderFW4DropInsWithOptions(cfg, nil, "", now, tailscale.FW4RenderOptions{LocalTailscaleRunning: false})
	if err != nil {
		t.Fatalf("render stopped: %v", err)
	}
	if _, err := mgr.Apply(t.Context(), dStopped); err != nil {
		t.Fatalf("Apply(stopped) failed: %v", err)
	}
	dstnatPath := filepath.Join(baseDir, "chain-pre", "dstnat", "singctl-ts-lan-jit.nft")
	srcnatPath := filepath.Join(baseDir, "chain-pre", "srcnat_lan", "singctl-ts-lan-jit.nft")
	fwdWANPath := filepath.Join(baseDir, "chain-pre", "forward_wan", "singctl-ts-lan-jit.nft")
	for _, p := range []string{dstnatPath, srcnatPath, fwdWANPath} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("expected drop-in %s to exist in stopped mode: %v", p, err)
		}
	}

	// 2. Switch to local Tailscale running -> stale IPv4 dstnat & srcnat_lan drop-ins MUST be removed, forward_wan kept for IPv6.
	dRunning, err := tailscale.RenderFW4DropInsWithOptions(cfg, nil, "192.168.31.0/24", now, tailscale.FW4RenderOptions{LocalTailscaleRunning: true})
	if err != nil {
		t.Fatalf("render running: %v", err)
	}
	if _, err := mgr.Apply(t.Context(), dRunning); err != nil {
		t.Fatalf("Apply(running) failed: %v", err)
	}
	for _, removed := range []string{dstnatPath, srcnatPath} {
		if _, err := os.Stat(removed); !os.IsNotExist(err) {
			t.Fatalf("expected stale IPv4 drop-in %s to be removed when local tailscale runs, stat err=%v", removed, err)
		}
	}
	if _, err := os.Stat(fwdWANPath); err != nil {
		t.Fatalf("expected IPv6 forward_wan drop-in %s to remain: %v", fwdWANPath, err)
	}
}
