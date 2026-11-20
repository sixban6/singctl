package tailscale

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
)

func boolPtr(b bool) *bool { return &b }

func TestParseAllowedLANTarget_ValidationAndFormatting(t *testing.T) {
	cases := []struct {
		raw      string
		wantOK   bool
		wantV6   bool
		wantProto string
		wantPort int
		wantAddr string
	}{
		{raw: "192.168.180.0/24", wantOK: true, wantAddr: "192.168.180.0/24"},
		{raw: "192.168.180.10", wantOK: true, wantAddr: "192.168.180.10"},
		{raw: "192.168.180.10:8445", wantOK: true, wantPort: 8445, wantAddr: "192.168.180.10"},
		{raw: "tcp/192.168.180.10:8445", wantOK: true, wantProto: "tcp", wantPort: 8445, wantAddr: "192.168.180.10"},
		{raw: "udp/192.168.180.0/24:5353", wantOK: true, wantProto: "udp", wantPort: 5353, wantAddr: "192.168.180.0/24"},
		{raw: "2001:db8:1::/64", wantOK: true, wantV6: true, wantAddr: "2001:db8:1::/64"},
		{raw: "[2001:db8:1::10]:445", wantOK: true, wantV6: true, wantPort: 445, wantAddr: "2001:db8:1::10"},
		// Invalid / injection inputs
		{raw: "", wantOK: false},
		{raw: "192.168.180.0/24; counter accept", wantOK: false},
		{raw: "192.168.180.10:0", wantOK: false},
		{raw: "192.168.180.10:70000", wantOK: false},
		{raw: "icmp/192.168.180.10:80", wantOK: false},
		{raw: "192.168.180.10\naccept", wantOK: false},
	}

	for _, tc := range cases {
		got, err := ParseAllowedLANTarget(tc.raw)
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
	peers := []ResolvedPeerACL{
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

	dropIns, err := RenderFW4DropIns(cfg, peers, "192.168.180.0/24", now)
	if err != nil {
		t.Fatalf("RenderFW4DropIns failed: %v", err)
	}

	// Verify Layer 1 + Layer 2 raw payload filter inside table-pre
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

	// Layer 4 input_tailscale drops router management plane for ALL configured peers
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

	// Layer 4 forward_tailscale: Peer A allows ONLY 192.168.180.10:8445 before its drop, Peer B drops all,
	// Peer C (expired) has NO accept rules and drops all!
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

	// Unlisted admin IP must NEVER appear in drop rules
	if strings.Contains(inputRules+fwdRules, "100.64.200.99") {
		t.Fatalf("unlisted admin IP must never appear in ACL rules")
	}

	// Check payload_filter=false omits @th rules while keeping rate limit
	cfg.PayloadFilter = boolPtr(false)
	noFilter, err := RenderFW4DropIns(cfg, peers, "192.168.180.0/24", now)
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
	dropIns, err := RenderFW4DropIns(config.TailscaleP2PAssistConfig{Enabled: true, JITWindowSec: 5}, []ResolvedPeerACL{
		{
			Config:       config.TailscaleP2PPeerConfig{ID: "p1", Name: "r1", JITEnabled: true, AccessMode: config.TailscaleAccessOutboundOnly},
			TailscaleIPs: []string{"100.64.200.2"},
		},
	}, "192.168.180.0/24", now)
	if err != nil {
		t.Fatalf("render: %v", err)
	}

	// Case 1: Clean fw4 path -> fw4_reload, second identical call skips reload
	var calls []string
	liveHasChain := false
	mgr := &FW4Manager{
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
	if err != nil || mode != ApplyModeFW4Reload {
		t.Fatalf("expected fw4_reload, got mode=%q err=%v", mode, err)
	}
	if _, err := os.Stat(filepath.Join(baseDir, "table-pre", "singctl-ts-jit.nft")); err != nil {
		t.Fatalf("expected drop-in written: %v", err)
	}

	callsBeforeSecond := len(calls)
	mode2, err := mgr.Apply(ctx, dropIns)
	if err != nil || mode2 != ApplyModeFW4Reload {
		t.Fatalf("second Apply unexpected: mode=%q err=%v", mode2, err)
	}
	for _, c := range calls[callsBeforeSecond:] {
		if c == "fw4 reload" || strings.HasPrefix(c, "nft -f") {
			t.Fatalf("expected second identical Apply to skip reload, got call %q", c)
		}
	}

	// Case 2: fw4 check fails -> hybrid direct nft path applies atomically into table inet fw4
	var appliedScript string
	mgrDirect := &FW4Manager{
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
	if err != nil || modeDirect != ApplyModeNFTDirect {
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

	// Case 3: Both fw4 check and nft_direct fail -> drop-in files are rolled back cleanly
	rbDir := t.TempDir()
	mgrFail := &FW4Manager{
		BaseDir: rbDir,
		Runner: func(ctx context.Context, stdin string, name string, args ...string) ([]byte, error) {
			if name == "nft" && len(args) >= 2 && args[0] == "-c" {
				return nil, nil // allow dryrun syntax check
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
	var cmds []string
	mgr := &FW4Manager{
		BaseDir: t.TempDir(),
		Runner: func(ctx context.Context, stdin string, name string, args ...string) ([]byte, error) {
			cmds = append(cmds, name+" "+strings.Join(args, " "))
			if len(args) >= 2 && args[0] == "delete" && args[1] == "element" {
				return []byte("Error: Could not process rule: No such file or directory"), errors.New("exit 1")
			}
			if len(args) >= 4 && args[0] == "-j" && args[1] == "list" && args[2] == "set" {
				if args[5] == "TS_JIT_ALLOW4" {
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
	// ClosePinhole must ignore ENOENT when kernel timeout already expired the element
	if err := mgr.ClosePinhole(ctx, v4, v6); err != nil {
		t.Fatalf("ClosePinhole should ignore missing element, got: %v", err)
	}

	cnt, ips := mgr.CountOpenPinholes(ctx)
	if cnt != 1 || len(ips) != 1 || ips[0] != "198.51.100.10" {
		t.Fatalf("unexpected CountOpenPinholes: cnt=%d ips=%v", cnt, ips)
	}

	// Verify remove in nft_direct fallback cleans up tagged rules, chains, and sets
	var removeScript string
	rmDir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(rmDir, "table-pre"), 0755)
	_ = os.WriteFile(filepath.Join(rmDir, "table-pre", "singctl-ts-jit.nft"), []byte("x"), 0644)
	mgrRm := &FW4Manager{
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
