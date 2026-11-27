// 文件职责：覆盖 Tailscale P2P 防线 iptables+ip6tables+ipset 独立后端渲染、JIT 开闭孔、/etc/firewall.user 持久化、自动探测切换与并发安全测试。
package tailscale_test

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"singctl/internal/config"
	"singctl/internal/tailscale"
)

func TestRenderIPTablesP2P_3StateACLPayloadAndInjectionGuard(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	cfg := config.TailscaleP2PAssistConfig{
		Enabled:       true,
		JITWindowSec:  7,
		PayloadFilter: new(true),
		ListenPort:    41641,
	}
	peers := []tailscale.ResolvedPeerACL{
		{
			Config: config.TailscaleP2PPeerConfig{
				ID:                 "peer-bi",
				Name:               "remote-bi",
				JITEnabled:         true,
				AccessMode:         config.TailscaleAccessBidirectionalTimed,
				BidirectionalUntil: now.Add(12 * time.Hour).Format(time.RFC3339),
				AllowedLANTargets:  []string{"192.168.180.10:8445", "tcp/192.168.180.20:443", "udp/192.168.180.0/24:5353", "[2001:db8:1::10]:445"},
			},
			TailscaleIPs:  []string{"100.64.200.2", "fd7a:115c:a1e0::2"},
			PrimaryRoutes: []string{"192.168.55.0/24"},
		},
		{
			Config: config.TailscaleP2PPeerConfig{
				ID:         "peer-out",
				Name:       "remote-out",
				JITEnabled: true,
				AccessMode: config.TailscaleAccessOutboundOnly,
			},
			TailscaleIPs:  []string{"100.64.200.3"},
			PrimaryRoutes: []string{"192.168.66.0/24"},
		},
		{
			Config: config.TailscaleP2PPeerConfig{
				ID:                 "peer-expired",
				Name:               "remote-expired",
				JITEnabled:         true,
				AccessMode:         config.TailscaleAccessBidirectionalTimed,
				BidirectionalUntil: now.Add(-5 * time.Minute).Format(time.RFC3339),
				AllowedLANTargets:  []string{"192.168.180.30"},
			},
			TailscaleIPs: []string{"100.64.200.4"},
		},
	}

	rs, err := tailscale.RenderIPTablesP2P(cfg, peers, "192.168.180.0/24", now)
	if err != nil {
		t.Fatalf("RenderIPTablesP2P failed: %v", err)
	}
	if rs.ListenPort != 41641 || rs.JITWindowSec != 7 || !rs.PayloadFilter {
		t.Fatalf("unexpected ruleset metadata: %+v", rs)
	}

	joinRules := func(rules [][]string) string {
		lines := make([]string, len(rules))
		for i, r := range rules {
			lines[i] = strings.Join(r, " ")
		}
		return strings.Join(lines, "\n")
	}

	v4JIT := joinRules(rs.V4JIT)
	for _, want := range []string{
		"-m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
		"-m set --match-set TS_JIT_ALLOW4 src -m limit --limit 300/sec --limit-burst 600 -j ACCEPT",
		"-j DROP",
	} {
		if !strings.Contains(v4JIT, want) {
			t.Fatalf("V4JIT missing %q:\n%s", want, v4JIT)
		}
	}

	v6JIT := joinRules(rs.V6JIT)
	if !strings.Contains(v6JIT, "-m set --match-set TS_JIT_ALLOW6 src") {
		t.Fatalf("V6JIT missing TS_JIT_ALLOW6 match:\n%s", v6JIT)
	}

	v4In := joinRules(rs.V4InACL)
	for _, want := range []string{
		"-m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
		"-s 100.64.200.2 -j DROP",
		"-s 192.168.55.0/24 -j DROP",
		"-s 100.64.200.3 -j DROP",
		"-s 192.168.66.0/24 -j DROP",
		"-s 100.64.200.4 -j DROP",
	} {
		if !strings.Contains(v4In, want) {
			t.Fatalf("V4InACL missing %q:\n%s", want, v4In)
		}
	}

	v4Fwd := joinRules(rs.V4FwdACL)
	for _, want := range []string{
		"-s 100.64.200.2 -d 192.168.180.10 -p tcp --dport 8445 -j ACCEPT",
		"-s 100.64.200.2 -d 192.168.180.10 -p udp --dport 8445 -j ACCEPT",
		"-s 100.64.200.2 -d 192.168.180.20 -p tcp --dport 443 -j ACCEPT",
		"-s 100.64.200.2 -d 192.168.180.0/24 -p udp --dport 5353 -j ACCEPT",
		"-s 192.168.55.0/24 -d 192.168.180.10 -p tcp --dport 8445 -j ACCEPT",
		"-s 100.64.200.4 -j DROP",
	} {
		if !strings.Contains(v4Fwd, want) {
			t.Fatalf("V4FwdACL missing %q:\n%s", want, v4Fwd)
		}
	}
	if strings.Contains(v4Fwd, "192.168.180.30") {
		t.Fatalf("expired peer must not emit forward allow rule:\n%s", v4Fwd)
	}

	v6Fwd := joinRules(rs.V6FwdACL)
	if !strings.Contains(v6Fwd, "-s fd7a:115c:a1e0::2 -d 2001:db8:1::10 -p tcp --dport 445 -j ACCEPT") {
		t.Fatalf("V6FwdACL missing IPv6 allow rule:\n%s", v6Fwd)
	}

	// PayloadFilter=false should not emit final non-whitelist DROP in JIT chain.
	cfgNoDrop := cfg
	cfgNoDrop.PayloadFilter = new(false)
	rsNoDrop, err := tailscale.RenderIPTablesP2P(cfgNoDrop, peers, "192.168.180.0/24", now)
	if err != nil {
		t.Fatalf("RenderIPTablesP2P(payload_filter=false) failed: %v", err)
	}
	lastRule := strings.Join(rsNoDrop.V4JIT[len(rsNoDrop.V4JIT)-1], " ")
	if lastRule == "-j DROP" {
		t.Fatalf("payload_filter=false must not drop non-whitelist probes unconditionally, got %v", rsNoDrop.V4JIT)
	}

	// Injection guard in allowed_lan_targets must fail.
	badPeers := []tailscale.ResolvedPeerACL{{
		Config: config.TailscaleP2PPeerConfig{
			ID:                "bad",
			AccessMode:        config.TailscaleAccessBidirectional,
			AllowedLANTargets: []string{"192.168.180.1; rm -rf /"},
		},
		TailscaleIPs: []string{"100.64.200.9"},
	}}
	if _, err := tailscale.RenderIPTablesP2P(cfg, badPeers, "", now); err == nil {
		t.Fatal("expected error for command injection payload in allowed_lan_targets")
	}

	// Rendered firewall.user block must pass POSIX sh -n syntax check.
	fwUserBlock := rs.RenderFirewallUserBlock()
	if !strings.Contains(fwUserBlock, "# BEGIN SINGCTL_TS_P2P") || !strings.Contains(fwUserBlock, "# END SINGCTL_TS_P2P") {
		t.Fatalf("missing managed markers in firewall.user block:\n%s", fwUserBlock)
	}
	if !strings.Contains(fwUserBlock, "iptables -w 5 -N SINGCTL_TS_JIT") || !strings.Contains(fwUserBlock, "ip6tables -w 5 -N SINGCTL_TS_JIT") {
		t.Fatalf("firewall.user block must pass -w 5 to avoid xtables lock contention:\n%s", fwUserBlock)
	}
	if shBin, err := exec.LookPath("sh"); err == nil {
		tmp := filepath.Join(t.TempDir(), "fw_user.sh")
		if err := os.WriteFile(tmp, []byte(fwUserBlock), 0600); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.CommandContext(t.Context(), shBin, "-n", tmp).CombinedOutput(); err != nil {
			t.Fatalf("firewall.user block failed sh -n: %v (%s)", err, string(out))
		}
	}
}

func TestIPTablesP2PManager_ApplyPinholesPersistenceRemoveAndParsing(t *testing.T) {
	ctx := t.Context()
	tmpDir := t.TempDir()
	fwUserPath := filepath.Join(tmpDir, "firewall.user")
	existingUserLine := "# custom user firewall rule\niptables -I INPUT -p icmp -j ACCEPT\n"
	if err := os.WriteFile(fwUserPath, []byte(existingUserLine), 0600); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var cmds []string
	liveChains := map[string]bool{}
	setMembers := map[string]map[string]int{
		"TS_JIT_ALLOW4": {},
		"TS_JIT_ALLOW6": {},
	}

	mgr := &tailscale.IPTablesP2PManager{
		FirewallUserPath: fwUserPath,
		LookPath: func(file string) (string, error) {
			switch file {
			case "iptables", "ip6tables", "ipset":
				return "/usr/sbin/" + file, nil
			default:
				return "", &exec.Error{Name: file, Err: exec.ErrNotFound}
			}
		},
		Runner: func(_ context.Context, _ string, name string, args ...string) ([]byte, error) {
			mu.Lock()
			defer mu.Unlock()
			full := name + " " + strings.Join(args, " ")
			cmds = append(cmds, full)

			if name == "ipset" && len(args) >= 2 {
				switch args[0] {
				case "create":
					if _, ok := setMembers[args[1]]; !ok {
						setMembers[args[1]] = map[string]int{}
					}
					return nil, nil
				case "add":
					if len(args) >= 3 {
						setMembers[args[1]][args[2]] = 5
					}
					return nil, nil
				case "del":
					if len(args) >= 3 {
						delete(setMembers[args[1]], args[2])
					}
					return nil, nil
				case "list":
					var b strings.Builder
					b.WriteString("Name: " + args[1] + "\nType: hash:ip\nHeader: family inet timeout 300\nMembers:\n")
					for ip := range setMembers[args[1]] {
						b.WriteString(ip + " timeout 4\n")
					}
					return []byte(b.String()), nil
				case "destroy":
					delete(setMembers, args[1])
					return nil, nil
				}
			}
			if (name == "iptables" || name == "ip6tables") && len(args) >= 2 {
				key := name + ":" + args[1]
				switch args[0] {
				case "-N":
					if liveChains[key] {
						return []byte("iptables: Chain already exists."), errors.New("exit 1")
					}
					liveChains[key] = true
					return nil, nil
				case "-L":
					if !liveChains[key] {
						return []byte("iptables: No chain/target/match by that name."), errors.New("exit 1")
					}
					return []byte("Chain " + args[1] + " (1 references)\n"), nil
				case "-C":
					return nil, errors.New("exit 1")
				case "-S":
					if args[1] == "INPUT" && liveChains[name+":"+tailscale.IPTablesChainTSJIT] {
						return []byte("-P INPUT ACCEPT\n-A INPUT -p udp -m udp --dport 41641 -m comment --comment \"singctl-ts-jit\" -j SINGCTL_TS_JIT\n-A INPUT -i tailscale+ -m comment --comment \"singctl-ts-acl\" -j SINGCTL_TS_IN_ACL\n"), nil
					}
					if args[1] == "FORWARD" && liveChains[name+":"+tailscale.IPTablesChainTSFwdACL] {
						return []byte("-P FORWARD ACCEPT\n-A FORWARD -i tailscale+ -m comment --comment \"singctl-ts-acl\" -j SINGCTL_TS_FWD_ACL\n"), nil
					}
					return []byte("-P " + args[1] + " ACCEPT\n"), nil
				case "-X":
					delete(liveChains, key)
					return nil, nil
				}
			}
			return nil, nil
		},
	}

	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	rs, err := tailscale.RenderIPTablesP2P(config.TailscaleP2PAssistConfig{Enabled: true, JITWindowSec: 5}, []tailscale.ResolvedPeerACL{
		{
			Config:       config.TailscaleP2PPeerConfig{ID: "p1", Name: "r1", JITEnabled: true, AccessMode: config.TailscaleAccessOutboundOnly},
			TailscaleIPs: []string{"100.64.200.2"},
		},
	}, "192.168.180.0/24", now)
	if err != nil {
		t.Fatal(err)
	}

	mode, err := mgr.Apply(ctx, rs)
	if err != nil || mode != tailscale.ApplyModeIPTablesIPSet {
		t.Fatalf("Apply failed: mode=%q err=%v", mode, err)
	}

	joinedCmds := strings.Join(cmds, "\n")
	for _, want := range []string{
		"ipset create TS_JIT_ALLOW4 hash:ip family inet timeout 300 -exist",
		"ipset create TS_JIT_ALLOW6 hash:ip family inet6 timeout 300 -exist",
		"iptables -N SINGCTL_TS_JIT",
		"iptables -N SINGCTL_TS_IN_ACL",
		"iptables -N SINGCTL_TS_FWD_ACL",
		"ip6tables -N SINGCTL_TS_JIT",
	} {
		if !strings.Contains(joinedCmds, want) {
			t.Fatalf("expected command %q in:\n%s", want, joinedCmds)
		}
	}

	// Verify /etc/firewall.user managed block written while preserving existing lines.
	fwData, err := os.ReadFile(fwUserPath)
	if err != nil {
		t.Fatal(err)
	}
	fwStr := string(fwData)
	if !strings.Contains(fwStr, "# custom user firewall rule") ||
		!strings.Contains(fwStr, "# BEGIN SINGCTL_TS_P2P") ||
		!strings.Contains(fwStr, "# END SINGCTL_TS_P2P") {
		t.Fatalf("unexpected firewall.user contents:\n%s", fwStr)
	}

	// Idempotent second Apply should not duplicate managed block or re-flush unnecessarily.
	beforeSecond := len(cmds)
	if mode2, err := mgr.Apply(ctx, rs); err != nil || mode2 != tailscale.ApplyModeIPTablesIPSet {
		t.Fatalf("second Apply failed: mode=%q err=%v", mode2, err)
	}
	fwData2, _ := os.ReadFile(fwUserPath)
	if strings.Count(string(fwData2), "# BEGIN SINGCTL_TS_P2P") != 1 {
		t.Fatalf("duplicate managed block in firewall.user:\n%s", string(fwData2))
	}
	for _, c := range cmds[beforeSecond:] {
		if strings.Contains(c, "-F SINGCTL_TS_JIT") {
			t.Fatalf("idempotent second Apply should skip re-flushing live chain, got %q", c)
		}
	}

	// Pinhole open / list / close lifecycle
	v4 := []netip.Addr{netip.MustParseAddr("198.51.100.10")}
	v6 := []netip.Addr{netip.MustParseAddr("2001:db8::10")}
	if err := mgr.AddPinhole(ctx, v4, v6, 5); err != nil {
		t.Fatalf("AddPinhole failed: %v", err)
	}
	cnt, ips := mgr.ListActivePinholes(ctx)
	if cnt != 2 || !slices.Equal(ips, []string{"198.51.100.10", "2001:db8::10"}) {
		t.Fatalf("unexpected ListActivePinholes: cnt=%d ips=%v", cnt, ips)
	}
	if err := mgr.RemovePinhole(ctx, v4, v6); err != nil {
		t.Fatalf("RemovePinhole failed: %v", err)
	}
	cntAfter, _ := mgr.ListActivePinholes(ctx)
	if cntAfter != 0 {
		t.Fatalf("expected 0 active pinholes after RemovePinhole, got %d", cntAfter)
	}

	// Clean Remove strips managed block, deletes chains & ipsets, preserves user lines.
	if err := mgr.Remove(ctx); err != nil {
		t.Fatalf("Remove failed: %v", err)
	}
	fwAfterRm, _ := os.ReadFile(fwUserPath)
	if strings.Contains(string(fwAfterRm), "# BEGIN SINGCTL_TS_P2P") || !strings.Contains(string(fwAfterRm), "# custom user firewall rule") {
		t.Fatalf("Remove corrupted firewall.user:\n%s", string(fwAfterRm))
	}
	if !strings.Contains(strings.Join(cmds, "\n"), "ipset destroy TS_JIT_ALLOW4") {
		t.Fatalf("expected Remove to destroy TS_JIT_ALLOW4")
	}

	// Pure ipset parser edge cases
	parsed := tailscale.ParseIPSetMembers("Name: TS_JIT_ALLOW4\nType: hash:ip\nMembers:\n198.51.100.20 timeout 4\nnot-an-ip\n203.0.113.5\n")
	if !slices.Equal(parsed, []string{"198.51.100.20", "203.0.113.5"}) {
		t.Fatalf("unexpected ParseIPSetMembers result: %v", parsed)
	}
}

func TestP2PAssistController_AutoFallbackToIPTablesIPSet_NoNFTWarn(t *testing.T) {
	ctx := t.Context()
	clk := newFakeClock()
	tmpDir := t.TempDir()

	var mu sync.Mutex
	var openIPSetCmds []string
	var closeIPSetCmds []string
	var directNow bool

	lookPath := func(file string) (string, error) {
		switch file {
		case "iptables", "ip6tables", "ipset":
			return "/usr/sbin/" + file, nil
		default:
			return "", &exec.Error{Name: file, Err: exec.ErrNotFound}
		}
	}

	fw4 := &tailscale.FW4Manager{
		BaseDir:          tmpDir,
		FirewallUserPath: filepath.Join(tmpDir, "firewall.user"),
		LookPath:         lookPath,
		Runner: func(_ context.Context, _ string, name string, args ...string) ([]byte, error) {
			mu.Lock()
			defer mu.Unlock()
			if name == "nft" || name == "fw4" {
				return nil, &exec.Error{Name: name, Err: exec.ErrNotFound}
			}
			if name == "ipset" && len(args) >= 2 {
				if args[0] == "add" {
					openIPSetCmds = append(openIPSetCmds, strings.Join(args, " "))
					directNow = true
				}
				if args[0] == "del" {
					closeIPSetCmds = append(closeIPSetCmds, strings.Join(args, " "))
				}
				if args[0] == "list" {
					return []byte("Name: " + args[1] + "\nMembers:\n"), nil
				}
			}
			if (name == "iptables" || name == "ip6tables") && len(args) >= 1 && args[0] == "-C" {
				return nil, errors.New("not present")
			}
			if (name == "iptables" || name == "ip6tables") && len(args) >= 1 && args[0] == "-S" {
				return []byte("-P " + args[1] + " ACCEPT\n"), nil
			}
			return nil, nil
		},
	}

	api := &fakeLocalAPI{
		statusFn: func(_ int) (*tailscale.StatusSnapshot, error) {
			mu.Lock()
			cur := ""
			relay := "sfo"
			if directNow {
				cur = "198.51.100.10:41641"
				relay = ""
			}
			mu.Unlock()
			return &tailscale.StatusSnapshot{
				BackendState: "Running",
				Self:         tailscale.PeerStatus{ID: "nSelf", ShortName: "n60pro"},
				Peers: []tailscale.PeerStatus{
					{ID: "p1", ShortName: "peer-a", TailscaleIPs: []string{"100.64.200.2"}, Online: true, Active: true, CurAddr: cur, Relay: relay},
				},
			}, nil
		},
		netMap: &tailscale.NetMapSnapshot{
			SelfEndpoints: []string{"203.0.113.1:41641"},
			PeerEndpoints: map[string][]string{"p1": {"198.51.100.10:41641"}},
		},
	}

	ctrl := &tailscale.P2PAssistController{
		LocalAPI:        api,
		FW4:             fw4,
		LookPath:        lookPath,
		Now:             clk.Now,
		Sleep:           clk.Sleep,
		MinAutoJITBytes: -1,
		DefaultLANCIDR:  func() string { return "192.168.180.0/24" },
		HostSelfIPs:     func() []netip.Addr { return []netip.Addr{netip.MustParseAddr("203.0.113.1")} },
	}
	cfg := config.TailscaleP2PAssistConfig{
		Enabled:      true,
		JITWindowSec: 5,
		Peers: []config.TailscaleP2PPeerConfig{
			{ID: "p1", Name: "peer-a", JITEnabled: true, AccessMode: config.TailscaleAccessOutboundOnly},
		},
	}

	snap, err := ctrl.Reconcile(ctx, cfg)
	ctrl.WaitBackground()
	if err != nil {
		t.Fatalf("expected zero error when falling back to iptables_ipset, got: %v", err)
	}
	if snap.ApplyMode != tailscale.ApplyModeIPTablesIPSet || snap.LastError != "" {
		t.Fatalf("expected applyMode=%q and empty LastError, got %+v", tailscale.ApplyModeIPTablesIPSet, snap)
	}

	mu.Lock()
	opens := len(openIPSetCmds)
	closes := len(closeIPSetCmds)
	mu.Unlock()
	if opens != 1 || closes != 1 {
		t.Fatalf("expected 1 ipset add and 1 ipset del during JIT upgrade, got opens=%d closes=%d", opens, closes)
	}

	// Disable should cleanly tear down iptables chains & ipset without error.
	cfg.Enabled = false
	snapOff, err := ctrl.Reconcile(ctx, cfg)
	if err != nil || snapOff.Enabled {
		t.Fatalf("expected clean disable on iptables backend, got snap=%+v err=%v", snapOff, err)
	}
}

func TestRenderIPTablesP2P_MultiSubnetAndBidirectionalRouterInput(t *testing.T) {
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
	}

	rs, err := tailscale.RenderIPTablesP2P(cfg, peers, "192.168.31.0/24,192.168.27.0/24", now)
	if err != nil {
		t.Fatalf("RenderIPTablesP2P failed: %v", err)
	}
	joinLines := func(rules [][]string) string {
		lines := make([]string, len(rules))
		for i, r := range rules {
			lines[i] = strings.Join(r, " ")
		}
		return strings.Join(lines, "\n")
	}

	v4Fwd := joinLines(rs.V4FwdACL)
	for _, want := range []string{
		"-s 192.168.55.0/24 -d 192.168.31.0/24 -j ACCEPT",
		"-s 192.168.55.0/24 -d 192.168.27.0/24 -j ACCEPT",
	} {
		if !strings.Contains(v4Fwd, want) {
			t.Fatalf("V4FwdACL missing %q:\n%s", want, v4Fwd)
		}
	}

	v4In := joinLines(rs.V4InACL)
	for _, want := range []string{
		"-s 192.168.55.0/24 -d 192.168.31.0/24 -j ACCEPT",
		"-s 192.168.55.0/24 -d 100.64.0.0/10 -j ACCEPT",
		"-s 192.168.55.0/24 -j DROP",
	} {
		if !strings.Contains(v4In, want) {
			t.Fatalf("V4InACL missing %q:\n%s", want, v4In)
		}
	}
	if strings.Index(v4In, "-s 192.168.55.0/24 -d 192.168.31.0/24 -j ACCEPT") >= strings.Index(v4In, "-s 192.168.55.0/24 -j DROP") {
		t.Fatalf("ACCEPT rule must precede DROP rule in V4InACL:\n%s", v4In)
	}
}

func TestRenderIPTablesP2P_LocalDeviceScopesAndEgressACL(t *testing.T) {
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
	joinLines := func(rules [][]string) string {
		lines := make([]string, len(rules))
		for i, r := range rules {
			lines[i] = strings.Join(r, " ")
		}
		return strings.Join(lines, "\n")
	}

	// 1. Allowlist mode
	rsAllow, err := tailscale.RenderIPTablesP2P(config.TailscaleP2PAssistConfig{
		Enabled:       true,
		RoleMode:      "router",
		PayloadFilter: boolPtr(true),
		LocalRules: []config.TailscaleLocalSubnetRule{
			{CIDR: "192.168.31.0/24", Scope: config.TailscaleScopeAllowlist, Devices: []string{"192.168.31.88"}},
		},
	}, peers, "192.168.31.0/24", now)
	if err != nil {
		t.Fatalf("allowlist RenderIPTablesP2P failed: %v", err)
	}
	v4OutAllow := joinLines(rsAllow.V4OutACL)
	if !strings.Contains(v4OutAllow, "-s 192.168.31.88 -j ACCEPT") || strings.Contains(v4OutAllow, "-s 192.168.31.0/24 -j ACCEPT") {
		t.Fatalf("unexpected V4OutACL for allowlist:\n%s", v4OutAllow)
	}
	if !strings.Contains(v4OutAllow, "--ctdir REPLY -j ACCEPT") || !strings.Contains(v4OutAllow, "-j DROP") {
		t.Fatalf("V4OutACL missing conntrack reply or final drop:\n%s", v4OutAllow)
	}
	v4FwdAllow := joinLines(rsAllow.V4FwdACL)
	if !strings.Contains(v4FwdAllow, "-s 192.168.55.0/24 -d 192.168.31.88 -j ACCEPT") || strings.Contains(v4FwdAllow, "-s 192.168.55.0/24 -d 192.168.31.0/24 -j ACCEPT") {
		t.Fatalf("expected bidirectional peer forward limited to allowlisted host:\n%s", v4FwdAllow)
	}
	if !strings.Contains(v4FwdAllow, "-d 192.168.31.88 -j RETURN") || !strings.Contains(v4FwdAllow, "-d 192.168.31.0/24 -j DROP") {
		t.Fatalf("expected personal-device allowlist tail in V4FwdACL:\n%s", v4FwdAllow)
	}

	// 2. Denylist mode
	rsDeny, err := tailscale.RenderIPTablesP2P(config.TailscaleP2PAssistConfig{
		Enabled:       true,
		RoleMode:      "router",
		PayloadFilter: boolPtr(true),
		LocalRules: []config.TailscaleLocalSubnetRule{
			{CIDR: "192.168.31.0/24", Scope: config.TailscaleScopeDenylist, Devices: []string{"192.168.31.151"}},
		},
	}, peers, "192.168.31.0/24", now)
	if err != nil {
		t.Fatalf("denylist RenderIPTablesP2P failed: %v", err)
	}
	v4OutDeny := joinLines(rsDeny.V4OutACL)
	if strings.Index(v4OutDeny, "-s 192.168.31.151 -j DROP") >= strings.Index(v4OutDeny, "-s 192.168.31.0/24 -j ACCEPT") {
		t.Fatalf("denylist drop must precede subnet accept in V4OutACL:\n%s", v4OutDeny)
	}
	v4FwdDeny := joinLines(rsDeny.V4FwdACL)
	if !strings.Contains(v4FwdDeny, "-d 192.168.31.151 -j DROP") {
		t.Fatalf("denylist must block ingress to excluded IP in V4FwdACL:\n%s", v4FwdDeny)
	}
}
