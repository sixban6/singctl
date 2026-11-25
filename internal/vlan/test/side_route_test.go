// 文件职责：测试 VLAN 子网「交由旁路由分流 (side_router)」的校验、DHCP/DNS 联动、防火墙安全隔离顺序、策略路由生成、故障摘除与并发安全。
package vlan_test

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"singctl/internal/vlan"
)

func TestVLAN_SideRouterModePreviewApplyAndDelete(t *testing.T) {
	tmpDir := t.TempDir()
	bypassFile := filepath.Join(tmpDir, "vlan-proxy-bypass.list")
	dnsBypassFile := filepath.Join(tmpDir, "vlan-dns-bypass.list")
	sideRoutesFile := filepath.Join(tmpDir, "vlan-side-routes.list")

	var syncedSide vlan.VLANSideRouteSpec
	var syncedBypass []string
	var syncedDNS []vlan.VLANDNSBypassRule

	env := vlan.Env{
		SideRouterIP:    "192.168.55.88",
		ProxyBypassFile: bypassFile,
		DNSBypassFile:   dnsBypassFile,
		SideRoutesFile:  sideRoutesFile,
		IsOpenWrt:       func() bool { return true },
		RunUCI: func(_ context.Context, args ...string) (string, error) {
			if len(args) == 2 && args[0] == "show" {
				switch args[1] {
				case "network":
					return strings.ReplaceAll(sampleAX3000TNetworkUCI, "192.168.50.1", "192.168.55.1"), nil
				case "wireless":
					return sampleAX3000TWirelessUCI, nil
				case "dhcp":
					return "dhcp.lan=dhcp\ndhcp.lan.interface='lan'\ndhcp.lan.ignore='1'\ndhcp.baidu_lan=dhcp\ndhcp.baidu_lan.interface='baidu_lan'\n", nil
				case "firewall":
					return "firewall.@zone[0]=zone\nfirewall.@zone[0].name='lan'\nfirewall.@zone[0].network='lan'\n", nil
				}
			}
			return "", nil
		},
		BatchUCI:      func(context.Context, []string) error { return nil },
		ReloadNetwork: func(context.Context) error { return nil },
		SyncProxyBypass: func(_ context.Context, cidrs []string) error {
			syncedBypass = slices.Clone(cidrs)
			return vlan.WriteProxyBypassList(bypassFile, cidrs)
		},
		SyncDNSBypass: func(_ context.Context, rules []vlan.VLANDNSBypassRule) error {
			syncedDNS = slices.Clone(rules)
			return vlan.WriteDNSBypassRules(dnsBypassFile, rules)
		},
		SyncSideRoutes: func(_ context.Context, spec vlan.VLANSideRouteSpec) error {
			syncedSide = spec
			return vlan.WriteSideRouteSpec(sideRoutesFile, spec)
		},
		ReadFile: func(string) ([]byte, error) { return nil, os.ErrNotExist },
		ListNetDevs: func() ([]string, error) {
			return []string{"lo", "eth0", "eth0.1", "eth0.2", "eth0.3", "eth0.8", "br-lan", "iot-br", "br-v8"}, nil
		},
		ReadIPv4Addrs: func() (map[string]string, error) {
			return map[string]string{
				"eth0.2": "192.168.3.181/24",
				"br-lan": "192.168.55.1/24",
				"iot-br": "192.168.34.1/24",
				"br-v8":  "192.168.89.1/24",
			}, nil
		},
	}

	svc := vlan.NewService(env)

	// 1. Validation rejects side_router when SideRouterIP is missing or AllowWAN is false or SideRouterIP collides with segment subnet.
	envNoSide := env
	envNoSide.SideRouterIP = ""
	noSidePrev, err := vlan.NewService(envNoSide).PreviewSave(t.Context(), "192.168.55.10", vlan.SaveSegmentRequest{
		ID:        "baidu_lan",
		VLANID:    8,
		IPAddr:    "192.168.89.1",
		ProxyMode: vlan.ProxyModeSideRouter,
		Policy:    vlan.SecurityPolicy{AllowWAN: true},
	})
	if err != nil || noSidePrev.Valid {
		t.Fatalf("expected invalid preview when SideRouterIP missing, got valid=%v err=%v", noSidePrev.Valid, err)
	}

	noWANPrev, err := svc.PreviewSave(t.Context(), "192.168.55.10", vlan.SaveSegmentRequest{
		ID:        "baidu_lan",
		VLANID:    8,
		IPAddr:    "192.168.89.1",
		ProxyMode: vlan.ProxyModeSideRouter,
		Policy:    vlan.SecurityPolicy{AllowWAN: false},
	})
	if err != nil || noWANPrev.Valid {
		t.Fatalf("expected invalid preview when AllowWAN=false with ProxyModeSideRouter, got valid=%v err=%v", noWANPrev.Valid, err)
	}

	// 2. Valid save of baidu_lan in side_router mode (leaving DHCPDNS empty auto-populates 192.168.55.88).
	saveReq := vlan.SaveSegmentRequest{
		ID:          "baidu_lan",
		DisplayName: "办公分流网",
		VLANID:      8,
		IPAddr:      "192.168.89.1",
		Netmask:     "255.255.255.0",
		DHCPStart:   100,
		DHCPLimit:   150,
		LeaseTime:   "12h",
		ProxyMode:   vlan.ProxyModeSideRouter,
		Policy: vlan.SecurityPolicy{
			AllowWAN:         true,
			BlockRouterMgmt:  true,
			BlockUpstreamLAN: true,
		},
	}

	prev, err := svc.PreviewSave(t.Context(), "192.168.55.10", saveReq)
	if err != nil || !prev.Valid {
		t.Fatalf("expected valid PreviewSave for side_router, got err=%v errors=%v", err, prev.Errors)
	}

	// Verify DHCP Option 6 auto-populated with 192.168.55.88 + ra_dns='0'.
	if !slices.Contains(prev.UCICommands, "add_list dhcp.baidu_lan.dhcp_option='6,192.168.55.88'") {
		t.Fatalf("expected auto DHCP Option 6=192.168.55.88, got %v", prev.UCICommands)
	}

	// Verify firewall order: singctl_allow_dns_baidu_lan_0 BEFORE singctl_side_iso_baidu_lan BEFORE singctl_side_fwd_baidu_lan!
	idxDNS := slices.Index(prev.UCICommands, "set firewall.singctl_allow_dns_baidu_lan_0=rule")
	idxIso := slices.Index(prev.UCICommands, "set firewall.singctl_side_iso_baidu_lan=rule")
	idxFwd := slices.Index(prev.UCICommands, "set firewall.singctl_side_fwd_baidu_lan=rule")
	if idxDNS < 0 || idxIso < 0 || idxFwd < 0 || !(idxDNS < idxIso && idxIso < idxFwd) {
		t.Fatalf("invalid firewall rule order (dns=%d iso=%d fwd=%d): %v", idxDNS, idxIso, idxFwd, prev.UCICommands)
	}
	if !slices.Contains(prev.UCICommands, "set firewall.singctl_side_iso_baidu_lan.dest='lan'") ||
		!slices.Contains(prev.UCICommands, "set firewall.singctl_side_iso_baidu_lan.target='REJECT'") ||
		!slices.Contains(prev.UCICommands, "set firewall.singctl_side_fwd_baidu_lan.dest='lan'") ||
		!slices.Contains(prev.UCICommands, "set firewall.singctl_side_fwd_baidu_lan.target='ACCEPT'") {
		t.Fatalf("missing expected side router firewall isolation/forward attributes: %v", prev.UCICommands)
	}

	res, err := svc.ApplySave(t.Context(), "192.168.55.10", saveReq)
	if err != nil || !res.OK {
		t.Fatalf("ApplySave failed: err=%v res=%+v", err, res)
	}
	if syncedSide.SideRouterIP != "192.168.55.88" || !slices.Equal(syncedSide.CIDRs, []string{"192.168.89.0/24"}) {
		t.Fatalf("unexpected synced side routes: %+v", syncedSide)
	}
	if !slices.Contains(syncedBypass, "192.168.89.0/24") {
		t.Fatalf("side_router segment must bypass local sing-box TProxy, got bypass=%v", syncedBypass)
	}
	if len(syncedDNS) == 0 || syncedDNS[0].CIDR != "192.168.89.0/24" || !slices.Equal(syncedDNS[0].DNSIPs, []string{"192.168.55.88"}) {
		t.Fatalf("unexpected synced DNS bypass: %+v", syncedDNS)
	}

	st, statErr := os.Stat(sideRoutesFile)
	if statErr != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 permissions on side routes file, err=%v mode=%v", statErr, st.Mode().Perm())
	}

	// Overview should now reflect baidu_lan ProxyMode == side_router & Overview.SideRouterIP == 192.168.55.88.
	ov, err := svc.Overview(t.Context(), "192.168.55.10")
	if err != nil {
		t.Fatalf("Overview failed: %v", err)
	}
	if ov.SideRouterIP != "192.168.55.88" {
		t.Fatalf("expected ov.SideRouterIP=192.168.55.88, got %q", ov.SideRouterIP)
	}
	var baiduSeg vlan.Segment
	for _, s := range ov.Segments {
		if s.ID == "baidu_lan" {
			baiduSeg = s
		}
	}
	if baiduSeg.ProxyMode != vlan.ProxyModeSideRouter {
		t.Fatalf("expected baidu_lan ProxyMode=side_router, got %q", baiduSeg.ProxyMode)
	}
	hasBadge := false
	for _, b := range baiduSeg.Relations {
		if strings.Contains(b.Text, "旁路由分流") {
			hasBadge = true
		}
	}
	if !hasBadge {
		t.Fatalf("expected side router relation badge on baidu_lan, got %+v", baiduSeg.Relations)
	}

	// 3. Delete segment cleans side routes spec too.
	if _, err := svc.ApplyDelete(t.Context(), "192.168.55.10", "baidu_lan"); err != nil {
		t.Fatalf("ApplyDelete failed: %v", err)
	}
	if len(syncedSide.CIDRs) != 0 {
		t.Fatalf("expected empty side routes after segment deletion, got %+v", syncedSide)
	}
}

func TestVLAN_ApplyAndSuspendRuntimeSideRoutes(t *testing.T) {
	var cmds []string
	var mu sync.Mutex
	runner := func(_ context.Context, name string, args ...string) ([]byte, error) {
		line := name + " " + strings.Join(args, " ")
		mu.Lock()
		cmds = append(cmds, line)
		mu.Unlock()
		if line == "ip -4 rule show" {
			return []byte("0:\tfrom all lookup local\n18810:\tfrom 192.168.89.0/24 lookup 188\n32766:\tfrom all lookup main\n"), nil
		}
		return nil, nil
	}

	spec := vlan.VLANSideRouteSpec{
		SideRouterIP: "192.168.55.88",
		CIDRs:        []string{"192.168.89.0/24", "192.168.34.0/24"},
	}
	if err := vlan.ApplyRuntimeSideRoutes(t.Context(), spec, runner); err != nil {
		t.Fatalf("ApplyRuntimeSideRoutes failed: %v", err)
	}

	joined := strings.Join(cmds, "\n")
	for _, want := range []string{
		"ip -4 rule del pref 18810",
		"ip -4 route flush table 188",
		"ip -4 route replace throw 10.0.0.0/8 table 188",
		"ip -4 route replace throw 172.16.0.0/12 table 188",
		"ip -4 route replace throw 192.168.0.0/16 table 188",
		"ip -4 route replace throw 100.64.0.0/10 table 188",
		"ip -4 route replace default via 192.168.55.88 table 188",
		"ip -4 rule add from 192.168.34.0/24 lookup 188 pref 18810",
		"ip -4 rule add from 192.168.89.0/24 lookup 188 pref 18811",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing expected runtime PBR command %q in:\n%s", want, joined)
		}
	}

	cmds = nil
	if err := vlan.SuspendRuntimeSideRoutes(t.Context(), runner); err != nil {
		t.Fatalf("SuspendRuntimeSideRoutes failed: %v", err)
	}
	joinedSuspend := strings.Join(cmds, "\n")
	if !strings.Contains(joinedSuspend, "ip -4 rule del pref 18810") || strings.Contains(joinedSuspend, "default via") {
		t.Fatalf("SuspendRuntimeSideRoutes should only delete active ip rules, got:\n%s", joinedSuspend)
	}

	// Reject malformed / injection inputs.
	if _, err := vlan.NormalizeSideRouteSpec(vlan.VLANSideRouteSpec{
		SideRouterIP: "192.168.55.88;rm -rf /",
		CIDRs:        []string{"192.168.89.0/24"},
	}); err == nil {
		t.Fatal("expected NormalizeSideRouteSpec to reject command injection in SideRouterIP")
	}
	if _, err := vlan.NormalizeSideRouteSpec(vlan.VLANSideRouteSpec{
		SideRouterIP: "192.168.55.88",
		CIDRs:        []string{"127.0.0.0/8"},
	}); err == nil {
		t.Fatal("expected NormalizeSideRouteSpec to reject loopback CIDR")
	}

	// Concurrent 0600 file writes & reads (-race).
	file := filepath.Join(t.TempDir(), "vlan-side-routes.list")
	var wg sync.WaitGroup
	for range 6 {
		wg.Go(func() {
			if err := vlan.WriteSideRouteSpec(file, spec); err != nil {
				t.Errorf("concurrent write failed: %v", err)
				return
			}
			got := vlan.ReadSideRouteSpec(file)
			if got.SideRouterIP != "192.168.55.88" {
				t.Errorf("unexpected concurrent read: %+v", got)
			}
		})
	}
	wg.Wait()
}

func TestVLAN_SyncFW4SideNoMasqInclude(t *testing.T) {
	// 1. Non-existent fw4Root (e.g. OpenWrt 21 fw3 host) is a safe no-op and does not create directories.
	missingRoot := filepath.Join(t.TempDir(), "missing-nftables.d")
	if err := vlan.SyncFW4SideNoMasqInclude(missingRoot, []string{"192.168.89.0/24"}); err != nil {
		t.Fatalf("expected nil when fw4Root does not exist, got %v", err)
	}
	if _, err := os.Stat(missingRoot); !os.IsNotExist(err) {
		t.Fatalf("expected missingRoot not to be created, stat err=%v", err)
	}

	// 2. Existing fw4Root writes normalized sorted CIDRs with 0600 file / 0700 parent permissions.
	fw4Root := filepath.Join(t.TempDir(), "nftables.d")
	if err := os.MkdirAll(fw4Root, 0755); err != nil {
		t.Fatalf("mkdir fw4Root: %v", err)
	}
	targetFile := filepath.Join(fw4Root, "chain-pre", "srcnat_lan", "singctl-side-nomasq.nft")
	if err := vlan.SyncFW4SideNoMasqInclude(fw4Root, []string{"192.168.89.0/24", "192.168.34.0/24", "192.168.89.0/24"}); err != nil {
		t.Fatalf("SyncFW4SideNoMasqInclude apply failed: %v", err)
	}
	raw, err := os.ReadFile(targetFile)
	if err != nil {
		t.Fatalf("read generated nft include failed: %v", err)
	}
	wantLine := `ip saddr { 192.168.34.0/24, 192.168.89.0/24 } accept comment "singctl-side-nomasq"`
	if !strings.Contains(string(raw), wantLine) {
		t.Fatalf("unexpected nft include content:\n%s\nwant substring: %s", string(raw), wantLine)
	}
	fi, err := os.Stat(targetFile)
	if err != nil || fi.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 perm on %s, err=%v mode=%v", targetFile, err, fi.Mode().Perm())
	}
	dirInfo, err := os.Stat(filepath.Dir(targetFile))
	if err != nil || dirInfo.Mode().Perm() != 0700 {
		t.Fatalf("expected 0700 perm on parent dir, err=%v mode=%v", err, dirInfo.Mode().Perm())
	}

	// 3. Malformed / injection CIDR errors out and leaves valid file intact.
	if err := vlan.SyncFW4SideNoMasqInclude(fw4Root, []string{"192.168.89.0/24; rm -rf /"}); err == nil {
		t.Fatal("expected SyncFW4SideNoMasqInclude to reject injection CIDR")
	}
	rawAfterErr, err := os.ReadFile(targetFile)
	if err != nil || !strings.Contains(string(rawAfterErr), wantLine) {
		t.Fatalf("expected valid file preserved on validation error, got err=%v content=%s", err, string(rawAfterErr))
	}

	// 4. Empty/nil CIDRs removes include file idempotently.
	if err := vlan.SyncFW4SideNoMasqInclude(fw4Root, nil); err != nil {
		t.Fatalf("SyncFW4SideNoMasqInclude(nil) cleanup failed: %v", err)
	}
	if _, err := os.Stat(targetFile); !os.IsNotExist(err) {
		t.Fatalf("expected include file removed on nil CIDRs, stat err=%v", err)
	}
	if err := vlan.SyncFW4SideNoMasqInclude(fw4Root, []string{}); err != nil {
		t.Fatalf("idempotent empty SyncFW4SideNoMasqInclude failed: %v", err)
	}
}

func TestVLAN_SideRouteLANNoMasqRules(t *testing.T) {
	tests := []struct {
		name           string
		nftListOutput  string
		nftListErr     bool
		nftFwdOutput   string
		nftFwdErr      bool
		iptListOutput  string
		iptListErr     bool
		spec           vlan.VLANSideRouteSpec
		wantApplyCmds  []string
		wantSuspCmds   []string
		forbidApplySub []string
	}{
		{
			name:          "fw3 iptables postrouting_lan_rule",
			nftListErr:    true,
			nftFwdErr:     true,
			iptListOutput: "-N postrouting_lan_rule\n-A postrouting_lan_rule -s 192.168.99.0/24 -m comment --comment \"singctl-side-nomasq\" -j ACCEPT\n-A postrouting_lan_rule -s 192.168.10.0/24 -j ACCEPT\n",
			spec: vlan.VLANSideRouteSpec{
				SideRouterIP: "192.168.55.88",
				CIDRs:        []string{"192.168.89.0/24", "192.168.34.0/24"},
			},
			wantApplyCmds: []string{
				"iptables -t nat -D postrouting_lan_rule -s 192.168.99.0/24 -m comment --comment singctl-side-nomasq -j ACCEPT",
				"iptables -t nat -I postrouting_lan_rule 1 -s 192.168.34.0/24 -m comment --comment singctl-side-nomasq -j ACCEPT",
				"iptables -t nat -I postrouting_lan_rule 1 -s 192.168.89.0/24 -m comment --comment singctl-side-nomasq -j ACCEPT",
			},
			forbidApplySub: []string{
				"-D postrouting_lan_rule -s 192.168.10.0/24",
			},
			wantSuspCmds: []string{
				"iptables -t nat -D postrouting_lan_rule -s 192.168.99.0/24 -m comment --comment singctl-side-nomasq -j ACCEPT",
			},
		},
		{
			name: "fw4 nftables srcnat_lan",
			nftListOutput: "table inet fw4 {\n\tchain srcnat_lan {\n\t\tip saddr 192.168.99.0/24 accept comment \"singctl-side-nomasq\" # handle 42\n\t\tip saddr 192.168.10.0/24 masquerade # handle 99\n\t}\n}\n",
			nftFwdErr: true,
			iptListErr: true,
			spec: vlan.VLANSideRouteSpec{
				SideRouterIP: "192.168.55.88",
				CIDRs:        []string{"192.168.89.0/24"},
			},
			wantApplyCmds: []string{
				"nft delete rule inet fw4 srcnat_lan handle 42",
				"nft insert rule inet fw4 srcnat_lan ip saddr 192.168.89.0/24 accept comment singctl-side-nomasq",
			},
			forbidApplySub: []string{
				"handle 99",
			},
			wantSuspCmds: []string{
				"nft delete rule inet fw4 srcnat_lan handle 42",
			},
		},
		{
			name:          "fw4 nftables forward flow offload bypass",
			nftListOutput: "table inet fw4 {\n\tchain srcnat_lan {\n\t\tip saddr 192.168.10.0/24 masquerade # handle 99\n\t}\n}\n",
			nftFwdOutput: "table inet fw4 {\n\tchain forward {\n\t\tct state established,related accept comment \"singctl-side-nomasq\" # handle 77\n\t\tmeta l4proto { tcp, udp } flow add @ft # handle 88\n\t\tjump forward_lan\n\t}\n}\n",
			iptListErr: true,
			spec: vlan.VLANSideRouteSpec{
				SideRouterIP: "192.168.55.88",
				CIDRs:        []string{"192.168.89.0/24"},
			},
			wantApplyCmds: []string{
				"nft delete rule inet fw4 forward handle 77",
				"nft insert rule inet fw4 forward ip daddr 192.168.89.0/24 ct state established,related accept comment singctl-side-nomasq",
				"nft insert rule inet fw4 forward ip saddr 192.168.89.0/24 ct state established,related accept comment singctl-side-nomasq",
			},
			forbidApplySub: []string{
				"handle 88",
			},
			wantSuspCmds: []string{
				"nft delete rule inet fw4 forward handle 77",
			},
		},
		{
			name:          "fw4 nftables forward without flow offload",
			nftListOutput: "table inet fw4 {\n\tchain srcnat_lan {\n\t\tip saddr 192.168.10.0/24 masquerade # handle 99\n\t}\n}\n",
			nftFwdOutput: "table inet fw4 {\n\tchain forward {\n\t\tip daddr 192.168.99.0/24 ct state established,related accept comment \"singctl-side-nomasq\" # handle 75\n\t\tct state established,related accept # handle 55\n\t\tjump forward_lan\n\t}\n}\n",
			iptListErr: true,
			spec: vlan.VLANSideRouteSpec{
				SideRouterIP: "192.168.55.88",
				CIDRs:        []string{"192.168.89.0/24"},
			},
			wantApplyCmds: []string{
				"nft delete rule inet fw4 forward handle 75",
			},
			forbidApplySub: []string{
				"nft insert rule inet fw4 forward",
				"handle 55",
			},
			wantSuspCmds: []string{
				"nft delete rule inet fw4 forward handle 75",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var cmds []string
			var mu sync.Mutex
			runner := func(_ context.Context, name string, args ...string) ([]byte, error) {
				line := name + " " + strings.Join(args, " ")
				mu.Lock()
				cmds = append(cmds, line)
				mu.Unlock()
				switch line {
				case "ip -4 rule show":
					return []byte("18810:\tfrom 192.168.89.0/24 lookup 188\n"), nil
				case "nft -a list chain inet fw4 srcnat_lan":
					if tc.nftListErr {
						return nil, context.DeadlineExceeded
					}
					return []byte(tc.nftListOutput), nil
				case "nft -a list chain inet fw4 forward":
					if tc.nftFwdErr {
						return nil, context.DeadlineExceeded
					}
					return []byte(tc.nftFwdOutput), nil
				case "iptables -t nat -S postrouting_lan_rule":
					if tc.iptListErr {
						return nil, context.DeadlineExceeded
					}
					return []byte(tc.iptListOutput), nil
				default:
					return nil, nil
				}
			}

			if err := vlan.ApplyRuntimeSideRoutes(t.Context(), tc.spec, runner); err != nil {
				t.Fatalf("ApplyRuntimeSideRoutes failed: %v", err)
			}
			applyJoined := strings.Join(cmds, "\n")
			for _, want := range tc.wantApplyCmds {
				if !strings.Contains(applyJoined, want) {
					t.Fatalf("missing apply no-masq cmd %q in:\n%s", want, applyJoined)
				}
			}
			for _, forbid := range tc.forbidApplySub {
				if strings.Contains(applyJoined, forbid) {
					t.Fatalf("unexpected cmd matching %q in:\n%s", forbid, applyJoined)
				}
			}

			// Suspend cleans no-masq rules too.
			mu.Lock()
			cmds = nil
			mu.Unlock()
			if err := vlan.SuspendRuntimeSideRoutes(t.Context(), runner); err != nil {
				t.Fatalf("SuspendRuntimeSideRoutes failed: %v", err)
			}
			suspJoined := strings.Join(cmds, "\n")
			for _, want := range tc.wantSuspCmds {
				if !strings.Contains(suspJoined, want) {
					t.Fatalf("missing suspend cleanup cmd %q in:\n%s", want, suspJoined)
				}
			}

			// Empty CIDRs on Apply cleans no-masq rules too.
			mu.Lock()
			cmds = nil
			mu.Unlock()
			if err := vlan.ApplyRuntimeSideRoutes(t.Context(), vlan.VLANSideRouteSpec{SideRouterIP: "192.168.55.88"}, runner); err != nil {
				t.Fatalf("ApplyRuntimeSideRoutes(empty) failed: %v", err)
			}
			emptyJoined := strings.Join(cmds, "\n")
			for _, want := range tc.wantSuspCmds {
				if !strings.Contains(emptyJoined, want) {
					t.Fatalf("missing empty cleanup cmd %q in:\n%s", want, emptyJoined)
				}
			}
		})
	}

	t.Run("concurrent_idempotency_serialized", func(t *testing.T) {
		var mu sync.Mutex
		var chainRules []string
		var inFlight atomic.Int32
		var overlapDetected atomic.Bool

		statefulRunner := func(_ context.Context, name string, args ...string) ([]byte, error) {
			if cur := inFlight.Add(1); cur > 1 {
				overlapDetected.Store(true)
			}
			defer inFlight.Add(-1)

			// Yield briefly so unserialized callers deterministically overlap.
			time.Sleep(2 * time.Millisecond)

			line := name + " " + strings.Join(args, " ")
			switch {
			case line == "ip -4 rule show":
				return []byte("18810:\tfrom 192.168.89.0/24 lookup 188\n"), nil
			case line == "nft -a list chain inet fw4 srcnat_lan":
				return nil, context.DeadlineExceeded
			case line == "iptables -t nat -S postrouting_lan_rule":
				mu.Lock()
				defer mu.Unlock()
				lines := append([]string{"-N postrouting_lan_rule"}, chainRules...)
				return []byte(strings.Join(lines, "\n") + "\n"), nil
			case strings.HasPrefix(line, "iptables -t nat -D postrouting_lan_rule "):
				rule := "-A postrouting_lan_rule " + strings.TrimPrefix(line, "iptables -t nat -D postrouting_lan_rule ")
				mu.Lock()
				if idx := slices.Index(chainRules, rule); idx >= 0 {
					chainRules = append(chainRules[:idx], chainRules[idx+1:]...)
				}
				mu.Unlock()
			case strings.HasPrefix(line, "iptables -t nat -I postrouting_lan_rule 1 "):
				rule := "-A postrouting_lan_rule " + strings.TrimPrefix(line, "iptables -t nat -I postrouting_lan_rule 1 ")
				mu.Lock()
				chainRules = append([]string{rule}, chainRules...)
				mu.Unlock()
			}
			return nil, nil
		}

		spec := vlan.VLANSideRouteSpec{
			SideRouterIP: "192.168.55.88",
			CIDRs:        []string{"192.168.89.0/24"},
		}
		var wg sync.WaitGroup
		for i := range 4 {
			wg.Go(func() {
				if i%2 == 0 {
					if err := vlan.ApplyRuntimeSideRoutes(t.Context(), spec, statefulRunner); err != nil {
						t.Errorf("concurrent ApplyRuntimeSideRoutes failed: %v", err)
					}
				} else {
					if err := vlan.SuspendRuntimeSideRoutes(t.Context(), statefulRunner); err != nil {
						t.Errorf("concurrent SuspendRuntimeSideRoutes failed: %v", err)
					}
				}
			})
		}
		wg.Wait()

		if overlapDetected.Load() {
			t.Fatal("expected ApplyRuntimeSideRoutes / SuspendRuntimeSideRoutes to serialize via runtime mutex")
		}
		if err := vlan.ApplyRuntimeSideRoutes(t.Context(), spec, statefulRunner); err != nil {
			t.Fatalf("final ApplyRuntimeSideRoutes failed: %v", err)
		}
		mu.Lock()
		gotLen := len(chainRules)
		mu.Unlock()
		if gotLen != 1 {
			t.Fatalf("expected exactly 1 no-masq rule after concurrent apply/suspend, got %d: %v", gotLen, chainRules)
		}
	})
}

func TestVLAN_SyncFW3SideNoMasqInclude(t *testing.T) {
	scriptPath := filepath.Join(t.TempDir(), "etc", "singctl", "vlan-side-nomasq.fw3.sh")
	var cmds []string
	uciPresent := false
	runner := func(_ context.Context, name string, args ...string) ([]byte, error) {
		line := name + " " + strings.Join(args, " ")
		cmds = append(cmds, line)
		if line == "uci -q get firewall.singctl_vlan_nomasq" && !uciPresent {
			return nil, os.ErrNotExist
		}
		if line == "uci set firewall.singctl_vlan_nomasq=include" {
			uciPresent = true
		}
		if line == "uci delete firewall.singctl_vlan_nomasq" {
			uciPresent = false
		}
		return nil, nil
	}

	// 1. Write 0600 script + register UCI firewall.singctl_vlan_nomasq=include
	if err := vlan.SyncFW3SideNoMasqInclude(scriptPath, []string{"192.168.89.0/24", "192.168.34.0/24"}, runner); err != nil {
		t.Fatalf("SyncFW3SideNoMasqInclude apply failed: %v", err)
	}
	st, err := os.Stat(scriptPath)
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 perm on %s, err=%v mode=%v", scriptPath, err, st.Mode().Perm())
	}
	raw, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("read fw3 no-masq script: %v", err)
	}
	text := string(raw)
	for _, want := range []string{
		"postrouting_lan_rule",
		"192.168.34.0/24",
		"192.168.89.0/24",
		"singctl-side-nomasq",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("fw3 no-masq script missing %q:\n%s", want, text)
		}
	}
	joined := strings.Join(cmds, "\n")
	for _, wantCmd := range []string{
		"uci set firewall.singctl_vlan_nomasq=include",
		"uci set firewall.singctl_vlan_nomasq.type=script",
		"uci set firewall.singctl_vlan_nomasq.path=" + scriptPath,
		"uci set firewall.singctl_vlan_nomasq.reload=1",
		"uci commit firewall",
	} {
		if !strings.Contains(joined, wantCmd) {
			t.Fatalf("missing expected UCI include command %q in:\n%s", wantCmd, joined)
		}
	}

	// 2. Injection CIDR fails without removing valid script
	if err := vlan.SyncFW3SideNoMasqInclude(scriptPath, []string{"192.168.89.0/24; id"}, runner); err == nil {
		t.Fatal("expected SyncFW3SideNoMasqInclude to reject injection CIDR")
	}
	if _, statErr := os.Stat(scriptPath); statErr != nil {
		t.Fatalf("expected existing script intact on validation error, got %v", statErr)
	}

	// 3. Empty/nil CIDRs cleans script and removes UCI section idempotently
	cmds = nil
	if err := vlan.SyncFW3SideNoMasqInclude(scriptPath, nil, runner); err != nil {
		t.Fatalf("SyncFW3SideNoMasqInclude(nil) cleanup failed: %v", err)
	}
	if _, statErr := os.Stat(scriptPath); !os.IsNotExist(statErr) {
		t.Fatalf("expected script removed after cleanup, err=%v", statErr)
	}
	cleanJoined := strings.Join(cmds, "\n")
	if !strings.Contains(cleanJoined, "uci delete firewall.singctl_vlan_nomasq") || !strings.Contains(cleanJoined, "uci commit firewall") {
		t.Fatalf("expected cleanup to remove UCI firewall.singctl_vlan_nomasq, got:\n%s", cleanJoined)
	}
}

func TestVLAN_ApplySideRoutesWithRetry(t *testing.T) {
	spec := vlan.VLANSideRouteSpec{
		SideRouterIP: "192.168.55.88",
		CIDRs:        []string{"192.168.89.0/24"},
	}

	t.Run("recovers on third attempt", func(t *testing.T) {
		attempts := 0
		err := vlan.ApplySideRoutesWithRetry(t.Context(), spec, 5, 5*time.Millisecond, func(_ context.Context, got vlan.VLANSideRouteSpec) error {
			attempts++
			if got.SideRouterIP != spec.SideRouterIP || len(got.CIDRs) != 1 {
				t.Fatalf("unexpected spec passed to applyFn: %+v", got)
			}
			if attempts < 3 {
				return os.ErrInvalid
			}
			return nil
		})
		if err != nil {
			t.Fatalf("expected retry to recover on attempt 3, got err=%v (attempts=%d)", err, attempts)
		}
		if attempts != 3 {
			t.Fatalf("expected 3 attempts, got %d", attempts)
		}
	})

	t.Run("aborts immediately on canceled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		attempts := 0
		err := vlan.ApplySideRoutesWithRetry(ctx, spec, 5, time.Second, func(_ context.Context, _ vlan.VLANSideRouteSpec) error {
			attempts++
			cancel()
			return os.ErrInvalid
		})
		if err == nil {
			t.Fatal("expected canceled error, got nil")
		}
		if attempts != 1 {
			t.Fatalf("expected immediate abort after cancel (1 attempt), got %d", attempts)
		}
	})

	t.Run("returns error after exhausting maxAttempts", func(t *testing.T) {
		attempts := 0
		err := vlan.ApplySideRoutesWithRetry(t.Context(), spec, 3, time.Millisecond, func(_ context.Context, _ vlan.VLANSideRouteSpec) error {
			attempts++
			return os.ErrInvalid
		})
		if err == nil {
			t.Fatal("expected error after exhausting maxAttempts, got nil")
		}
		if attempts != 3 {
			t.Fatalf("expected 3 attempts, got %d", attempts)
		}
	})
}
