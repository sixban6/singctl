// 文件职责：测试 VLAN 子网「交由旁路由分流 (side_router)」的校验、DHCP/DNS 联动、防火墙安全隔离顺序、策略路由生成、故障摘除与并发安全。
package vlan_test

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

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
