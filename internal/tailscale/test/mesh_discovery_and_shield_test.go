// 文件职责：覆盖 Tailscale 全拓扑局域网自动发现（主网/VLAN/下级静态路由）、热切换参数下发与内网双通防锁死护盾单元测试。
package tailscale_test

import (
	"context"
	"slices"
	"strings"
	"sync"
	"testing"

	"singctl/internal/config"
	"singctl/internal/tailscale"
)

func TestDiscoverLocalNetworks_MainVLANAndDownstreamRoutes(t *testing.T) {
	routeOut := strings.Join([]string{
		"default via 198.51.100.1 dev pppoe-wan",
		"198.51.100.1 dev pppoe-wan proto kernel scope link src 203.0.113.5",
		"192.168.27.0/24 via 192.168.31.151 dev br-lan",
		"192.168.28.0/24 via 192.168.31.151 dev br-lan",
		"192.168.29.0/24 via 192.168.31.151 dev br-lan",
		"192.168.31.0/24 dev br-lan proto kernel scope link src 192.168.31.1",
		"192.168.89.0/24 dev br-baidu_lan proto kernel scope link src 192.168.89.1",
		"172.17.0.0/16 dev docker0 proto kernel scope link src 172.17.0.1",
		"10.10.0.0/24 dev veth1234 proto kernel scope link src 10.10.0.1",
		"100.64.0.0/10 dev tailscale0 scope link",
		"192.168.0.0/16 via 192.168.31.2 dev br-lan",
	}, "\n")

	nets := tailscale.DiscoverLocalNetworks(t.Context(), tailscale.DiscoverOptions{
		PrimaryLANCIDR:        "192.168.31.0/24",
		ConfiguredSubnets:     "192.168.31.0/24,192.168.27.0/24,10.99.88.0/24,0.0.0.0/0",
		LiveAdvertisedSubnets: "192.168.31.0/24",
		VLANHints: []tailscale.VLANHint{
			{ID: "lan", DisplayName: "家庭主网", CIDR: "192.168.31.0/24", IsPrimaryLAN: true, OnlineClients: 4},
			{ID: "baidu_lan", DisplayName: "工作无线", CIDR: "192.168.89.0/24", VLANID: 89, SSID: "sweetcs", OnlineClients: 2},
		},
		RouteOutput: routeOut,
	})

	byCIDR := make(map[string]tailscale.LocalNetwork, len(nets))
	for _, n := range nets {
		if _, dup := byCIDR[n.CIDR]; dup {
			t.Fatalf("duplicate discovered network CIDR %q", n.CIDR)
		}
		byCIDR[n.CIDR] = n
	}

	// Primary LAN enriched by VLANHint and marked selected & approved.
	lan, ok := byCIDR["192.168.31.0/24"]
	if !ok || lan.Kind != tailscale.LocalNetPrimaryLAN || !lan.Selected || !lan.Approved || lan.OnlineClients != 4 {
		t.Fatalf("unexpected primary LAN entry: %+v (ok=%v)", lan, ok)
	}

	// VLAN enriched with SSID and marked unselected because not in ConfiguredSubnets.
	vlanNet, ok := byCIDR["192.168.89.0/24"]
	if !ok || vlanNet.Kind != tailscale.LocalNetVLAN || vlanNet.Selected || vlanNet.SSID != "sweetcs" || vlanNet.VLANID != 89 {
		t.Fatalf("unexpected VLAN entry: %+v (ok=%v)", vlanNet, ok)
	}

	// Downstream subnets via 192.168.31.151 (n4120 static route pattern).
	for _, sub := range []string{"192.168.27.0/24", "192.168.28.0/24", "192.168.29.0/24"} {
		dn, exists := byCIDR[sub]
		if !exists {
			t.Fatalf("expected downstream subnet %s to be discovered", sub)
		}
		if dn.Kind != tailscale.LocalNetDownstreamSubnet || dn.ViaGateway != "192.168.31.151" || dn.NATHint == "" {
			t.Fatalf("unexpected downstream entry for %s: %+v", sub, dn)
		}
		wantSelected := sub == "192.168.27.0/24"
		if dn.Selected != wantSelected || dn.Approved {
			t.Fatalf("downstream %s selected=%v approved=%v, want selected=%v approved=false", sub, dn.Selected, dn.Approved, wantSelected)
		}
	}

	// Custom configured subnet kept.
	custom, ok := byCIDR["10.99.88.0/24"]
	if !ok || custom.Kind != tailscale.LocalNetCustom || !custom.Selected {
		t.Fatalf("unexpected custom configured subnet: %+v (ok=%v)", custom, ok)
	}

	// Container / virtual / WAN / CGNAT / /16 supernet summary routes excluded.
	for _, excluded := range []string{"172.17.0.0/16", "10.10.0.0/24", "100.64.0.0/10", "192.168.0.0/16", "0.0.0.0/0", "198.51.100.1"} {
		if _, found := byCIDR[excluded]; found {
			t.Fatalf("excluded route %q must not appear in localNetworks", excluded)
		}
	}
}

func TestSyncLiveTailscaleMesh_CallsTailscaleSetAndPreservesExitNode(t *testing.T) {
	var calls []string
	err := tailscale.SyncLiveTailscaleMesh(t.Context(), tailscale.SyncLiveMeshOptions{
		BinPath:      "/usr/sbin/tailscale",
		SubnetsCSV:   "192.168.31.0/24,192.168.27.0/24",
		AcceptRoutes: true,
		IsOpenWrt:    true,
		Runner: func(_ context.Context, _ string, name string, args ...string) ([]byte, error) {
			calls = append(calls, name+" "+strings.Join(args, " "))
			return nil, nil
		},
	})
	if err != nil {
		t.Fatalf("SyncLiveTailscaleMesh unexpected error: %v", err)
	}
	if len(calls) != 1 {
		t.Fatalf("expected 1 tailscale set call, got %v", calls)
	}
	got := calls[0]
	for _, want := range []string{
		"/usr/sbin/tailscale set",
		"--advertise-routes=192.168.31.0/24,192.168.27.0/24",
		"--accept-routes=true",
		"--snat-subnet-routes=false",
		"--netfilter-mode=off",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("tailscale set command missing %q: %s", want, got)
		}
	}
	if strings.Contains(got, "--advertise-exit-node") {
		t.Fatalf("SyncLiveTailscaleMesh must preserve exit node when AdvertiseExitNode==nil, got: %s", got)
	}
}

func TestLANCoexistenceShield_SideRouterMainRouterIdempotencyAndRemove(t *testing.T) {
	var mu sync.Mutex
	var cmds []string
	rules := map[int]string{
		0:     "0:\tfrom all lookup local",
		5270:  "5270:\tfrom all lookup 52",
		32766: "32766:\tfrom all lookup main",
	}

	runner := func(_ context.Context, _ string, name string, args ...string) ([]byte, error) {
		mu.Lock()
		defer mu.Unlock()
		line := name + " " + strings.Join(args, " ")
		cmds = append(cmds, line)
		if name == "ip" && slices.Equal(args, []string{"-4", "rule", "show"}) {
			var lines []string
			for _, v := range rules {
				lines = append(lines, v)
			}
			return []byte(strings.Join(lines, "\n")), nil
		}
		if name == "ip" && len(args) >= 4 && args[1] == "rule" && args[2] == "add" {
			prefIdx := slices.Index(args, "pref")
			if prefIdx >= 0 && prefIdx+1 < len(args) {
				if args[prefIdx+1] == "5260" {
					rules[5260] = "5260:\tfrom all to 192.168.55.0/24 lookup main"
				} else if args[prefIdx+1] == "5265" {
					rules[5265] = "5265:\tfrom 192.168.55.88 to 100.64.0.0/10 lookup main"
				}
			}
		}
		if name == "ip" && len(args) >= 5 && args[1] == "rule" && args[2] == "del" && args[3] == "pref" {
			if args[4] == "5260" {
				delete(rules, 5260)
			}
			if args[4] == "5265" {
				delete(rules, 5265)
			}
		}
		return nil, nil
	}

	// 1. Side router (not advertising LAN): installs both 5260 and 5265 + --netfilter-mode=off.
	err := tailscale.SyncLANCoexistenceShield(t.Context(), tailscale.LANShieldOptions{
		Runner:             runner,
		LocalCIDRs:         []string{"192.168.55.0/24"},
		LocalLANIP:         "192.168.55.88",
		AdvertiseLocalLAN:  false,
		IsOpenWrt:          true,
		EnsureNetfilterOff: true,
		BinPath:            "/usr/sbin/tailscale",
	})
	if err != nil {
		t.Fatalf("side router SyncLANCoexistenceShield failed: %v", err)
	}
	joined := strings.Join(cmds, "\n")
	for _, want := range []string{
		"ip -4 rule add to 192.168.55.0/24 lookup main pref 5260",
		"ip -4 rule add from 192.168.55.88 to 100.64.0.0/10 lookup main pref 5265",
		"/usr/sbin/tailscale set --netfilter-mode=off",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("expected command %q in:\n%s", want, joined)
		}
	}

	// 2. Second identical call skips rule mutations (idempotent).
	before := len(cmds)
	err = tailscale.SyncLANCoexistenceShield(t.Context(), tailscale.LANShieldOptions{
		Runner:             runner,
		LocalCIDRs:         []string{"192.168.55.0/24"},
		LocalLANIP:         "192.168.55.88",
		AdvertiseLocalLAN:  false,
		IsOpenWrt:          false,
		EnsureNetfilterOff: false,
	})
	if err != nil {
		t.Fatalf("second SyncLANCoexistenceShield failed: %v", err)
	}
	for _, c := range cmds[before:] {
		if strings.Contains(c, "rule add") || strings.Contains(c, "rule del") {
			t.Fatalf("expected idempotent skip of ip rule add/del, got %q", c)
		}
	}

	// 3. Switching to Advertising LAN removes 5265 while keeping 5260.
	cmds = nil
	err = tailscale.SyncLANCoexistenceShield(t.Context(), tailscale.LANShieldOptions{
		Runner:            runner,
		LocalCIDRs:        []string{"192.168.55.0/24"},
		LocalLANIP:        "192.168.55.88",
		AdvertiseLocalLAN: true,
	})
	if err != nil {
		t.Fatalf("advertising SyncLANCoexistenceShield failed: %v", err)
	}
	if _, has5265 := rules[5265]; has5265 {
		t.Fatal("expected pref 5265 to be deleted when advertising local LAN")
	}
	if _, has5260 := rules[5260]; !has5260 {
		t.Fatal("expected pref 5260 to remain active when advertising local LAN")
	}

	// 4. Clean removal clears 5260 and 5265 without touching 5270 or 32766.
	if err := tailscale.RemoveLANCoexistenceShield(t.Context(), runner); err != nil {
		t.Fatalf("RemoveLANCoexistenceShield failed: %v", err)
	}
	if _, has5260 := rules[5260]; has5260 {
		t.Fatal("expected 5260 deleted on RemoveLANCoexistenceShield")
	}
	if _, has5270 := rules[5270]; !has5270 {
		t.Fatal("must never delete Tailscale rule 5270")
	}
}

func TestDiscoverLocalNetworks_DefaultsAndDeviceDiscovery(t *testing.T) {
	// 1. Fresh install (no ConfiguredSubnets, no LiveAdvertisedSubnets, not explicitly client/exit):
	// Primary LAN defaults to Selected=true for zero-friction onboarding.
	fresh := tailscale.DiscoverLocalNetworks(t.Context(), tailscale.DiscoverOptions{
		PrimaryLANCIDR: "192.168.31.0/24",
		RouteOutput:    "192.168.31.0/24 dev br-lan scope link src 192.168.31.1",
	})
	if len(fresh) != 1 || !fresh[0].Selected {
		t.Fatalf("expected primary LAN selected by default on fresh install, got %+v", fresh)
	}

	// 2. Discovers per-subnet devices (leases + neigh + static hosts + conntrack downstream + nicknames) and attaches LocalRules.
	nets := tailscale.DiscoverLocalNetworks(t.Context(), tailscale.DiscoverOptions{
		PrimaryLANCIDR:        "192.168.31.0/24",
		ConfiguredSubnets:     "192.168.31.0/24",
		LiveAdvertisedSubnets: "192.168.31.0/24",
		SelfLANIP:             "192.168.31.1",
		LocalRules: []config.TailscaleLocalSubnetRule{
			{CIDR: "192.168.31.0/24", Scope: config.TailscaleScopeAllowlist, Devices: []string{"192.168.31.88"}},
		},
		DeviceNicknames: map[string]string{
			"192.168.31.88": "PVE宿主机",
		},
		StaticHostIPs: map[string]bool{
			"192.168.31.88": true,
		},
		LeaseText: "1795741969 02:00:00:00:01:51 192.168.31.151 ImmortalWrt *\n",
		NeighText: strings.Join([]string{
			"192.168.31.151 dev br-lan lladdr 02:00:00:00:01:51 REACHABLE",
			"192.168.31.88 dev br-lan lladdr 02:00:00:00:01:88 REACHABLE",
			"192.168.31.204 dev br-lan FAILED",
			"192.168.31.1 dev br-lan lladdr aa:bb:cc:dd:ee:ff PERMANENT",
		}, "\n"),
		RouteOutput: strings.Join([]string{
			"192.168.27.0/24 via 192.168.31.151 dev br-lan",
			"192.168.31.0/24 dev br-lan scope link src 192.168.31.1",
		}, "\n"),
		ConntrackText: "ipv4 2 tcp 6 100 ESTABLISHED src=192.168.31.88 dst=192.168.27.154 sport=1000 dport=7000\n",
	})

	var net31, net27 tailscale.LocalNetwork
	for _, n := range nets {
		if n.CIDR == "192.168.31.0/24" {
			net31 = n
		}
		if n.CIDR == "192.168.27.0/24" {
			net27 = n
		}
	}
	if net31.Scope != config.TailscaleScopeAllowlist || !slices.Equal(net31.SelectedDevices, []string{"192.168.31.88"}) {
		t.Fatalf("unexpected LocalRule binding on 31.0/24: %+v", net31)
	}
	dev31 := make(map[string]tailscale.LocalDevice)
	for _, d := range net31.Devices {
		dev31[d.IP] = d
	}
	if _, hasSelf := dev31["192.168.31.1"]; hasSelf {
		t.Fatal("SelfLANIP 192.168.31.1 must be excluded from device list")
	}
	if _, hasFailed := dev31["192.168.31.204"]; hasFailed {
		t.Fatal("FAILED ARP entry without MAC must not be listed")
	}
	if d := dev31["192.168.31.88"]; d.Name != "PVE宿主机" || !d.Online || !d.StaticLease {
		t.Fatalf("unexpected 31.88 device: %+v", d)
	}
	if d := dev31["192.168.31.151"]; d.Name != "ImmortalWrt" || !d.IsDownstream || !d.Online {
		t.Fatalf("unexpected 31.151 downstream router device: %+v", d)
	}
	if len(net27.Devices) == 0 || net27.Devices[0].IP != "192.168.27.154" {
		t.Fatalf("expected active conntrack host 192.168.27.154 in 27.0/24 devices, got %+v", net27.Devices)
	}
}
