// 文件职责：测试三源设备发现、Tailscale 外网可达性评估、DHCP 自动跟随、OpenWrt dnsmasq 精准 rebind_domain 与双引擎重写同步。
package homedomain_test

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"singctl/internal/config"
	"singctl/internal/homedomain"
)

func TestDiscovery_ReachabilityAndDHCPFollow(t *testing.T) {
	dir := t.TempDir()
	leasesPath := filepath.Join(dir, "dhcp.leases")
	arpPath := filepath.Join(dir, "arp")
	_ = os.WriteFile(leasesPath, []byte("1799999999 aa:bb:cc:dd:ee:01 192.0.2.10 My_NAS 01:aa\n1799999999 aa:bb:cc:dd:ee:02 192.0.2.25 MacBook-Pro 01:bb\n"), 0644)
	_ = os.WriteFile(arpPath, []byte("IP address       HW type     Flags       HW address            Mask     Device\n192.0.2.10       0x1         0x2         aa:bb:cc:dd:ee:01     *        br-lan\n192.0.2.30       0x1         0x2         aa:bb:cc:dd:ee:03     *        br-lan\n"), 0644)

	tsStatusJSON := `{
		"BackendState": "Running",
		"Self": {
			"HostName": "n4120",
			"TailscaleIPs": ["100.64.0.1"],
			"AdvertisedRoutes": ["192.0.2.0/24"],
			"Online": true
		},
		"Peer": {
			"k1": {
				"HostName": "ax3000t",
				"DNSName": "ax3000t.tailnet.ts.net.",
				"TailscaleIPs": ["100.64.0.22"],
				"Online": true,
				"OS": "linux"
			}
		}
	}`

	disc := homedomain.DiscoverDevices(t.Context(), homedomain.DiscoveryDeps{
		LeaseFiles:      []string{leasesPath},
		ARPFile:         arpPath,
		HostnameFunc:    func() (string, error) { return "n4120", nil },
		PrimaryLANIP:    func() string { return "192.0.2.1" },
		TailscaleStatus: func(context.Context) ([]byte, error) { return []byte(tsStatusJSON), nil },
	})

	if disc.Self.Hostname != "n4120" || disc.Self.LANIP != "192.0.2.1" || disc.Self.TailscaleIP != "100.64.0.1" {
		t.Fatalf("unexpected Self discovery: %+v", disc.Self)
	}
	if len(disc.LANDevices) < 3 {
		t.Fatalf("expected >= 3 LAN devices from leases+arp, got %+v", disc.LANDevices)
	}
	if len(disc.TailscalePeers) != 1 || disc.TailscalePeers[0].SuggestedAlias != "ax3000t" {
		t.Fatalf("expected 1 Tailscale peer ax3000t, got %+v", disc.TailscalePeers)
	}

	// Reachability evaluation:
	// - 100.64.0.22 -> "tailscale"
	// - 192.0.2.10 (covered by advertised 192.0.2.0/24) -> "subnet"
	// - 198.51.100.1 (uncovered cascaded router ax3000t) -> "lan_only" + suggestedTailscaleIp = "100.64.0.22"
	adv := []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	rTS := homedomain.EvaluateReachability(config.HomeDomainDevice{Alias: "n60pro", IP: "100.64.0.20"}, adv, disc.TailscalePeers)
	if rTS.Status != "tailscale" {
		t.Fatalf("expected tailscale reachability, got %+v", rTS)
	}
	rSub := homedomain.EvaluateReachability(config.HomeDomainDevice{Alias: "nas", IP: "192.0.2.10"}, adv, disc.TailscalePeers)
	if rSub.Status != "subnet" {
		t.Fatalf("expected subnet reachability, got %+v", rSub)
	}
	rOnly := homedomain.EvaluateReachability(config.HomeDomainDevice{Alias: "ax3000t", IP: "198.51.100.1"}, adv, disc.TailscalePeers)
	if rOnly.Status != "lan_only" || rOnly.SuggestedTailscaleIP != "100.64.0.22" {
		t.Fatalf("expected lan_only with suggestedTailscaleIp=100.64.0.22, got %+v", rOnly)
	}

	// DHCP MAC->IP auto-follow updates changed IP cleanly
	cfg := &config.Config{
		HomeDomain: config.HomeDomainConfig{
			Suffix: "home",
			Devices: []config.HomeDomainDevice{
				{Alias: "nas", IP: "192.0.2.99", MAC: "aa:bb:cc:dd:ee:01", Source: "lan"},
			},
		},
	}
	changed, updates := homedomain.ReconcileDHCPAddresses(cfg, disc.LANDevices)
	if !changed || len(updates) != 1 || cfg.HomeDomain.Devices[0].IP != "192.0.2.10" {
		t.Fatalf("ReconcileDHCPAddresses = (%v, %v, ip=%s), want changed to 192.0.2.10", changed, updates, cfg.HomeDomain.Devices[0].IP)
	}
}

func TestOpenWrtDnsmasq_RebindServerAndExcludeTailscale(t *testing.T) {
	lists := map[string][]string{}
	reloads := 0
	var cmds []string
	deps := homedomain.DnsmasqDeps{
		IsOpenWrt: func() bool { return true },
		RunUCI: func(_ context.Context, args ...string) (string, error) {
			cmds = append(cmds, strings.Join(args, " "))
			if len(args) >= 2 && args[0] == "-q" && args[1] == "get" {
				return strings.Join(lists[args[2]], " "), nil
			}
			if len(args) >= 2 && args[0] == "add_list" {
				k, v, _ := strings.Cut(args[1], "=")
				lists[k] = append(lists[k], v)
			}
			if len(args) >= 2 && args[0] == "del_list" {
				k, v, _ := strings.Cut(args[1], "=")
				lists[k] = slices.DeleteFunc(lists[k], func(x string) bool { return x == v })
			}
			return "", nil
		},
		ReloadDnsmasq: func(context.Context) error {
			reloads++
			return nil
		},
	}

	changed, err := homedomain.ReconcileOpenWrtDnsmasq(t.Context(), homedomain.DnsmasqDesired{
		Enabled:          true,
		Suffix:           "home",
		LocalDNSPort:     5353,
		ExcludeTailscale: true,
	}, deps)
	if err != nil || !changed || reloads != 1 {
		t.Fatalf("first ReconcileOpenWrtDnsmasq = (%v, %v) reloads=%d", changed, err, reloads)
	}
	if !slices.Contains(lists["dhcp.@dnsmasq[0].rebind_domain"], "home") {
		t.Fatalf("missing rebind_domain=home: %v", lists)
	}
	if !slices.Contains(lists["dhcp.@dnsmasq[0].server"], "/home/127.0.0.1#5353") {
		t.Fatalf("missing server=/home/127.0.0.1#5353: %v", lists)
	}
	if !slices.Contains(lists["dhcp.@dnsmasq[0].notinterface"], "tailscale0") {
		t.Fatalf("missing notinterface=tailscale0: %v", lists)
	}
	// Safety redline: never touch global localservice or rebind_protection
	for _, c := range cmds {
		if strings.Contains(c, "localservice") || strings.Contains(c, "rebind_protection") {
			t.Fatalf("forbidden global dnsmasq mutation: %s", c)
		}
	}

	// Strictly idempotent on repeat
	changed2, err := homedomain.ReconcileOpenWrtDnsmasq(t.Context(), homedomain.DnsmasqDesired{
		Enabled:          true,
		Suffix:           "home",
		LocalDNSPort:     5353,
		ExcludeTailscale: true,
	}, deps)
	if err != nil || changed2 || reloads != 1 {
		t.Fatalf("repeat ReconcileOpenWrtDnsmasq must be idempotent, got changed=%v reloads=%d err=%v", changed2, reloads, err)
	}
}

func TestMergeManagedRewrites_PreservesManualEntries(t *testing.T) {
	existing := []config.DNSRewriteRule{
		{Domain: "custom.example.com", Answer: "198.51.100.5"},
		{Domain: "old.home", Answer: "192.0.2.88"},
		{Domain: "*.old.home", Answer: "192.0.2.88"},
	}
	prevManaged := []config.DNSRewriteRule{
		{Domain: "old.home", Answer: "192.0.2.88"},
		{Domain: "*.old.home", Answer: "192.0.2.88"},
	}
	nextManaged := []config.DNSRewriteRule{
		{Domain: "nas.home", Answer: "192.0.2.10"},
		{Domain: "*.nas.home", Answer: "192.0.2.10"},
	}

	merged, toAdd, toDelete := homedomain.ComputeRewriteDiff(existing, prevManaged, nextManaged)
	if len(toDelete) != 2 || len(toAdd) != 2 {
		t.Fatalf("unexpected diff add=%v del=%v", toAdd, toDelete)
	}
	if len(merged) != 3 || merged[0].Domain != "custom.example.com" {
		t.Fatalf("manual rewrite must be preserved, merged=%+v", merged)
	}
}
