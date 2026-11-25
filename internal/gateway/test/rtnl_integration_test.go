package gateway_test

import (
	"net/netip"
	"slices"
	"strings"
	"testing"

	"singctl/internal/config"
	"singctl/internal/gateway"
	"singctl/internal/platform/rtnl"
)

func TestController_UsesRTNLForSideRoutesAndIPv6ZeroIPSubprocess(t *testing.T) {
	mockRTNL := rtnl.NewMockClient()
	mockRTNL.DefaultRoutes[4] = rtnl.DefaultRoute{
		Family:  4,
		Gateway: netip.MustParseAddr("192.0.2.1"),
		IfIndex: 2,
		IfName:  "br-lan",
	}
	mockRTNL.DefaultRoutes[6] = rtnl.DefaultRoute{
		Family:  6,
		Gateway: netip.MustParseAddr("fe80::1"),
		IfIndex: 3,
		IfName:  "pppoe-wan",
	}
	mockRTNL.Addresses = []rtnl.InterfaceAddr{
		{
			IfIndex: 2,
			IfName:  "br-lan",
			IsUp:    true,
			Prefix:  netip.MustParsePrefix("2001:db8:cafe:1::1/64"),
		},
	}
	mockRTNL.LocalTables[[2]int{4, 100}] = true
	mockRTNL.LocalTables[[2]int{6, 100}] = true

	var cmds []string
	ctrl := &gateway.Controller{
		StateDir:       t.TempDir(),
		FW4IncludeRoot: t.TempDir(),
		RTNL:           mockRTNL,
		IsOpenWrt:      func() bool { return false },
		Prober: func() gateway.TopologyInfo {
			return gateway.TopologyInfo{
				LANIP:                 "192.0.2.2",
				LANCIDR:               "192.0.2.0/24",
				LANIface:              "br-lan",
				CurrentGatewayIP:      "192.0.2.1",
				SuggestedMainRouterIP: "192.0.2.1",
			}
		},
		IPv6KernelProbe: func() (bool, bool) { return true, true },
		Exec: func(name string, args ...string) ([]byte, error) {
			cmds = append(cmds, name+" "+strings.Join(args, " "))
			return nil, nil
		},
	}

	if err := ctrl.Apply(t.Context(), config.GatewayConfig{
		Mode:         gateway.ModeSide,
		MainRouterIP: "192.0.2.1",
	}); err != nil {
		t.Fatalf("Apply(ModeSide) failed: %v", err)
	}

	// Default route & table 100 throw routes must go through RTNL, NOT `ip` CLI subprocesses!
	for _, cmd := range cmds {
		if strings.HasPrefix(cmd, "ip ") {
			t.Fatalf("expected zero `ip` subprocess invocations when RTNL is injected, got %q", cmd)
		}
	}
	def, ok, _ := mockRTNL.GetDefaultRoute(4)
	if !ok || def.Gateway.String() != "192.0.2.1" || def.IfName != "br-lan" {
		t.Fatalf("unexpected replaced default route in RTNL mock: %+v", def)
	}
	if !slices.Contains(mockRTNL.EnsuredThrows(), netip.MustParsePrefix("192.0.2.0/24")) {
		t.Fatalf("expected LANCIDR throw route reconciled via RTNL, got %v", mockRTNL.EnsuredThrows())
	}

	// ProbeIPv6Status must also extract default IPv6 route and LAN /64 prefix via RTNL!
	v6Status := ctrl.ProbeIPv6Status(t.Context(), config.GatewayConfig{Mode: "main", IPv6Mode: "cn_only"}, gateway.TopologyInfo{
		LANIP:    "192.0.2.2",
		LANCIDR:  "192.0.2.0/24",
		LANIface: "br-lan",
	})
	if !v6Status.WANHasDefaultV6 || len(v6Status.LANPrefixes) == 0 || v6Status.LANPrefixes[0] != "2001:db8:cafe:1::/64" {
		t.Fatalf("expected ProbeIPv6Status to read default route & LAN prefix via RTNL, got %+v", v6Status)
	}
}
