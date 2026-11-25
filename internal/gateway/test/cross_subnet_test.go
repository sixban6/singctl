// 文件职责：测试旁路由跨子网 RFC1918 回程路由配置与 OpenWrt dnsmasq 跨网段响应 (localservice=0) 的幂等应用与可逆还原。
package gateway_test

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"singctl/internal/config"
	"singctl/internal/gateway"
	"singctl/internal/platform/servicemgr"
)

func TestSideRouterCrossSubnetRoutesAndDnsmasq(t *testing.T) {
	stateDir := t.TempDir()
	fw4Root := t.TempDir()
	mockMgr := servicemgr.NewMock()

	localServiceVal := "1"
	var cmds []string
	ctrl := &gateway.Controller{
		StateDir:       stateDir,
		FW4IncludeRoot: fw4Root,
		ServiceMgr:     mockMgr,
		IsOpenWrt:      func() bool { return true },
		Prober: func() gateway.TopologyInfo {
			return gateway.TopologyInfo{
				LANIP:               "192.168.55.88",
				LANCIDR:             "192.168.55.0/24",
				LANIface:            "eth0",
				CurrentGatewayIP:    "192.168.55.1",
				HasLocalDNSListener: true,
			}
		},
		Exec: func(name string, args ...string) ([]byte, error) {
			line := name + " " + strings.Join(args, " ")
			cmds = append(cmds, line)
			switch line {
			case "uci -q get dhcp.@dnsmasq[0].localservice":
				return []byte(localServiceVal + "\n"), nil
			case "uci set dhcp.@dnsmasq[0].localservice=0":
				localServiceVal = "0"
			case "uci set dhcp.@dnsmasq[0].localservice=1":
				localServiceVal = "1"
			}
			return nil, nil
		},
	}

	gwCfg := config.GatewayConfig{
		Mode:         gateway.ModeSide,
		MainRouterIP: "192.168.55.1",
	}
	if err := ctrl.Apply(t.Context(), gwCfg); err != nil {
		t.Fatalf("first Apply failed: %v", err)
	}

	// 1. Verify RFC1918 metric 200 return routes were added & persisted at 0600.
	joined := strings.Join(cmds, "\n")
	for _, want := range []string{
		"ip -4 route replace 10.0.0.0/8 via 192.168.55.1 dev eth0 metric 200",
		"ip -4 route replace 172.16.0.0/12 via 192.168.55.1 dev eth0 metric 200",
		"ip -4 route replace 192.168.0.0/16 via 192.168.55.1 dev eth0 metric 200",
		"uci set dhcp.@dnsmasq[0].localservice=0",
		"uci commit dhcp",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("expected %q in first Apply commands:\n%s", want, joined)
		}
	}
	if !slices.Contains(mockMgr.Calls(), "reload dnsmasq") {
		t.Fatalf("expected reload dnsmasq call, got %v", mockMgr.Calls())
	}

	for _, fname := range []string{"return_routes.json", "dnsmasq.orig.json"} {
		p := filepath.Join(stateDir, fname)
		st, err := os.Stat(p)
		if err != nil {
			t.Fatalf("expected snapshot %s: %v", p, err)
		}
		if st.Mode().Perm() != 0600 {
			t.Fatalf("expected %s mode 0600, got %04o", fname, st.Mode().Perm())
		}
	}

	// 2. Second Apply when localservice is already "0" must NOT overwrite original snapshot or redundantly commit/reload dnsmasq.
	cmds = nil
	if err := ctrl.Apply(t.Context(), gwCfg); err != nil {
		t.Fatalf("second Apply failed: %v", err)
	}
	joined2 := strings.Join(cmds, "\n")
	if strings.Contains(joined2, "uci set dhcp.@dnsmasq[0].localservice") || strings.Contains(joined2, "uci commit dhcp") {
		t.Fatalf("second Apply should be idempotent when localservice is already 0, got:\n%s", joined2)
	}
	if len(mockMgr.Calls()) != 1 {
		t.Fatalf("expected dnsmasq reload only once across two Applies, got %v", mockMgr.Calls())
	}

	// 3. Teardown deletes metric 200 return routes and restores localservice=1.
	cmds = nil
	if err := ctrl.Teardown(t.Context()); err != nil {
		t.Fatalf("Teardown failed: %v", err)
	}
	joinedTD := strings.Join(cmds, "\n")
	for _, want := range []string{
		"ip -4 route del 10.0.0.0/8 via 192.168.55.1 dev eth0 metric 200",
		"ip -4 route del 172.16.0.0/12 via 192.168.55.1 dev eth0 metric 200",
		"ip -4 route del 192.168.0.0/16 via 192.168.55.1 dev eth0 metric 200",
		"uci set dhcp.@dnsmasq[0].localservice=1",
		"uci commit dhcp",
	} {
		if !strings.Contains(joinedTD, want) {
			t.Fatalf("expected teardown cmd %q in:\n%s", want, joinedTD)
		}
	}
	if localServiceVal != "1" {
		t.Fatalf("expected localservice restored to 1, got %q", localServiceVal)
	}
	if calls := mockMgr.Calls(); len(calls) != 2 || calls[1] != "reload dnsmasq" {
		t.Fatalf("expected second reload dnsmasq on Teardown, got %v", calls)
	}

	// 4. Non-OpenWrt host still installs return routes without touching uci/dnsmasq.
	nonOWRTState := t.TempDir()
	nonOWRTMgr := servicemgr.NewMock()
	var nonOWRTCmds []string
	nonOWRTCtrl := &gateway.Controller{
		StateDir:       nonOWRTState,
		FW4IncludeRoot: t.TempDir(),
		ServiceMgr:     nonOWRTMgr,
		IsOpenWrt:      func() bool { return false },
		Prober: func() gateway.TopologyInfo {
			return gateway.TopologyInfo{
				LANIP:    "192.168.55.88",
				LANCIDR:  "192.168.55.0/24",
				LANIface: "eth0",
			}
		},
		Exec: func(name string, args ...string) ([]byte, error) {
			line := name + " " + strings.Join(args, " ")
			nonOWRTCmds = append(nonOWRTCmds, line)
			return nil, nil
		},
	}
	if err := nonOWRTCtrl.Apply(t.Context(), gwCfg); err != nil {
		t.Fatalf("non-OpenWrt Apply failed: %v", err)
	}
	nonJoined := strings.Join(nonOWRTCmds, "\n")
	if strings.Contains(nonJoined, "uci ") {
		t.Fatalf("non-OpenWrt must not run uci commands, got:\n%s", nonJoined)
	}
	if !strings.Contains(nonJoined, "ip -4 route replace 192.168.0.0/16 via 192.168.55.1 dev eth0 metric 200") {
		t.Fatalf("non-OpenWrt missing return route cmd:\n%s", nonJoined)
	}
}
