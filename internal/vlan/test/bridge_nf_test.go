// 文件职责：测试 OpenWrt 24/21 VLAN DHCPv4 服务启用、dnsmasq 完整重启编排及 DSA br-lan 同段二层直通持久化规则。
package vlan_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"singctl/internal/platform/servicemgr"
	"singctl/internal/vlan"
)

type procdMockManager struct {
	*servicemgr.MockManager
	reloadErr map[string]error
	restartErr error
}

func (p *procdMockManager) Kind() servicemgr.InitKind {
	return servicemgr.InitProcd
}

func (p *procdMockManager) Reload(ctx context.Context, name string) error {
	_ = p.MockManager.Reload(ctx, name)
	if err, ok := p.reloadErr[name]; ok {
		return err
	}
	return nil
}

func (p *procdMockManager) Restart(ctx context.Context, name string) error {
	_ = p.MockManager.Restart(ctx, name)
	if name == "dnsmasq" && p.restartErr != nil {
		return p.restartErr
	}
	return nil
}

func TestVLAN_BuildDHCPCommands_EmitsDHCPv4Server(t *testing.T) {
	boardJSON := `{"model":{"id":"xiaomi,ax3000t","name":"AX3000T"},"network":{"lan":{"ports":["lan1","lan2","lan3","lan4"]},"wan":{"device":"eth0"}}}`
	networkUCI := strings.Join([]string{
		"network.loopback=interface",
		"network.loopback.device='lo'",
		"network.lan_dev=device",
		"network.lan_dev.name='br-lan'",
		"network.lan_dev.type='bridge'",
		"network.lan_dev.ports='lan1' 'lan2' 'lan3' 'lan4'",
		"network.lan=interface",
		"network.lan.device='br-lan'",
		"network.lan.proto='static'",
		"network.lan.ipaddr='192.168.55.1'",
		"network.lan.netmask='255.255.255.0'",
		"network.wan=interface",
		"network.wan.device='eth0'",
		"network.wan.proto='dhcp'",
	}, "\n")
	firewallUCI := "firewall.@zone[0]=zone\nfirewall.@zone[0].name='lan'\nfirewall.@zone[0].network='lan'\n"

	env := vlan.Env{
		IsOpenWrt: func() bool { return true },
		ReadFile: func(path string) ([]byte, error) {
			if strings.HasSuffix(path, "board.json") {
				return []byte(boardJSON), nil
			}
			return nil, os.ErrNotExist
		},
		ListNetDevs: func() ([]string, error) {
			return []string{"lo", "eth0", "br-lan", "lan1", "lan2", "lan3", "lan4"}, nil
		},
		RunUCI: func(_ context.Context, args ...string) (string, error) {
			if len(args) >= 2 && args[0] == "show" {
				switch args[1] {
				case "network":
					return networkUCI, nil
				case "firewall":
					return firewallUCI, nil
				case "dhcp":
					return "dhcp.lan=dhcp\ndhcp.lan.interface='lan'\n", nil
				}
			}
			return "", nil
		},
	}

	svc := vlan.NewService(env)
	prev, err := svc.PreviewSave(t.Context(), "192.168.55.50", vlan.SaveSegmentRequest{
		ID:        "baidu_lan",
		VLANID:    8,
		IPAddr:    "192.168.89.1",
		Netmask:   "255.255.255.0",
		DHCPStart: 100,
		DHCPLimit: 150,
		LeaseTime: "12h",
		ProxyMode: vlan.ProxyModeDirect,
		Ports:     map[string]string{"lan3": vlan.PortModeAccess},
		Policy: vlan.SecurityPolicy{
			AllowWAN:        true,
			BlockRouterMgmt: true,
		},
	})
	if err != nil || !prev.Valid {
		t.Fatalf("PreviewSave failed: err=%v errors=%v", err, prev.Errors)
	}
	if !slices.Contains(prev.UCICommands, "set dhcp.baidu_lan.dhcpv4='server'") {
		t.Fatalf("expected set dhcp.baidu_lan.dhcpv4='server' in UCI commands, got:\n%s", strings.Join(prev.UCICommands, "\n"))
	}
}

func TestVLAN_ReloadOpenWrtServices_RestartsDnsmasq(t *testing.T) {
	t.Run("procd executes network reload, firewall reload, dnsmasq restart", func(t *testing.T) {
		mock := &procdMockManager{MockManager: servicemgr.NewMock()}
		if err := vlan.ReloadOpenWrtServices(t.Context(), mock, 5*time.Millisecond); err != nil {
			t.Fatalf("ReloadOpenWrtServices failed: %v", err)
		}
		want := []string{"reload network", "reload firewall", "restart dnsmasq"}
		if !slices.Equal(mock.Calls(), want) {
			t.Fatalf("unexpected service call sequence: got %v, want %v", mock.Calls(), want)
		}
	})

	t.Run("aggregates reload and restart errors without aborting remaining steps", func(t *testing.T) {
		mock := &procdMockManager{
			MockManager: servicemgr.NewMock(),
			reloadErr:   map[string]error{"firewall": errors.New("fw boom")},
			restartErr:  errors.New("dns boom"),
		}
		err := vlan.ReloadOpenWrtServices(t.Context(), mock, time.Millisecond)
		if err == nil || !strings.Contains(err.Error(), "fw boom") || !strings.Contains(err.Error(), "dns boom") {
			t.Fatalf("expected aggregated firewall + dnsmasq error, got: %v", err)
		}
		want := []string{"reload network", "reload firewall", "restart dnsmasq"}
		if !slices.Equal(mock.Calls(), want) {
			t.Fatalf("expected all steps attempted despite errors, got %v", mock.Calls())
		}
	})

	t.Run("non-procd manager is no-op", func(t *testing.T) {
		nonProcd := servicemgr.NewMock() // Kind() == InitSystemd
		if err := vlan.ReloadOpenWrtServices(t.Context(), nonProcd, time.Millisecond); err != nil {
			t.Fatalf("expected nil for non-procd manager, got: %v", err)
		}
		if len(nonProcd.Calls()) != 0 {
			t.Fatalf("expected 0 calls for non-procd manager, got %v", nonProcd.Calls())
		}
	})
}

func TestVLAN_SyncBridgeVLANL2Forward(t *testing.T) {
	t.Run("fw4 enable writes 0600 nft include, replaces stale handles idempotently", func(t *testing.T) {
		fw4Root := t.TempDir()
		var cmds []string
		nftList := "table inet fw4 {\n\tchain forward {\n\t\tiifname \"br-lan\" oifname \"br-lan\" accept comment \"singctl-vlan-br-l2\" # handle 77\n\t\tiifname \"br-lan.1\" accept # handle 12\n\t}\n}\n"
		runner := func(_ context.Context, name string, args ...string) ([]byte, error) {
			line := name + " " + strings.Join(args, " ")
			cmds = append(cmds, line)
			switch line {
			case "nft --version":
				return []byte("nftables v1.0.9"), nil
			case "nft -a list chain inet fw4 forward":
				return []byte(nftList), nil
			default:
				return nil, nil
			}
		}

		fw3Script := filepath.Join(t.TempDir(), "unused.fw3.sh")
		if err := vlan.SyncBridgeVLANL2Forward(t.Context(), true, fw4Root, fw3Script, runner); err != nil {
			t.Fatalf("SyncBridgeVLANL2Forward fw4 enable failed: %v", err)
		}

		nftFile := filepath.Join(fw4Root, "chain-pre", "forward", "singctl-vlan-br-l2.nft")
		st, err := os.Stat(nftFile)
		if err != nil || st.Mode().Perm() != 0600 {
			t.Fatalf("expected 0600 nft include at %s, err=%v mode=%v", nftFile, err, st.Mode().Perm())
		}
		raw, err := os.ReadFile(nftFile)
		if err != nil {
			t.Fatalf("read %s: %v", nftFile, err)
		}
		if !strings.Contains(string(raw), `iifname "br-lan" oifname "br-lan" accept comment "singctl-vlan-br-l2"`) {
			t.Fatalf("unexpected nft include content:\n%s", string(raw))
		}
		joined := strings.Join(cmds, "\n")
		if !strings.Contains(joined, "nft delete rule inet fw4 forward handle 77") {
			t.Fatalf("expected stale handle 77 deleted before insert, cmds:\n%s", joined)
		}
		if !strings.Contains(joined, "nft insert rule inet fw4 forward iifname br-lan oifname br-lan accept comment singctl-vlan-br-l2") {
			t.Fatalf("expected live nft insert rule command, cmds:\n%s", joined)
		}
		if _, statErr := os.Stat(fw3Script); !os.IsNotExist(statErr) {
			t.Fatalf("did not expect fw3 script written in fw4 mode, err=%v", statErr)
		}
	})

	t.Run("fw3 enable writes 0600 script without exit, configures iptables and UCI include", func(t *testing.T) {
		fw3Script := filepath.Join(t.TempDir(), "etc", "singctl", "vlan-br-l2.fw3.sh")
		missingFW4 := filepath.Join(t.TempDir(), "no-fw4")
		var cmds []string
		uciPresent := false
		runner := func(_ context.Context, name string, args ...string) ([]byte, error) {
			line := name + " " + strings.Join(args, " ")
			cmds = append(cmds, line)
			if line == "nft --version" {
				return nil, errors.New("nft not found")
			}
			if name == "uci" && len(args) == 3 && args[0] == "-q" && args[1] == "get" && args[2] == "firewall.singctl_vlan_br_l2" && !uciPresent {
				return nil, os.ErrNotExist
			}
			if line == "uci set firewall.singctl_vlan_br_l2=include" {
				uciPresent = true
			}
			if line == "iptables -w 2 -S FORWARD" {
				return []byte("-P FORWARD REJECT\n-A FORWARD -i br-lan -o br-lan -m comment --comment singctl-vlan-br-l2 -j ACCEPT\n"), nil
			}
			return nil, nil
		}

		if err := vlan.SyncBridgeVLANL2Forward(t.Context(), true, missingFW4, fw3Script, runner); err != nil {
			t.Fatalf("SyncBridgeVLANL2Forward fw3 enable failed: %v", err)
		}
		st, err := os.Stat(fw3Script)
		if err != nil || st.Mode().Perm() != 0600 {
			t.Fatalf("expected 0600 fw3 script %s, err=%v mode=%v", fw3Script, err, st.Mode().Perm())
		}
		raw, err := os.ReadFile(fw3Script)
		if err != nil {
			t.Fatalf("read fw3 script: %v", err)
		}
		scriptText := string(raw)
		if strings.Contains(scriptText, "exit ") || strings.Contains(scriptText, "\nexit\n") {
			t.Fatalf("fw3 include script MUST NOT contain exit statements:\n%s", scriptText)
		}
		if !strings.Contains(scriptText, "for ipt in iptables ip6tables") ||
			!strings.Contains(scriptText, "-w 2 -I FORWARD 1 -i br-lan -o br-lan -m comment --comment singctl-vlan-br-l2 -j ACCEPT") {
			t.Fatalf("fw3 script missing FORWARD br-lan accept rule:\n%s", scriptText)
		}
		joined := strings.Join(cmds, "\n")
		for _, wantCmd := range []string{
			"iptables -w 2 -D FORWARD -i br-lan -o br-lan -m comment --comment singctl-vlan-br-l2 -j ACCEPT",
			"iptables -w 2 -I FORWARD 1 -i br-lan -o br-lan -m comment --comment singctl-vlan-br-l2 -j ACCEPT",
			"uci set firewall.singctl_vlan_br_l2=include",
			"uci set firewall.singctl_vlan_br_l2.type=script",
			"uci set firewall.singctl_vlan_br_l2.path=" + fw3Script,
			"uci set firewall.singctl_vlan_br_l2.reload=1",
			"uci commit firewall",
		} {
			if !strings.Contains(joined, wantCmd) {
				t.Fatalf("missing expected fw3 command %q in:\n%s", wantCmd, joined)
			}
		}
	})

	t.Run("disable cleans fw4 include/handles and fw3 script/iptables/UCI idempotently", func(t *testing.T) {
		fw4Root := t.TempDir()
		nftDir := filepath.Join(fw4Root, "chain-pre", "forward")
		_ = os.MkdirAll(nftDir, 0700)
		nftFile := filepath.Join(nftDir, "singctl-vlan-br-l2.nft")
		_ = os.WriteFile(nftFile, []byte("stale\n"), 0600)

		fw3Script := filepath.Join(t.TempDir(), "vlan-br-l2.fw3.sh")
		_ = os.WriteFile(fw3Script, []byte("# stale\n"), 0600)

		var cmds []string
		runner := func(_ context.Context, name string, args ...string) ([]byte, error) {
			line := name + " " + strings.Join(args, " ")
			cmds = append(cmds, line)
			switch line {
			case "nft --version":
				return []byte("nftables v1.0.9"), nil
			case "nft -a list chain inet fw4 forward":
				return []byte("\t\tiifname \"br-lan\" oifname \"br-lan\" accept comment \"singctl-vlan-br-l2\" # handle 99\n"), nil
			case "iptables -w 2 -S FORWARD":
				return []byte("-A FORWARD -i br-lan -o br-lan -m comment --comment singctl-vlan-br-l2 -j ACCEPT\n"), nil
			case "ip6tables -w 2 -S FORWARD":
				return []byte("-A FORWARD -i br-lan -o br-lan -m comment --comment singctl-vlan-br-l2 -j ACCEPT\n"), nil
			case "uci -q get firewall.singctl_vlan_br_l2":
				return []byte("include"), nil
			default:
				return nil, nil
			}
		}

		if err := vlan.SyncBridgeVLANL2Forward(t.Context(), false, fw4Root, fw3Script, runner); err != nil {
			t.Fatalf("SyncBridgeVLANL2Forward disable failed: %v", err)
		}
		if _, err := os.Stat(nftFile); !os.IsNotExist(err) {
			t.Fatalf("expected %s removed, err=%v", nftFile, err)
		}
		if _, err := os.Stat(fw3Script); !os.IsNotExist(err) {
			t.Fatalf("expected %s removed, err=%v", fw3Script, err)
		}
		joined := strings.Join(cmds, "\n")
		for _, wantCmd := range []string{
			"nft delete rule inet fw4 forward handle 99",
			"iptables -w 2 -D FORWARD -i br-lan -o br-lan -m comment --comment singctl-vlan-br-l2 -j ACCEPT",
			"ip6tables -w 2 -D FORWARD -i br-lan -o br-lan -m comment --comment singctl-vlan-br-l2 -j ACCEPT",
			"uci delete firewall.singctl_vlan_br_l2",
			"uci commit firewall",
		} {
			if !strings.Contains(joined, wantCmd) {
				t.Fatalf("expected cleanup command %q in:\n%s", wantCmd, joined)
			}
		}
	})
}
