// 文件职责：验证 OpenWrt IPv6 PD 前缀解析、主路由 LAN RA/DHCPv6/dnsmasq 自动配置与安全备份还原。
package gateway_test

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"singctl/internal/config"
	"singctl/internal/gateway"
)

func TestParseOpenWrtIfstatusPDPrefix(t *testing.T) {
	sample := []byte(`{
		"up": true,
		"l3_device": "pppoe-wan",
		"ipv6-prefix": [
			{"address": "2001:db8:abcd::", "mask": 60}
		]
	}`)
	pfx, mask, ok := gateway.ParseOpenWrtIfstatusPDPrefix(sample)
	if !ok || pfx != "2001:db8:abcd::/60" || mask != 60 {
		t.Fatalf("expected 2001:db8:abcd::/60 mask=60 ok=true, got %q mask=%d ok=%v", pfx, mask, ok)
	}

	if _, _, ok := gateway.ParseOpenWrtIfstatusPDPrefix([]byte(`{"up":true}`)); ok {
		t.Fatal("expected ok=false when ipv6-prefix is missing")
	}
}

func TestControllerSyncIPv6Host_OpenWrtAutoConfigAndRestore(t *testing.T) {
	dir := t.TempDir()
	backupPath := filepath.Join(dir, "ipv6-uci-backup.json")

	var cmds []string
	ctrl := &gateway.Controller{
		StateDir:       dir,
		IPv6BackupPath: backupPath,
		IsOpenWrt:      func() bool { return true },
		Prober: func() gateway.TopologyInfo {
			return gateway.TopologyInfo{
				LANIP:    "192.168.1.1",
				LANCIDR:  "192.168.1.0/24",
				LANIface: "br-lan",
			}
		},
		Exec: func(name string, args ...string) ([]byte, error) {
			cmdLine := strings.TrimSpace(name + " " + strings.Join(args, " "))
			cmds = append(cmds, cmdLine)
			switch cmdLine {
			case "uci -q get network.lan.delegate":
				return []byte("0\n"), nil
			case "uci -q get network.lan.ip6assign":
				return []byte(""), os.ErrNotExist
			case "uci -q get dhcp.lan.ra":
				return []byte(""), os.ErrNotExist
			case "uci -q get dhcp.lan.dhcpv6":
				return []byte(""), os.ErrNotExist
			case "uci -q get dhcp.lan.ra_slaac":
				return []byte(""), os.ErrNotExist
			case "uci -q get dhcp.lan.ra_flags":
				return []byte(""), os.ErrNotExist
			case "uci -q get dhcp.lan.ra_dns":
				return []byte(""), os.ErrNotExist
			case "uci -q get dhcp.lan.dns_service":
				return []byte(""), os.ErrNotExist
			case "uci -q get dhcp.@dnsmasq[0].filter_aaaa":
				return []byte("1\n"), nil
			case "uci -q get dhcp.@dnsmasq[0].dnsforwardmax":
				return []byte(""), os.ErrNotExist
			case "ifstatus wan_6":
				return []byte(`{"up":true,"ipv6-prefix":[{"address":"2001:db8:10::","mask":60}]}`), nil
			}
			return nil, nil
		},
	}

	// 1. Side-router mode rejects non-off IPv6 mode cleanly
	if _, err := ctrl.SyncIPv6Host(t.Context(), config.GatewayConfig{Mode: "side", MainRouterIP: "192.168.1.254", IPv6Mode: "cn_only"}); err == nil {
		t.Fatal("expected SyncIPv6Host to reject non-off IPv6 mode in side router")
	}

	// 2. Enabling cn_only on OpenWrt main router creates 0600 backup, sets LAN RA/DHCPv6/dnsmasq, reloads softly without WAN restart
	resEnable, err := ctrl.SyncIPv6Host(t.Context(), config.GatewayConfig{Mode: "main", IPv6Mode: "cn_only"})
	if err != nil {
		t.Fatalf("SyncIPv6Host(cn_only) failed: %v", err)
	}
	if !resEnable.OpenWrtAutoApplied {
		t.Fatal("expected OpenWrtAutoApplied=true")
	}
	st, err := os.Stat(backupPath)
	if err != nil {
		t.Fatalf("expected backup file at %s: %v", backupPath, err)
	}
	if st.Mode().Perm() != 0600 {
		t.Fatalf("expected backup file mode 0600, got %o", st.Mode().Perm())
	}

	for _, wantCmd := range []string{
		"sysctl -w net.ipv6.conf.all.forwarding=1",
		"uci set network.lan.delegate=1",
		"uci set network.lan.ip6assign=64",
		"uci set dhcp.lan.ra=server",
		"uci set dhcp.lan.dhcpv6=server",
		"uci set dhcp.lan.ra_dns=0",
		"uci set dhcp.lan.dns_service=0",
		"uci set dhcp.@dnsmasq[0].filter_aaaa=0",
		"uci set dhcp.@dnsmasq[0].dnsforwardmax=1024",
		"ubus call network reload",
	} {
		if !slices.Contains(cmds, wantCmd) {
			t.Fatalf("expected command %q to run during cn_only enable; ran: %v", wantCmd, cmds)
		}
	}

	// 3. Disabling IPv6 restores original UCI settings and sets filter_aaaa=1
	cmds = nil
	resDisable, err := ctrl.SyncIPv6Host(t.Context(), config.GatewayConfig{Mode: "main", IPv6Mode: "off"})
	if err != nil {
		t.Fatalf("SyncIPv6Host(off) failed: %v", err)
	}
	if !resDisable.RestoredFromBackup {
		t.Fatal("expected RestoredFromBackup=true when returning to off")
	}
	if _, err := os.Stat(backupPath); !os.IsNotExist(err) {
		t.Fatalf("expected backup file to be removed after restore, err=%v", err)
	}
	for _, wantCmd := range []string{
		"uci set dhcp.@dnsmasq[0].filter_aaaa=1",
		"uci set network.lan.delegate=0",
		"uci -q delete dhcp.lan.ra",
		"uci -q delete dhcp.lan.dhcpv6",
		"uci -q delete dhcp.@dnsmasq[0].dnsforwardmax",
		"uci commit network",
		"uci commit dhcp",
	} {
		if !slices.Contains(cmds, wantCmd) {
			t.Fatalf("expected restore command %q; ran: %v", wantCmd, cmds)
		}
	}
}

func TestProbeIPv6Status_RADNSAnnounceAndBackupBackfill(t *testing.T) {
	dir := t.TempDir()
	backupPath := filepath.Join(dir, "ipv6-uci-backup.json")
	legacyBackup := `{"keys":{"network.lan.delegate":{"set":true,"value":"0"}}}`
	if err := os.WriteFile(backupPath, []byte(legacyBackup), 0600); err != nil {
		t.Fatalf("write legacy backup: %v", err)
	}

	raDNS := "1"
	dnsSvc := "0"
	fwdMax := "1024"
	topo := gateway.TopologyInfo{LANIP: "192.168.1.1", LANCIDR: "192.168.1.0/24", LANIface: "br-lan"}
	ctrl := &gateway.Controller{
		StateDir:       dir,
		IPv6BackupPath: backupPath,
		IsOpenWrt:      func() bool { return true },
		Prober: func() gateway.TopologyInfo {
			return topo
		},
		Exec: func(name string, args ...string) ([]byte, error) {
			switch strings.TrimSpace(name + " " + strings.Join(args, " ")) {
			case "uci -q get dhcp.lan.ra":
				return []byte("server\n"), nil
			case "uci -q get dhcp.lan.dhcpv6":
				return []byte("server\n"), nil
			case "uci -q get dhcp.lan.ra_dns":
				return []byte(raDNS + "\n"), nil
			case "uci -q get dhcp.lan.dns_service":
				return []byte(dnsSvc + "\n"), nil
			case "uci -q get dhcp.@dnsmasq[0].dnsforwardmax":
				return []byte(fwdMax + "\n"), nil
			case "ifstatus wan_6":
				return []byte(`{"up":true,"ipv6-prefix":[{"address":"2001:db8:10::","mask":60}]}`), nil
			}
			return nil, os.ErrNotExist
		},
	}

	gwCfg := config.GatewayConfig{Mode: "main", IPv6Mode: "cn_only"}
	stOneEnabled := ctrl.ProbeIPv6Status(t.Context(), gwCfg, topo)
	if !stOneEnabled.RADNSAnnounce {
		t.Fatal("expected RADNSAnnounce=true when ra_dns=1 even if dns_service=0")
	}
	if stOneEnabled.DnsmasqForwardMax != "1024" {
		t.Fatalf("expected DnsmasqForwardMax=1024, got %q", stOneEnabled.DnsmasqForwardMax)
	}

	raDNS = "0"
	stBothOff := ctrl.ProbeIPv6Status(t.Context(), gwCfg, topo)
	if stBothOff.RADNSAnnounce {
		t.Fatal("expected RADNSAnnounce=false when both ra_dns=0 and dns_service=0")
	}

	if _, err := ctrl.SyncIPv6Host(t.Context(), gwCfg); err != nil {
		t.Fatalf("SyncIPv6Host backfill failed: %v", err)
	}
	raw, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatalf("read backfilled backup: %v", err)
	}
	content := string(raw)
	if !strings.Contains(content, `"network.lan.delegate"`) || !strings.Contains(content, `"dhcp.@dnsmasq[0].dnsforwardmax"`) || !strings.Contains(content, `"1024"`) {
		t.Fatalf("expected legacy backup preserved and dnsforwardmax backfilled, got:\n%s", content)
	}
}

func TestProbeIPv6Status_SideRouterTreatsLANGUAAsIPv6Availability(t *testing.T) {
	tests := []struct {
		name          string
		side          bool
		kernelProbe   func() (bool, bool)
		probe         func(string) (bool, string, []string)
		wantAvailable bool
		wantWarning   string
	}{
		{
			name:          "side router inherits IPv6 on LAN",
			side:          true,
			probe:         func(string) (bool, string, []string) { return false, "2001:db8:10::2", []string{"2001:db8:10::/64"} },
			wantAvailable: true,
			wantWarning:   "已通过 LAN 口",
		},
		{
			name:          "side router without LAN GUA",
			side:          true,
			probe:         func(string) (bool, string, []string) { return false, "", nil },
			wantAvailable: false,
			wantWarning:   "LAN 口未检测到公网 IPv6",
		},
		{
			name:          "side router with kernel IPv6 disabled reports kernel warning first",
			side:          true,
			kernelProbe:   func() (bool, bool) { return false, false },
			probe:         func(string) (bool, string, []string) { return false, "", nil },
			wantAvailable: false,
			wantWarning:   "系统内核已禁用 IPv6",
		},
		{
			name:          "main router still requires WAN IPv6",
			probe:         func(string) (bool, string, []string) { return false, "2001:db8:10::2", []string{"2001:db8:10::/64"} },
			wantAvailable: false,
			wantWarning:   "WAN 口暂未检测到公网 IPv6",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := &gateway.Controller{
				IsOpenWrt: func() bool { return false },
				Exec: func(name string, args ...string) ([]byte, error) {
					if strings.TrimSpace(name+" "+strings.Join(args, " ")) == "ip -6 route show default" {
						return []byte("default via fe80::1 dev eth0 proto static\n"), nil
					}
					return nil, os.ErrNotExist
				},
				IPv6IfaceProbe:  tt.probe,
				IPv6KernelProbe: tt.kernelProbe,
			}
			mode := "main"
			if tt.side {
				mode = "side"
			}
			st := ctrl.ProbeIPv6Status(t.Context(), config.GatewayConfig{Mode: mode, MainRouterIP: "192.168.1.1"}, gateway.TopologyInfo{LANIface: "eth0"})
			if st.HasPublicIPv6 != tt.wantAvailable {
				t.Fatalf("expected HasPublicIPv6=%v, got %v (lanGua=%q prefixes=%v)", tt.wantAvailable, st.HasPublicIPv6, st.LANGUA, st.LANPrefixes)
			}
			if !slices.ContainsFunc(st.Warnings, func(w string) bool { return strings.Contains(w, tt.wantWarning) }) {
				t.Fatalf("expected warning containing %q, got %v", tt.wantWarning, st.Warnings)
			}
		})
	}
}
