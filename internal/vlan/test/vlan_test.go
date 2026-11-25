// 文件职责：以真实 n60pro (DSA)、ax3000t (swconfig)、n4120 (x86 软路由) UCI 样本覆盖 VLAN 拓扑探测、校验、防锁死、代理绕行与并发安全测试。
package vlan_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"singctl/internal/vlan"
)

const sampleN60ProBoardJSON = `{
  "model": { "id": "netcore,n60pro", "name": "Netcore N60 Pro" },
  "network": {
    "lan": { "ports": ["lan0", "lan1", "lan2", "lan3", "lan4", "lan5"], "protocol": "static" },
    "wan": { "device": "eth1", "protocol": "dhcp" }
  }
}`

const sampleN60ProNetworkUCI = `network.loopback=interface
network.loopback.device='lo'
network.loopback.proto='static'
network.loopback.ipaddr='127.0.0.1'
network.@device[0]=device
network.@device[0].name='br-lan'
network.@device[0].type='bridge'
network.@device[0].ports='lan1' 'lan2' 'lan3' 'lan4'
network.lan=interface
network.lan.device='br-lan'
network.lan.proto='static'
network.lan.ipaddr='192.168.29.1'
network.lan.netmask='255.255.255.0'
network.wan=interface
network.wan.proto='dhcp'
network.wan.device='eth1'
network.@bridge-vlan[0]=bridge-vlan
network.@bridge-vlan[0].device='br-lan'
network.@bridge-vlan[0].vlan='27'
network.@bridge-vlan[0].ports='lan1' 'lan2:u*' 'lan3:t' 'lan4'
network.@bridge-vlan[1]=bridge-vlan
network.@bridge-vlan[1].device='br-lan'
network.@bridge-vlan[1].vlan='28'
network.@bridge-vlan[1].ports='lan1' 'lan2' 'lan3:t' 'lan4:u*'
network.wifi=interface
network.wifi.proto='static'
network.wifi.device='br-lan.27'
network.wifi.ipaddr='192.168.10.1'
network.wifi.netmask='255.255.255.0'
network.wifi.ip6assign='64'
network.iot=interface
network.iot.proto='static'
network.iot.device='br-lan.28'
network.iot.ipaddr='192.168.20.1'
network.iot.netmask='255.255.255.0'
network.tailscale=interface
network.tailscale.device='tailscale0'
network.tailscale.proto='unmanaged'
`

const sampleN60ProWirelessUCI = `wireless.MT7986_1_1=wifi-device
wireless.MT7986_1_1.type='mtwifi'
wireless.MT7986_1_1.phy='ra0'
wireless.MT7986_1_1.band='2g'
wireless.default_MT7986_1_1=wifi-iface
wireless.default_MT7986_1_1.device='MT7986_1_1'
wireless.default_MT7986_1_1.mode='ap'
wireless.default_MT7986_1_1.network='iot'
wireless.default_MT7986_1_1.ssid='IoT-Example'
wireless.default_MT7986_1_1.key='SuperSecretWiFiPass123'
wireless.default_MT7986_1_1.isolate='1'
wireless.default_MT7986_1_1.encryption='psk2'
wireless.MT7986_1_2=wifi-device
wireless.MT7986_1_2.type='mtwifi'
wireless.MT7986_1_2.phy='rax0'
wireless.MT7986_1_2.band='5g'
wireless.default_MT7986_1_2=wifi-iface
wireless.default_MT7986_1_2.device='MT7986_1_2'
wireless.default_MT7986_1_2.mode='ap'
wireless.default_MT7986_1_2.network='wifi'
wireless.default_MT7986_1_2.ssid='Home-5G-Example'
wireless.default_MT7986_1_2.key='AnotherSecret456'
wireless.default_MT7986_1_2.encryption='sae-mixed'
`

const sampleN60ProDHCP = `dhcp.lan=dhcp
dhcp.lan.interface='lan'
dhcp.lan.start='100'
dhcp.lan.limit='150'
dhcp.lan.leasetime='12h'
dhcp.lan.ra='server'
dhcp.lan.dhcpv6='server'
dhcp.wifi=dhcp
dhcp.wifi.interface='wifi'
dhcp.wifi.start='100'
dhcp.wifi.limit='150'
dhcp.wifi.leasetime='12h'
dhcp.wifi.ra='relay'
dhcp.wifi.dhcpv6='relay'
dhcp.iot=dhcp
dhcp.iot.interface='iot'
dhcp.iot.start='100'
dhcp.iot.limit='150'
dhcp.iot.leasetime='12h'
`

const sampleN60ProFirewall = `firewall.@zone[0]=zone
firewall.@zone[0].name='lan'
firewall.@zone[0].input='ACCEPT'
firewall.@zone[0].output='ACCEPT'
firewall.@zone[0].forward='ACCEPT'
firewall.@zone[0].network='lan'
firewall.@zone[1]=zone
firewall.@zone[1].name='wan'
firewall.@zone[1].network='wan' 'wan6'
firewall.@zone[2]=zone
firewall.@zone[2].name='wifi'
firewall.@zone[2].input='ACCEPT'
firewall.@zone[2].output='ACCEPT'
firewall.@zone[2].forward='REJECT'
firewall.@zone[2].network='wifi'
firewall.@forwarding[1]=forwarding
firewall.@forwarding[1].src='wifi'
firewall.@forwarding[1].dest='wan'
firewall.@zone[3]=zone
firewall.@zone[3].name='iot'
firewall.@zone[3].input='ACCEPT'
firewall.@zone[3].output='ACCEPT'
firewall.@zone[3].forward='REJECT'
firewall.@zone[3].network='iot'
firewall.@forwarding[2]=forwarding
firewall.@forwarding[2].src='iot'
firewall.@forwarding[2].dest='wan'
firewall.wifi_to_iot=forwarding
firewall.wifi_to_iot.src='wifi'
firewall.wifi_to_iot.dest='iot'
firewall.@rule[11]=rule
firewall.@rule[11].name='Allow-HA-to-IoT'
firewall.@rule[11].src='wan'
firewall.@rule[11].dest='iot'
firewall.@rule[11].src_ip='192.168.1.0/24'
firewall.@rule[11].target='ACCEPT'
firewall.@rule[13]=rule
firewall.@rule[13].name='Allow-mDNS-WAN'
firewall.@rule[13].src='wan'
firewall.@rule[13].proto='udp'
firewall.@rule[13].dest_port='5353'
firewall.@rule[13].target='ACCEPT'
firewall.@rule[14]=rule
firewall.@rule[14].name='Block-IoT-to-MainLAN'
firewall.@rule[14].src='iot'
firewall.@rule[14].dest='wan'
firewall.@rule[14].dest_ip='192.168.1.0/24'
firewall.@rule[14].target='REJECT'
firewall.@rule[15]=rule
firewall.@rule[15].name='Block-IoT-to-Router-Mgmt'
firewall.@rule[15].src='iot'
firewall.@rule[15].dest_port='22 80 443'
firewall.@rule[15].proto='tcp'
firewall.@rule[15].target='REJECT'
`

const sampleAX3000TNetworkUCI = `network.@device[0]=device
network.@device[0].name='br-lan'
network.@device[0].type='bridge'
network.@device[0].ports='eth0.1'
network.lan=interface
network.lan.device='br-lan'
network.lan.proto='static'
network.lan.ipaddr='192.168.50.1'
network.lan.netmask='255.255.255.0'
network.wan=interface
network.wan.device='eth0.2'
network.wan.proto='dhcp'
network.@switch[0]=switch
network.@switch[0].name='switch0'
network.@switch[0].enable_vlan='1'
network.@switch_vlan[0]=switch_vlan
network.@switch_vlan[0].device='switch0'
network.@switch_vlan[0].vlan='1'
network.@switch_vlan[0].vid='1'
network.@switch_vlan[0].ports='5t 1'
network.@switch_vlan[1]=switch_vlan
network.@switch_vlan[1].device='switch0'
network.@switch_vlan[1].vlan='2'
network.@switch_vlan[1].vid='2'
network.@switch_vlan[1].ports='5t 0'
network.@switch_vlan[2]=switch_vlan
network.@switch_vlan[2].device='switch0'
network.@switch_vlan[2].vlan='3'
network.@switch_vlan[2].vid='3'
network.@switch_vlan[2].ports='5t 3'
network.@device[3]=device
network.@device[3].type='bridge'
network.@device[3].name='iot-br'
network.@device[3].ports='eth0.3'
network.iot=interface
network.iot.proto='static'
network.iot.device='iot-br'
network.iot.ipaddr='192.168.34.1'
network.iot.netmask='255.255.255.0'
network.@switch_vlan[3]=switch_vlan
network.@switch_vlan[3].device='switch0'
network.@switch_vlan[3].vlan='4'
network.@switch_vlan[3].vid='8'
network.@switch_vlan[3].ports='5t 2'
network.@device[4]=device
network.@device[4].type='bridge'
network.@device[4].name='br-v8'
network.@device[4].ports='eth0.8'
network.baidu_lan=interface
network.baidu_lan.proto='static'
network.baidu_lan.device='br-v8'
network.baidu_lan.ipaddr='192.168.89.1'
network.baidu_lan.netmask='255.255.255.0'
`

const sampleAX3000TWirelessUCI = `wireless.MT7981_1_1=wifi-device
wireless.MT7981_1_1.type='mtwifi'
wireless.MT7981_1_1.phy='ra0'
wireless.MT7981_1_1.band='2g'
wireless.default_MT7981_1_1=wifi-iface
wireless.default_MT7981_1_1.device='MT7981_1_1'
wireless.default_MT7981_1_1.mode='ap'
wireless.default_MT7981_1_1.ssid='Office-2.4G'
wireless.default_MT7981_1_1.network='baidu_lan'
wireless.default_MT7981_1_1.encryption='sae-mixed'
wireless.default_MT7981_1_1.key='SecretKey1'
wireless.wifinet2=wifi-iface
wireless.wifinet2.device='MT7981_1_1'
wireless.wifinet2.mode='ap'
wireless.wifinet2.ssid='IoT-Net'
wireless.wifinet2.network='iot'
wireless.wifinet2.isolate='1'
wireless.wifinet2.encryption='psk2'
wireless.wifinet2.key='SecretKey2'
`

const sampleN4120NetworkUCI = `network.@device[0]=device
network.@device[0].name='br-lan'
network.@device[0].type='bridge'
network.@device[0].ports='eth0' 'eth2' 'eth3'
network.lan=interface
network.lan.device='br-lan'
network.lan.proto='static'
network.lan.ipaddr='192.168.1.1'
network.lan.netmask='255.255.255.0'
network.wan=interface
network.wan.proto='pppoe'
network.wan.device='eth1'
`

func newN60ProEnv(t *testing.T) (vlan.Env, *[]string, *[]string, *bool) {
	t.Helper()
	tmpDir := t.TempDir()
	bypassFile := filepath.Join(tmpDir, "vlan-proxy-bypass.list")
	if err := os.WriteFile(bypassFile, []byte("192.168.20.0/24\n"), 0600); err != nil {
		t.Fatal(err)
	}
	leasesFile := filepath.Join(tmpDir, "dhcp.leases")
	leasesData := "1795500000 aa:bb:cc:dd:ee:01 192.168.10.105 laptop *\n" +
		"1795500000 aa:bb:cc:dd:ee:02 192.168.10.106 phone *\n" +
		"1795500000 aa:bb:cc:dd:ee:03 192.168.20.110 camera *\n"
	if err := os.WriteFile(leasesFile, []byte(leasesData), 0600); err != nil {
		t.Fatal(err)
	}

	var batchLog []string
	var syncedBypass []string
	reloaded := false

	files := map[string]string{
		"/etc/board.json":              sampleN60ProBoardJSON,
		"/sys/class/net/eth1/carrier":  "1\n",
		"/sys/class/net/eth1/speed":    "2500\n",
		"/sys/class/net/lan1/carrier":  "1\n",
		"/sys/class/net/lan1/speed":    "1000\n",
		"/sys/class/net/lan2/carrier":  "1\n",
		"/sys/class/net/lan2/speed":    "1000\n",
		"/sys/class/net/lan3/carrier":  "0\n",
		"/sys/class/net/lan3/speed":    "-1\n",
		"/sys/class/net/lan4/carrier":  "0\n",
		"/sys/class/net/lan4/speed":    "-1\n",
		leasesFile:                     leasesData,
	}

	env := vlan.Env{
		IsOpenWrt: func() bool { return true },
		RunUCI: func(_ context.Context, args ...string) (string, error) {
			if len(args) == 2 && args[0] == "show" {
				switch args[1] {
				case "network":
					return sampleN60ProNetworkUCI, nil
				case "wireless":
					return sampleN60ProWirelessUCI, nil
				case "dhcp":
					return sampleN60ProDHCP, nil
				case "firewall":
					return sampleN60ProFirewall, nil
				}
			}
			return "", errors.New("unexpected uci call")
		},
		BatchUCI: func(_ context.Context, cmds []string) error {
			batchLog = append(batchLog, cmds...)
			return nil
		},
		ReloadNetwork: func(_ context.Context) error {
			reloaded = true
			return nil
		},
		SyncProxyBypass: func(_ context.Context, cidrs []string) error {
			syncedBypass = slices.Clone(cidrs)
			return vlan.WriteProxyBypassList(bypassFile, cidrs)
		},
		ReadFile: func(p string) ([]byte, error) {
			if v, ok := files[p]; ok {
				return []byte(v), nil
			}
			return os.ReadFile(p)
		},
		ListNetDevs: func() ([]string, error) {
			return []string{"lo", "eth0", "eth1", "lan1", "lan2", "lan3", "lan4", "br-lan", "br-lan.27", "br-lan.28", "ra0", "rax0"}, nil
		},
		ReadIPv4Addrs: func() (map[string]string, error) {
			return map[string]string{
				"eth1":      "192.168.1.151/24",
				"br-lan":    "192.168.29.1/24",
				"br-lan.27": "192.168.10.1/24",
				"br-lan.28": "192.168.20.1/24",
			}, nil
		},
		ProxyBypassFile: bypassFile,
		BoardJSONPath:   "/etc/board.json",
		DHCPLeasesPath:  leasesFile,
	}
	return env, &batchLog, &syncedBypass, &reloaded
}

func TestOverview_N60ProDSAParsingAndSecurityRedaction(t *testing.T) {
	env, _, _, _ := newN60ProEnv(t)
	svc := vlan.NewService(env)

	ov, err := svc.Overview(t.Context(), "192.168.10.179")
	if err != nil {
		t.Fatalf("Overview failed: %v", err)
	}
	if !ov.Supported || ov.Driver != vlan.DriverDSA {
		t.Fatalf("expected Supported=true Driver=dsa, got supported=%v driver=%q", ov.Supported, ov.Driver)
	}
	if ov.BoardModel != "Netcore N60 Pro" {
		t.Fatalf("BoardModel=%q, want Netcore N60 Pro", ov.BoardModel)
	}
	if ov.WANSubnet != "192.168.1.0/24" || ov.CallerSegmentID != "wifi" {
		t.Fatalf("WANSubnet=%q CallerSegmentID=%q, want 192.168.1.0/24 & wifi", ov.WANSubnet, ov.CallerSegmentID)
	}

	// Phantom lan0/lan5 from board.json must be filtered out; must only have eth1 + lan1..lan4 = 5 ports.
	if len(ov.Ports) != 5 {
		t.Fatalf("expected 5 physical ports (eth1 + lan1..lan4), got %d: %+v", len(ov.Ports), ov.Ports)
	}
	if !ov.Ports[0].IsWAN || ov.Ports[0].SpeedMbps != 2500 || !ov.Ports[0].LinkUp {
		t.Fatalf("unexpected WAN port info: %+v", ov.Ports[0])
	}

	// Verify Wi-Fi passwords are NEVER leaked in Overview.
	for _, ssid := range ov.ExistingSSIDs {
		if !ssid.PasswordConfigured {
			t.Errorf("expected PasswordConfigured=true for %q", ssid.SSID)
		}
	}

	// Verify segments: lan, wifi (2 clients, caller mgmt), iot (1 client, direct proxy mode, isolated).
	segByID := make(map[string]vlan.Segment, len(ov.Segments))
	for _, seg := range ov.Segments {
		segByID[seg.ID] = seg
		if seg.Wireless != nil && seg.Wireless.Password != "" {
			t.Fatalf("segment %s leaked plaintext Wi-Fi password!", seg.ID)
		}
	}
	wifiSeg, ok := segByID["wifi"]
	if !ok || wifiSeg.VLANID != 27 || !wifiSeg.IsCallerMgmt || wifiSeg.OnlineClients != 2 || wifiSeg.ProxyMode != vlan.ProxyModeFollow {
		t.Fatalf("unexpected wifi segment: %+v", wifiSeg)
	}
	iotSeg, ok := segByID["iot"]
	if !ok || iotSeg.VLANID != 28 || iotSeg.OnlineClients != 1 || iotSeg.ProxyMode != vlan.ProxyModeDirect {
		t.Fatalf("unexpected iot segment: %+v", iotSeg)
	}
	if !iotSeg.Policy.BlockRouterMgmt || !iotSeg.Policy.BlockUpstreamLAN || !iotSeg.Policy.AllowMDNS {
		t.Fatalf("unexpected iot security policy: %+v", iotSeg.Policy)
	}
	if iotSeg.Wireless == nil || iotSeg.Wireless.SSID != "IoT-Example" || !iotSeg.Wireless.Isolate {
		t.Fatalf("unexpected iot wireless spec: %+v", iotSeg.Wireless)
	}
	if len(ov.Presets) != 4 {
		t.Fatalf("expected 4 scenario presets, got %d", len(ov.Presets))
	}
	// Suggested preset subnet/VLAN must avoid 27, 28, 29, 31.
	for _, p := range ov.Presets {
		if p.SuggestedVLANID == 27 || p.SuggestedVLANID == 28 || p.SuggestedIPAddr == "192.168.10.1" || p.SuggestedIPAddr == "192.168.20.1" || p.SuggestedIPAddr == "192.168.29.1" || p.SuggestedIPAddr == "192.168.1.1" {
			t.Errorf("preset %s suggested conflicting VLAN/IP: vid=%d ip=%s", p.ID, p.SuggestedVLANID, p.SuggestedIPAddr)
		}
	}
}

func TestOverview_AX3000TSwconfigAndN4120SoftRouter(t *testing.T) {
	t.Run("ax3000t_swconfig", func(t *testing.T) {
		env := vlan.Env{
			IsOpenWrt: func() bool { return true },
			RunUCI: func(_ context.Context, args ...string) (string, error) {
				if len(args) == 2 && args[0] == "show" {
					switch args[1] {
					case "network":
						return sampleAX3000TNetworkUCI, nil
					case "wireless":
						return sampleAX3000TWirelessUCI, nil
					default:
						return "", nil
					}
				}
				return "", nil
			},
			ReadFile: func(string) ([]byte, error) { return nil, os.ErrNotExist },
			ListNetDevs: func() ([]string, error) {
				return []string{"lo", "eth0", "eth0.1", "eth0.2", "eth0.3", "eth0.8", "br-lan", "iot-br", "br-v8"}, nil
			},
			ReadIPv4Addrs: func() (map[string]string, error) {
				return map[string]string{
					"eth0.2": "192.168.3.181/24",
					"br-lan": "192.168.50.1/24",
					"iot-br": "192.168.34.1/24",
					"br-v8":  "192.168.89.1/24",
				}, nil
			},
			ProxyBypassFile: filepath.Join(t.TempDir(), "bypass.list"),
		}
		ov, err := vlan.NewService(env).Overview(t.Context(), "192.168.50.10")
		if err != nil {
			t.Fatalf("ax3000t Overview failed: %v", err)
		}
		if !ov.Supported || ov.Driver != vlan.DriverSwconfig {
			t.Fatalf("expected swconfig driver, got supported=%v driver=%q", ov.Supported, ov.Driver)
		}
		if len(ov.Ports) != 4 {
			t.Fatalf("expected 4 swconfig ports (0..3), got %d: %+v", len(ov.Ports), ov.Ports)
		}
		foundBaidu := false
		for _, seg := range ov.Segments {
			if seg.ID == "baidu_lan" && seg.VLANID == 8 && seg.IPAddr == "192.168.89.1" {
				foundBaidu = true
			}
		}
		if !foundBaidu {
			t.Fatalf("expected baidu_lan (VID 8, 192.168.89.1) parsed from swconfig, got: %+v", ov.Segments)
		}
	})

	t.Run("n4120_x86_softrouter_no_wifi", func(t *testing.T) {
		env := vlan.Env{
			IsOpenWrt: func() bool { return true },
			RunUCI: func(_ context.Context, args ...string) (string, error) {
				if len(args) == 2 && args[0] == "show" && args[1] == "network" {
					return sampleN4120NetworkUCI, nil
				}
				return "", nil
			},
			ReadFile: func(string) ([]byte, error) { return nil, os.ErrNotExist },
			ListNetDevs: func() ([]string, error) {
				return []string{"lo", "eth0", "eth1", "eth2", "eth3", "br-lan"}, nil
			},
			ReadIPv4Addrs: func() (map[string]string, error) {
				return map[string]string{"br-lan": "192.168.1.1/24"}, nil
			},
			ProxyBypassFile: filepath.Join(t.TempDir(), "bypass.list"),
		}
		ov, err := vlan.NewService(env).Overview(t.Context(), "192.168.1.50")
		if err != nil {
			t.Fatalf("n4120 Overview failed: %v", err)
		}
		if !ov.Supported || ov.Driver != vlan.DriverSoftRouter {
			t.Fatalf("expected softrouter driver, got supported=%v driver=%q", ov.Supported, ov.Driver)
		}
		if len(ov.Radios) != 0 {
			t.Fatalf("expected 0 wireless radios on x86 softrouter, got %d", len(ov.Radios))
		}
	})

	t.Run("non_openwrt_graceful_unsupported", func(t *testing.T) {
		ov, err := vlan.NewService(vlan.Env{
			IsOpenWrt: func() bool { return false },
		}).Overview(t.Context(), "192.168.1.10")
		if err != nil {
			t.Fatalf("non-OpenWrt Overview should not return error, got: %v", err)
		}
		if ov.Supported || ov.Driver != vlan.DriverUnsupported {
			t.Fatalf("expected Supported=false Driver=unsupported, got %+v", ov)
		}
	})
}

func TestSaveAndDelete_ValidationAntiLockoutAndApply(t *testing.T) {
	env, batchLog, syncedBypass, reloaded := newN60ProEnv(t)
	svc := vlan.NewService(env)

	badCases := []struct {
		name string
		req  vlan.SaveSegmentRequest
	}{
		{
			name: "reserved_id_wan",
			req:  vlan.SaveSegmentRequest{ID: "wan", VLANID: 30, IPAddr: "192.168.30.1"},
		},
		{
			name: "injection_in_id",
			req:  vlan.SaveSegmentRequest{ID: "guest;rm", VLANID: 30, IPAddr: "192.168.30.1"},
		},
		{
			name: "invalid_vlan_id_1",
			req:  vlan.SaveSegmentRequest{ID: "guest", VLANID: 1, IPAddr: "192.168.30.1"},
		},
		{
			name: "subnet_overlaps_wan",
			req:  vlan.SaveSegmentRequest{ID: "guest", VLANID: 30, IPAddr: "192.168.1.1"},
		},
		{
			name: "subnet_overlaps_tailscale_cgnat",
			req:  vlan.SaveSegmentRequest{ID: "guest", VLANID: 30, IPAddr: "100.64.10.1"},
		},
		{
			name: "public_ip_rejected",
			req:  vlan.SaveSegmentRequest{ID: "guest", VLANID: 30, IPAddr: "203.0.113.1"},
		},
		{
			name: "assign_wan_port_rejected",
			req:  vlan.SaveSegmentRequest{ID: "guest", VLANID: 30, IPAddr: "192.168.30.1", Ports: map[string]string{"eth1": vlan.PortModeAccess}},
		},
		{
			name: "newline_injection_in_ssid",
			req: vlan.SaveSegmentRequest{
				ID: "guest", VLANID: 30, IPAddr: "192.168.30.1",
				Wireless: &vlan.WirelessSpec{Enabled: true, Radio: "MT7986_1_1", SSID: "Guest\nEvil", Password: "password123"},
			},
		},
		{
			name: "short_wifi_password",
			req: vlan.SaveSegmentRequest{
				ID: "guest", VLANID: 30, IPAddr: "192.168.30.1",
				Wireless: &vlan.WirelessSpec{Enabled: true, Radio: "MT7986_1_1", SSID: "Guest-WiFi", Password: "123"},
			},
		},
		{
			name: "modify_caller_mgmt_segment_blocked_without_override",
			req:  vlan.SaveSegmentRequest{ID: "wifi", VLANID: 27, IPAddr: "192.168.40.1"},
		},
	}

	for _, tc := range badCases {
		t.Run("reject_"+tc.name, func(t *testing.T) {
			prev, err := svc.PreviewSave(t.Context(), "192.168.10.179", tc.req)
			if err != nil {
				t.Fatalf("PreviewSave should report validation errors in result, got err=%v", err)
			}
			if prev.Valid || len(prev.Errors) == 0 {
				t.Fatalf("expected invalid preview for %s, got valid=%v errors=%v", tc.name, prev.Valid, prev.Errors)
			}
			if _, applyErr := svc.ApplySave(t.Context(), "192.168.10.179", tc.req); applyErr == nil {
				t.Fatalf("expected ApplySave to reject %s", tc.name)
			}
		})
	}

	// Deleting caller's own active management segment ("wifi") must be blocked.
	if prevDel, err := svc.PreviewDelete(t.Context(), "192.168.10.179", "wifi"); err != nil || prevDel.Valid {
		t.Fatalf("expected PreviewDelete on caller mgmt segment 'wifi' blocked, got valid=%v err=%v", prevDel.Valid, err)
	}
	if _, err := svc.ApplyDelete(t.Context(), "192.168.10.179", "wifi"); err == nil {
		t.Fatal("expected ApplyDelete on caller mgmt segment 'wifi' rejected")
	}

	// Valid creation of Guest VLAN 30 with direct proxy bypass + Wi-Fi + LAN3 access port.
	goodReq := vlan.SaveSegmentRequest{
		ID:          "guest",
		DisplayName: "访客隔离网",
		Preset:      vlan.PresetGuest,
		VLANID:      30,
		IPAddr:      "192.168.30.1",
		Netmask:     "255.255.255.0",
		DHCPStart:   100,
		DHCPLimit:   100,
		LeaseTime:   "2h",
		IPv6Mode:    vlan.IPv6Off,
		ProxyMode:   vlan.ProxyModeDirect,
		Ports:       map[string]string{"lan3": vlan.PortModeAccess},
		Wireless: &vlan.WirelessSpec{
			Enabled:    true,
			Radio:      "MT7986_1_1",
			SSID:       "Guest-Example",
			Password:   "GuestPass1234",
			Encryption: "psk2",
			Isolate:    true,
		},
		Policy: vlan.SecurityPolicy{
			AllowWAN:         true,
			BlockRouterMgmt:  true,
			BlockUpstreamLAN: true,
		},
	}

	prev, err := svc.PreviewSave(t.Context(), "192.168.10.179", goodReq)
	if err != nil || !prev.Valid {
		t.Fatalf("expected valid preview for guest VLAN, got err=%v errors=%v", err, prev.Errors)
	}
	if len(prev.PlainSummary) == 0 || len(prev.UCICommands) == 0 {
		t.Fatalf("expected non-empty PlainSummary and UCICommands: %+v", prev)
	}
	if !slices.Contains(prev.ProxyBypassCIDRs, "192.168.30.0/24") || !slices.Contains(prev.ProxyBypassCIDRs, "192.168.20.0/24") {
		t.Fatalf("expected both existing 192.168.20.0/24 and new 192.168.30.0/24 in ProxyBypassCIDRs, got %v", prev.ProxyBypassCIDRs)
	}
	if !strings.Contains(prev.UpstreamRouteHint, "192.168.30.0/24") {
		t.Fatalf("expected UpstreamRouteHint mentioning 192.168.30.0/24, got %q", prev.UpstreamRouteHint)
	}
	if !slices.Contains(prev.UCICommands, "set network.singctl_bv_guest.local='1'") {
		t.Fatalf("expected bridge-vlan local='1' for OpenWrt 21.02+/DSA CPU port reachability, got %v", prev.UCICommands)
	}
	if !slices.Contains(prev.UCICommands, "set network.guest.type='bridge'") {
		t.Fatalf("expected wireless-bound DSA interface to include type='bridge' (mtwifi/ImmortalWrt compat), got %v", prev.UCICommands)
	}
	if !slices.Contains(prev.UCICommands, "set network.singctl_bv_lan.vlan='1'") ||
		!slices.Contains(prev.UCICommands, "set network.lan.device='br-lan.1'") {
		t.Fatalf("expected DSA VLAN-1 preservation (singctl_bv_lan + network.lan.device='br-lan.1') to prevent LAN lockout when vlan_filtering activates, got %v", prev.UCICommands)
	}
	if slices.Contains(prev.UCICommands, "add_list network.singctl_bv_lan.ports='lan3:u*'") {
		t.Fatalf("port lan3 assigned as access to guest must NOT remain untagged in VLAN 1: %v", prev.UCICommands)
	}
	if !slices.Contains(prev.UCICommands, "add_list network.singctl_bv_lan.ports='lan1:u*'") {
		t.Fatalf("remaining LAN port lan1 must stay untagged in VLAN 1: %v", prev.UCICommands)
	}

	res, err := svc.ApplySave(t.Context(), "192.168.10.179", goodReq)
	if err != nil || !res.OK {
		t.Fatalf("ApplySave failed: err=%v res=%+v", err, res)
	}
	if !*reloaded {
		t.Fatal("expected ReloadNetwork to be called after ApplySave")
	}
	if !slices.Contains(*syncedBypass, "192.168.30.0/24") {
		t.Fatalf("expected syncedBypass to include 192.168.30.0/24, got %v", *syncedBypass)
	}
	joinedCmds := strings.Join(*batchLog, "\n")
	for _, want := range []string{
		"network.guest=interface",
		"network.guest.device='br-lan.30'",
		"dhcp.guest=dhcp",
		"wireless.singctl_vlan_guest=wifi-iface",
		"firewall.singctl_zone_guest=zone",
		"firewall.singctl_block_mgmt_guest=rule",
		"firewall.singctl_block_up_guest=rule",
	} {
		if !strings.Contains(joinedCmds, want) {
			t.Errorf("BatchUCI missing %q\n--- cmds ---\n%s", want, joinedCmds)
		}
	}

	// Verify bypass file permission is 0600.
	st, err := os.Stat(env.ProxyBypassFile)
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("proxy bypass file stat err=%v perm=%o (want 0600)", err, st.Mode().Perm())
	}

	// Concurrent -race check on Overview and PreviewSave.
	var wg sync.WaitGroup
	for range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = svc.Overview(t.Context(), "192.168.10.179")
			_, _ = svc.PreviewSave(t.Context(), "192.168.10.179", goodReq)
		}()
	}
	wg.Wait()
}

func TestSwconfigDedup_DirtyWirelessSkipReload_AndDMAHeadroom(t *testing.T) {
	axNetWithDups := `network.loopback=interface
network.loopback.device='lo'
network.loopback.proto='static'
network.loopback.ipaddr='127.0.0.1'
network.lan=interface
network.lan.device='br-lan'
network.lan.proto='static'
network.lan.ipaddr='192.168.50.1'
network.lan.netmask='255.255.255.0'
network.wan=interface
network.wan.device='eth0.2'
network.wan.proto='dhcp'
network.@switch[0]=switch
network.@switch[0].name='switch0'
network.@switch[0].enable_vlan='1'
network.@switch_vlan[0]=switch_vlan
network.@switch_vlan[0].device='switch0'
network.@switch_vlan[0].vlan='1'
network.@switch_vlan[0].vid='1'
network.@switch_vlan[0].ports='0 1 2 6t'
network.@switch_vlan[1]=switch_vlan
network.@switch_vlan[1].device='switch0'
network.@switch_vlan[1].vlan='3'
network.@switch_vlan[1].vid='3'
network.@switch_vlan[1].ports='3 6t'
network.@device[3]=device
network.@device[3].name='iot-br'
network.@device[3].type='bridge'
network.@device[3].ports='eth0.3'
network.singctl_br_iot=device
network.singctl_br_iot.name='iot-br'
network.singctl_br_iot.type='bridge'
network.singctl_br_iot.ports='eth0.3'
network.iot=interface
network.iot.proto='static'
network.iot.device='iot-br'
network.iot.type='bridge'
network.iot.ipaddr='192.168.34.1'
network.iot.netmask='255.255.255.0'
`
	axWireless := `wireless.MT7981_1_1=wifi-device
wireless.MT7981_1_1.type='mtwifi'
wireless.MT7981_1_1.band='2g'
wireless.iot_2g=wifi-iface
wireless.iot_2g.device='MT7981_1_1'
wireless.iot_2g.mode='ap'
wireless.iot_2g.network='iot'
wireless.iot_2g.ssid='IoT-2G'
wireless.iot_2g.encryption='psk2'
wireless.iot_2g.disabled='0'
wireless.iot_2g.isolate='1'
wireless.iot_2g.key='ExistingSecret123'
`
	axFirewall := `firewall.@zone[2]=zone
firewall.@zone[2].name='iot'
firewall.@zone[2].network='iot'
firewall.@forwarding[1]=forwarding
firewall.@forwarding[1].src='iot'
firewall.@forwarding[1].dest='wan'
firewall.singctl_fwd_wan_iot=forwarding
firewall.singctl_fwd_wan_iot.src='iot'
firewall.singctl_fwd_wan_iot.dest='wan'
firewall.@forwarding[2]=forwarding
firewall.@forwarding[2].src='lan'
firewall.@forwarding[2].dest='iot'
firewall.singctl_fwd_main_iot=forwarding
firewall.singctl_fwd_main_iot.src='lan'
firewall.singctl_fwd_main_iot.dest='iot'
`

	var reloadOptsLog []vlan.ReloadOptions
	var dmaHeadroomCalls int
	makeSvc := func() *vlan.Service {
		return vlan.NewService(vlan.Env{
			IsOpenWrt: func() bool { return true },
			RunUCI: func(_ context.Context, args ...string) (string, error) {
				if len(args) == 2 && args[0] == "show" {
					switch args[1] {
					case "network":
						return axNetWithDups, nil
					case "wireless":
						return axWireless, nil
					case "firewall":
						return axFirewall, nil
					}
				}
				return "", nil
			},
			BatchUCI: func(_ context.Context, _ []string) error { return nil },
			ReloadNetworkWithOpts: func(_ context.Context, opts vlan.ReloadOptions) error {
				reloadOptsLog = append(reloadOptsLog, opts)
				return nil
			},
			PrepareDMAHeadroom: func() {
				dmaHeadroomCalls++
			},
			SyncProxyBypass: func(_ context.Context, _ []string) error { return nil },
			ReadFile:        func(string) ([]byte, error) { return nil, os.ErrNotExist },
			ListNetDevs:     func() ([]string, error) { return []string{"lo", "eth0", "eth0.1", "eth0.2", "eth0.3", "br-lan", "iot-br"}, nil },
			ReadIPv4Addrs: func() (map[string]string, error) {
				return map[string]string{"eth0.2": "192.168.3.181/24", "br-lan": "192.168.50.1/24", "iot-br": "192.168.34.1/24"}, nil
			},
			ProxyBypassFile: filepath.Join(t.TempDir(), "bypass.list"),
		})
	}

	svc := makeSvc()

	// 1. Edit IoT without changing any Wi-Fi parameter -> dedup bridge/forwarding, zero wireless.* cmds, WirelessChanged=false
	reqNoWifiChange := vlan.SaveSegmentRequest{
		ID:        "iot",
		VLANID:    3,
		IPAddr:    "192.168.34.1",
		Netmask:   "255.255.255.0",
		ProxyMode: vlan.ProxyModeDirect,
		Ports:     map[string]string{"lan4": vlan.PortModeAccess},
		Wireless: &vlan.WirelessSpec{
			Enabled:    true,
			Section:    "iot_2g",
			Radio:      "MT7981_1_1",
			SSID:       "IoT-2G",
			Encryption: "psk2",
			Isolate:    true,
			Password:   "", // unchanged
		},
		Policy: vlan.SecurityPolicy{
			AllowWAN:         true,
			AllowFromMainLAN: true,
			BlockRouterMgmt:  true,
			BlockUpstreamLAN: true,
			AllowMDNS:        true,
		},
	}

	commitRes, err := svc.CommitSave(t.Context(), "192.168.50.10", reqNoWifiChange)
	if err != nil {
		t.Fatalf("CommitSave failed: %v", err)
	}
	joined := strings.Join(commitRes.UCICommands, "\n")
	if strings.Contains(joined, "wireless.") {
		t.Fatalf("expected ZERO wireless.* UCI commands when wireless fields unchanged:\n%s", joined)
	}
	if commitRes.ReloadOpts.WirelessChanged {
		t.Fatalf("expected ReloadOpts.WirelessChanged=false when wireless unchanged")
	}
	if !slices.Contains(commitRes.UCICommands, "delete network.singctl_br_iot") {
		t.Fatalf("expected duplicate network.singctl_br_iot cleaned up:\n%s", joined)
	}
	if !slices.Contains(commitRes.UCICommands, "delete network.iot.type") {
		t.Fatalf("expected legacy network.iot.type cleaned up:\n%s", joined)
	}
	if strings.Contains(joined, "set network.@device[3]=device") || strings.Contains(joined, "set network.singctl_br_iot=device") {
		t.Fatalf("must reuse @device[3] without creating duplicate bridge section:\n%s", joined)
	}
	if !slices.Contains(commitRes.UCICommands, "set network.@device[3].name='iot-br'") {
		t.Fatalf("expected reused @device[3] updated in place:\n%s", joined)
	}
	if !slices.Contains(commitRes.UCICommands, "delete firewall.singctl_fwd_wan_iot") ||
		!slices.Contains(commitRes.UCICommands, "delete firewall.singctl_fwd_main_iot") {
		t.Fatalf("expected duplicate singctl_fwd_* sections cleaned up when reusing @forwarding:\n%s", joined)
	}
	if pkgs := vlan.DirtyUCIPackages(commitRes.UCICommands); slices.Contains(pkgs, "wireless") {
		t.Fatalf("DirtyUCIPackages must not include wireless when unchanged: %v", pkgs)
	}

	if err := svc.ReloadWithOptions(t.Context(), commitRes.ReloadOpts); err != nil {
		t.Fatalf("ReloadWithOptions failed: %v", err)
	}
	if len(reloadOptsLog) != 1 || reloadOptsLog[0].WirelessChanged {
		t.Fatalf("expected ReloadWithOptions called with WirelessChanged=false, got %+v", reloadOptsLog)
	}
	if dmaHeadroomCalls != 0 {
		t.Fatalf("expected PrepareDMAHeadroom NOT called when WirelessChanged=false, got %d", dmaHeadroomCalls)
	}

	// 2. Edit IoT WITH password change -> emits wireless.* cmds, WirelessChanged=true, triggers DMA headroom prep
	reqWifiChanged := reqNoWifiChange
	wifiCopy := *reqNoWifiChange.Wireless
	wifiCopy.Password = "NewStrong-2026"
	reqWifiChanged.Wireless = &wifiCopy

	commitRes2, err := svc.CommitSave(t.Context(), "192.168.50.10", reqWifiChanged)
	if err != nil {
		t.Fatalf("CommitSave (wifi changed) failed: %v", err)
	}
	if !commitRes2.ReloadOpts.WirelessChanged {
		t.Fatalf("expected ReloadOpts.WirelessChanged=true when Wi-Fi password changed")
	}
	if !slices.Contains(vlan.DirtyUCIPackages(commitRes2.UCICommands), "wireless") {
		t.Fatalf("expected wireless in DirtyUCIPackages when Wi-Fi changed")
	}
	if err := svc.ReloadWithOptions(t.Context(), commitRes2.ReloadOpts); err != nil {
		t.Fatalf("ReloadWithOptions (wifi changed) failed: %v", err)
	}
	if len(reloadOptsLog) != 2 || !reloadOptsLog[1].WirelessChanged {
		t.Fatalf("expected second ReloadWithOptions with WirelessChanged=true, got %+v", reloadOptsLog)
	}
}

func TestOverview_SingleNICSideRouterAndNonNullJSON(t *testing.T) {
	sampleSingleNICBoardJSON := `{
  "model": { "id": "sample,single-nic", "name": "Sample Single-NIC Node" },
  "network": { "lan": { "device": "eth0", "protocol": "static" } }
}`
	sampleSingleNICNetworkUCI := `network.loopback=interface
network.loopback.device='lo'
network.loopback.proto='static'
network.loopback.ipaddr='127.0.0.1'
network.docker=interface
network.docker.device='docker0'
network.docker.proto='none'
network.lan=interface
network.lan.proto='static'
network.lan.netmask='255.255.255.0'
network.lan.device='eth0'
network.lan.ipaddr='192.168.1.2'
network.lan.gateway='192.168.1.1'
network.@device[0]=device
network.@device[0].type='bridge'
network.@device[0].name='docker0'
`
	env := vlan.Env{
		IsOpenWrt: func() bool { return true },
		RunUCI: func(_ context.Context, args ...string) (string, error) {
			if len(args) == 2 && args[0] == "show" && args[1] == "network" {
				return sampleSingleNICNetworkUCI, nil
			}
			return "", nil
		},
		ReadFile: func(p string) ([]byte, error) {
			if p == "/etc/board.json" {
				return []byte(sampleSingleNICBoardJSON), nil
			}
			return nil, os.ErrNotExist
		},
		ListNetDevs: func() ([]string, error) {
			return []string{"lo", "eth0", "docker0"}, nil
		},
		ReadIPv4Addrs: func() (map[string]string, error) {
			return map[string]string{"eth0": "192.168.1.2/24"}, nil
		},
		BoardJSONPath:   "/etc/board.json",
		ProxyBypassFile: filepath.Join(t.TempDir(), "bypass.list"),
	}

	ov, err := vlan.NewService(env).Overview(t.Context(), "127.0.0.1")
	if err != nil {
		t.Fatalf("Overview failed: %v", err)
	}
	if ov.Supported {
		t.Fatalf("single-NIC side router without br-lan/switch/AP must report Supported=false, got %+v", ov)
	}
	if ov.Driver != vlan.DriverUnsupported || ov.DriverLabel != "单网口旁路由" {
		t.Fatalf("expected Driver=unsupported DriverLabel='单网口旁路由', got driver=%q label=%q", ov.Driver, ov.DriverLabel)
	}
	if !strings.Contains(ov.UnsupportedReason, "单网口") || !strings.Contains(ov.UnsupportedReason, "主路由") {
		t.Fatalf("expected helpful single-NIC side-router guidance in UnsupportedReason, got %q", ov.UnsupportedReason)
	}

	rawJSON, err := json.Marshal(ov)
	if err != nil {
		t.Fatalf("json.Marshal Overview failed: %v", err)
	}
	js := string(rawJSON)
	for _, nullField := range []string{`"ports":null`, `"radios":null`, `"existingSsids":null`, `"segments":null`, `"presets":null`} {
		if strings.Contains(js, nullField) {
			t.Fatalf("Overview JSON must never contain %s; got: %s", nullField, js)
		}
	}
}

func TestWirelessSecret_OnDemandReadAndValidation(t *testing.T) {
	env, _, _, _ := newN60ProEnv(t)
	svc := vlan.NewService(env)

	ov, err := svc.Overview(t.Context(), "192.168.10.179")
	if err != nil {
		t.Fatalf("Overview failed: %v", err)
	}
	for _, seg := range ov.Segments {
		if seg.Wireless != nil && seg.Wireless.Password != "" {
			t.Fatalf("Overview must remain redacted, leaked password for %s", seg.ID)
		}
	}

	sec, err := svc.WirelessSecret(t.Context(), "iot")
	if err != nil {
		t.Fatalf("WirelessSecret(iot) failed: %v", err)
	}
	if !sec.PasswordConfigured || sec.SSID != "IoT-Example" || sec.Password != "SuperSecretWiFiPass123" {
		t.Fatalf("unexpected WirelessSecret(iot): %+v", sec)
	}

	lanSec, err := svc.WirelessSecret(t.Context(), "lan")
	if err != nil {
		t.Fatalf("WirelessSecret(lan) failed: %v", err)
	}
	if lanSec.PasswordConfigured || lanSec.Password != "" {
		t.Fatalf("expected lan without wifi binding to have PasswordConfigured=false, got %+v", lanSec)
	}

	for _, badID := range []string{"", "iot;id", "guest\nrm", "../etc"} {
		if _, err := svc.WirelessSecret(t.Context(), badID); !errors.Is(err, vlan.ErrInvalidSegmentID) {
			t.Fatalf("expected ErrInvalidSegmentID for %q, got %v", badID, err)
		}
	}
	if _, err := svc.WirelessSecret(t.Context(), "nonexistent"); !errors.Is(err, vlan.ErrSegmentNotFound) {
		t.Fatalf("expected ErrSegmentNotFound for missing segment, got %v", err)
	}
}

func TestCommitSave_PreFilledSamePasswordSkipsWifiReload(t *testing.T) {
	axNet := `network.lan=interface
network.lan.device='br-lan'
network.lan.proto='static'
network.lan.ipaddr='192.168.50.1'
network.lan.netmask='255.255.255.0'
network.wan=interface
network.wan.device='eth0.2'
network.wan.proto='dhcp'
network.@switch[0]=switch
network.@switch[0].name='switch0'
network.@switch[0].enable_vlan='1'
network.@switch_vlan[0]=switch_vlan
network.@switch_vlan[0].device='switch0'
network.@switch_vlan[0].vlan='1'
network.@switch_vlan[0].vid='1'
network.@switch_vlan[0].ports='0 1 2 6t'
network.@switch_vlan[1]=switch_vlan
network.@switch_vlan[1].device='switch0'
network.@switch_vlan[1].vlan='3'
network.@switch_vlan[1].vid='3'
network.@switch_vlan[1].ports='3 6t'
network.@device[3]=device
network.@device[3].name='iot-br'
network.@device[3].type='bridge'
network.@device[3].ports='eth0.3'
network.iot=interface
network.iot.proto='static'
network.iot.device='iot-br'
network.iot.ipaddr='192.168.34.1'
network.iot.netmask='255.255.255.0'
`
	axWireless := `wireless.MT7981_1_1=wifi-device
wireless.MT7981_1_1.type='mtwifi'
wireless.MT7981_1_1.band='2g'
wireless.iot_2g=wifi-iface
wireless.iot_2g.device='MT7981_1_1'
wireless.iot_2g.mode='ap'
wireless.iot_2g.network='iot'
wireless.iot_2g.ssid='IoT-2G'
wireless.iot_2g.encryption='psk2'
wireless.iot_2g.disabled='0'
wireless.iot_2g.isolate='1'
wireless.iot_2g.key='ExistingSecret123'
`
	svc := vlan.NewService(vlan.Env{
		IsOpenWrt: func() bool { return true },
		RunUCI: func(_ context.Context, args ...string) (string, error) {
			if len(args) == 2 && args[0] == "show" {
				switch args[1] {
				case "network":
					return axNet, nil
				case "wireless":
					return axWireless, nil
				}
			}
			return "", nil
		},
		BatchUCI:        func(_ context.Context, _ []string) error { return nil },
		SyncProxyBypass: func(_ context.Context, _ []string) error { return nil },
		SyncDNSBypass:   func(_ context.Context, _ []vlan.VLANDNSBypassRule) error { return nil },
		ReadFile:        func(string) ([]byte, error) { return nil, os.ErrNotExist },
		ListNetDevs:     func() ([]string, error) { return []string{"lo", "eth0", "eth0.1", "eth0.2", "eth0.3", "br-lan", "iot-br"}, nil },
		ReadIPv4Addrs: func() (map[string]string, error) {
			return map[string]string{"eth0.2": "192.168.3.181/24", "br-lan": "192.168.50.1/24", "iot-br": "192.168.34.1/24"}, nil
		},
		ProxyBypassFile: filepath.Join(t.TempDir(), "bypass.list"),
		DNSBypassFile:   filepath.Join(t.TempDir(), "dns-bypass.list"),
	})

	req := vlan.SaveSegmentRequest{
		ID:        "iot",
		VLANID:    3,
		IPAddr:    "192.168.34.1",
		Netmask:   "255.255.255.0",
		ProxyMode: vlan.ProxyModeDirect,
		DHCPDNS:   []string{"223.5.5.5"},
		Ports:     map[string]string{"lan4": vlan.PortModeAccess},
		Wireless: &vlan.WirelessSpec{
			Enabled:    true,
			Section:    "iot_2g",
			Radio:      "MT7981_1_1",
			SSID:       "IoT-2G",
			Encryption: "psk2",
			Isolate:    true,
			Password:   "ExistingSecret123", // exact same pre-filled password from UI reveal
		},
		Policy: vlan.SecurityPolicy{AllowWAN: true, BlockRouterMgmt: true},
	}

	res, err := svc.CommitSave(t.Context(), "192.168.50.10", req)
	if err != nil {
		t.Fatalf("CommitSave failed: %v", err)
	}
	if res.ReloadOpts.WirelessChanged {
		t.Fatal("expected WirelessChanged=false when pre-filled password equals existing UCI key")
	}
	for _, cmd := range res.UCICommands {
		if strings.Contains(cmd, "wireless.") {
			t.Fatalf("expected ZERO wireless.* UCI commands when password unchanged, got %q", cmd)
		}
	}
}

func TestCustomDHCPDNS_FullPipeline(t *testing.T) {
	t.Run("parse_existing_dhcp_option", func(t *testing.T) {
		env, _, _, _ := newN60ProEnv(t)
		origRunUCI := env.RunUCI
		env.RunUCI = func(ctx context.Context, args ...string) (string, error) {
			if len(args) == 2 && args[0] == "show" && args[1] == "dhcp" {
				return sampleN60ProDHCP + `dhcp.iot.dhcp_option='3,192.168.20.1' '6,192.168.29.88,223.5.5.5'
`, nil
			}
			return origRunUCI(ctx, args...)
		}
		ov, err := vlan.NewService(env).Overview(t.Context(), "192.168.10.179")
		if err != nil {
			t.Fatalf("Overview failed: %v", err)
		}
		var iotSeg *vlan.Segment
		for i := range ov.Segments {
			if ov.Segments[i].ID == "iot" {
				iotSeg = &ov.Segments[i]
				break
			}
		}
		if iotSeg == nil {
			t.Fatal("iot segment missing")
		}
		want := []string{"192.168.29.88", "223.5.5.5"}
		if !slices.Equal(iotSeg.DHCPDNS, want) {
			t.Fatalf("iot DHCPDNS=%v, want %v", iotSeg.DHCPDNS, want)
		}
	})

	t.Run("validation_rejects_invalid_dns", func(t *testing.T) {
		env, _, _, _ := newN60ProEnv(t)
		svc := vlan.NewService(env)
		badDNSLists := [][]string{
			{"not-an-ip"},
			{"127.0.0.1"},
			{"0.0.0.0"},
			{"224.0.0.1"},
			{"255.255.255.255"},
			{"223.5.5.5;rm"},
			{"223.5.5.5", "119.29.29.29", "114.114.114.114", "1.1.1.1", "8.8.8.8"},
		}
		for _, dnsList := range badDNSLists {
			prev, err := svc.PreviewSave(t.Context(), "192.168.10.179", vlan.SaveSegmentRequest{
				ID:      "guest",
				VLANID:  30,
				IPAddr:  "192.168.30.1",
				DHCPDNS: dnsList,
			})
			if err != nil {
				t.Fatalf("PreviewSave err=%v for dnsList=%v", err, dnsList)
			}
			if prev.Valid || len(prev.Errors) == 0 {
				t.Fatalf("expected invalid preview for bad DHCPDNS %v", dnsList)
			}
		}
	})

	t.Run("apply_preserve_other_options_pinholes_and_dns_bypass", func(t *testing.T) {
		tmpDir := t.TempDir()
		dnsBypassFile := filepath.Join(tmpDir, "vlan-dns-bypass.list")
		env, _, _, _ := newN60ProEnv(t)
		origRunUCI := env.RunUCI

		dhcpExtra := `dhcp.guest=dhcp
dhcp.guest.interface='guest'
dhcp.guest.start='100'
dhcp.guest.limit='150'
dhcp.guest.leasetime='12h'
dhcp.guest.dhcp_option='3,192.168.30.1' '6,1.2.3.4'
`
		clearOption6 := false
		env.RunUCI = func(ctx context.Context, args ...string) (string, error) {
			if len(args) == 2 && args[0] == "show" && args[1] == "dhcp" {
				if clearOption6 {
					return sampleN60ProDHCP + `dhcp.guest=dhcp
dhcp.guest.interface='guest'
dhcp.guest.start='100'
dhcp.guest.limit='150'
dhcp.guest.leasetime='12h'
dhcp.guest.dhcp_option='3,192.168.30.1' '6,192.168.29.88,192.168.1.53,223.5.5.5'
`, nil
				}
				return sampleN60ProDHCP + dhcpExtra, nil
			}
			if len(args) == 2 && args[0] == "show" && args[1] == "firewall" {
				if clearOption6 {
					return sampleN60ProFirewall + `firewall.singctl_allow_dns_guest_0=rule
firewall.singctl_allow_dns_guest_0.src='guest'
`, nil
				}
			}
			return origRunUCI(ctx, args...)
		}

		var syncedDNS []vlan.VLANDNSBypassRule
		env.DNSBypassFile = dnsBypassFile
		env.SyncDNSBypass = func(_ context.Context, rules []vlan.VLANDNSBypassRule) error {
			syncedDNS = slices.Clone(rules)
			return nil
		}

		svc := vlan.NewService(env)
		req := vlan.SaveSegmentRequest{
			ID:        "guest",
			VLANID:    30,
			IPAddr:    "192.168.30.1",
			ProxyMode: vlan.ProxyModeDirect,
			DHCPDNS:   []string{"192.168.29.88", "192.168.1.53", "223.5.5.5"},
			Ports:     map[string]string{"lan3": vlan.PortModeAccess},
			Policy: vlan.SecurityPolicy{
				AllowWAN:         true,
				BlockRouterMgmt:  true,
				BlockUpstreamLAN: true,
			},
		}

		res, err := svc.CommitSave(t.Context(), "192.168.10.179", req)
		if err != nil {
			t.Fatalf("CommitSave failed: %v", err)
		}
		joined := strings.Join(res.UCICommands, "\n")
		for _, want := range []string{
			"delete dhcp.guest.dhcp_option",
			"add_list dhcp.guest.dhcp_option='3,192.168.30.1'",
			"add_list dhcp.guest.dhcp_option='6,192.168.29.88,192.168.1.53,223.5.5.5'",
			"set dhcp.guest.ra_dns='0'",
			"set dhcp.guest.dns_service='0'",
		} {
			if !strings.Contains(joined, want) {
				t.Fatalf("missing DHCP command %q in:\n%s", want, joined)
			}
		}

		// Verify firewall pinhole rules for LAN IP (192.168.29.88) and WAN-subnet IP (192.168.1.53) appear BEFORE block_up rule.
		allowLANIdx := strings.Index(joined, "dest_ip='192.168.29.88'")
		allowWANIdx := strings.Index(joined, "dest_ip='192.168.1.53'")
		blockUpIdx := strings.Index(joined, "singctl_block_up_guest=")
		if allowLANIdx < 0 || allowWANIdx < 0 || blockUpIdx < 0 {
			t.Fatalf("missing custom DNS firewall rules or block_up in:\n%s", joined)
		}
		if allowWANIdx > blockUpIdx {
			t.Fatalf("WAN-subnet DNS pinhole rule MUST appear before singctl_block_up_guest:\n%s", joined)
		}
		if !strings.Contains(joined, "dest='lan'") || !strings.Contains(joined, "dest_port='53'") {
			t.Fatalf("expected dest='lan' and dest_port='53' in firewall pinhole:\n%s", joined)
		}

		if len(syncedDNS) != 1 || syncedDNS[0].CIDR != "192.168.30.0/24" || !slices.Equal(syncedDNS[0].DNSIPs, req.DHCPDNS) {
			t.Fatalf("unexpected SyncDNSBypass rules: %+v", syncedDNS)
		}

		// Verify default OS persistence writes 0600 file when SyncDNSBypass is nil.
		envDisk := env
		envDisk.SyncDNSBypass = nil
		if _, err := vlan.NewService(envDisk).CommitSave(t.Context(), "192.168.10.179", req); err != nil {
			t.Fatalf("CommitSave(disk fallback) failed: %v", err)
		}
		st, err := os.Stat(dnsBypassFile)
		if err != nil || st.Mode().Perm() != 0600 {
			t.Fatalf("dns bypass file stat err=%v perm=%o (want 0600)", err, st.Mode().Perm())
		}
		rawBypass, _ := os.ReadFile(dnsBypassFile)
		if !strings.Contains(string(rawBypass), "192.168.30.0/24 192.168.29.88,192.168.1.53,223.5.5.5") {
			t.Fatalf("unexpected dns bypass file contents:\n%s", string(rawBypass))
		}

		// Clearing DHCPDNS should remove option 6 (preserving option 3), delete singctl_allow_dns_guest_*, and clear dns-bypass file.
		clearOption6 = true
		req.DHCPDNS = nil
		resClear, err := vlan.NewService(envDisk).CommitSave(t.Context(), "192.168.10.179", req)
		if err != nil {
			t.Fatalf("CommitSave(clear dns) failed: %v", err)
		}
		joinedClear := strings.Join(resClear.UCICommands, "\n")
		if strings.Contains(joinedClear, "'6,") {
			t.Fatalf("expected option 6 removed when DHCPDNS cleared, got:\n%s", joinedClear)
		}
		if !strings.Contains(joinedClear, "add_list dhcp.guest.dhcp_option='3,192.168.30.1'") {
			t.Fatalf("expected non-DNS dhcp_option 3 preserved when clearing DNS, got:\n%s", joinedClear)
		}
		if !strings.Contains(joinedClear, "delete firewall.singctl_allow_dns_guest_0") {
			t.Fatalf("expected stale singctl_allow_dns_guest_0 deleted, got:\n%s", joinedClear)
		}
		rawBypassCleared, _ := os.ReadFile(dnsBypassFile)
		if strings.Contains(string(rawBypassCleared), "192.168.30.0/24") {
			t.Fatalf("expected dns bypass file cleared, got:\n%s", string(rawBypassCleared))
		}
	})
}
