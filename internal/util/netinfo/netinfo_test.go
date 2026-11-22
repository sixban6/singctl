// 文件职责：针对 netinfo 包的纯内存与临时目录离线表驱动单元测试（覆盖私网/ECS 网段计算、LAN 首选网卡筛选、DNS 配置解析与带宽折算）。
package netinfo

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"
)

func TestIsPrivateIP_And_SubnetHelpers(t *testing.T) {
	privCases := []struct {
		ip   string
		want bool
	}{
		{"10.0.0.1", true},
		{"172.16.0.1", true},
		{"172.31.255.254", true},
		{"172.15.255.255", false},
		{"172.32.0.1", false},
		{"192.168.1.1", true},
		{"fd00::1", true},
		{"fe80::1", false},
		{"198.51.100.10", false},
		{"not-an-ip", false},
		{"", false},
	}
	for _, tc := range privCases {
		if got := IsPrivateIP(tc.ip); got != tc.want {
			t.Fatalf("IsPrivateIP(%q) = %v, want %v", tc.ip, got, tc.want)
		}
	}

	if !IsPublicAnycastDNS("223.5.5.5") || !IsPublicAnycastDNS("1.1.1.1") {
		t.Fatal("expected 223.5.5.5 and 1.1.1.1 to be recognized as public Anycast DNS")
	}
	if IsPublicAnycastDNS("202.101.172.35") || IsPublicAnycastDNS("invalid") {
		t.Fatal("expected regional ISP DNS and invalid IP to return false for IsPublicAnycastDNS")
	}

	if got := ToIPv4Subnet24("202.101.172.35"); got != "202.101.172.0/24" {
		t.Fatalf("ToIPv4Subnet24() = %q, want 202.101.172.0/24", got)
	}
	if got := ToIPv4Subnet24("2001:db8::1"); got != "" {
		t.Fatalf("expected empty subnet24 for IPv6 input, got %q", got)
	}
	if got := ToIPv4Subnet24("bad"); got != "" {
		t.Fatalf("expected empty subnet24 for invalid input, got %q", got)
	}

	// Regional ISP DNS shortcut in ResolveClientSubnet (0 network I/O!)
	if got := ResolveClientSubnet(t.Context(), "202.101.172.48"); got != "202.101.172.0/24" {
		t.Fatalf("ResolveClientSubnet(regional DNS) = %q, want 202.101.172.0/24", got)
	}
}

func TestLookupRegionalISPSubnet_And_ParseIPIPNetOutput(t *testing.T) {
	cases := []struct {
		region string
		city   string
		isp    string
		want   string
	}{
		{"浙江省", "杭州市", "中国电信", "202.101.172.0/24"},
		{"Guangdong", "Shenzhen", "China Unicom AS4837", "210.21.196.0/24"},
		{"广西壮族自治区", "南宁市", "中国移动 CMCC", "211.138.240.0/24"},
		{"UnknownRegion", "", "联通", "202.106.0.0/24"},
		{"UnknownRegion", "", "移动", "211.136.112.0/24"},
		{"", "", "", DefaultClientSubnet},
	}
	for _, tc := range cases {
		if got := LookupRegionalISPSubnet(tc.region, tc.city, tc.isp); got != tc.want {
			t.Fatalf("LookupRegionalISPSubnet(%q, %q, %q) = %q, want %q", tc.region, tc.city, tc.isp, got, tc.want)
		}
	}

	r1, c1, i1 := ParseIPIPNetOutput("当前 IP：198.51.100.25  来自于：中国 浙江 杭州  电信\n")
	if r1 != "浙江" || c1 != "杭州" || i1 != "电信" {
		t.Fatalf("unexpected ParseIPIPNetOutput: %q / %q / %q", r1, c1, i1)
	}
	r2, c2, i2 := ParseIPIPNetOutput("当前 IP: 203.0.113.8 来自于: 中国 上海 联通")
	if r2 != "上海" || i2 != "联通" || c2 == "" {
		t.Fatalf("unexpected 3-field ParseIPIPNetOutput: %q / %q / %q", r2, c2, i2)
	}
	if r3, c3, i3 := ParseIPIPNetOutput("garbage without marker"); r3 != "" || c3 != "" || i3 != "" {
		t.Fatalf("expected empty result on malformed ipip output, got %q/%q/%q", r3, c3, i3)
	}
}

func TestSelectPrimaryLANIPv4_And_OpenWrtUbusParsers(t *testing.T) {
	// 1. br-lan takes top priority over eth0 and pppoe-wan
	cands1 := []InterfaceCandidate{
		{Name: "pppoe-wan", Up: true, IPv4Addrs: []string{"203.0.113.99"}},
		{Name: "eth0", Up: true, IPv4Addrs: []string{"10.0.0.2"}},
		{Name: "br-lan", Up: true, IPv4Addrs: []string{"192.168.50.1"}},
	}
	if got := SelectPrimaryLANIPv4(cands1, "eth0"); got != "192.168.50.1" {
		t.Fatalf("expected br-lan 192.168.50.1, got %q", got)
	}

	// 2. preferredDev takes priority when br-lan absent, while virtual interfaces are ignored
	cands2 := []InterfaceCandidate{
		{Name: "tailscale0", Up: true, IPv4Addrs: []string{"100.64.0.8", "192.168.99.1"}},
		{Name: "docker0", Up: true, IPv4Addrs: []string{"172.17.0.1"}},
		{Name: "ens18", Up: true, IPv4Addrs: []string{"10.10.0.5"}},
		{Name: "eth1", Up: true, IPv4Addrs: []string{"192.168.2.10"}},
	}
	if got := SelectPrimaryLANIPv4(cands2, "ens18"); got != "10.10.0.5" {
		t.Fatalf("expected preferredDev ens18 10.10.0.5, got %q", got)
	}

	// 3. Only public / loopback / down interfaces -> safe fallback 127.0.0.1 (never public IP!)
	cands3 := []InterfaceCandidate{
		{Name: "lo", Up: true, Loopback: true, IPv4Addrs: []string{"127.0.0.1"}},
		{Name: "eth0", Up: true, IPv4Addrs: []string{"198.51.100.77"}},
		{Name: "br-lan", Up: false, IPv4Addrs: []string{"192.168.1.1"}},
	}
	if got := SelectPrimaryLANIPv4(cands3, "eth0"); got != "127.0.0.1" {
		t.Fatalf("expected safe fallback 127.0.0.1 when no active RFC1918 exists, got %q", got)
	}

	// 4. OpenWrt ubus LAN & WAN DNS parsers
	ubusLAN := []byte(`{"ipv4-address":[{"address":"203.0.113.1"},{"address":"192.168.6.1"}]}`)
	if got := ParseUbusLANStatusIP(ubusLAN); got != "192.168.6.1" {
		t.Fatalf("expected RFC1918 192.168.6.1 from ubus LAN status, got %q", got)
	}
	if got := ParseUbusLANStatusIP([]byte(`{invalid`)); got != "" {
		t.Fatalf("expected empty string on invalid JSON, got %q", got)
	}

	ubusDump := []byte(`{
		"interface": [
			{"interface": "lan", "up": true, "dns-server": ["192.168.1.1"]},
			{"interface": "tailscale", "up": true, "dns-server": ["100.100.100.100"]},
			{"interface": "wan", "up": true, "dns-server": ["127.0.0.1", "198.18.0.2", "202.101.172.35", "223.5.5.5", "2400:3200::1"]}
		]
	}`)
	gotDNS := ParseUbusInterfaceDNS(ubusDump)
	wantDNS := []string{"202.101.172.35", "223.5.5.5"}
	if !slices.Equal(gotDNS, wantDNS) {
		t.Fatalf("ParseUbusInterfaceDNS() = %v, want %v", gotDNS, wantDNS)
	}
}

func TestDNSConfigFileParsers_And_MeasureHy2Bandwidth(t *testing.T) {
	tmp := t.TempDir()
	resolvPath := filepath.Join(tmp, "resolv.conf")
	if err := os.WriteFile(resolvPath, []byte("# comment\nnameserver 127.0.0.53\nnameserver 198.18.0.2\nnameserver 223.5.5.5\nnameserver 119.29.29.29\n"), 0600); err != nil {
		t.Fatal(err)
	}
	rawServers, err := parseResolvConf(resolvPath)
	if err != nil {
		t.Fatal(err)
	}
	filtered := filterLocalAddresses(rawServers)
	if !slices.Equal(filtered, []string{"223.5.5.5", "119.29.29.29"}) {
		t.Fatalf("unexpected filtered resolv.conf servers: %v", filtered)
	}

	resolvedConf := filepath.Join(tmp, "resolved.conf")
	if err := os.WriteFile(resolvedConf, []byte("[Resolve]\nDNS=223.5.5.5#dns.alidns.com 100.100.100.100\nFallbackDNS=1.12.12.12\n"), 0600); err != nil {
		t.Fatal(err)
	}
	sysServers, err := ParseSystemdResolvedConf(resolvedConf)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(filterLocalAddresses(sysServers), []string{"223.5.5.5", "1.12.12.12"}) {
		t.Fatalf("unexpected systemd-resolved servers: %v", filterLocalAddresses(sysServers))
	}

	// MeasureHy2Bandwidth with stubbed SpeedTestFn
	origFn := SpeedTestFn
	t.Cleanup(func() { SpeedTestFn = origFn })

	SpeedTestFn = func() (float64, float64, time.Duration, string, error) {
		return 100.0, 500.0, 12 * time.Millisecond, "MockServer", nil
	}
	up, down, err := MeasureHy2Bandwidth()
	if err != nil || up != 80 || down != 450 {
		t.Fatalf("MeasureHy2Bandwidth(100/500) = (%d, %d, %v), want (80, 450, nil)", up, down, err)
	}

	// Low-bandwidth floor guard (min up=5, min down=20)
	SpeedTestFn = func() (float64, float64, time.Duration, string, error) {
		return 2.0, 8.0, 50 * time.Millisecond, "SlowServer", nil
	}
	upFloor, downFloor, err := MeasureHy2Bandwidth()
	if err != nil || upFloor != 5 || downFloor != 20 {
		t.Fatalf("MeasureHy2Bandwidth floor = (%d, %d, %v), want (5, 20, nil)", upFloor, downFloor, err)
	}

	// Error propagation
	SpeedTestFn = func() (float64, float64, time.Duration, string, error) {
		return 0, 0, 0, "", errors.New("network unreachable")
	}
	if _, _, err := MeasureHy2Bandwidth(); err == nil {
		t.Fatal("expected error when SpeedTestFn fails")
	}

	// Concurrent read safety under -race
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			_ = LookupRegionalISPSubnet("浙江", "杭州", "电信")
			_ = SelectPrimaryLANIPv4([]InterfaceCandidate{{Name: "br-lan", Up: true, IPv4Addrs: []string{"192.168.1.1"}}}, "")
			_ = IsPublicAnycastDNS("223.5.5.5")
		})
	}
	wg.Wait()
}
