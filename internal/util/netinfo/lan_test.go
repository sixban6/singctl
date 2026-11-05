package netinfo

import "testing"

func TestSelectPrimaryLANIPv4(t *testing.T) {
	t.Run("prefers br-lan over pppoe-wan public IP and tun", func(t *testing.T) {
		candidates := []InterfaceCandidate{
			{Name: "pppoe-wan", Up: true, IPv4Addrs: []string{"203.0.113.45"}},
			{Name: "tun0", Up: true, IPv4Addrs: []string{"10.8.8.8"}},
			{Name: "tailscale0", Up: true, IPv4Addrs: []string{"100.101.102.103"}},
			{Name: "br-lan", Up: true, IPv4Addrs: []string{"192.168.1.1"}},
		}
		got := SelectPrimaryLANIPv4(candidates, "pppoe-wan")
		if got != "192.168.1.1" {
			t.Fatalf("SelectPrimaryLANIPv4 = %q, want 192.168.1.1", got)
		}
	})

	t.Run("side router uses preferred physical interface and ignores docker/tun", func(t *testing.T) {
		candidates := []InterfaceCandidate{
			{Name: "docker0", Up: true, IPv4Addrs: []string{"172.17.0.1"}},
			{Name: "tun0", Up: true, IPv4Addrs: []string{"10.8.8.8"}},
			{Name: "eth0", Up: true, IPv4Addrs: []string{"10.0.0.2"}},
		}
		got := SelectPrimaryLANIPv4(candidates, "eth0")
		if got != "10.0.0.2" {
			t.Fatalf("SelectPrimaryLANIPv4 = %q, want 10.0.0.2", got)
		}
	})

	t.Run("falls back safely to 127.0.0.1 when only public or virtual IPs exist", func(t *testing.T) {
		candidates := []InterfaceCandidate{
			{Name: "eth0", Up: true, IPv4Addrs: []string{"198.51.100.12"}},
			{Name: "tun0", Up: true, IPv4Addrs: []string{"10.8.8.8"}},
			{Name: "tailscale0", Up: true, IPv4Addrs: []string{"100.64.0.9"}},
		}
		got := SelectPrimaryLANIPv4(candidates, "eth0")
		if got != "127.0.0.1" {
			t.Fatalf("SelectPrimaryLANIPv4 = %q, want 127.0.0.1", got)
		}
	})
}

func TestParseUbusLANStatusIP(t *testing.T) {
	raw := []byte(`{"up":true,"ipv4-address":[{"address":"192.168.2.1","mask":24}]}`)
	if got := parseUbusLANStatusIP(raw); got != "192.168.2.1" {
		t.Fatalf("parseUbusLANStatusIP = %q, want 192.168.2.1", got)
	}
}
