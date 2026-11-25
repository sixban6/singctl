// 文件职责：测试主路由旁路由托管协同逻辑（SideRouterIP 防注入与自环校验、在线/端口探活、主网 DHCP 接管识别、TProxy 清理与并发安全）。
package gateway_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"singctl/internal/gateway"
)

func TestValidateSideRouterIP(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		selfLAN string
		want    string
		wantErr bool
	}{
		{name: "empty clears value", raw: "  ", selfLAN: "192.168.55.1", want: "", wantErr: false},
		{name: "valid lan ipv4", raw: " 192.168.55.88 ", selfLAN: "192.168.55.1", want: "192.168.55.88", wantErr: false},
		{name: "same as self lan ip", raw: "192.168.55.1", selfLAN: "192.168.55.1", wantErr: true},
		{name: "loopback rejected", raw: "127.0.0.1", selfLAN: "192.168.55.1", wantErr: true},
		{name: "unspecified rejected", raw: "0.0.0.0", selfLAN: "192.168.55.1", wantErr: true},
		{name: "broadcast rejected", raw: "255.255.255.255", selfLAN: "192.168.55.1", wantErr: true},
		{name: "multicast rejected", raw: "224.0.0.1", selfLAN: "192.168.55.1", wantErr: true},
		{name: "ipv6 rejected", raw: "fe80::1", selfLAN: "192.168.55.1", wantErr: true},
		{name: "public ip rejected", raw: "8.8.8.8", selfLAN: "192.168.55.1", wantErr: true},
		{name: "command injection rejected", raw: "192.168.55.88;id", selfLAN: "192.168.55.1", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := gateway.ValidateSideRouterIP(tc.raw, tc.selfLAN)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q, got %q", tc.raw, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestProbeSideRouterStatus(t *testing.T) {
	// 1. Unconfigured
	stEmpty := gateway.ProbeSideRouterStatus(t.Context(), "", gateway.SideRouterProbeDeps{})
	if stEmpty.Configured || stEmpty.Online {
		t.Fatalf("empty side router IP must not report configured/online: %+v", stEmpty)
	}

	// 2. Both 8090 & 53 up + side router serving LAN DHCP (dhcp.lan.ignore='1')
	stFull := gateway.ProbeSideRouterStatus(t.Context(), "192.168.55.88", gateway.SideRouterProbeDeps{
		DialTCP: func(_ context.Context, addr string) (time.Duration, error) {
			if strings.HasSuffix(addr, ":8090") {
				return 2 * time.Millisecond, nil
			}
			if strings.HasSuffix(addr, ":53") {
				return 1 * time.Millisecond, nil
			}
			return 0, errors.New("unexpected port")
		},
		RunUCI: func(_ context.Context, args ...string) (string, error) {
			if len(args) >= 2 && args[1] == "dhcp.lan.ignore" {
				return "1\n", nil
			}
			return "", errors.New("not found")
		},
	})
	if !stFull.Configured || !stFull.Online || !stFull.WebUIReady || !stFull.DNSReady {
		t.Fatalf("expected full online status, got %+v", stFull)
	}
	if stFull.LatencyMs != 1 || stFull.LANDHCPMode != "side_dhcp" {
		t.Fatalf("unexpected latency or dhcp mode: %+v", stFull)
	}

	// 3. Only DNS :53 reachable + main router option 3/6 delegation
	stDNSOnly := gateway.ProbeSideRouterStatus(t.Context(), "192.168.55.88", gateway.SideRouterProbeDeps{
		DialTCP: func(_ context.Context, addr string) (time.Duration, error) {
			if strings.HasSuffix(addr, ":53") {
				return 3 * time.Millisecond, nil
			}
			return 0, errors.New("connection refused")
		},
		RunUCI: func(_ context.Context, args ...string) (string, error) {
			if len(args) >= 2 && args[1] == "dhcp.lan.dhcp_option" {
				return "3,192.168.55.88 6,192.168.55.88\n", nil
			}
			return "", errors.New("not set")
		},
	})
	if !stDNSOnly.Online || !stDNSOnly.DNSReady || stDNSOnly.WebUIReady || stDNSOnly.LANDHCPMode != "main_dhcp_option" {
		t.Fatalf("expected dns-only online + main_dhcp_option, got %+v", stDNSOnly)
	}

	// 4. Completely unreachable + main_local DHCP
	stOffline := gateway.ProbeSideRouterStatus(t.Context(), "192.168.55.88", gateway.SideRouterProbeDeps{
		DialTCP: func(context.Context, string) (time.Duration, error) {
			return 0, errors.New("i/o timeout")
		},
		RunUCI: func(_ context.Context, _ ...string) (string, error) {
			return "0\n", nil
		},
	})
	if !stOffline.Configured || stOffline.Online || stOffline.LANDHCPMode != "main_local" {
		t.Fatalf("expected offline main_local status, got %+v", stOffline)
	}

	// 5. Concurrent probing (-race safety)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			res := gateway.ProbeSideRouterStatus(t.Context(), "192.168.55.88", gateway.SideRouterProbeDeps{
				DialTCP: func(context.Context, string) (time.Duration, error) { return 2 * time.Millisecond, nil },
				RunUCI:  func(context.Context, ...string) (string, error) { return "1\n", nil },
			})
			if !res.Online {
				t.Errorf("concurrent probe expected online")
			}
		})
	}
	wg.Wait()
}

func TestCleanupLocalTProxyTables(t *testing.T) {
	var calls []string
	var mu sync.Mutex
	gateway.CleanupLocalTProxyTables(t.Context(), func(_ context.Context, name string, args ...string) ([]byte, error) {
		mu.Lock()
		calls = append(calls, name+" "+strings.Join(args, " "))
		mu.Unlock()
		return nil, nil
	})
	joined := strings.Join(calls, "\n")
	if !strings.Contains(joined, "nft delete table inet sing-box") {
		t.Fatalf("expected nft table cleanup, got:\n%s", joined)
	}
	if !strings.Contains(joined, "iptables -t mangle -D PREROUTING -j SING_BOX") {
		t.Fatalf("expected iptables PREROUTING cleanup, got:\n%s", joined)
	}
}
