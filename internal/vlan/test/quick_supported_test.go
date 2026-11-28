// 文件职责：覆盖 VLAN 服务零子进程 QuickSupported 设备能力探针的表驱动边界单测。
package vlan_test

import (
	"context"
	"errors"
	"os"
	"testing"

	"singctl/internal/vlan"
)

func TestQuickSupported_ZeroExecTableDriven(t *testing.T) {
	tests := []struct {
		name      string
		isOpenWrt bool
		network   string
		wireless  string
		want      bool
	}{
		{
			name:      "non_openwrt_false",
			isOpenWrt: false,
			network:   "config switch 'switch0'\n",
			want:      false,
		},
		{
			name:      "side_router_single_nic_no_bridge_no_wifi",
			isOpenWrt: true,
			network:   "config interface 'lan'\n\toption device 'eth0'\n\toption ipaddr '192.168.1.2'\n",
			want:      false,
		},
		{
			name:      "dsa_multiport_bridge_true",
			isOpenWrt: true,
			network:   "config device 'br_lan'\n\toption name 'br-lan'\n\toption type 'bridge'\n\tlist ports 'lan1'\n\tlist ports 'lan2'\n",
			want:      true,
		},
		{
			name:      "swconfig_switch_true",
			isOpenWrt: true,
			network:   "config switch 'switch0'\n\toption name 'switch0'\nconfig switch_vlan\n\toption vlan '1'\n",
			want:      true,
		},
		{
			name:      "single_port_plus_wifi_ap_true",
			isOpenWrt: true,
			network:   "config interface 'lan'\n\toption device 'eth0'\n",
			wireless:  "config wifi-device 'radio0'\n",
			want:      true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			uciCalls := 0
			netPath := "/tmp/mock-network"
			wifiPath := "/tmp/mock-wireless"
			env := vlan.Env{
				IsOpenWrt:    func() bool { return tc.isOpenWrt },
				NetworkFile:  netPath,
				WirelessFile: wifiPath,
				RunUCI: func(context.Context, ...string) (string, error) {
					uciCalls++
					return "", errors.New("QuickSupported must not exec uci")
				},
				ReadFile: func(path string) ([]byte, error) {
					switch path {
					case netPath:
						if tc.network == "" {
							return nil, os.ErrNotExist
						}
						return []byte(tc.network), nil
					case wifiPath:
						if tc.wireless == "" {
							return nil, os.ErrNotExist
						}
						return []byte(tc.wireless), nil
					default:
						return nil, os.ErrNotExist
					}
				},
			}
			if got := vlan.QuickSupported(env); got != tc.want {
				t.Fatalf("QuickSupported() = %v, want %v", got, tc.want)
			}
			if uciCalls != 0 {
				t.Fatalf("QuickSupported invoked RunUCI %d times (must be 0)", uciCalls)
			}
		})
	}
}
