// 文件职责：测试流量审计采集器自动叠加本地域名设备昵称（MAC 优先匹配双栈 IPv4/IPv6，IP 兜底）。
package audit_test

import (
	"testing"

	"singctl/internal/audit"
	"singctl/internal/config"
)

func TestAudit_ResolveHomeDomainFriendlyNameOverlay(t *testing.T) {
	cfg := &config.Config{
		HomeDomain: config.HomeDomainConfig{
			Suffix: "home",
			Devices: []config.HomeDomainDevice{
				{Alias: "nas", DisplayName: "家庭NAS", IP: "192.0.2.10", MAC: "aa:bb:cc:dd:ee:01"},
				{Alias: "ax3000t", IP: "100.64.0.22"},
			},
		},
	}

	if got := audit.FormatFriendlyDeviceName(cfg, "192.0.2.10", "aa:bb:cc:dd:ee:01", "OpenWrt"); got != "家庭NAS (nas.home)" {
		t.Fatalf("expected 家庭NAS (nas.home), got %q", got)
	}
	// IPv6 address sharing MAC still inherits friendly name!
	if got := audit.FormatFriendlyDeviceName(cfg, "2001:db8::99", "AA:BB:CC:DD:EE:01", ""); got != "家庭NAS (nas.home)" {
		t.Fatalf("expected IPv6 MAC match 家庭NAS (nas.home), got %q", got)
	}
	// Alias without DisplayName falls back cleanly to alias.home
	if got := audit.FormatFriendlyDeviceName(cfg, "100.64.0.22", "", "100.64.0.22"); got != "ax3000t.home" {
		t.Fatalf("expected ax3000t.home, got %q", got)
	}
	// Unmatched device keeps original DHCP/ARP hostname
	if got := audit.FormatFriendlyDeviceName(cfg, "192.0.2.55", "11:22:33:44:55:66", "iPhone"); got != "iPhone" {
		t.Fatalf("expected original fallback iPhone, got %q", got)
	}
}
