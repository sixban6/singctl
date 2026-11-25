// 文件职责：测试 SmartDNS 超小内存设备（<=288MiB）的默认精简加密上游、轻量测速策略与零回归配置生成。
package smartdns_test

import (
	"strings"
	"testing"

	"singctl/internal/smartdns"
)

func TestSmartDNS_UltraLowMemoryDefaultsAndSpeedCheck(t *testing.T) {
	if ups := smartdns.DefaultUpstreamsForMemory(true); len(ups) != 2 {
		t.Fatalf("expected 2 lean encrypted upstreams on ultra-low-memory host, got %v", ups)
	}
	if ups := smartdns.DefaultUpstreamsForMemory(false); len(ups) != 4 {
		t.Fatalf("expected 4 default encrypted upstreams on standard host, got %v", ups)
	}

	// Ultra-low-memory with default empty mode & upstreams -> 2 upstreams + load_balance (speed-check-mode none)
	conf, err := smartdns.BuildConfig(smartdns.ConfigInput{
		DNSPort:          5353,
		IsUltraLowMemory: true,
	}, "/etc/singctl/smartdns-rules.d", "/tmp/audit.log", "/tmp/sd.log")
	if err != nil {
		t.Fatalf("BuildConfig(ultraLowMem) failed: %v", err)
	}
	if !strings.Contains(conf, "speed-check-mode none") || !strings.Contains(conf, "response-mode fastest-response") {
		t.Fatalf("ultra-low-memory default mode must use speed-check-mode none + fastest-response:\n%s", conf)
	}
	if strings.Count(conf, "server-https ")+strings.Count(conf, "server-tls ") != 2 {
		t.Fatalf("ultra-low-memory default upstreams must have exactly 2 entries:\n%s", conf)
	}

	// Explicit fastest_ip on ultra-low-memory trims 3-way probe to lightweight tcp:443
	confFast, err := smartdns.BuildConfig(smartdns.ConfigInput{
		DNSPort:          5353,
		UpstreamMode:     "fastest_ip",
		IsUltraLowMemory: true,
	}, "/etc/singctl/smartdns-rules.d", "/tmp/audit.log", "/tmp/sd.log")
	if err != nil {
		t.Fatalf("BuildConfig(ultraLowMem fastest_ip) failed: %v", err)
	}
	if !strings.Contains(confFast, "speed-check-mode tcp:443") || strings.Contains(confFast, "ping,tcp:80,tcp:443") {
		t.Fatalf("ultra-low-memory fastest_ip should trim speed-check-mode to tcp:443:\n%s", confFast)
	}
}
