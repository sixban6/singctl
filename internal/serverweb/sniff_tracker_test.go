package serverweb

import (
	"testing"
)

func TestSniffTrackerAggregationAndTrustedExclusion(t *testing.T) {
	geo := NewIPGeoResolver()
	geo.SeedCountry("198.51.100.10", "US")
	geo.SeedCountry("198.51.100.25", "US")
	geo.SeedCountry("203.0.113.88", "NL")
	geo.SeedCountry("162.142.125.12", "US")

	tracker := NewSniffTracker(geo, nil)
	tracker.enableSystemProbe = false

	// 1. 同一 /24 网段内多个 IP 进行探测
	tracker.Observe("198.51.100.10", "TLS/443 伪装回落嗅探", "masqueraded", 4)
	tracker.Observe("198.51.100.25", "TLS/443 伪装回落嗅探", "masqueraded", 2)
	// 2. 另一个国家的 SSH 爆破源
	tracker.Observe("203.0.113.88", "SSH 暴力破解", "banned", 5)
	// 3. 已知 Censys 测绘引擎 IP
	tracker.Observe("162.142.125.12", "HTTP/80 端口嗅探", "masqueraded", 3)
	// 4. 合法代理客户端 IP (应被自动排除)
	tracker.Observe("192.0.2.55", "TLS/443 伪装回落嗅探", "masqueraded", 10)

	summary := tracker.Snapshot(t.Context(), "192.0.2.55")

	if summary.TotalSniffIPs != 4 {
		t.Fatalf("expected 4 external sniffing IPs after excluding trusted client, got %d", summary.TotalSniffIPs)
	}
	if summary.TotalSubnets != 3 {
		t.Fatalf("expected 3 unique /24 subnets, got %d", summary.TotalSubnets)
	}
	if len(summary.TopSubnets) == 0 || summary.TopSubnets[0].CIDR != "198.51.100.0/24" || summary.TopSubnets[0].UniqueIPs != 2 {
		t.Fatalf("expected top subnet 198.51.100.0/24 with 2 unique IPs, got %+v", summary.TopSubnets)
	}

	foundCensys := false
	for _, ipStat := range summary.TopIPs {
		if ipStat.IP == "192.0.2.55" {
			t.Fatalf("trusted proxy client IP 192.0.2.55 must not appear in TopIPs")
		}
		if ipStat.IP == "162.142.125.12" && ipStat.ScannerTag == "Censys 测绘" {
			foundCensys = true
		}
	}
	if !foundCensys {
		t.Fatalf("expected 162.142.125.12 to be tagged as Censys 测绘, got %+v", summary.TopIPs)
	}
}

func TestSniffTrackerBlockTargetAndAntiLockout(t *testing.T) {
	tracker := NewSniffTracker(NewIPGeoResolver(), nil)
	tracker.enableSystemProbe = false

	tracker.Observe("198.51.100.10", "TLS/443 伪装回落嗅探", "masqueraded", 2)
	tracker.Observe("198.51.100.99", "HTTP/80 端口嗅探", "masqueraded", 1)

	// 1. 防锁死测试：禁止拉黑管理员自身 IP 或包含管理员 IP 的 /24 网段
	if _, err := tracker.BlockTarget("203.0.113.5", "203.0.113.5"); err == nil {
		t.Fatalf("expected error when blocking operator's own IP")
	}
	if _, err := tracker.BlockTarget("203.0.113.0/24", "203.0.113.5"); err == nil {
		t.Fatalf("expected error when blocking /24 subnet containing operator's own IP")
	}
	if _, err := tracker.BlockTarget("127.0.0.1", "203.0.113.5"); err == nil {
		t.Fatalf("expected error when blocking loopback IP")
	}

	// 2. 正常拉黑 /24 网段：该网段内所有活跃嗅探 IP 应立即变为 banned
	cidr, err := tracker.BlockTarget("198.51.100.0/24", "203.0.113.5")
	if err != nil {
		t.Fatalf("unexpected error blocking /24 subnet: %v", err)
	}
	if cidr != "198.51.100.0/24" {
		t.Fatalf("expected canonical CIDR 198.51.100.0/24, got %s", cidr)
	}

	summary := tracker.Snapshot(t.Context())
	if summary.TotalBannedIPs != 2 {
		t.Fatalf("expected both IPs in 198.51.100.0/24 to be marked banned, got %d", summary.TotalBannedIPs)
	}
	if len(summary.TopSubnets) == 0 || summary.TopSubnets[0].Status != "banned" {
		t.Fatalf("expected subnet 198.51.100.0/24 status=banned, got %+v", summary.TopSubnets)
	}
}
