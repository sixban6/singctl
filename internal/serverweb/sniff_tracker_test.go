package serverweb

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
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
		if ipStat.FirstSeen == "" || ipStat.LastSeen == "" {
			t.Fatalf("expected non-empty FirstSeen and LastSeen for IP %s, got first=%q last=%q", ipStat.IP, ipStat.FirstSeen, ipStat.LastSeen)
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

func TestSniffTrackerMultiNodeTimestampsAndFullList(t *testing.T) {
	persistFile := filepath.Join(t.TempDir(), ".serverweb_sniff.json")
	tracker := NewSniffTracker(NewIPGeoResolver(), nil, persistFile)
	tracker.enableSystemProbe = false

	baseNow := time.Now().Truncate(time.Second)
	t1 := baseNow.Add(-2 * time.Hour)
	t2 := baseNow.Add(-15 * time.Minute)

	// 同一扫描 IP 先后探测本机与子节点，验证开始时间保留最早值、最近时间保留最新值
	tracker.ObserveNodeAt("local", "本机网关", "198.51.100.77", "TLS/443 伪装回落嗅探", "masqueraded", 3, t1, t1)
	tracker.ObserveNodeAt("jp-tyo", "日本东京", "198.51.100.77", "SSH 暴力破解", "banned", 5, t2, t2)

	// 在 us-lax 子节点注入 12 个独立嗅探 IP，验证不再被 Top 8 截断
	for i := 1; i <= 12; i++ {
		ip := fmt.Sprintf("203.0.113.%d", i)
		tracker.ObserveNodeAt("us-lax", "美国洛杉矶", ip, "HTTP/80 端口嗅探", "masqueraded", i, t1, t2)
	}

	// 1. 查看全集群汇总 ("all")：应包含 1 + 12 = 13 个 IP，全部返回不截断
	allSum := tracker.SnapshotForNode(t.Context(), "all", false)
	if allSum.TotalSniffIPs != 13 || len(allSum.TopIPs) != 13 {
		t.Fatalf("expected all 13 IPs returned without Top 8 truncation, got total=%d len=%d", allSum.TotalSniffIPs, len(allSum.TopIPs))
	}

	var merged77 *SniffIPStat
	for i := range allSum.TopIPs {
		if allSum.TopIPs[i].IP == "198.51.100.77" {
			merged77 = &allSum.TopIPs[i]
			break
		}
	}
	if merged77 == nil {
		t.Fatalf("expected 198.51.100.77 in cluster summary")
	}
	if merged77.Hits != 8 || merged77.Status != "banned" {
		t.Fatalf("expected merged hits=8 status=banned, got %+v", *merged77)
	}
	if merged77.FirstSeen != t1.Format(sniffTimeLayout) || merged77.LastSeen != t2.Format(sniffTimeLayout) {
		t.Fatalf("expected firstSeen=%s lastSeen=%s, got first=%s last=%s",
			t1.Format(sniffTimeLayout), t2.Format(sniffTimeLayout), merged77.FirstSeen, merged77.LastSeen)
	}
	if len(merged77.Nodes) != 2 {
		t.Fatalf("expected 2 nodes on 198.51.100.77, got %+v", merged77.Nodes)
	}

	// 2. 分主机查看 "us-lax"：应仅包含该节点的 12 个 IP
	usSum := tracker.SnapshotForNode(t.Context(), "us-lax", false)
	if usSum.TotalSniffIPs != 12 || len(usSum.TopIPs) != 12 {
		t.Fatalf("expected 12 IPs for node us-lax, got %d", usSum.TotalSniffIPs)
	}

	// 3. 分主机查看 "local"：应仅包含本机的 1 个 IP
	localSum := tracker.SnapshotForNode(t.Context(), "local", false)
	if localSum.TotalSniffIPs != 1 || localSum.TopIPs[0].IP != "198.51.100.77" {
		t.Fatalf("expected 1 IP (198.51.100.77) on local node, got %+v", localSum.TopIPs)
	}

	// 4. 验证持久化文件权限 (0600) 及重启恢复
	tracker.mu.Lock()
	tracker.saveLocked(true)
	tracker.mu.Unlock()
	if st, err := os.Stat(persistFile); err != nil {
		t.Fatalf("expected persist file to exist: %v", err)
	} else if st.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 permission on sniff persist file, got %o", st.Mode().Perm())
	}

	reloaded := NewSniffTracker(NewIPGeoResolver(), nil, persistFile)
	reloaded.enableSystemProbe = false
	reSum := reloaded.SnapshotForNode(t.Context(), "all", false)
	if reSum.TotalSniffIPs != 13 {
		t.Fatalf("expected 13 IPs after reload from persist file, got %d", reSum.TotalSniffIPs)
	}
}

func TestSniffTrackerRemoteIngestAndLogTimestamps(t *testing.T) {
	tracker := NewSniffTracker(NewIPGeoResolver(), nil)
	tracker.enableSystemProbe = false

	now := time.Now().Truncate(time.Second)
	tsEarly := now.Add(-45 * time.Minute).Format(time.RFC3339)
	tsLate := now.Add(-5 * time.Minute).Format(time.RFC3339)

	remoteRaw := fmt.Sprintf(`
===SINGCTL_TRUSTED===
{"connections":[{"metadata":{"sourceIP":"192.0.2.88"}}]}
===SINGCTL_NFT===
table inet security {
	set blocklist_ip4 {
		elements = { 198.51.100.33 timeout 6d }
	}
}
===SINGCTL_F2B===
Status for the jail: sshd
   |- Banned IP list:	203.0.113.44
===SINGCTL_KERN===
%s sg-node kernel: [NFT] Blocked IN=eth0 SRC=198.51.100.90 DST=192.0.2.1 PROTO=TCP DPT=3389
%s sg-node kernel: [NFT] Blocked IN=eth0 SRC=198.51.100.90 DST=192.0.2.1 PROTO=TCP DPT=3389
===SINGCTL_SS===
ESTAB 0 0 192.0.2.1:443 192.0.2.88:54321
SYN-RECV 0 0 192.0.2.1:443 198.51.100.120:60123
`, tsEarly, tsLate)

	tracker.ingestRemoteSniffOutput("sg-1", "新加坡节点", remoteRaw)

	sgSum := tracker.SnapshotForNode(t.Context(), "sg-1", false)
	if sgSum.TotalSniffIPs != 4 {
		t.Fatalf("expected 4 sniffing IPs on sg-1 (excluding trusted 192.0.2.88), got %d: %+v", sgSum.TotalSniffIPs, sgSum.TopIPs)
	}

	var nft90 *SniffIPStat
	for i := range sgSum.TopIPs {
		if sgSum.TopIPs[i].IP == "192.0.2.88" {
			t.Fatalf("trusted sing-box client 192.0.2.88 must be excluded")
		}
		if sgSum.TopIPs[i].IP == "198.51.100.90" {
			nft90 = &sgSum.TopIPs[i]
		}
	}
	if nft90 == nil {
		t.Fatalf("expected 198.51.100.90 from remote kernel log")
	}
	wantFirst := now.Add(-45 * time.Minute).Format(sniffTimeLayout)
	wantLast := now.Add(-5 * time.Minute).Format(sniffTimeLayout)
	if nft90.FirstSeen != wantFirst || nft90.LastSeen != wantLast || nft90.Hits != 2 {
		t.Fatalf("expected 198.51.100.90 hits=2 first=%s last=%s, got %+v", wantFirst, wantLast, *nft90)
	}
}
