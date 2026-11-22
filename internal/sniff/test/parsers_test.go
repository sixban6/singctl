// 文件职责：覆盖 sniff 日志解析器、指纹归一化、防撕裂尾部读取与 OCP 扩展表驱动单测及 Fuzz 测试。
package sniff_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"singctl/internal/sniff"
)

func TestSniffParsersAndFingerprints_TableDrivenBoundaries(t *testing.T) {
	normCases := []struct {
		raw  string
		want string
	}{
		{"198.51.100.42:54321", "198.51.100.42"},
		{"[::ffff:198.51.100.42]:54321", "198.51.100.42"},
		{"::ffff:198.51.100.42:54321", "198.51.100.42"},
		{"[::FFFF:203.0.113.9]:443", "203.0.113.9"},
		{"::FFFF:203.0.113.9:443", "203.0.113.9"},
		{"198.51.100.42%eth0:54321", "198.51.100.42"},
		{"[2001:db8::1%eth0]:54321", "2001:db8::1"},
		{"not-an-ip:443", ""},
		{"", ""},
	}
	for _, tc := range normCases {
		if got := sniff.NormalizeIPString(tc.raw); got != tc.want {
			t.Errorf("NormalizeIPString(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}

	if tag := sniff.MatchScannerTag("162.142.125.12", ""); tag != "Censys 测绘" {
		t.Fatalf("expected Censys tag, got %q", tag)
	}
	if tag := sniff.MatchScannerTag("198.51.100.1", "Shodan.io LLC"); tag != "Shodan 扫描" {
		t.Fatalf("expected Shodan ISP tag, got %q", tag)
	}

	t.Run("ss_port_probes_default_and_ocp_custom_rule", func(t *testing.T) {
		rawSS := strings.Join([]string{
			"State      Recv-Q Send-Q Local Address:Port   Peer Address:Port",
			"LISTEN     0      128    0.0.0.0:443          0.0.0.0:*",
			"SYN-RECV   0      0      192.0.2.1:443        198.51.100.11:40100",
			"ESTAB      0      0      192.0.2.1:443        198.51.100.12:40101",
			"TIME-WAIT  0      0      192.0.2.1:2222       198.51.100.13:40102",
			"ESTAB      0      0      192.0.2.1:2222       198.51.100.14:40103",
			"TIME-WAIT  0      0      192.0.2.1:80         198.51.100.15:40104",
			"TIME-WAIT  0      0      192.0.2.1:9445       198.51.100.15:40105",
			"SYN-RECV   0      0      192.0.2.1:80         127.0.0.1:40106",
			"SYN-RECV   0      0      192.0.2.1:8443       203.0.113.55:40107",
		}, "\n")

		items := sniff.ParseSSExternalProbes(rawSS)
		byIP := make(map[string]sniff.SSProbeItem, len(items))
		for _, it := range items {
			byIP[it.IP] = it
		}
		if len(byIP) != 4 {
			t.Fatalf("expected 4 unique external IPs, got %d: %+v", len(byIP), items)
		}
		if byIP["198.51.100.11"].Vector != "TLS/443 握手探测" || byIP["198.51.100.12"].Vector != "TLS/443 伪装回落嗅探" {
			t.Fatalf("unexpected 443 vector classification: %+v / %+v", byIP["198.51.100.11"], byIP["198.51.100.12"])
		}
		if byIP["198.51.100.13"].Status != "observing" || byIP["198.51.100.15"].Hits != 2 {
			t.Fatalf("unexpected status/hits: %+v / %+v", byIP["198.51.100.13"], byIP["198.51.100.15"])
		}

		extendedRules := append(sniff.DefaultSSPortProbeRules(), sniff.SSPortProbeRule{
			Port:       8443,
			OnlyStates: []string{"SYN-RECV"},
			Vector:     "自定义蜜罐端口探测",
			Status:     "observing",
		})
		extItems := sniff.ParseSSExternalProbesWithRules(rawSS, extendedRules)
		var foundCustom bool
		for _, it := range extItems {
			if it.IP == "203.0.113.55" && it.Vector == "自定义蜜罐端口探测" {
				foundCustom = true
			}
		}
		if !foundCustom {
			t.Fatalf("expected OCP custom rule match, got %+v", extItems)
		}
	})

	t.Run("nft_duration_set_entries_and_tail_bytes", func(t *testing.T) {
		if d := sniff.ParseNFTDuration("-5m"); d != 0 {
			t.Fatalf("expected negative duration clamped to 0, got %v", d)
		}
		if d := sniff.ParseNFTDuration("99999d"); d != 3650*24*time.Hour {
			t.Fatalf("expected huge day duration clamped to 3650d, got %v", d)
		}
		if d := sniff.ParseNFTDuration("2d3h"); d != 51*time.Hour {
			t.Fatalf("expected 51h, got %v", d)
		}

		refNow := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
		rawNFT := `table inet security {
			set blocklist_ip4 {
				type ipv4_addr
				elements = {
					198.51.100.20 timeout 7d expires 6d23h,
					198.51.100.20 timeout 7d expires 6d22h,
					198.51.100.0/24 timeout 7d expires 6d23h,
					203.0.113.99 timeout 7d expires 1d
				}
			}
		}`
		entries := sniff.ParseNFTSetEntries(rawNFT, refNow)
		if len(entries) != 1 || entries[0].IP != "198.51.100.20" || entries[0].ObservedAt.IsZero() {
			t.Fatalf("unexpected NFT set entries: %+v", entries)
		}

		janNow := time.Date(2026, 1, 5, 10, 0, 0, 0, time.UTC)
		if syslogTS := sniff.ParseLogLineTimestamp("Dec 31 23:59:50 host kernel: [NFT] DROP", janNow); syslogTS.Year() != 2025 {
			t.Fatalf("expected Dec 31 syslog relative to Jan 5 2026 to roll back to 2025, got %v", syslogTS)
		}

		dir := t.TempDir()
		logFile := filepath.Join(dir, "kern.log")
		line1 := "2026-05-01T10:00:00Z host kernel: [NFT] DROP IN=eth0 SRC=198.51.100.123 DST=203.0.113.1 PROTO=TCP DPT=23\n"
		line2 := "2026-05-01T10:00:01Z host kernel: [NFT] DROP IN=eth0 SRC=203.0.113.88 DST=203.0.113.1 PROTO=TCP DPT=3389\n"
		if err := os.WriteFile(logFile, []byte(line1+line2), 0600); err != nil {
			t.Fatal(err)
		}
		idx := strings.Index(line1, "198.51.100.123")
		maxBytes := int64(len(line1)+len(line2)) - int64(idx+1)
		tail, err := sniff.ReadTailBytes(logFile, maxBytes)
		if err != nil || strings.Contains(string(tail), "98.51.100.123") || !strings.Contains(string(tail), "203.0.113.88") {
			t.Fatalf("ReadTailBytes torn-line guard failed: tail=%q err=%v", string(tail), err)
		}
	})
}

func TestSniffTracker_RevisionCacheAndConcurrentPersistence(t *testing.T) {
	ctx := t.Context()
	tmpDir := t.TempDir()
	lim := newFakeBanLimiter()

	var fleetRev atomic.Uint64
	fleetRev.Store(1)
	var mu sync.Mutex
	targets := []sniff.RemoteTarget{}

	tracker := sniff.NewTracker(nil, lim, filepath.Join(tmpDir, "sniff.json"))
	tracker.EnableSystemProbe = false
	tracker.SetRemoteProvider(&sniff.RemoteProvider{
		ListTargets: func() ([]sniff.RemoteTarget, error) {
			mu.Lock()
			defer mu.Unlock()
			cp := make([]sniff.RemoteTarget, len(targets))
			copy(cp, targets)
			return cp, nil
		},
		Revision: func() uint64 { return fleetRev.Load() },
		Exec:     func(context.Context, sniff.RemoteTarget, string) (string, int, error) { return "", 1, nil },
	})

	for i := range 60 {
		ip := "198.51.100." + []string{"10", "11", "12", "13", "14", "15"}[i%6]
		tracker.Observe(ip, "TLS/443 伪装回落嗅探", "masqueraded", 1)
	}

	s1 := tracker.Snapshot(ctx)
	if s1.TotalSniffIPs != 6 {
		t.Fatalf("expected 6 unique IPs, got %d", s1.TotalSniffIPs)
	}
	rebuildsAfterFirst := tracker.SnapshotRebuilds()
	for range 5 {
		_ = tracker.Snapshot(ctx)
	}
	if got := tracker.SnapshotRebuilds(); got != rebuildsAfterFirst {
		t.Fatalf("expected cached Snapshot() to cause 0 rebuilds, went from %d to %d", rebuildsAfterFirst, got)
	}

	// Limiter attempt invalidation
	lim.recordLoginFail("203.0.113.105")
	sAfterLim := tracker.Snapshot(ctx)
	if sAfterLim.TotalSniffIPs != 7 {
		t.Fatalf("expected limiter attempt to invalidate cache and expose 7th IP, got %d", sAfterLim.TotalSniffIPs)
	}

	// Remote target list change invalidation
	mu.Lock()
	targets = append(targets, sniff.RemoteTarget{ID: "tokyo-1", Name: "Tokyo Node", Host: "203.0.113.150", Enabled: true, Online: true})
	fleetRev.Add(1)
	mu.Unlock()

	sAfterFleet := tracker.Snapshot(ctx)
	var foundTokyo bool
	for _, n := range sAfterFleet.Nodes {
		if n.ID == "tokyo-1" {
			foundTokyo = true
		}
	}
	if !foundTokyo {
		t.Fatalf("expected RemoteProvider revision bump to expose tokyo-1 immediately, got %+v", sAfterFleet.Nodes)
	}
}

func FuzzSniffParsers(f *testing.F) {
	f.Add("elements = { 198.51.100.5 timeout 7d expires 6d23h59m, 198.51.100.0/24 }")
	f.Add("2026-05-01 12:30:45,123 fail2ban.actions [123]: NOTICE [sshd] Ban 203.0.113.45")
	f.Add("SYN-RECV 0 0 [::ffff:203.0.113.1]:443 ::ffff:198.51.100.77:51234")
	f.Add("Mar  7 03:15:22 vps kernel: [NFT] SRC=198.51.100.9 DST=203.0.113.1 DPT=445")
	f.Add("   `- Banned IP list:\t198.51.100.11 2001:db8::2 invalid_tok")

	refNow := time.Date(2026, 1, 1, 0, 30, 0, 0, time.UTC)
	f.Fuzz(func(t *testing.T, raw string) {
		_ = sniff.NormalizeIPString(raw)
		_ = sniff.ComputeSubnetCIDR(raw)
		_ = sniff.MatchScannerTag(raw, raw)
		_ = sniff.ParseNFTDuration(raw)
		_ = sniff.ParseNFTSetEntries(raw, refNow)
		_ = sniff.ParseFail2banLogTimestamps(raw, refNow)
		_ = sniff.ParseFail2banBannedIPs(raw)
		_ = sniff.ParseSSExternalProbes(raw)
		_ = sniff.ParseLogLineTimestamp(raw, refNow)
	})
}
