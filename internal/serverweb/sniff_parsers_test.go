package serverweb

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSniffParsers_TableDrivenBoundaries(t *testing.T) {
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

		items := parseSSExternalProbesWithRules(rawSS, defaultSSPortProbeRules)
		byIP := make(map[string]ssProbeItem, len(items))
		for _, it := range items {
			byIP[it.ip] = it
		}
		if len(byIP) != 4 {
			t.Fatalf("expected 4 unique external IPs (ignoring ESTAB :2222, LISTEN, loopback, unconfigured :8443), got %d: %+v", len(byIP), items)
		}
		if byIP["198.51.100.11"].vector != "TLS/443 握手探测" || byIP["198.51.100.12"].vector != "TLS/443 伪装回落嗅探" {
			t.Fatalf("unexpected 443 vector classification: %+v / %+v", byIP["198.51.100.11"], byIP["198.51.100.12"])
		}
		if byIP["198.51.100.13"].status != "observing" {
			t.Fatalf("expected :2222 TIME-WAIT observing, got %+v", byIP["198.51.100.13"])
		}
		if byIP["198.51.100.15"].hits != 2 {
			t.Fatalf("expected deduplicated hits=2 for 198.51.100.15, got %+v", byIP["198.51.100.15"])
		}

		// OCP extension: extend via declarative rule entry without modifying parser logic.
		extendedRules := append(append([]ssPortProbeRule(nil), defaultSSPortProbeRules...), ssPortProbeRule{
			Port:       8443,
			OnlyStates: []string{"SYN-RECV"},
			Vector:     "自定义蜜罐端口探测",
			Status:     "observing",
		})
		extItems := parseSSExternalProbesWithRules(rawSS, extendedRules)
		var foundCustom bool
		for _, it := range extItems {
			if it.ip == "203.0.113.55" && it.vector == "自定义蜜罐端口探测" && it.status == "observing" {
				foundCustom = true
			}
		}
		if !foundCustom {
			t.Fatalf("expected OCP custom rule for port 8443 to match 203.0.113.55, got %+v", extItems)
		}
	})

	t.Run("nft_duration_and_set_entries_boundaries", func(t *testing.T) {
		if d := parseNFTDuration("-5m"); d != 0 {
			t.Fatalf("expected negative duration clamped to 0, got %v", d)
		}
		if d := parseNFTDuration("99999d"); d != 3650*24*time.Hour {
			t.Fatalf("expected huge day duration clamped to 3650d, got %v", d)
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
		entries := parseNFTSetEntries(rawNFT, refNow)
		if len(entries) != 1 || entries[0].ip != "198.51.100.20" {
			t.Fatalf("expected only deduplicated recent 198.51.100.20 (CIDR and expired >24h skipped), got %+v", entries)
		}
		if entries[0].observedAt.IsZero() {
			t.Fatalf("expected non-zero observedAt derived from timeout-expires")
		}
	})

	t.Run("fail2ban_syslog_and_readTailBytes_boundaries", func(t *testing.T) {
		refNow := time.Date(2026, 1, 5, 10, 0, 0, 0, time.UTC)
		syslogTS := parseLogLineTimestamp("Dec 31 23:59:50 host kernel: [NFT] DROP", refNow)
		if syslogTS.Year() != 2025 {
			t.Fatalf("expected Dec 31 syslog relative to Jan 5 2026 to roll back to 2025, got %v", syslogTS)
		}

		banned := parseFail2banBannedIPs("Banned IP list:\t198.51.100.77 198.51.100.77 203.0.113.88")
		if len(banned) != 2 || banned[0] != "198.51.100.77" || banned[1] != "203.0.113.88" {
			t.Fatalf("unexpected banned IPs: %+v", banned)
		}

		f2bLog := strings.Join([]string{
			"2026-06-15 10:00:00 fail2ban.actions [1]: NOTICE [sshd] Found 198.51.100.40",
			"2026-06-15 10:01:00 fail2ban.actions [1]: NOTICE [sshd] Ban 198.51.100.40",
			"2026-06-15 10:01:05 fail2ban.actions [1]: NOTICE [sshd] Ban 127.0.0.1",
			"malformed line",
		}, "\n")
		tsMap := parseFail2banLogTimestamps(f2bLog, refNow)
		info, ok := tsMap["198.51.100.40"]
		if !ok || info.hits != 2 {
			t.Fatalf("expected 198.51.100.40 hits=2, got (%+v, %v)", info, ok)
		}
		if _, hasLocal := tsMap["127.0.0.1"]; hasLocal {
			t.Fatalf("expected internal loopback IP excluded from fail2ban timestamps")
		}

		tmpDir := t.TempDir()
		logPath := filepath.Join(tmpDir, "kern.log")
		if err := os.WriteFile(logPath, []byte("first-very-long-line\nsecond-line\nthird-line\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if b, err := readTailBytes(logPath, 0); err != nil || len(b) != 0 {
			t.Fatalf("readTailBytes(0) = (%q, %v)", string(b), err)
		}
		tail, err := readTailBytes(logPath, 24)
		if err != nil {
			t.Fatalf("readTailBytes failed: %v", err)
		}
		if strings.HasPrefix(string(tail), "first") || !strings.Contains(string(tail), "third-line") {
			t.Fatalf("expected partial first line trimmed and tail retained, got %q", string(tail))
		}
	})

	t.Run("concurrent_observe_and_snapshot_race_safe", func(t *testing.T) {
		tracker := NewSniffTracker(nil, nil, filepath.Join(t.TempDir(), "sniff.json"))
		tracker.EnableSystemProbe = false

		var wg sync.WaitGroup
		for i := range 8 {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				ip := "198.51.100." + string(rune('1'+idx))
				if idx == 7 {
					ip = "198.51.100.28"
				} else {
					ip = "198.51.100." + []string{"21", "22", "23", "24", "25", "26", "27"}[idx]
				}
				tracker.ObserveNode("local", "本机网关", ip, "SSH/:22 端口试探", "observing", 1)
				_ = tracker.SnapshotForNode(t.Context(), "all", false)
			}(i)
		}
		wg.Wait()
		snap := tracker.Snapshot(t.Context())
		if snap.TotalSniffIPs != 8 {
			t.Fatalf("expected 8 tracked external IPs after concurrent observe, got %d", snap.TotalSniffIPs)
		}
	})
}
