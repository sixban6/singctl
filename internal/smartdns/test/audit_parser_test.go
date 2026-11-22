// 文件职责：验证 SmartDNS tmpfs 审计日志多格式解析、拦截判定、轮转截断检测与并发安全增量读取。
package smartdns_test

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"singctl/internal/smartdns"
)

func TestParseAuditLine_AllFormatsAndBlockedDetection(t *testing.T) {
	cases := []struct {
		name      string
		line      string
		wantOK    bool
		domain    string
		qtype     string
		latencyMs float64
		blocked   bool
	}{
		{
			name:      "classic_allowed_ipv4",
			line:      "[2026-11-23 00:00:01,123] 127.0.0.1 query example.com, type 1, time 12ms, speed: 10.1ms, result 192.0.2.1",
			wantOK:    true,
			domain:    "example.com",
			qtype:     "A",
			latencyMs: 12,
			blocked:   false,
		},
		{
			name:      "classic_with_group_and_multi_ip",
			line:      "[2026-11-23 00:00:02,456] 127.0.0.1 query api.example.com., type 28, time 4.5ms, speed: 3.2ms, group default, result 2001:db8::1, 2001:db8::2",
			wantOK:    true,
			domain:    "api.example.com",
			qtype:     "AAAA",
			latencyMs: 4.5,
			blocked:   false,
		},
		{
			name:      "blocked_soa",
			line:      "[2026-11-23 00:00:03,000] 127.0.0.1 query ads.example.com, type 1, time 0ms, speed: 0.0ms, result SOA",
			wantOK:    true,
			domain:    "ads.example.com",
			qtype:     "A",
			latencyMs: 0,
			blocked:   true,
		},
		{
			name:      "blocked_nxdomain",
			line:      "[2026-11-23 00:00:04,000] 127.0.0.1 query track.example.com, type 1, time 1ms, group default, result NXDOMAIN",
			wantOK:    true,
			domain:    "track.example.com",
			qtype:     "A",
			latencyMs: 1,
			blocked:   true,
		},
		{
			name:      "blocked_zero_ipv4",
			line:      "[2026-11-23 00:00:05,000] 127.0.0.1 query zero.example.com, type 1, time 0ms, result 0.0.0.0",
			wantOK:    true,
			domain:    "zero.example.com",
			qtype:     "A",
			latencyMs: 0,
			blocked:   true,
		},
		{
			name:      "blocked_zero_ipv6",
			line:      "[2026-11-23 00:00:06,000] 127.0.0.1 query v6block.example.com, type 28, time 0ms, result ::",
			wantOK:    true,
			domain:    "v6block.example.com",
			qtype:     "AAAA",
			latencyMs: 0,
			blocked:   true,
		},
		{
			name:      "blocked_empty_result",
			line:      "[2026-11-23 00:00:07,000] 127.0.0.1 query empty.example.com, type 65, time 2ms, result ",
			wantOK:    true,
			domain:    "empty.example.com",
			qtype:     "HTTPS",
			latencyMs: 2,
			blocked:   true,
		},
		{
			name:      "colon_style_dns_server_variant",
			line:      "[2026-11-23 00:00:08,261][ INFO][ dns_server.c:2390] result: cdn.example.com, client: 127.0.0.1, qtype: 1, id: 4708, group: default, time: 7ms",
			wantOK:    true,
			domain:    "cdn.example.com",
			qtype:     "A",
			latencyMs: 7,
			blocked:   false,
		},
		{
			name:      "real_release48_local_adblock_a_lowercase_soa",
			line:      "[2026-11-22 17:51:58,602] 127.0.0.1 query ads.example.com, type 1, time 0ms, speed: -0.1ms, group default, result soa",
			wantOK:    true,
			domain:    "ads.example.com",
			qtype:     "A",
			latencyMs: 0,
			blocked:   true,
		},
		{
			name:      "real_release48_aaaa_force_soa_not_blocked",
			line:      "[2026-11-22 17:50:51,123] 127.0.0.1 query www.example.com, type 28, time 0ms, speed: -0.1ms, group default, result soa",
			wantOK:    true,
			domain:    "www.example.com",
			qtype:     "AAAA",
			latencyMs: 0,
			blocked:   false,
		},
		{
			name:      "real_release48_aaaa_ipv4_only_upstream_soa_not_blocked",
			line:      "[2026-11-22 17:51:58,579] 127.0.0.1 query v4only.example.com, type 28, time 405ms, speed: -0.1ms, group default, result soa",
			wantOK:    true,
			domain:    "v4only.example.com",
			qtype:     "AAAA",
			latencyMs: 405,
			blocked:   false,
		},
		{
			name:      "real_release48_rewrite_aaaa_soa_not_blocked",
			line:      "[2026-11-22 17:51:58,794] 127.0.0.1 query nas.example.com, type 28, time 0ms, speed: -0.1ms, group default, result soa",
			wantOK:    true,
			domain:    "nas.example.com",
			qtype:     "AAAA",
			latencyMs: 0,
			blocked:   false,
		},
		{
			name:      "real_release48_upstream_nodata_a_soa_not_blocked",
			line:      "[2026-11-22 17:51:58,790] 127.0.0.1 query ok.ads.example.com, type 1, time 187ms, speed: -0.1ms, group default, result soa",
			wantOK:    true,
			domain:    "ok.ads.example.com",
			qtype:     "A",
			latencyMs: 187,
			blocked:   false,
		},
		{
			name:      "real_release48_upstream_nxdomain_empty_result_not_blocked",
			line:      "[2026-11-22 17:51:59,024] 127.0.0.1 query missing.example.com, type 1, time 229ms, speed: -0.1ms, group default, result ",
			wantOK:    true,
			domain:    "missing.example.com",
			qtype:     "A",
			latencyMs: 229,
			blocked:   false,
		},
		{
			name:      "real_release48_upstream_servfail_timeout_not_blocked",
			line:      "[2026-11-22 17:50:53,829] 127.0.0.1 query timeout.example.com, type 1, time 2707ms, speed: -0.1ms, group default, result ",
			wantOK:    true,
			domain:    "timeout.example.com",
			qtype:     "A",
			latencyMs: 2707,
			blocked:   false,
		},
		{
			name:      "real_release48_allowed_ipv4_with_speed",
			line:      "[2026-11-22 17:51:58,600] 127.0.0.1 query ok.example.com, type 1, time 429ms, speed: 19.8ms, group default, result 192.0.2.10",
			wantOK:    true,
			domain:    "ok.example.com",
			qtype:     "A",
			latencyMs: 429,
			blocked:   false,
		},
		{
			name:      "real_release48_allowed_rewrite",
			line:      "[2026-11-22 17:51:58,793] 127.0.0.1 query nas.example.com, type 1, time 0ms, speed: -0.1ms, group default, result 192.168.1.50",
			wantOK:    true,
			domain:    "nas.example.com",
			qtype:     "A",
			latencyMs: 0,
			blocked:   false,
		},
		{
			name:      "real_release48_allowed_multi_ipv6",
			line:      "[2026-11-22 17:51:59,334] 127.0.0.1 query dual.example.com, type 28, time 184ms, speed: -0.1ms, group default, result 2001:db8::1, 2001:db8::2",
			wantOK:    true,
			domain:    "dual.example.com",
			qtype:     "AAAA",
			latencyMs: 184,
			blocked:   false,
		},
		{
			name:   "empty_and_malformed",
			line:   "not a valid smartdns audit line",
			wantOK: false,
		},
		{
			name:   "blank",
			line:   "   ",
			wantOK: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			entry, ok := smartdns.ParseAuditLine(tc.line)
			if ok != tc.wantOK {
				t.Fatalf("ParseAuditLine ok = %v, want %v (entry=%+v)", ok, tc.wantOK, entry)
			}
			if !tc.wantOK {
				return
			}
			if entry.Timestamp.IsZero() {
				t.Error("expected non-zero Timestamp")
			}
			if entry.Domain != tc.domain {
				t.Errorf("Domain = %q, want %q", entry.Domain, tc.domain)
			}
			if entry.QueryType != tc.qtype {
				t.Errorf("QueryType = %q, want %q", entry.QueryType, tc.qtype)
			}
			if entry.LatencyMs != tc.latencyMs {
				t.Errorf("LatencyMs = %v, want %v", entry.LatencyMs, tc.latencyMs)
			}
			if entry.Blocked != tc.blocked {
				t.Errorf("Blocked = %v, want %v", entry.Blocked, tc.blocked)
			}
		})
	}
}

func TestAuditLogTailer_IncrementalRotationTruncationAndConcurrency(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "singctl-smartdns-audit.log")
	tailer := smartdns.NewAuditLogTailer(logPath)

	// Missing file returns empty without error
	entries, err := tailer.ReadNew()
	if err != nil || len(entries) != 0 {
		t.Fatalf("missing file ReadNew = (%v, %v), want empty/nil", entries, err)
	}

	// Write initial 2 lines + 1 partial line without newline
	line1 := "[2026-11-23 00:00:01,100] 127.0.0.1 query a.example.com, type 1, time 5ms, result 192.0.2.1\n"
	line2 := "[2026-11-23 00:00:02,200] 127.0.0.1 query ad.example.com, type 1, time 0ms, result SOA\n"
	partA := "[2026-11-23 00:00:03,300] 127.0.0.1 query half.example.com, "
	partB := "type 28, time 8ms, result 2001:db8::1\n"

	if err := os.WriteFile(logPath, []byte(line1+line2+partA), 0600); err != nil {
		t.Fatal(err)
	}

	entries, err = tailer.ReadNew()
	if err != nil {
		t.Fatalf("first ReadNew failed: %v", err)
	}
	if len(entries) != 2 || entries[0].Domain != "a.example.com" || entries[0].Blocked || entries[1].Domain != "ad.example.com" || !entries[1].Blocked {
		t.Fatalf("unexpected first entries: %+v", entries)
	}
	if tailer.Offset() == 0 {
		t.Fatal("expected positive offset after read")
	}

	// Second call with no new data returns empty
	entries, err = tailer.ReadNew()
	if err != nil || len(entries) != 0 {
		t.Fatalf("idle ReadNew = (%v, %v), want empty/nil", entries, err)
	}

	// Complete the partial line
	f, err := os.OpenFile(logPath, os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString(partB)
	_ = f.Close()

	entries, err = tailer.ReadNew()
	if err != nil || len(entries) != 1 || entries[0].Domain != "half.example.com" || entries[0].QueryType != "AAAA" {
		t.Fatalf("partial completion ReadNew = (%+v, %v)", entries, err)
	}

	// Simulate SmartDNS audit-size 128k rotation: rename old file and create new file (even if larger than previous)
	if err := os.Rename(logPath, logPath+".1"); err != nil {
		t.Fatal(err)
	}
	rotated := "[2026-11-23 00:01:00,000] 127.0.0.1 query rot1.example.com, type 1, time 3ms, result 192.0.2.2\n" +
		"[2026-11-23 00:01:01,000] 127.0.0.1 query rot2.example.com, type 1, time 4ms, result 192.0.2.3\n" +
		"[2026-11-23 00:01:02,000] 127.0.0.1 query rot3.example.com, type 1, time 5ms, result 192.0.2.4\n" +
		"[2026-11-23 00:01:03,000] 127.0.0.1 query rot4.example.com, type 1, time 6ms, result 192.0.2.5\n"
	if err := os.WriteFile(logPath, []byte(rotated), 0600); err != nil {
		t.Fatal(err)
	}

	entries, err = tailer.ReadNew()
	if err != nil || len(entries) != 4 || entries[0].Domain != "rot1.example.com" {
		t.Fatalf("after inode rotation ReadNew = (%+v, %v), want 4 rotated entries", entries, err)
	}

	// Simulate in-place truncation (smaller size on same inode)
	truncated := "[2026-11-23 00:02:00,000] 127.0.0.1 query trunc.example.com, type 1, time 2ms, result 192.0.2.9\n"
	if err := os.WriteFile(logPath, []byte(truncated), 0600); err != nil {
		t.Fatal(err)
	}
	entries, err = tailer.ReadNew()
	if err != nil || len(entries) != 1 || entries[0].Domain != "trunc.example.com" {
		t.Fatalf("after truncation ReadNew = (%+v, %v), want 1 entry", entries, err)
	}

	// Reset re-reads from byte 0
	tailer.Reset()
	if tailer.Offset() != 0 {
		t.Fatalf("expected offset 0 after Reset, got %d", tailer.Offset())
	}
	entries, err = tailer.ReadNew()
	if err != nil || len(entries) != 1 || entries[0].Domain != "trunc.example.com" {
		t.Fatalf("after Reset ReadNew = (%+v, %v)", entries, err)
	}

	// Concurrent ReadNew under -race must be safe
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 10 {
				_, _ = tailer.ReadNew()
			}
		})
	}
	wg.Wait()
}
