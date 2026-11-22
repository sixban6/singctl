// 文件职责：覆盖 SubHub 订阅访问日志 0600 落盘、爬虫 UA 识别与 24h 防盗刷风险评估表驱动单测。
package subhub_test

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"singctl/internal/subhub"
)

func TestEvaluateAccessRisk_TableDrivenAndConcurrency(t *testing.T) {
	nowStr := time.Now().UTC().Format(time.RFC3339)
	oldStr := time.Now().UTC().Add(-48 * time.Hour).Format(time.RFC3339)

	t.Run("safe_warn_high_expired_and_denied_cases", func(t *testing.T) {
		emptyRisk := subhub.EvaluateAccessRisk(nil)
		if emptyRisk.Level != "safe" || emptyRisk.Reasons == nil || len(emptyRisk.Reasons) != 0 {
			t.Fatalf("expected safe with empty non-nil reasons slice, got %+v", emptyRisk)
		}

		safeRisk := subhub.EvaluateAccessRisk([]subhub.AccessLogEntry{
			{Timestamp: nowStr, IP: "198.51.100.1", CountryCode: "SG", UserAgent: "Shadowrocket/2075", Status: "ok"},
			{Timestamp: nowStr, IP: "198.51.100.2", CountryCode: "SG", UserAgent: "ClashMetaForAndroid/2.10", Status: "ok"},
			{Timestamp: oldStr, IP: "203.0.113.99", CountryCode: "RU", UserAgent: "python-requests/2.31", Status: "ok"}, // >24h ignored
		})
		if safeRisk.Level != "safe" || safeRisk.UniqueIPs24h != 2 || safeRisk.UniqueCountries24h != 1 {
			t.Fatalf("expected safe risk ignoring >24h entry, got %+v", safeRisk)
		}

		deniedWarn := subhub.EvaluateAccessRisk([]subhub.AccessLogEntry{
			{Timestamp: nowStr, IP: "198.51.100.10", Status: "denied"},
			{Timestamp: nowStr, IP: "198.51.100.11", Status: "denied"},
			{Timestamp: nowStr, IP: "198.51.100.12", Status: "denied"},
		})
		if deniedWarn.Level != "warn" || deniedWarn.DeniedHits24h != 3 {
			t.Fatalf("expected warn on 3 denied key probes, got %+v", deniedWarn)
		}

		var highLogs []subhub.AccessLogEntry
		countries := []string{"US", "NL", "DE", "RU"}
		for i := 1; i <= 11; i++ {
			highLogs = append(highLogs, subhub.AccessLogEntry{
				Timestamp:   nowStr,
				IP:          fmt.Sprintf("203.0.113.%d", i),
				CountryCode: countries[i%len(countries)],
				UserAgent:   "python-requests/2.31.0",
				Status:      "ok",
			})
		}
		highRisk := subhub.EvaluateAccessRisk(highLogs)
		if highRisk.Level != "high" || highRisk.UniqueIPs24h != 11 || highRisk.UniqueCountries24h != 4 || len(highRisk.Reasons) < 2 {
			t.Fatalf("expected high risk summary, got %+v", highRisk)
		}
	})

	t.Run("suspicious_ua_and_0600_access_log_persistence", func(t *testing.T) {
		if !subhub.IsSuspiciousSubUA("") || !subhub.IsSuspiciousSubUA("curl/8.5.0") || !subhub.IsSuspiciousSubUA("Go-http-client/2.0") {
			t.Fatal("expected empty/curl/Go-http-client UAs flagged suspicious")
		}
		if subhub.IsSuspiciousSubUA("Shadowrocket/2078") {
			t.Fatal("expected Shadowrocket UA not flagged suspicious")
		}

		dir := t.TempDir()
		st := subhub.NewStore(dir, filepath.Join(dir, "sub-store.json"))
		var wg sync.WaitGroup
		for i := range 6 {
			wg.Go(func() {
				st.RecordAccess(subhub.AccessLogEntry{
					IP:        fmt.Sprintf("198.51.100.%d", i+1),
					ClientApp: "Sing-box",
					UserAgent: "SFI/1.12.0",
					Target:    "Sing-Box",
					Status:    "ok",
				})
				_, _ = st.ListAccessLogs()
			})
		}
		wg.Wait()

		auditPath := filepath.Join(dir, ".access_audit.json")
		fi, err := os.Stat(auditPath)
		if err != nil || fi.Mode().Perm() != 0600 {
			t.Fatalf("expected 0600 .access_audit.json, got %v err=%v", fi, err)
		}
	})
}
