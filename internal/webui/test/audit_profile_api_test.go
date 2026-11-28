package webui_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"singctl/internal/audit"
	"singctl/internal/config"
	"singctl/internal/webui"
)

func TestAuditDeviceProfileAPI_ValidationReportAndAI(t *testing.T) {
	now := time.Date(2026, 11, 28, 21, 5, 10, 0, time.FixedZone("CST", 8*3600))
	clashSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"connections": []map[string]any{
				{
					"id":       "yt-1",
					"upload":   8192,
					"download": 524288,
					"start":    now.Format(time.RFC3339),
					"chains":   []string{"node-a", "Proxy"},
					"rule":     "rule_set=geosite-youtube",
					"metadata": map[string]any{
						"network":         "tcp",
						"sourceIP":        "192.168.1.50",
						"destinationIP":   "203.0.113.88",
						"destinationPort": "443",
						"host":            "www.youtube.com",
					},
				},
				{
					"id":       "ap-1",
					"upload":   2048,
					"download": 65536,
					"start":    now.Format(time.RFC3339),
					"chains":   []string{"DIRECT"},
					"rule":     "final",
					"metadata": map[string]any{
						"network":         "tcp",
						"sourceIP":        "192.168.1.50",
						"destinationIP":   "17.57.145.10",
						"destinationPort": "443",
						"host":            "push.apple.com",
					},
				},
			},
		})
	}))
	defer clashSrv.Close()

	tmp := t.TempDir()
	cfgPath := filepath.Join(tmp, "singctl.yaml")
	if err := os.WriteFile(cfgPath, []byte("subs: []\n"), 0600); err != nil {
		t.Fatal(err)
	}
	collector := audit.NewCollector(&config.Config{})
	collector.SetEndpointsForTest([]string{clashSrv.URL}, "", filepath.Join(tmp, "audit-state.json"))
	collector.SetProfileHistoryPathForTest(filepath.Join(tmp, "profile-history.json"), 64<<10)
	collector.SetLeaseFilesForTest(nil, filepath.Join(tmp, "no-arp"), filepath.Join(tmp, "no-hosts"))
	collector.SetNowFuncForTest(func() time.Time { return now })
	if !collector.SampleActiveConnections(t.Context()) {
		t.Fatal("seed SampleActiveConnections failed")
	}

	srv := webui.New(webui.Options{
		ConfigPath:     cfgPath,
		AuditCollector: collector,
	})

	// 1. Missing / invalid IP -> 400
	for _, badURL := range []string{"/api/audit/device-profile", "/api/audit/device-profile?ip=not-an-ip"} {
		rec := httptest.NewRecorder()
		srv.Mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, badURL, nil))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("GET %s status=%d, want 400 (body=%s)", badURL, rec.Code, rec.Body.String())
		}
	}

	// 2. Valid 24h & 7d profile queries
	for _, qRange := range []string{"24h", "7d"} {
		rec := httptest.NewRecorder()
		srv.Mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/audit/device-profile?ip=192.168.1.50&range="+qRange, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("GET profile range=%s status=%d body=%s", qRange, rec.Code, rec.Body.String())
		}
		var prof audit.DeviceProfileReport
		if err := json.Unmarshal(rec.Body.Bytes(), &prof); err != nil {
			t.Fatalf("decode profile range=%s: %v", qRange, err)
		}
		if prof.DeviceIP != "192.168.1.50" || prof.TotalForegroundMinutes != 1 || len(prof.TopApps) != 1 || prof.TopApps[0].AppName != "YouTube" {
			t.Fatalf("unexpected profile range=%s: %+v", qRange, prof)
		}
		if len(prof.HourlyTimeline) != 24 {
			t.Fatalf("expected 24 hourly buckets, got %d", len(prof.HourlyTimeline))
		}
		if !prof.Storage.AutoCleanup || prof.Storage.RetentionDays != 7 {
			t.Fatalf("unexpected storage budget metadata: %+v", prof.Storage)
		}
		if qRange == "7d" && len(prof.DailyTrend) == 0 {
			t.Fatalf("expected non-empty DailyTrend in 7d mode")
		}
	}

	// 3. Manual AI profile summary endpoint
	recAI := httptest.NewRecorder()
	reqAI := httptest.NewRequest(http.MethodPost, "/api/audit/device-profile/ai", bytes.NewBufferString(`{"deviceIp":"192.168.1.50","range":"24h"}`))
	reqAI.Header.Set("Content-Type", "application/json")
	srv.Mux.ServeHTTP(recAI, reqAI)
	if recAI.Code != http.StatusOK {
		t.Fatalf("POST /api/audit/device-profile/ai status=%d body=%s", recAI.Code, recAI.Body.String())
	}
	var aiRes audit.DeviceProfileAISummary
	if err := json.Unmarshal(recAI.Body.Bytes(), &aiRes); err != nil {
		t.Fatalf("decode AI summary: %v", err)
	}
	if !aiRes.OK || aiRes.Summary == "" {
		t.Fatalf("expected ok=true and non-empty AI summary, got %+v", aiRes)
	}
}
