// 文件职责：测试审计流活跃子连接下钻快照、Clash 级多维排序（latest/live_up/live_down）与原子批量封禁契约。
package audit_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"singctl/internal/audit"
	"singctl/internal/config"
)

func TestCollector_ActiveConnDetailsAndClashGradeSorting(t *testing.T) {
	now := time.Date(2026, 11, 24, 20, 0, 10, 0, time.UTC)
	poll := 0
	mockClash := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/connections" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		poll++
		up1, down1 := int64(1024), int64(2048)
		up2, down2 := int64(512), int64(4096)
		if poll >= 2 {
			up1 += 400_000   // +200 KB/s upload over 2s
			down1 += 10_000
			up2 += 1_000
			down2 += 1_600_000 // +800 KB/s download over 2s
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"connections": []map[string]any{
				{
					"id":          "conn-up-1",
					"upload":      up1,
					"download":    down1,
					"start":       now.Add(-45 * time.Second).Format(time.RFC3339Nano),
					"chains":      []string{"HK-01", "Proxy"},
					"rule":        "rule_set",
					"rulePayload": "geosite-cn",
					"metadata": map[string]any{
						"network":         "tcp",
						"type":            "tproxy-in",
						"sourceIP":        "192.168.1.50",
						"sourcePort":      "54321",
						"destinationIP":   "198.51.100.10",
						"destinationPort": "443",
						"host":            "upload.example.com",
					},
				},
				{
					"id":          "conn-up-2",
					"upload":      int64(2048),
					"download":    int64(1024),
					"start":       now.Add(-12 * time.Second).Format(time.RFC3339Nano),
					"chains":      []string{"HK-01", "Proxy"},
					"rule":        "rule_set",
					"rulePayload": "geosite-cn",
					"metadata": map[string]any{
						"network":         "tcp",
						"type":            "tproxy-in",
						"sourceIP":        "192.168.1.50",
						"sourcePort":      "54322",
						"destinationIP":   "198.51.100.11",
						"destinationPort": "443",
						"host":            "upload.example.com",
					},
				},
				{
					"id":          "conn-down-1",
					"upload":      up2,
					"download":    down2,
					"start":       now.Add(-5 * time.Second).Format(time.RFC3339Nano),
					"chains":      []string{"DIRECT"},
					"rule":        "final",
					"metadata": map[string]any{
						"network":         "udp",
						"type":            "tproxy-in",
						"sourceIP":        "192.168.1.60",
						"sourcePort":      "60001",
						"destinationIP":   "203.0.113.20",
						"destinationPort": "443",
						"host":            "video.example.com",
					},
				},
			},
		})
	}))
	defer mockClash.Close()

	curTime := now
	col := audit.NewCollector(&config.Config{})
	col.SetEndpointsForTest([]string{mockClash.URL}, "", filepath.Join(t.TempDir(), "state.json"))
	col.SetNowFuncForTest(func() time.Time { return curTime })

	// Poll 1: baseline
	_ = col.Collect(t.Context(), audit.CollectOptions{})
	// Poll 2: 2s later to populate live rates + active sub-connection details
	curTime = now.Add(2 * time.Second)
	repUp := col.Collect(t.Context(), audit.CollectOptions{SortBy: "live_up"})
	if len(repUp.Flows) != 2 {
		t.Fatalf("expected 2 aggregated flows, got %d", len(repUp.Flows))
	}
	if repUp.Flows[0].Target != "upload.example.com" {
		t.Fatalf("sort=live_up expected upload.example.com first, got %q", repUp.Flows[0].Target)
	}
	if repUp.Flows[0].LastSeenUnix == 0 {
		t.Fatal("expected non-zero LastSeenUnix")
	}
	if len(repUp.Flows[0].ActiveConnDetails) != 2 {
		t.Fatalf("expected 2 active sub-connection details for upload.example.com, got %d: %+v",
			len(repUp.Flows[0].ActiveConnDetails), repUp.Flows[0].ActiveConnDetails)
	}
	d0 := repUp.Flows[0].ActiveConnDetails[0]
	if d0.ID != "conn-up-1" || d0.SourcePort != "54321" || d0.UploadBps <= 0 || d0.InboundType != "tproxy-in" || d0.DurationSec < 40 {
		t.Fatalf("unexpected active sub-connection detail: %+v", d0)
	}

	// Sort by live_down must put video.example.com first
	repDown := col.Collect(t.Context(), audit.CollectOptions{SortBy: "live_down"})
	if repDown.Flows[0].Target != "video.example.com" {
		t.Fatalf("sort=live_down expected video.example.com first, got %q", repDown.Flows[0].Target)
	}

	// SortFlows directly for latest (desc & asc)
	flows := []audit.FlowRecord{
		{Target: "older.example.com", LastSeenUnix: 1000},
		{Target: "newest.example.com", LastSeenUnix: 3000},
		{Target: "mid.example.com", LastSeenUnix: 2000},
	}
	audit.SortFlows(flows, "latest", false)
	if flows[0].Target != "newest.example.com" || flows[2].Target != "older.example.com" {
		t.Fatalf("SortFlows(latest, desc) unexpected order: %+v", flows)
	}
	audit.SortFlows(flows, "latest", true)
	if flows[0].Target != "older.example.com" || flows[2].Target != "newest.example.com" {
		t.Fatalf("SortFlows(latest, asc) unexpected order: %+v", flows)
	}
}

func TestEnforcer_BlockBatch_AtomicSingleReloadAndSafety(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "singctl.yaml")
	sbPath := filepath.Join(tmpDir, "config.json")
	aghPath := filepath.Join(tmpDir, "missing-agh.yaml")

	cfg := &config.Config{}
	if err := config.Save(cfgPath, cfg); err != nil {
		t.Fatal(err)
	}
	baseSB := `{
  "dns": {"servers": [{"tag": "dns_local", "type": "udp", "server": "223.5.5.5", "server_port": 53}], "rules": [], "final": "dns_local"},
  "inbounds": [{"type": "tproxy", "tag": "tproxy-in", "listen": "::", "listen_port": 7895}],
  "outbounds": [{"type": "direct", "tag": "direct"}],
  "route": {"rules": [{"action": "sniff"}], "final": "direct"}
}`
	if err := os.WriteFile(sbPath, []byte(baseSB), 0600); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var closedIDs []string
	mockClash := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/connections":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"connections": []map[string]any{
					{
						"id": "kill-1",
						"metadata": map[string]any{
							"sourceIP": "192.168.1.50",
							"host":     "bad1.example.com",
						},
					},
					{
						"id": "kill-2",
						"metadata": map[string]any{
							"sourceIP": "192.168.1.60",
							"host":     "bad2.example.com",
						},
					},
					{
						"id": "keep-other-device",
						"metadata": map[string]any{
							"sourceIP": "192.168.1.99",
							"host":     "bad1.example.com",
						},
					},
				},
			})
		case r.Method == http.MethodDelete && len(r.URL.Path) > len("/connections/"):
			mu.Lock()
			closedIDs = append(closedIDs, r.URL.Path[len("/connections/"):])
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer mockClash.Close()

	enf := audit.NewEnforcer(cfg, cfgPath)
	enf.SetPathsForTest(sbPath, aghPath, []string{mockClash.URL}, "")
	enf.SetDeps(mockClash.Client(), func() string { return "" })

	// Empty batch must fail cleanly
	if _, err := enf.BlockBatch(t.Context(), nil); err == nil {
		t.Fatal("expected error for empty batch")
	}

	// Mixed batch: 2 valid (1 device-scoped, 1 global) + 1 duplicate + 1 protected target
	res, err := enf.BlockBatch(t.Context(), []audit.BlockBatchItem{
		{Target: "bad1.example.com", SourceIP: "192.168.1.50", Reason: "device telemetry"},
		{Target: "bad1.example.com", SourceIP: "192.168.1.50", Reason: "duplicate"},
		{Target: "bad2.example.com", Reason: "global tracker"},
		{Target: "127.0.0.1", Reason: "should be rejected"},
	})
	if err != nil {
		t.Fatalf("BlockBatch failed: %v", err)
	}
	if !res.OK || res.Added != 2 || res.Failed != 1 || !res.ConfigSaved {
		t.Fatalf("unexpected BlockBatchResult: %+v", res)
	}
	if res.KilledConnections != 2 {
		t.Fatalf("expected 2 matching connections killed (keep-other-device spared), got %d (closed=%v)", res.KilledConnections, closedIDs)
	}

	reloaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(reloaded.CustomRules.Block) != 2 {
		t.Fatalf("expected 2 persisted block rules, got %d: %+v", len(reloaded.CustomRules.Block), reloaded.CustomRules.Block)
	}

	// All-invalid batch must return error
	if _, err := enf.BlockBatch(t.Context(), []audit.BlockBatchItem{{Target: "127.0.0.1"}}); err == nil {
		t.Fatal("expected error when every item in batch is protected/invalid")
	}
}
