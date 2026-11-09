package test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"singctl/internal/telemetry"
	"sync/atomic"
	"testing"
	"time"
)

func TestEnsureConfigTelemetryAndCollector(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.json")

	initial := `{
  "inbounds": [{"type": "vless", "tag": "vless-in"}],
  "outbounds": [{"type": "direct", "tag": "DC"}],
  "experimental": {"cache_file": {"enabled": true}}
}`
	if err := os.WriteFile(cfgPath, []byte(initial), 0600); err != nil {
		t.Fatal(err)
	}

	changed, addr, secret, err := telemetry.EnsureConfigTelemetry(cfgPath)
	if err != nil {
		t.Fatalf("EnsureConfigTelemetry error: %v", err)
	}
	if !changed || addr != telemetry.DefaultControllerAddr || len(secret) < 16 {
		t.Fatalf("unexpected telemetry setup: changed=%v addr=%q secretLen=%d", changed, addr, len(secret))
	}

	// Second call must be idempotent
	changed2, addr2, secret2, err := telemetry.EnsureConfigTelemetry(cfgPath)
	if err != nil || changed2 || addr2 != addr || secret2 != secret {
		t.Fatalf("expected idempotent call, got changed=%v addr=%q secret=%q err=%v", changed2, addr2, secret2, err)
	}

	// Spin up mock loopback Clash API server
	var upCounter atomic.Int64
	var dnCounter atomic.Int64
	upCounter.Store(100_000)
	dnCounter.Store(500_000)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+secret {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"uploadTotal":   upCounter.Load(),
			"downloadTotal": dnCounter.Load(),
			"memory":        15728640,
			"connections": []map[string]any{
				{
					"id":       "c1",
					"upload":   20000,
					"download": 300000,
					"chains":   []string{"WARP"},
					"rule":     "rule_set=rule-openai",
					"metadata": map[string]any{
						"type": "hysteria2/HYSTERIA2",
						"host": "chatgpt.com",
					},
				},
				{
					"id":       "c2",
					"upload":   10000,
					"download": 200000,
					"chains":   []string{"DC"},
					"rule":     "rule_set=rule-youtube",
					"metadata": map[string]any{
						"type": "vless/vless-in",
						"host": "googlevideo.com",
					},
				},
			},
		})
	}))
	defer srv.Close()

	// Point config's external_controller to srv's loopback address
	var doc map[string]any
	raw, _ := os.ReadFile(cfgPath)
	_ = json.Unmarshal(raw, &doc)
	doc["experimental"].(map[string]any)["clash_api"].(map[string]any)["external_controller"] = srv.Listener.Addr().String()
	updated, _ := json.Marshal(doc)
	_ = os.WriteFile(cfgPath, updated, 0600)

	collector := telemetry.NewCollector(cfgPath)
	snap1 := collector.Collect(context.Background())
	if !snap1.Enabled || !snap1.Reachable || snap1.ActiveConnections != 2 {
		t.Fatalf("unexpected snap1: %+v", snap1)
	}
	if snap1.Protocols.Hy2Connections != 1 || snap1.Protocols.RealityConnections != 1 {
		t.Fatalf("unexpected protocol breakdown: %+v", snap1.Protocols)
	}
	if snap1.Outbounds.WarpConnections != 1 || snap1.Outbounds.DirectConnections != 1 {
		t.Fatalf("unexpected outbound breakdown: %+v", snap1.Outbounds)
	}

	time.Sleep(300 * time.Millisecond)
	upCounter.Add(300_000)
	dnCounter.Add(1_500_000)

	snap2 := collector.Collect(context.Background())
	if snap2.UpBps <= 0 || snap2.DownBps <= 0 {
		t.Fatalf("expected positive instantaneous rates on second sample, got up=%d down=%d", snap2.UpBps, snap2.DownBps)
	}
}
