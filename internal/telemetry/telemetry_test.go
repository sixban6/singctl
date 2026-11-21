package telemetry

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestGetActiveDestinationsAndEvictMismatchedConnections(t *testing.T) {
	var mu sync.Mutex
	var deletedIDs []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-secret-123456" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.Method == http.MethodGet && r.URL.Path == "/connections" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"downloadTotal": 12000,
				"uploadTotal":   3000,
				"connections": []map[string]any{
					{
						"id":       "c1",
						"upload":   100,
						"download": 900,
						"chains":   []string{"DC"},
						"rule":     "final",
						"metadata": map[string]any{
							"type":          "hysteria2",
							"sourceIP":      "192.0.2.50",
							"host":          "cdn.example.com",
							"destinationIP": "198.51.100.10",
						},
					},
					{
						"id":       "c2",
						"upload":   200,
						"download": 1800,
						"chains":   []string{"DC"},
						"rule":     "final",
						"metadata": map[string]any{
							"type":          "hysteria2",
							"sourceIP":      "192.0.2.50",
							"host":          "cdn.example.com",
							"destinationIP": "198.51.100.10",
						},
					},
					{
						"id":       "c3",
						"upload":   50,
						"download": 500,
						"chains":   []string{"WARP"},
						"rule":     "rule_set=rule-reddit",
						"metadata": map[string]any{
							"type":          "vless",
							"sourceIP":      "192.0.2.51",
							"host":          "www.reddit.com",
							"destinationIP": "198.51.100.20",
						},
					},
				},
			})
			return
		}
		if r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/connections/") {
			id := strings.TrimPrefix(r.URL.Path, "/connections/")
			mu.Lock()
			deletedIDs = append(deletedIDs, id)
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	ctrlAddr := strings.TrimPrefix(srv.URL, "http://")
	cfgPath := filepath.Join(t.TempDir(), "config.json")
	rawCfg, _ := json.Marshal(map[string]any{
		"experimental": map[string]any{
			"clash_api": map[string]any{
				"external_controller": ctrlAddr,
				"secret":              "test-secret-123456",
			},
		},
	})
	if err := os.WriteFile(cfgPath, rawCfg, 0600); err != nil {
		t.Fatal(err)
	}

	collector := NewCollector(cfgPath)
	ctx := t.Context()

	// 1. 验证目标聚合 + RootDomain + 客户端来源 IP 零暴露
	groups, err := collector.GetActiveDestinations(ctx, "", "all")
	if err != nil {
		t.Fatalf("GetActiveDestinations failed: %v", err)
	}
	if len(groups) != 2 {
		t.Fatalf("expected 2 destination groups, got %d", len(groups))
	}
	if groups[0].Target != "cdn.example.com" || groups[0].RootDomain != "example.com" || groups[0].Connections != 2 || groups[0].TotalBytes != 3000 {
		t.Fatalf("unexpected top destination group: %+v", groups[0])
	}
	serialized, _ := json.Marshal(groups)
	if strings.Contains(string(serialized), "192.0.2.50") || strings.Contains(string(serialized), "192.0.2.51") {
		t.Fatal("client source IP must NEVER be exposed in destination group response")
	}

	// 2. 验证按出站筛选 WARP
	warpOnly, err := collector.GetActiveDestinations(ctx, "", "WARP")
	if err != nil || len(warpOnly) != 1 || warpOnly[0].Target != "www.reddit.com" {
		t.Fatalf("expected only www.reddit.com for WARP filter, got %+v (err=%v)", warpOnly, err)
	}

	// 3. 验证精准踢流只删除命中变更规则的 c1 / c2，保留 c3
	evicted, err := collector.EvictMismatchedConnections(ctx, func(host, dstIP, rule, currentOutbound string) bool {
		return strings.HasSuffix(host, "example.com") && currentOutbound == "Direct"
	})
	if err != nil {
		t.Fatalf("EvictMismatchedConnections failed: %v", err)
	}
	if evicted != 2 || len(deletedIDs) != 2 {
		t.Fatalf("expected 2 evicted connections (c1, c2), got evicted=%d deletedIDs=%v", evicted, deletedIDs)
	}
}

func TestCollector_CachesResolvedConfigAndReloadsOnModify(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sec := r.Header.Get("Authorization")
		if sec != "Bearer secret-one-123456" && sec != "Bearer secret-two-654321" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"uploadTotal":100,"downloadTotal":200,"connections":[]}`))
	}))
	defer srv.Close()

	ctrlAddr := strings.TrimPrefix(srv.URL, "http://")
	cfgPath := filepath.Join(t.TempDir(), "config.json")
	writeCfg := func(sec string, enabled bool) {
		t.Helper()
		payload := map[string]any{"experimental": map[string]any{}}
		if enabled {
			payload["experimental"] = map[string]any{
				"clash_api": map[string]any{
					"external_controller": ctrlAddr,
					"secret":              sec,
				},
			}
		}
		raw, _ := json.Marshal(payload)
		if err := os.WriteFile(cfgPath, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}

	writeCfg("secret-one-123456", true)
	c := NewCollector(cfgPath)

	for range 20 {
		snap := c.Collect(t.Context())
		if !snap.Enabled || !snap.Reachable {
			t.Fatalf("expected reachable telemetry snapshot, got %+v", snap)
		}
	}
	if reads := c.cfgDiskReads.Load(); reads != 1 {
		t.Fatalf("expected unchanged config to read/parse disk exactly 1 time across 20 Collect calls, got %d", reads)
	}

	// 修改配置文件内容与 mtime -> 必须立即重新加载新配置
	writeCfg("secret-two-654321", true)
	nowFuture := time.Now().Add(2 * time.Second)
	_ = os.Chtimes(cfgPath, nowFuture, nowFuture)

	snap2 := c.Collect(t.Context())
	if !snap2.Enabled || !snap2.Reachable {
		t.Fatalf("expected reloaded config snapshot to succeed, got %+v", snap2)
	}
	if reads := c.cfgDiskReads.Load(); reads != 2 {
		t.Fatalf("expected 2 disk reads after config modification, got %d", reads)
	}

	// 移除配置文件 -> 立即失效并反映 Enabled=false
	_ = os.Remove(cfgPath)
	snap3 := c.Collect(t.Context())
	if snap3.Enabled {
		t.Fatalf("expected removed config to report Enabled=false immediately, got %+v", snap3)
	}
}

func BenchmarkCollector_Collect_300Conns(b *testing.B) {
	var body strings.Builder
	body.WriteString(`{"downloadTotal":987654321,"uploadTotal":12345678,"memory":33554432,"connections":[`)
	for i := range 300 {
		if i > 0 {
			body.WriteByte(',')
		}
		fmt.Fprintf(&body,
			`{"id":"t-%d","upload":%d,"download":%d,"chains":["WARP"],"rule":"final","metadata":{"network":"tcp","type":"hysteria2","sourceIP":"192.0.2.%d","host":"cdn%d.example.com","destinationIP":"198.51.100.%d","destinationPort":"443"}}`,
			i, i*100, i*1000, (i%200)+1, i%25, (i%200)+1,
		)
	}
	body.WriteString(`]}`)
	payload := []byte(body.String())

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(payload)
	}))
	defer srv.Close()

	cfgPath := filepath.Join(b.TempDir(), "config.json")
	rawCfg, _ := json.Marshal(map[string]any{
		"experimental": map[string]any{
			"clash_api": map[string]any{
				"external_controller": strings.TrimPrefix(srv.URL, "http://"),
				"secret":              "bench-secret-123456",
			},
		},
	})
	if err := os.WriteFile(cfgPath, rawCfg, 0600); err != nil {
		b.Fatal(err)
	}

	c := NewCollector(cfgPath)
	ctx := b.Context()
	c.Collect(ctx)

	b.ReportAllocs()
	for b.Loop() {
		snap := c.Collect(ctx)
		if !snap.Reachable || snap.ActiveConnections != 300 {
			b.Fatalf("unexpected snap: reachable=%v active=%d", snap.Reachable, snap.ActiveConnections)
		}
	}
}
