// 文件职责：验证采集器空闲零增量节流免写盘、活跃增量即时落盘、规则热更新清洗及 200 连接采样基准。
package audit_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"singctl/internal/audit"
	"singctl/internal/config"
)

func TestCollector_IdleSampleSkipsWrite_ActiveSamplePersistsImmediately(t *testing.T) {
	var stage atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		down := int64(4096)
		if stage.Load() >= 1 {
			down = 1048576
		}
		_, _ = fmt.Fprintf(w, `{
			"connections": [
				{
					"id": "idle-conn-1",
					"upload": 512,
					"download": %d,
					"start": "2026-11-21T12:00:00Z",
					"chains": ["Proxy"],
					"rule": "final",
					"metadata": {
						"network": "tcp",
						"sourceIP": "192.168.100.20",
						"destinationIP": "203.0.113.10",
						"destinationPort": "443",
						"host": "cdn.example.com"
					}
				}
			]
		}`, down)
	}))
	defer srv.Close()

	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "audit-state.json")
	cfg := &config.Config{}

	c := audit.NewCollector(cfg)
	c.SetLeaseFilesForTest(nil, filepath.Join(tmpDir, "missing-arp"), filepath.Join(tmpDir, "missing-hosts"))
	c.SetEndpointsForTest([]string{srv.URL}, "", statePath)
	fixedNow := time.Date(2026, 11, 21, 14, 0, 0, 0, time.UTC)
	c.SetNowFuncForTest(func() time.Time { return fixedNow })

	if !c.SampleActiveConnections(t.Context()) {
		t.Fatal("expected first sample to succeed")
	}
	info1, err := os.Stat(statePath)
	if err != nil {
		t.Fatalf("expected state file created after first sample: %v", err)
	}

	if !c.SampleActiveConnections(t.Context()) {
		t.Fatal("expected second sample to succeed")
	}
	info2, err := os.Stat(statePath)
	if err != nil {
		t.Fatalf("expected state file present: %v", err)
	}
	if !os.SameFile(info1, info2) || !info1.ModTime().Equal(info2.ModTime()) {
		t.Fatalf("expected idle sample with 0 delta to skip disk rewrite (sameFile=%v mtime1=%v mtime2=%v)",
			os.SameFile(info1, info2), info1.ModTime(), info2.ModTime())
	}

	stage.Store(1)
	if !c.SampleActiveConnections(t.Context()) {
		t.Fatal("expected third sample to succeed")
	}
	info3, err := os.Stat(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(info2, info3) {
		t.Fatal("expected active delta sample to atomically rewrite state file with new inode")
	}
	c2 := audit.NewCollector(cfg)
	c2.SetLeaseFilesForTest(nil, filepath.Join(tmpDir, "missing-arp"), filepath.Join(tmpDir, "missing-hosts"))
	c2.SetEndpointsForTest([]string{srv.URL}, "", statePath)
	c2.SetNowFuncForTest(func() time.Time { return fixedNow })
	rep2 := c2.Collect(t.Context(), audit.CollectOptions{Limit: -1})
	if len(rep2.Flows) != 1 || rep2.Flows[0].DownloadBytes != 1048576 {
		t.Fatalf("expected persisted flow download=1048576, got %+v", rep2.Flows)
	}

	updatedCfg := &config.Config{
		CustomRules: config.CustomRulesConfig{
			Block: []config.BlockRule{
				{Target: "cdn.example.com"},
			},
		},
	}
	c.UpdateConfig(updatedCfg)
	if !c.SampleActiveConnections(t.Context()) {
		t.Fatal("expected blocked update sample to succeed")
	}
	repAfterBlock := c.Collect(t.Context(), audit.CollectOptions{Limit: -1})
	if len(repAfterBlock.Flows) != 0 {
		t.Fatalf("expected newly blocked flow to be purged after config update, got %+v", repAfterBlock.Flows)
	}
	rawState, err := os.ReadFile(statePath)
	if err != nil || strings.Contains(string(rawState), "cdn.example.com") {
		t.Fatalf("expected state file purged of newly blocked target, err=%v raw=%s", err, string(rawState))
	}
}

func BenchmarkCollector_SampleActiveConnections_Idle_200Conns(b *testing.B) {
	var body strings.Builder
	body.WriteString(`{"connections":[`)
	for i := range 200 {
		if i > 0 {
			body.WriteByte(',')
		}
		fmt.Fprintf(&body,
			`{"id":"c-%d","upload":1024,"download":8192,"start":"2026-11-21T12:00:00Z","chains":["Proxy"],"rule":"final","metadata":{"network":"tcp","sourceIP":"192.168.100.%d","destinationIP":"203.0.113.%d","destinationPort":"443","host":"host%d.example.com"}}`,
			i, (i%50)+10, (i%200)+1, i,
		)
	}
	body.WriteString(`]}`)
	payload := []byte(body.String())

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(payload)
	}))
	defer srv.Close()

	tmpDir := b.TempDir()
	c := audit.NewCollector(&config.Config{})
	c.SetLeaseFilesForTest(nil, filepath.Join(tmpDir, "missing-arp"), filepath.Join(tmpDir, "missing-hosts"))
	c.SetEndpointsForTest([]string{srv.URL}, "", filepath.Join(tmpDir, "audit-state.json"))
	c.SampleActiveConnections(b.Context())

	b.ReportAllocs()
	for b.Loop() {
		if !c.SampleActiveConnections(b.Context()) {
			b.Fatal("sample failed")
		}
	}
}
