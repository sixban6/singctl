// 文件职责：覆盖审计采集器低内存自适应判定、256 条风险感知有界环（严防误淘汰高危/可疑 PCDN 流）、满载 BT 内存上限及邻居表刷新降频测试。
package audit_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"singctl/internal/audit"
	"singctl/internal/common/sysinfo"
	"singctl/internal/config"
)

func TestIsLowMemoryAuditMemInfo_TableDriven(t *testing.T) {
	const mib = 1024 * 1024
	cases := []struct {
		name string
		mi   sysinfo.MemInfo
		want bool
	}{
		{"n60pro_479mib_total_205mib_avail", sysinfo.MemInfo{TotalBytes: 491040 * 1024, AvailableBytes: 210260 * 1024}, true},
		{"ultra_low_224mib_router", sysinfo.MemInfo{TotalBytes: 224 * mib, AvailableBytes: 90 * mib}, true},
		{"exact_288mib_router", sysinfo.MemInfo{TotalBytes: 288 * mib, AvailableBytes: 150 * mib}, true},
		{"exact_512mib_router", sysinfo.MemInfo{TotalBytes: 512 * mib, AvailableBytes: 320 * mib}, true},
		{"1gib_total_with_200mib_avail", sysinfo.MemInfo{TotalBytes: 1024 * mib, AvailableBytes: 200 * mib}, true},
		{"1gib_total_with_600mib_avail", sysinfo.MemInfo{TotalBytes: 1024 * mib, AvailableBytes: 600 * mib}, false},
		{"zero_meminfo_unknown", sysinfo.MemInfo{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := audit.IsLowMemoryAuditMemInfo(tc.mi); got != tc.want {
				t.Fatalf("IsLowMemoryAuditMemInfo(%+v) = %v, want %v", tc.mi, got, tc.want)
			}
		})
	}
}

func TestCollectorLowMemory_Bounded256EvictsLowestRiskOldestNormal_NeverEvictsPCDN(t *testing.T) {
	var mu sync.Mutex
	var currentPayload []byte

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		mu.Lock()
		p := currentPayload
		mu.Unlock()
		_, _ = w.Write(p)
	}))
	defer srv.Close()

	cfg := &config.Config{}
	cfg.Audit.SetPCDNBlock(false) // 允许观测商业 PCDN 节点进入评分引擎而不被前置直接丢弃

	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "audit-state.json")

	c := audit.NewCollectorWithOptions(cfg, audit.CollectorOptions{
		MemTotalBytes:     491040 * 1024, // n60pro 实测内存自动开启低内存模式
		MemAvailableBytes: 210260 * 1024,
	})
	if !c.IsLowMemoryMode() || c.MaxTrackedFlows() != audit.LowMemMaxTrackedFlows {
		t.Fatalf("expected auto low-memory mode with maxTrackedFlows=256, got lowMem=%v max=%d", c.IsLowMemoryMode(), c.MaxTrackedFlows())
	}
	c.SetLeaseFilesForTest(nil, filepath.Join(tmpDir, "no-arp"), filepath.Join(tmpDir, "no-hosts"))
	c.SetEndpointsForTest([]string{srv.URL}, "", statePath)

	var clockMu sync.Mutex
	curTime := time.Date(2026, 11, 22, 14, 0, 0, 0, time.UTC)
	c.SetNowFuncForTest(func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return curTime
	})
	setTime := func(next time.Time) {
		clockMu.Lock()
		curTime = next
		clockMu.Unlock()
	}

	// Round 1 (t = 14:00): Inject high-risk / suspicious PCDN flows + earliest-inactive normal flows
	//   1) Commercial PCDN upload domain (node01.xycdn.com) -> HighRisk PCDN upload
	//   2) Direct-IP non-standard port heavy upload (198.51.100.88:19999) -> HighRisk / Suspicious
	//   3) 10 UDP swarm flows across distinct /16 subnets -> PCDNSwarm suspicious
	//   4) 50 earliest-inactive benign HTTPS web flows (earliest0..earliest49.example.com, RiskScore ~ 0)
	var b1 strings.Builder
	b1.WriteString(`{"connections":[`)
	b1.WriteString(`{"id":"pcdn-up-1","upload":16777216,"download":131072,"start":"2026-11-22T14:00:00Z","chains":["DIRECT"],"rule":"final","metadata":{"network":"udp","sourceIP":"192.168.1.50","destinationIP":"203.0.113.200","destinationPort":"8800","host":"node01.xycdn.com"}},`)
	b1.WriteString(`{"id":"direct-up-1","upload":20971520,"download":65536,"start":"2026-11-22T14:00:00Z","chains":["DIRECT"],"rule":"final","metadata":{"network":"tcp","sourceIP":"192.168.1.50","destinationIP":"198.51.100.88","destinationPort":"19999","host":""}}`)
	for i := 1; i <= 10; i++ {
		fmt.Fprintf(&b1, `,{"id":"swarm-%d","upload":1048576,"download":65536,"start":"2026-11-22T14:00:00Z","chains":["DIRECT"],"rule":"final","metadata":{"network":"udp","sourceIP":"192.168.1.60","destinationIP":"198.%d.10.20","destinationPort":"%d","host":""}}`, i, i+10, 24000+i)
	}
	for i := range 50 {
		fmt.Fprintf(&b1, `,{"id":"early-benign-%d","upload":1024,"download":131072,"start":"2026-11-22T14:00:00Z","chains":["Proxy"],"rule":"final","metadata":{"network":"tcp","sourceIP":"192.168.1.20","destinationIP":"203.0.113.%d","destinationPort":"443","host":"earliest-%d.example.com"}}`, i, (i%200)+1, i)
	}
	b1.WriteString(`]}`)

	mu.Lock()
	currentPayload = []byte(b1.String())
	mu.Unlock()
	if !c.SampleActiveConnections(t.Context()) {
		t.Fatal("round 1 sample failed")
	}

	// Round 2 (t = 14:05): All Round 1 connections closed! Now simulate full-load BT download burst:
	// 230 inactive later benign flows at t=14:05 (so total historical flows > 290 > 256!)
	setTime(curTime.Add(5 * time.Minute))
	var b2 strings.Builder
	b2.WriteString(`{"connections":[`)
	for i := range 230 {
		if i > 0 {
			b2.WriteByte(',')
		}
		fmt.Fprintf(&b2, `{"id":"later-benign-%d","upload":2048,"download":524288,"start":"2026-11-22T14:05:00Z","chains":["Proxy"],"rule":"final","metadata":{"network":"tcp","sourceIP":"192.168.1.21","destinationIP":"192.0.2.%d","destinationPort":"443","host":"later-%d.example.com"}}`, i, (i%200)+1, i)
	}
	b2.WriteString(`]}`)
	mu.Lock()
	currentPayload = []byte(b2.String())
	mu.Unlock()
	if !c.SampleActiveConnections(t.Context()) {
		t.Fatal("round 2 sample failed")
	}

	// Round 3 (t = 14:10): Flood 400 brand-new BT download peer connections in multiple batches (testing < 2 MB memory bound & cursor pruning)
	runtime.GC()
	var memBefore runtime.MemStats
	runtime.ReadMemStats(&memBefore)

	for batch := range 4 {
		setTime(curTime.Add(30 * time.Second))
		var bFlood strings.Builder
		bFlood.WriteString(`{"connections":[`)
		for i := range 320 {
			if i > 0 {
				bFlood.WriteByte(',')
			}
			connIdx := batch*320 + i
			fmt.Fprintf(&bFlood, `{"id":"bt-peer-%d","upload":4096,"download":4194304,"start":"2026-11-22T14:10:00Z","chains":["DIRECT"],"rule":"final","metadata":{"network":"tcp","sourceIP":"192.168.1.30","destinationIP":"203.0.113.%d","destinationPort":"443","host":"bt-mirror-%d.example.com"}}`, connIdx, (i%250)+1, connIdx)
		}
		bFlood.WriteString(`]}`)
		mu.Lock()
		currentPayload = []byte(bFlood.String())
		mu.Unlock()
		if !c.SampleActiveConnections(t.Context()) {
			t.Fatalf("flood batch %d failed", batch)
		}
	}

	runtime.GC()
	var memAfter runtime.MemStats
	runtime.ReadMemStats(&memAfter)
	var liveDelta int64
	if memAfter.HeapAlloc > memBefore.HeapAlloc {
		liveDelta = int64(memAfter.HeapAlloc - memBefore.HeapAlloc)
	}
	if liveDelta >= 2*1024*1024 {
		t.Fatalf("expected audit live heap delta < 2 MB under heavy BT churn, got %d bytes", liveDelta)
	}

	rep := c.Collect(t.Context(), audit.CollectOptions{Limit: -1, SortBy: "risk"})
	if rep.TotalFlows > audit.LowMemMaxTrackedFlows || len(rep.Flows) > audit.LowMemMaxTrackedFlows {
		t.Fatalf("expected tracked flows strictly bounded <= 256, got TotalFlows=%d len(Flows)=%d", rep.TotalFlows, len(rep.Flows))
	}

	byTarget := make(map[string]audit.FlowRecord, len(rep.Flows))
	earlyBenignKept := 0
	for _, f := range rep.Flows {
		byTarget[f.Target] = f
		if strings.HasPrefix(f.Target, "earliest-") {
			earlyBenignKept++
		}
	}

	// CRITICAL ASSERTION 1: High-risk & suspicious PCDN flows from t=14:00 MUST NEVER be evicted despite being oldest inactive!
	if _, ok := byTarget["node01.xycdn.com"]; !ok {
		t.Fatal("CRITICAL: high-risk PCDN flow node01.xycdn.com was falsely evicted!")
	}
	if _, ok := byTarget["198.51.100.88"]; !ok {
		t.Fatal("CRITICAL: high-risk direct-IP upload flow 198.51.100.88 was falsely evicted!")
	}
	for i := 1; i <= 10; i++ {
		swarmIP := fmt.Sprintf("198.%d.10.20", i+10)
		if _, ok := byTarget[swarmIP]; !ok {
			t.Fatalf("CRITICAL: suspicious PCDN UDP swarm flow %s was falsely evicted!", swarmIP)
		}
	}

	// CRITICAL ASSERTION 2: Earliest-deactivated ordinary flows (earliest-*.example.com from t=14:00) were evicted first!
	if earlyBenignKept != 0 {
		t.Fatalf("expected earliest-inactive zero-risk benign flows evicted first, but %d remained", earlyBenignKept)
	}
}

func TestCollectorLowMemory_DeviceAndIPv6RefreshThrottled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"connections":[{"id":"c1","upload":1024,"download":4096,"start":"2026-11-22T15:00:00Z","chains":["Proxy"],"rule":"final","metadata":{"network":"tcp","sourceIP":"192.168.1.88","destinationIP":"203.0.113.5","destinationPort":"443","host":"app.example.com"}}]}`))
	}))
	defer srv.Close()

	tmpDir := t.TempDir()
	leaseFile := filepath.Join(tmpDir, "dhcp.leases")
	arpFile := filepath.Join(tmpDir, "arp")
	if err := os.WriteFile(leaseFile, []byte("1700000000 aa:bb:cc:dd:ee:01 192.168.1.88 old-hostname *\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(arpFile, []byte("IP address HW type Flags HW address Mask Device\n192.168.1.88 0x1 0x2 aa:bb:cc:dd:ee:01 * br-lan\n"), 0600); err != nil {
		t.Fatal(err)
	}

	c := audit.NewCollector(&config.Config{})
	c.SetLeaseFilesForTest([]string{leaseFile}, arpFile, filepath.Join(tmpDir, "no-hosts"))
	c.SetEndpointsForTest([]string{srv.URL}, "", filepath.Join(tmpDir, "audit-state.json"))
	c.SetLowMemoryForTest(true)
	if !c.IsLowMemoryMode() || c.MaxTrackedFlows() != audit.LowMemMaxTrackedFlows {
		t.Fatal("expected SetLowMemoryForTest(true) to enable 256-flow low-memory profile")
	}

	var ipv6Calls atomic.Int32
	c.SetIPv6NeighCmdForTest(func() ([]byte, error) {
		ipv6Calls.Add(1)
		return []byte("fd00::88 dev br-lan lladdr aa:bb:cc:dd:ee:01 REACHABLE\n"), nil
	})

	var clockMu sync.Mutex
	curTime := time.Date(2026, 11, 22, 15, 0, 0, 0, time.UTC)
	c.SetNowFuncForTest(func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return curTime
	})
	advance := func(d time.Duration) {
		clockMu.Lock()
		curTime = curTime.Add(d)
		clockMu.Unlock()
	}

	// First collect populates caches (ipv6Calls == 1, device name == "old-hostname")
	rep1 := c.Collect(t.Context(), audit.CollectOptions{Limit: -1})
	if len(rep1.Flows) != 1 || rep1.Flows[0].DeviceName != "old-hostname" || ipv6Calls.Load() != 1 {
		t.Fatalf("unexpected initial collect: flows=%+v ipv6Calls=%d", rep1.Flows, ipv6Calls.Load())
	}

	// Rewrite lease file on disk immediately, then poll every 15s up to +90s (< 2m low-mem refresh interval):
	// both lease disk re-stat/read and `ip -6 neigh` subprocess must stay throttled!
	if err := os.WriteFile(leaseFile, []byte("1700000000 aa:bb:cc:dd:ee:01 192.168.1.88 new-hostname *\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for range 5 {
		advance(15 * time.Second)
		_ = c.SampleActiveConnections(t.Context())
	}
	if ipv6Calls.Load() != 1 {
		t.Fatalf("expected ipv6 neighbor command throttled (1 call) within 75s in low-mem mode, got %d", ipv6Calls.Load())
	}

	// Advance past 3m05s: both DHCP/ARP and IPv6 neighbor caches refresh cleanly!
	advance(2*time.Minute + 30*time.Second)
	rep2 := c.Collect(t.Context(), audit.CollectOptions{Limit: -1})
	if ipv6Calls.Load() != 2 {
		t.Fatalf("expected ipv6 neighbor refreshed after >=3m, got calls=%d", ipv6Calls.Load())
	}
	if len(rep2.Flows) != 1 || rep2.Flows[0].DeviceName != "new-hostname" {
		t.Fatalf("expected refreshed hostname 'new-hostname' after >=2m, got %+v", rep2.Flows)
	}
}
