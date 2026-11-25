// 文件职责：测试旁路由跨网段设备反向 PTR 主机名解析（主机名清洗、TTL 正/负缓存、主路由条件限制与并发竞态安全）。
package audit_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"singctl/internal/audit"
	"singctl/internal/config"
)

func TestNormalizePTRHostname(t *testing.T) {
	tests := []struct {
		raw  string
		want string
	}{
		{raw: "yunzhonnhedeMBP.lan.", want: "yunzhonnhedeMBP"},
		{raw: "LivingRoom-AppleTV.home", want: "LivingRoom-AppleTV"},
		{raw: "iphone.local.", want: "iphone"},
		{raw: "mac-studio", want: "mac-studio"},
		{raw: "*", want: ""},
		{raw: "localhost.", want: ""},
		{raw: "localhost", want: ""},
		{raw: "192.168.89.137", want: ""},
		{raw: "", want: ""},
		{raw: "   ", want: ""},
		{raw: "bad;host", want: ""},
	}
	for _, tc := range tests {
		if got := audit.NormalizePTRHostname(tc.raw); got != tc.want {
			t.Fatalf("NormalizePTRHostname(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}
}

func TestCollector_SideRouterPTRResolutionAndCache(t *testing.T) {
	dir := t.TempDir()
	mockClash := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"connections": []map[string]any{
				{
					"id":       "c1",
					"upload":   1024,
					"download": 4096,
					"chains":   []string{"Proxy"},
					"metadata": map[string]any{"sourceIP": "192.168.89.137", "host": "api.example.com", "network": "tcp", "destinationPort": "443"},
				},
				{
					"id":       "c2",
					"upload":   512,
					"download": 2048,
					"chains":   []string{"#DC"},
					"metadata": map[string]any{"sourceIP": "192.168.89.146", "host": "cdn.example.com", "network": "tcp", "destinationPort": "443"},
				},
				{
					"id":       "c3",
					"upload":   256,
					"download": 1024,
					"chains":   []string{"#DC"},
					"metadata": map[string]any{"sourceIP": "192.168.89.150", "host": "sync.example.com", "network": "tcp", "destinationPort": "443"},
				},
			},
		})
	}))
	defer mockClash.Close()

	cfg := &config.Config{
		Gateway: config.GatewayConfig{
			Mode:         "side",
			MainRouterIP: "192.168.55.1",
		},
		HomeDomain: config.HomeDomainConfig{
			Suffix: "home",
			Devices: []config.HomeDomainDevice{
				{Alias: "studio", DisplayName: "书房工作站", IP: "192.168.89.150"},
			},
		},
	}

	var curNow time.Time = time.Date(2026, 11, 26, 3, 0, 0, 0, time.UTC)
	var nowMu sync.Mutex

	var ptrMu sync.Mutex
	ptrCalls := map[string]int{}

	col := audit.NewCollectorWithOptions(cfg, audit.CollectorOptions{})
	col.SetEndpointsForTest([]string{mockClash.URL}, "", filepath.Join(dir, "audit-state.json"))
	col.SetLeaseFilesForTest(nil, filepath.Join(dir, "no-arp"), filepath.Join(dir, "no-hosts"))
	col.SetNowFuncForTest(func() time.Time {
		nowMu.Lock()
		defer nowMu.Unlock()
		return curNow
	})
	col.SetPTRLookupFuncForTest(func(_ context.Context, ip string) (string, error) {
		ptrMu.Lock()
		ptrCalls[ip]++
		ptrMu.Unlock()
		switch ip {
		case "192.168.89.137":
			return "yunzhonnhedeMBP.lan.", nil
		case "192.168.89.150":
			return "MacMini.lan.", nil
		default:
			return "", errors.New("NXDOMAIN")
		}
	})

	// 1. First Collect resolves cross-subnet PTR hostname immediately and preserves HomeDomain priority.
	rep := col.CollectWithConfig(t.Context(), cfg, audit.CollectOptions{})
	devNames := map[string]string{}
	for _, d := range rep.Devices {
		devNames[d.DeviceIP] = d.DeviceName
	}
	if devNames["192.168.89.137"] != "yunzhonnhedeMBP" {
		t.Fatalf("expected PTR resolved name yunzhonnhedeMBP, got %q (all=%+v)", devNames["192.168.89.137"], devNames)
	}
	if devNames["192.168.89.146"] != "192.168.89.146" {
		t.Fatalf("expected unresolved IP fallback 192.168.89.146, got %q", devNames["192.168.89.146"])
	}
	if !containsSub(devNames["192.168.89.150"], "studio.home") {
		t.Fatalf("expected HomeDomain nickname preserved for .150, got %q", devNames["192.168.89.150"])
	}

	// 2. Immediate second Collect hits both positive and negative caches (0 new calls).
	_ = col.CollectWithConfig(t.Context(), cfg, audit.CollectOptions{})
	ptrMu.Lock()
	c137, c146 := ptrCalls["192.168.89.137"], ptrCalls["192.168.89.146"]
	ptrMu.Unlock()
	if c137 != 1 || c146 != 1 {
		t.Fatalf("expected 1 lookup per IP with warm cache, got .137=%d .146=%d", c137, c146)
	}

	// 3. Advance +3m -> negative TTL (2m) expires for .146, positive TTL (10m) holds for .137.
	nowMu.Lock()
	curNow = curNow.Add(3 * time.Minute)
	nowMu.Unlock()
	_ = col.CollectWithConfig(t.Context(), cfg, audit.CollectOptions{})
	ptrMu.Lock()
	c137After3, c146After3 := ptrCalls["192.168.89.137"], ptrCalls["192.168.89.146"]
	ptrMu.Unlock()
	if c137After3 != 1 || c146After3 != 2 {
		t.Fatalf("expected .137 cached (1) and .146 refreshed (2), got .137=%d .146=%d", c137After3, c146After3)
	}

	// 4. Advance +11m -> positive TTL (10m) also expires.
	nowMu.Lock()
	curNow = curNow.Add(11 * time.Minute)
	nowMu.Unlock()
	_ = col.CollectWithConfig(t.Context(), cfg, audit.CollectOptions{})
	ptrMu.Lock()
	c137After14 := ptrCalls["192.168.89.137"]
	ptrMu.Unlock()
	if c137After14 != 2 {
		t.Fatalf("expected .137 refreshed after 10m TTL, got %d", c137After14)
	}

	// 5. Concurrent Collect calls (-race).
	var wg sync.WaitGroup
	for range 6 {
		wg.Go(func() {
			_ = col.CollectWithConfig(t.Context(), cfg, audit.CollectOptions{})
		})
	}
	wg.Wait()

	// 6. Main router mode must NOT trigger side-router PTR lookup.
	mainCfg := &config.Config{
		Gateway: config.GatewayConfig{Mode: "main", MainRouterIP: "192.168.55.1"},
	}
	mainCol := audit.NewCollectorWithOptions(mainCfg, audit.CollectorOptions{})
	mainCol.SetEndpointsForTest([]string{mockClash.URL}, "", filepath.Join(dir, "main-state.json"))
	mainCol.SetLeaseFilesForTest(nil, filepath.Join(dir, "no-arp"), filepath.Join(dir, "no-hosts"))
	mainCalls := 0
	mainCol.SetPTRLookupFuncForTest(func(_ context.Context, _ string) (string, error) {
		mainCalls++
		return "should-not-call.lan.", nil
	})
	_ = mainCol.CollectWithConfig(t.Context(), mainCfg, audit.CollectOptions{})
	if mainCalls != 0 {
		t.Fatalf("expected 0 PTR calls in main mode, got %d", mainCalls)
	}
}

func containsSub(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || (len(sub) > 0 && findSubIdx(s, sub) >= 0))
}

func findSubIdx(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
