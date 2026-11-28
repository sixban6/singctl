package audit_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"singctl/internal/audit"
	"singctl/internal/config"
)

type mockClashConn struct {
	ID       string
	Upload   int64
	Download int64
	Start    string
	Chains   []string
	Rule     string
	SrcIP    string
	DstIP    string
	DstPort  string
	Host     string
	Network  string
}

func newMutableClashServer(t *testing.T) (*httptest.Server, *sync.Mutex, *[]mockClashConn) {
	t.Helper()
	var mu sync.Mutex
	var conns []mockClashConn
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		snap := make([]map[string]any, 0, len(conns))
		for _, c := range conns {
			netw := c.Network
			if netw == "" {
				netw = "tcp"
			}
			port := c.DstPort
			if port == "" {
				port = "443"
			}
			chains := c.Chains
			if len(chains) == 0 {
				chains = []string{"DIRECT"}
			}
			snap = append(snap, map[string]any{
				"id":       c.ID,
				"upload":   c.Upload,
				"download": c.Download,
				"start":    c.Start,
				"chains":   chains,
				"rule":     c.Rule,
				"metadata": map[string]any{
					"network":         netw,
					"sourceIP":        c.SrcIP,
					"destinationIP":   c.DstIP,
					"destinationPort": port,
					"host":            c.Host,
				},
			})
		}
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"connections": snap})
	}))
	t.Cleanup(srv.Close)
	return srv, &mu, &conns
}

func TestClassifyApp_FineGrainedAndInfra(t *testing.T) {
	cases := []struct {
		target   string
		destIP   string
		rule     string
		wantName string
		wantCat  audit.AppCategory
		wantInf  bool
	}{
		{target: "szshort.weixin.qq.com", wantName: "微信", wantCat: audit.AppCategorySocial, wantInf: false},
		{target: "v.qq.com", wantName: "腾讯视频", wantCat: audit.AppCategoryVideo, wantInf: false},
		{target: "cgi.connect.qq.com", wantName: "QQ", wantCat: audit.AppCategorySocial, wantInf: false},
		{target: "v26-dy.douyinvod.com", wantName: "抖音", wantCat: audit.AppCategoryVideo, wantInf: false},
		{target: "open.feishu.cn", wantName: "飞书", wantCat: audit.AppCategoryAIDev, wantInf: false},
		{target: "rr3---sn-test.googlevideo.com", wantName: "YouTube", wantCat: audit.AppCategoryVideo, wantInf: false},
		{target: "upos-sz-mirrorcos.bilivideo.com", wantName: "哔哩哔哩 Bilibili", wantCat: audit.AppCategoryVideo, wantInf: false},
		{target: "sns-webpic-qc.xhscdn.com", wantName: "小红书", wantCat: audit.AppCategorySocial, wantInf: false},
		{target: "chat.openai.com", wantName: "OpenAI / ChatGPT", wantCat: audit.AppCategoryAIDev, wantInf: false},
		{target: "api.anthropic.com", wantName: "Claude / Anthropic", wantCat: audit.AppCategoryAIDev, wantInf: false},
		{target: "api.github.com", wantName: "GitHub", wantCat: audit.AppCategoryAIDev, wantInf: false},
		{target: "store.steampowered.com", wantName: "Steam", wantCat: audit.AppCategoryGamingMusic, wantInf: false},
		{target: "push.apple.com", destIP: "17.57.145.153", wantName: "Apple", wantCat: audit.AppCategorySystem, wantInf: true},
		{target: "gateway.icloud.com", wantName: "iCloud", wantCat: audit.AppCategorySystem, wantInf: true},
		{target: "workers.cloudflare.com", wantName: "Cloudflare", wantCat: audit.AppCategorySystem, wantInf: true},
		{target: "100.98.200.100", destIP: "100.98.200.100", wantName: "Tailscale 组网", wantCat: audit.AppCategorySystem, wantInf: true},
		{target: "dns.alidns.com", destIP: "223.5.5.5", wantName: "阿里公共 DNS", wantCat: audit.AppCategorySystem, wantInf: true},
		{target: "ot.io.mi.com", wantName: "小米 / 米家", wantCat: audit.AppCategorySystem, wantInf: true},
		{target: "unknown-blog.example.com", destIP: "203.0.113.55", wantName: "", wantCat: audit.AppCategoryOther, wantInf: false},
	}

	for _, tc := range cases {
		got := audit.ClassifyApp(tc.target, tc.destIP, tc.rule)
		if got.Name != tc.wantName || got.Category != tc.wantCat || got.IsInfra != tc.wantInf {
			t.Errorf("ClassifyApp(%q, %q) = %+v, want Name=%q Category=%q IsInfra=%v",
				tc.target, tc.destIP, got, tc.wantName, tc.wantCat, tc.wantInf)
		}
	}
}

func TestDeviceProfile_ForegroundDenoisingAndMultiDomainDedup(t *testing.T) {
	srv, mu, conns := newMutableClashServer(t)
	tmp := t.TempDir()
	now := time.Date(2026, 11, 28, 20, 0, 10, 0, time.FixedZone("CST", 8*3600))
	var nowMu sync.Mutex

	c := audit.NewCollector(&config.Config{})
	c.SetEndpointsForTest([]string{srv.URL}, "", filepath.Join(tmp, "audit-state.json"))
	c.SetProfileHistoryPathForTest(filepath.Join(tmp, "profile-history.json"), 128<<10)
	c.SetLeaseFilesForTest(nil, filepath.Join(tmp, "no-arp"), filepath.Join(tmp, "no-hosts"))
	c.SetNowFuncForTest(func() time.Time {
		nowMu.Lock()
		defer nowMu.Unlock()
		return now
	})
	setTime := func(ts time.Time) {
		nowMu.Lock()
		now = ts
		nowMu.Unlock()
	}

	// Minute 0 (20:00):
	// 1. Bilibili with small pre-fetch < 120KB -> background ONLY
	// 2. Apple push 5MB -> infra ONLY (never in TopApps)
	// 3. WeChat idle keep-alive (no new conn delta after minute 0, < 8KB) -> later minute should stay idle
	mu.Lock()
	*conns = []mockClashConn{
		{ID: "b1", Upload: 2048, Download: 30 * 1024, Start: now.Format(time.RFC3339), SrcIP: "192.168.1.50", DstIP: "203.0.113.10", Host: "api.bilibili.com"},
		{ID: "ap1", Upload: 10 * 1024, Download: 5 * 1024 * 1024, Start: now.Format(time.RFC3339), SrcIP: "192.168.1.50", DstIP: "17.57.145.10", Host: "updates.cdn-apple.com"},
		{ID: "wx-idle", Upload: 1024, Download: 1024, Start: now.Format(time.RFC3339), SrcIP: "192.168.1.50", DstIP: "203.0.113.20", Host: "szlong.weixin.qq.com"},
	}
	mu.Unlock()
	if !c.SampleActiveConnections(t.Context()) {
		t.Fatal("sample min 0 failed")
	}

	// Minute 1 (20:01):
	// Bilibili hits 3 distinct CDN domains in the SAME minute totaling > 120KB -> must dedup to EXACTLY 1 foreground minute!
	// WeChat receives 1KB keep-alive on existing conn -> still NOT foreground!
	setTime(now.Add(1 * time.Minute))
	mu.Lock()
	*conns = []mockClashConn{
		{ID: "b1", Upload: 4096, Download: 100 * 1024, Start: now.Add(-1 * time.Minute).Format(time.RFC3339), SrcIP: "192.168.1.50", DstIP: "203.0.113.10", Host: "api.bilibili.com"},
		{ID: "b2", Upload: 4096, Download: 90 * 1024, Start: now.Format(time.RFC3339), SrcIP: "192.168.1.50", DstIP: "203.0.113.11", Host: "upos-sz-mirrorcos.bilivideo.com"},
		{ID: "b3", Upload: 4096, Download: 70 * 1024, Start: now.Format(time.RFC3339), SrcIP: "192.168.1.50", DstIP: "203.0.113.12", Host: "i0.hdslb.com"},
		{ID: "wx-idle", Upload: 1500, Download: 2500, Start: now.Add(-1 * time.Minute).Format(time.RFC3339), SrcIP: "192.168.1.50", DstIP: "203.0.113.20", Host: "szlong.weixin.qq.com"},
	}
	mu.Unlock()
	if !c.SampleActiveConnections(t.Context()) {
		t.Fatal("sample min 1 failed")
	}

	// Minutes 2..6: Periodic heartbeat every 60s on a shopping tracker (regular CV < 0.15, small bytes < 30KB)
	// First seed 5 regular connection arrivals on minute 2..5 on a known shopping domain to compute low CV, then verify heartbeat is suppressed.
	for m := 2; m <= 6; m++ {
		ts := time.Date(2026, 11, 28, 20, m, 10, 0, time.FixedZone("CST", 8*3600))
		setTime(ts)
		mu.Lock()
		*conns = []mockClashConn{
			{ID: fmt.Sprintf("hb-%d", m), Upload: 2048, Download: 4096, Start: ts.Format(time.RFC3339), SrcIP: "192.168.1.50", DstIP: "203.0.113.30", Host: "m.jd.com"},
		}
		mu.Unlock()
		_ = c.SampleActiveConnections(t.Context())
	}

	prof := c.BuildDeviceProfile(t.Context(), &config.Config{}, "192.168.1.50", audit.ProfileRange24h)
	if prof == nil {
		t.Fatal("expected non-nil DeviceProfileReport")
	}
	if prof.TotalForegroundMinutes != 1 {
		t.Fatalf("expected exactly 1 deduplicated foreground minute (Bilibili at min 1), got %d (topApps=%+v)", prof.TotalForegroundMinutes, prof.TopApps)
	}
	if len(prof.TopApps) != 1 || prof.TopApps[0].AppName != "哔哩哔哩 Bilibili" || prof.TopApps[0].ForegroundMinutes != 1 {
		t.Fatalf("expected TopApps=[Bilibili: 1m], got %+v", prof.TopApps)
	}
	if prof.TopApps[0].BackgroundMinutes < 1 {
		t.Fatalf("expected Bilibili min 0 pre-fetch counted in BackgroundMinutes >= 1, got %d", prof.TopApps[0].BackgroundMinutes)
	}
	if len(prof.SystemApps) == 0 || prof.SystemApps[0].AppName != "Apple" || !prof.SystemApps[0].IsInfra {
		t.Fatalf("expected Apple separated into SystemApps, got %+v", prof.SystemApps)
	}
	for _, app := range prof.TopApps {
		if app.AppName == "Apple" || app.AppName == "微信" {
			t.Fatalf("unexpected infra or idle app in TopApps: %+v", app)
		}
	}
}

func TestDeviceProfile_SessionizationAnd24hRollover(t *testing.T) {
	srv, mu, conns := newMutableClashServer(t)
	tmp := t.TempDir()
	tz := time.FixedZone("CST", 8*3600)
	base := time.Date(2026, 11, 28, 10, 0, 5, 0, tz)
	var nowMu sync.Mutex
	curNow := base

	c := audit.NewCollector(&config.Config{})
	c.SetEndpointsForTest([]string{srv.URL}, "", filepath.Join(tmp, "audit-state.json"))
	c.SetProfileHistoryPathForTest(filepath.Join(tmp, "profile-history.json"), 128<<10)
	c.SetLeaseFilesForTest(nil, filepath.Join(tmp, "no-arp"), filepath.Join(tmp, "no-hosts"))
	c.SetNowFuncForTest(func() time.Time {
		nowMu.Lock()
		defer nowMu.Unlock()
		return curNow
	})

	emitYouTubeAt := func(minuteOffset int, seq int) {
		ts := base.Add(time.Duration(minuteOffset) * time.Minute)
		nowMu.Lock()
		curNow = ts
		nowMu.Unlock()
		mu.Lock()
		*conns = []mockClashConn{
			{
				ID:       fmt.Sprintf("yt-%d", seq),
				Upload:   8192,
				Download: 300 * 1024,
				Start:    ts.Format(time.RFC3339),
				Chains:   []string{"node1", "Proxy"},
				SrcIP:    "192.168.1.60",
				DstIP:    "203.0.113.88",
				Host:     "www.youtube.com",
			},
		}
		mu.Unlock()
		if !c.SampleActiveConnections(t.Context()) {
			t.Fatalf("sample minuteOffset=%d failed", minuteOffset)
		}
	}

	// Session 1: 10:00, 10:01, skip 10:02 (gap 2m <= 3m merges!), 10:03, 10:04 -> 4 active mins, span 5m
	// Session 2: 10:15, 10:16, 10:17 -> gap 11m > 3m creates new session -> 3 active mins, span 3m
	offsets := []int{0, 1, 3, 4, 15, 16, 17}
	for i, off := range offsets {
		emitYouTubeAt(off, i+1)
	}

	prof := c.BuildDeviceProfile(t.Context(), &config.Config{}, "192.168.1.60", audit.ProfileRange24h)
	if prof == nil || len(prof.TopApps) != 1 {
		t.Fatalf("expected 1 top app (YouTube), got %+v", prof)
	}
	yt := prof.TopApps[0]
	if yt.ForegroundMinutes != 7 {
		t.Fatalf("expected 7 active minutes, got %d", yt.ForegroundMinutes)
	}
	if yt.Sessions != 2 {
		t.Fatalf("expected 2 merged sessions (gap<=3m merged, gap=11m split), got %d", yt.Sessions)
	}
	if yt.LongestSessionMin < 4 {
		t.Fatalf("expected LongestSessionMin >= 4, got %d", yt.LongestSessionMin)
	}
	if yt.PeakPeriod == "" || !strings.Contains(yt.PeakPeriod, "上午") {
		t.Fatalf("expected PeakPeriod 上午 for 10:xx, got %q", yt.PeakPeriod)
	}
	if prof.ProxySharePct < 99 {
		t.Fatalf("expected ProxySharePct ~100%%, got %.1f", prof.ProxySharePct)
	}

	// Advance 25 hours and emit 1 minute at 11:00 next day -> stale bits from 25h ago MUST roll off 24h view!
	emitYouTubeAt(25*60, 100)
	profAfter25h := c.BuildDeviceProfile(t.Context(), &config.Config{}, "192.168.1.60", audit.ProfileRange24h)
	if profAfter25h.TotalForegroundMinutes != 1 {
		t.Fatalf("expected 24h sliding window rollover to retain only 1 recent minute after +25h, got %d", profAfter25h.TotalForegroundMinutes)
	}
}

func TestDeviceProfile_SevenDayHistoryPersistenceAndAutoCleanup(t *testing.T) {
	srv, mu, conns := newMutableClashServer(t)
	tmp := t.TempDir()
	tz := time.FixedZone("CST", 8*3600)
	histPath := filepath.Join(tmp, "audit-profile-history.json")

	// Pre-seed 10 consecutive days (ending 2026-11-28) -> days older than 7 days must auto-purge!
	seedDays := make(map[string]any)
	baseDay := time.Date(2026, 11, 28, 0, 0, 0, 0, tz)
	for offset := 9; offset >= 1; offset-- {
		dStr := baseDay.AddDate(0, 0, -offset).Format("2006-01-02")
		seedDays[dStr] = map[string]any{
			"date": dStr,
			"devices": map[string]any{
				"192.168.1.77": map[string]any{
					"ip": "192.168.1.77",
					"fg": 15,
					"up": 100 * 1024,
					"dn": 2000 * 1024,
					"apps": map[string]any{
						"YouTube": map[string]any{
							"n":  "YouTube",
							"c":  "video",
							"fg": 15,
							"sc": 2,
							"lm": 10,
							"up": 100 * 1024,
							"dn": 2000 * 1024,
							"pp": "晚间 18-24",
						},
					},
				},
			},
		}
	}
	rawSeed, _ := json.Marshal(map[string]any{
		"schemaVersion": 1,
		"updatedUnix":   baseDay.Unix(),
		"days":          seedDays,
	})
	if err := os.WriteFile(histPath, rawSeed, 0600); err != nil {
		t.Fatal(err)
	}

	var nowMu sync.Mutex
	curNow := time.Date(2026, 11, 28, 21, 0, 5, 0, tz)
	newCol := func(stateFile string, maxBytes int) *audit.Collector {
		col := audit.NewCollector(&config.Config{})
		col.SetEndpointsForTest([]string{srv.URL}, "", stateFile)
		col.SetProfileHistoryPathForTest(histPath, maxBytes)
		col.SetLeaseFilesForTest(nil, filepath.Join(tmp, "no-arp"), filepath.Join(tmp, "no-hosts"))
		col.SetNowFuncForTest(func() time.Time {
			nowMu.Lock()
			defer nowMu.Unlock()
			return curNow
		})
		return col
	}

	col1 := newCol(filepath.Join(tmp, "state1.json"), 128<<10)
	// Emit 2 minutes of GitHub on today (2026-11-28)
	for m := range 2 {
		ts := time.Date(2026, 11, 28, 21, m, 5, 0, tz)
		nowMu.Lock()
		curNow = ts
		nowMu.Unlock()
		mu.Lock()
		*conns = []mockClashConn{
			{ID: fmt.Sprintf("gh-%d", m), Upload: 12 * 1024, Download: 32 * 1024, Start: ts.Format(time.RFC3339), SrcIP: "192.168.1.77", DstIP: "203.0.113.99", Host: "api.github.com"},
		}
		mu.Unlock()
		if !col1.SampleActiveConnections(t.Context()) {
			t.Fatal("sample col1 failed")
		}
	}
	col1.FlushProfileHistory()

	// Simulate mid-day router reboot: fresh state2.json (wiped /tmp), reload persisted history, add 1 MORE minute on minute 1 (already counted) + minute 2 (new!)
	col2 := newCol(filepath.Join(tmp, "state2.json"), 128<<10)
	for m := 1; m <= 2; m++ {
		ts := time.Date(2026, 11, 28, 21, m, 20, 0, tz)
		nowMu.Lock()
		curNow = ts
		nowMu.Unlock()
		mu.Lock()
		*conns = []mockClashConn{
			{ID: fmt.Sprintf("gh-reboot-%d", m), Upload: 12 * 1024, Download: 32 * 1024, Start: ts.Format(time.RFC3339), SrcIP: "192.168.1.77", DstIP: "203.0.113.99", Host: "api.github.com"},
		}
		mu.Unlock()
		if !col2.SampleActiveConnections(t.Context()) {
			t.Fatal("sample col2 failed")
		}
	}
	col2.FlushProfileHistory()

	prof7d := col2.BuildDeviceProfile(t.Context(), &config.Config{}, "192.168.1.77", audit.ProfileRange7d)
	if prof7d == nil {
		t.Fatal("expected non-nil 7d profile")
	}
	if prof7d.Storage.RetentionDays != 7 || !prof7d.Storage.AutoCleanup {
		t.Fatalf("expected RetentionDays=7 and AutoCleanup=true, got %+v", prof7d.Storage)
	}
	if prof7d.Storage.HistoryDays > 7 || len(prof7d.DailyTrend) > 7 {
		t.Fatalf("expected old days purged to <= 7 days, got HistoryDays=%d len(DailyTrend)=%d", prof7d.Storage.HistoryDays, len(prof7d.DailyTrend))
	}
	// Past 6 days * 15 mins YouTube = 90 mins + today 3 mins GitHub (min 0, min 1 not double counted, min 2!) = 93 mins!
	if prof7d.TotalForegroundMinutes != 93 {
		t.Fatalf("expected 93 foreground minutes (6*15 + 3 non-duplicated today mins), got %d", prof7d.TotalForegroundMinutes)
	}

	// Now test strict hard disk size cap (2048 bytes) with many bogus apps
	capPath := filepath.Join(tmp, "capped-history.json")
	colCap := audit.NewCollector(&config.Config{})
	colCap.SetEndpointsForTest([]string{srv.URL}, "", filepath.Join(tmp, "state-cap.json"))
	colCap.SetProfileHistoryPathForTest(capPath, 2048)
	colCap.SetNowFuncForTest(func() time.Time { return time.Date(2026, 11, 28, 22, 0, 5, 0, tz) })
	many := make([]mockClashConn, 0, 40)
	for i := range 40 {
		many = append(many, mockClashConn{
			ID: fmt.Sprintf("app-%d", i), Upload: 5000, Download: 30000,
			Start: time.Date(2026, 11, 28, 22, 0, 1, 0, tz).Format(time.RFC3339),
			SrcIP: fmt.Sprintf("192.168.2.%d", i+10), DstIP: "203.0.113.50",
			Host: "api.github.com",
		})
	}
	mu.Lock()
	*conns = many
	mu.Unlock()
	_ = colCap.SampleActiveConnections(t.Context())
	colCap.FlushProfileHistory()

	fi, err := os.Stat(capPath)
	if err != nil {
		t.Fatalf("expected capped history file created: %v", err)
	}
	if fi.Size() > 2048 {
		t.Fatalf("expected history file size <= 2048 bytes hard cap, got %d bytes", fi.Size())
	}
	if perm := fi.Mode().Perm(); perm != 0600 {
		t.Fatalf("expected 0600 permissions, got %04o", perm)
	}
	entries, _ := filepath.Glob(filepath.Join(tmp, "*tmp*"))
	if len(entries) != 0 {
		t.Fatalf("expected zero stale temp files, got %v", entries)
	}
}

func TestDeviceProfile_ConcurrentRaceSafety(t *testing.T) {
	srv, mu, conns := newMutableClashServer(t)
	mu.Lock()
	*conns = []mockClashConn{
		{ID: "c1", Upload: 10000, Download: 250000, Start: time.Now().Format(time.RFC3339), SrcIP: "192.168.1.88", DstIP: "203.0.113.10", Host: "www.youtube.com"},
	}
	mu.Unlock()

	tmp := t.TempDir()
	c := audit.NewCollector(&config.Config{})
	c.SetEndpointsForTest([]string{srv.URL}, "", filepath.Join(tmp, "race-state.json"))
	c.SetProfileHistoryPathForTest(filepath.Join(tmp, "race-history.json"), 64<<10)

	var wg sync.WaitGroup
	for g := range 6 {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := range 5 {
				_ = c.SampleActiveConnections(t.Context())
				rng := audit.ProfileRange24h
				if (id+i)%2 == 1 {
					rng = audit.ProfileRange7d
				}
				_ = c.BuildDeviceProfile(t.Context(), &config.Config{}, "192.168.1.88", rng)
			}
		}(g)
	}
	wg.Wait()
	c.FlushProfileHistory()
}

func TestAdvisor_SummarizeDeviceProfile_SanitizedAndOfflineFallback(t *testing.T) {
	prof := &audit.DeviceProfileReport{
		DeviceIP:               "192.168.88.123",
		DeviceName:             "workstation.home",
		DeviceMAC:              "aa:bb:cc:dd:ee:ff",
		DeviceRole:             "desktop",
		Range:                  audit.ProfileRange7d,
		TotalForegroundMinutes: 185,
		TotalBackgroundMinutes: 12,
		PeakHourLabel:          "晚间 21:00–22:00",
		ProxySharePct:          64.5,
		TopApps: []audit.DeviceAppStat{
			{AppName: "GitHub", CategoryLabel: "AI与开发", ForegroundMinutes: 110, Sessions: 4, LongestSessionMin: 45},
			{AppName: "YouTube", CategoryLabel: "视频娱乐", ForegroundMinutes: 75, Sessions: 2, LongestSessionMin: 50},
		},
		Categories: []audit.DeviceCategoryStat{
			{Category: audit.AppCategoryAIDev, Label: "AI与开发", Minutes: 110, SharePct: 59.5},
			{Category: audit.AppCategoryVideo, Label: "视频娱乐", Minutes: 75, SharePct: 40.5},
		},
	}

	// 1. Offline fallback
	offAdv := audit.NewAdvisor(config.AuditAIConfig{})
	resOff := offAdv.SummarizeDeviceProfile(t.Context(), prof, "")
	if resOff == nil || !resOff.OK || strings.TrimSpace(resOff.Summary) == "" {
		t.Fatalf("expected non-empty offline AI summary fallback, got %+v", resOff)
	}

	// 2. Remote mock endpoint must NOT receive real LAN IP or MAC (Rule 01)!
	var capturedBody string
	llmSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rawBody, _ := io.ReadAll(r.Body)
		capturedBody = string(rawBody)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"model": "test-model",
			"choices": []map[string]any{
				{"message": map[string]any{"content": "这台桌面设备过去 7 天以编程开发与视频浏览为主，晚间最活跃。"}},
			},
		})
	}))
	defer llmSrv.Close()

	remAdv := audit.NewAdvisor(config.AuditAIConfig{
		Enabled:  true,
		Endpoint: llmSrv.URL + "/v1/chat/completions",
		Model:    "test-model",
	})
	resRem := remAdv.SummarizeDeviceProfile(t.Context(), prof, "")
	if resRem == nil || !resRem.OK || !strings.Contains(resRem.Summary, "桌面设备") {
		t.Fatalf("expected remote LLM summary, got %+v", resRem)
	}
	if strings.Contains(capturedBody, "192.168.88.123") || strings.Contains(strings.ToLower(capturedBody), "aa:bb:cc:dd:ee:ff") || strings.Contains(capturedBody, "workstation") {
		t.Fatalf("Rule 01 violation: real device IP/MAC/hostname leaked into AI prompt: %s", capturedBody)
	}
}
