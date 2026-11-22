// 文件职责：覆盖服务端 SWR 有界单飞缓存、磁盘/systemd 假死韧性、嗅探版本号失效链路与性能基准测试。
package serverweb_test

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"singctl/internal/common/fsx"
	"singctl/internal/config"
	"singctl/internal/fleet"
	"singctl/internal/heal"
	"singctl/internal/serverweb"
	"singctl/internal/sniff"
	"singctl/internal/subhub"
)

func TestSniffTrackerAndGeoConcurrency_NonBlockingAndFlush(t *testing.T) {
	ctx := t.Context()
	tmpDir := t.TempDir()
	sniffFile := filepath.Join(tmpDir, ".serverweb_sniff.json")
	geoFile := filepath.Join(tmpDir, ".serverweb_geo_cache.json")

	staleTmp := filepath.Join(tmpDir, ".serverweb_sniff.json.12345.tmp")
	if err := os.WriteFile(staleTmp, nil, 0600); err != nil {
		t.Fatal(err)
	}
	oldTime := time.Now().Add(-5 * time.Minute)
	if err := os.Chtimes(staleTmp, oldTime, oldTime); err != nil {
		t.Fatal(err)
	}
	freshTmp := filepath.Join(tmpDir, ".serverweb_sniff.json.99999.tmp")
	if err := os.WriteFile(freshTmp, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}

	serverweb.CleanupStaleServerWebTmpFiles(tmpDir)
	if _, err := os.Stat(staleTmp); !os.IsNotExist(err) {
		t.Fatalf("expected stale 0-byte tmp file %s to be cleaned up", staleTmp)
	}
	if _, err := os.Stat(freshTmp); err != nil {
		t.Fatalf("expected fresh tmp file %s to be preserved, got err=%v", freshTmp, err)
	}
	_ = os.Remove(freshTmp)

	geo := serverweb.NewIPGeoResolver(geoFile)
	lim := serverweb.NewIPLimiter(3, 10*time.Minute, 15*time.Minute, filepath.Join(tmpDir, "bans.json"))
	defer lim.Close()
	tracker := serverweb.NewSniffTracker(geo, lim, sniffFile)
	tracker.EnableSystemProbe = false

	geo.SeedCountry("198.51.100.10", "US")
	geo.SeedCountry("203.0.113.20", "JP")
	tracker.Observe("198.51.100.10", "TLS/443 伪装回落嗅探", "masqueraded", 3)
	tracker.Observe("203.0.113.20", "SSH 暴力破解", "banned", 5)

	var wg sync.WaitGroup
	for i := range 8 {
		worker := i
		wg.Go(func() {
			for j := range 20 {
				if j%2 == 0 {
					geo.SeedCountry("192.0.2.50", "US")
					tracker.MarkTrustedClientIPs("192.0.2.50")
				} else {
					tracker.Observe("198.51.100.10", "TLS/443 伪装回落嗅探", "masqueraded", 1)
				}
				_ = tracker.Snapshot(ctx, "192.0.2.50")
				if worker == 0 && j%10 == 0 {
					tracker.Flush()
					geo.Flush()
				}
			}
		})
	}
	wg.Wait()

	tracker.Flush()
	geo.Flush()

	rawSniff, err := os.ReadFile(sniffFile)
	if err != nil {
		t.Fatalf("read flushed sniff file: %v", err)
	}
	if bytes.Contains(rawSniff, []byte("\n  ")) {
		t.Fatalf("expected compact JSON persistence for sniff file, got indented output")
	}
	if st, sErr := os.Stat(sniffFile); sErr != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 permissions on %s, got err=%v", sniffFile, sErr)
	}
	if st, gErr := os.Stat(geoFile); gErr != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 permissions on %s, got err=%v", geoFile, gErr)
	}

	reloadedGeo := serverweb.NewIPGeoResolver(geoFile)
	reloadedSniff := serverweb.NewSniffTracker(reloadedGeo, nil, sniffFile)
	reloadedSniff.EnableSystemProbe = false
	reSum := reloadedSniff.SnapshotForNode(ctx, "all", false)
	if reSum.TotalSniffIPs != 2 {
		t.Fatalf("expected 2 persisted sniff IPs after reload, got %d", reSum.TotalSniffIPs)
	}
	if info := reloadedGeo.Resolve("198.51.100.10"); info.CountryCode != "US" {
		t.Fatalf("expected persisted geo US for 198.51.100.10, got %+v", info)
	}
}

func TestParseSystemdShowBatchOutput(t *testing.T) {
	raw := `
Id=caddy.service
ActiveState=active
MainPID=568
ActiveEnterTimestamp=Mon 2026-11-16 15:06:25 EST

Id=sing-box.service
ActiveState=active
MainPID=571
ActiveEnterTimestamp=

Id=singctl-sub.service
ActiveState=inactive
MainPID=0
ActiveEnterTimestamp=n/a

Id=wireproxy.service
ActiveState=active
MainPID=983
ActiveEnterTimestamp=Mon 2026-11-16 15:07:37 EST
`
	parsed := serverweb.ParseSystemdShowBatchOutput(raw)
	if len(parsed) != 4 {
		t.Fatalf("expected 4 parsed units, got %d (%+v)", len(parsed), parsed)
	}
	if !parsed["caddy"].Running || parsed["caddy"].PID != "568" || parsed["caddy"].Uptime == "" {
		t.Fatalf("unexpected caddy probe: %+v", parsed["caddy"])
	}
	if !parsed["sing-box"].Running || parsed["sing-box"].PID != "571" || parsed["sing-box"].Uptime != "" {
		t.Fatalf("unexpected sing-box probe: %+v", parsed["sing-box"])
	}
	if parsed["singctl-sub"].Running || parsed["singctl-sub"].PID != "" || parsed["singctl-sub"].Uptime != "" {
		t.Fatalf("unexpected singctl-sub probe: %+v", parsed["singctl-sub"])
	}
	if !parsed["wireproxy"].Running || parsed["wireproxy"].PID != "983" {
		t.Fatalf("unexpected wireproxy probe: %+v", parsed["wireproxy"])
	}
}

func TestHandleHealStatus_CacheAndRefresh(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "singctl.yaml")
	if err := os.WriteFile(cfgPath, []byte(`
server:
  node_domain: "node.example.com"
  web_admin:
    username: "opsadmin"
    password: "Password123"
`), 0600); err != nil {
		t.Fatal(err)
	}

	srv := serverweb.New(serverweb.Options{
		ConfigPath:    cfgPath,
		SubStoreDir:   filepath.Join(tmpDir, "sub-store"),
		FleetFilePath: filepath.Join(tmpDir, "fleet.yaml"),
		Username:      "opsadmin",
		Password:      "Password123",
	})
	defer srv.Limiter().Close()
	srv.SniffTracker().EnableSystemProbe = false

	srv.SeedHealCache(&heal.StatusReport{
		CheckedAt:    "2026-11-17T04:00:00Z",
		Posture:      heal.PostureHealthy,
		PostureLabel: "cached-sentinel-label",
	}, time.Now())

	req := httptest.NewRequest(http.MethodGet, "/api/server/heal/status", nil)
	req.SetBasicAuth("opsadmin", "Password123")
	req.RemoteAddr = "127.0.0.1:54321"
	req.Header.Set("X-Real-IP", "192.0.2.1")
	rec := httptest.NewRecorder()
	srv.Mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK || !bytes.Contains(rec.Body.Bytes(), []byte("cached-sentinel-label")) {
		t.Fatalf("expected cached sentinel label in response, got %d: %s", rec.Code, rec.Body.String())
	}

	reqRefresh := httptest.NewRequest(http.MethodGet, "/api/server/heal/status?refresh=1", nil)
	reqRefresh.SetBasicAuth("opsadmin", "Password123")
	reqRefresh.RemoteAddr = "127.0.0.1:54321"
	reqRefresh.Header.Set("X-Real-IP", "192.0.2.1")
	recRefresh := httptest.NewRecorder()
	srv.Mux.ServeHTTP(recRefresh, reqRefresh)

	if recRefresh.Code != http.StatusOK || bytes.Contains(recRefresh.Body.Bytes(), []byte("cached-sentinel-label")) {
		t.Fatalf("expected ?refresh=1 to bypass cache, got %d: %s", recRefresh.Code, recRefresh.Body.String())
	}
}

func TestLoginAndStatus_SurviveTotalDiskAndSystemdStall(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "singctl.yaml")
	auditPath := filepath.Join(tmpDir, ".serverweb_audit.json")
	banPath := filepath.Join(tmpDir, ".serverweb_bans.json")

	if err := os.WriteFile(cfgPath, []byte(`
server:
  node_domain: "node.example.com"
  substore_domain: "sub.example.com"
  web_admin:
    path: "/sr/testpanel"
    username: "opsadmin"
    password: "Password123"
`), 0600); err != nil {
		t.Fatal(err)
	}

	srv := serverweb.New(serverweb.Options{
		ConfigPath:    cfgPath,
		SubStoreDir:   filepath.Join(tmpDir, "sub-store"),
		FleetFilePath: filepath.Join(tmpDir, "fleet.yaml"),
		AuditFilePath: auditPath,
		BanFilePath:   banPath,
		Username:      "opsadmin",
		Password:      "Password123",
	})
	srv.SniffTracker().EnableSystemProbe = false

	srv.SeedStatusCaches(
		map[string]string{"caddy": "2.9.1", "singbox": "1.12.0", "subhub": "1.14.130", "warp": "1.0.9"},
		[]serverweb.CertHealth{{Domain: "sub.example.com", Status: "healthy", DaysRemaining: 80}},
	)

	blockDiskCh := make(chan struct{})
	stalledWrite := func(path string, data []byte) error {
		<-blockDiskCh
		return fsx.WriteAtomic0600(path, data)
	}
	srv.AuditManager().SetWriteFunc(stalledWrite)
	srv.Limiter().SetWriteFunc(stalledWrite)
	srv.SetDeps(serverweb.Deps{
		ConfigLoader: func(p string) (*config.Config, error) {
			<-blockDiskCh
			return config.Load(p)
		},
		StatusProber: func() map[string]serverweb.ServiceProbeSnapshot {
			<-blockDiskCh
			return map[string]serverweb.ServiceProbeSnapshot{
				"caddy":    {Running: true, PID: "101"},
				"sing-box": {Running: true, PID: "102"},
			}
		},
	})
	srv.InvalidateConfigCache()

	srv.AuditManager().Record("127.0.0.1", "WARP 巡检模拟慢盘写入")

	t0 := time.Now()
	badReq := httptest.NewRequest(http.MethodPost, "/api/server/login", strings.NewReader(`{"username":"opsadmin","password":"WrongPassword"}`))
	badReq.RemoteAddr = "198.51.100.42:54321"
	badReq.Header.Set("Content-Type", "application/json")
	badRec := httptest.NewRecorder()
	srv.Mux.ServeHTTP(badRec, badReq)
	if badRec.Code != http.StatusUnauthorized || time.Since(t0) > 300*time.Millisecond {
		t.Fatalf("expected fast 401 on wrong password during disk stall, got %d in %v", badRec.Code, time.Since(t0))
	}

	t1 := time.Now()
	okReq := httptest.NewRequest(http.MethodPost, "/api/server/login", strings.NewReader(`{"username":"opsadmin","password":"Password123"}`))
	okReq.RemoteAddr = "198.51.100.42:54322"
	okReq.Header.Set("Content-Type", "application/json")
	okRec := httptest.NewRecorder()
	srv.Mux.ServeHTTP(okRec, okReq)
	if okRec.Code != http.StatusOK || time.Since(t1) > 300*time.Millisecond {
		t.Fatalf("expected fast 200 on valid login during disk stall, got %d in %v", okRec.Code, time.Since(t1))
	}
	cookies := okRec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("expected session cookie to be issued during disk stall")
	}

	t2 := time.Now()
	stReq := httptest.NewRequest(http.MethodGet, "/api/server/status", nil)
	stReq.RemoteAddr = "198.51.100.42:54323"
	for _, c := range cookies {
		stReq.AddCookie(c)
	}
	stRec := httptest.NewRecorder()
	srv.Mux.ServeHTTP(stRec, stReq)
	if stRec.Code != http.StatusOK || time.Since(t2) > 1500*time.Millisecond {
		t.Fatalf("expected /api/server/status 200 within bounded fallback window, got %d in %v", stRec.Code, time.Since(t2))
	}
	if !strings.Contains(stRec.Body.String(), "sub.example.com") {
		t.Fatalf("expected fallback cached config domain in status response, got: %s", stRec.Body.String())
	}

	close(blockDiskCh)
	srv.AuditManager().Flush()
	srv.Limiter().Close()

	stAudit, err := os.Stat(auditPath)
	if err != nil || stAudit.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 flushed audit file after stall recovery, err=%v", err)
	}
	reloadedAudit := serverweb.NewAuditManager(auditPath)
	if len(reloadedAudit.List()) < 3 {
		t.Fatalf("expected all 3 audit entries coalesced and persisted after stall recovery, got %d", len(reloadedAudit.List()))
	}
}

func TestWarpWatchdog_LegacyFscarmenCheckRunsOnceNotEveryTick(t *testing.T) {
	ctx := t.Context()
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "singctl.yaml")
	if err := os.WriteFile(cfgPath, []byte(`
server:
  node_domain: "node.example.com"
  web_admin:
    username: "opsadmin"
    password: "Password123"
`), 0600); err != nil {
		t.Fatal(err)
	}

	srv := serverweb.New(serverweb.Options{
		ConfigPath:    cfgPath,
		SubStoreDir:   filepath.Join(tmpDir, "sub-store"),
		FleetFilePath: filepath.Join(tmpDir, "fleet.yaml"),
		Username:      "opsadmin",
		Password:      "Password123",
	})
	defer srv.Limiter().Close()
	srv.SniffTracker().EnableSystemProbe = false

	var legacyChecks atomic.Int32
	srv.SetDeps(serverweb.Deps{
		WarpWatchdogDeps: &serverweb.WarpWatchdogDeps{
			HasLegacyFscarmen: func() bool {
				legacyChecks.Add(1)
				return false
			},
			ProbeRealTargets: func(time.Duration) (string, string, error) {
				return "198.51.100.10", "LAX", nil
			},
		},
	})

	for range 5 {
		srv.RunWarpWatchdogTick(ctx)
	}
	if got := legacyChecks.Load(); got != 1 {
		t.Fatalf("expected HasLegacyFscarmen check to run exactly once on boot, got %d calls across 5 ticks", got)
	}
}

func TestServerTabs_StaleWhileRevalidate_NonBlocking(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "singctl.yaml")
	if err := os.WriteFile(cfgPath, []byte(`
server:
  node_domain: "node.example.com"
  substore_domain: "sub.example.com"
  web_admin:
    username: "opsadmin"
    password: "Password123"
`), 0600); err != nil {
		t.Fatal(err)
	}

	srv := serverweb.New(serverweb.Options{
		ConfigPath:    cfgPath,
		SubStoreDir:   filepath.Join(tmpDir, "sub-store"),
		FleetFilePath: filepath.Join(tmpDir, "fleet.yaml"),
		Username:      "opsadmin",
		Password:      "Password123",
	})
	defer srv.Limiter().Close()
	srv.SniffTracker().EnableSystemProbe = false
	srv.SubStore().AllowLoopbackRemote = true

	loginReq := httptest.NewRequest(http.MethodPost, "/api/server/login", strings.NewReader(`{"username":"opsadmin","password":"Password123"}`))
	loginReq.RemoteAddr = "198.51.100.88:50001"
	loginReq.Header.Set("Content-Type", "application/json")
	loginRec := httptest.NewRecorder()
	srv.Mux.ServeHTTP(loginRec, loginReq)
	cookies := loginRec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("expected session cookie")
	}
	authedGet := func(url string) (*httptest.ResponseRecorder, time.Duration) {
		t0 := time.Now()
		req := httptest.NewRequest(http.MethodGet, url, nil)
		req.RemoteAddr = "198.51.100.88:50002"
		for _, c := range cookies {
			req.AddCookie(c)
		}
		rec := httptest.NewRecorder()
		srv.Mux.ServeHTTP(rec, req)
		return rec, time.Since(t0)
	}

	var warpFetchCalls atomic.Int32
	var healCalls atomic.Int32
	srv.SetDeps(serverweb.Deps{
		WarpPortChecker: func() bool { return true },
		WarpExitFetcher: func(time.Duration) (string, string, string, bool) {
			warpFetchCalls.Add(1)
			time.Sleep(450 * time.Millisecond)
			return "198.51.100.200", "SJC", "", true
		},
		HealScanner: func(context.Context, string, string) heal.StatusReport {
			healCalls.Add(1)
			time.Sleep(450 * time.Millisecond)
			return heal.StatusReport{Posture: heal.PostureHealthy, PostureLabel: "fresh-scan"}
		},
	})
	srv.SeedWarpExitCache("198.51.100.100", "LAX", time.Now().Add(-10*time.Minute))
	srv.SeedHealCache(&heal.StatusReport{Posture: heal.PostureHealthy, PostureLabel: "stale-cached"}, time.Now().Add(-10*time.Minute))

	warpRec, warpElapsed := authedGet("/api/server/warp/routing")
	if warpRec.Code != http.StatusOK || warpElapsed > 120*time.Millisecond || !strings.Contains(warpRec.Body.String(), "198.51.100.100") {
		t.Fatalf("expected fast stale WARP IP 198.51.100.100 (<120ms), got code=%d elapsed=%v body=%s", warpRec.Code, warpElapsed, warpRec.Body.String())
	}

	healRec, healElapsed := authedGet("/api/server/heal/status")
	if healRec.Code != http.StatusOK || healElapsed > 120*time.Millisecond || !strings.Contains(healRec.Body.String(), "stale-cached") {
		t.Fatalf("expected fast stale heal status (<120ms), got code=%d elapsed=%v body=%s", healRec.Code, healElapsed, healRec.Body.String())
	}

	var slowUpstream atomic.Bool
	upstreamSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if slowUpstream.Load() {
			time.Sleep(450 * time.Millisecond)
		}
		_, _ = w.Write([]byte("vless://11111111-1111-1111-1111-111111111111@198.51.100.10:443?security=none#DemoNode\n"))
	}))
	defer upstreamSrv.Close()

	enabled := true
	if _, err := srv.SubStore().UpsertSource(t.Context(), subhub.SourceUpsertInput{
		Name:        "ext-sub",
		DisplayName: "Ext Sub",
		Source:      "remote",
		URL:         upstreamSrv.URL + "/sub",
		Enabled:     &enabled,
	}); err != nil {
		t.Fatalf("UpsertSource failed: %v", err)
	}
	srv.SubStore().CacheTTL = time.Millisecond
	time.Sleep(5 * time.Millisecond)
	slowUpstream.Store(true)

	subRec, subElapsed := authedGet("/api/server/subscriptions")
	if subRec.Code != http.StatusOK || subElapsed > 120*time.Millisecond {
		t.Fatalf("expected non-blocking /api/server/subscriptions (<120ms), got code=%d elapsed=%v", subRec.Code, subElapsed)
	}

	srv.SniffTracker().Observe("198.51.100.222", "TLS/443 握手探测", "masqueraded", 4)
	sniffRec, sniffElapsed := authedGet("/api/server/security/sniffers")
	if sniffRec.Code != http.StatusOK || sniffElapsed > 120*time.Millisecond {
		t.Fatalf("expected non-blocking /api/server/security/sniffers (<120ms), got code=%d elapsed=%v", sniffRec.Code, sniffElapsed)
	}

	time.Sleep(550 * time.Millisecond)
	warpAfter, _ := authedGet("/api/server/warp/routing")
	if !strings.Contains(warpAfter.Body.String(), "198.51.100.200") {
		t.Fatalf("expected async WARP refresh to update cached IP to 198.51.100.200, got: %s", warpAfter.Body.String())
	}
	healAfter, _ := authedGet("/api/server/heal/status")
	if !strings.Contains(healAfter.Body.String(), "fresh-scan") {
		t.Fatalf("expected async heal scan to update cached report to fresh-scan, got: %s", healAfter.Body.String())
	}
	if warpFetchCalls.Load() != 1 || healCalls.Load() != 1 {
		t.Fatalf("expected single-flight refreshes (1 each), got warp=%d heal=%d", warpFetchCalls.Load(), healCalls.Load())
	}
}

func TestSniffTracker_ServerWebFleetCallbackWiringAndInvalidation(t *testing.T) {
	ctx := t.Context()
	tmpDir := t.TempDir()
	srv := serverweb.New(serverweb.Options{
		ConfigPath:    filepath.Join(tmpDir, "singctl.yaml"),
		SubStoreDir:   filepath.Join(tmpDir, "sub-store"),
		FleetFilePath: filepath.Join(tmpDir, "fleet.yaml"),
		BanFilePath:   filepath.Join(tmpDir, "bans.json"),
		AuditFilePath: filepath.Join(tmpDir, "audit.json"),
		Username:      "opsadmin",
		Password:      "Password123",
	})
	defer srv.Limiter().Close()
	tracker := srv.SniffTracker()
	tracker.EnableSystemProbe = false

	for i := range 200 {
		ip := fmt.Sprintf("198.51.%d.%d", (i/250)+100, (i%250)+1)
		srv.GeoResolver().SeedCountry(ip, "US")
		tracker.Observe(ip, "TLS/443 伪装回落嗅探", "masqueraded", i+1)
	}

	s1 := tracker.Snapshot(ctx)
	if s1.TotalSniffIPs != 200 {
		t.Fatalf("expected 200 IPs, got %d", s1.TotalSniffIPs)
	}
	rebuildsAfterFirst := tracker.SnapshotRebuilds()
	for range 10 {
		_ = tracker.Snapshot(ctx)
	}
	if got := tracker.SnapshotRebuilds(); got != rebuildsAfterFirst {
		t.Fatalf("expected 0 rebuilds on cached Snapshot(), went from %d to %d", rebuildsAfterFirst, got)
	}

	// fleet.Store Upsert must invalidate SniffTracker snapshot via RemoteProvider.Revision closure
	if _, err := srv.FleetManager().Store.Upsert(fleet.UpsertInput{
		ID:       "tokyo-1",
		Name:     "Tokyo Node",
		Host:     "203.0.113.150",
		User:     "root",
		Password: "pw",
	}); err != nil {
		t.Fatal(err)
	}
	sAfterFleet := tracker.Snapshot(ctx)
	var foundTokyo bool
	for _, n := range sAfterFleet.Nodes {
		if n.ID == "tokyo-1" {
			foundTokyo = true
		}
	}
	if !foundTokyo {
		t.Fatalf("expected fleet.Store Upsert to invalidate sniff snapshot and expose tokyo-1 immediately, got %+v", sAfterFleet.Nodes)
	}
	_ = sniff.TimeLayout
}

func BenchmarkSniffTracker_Snapshot_500IPs(b *testing.B) {
	tmpDir := b.TempDir()
	geo := serverweb.NewIPGeoResolver(filepath.Join(tmpDir, "geo.json"))
	limiter := serverweb.NewIPLimiter(3, 10*time.Minute, 15*time.Minute, filepath.Join(tmpDir, "ban.json"))
	defer limiter.Close()
	tracker := serverweb.NewSniffTracker(geo, limiter, filepath.Join(tmpDir, "sniff.json"))
	tracker.EnableSystemProbe = false

	countries := []string{"US", "JP", "SG", "DE", "NL"}
	for i := range 500 {
		ip := fmt.Sprintf("198.51.%d.%d", (i/250)+10, (i%250)+1)
		geo.SeedCountry(ip, countries[i%len(countries)])
		tracker.Observe(ip, "TLS/443 伪装回落嗅探", "masqueraded", (i%20)+1)
	}
	ctx := b.Context()
	_ = tracker.Snapshot(ctx)

	b.ReportAllocs()
	for b.Loop() {
		snap := tracker.Snapshot(ctx)
		if snap.TotalSniffIPs != 500 {
			b.Fatalf("expected 500 IPs, got %d", snap.TotalSniffIPs)
		}
	}
}
