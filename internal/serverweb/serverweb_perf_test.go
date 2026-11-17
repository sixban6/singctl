package serverweb

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"singctl/internal/config"
	"singctl/internal/heal"
	"singctl/internal/subhub"
)

func TestSniffTrackerAndGeoConcurrency_NonBlockingAndFlush(t *testing.T) {
	ctx := t.Context()
	tmpDir := t.TempDir()
	sniffFile := filepath.Join(tmpDir, ".serverweb_sniff.json")
	geoFile := filepath.Join(tmpDir, ".serverweb_geo_cache.json")

	// Simulate an orphaned 0-byte .tmp file left behind during an I/O stall
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

	cleanupStaleServerWebTmpFiles(tmpDir)
	if _, err := os.Stat(staleTmp); !os.IsNotExist(err) {
		t.Fatalf("expected stale 0-byte tmp file %s to be cleaned up", staleTmp)
	}
	if _, err := os.Stat(freshTmp); err != nil {
		t.Fatalf("expected fresh tmp file %s to be preserved, got err=%v", freshTmp, err)
	}
	_ = os.Remove(freshTmp)

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

	srv := New(Options{
		ConfigPath:    cfgPath,
		SubStoreDir:   filepath.Join(tmpDir, "sub-store"),
		FleetFilePath: filepath.Join(tmpDir, "fleet.yaml"),
		Username:      "opsadmin",
		Password:      "Password123",
	})
	srv.sniff.EnableSystemProbe = false

	srv.geo = NewIPGeoResolver(geoFile)
	srv.sniff = NewSniffTracker(srv.geo, srv.limiter, sniffFile)
	srv.sniff.EnableSystemProbe = false

	srv.geo.SeedCountry("198.51.100.10", "US")
	srv.geo.SeedCountry("203.0.113.20", "JP")
	srv.sniff.Observe("198.51.100.10", "TLS/443 伪装回落嗅探", "masqueraded", 3)
	srv.sniff.Observe("203.0.113.20", "SSH 暴力破解", "banned", 5)

	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for j := range 20 {
				if j%2 == 0 {
					srv.geo.SeedCountry("192.0.2.50", "US")
					srv.sniff.MarkTrustedClientIPs("192.0.2.50")
				} else {
					srv.sniff.Observe("198.51.100.10", "TLS/443 伪装回落嗅探", "masqueraded", 1)
				}
				_ = srv.sniff.Snapshot(ctx, "192.0.2.50")
				if worker == 0 && j%10 == 0 {
					srv.sniff.Flush()
					srv.geo.Flush()
				}
			}
		}(i)
	}
	wg.Wait()

	srv.sniff.Flush()
	srv.geo.Flush()

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

	reloadedGeo := NewIPGeoResolver(geoFile)
	reloadedSniff := NewSniffTracker(reloadedGeo, nil, sniffFile)
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
	parsed := parseSystemdShowBatchOutput(raw)
	if len(parsed) != 4 {
		t.Fatalf("expected 4 parsed units, got %d (%+v)", len(parsed), parsed)
	}
	if !parsed["caddy"].running || parsed["caddy"].pid != "568" || parsed["caddy"].uptime == "" {
		t.Fatalf("unexpected caddy probe: %+v", parsed["caddy"])
	}
	if !parsed["sing-box"].running || parsed["sing-box"].pid != "571" || parsed["sing-box"].uptime != "" {
		t.Fatalf("unexpected sing-box probe: %+v", parsed["sing-box"])
	}
	if parsed["singctl-sub"].running || parsed["singctl-sub"].pid != "" || parsed["singctl-sub"].uptime != "" {
		t.Fatalf("unexpected singctl-sub probe: %+v", parsed["singctl-sub"])
	}
	if !parsed["wireproxy"].running || parsed["wireproxy"].pid != "983" {
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

	srv := New(Options{
		ConfigPath:    cfgPath,
		SubStoreDir:   filepath.Join(tmpDir, "sub-store"),
		FleetFilePath: filepath.Join(tmpDir, "fleet.yaml"),
		Username:      "opsadmin",
		Password:      "Password123",
	})
	srv.sniff.EnableSystemProbe = false

	sentinel := &heal.StatusReport{
		CheckedAt:    "2026-11-17T04:00:00Z",
		Posture:      heal.PostureHealthy,
		PostureLabel: "cached-sentinel-label",
	}
	srv.healCacheMu.Lock()
	srv.cachedHealReport = sentinel
	srv.cachedHealAt = time.Now()
	srv.healCacheMu.Unlock()

	// 1. Default request should serve cached sentinel without invoking live scan
	req := httptest.NewRequest(http.MethodGet, "/api/server/heal/status", nil)
	req.SetBasicAuth("opsadmin", "Password123")
	req.RemoteAddr = "127.0.0.1:54321"
	req.Header.Set("X-Real-IP", "192.0.2.1")
	rec := httptest.NewRecorder()
	srv.Mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/server/heal/status failed: %d %s", rec.Code, rec.Body.String())
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte("cached-sentinel-label")) {
		t.Fatalf("expected cached sentinel label in response, got: %s", rec.Body.String())
	}

	// 2. ?refresh=1 should bypass cache and overwrite cachedHealReport
	reqRefresh := httptest.NewRequest(http.MethodGet, "/api/server/heal/status?refresh=1", nil)
	reqRefresh.SetBasicAuth("opsadmin", "Password123")
	reqRefresh.RemoteAddr = "127.0.0.1:54321"
	reqRefresh.Header.Set("X-Real-IP", "192.0.2.1")
	recRefresh := httptest.NewRecorder()
	srv.Mux.ServeHTTP(recRefresh, reqRefresh)

	if recRefresh.Code != http.StatusOK {
		t.Fatalf("GET /api/server/heal/status?refresh=1 failed: %d %s", recRefresh.Code, recRefresh.Body.String())
	}
	if bytes.Contains(recRefresh.Body.Bytes(), []byte("cached-sentinel-label")) {
		t.Fatalf("expected ?refresh=1 to bypass cache, still got sentinel: %s", recRefresh.Body.String())
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

	srv := New(Options{
		ConfigPath:    cfgPath,
		SubStoreDir:   filepath.Join(tmpDir, "sub-store"),
		FleetFilePath: filepath.Join(tmpDir, "fleet.yaml"),
		AuditFilePath: auditPath,
		BanFilePath:   banPath,
		Username:      "opsadmin",
		Password:      "Password123",
	})
	srv.sniff.EnableSystemProbe = false

	// Seed cached component versions and certs so we focus on stalled disk + stalled systemd probes
	srv.versionCacheMu.Lock()
	srv.cachedVersions = map[string]string{"caddy": "2.9.1", "singbox": "1.12.0", "subhub": "1.14.130", "warp": "1.0.9"}
	srv.cachedVersionsAt = time.Now()
	srv.versionCacheMu.Unlock()
	srv.certProbeMu.Lock()
	srv.cachedCerts = []CertHealth{{Domain: "sub.example.com", Status: "healthy", DaysRemaining: 80}}
	srv.cachedCertsAt = time.Now()
	srv.certProbeMu.Unlock()

	// Simulate kernel D-state freeze on disk writes, config reads, and systemctl child processes
	blockDiskCh := make(chan struct{})
	stalledWrite := func(path string, data []byte) error {
		<-blockDiskCh
		return writeAtomicFile0600(path, data)
	}
	srv.audit.writer.setWriteFunc(stalledWrite)
	srv.limiter.writer.setWriteFunc(stalledWrite)
	srv.configLoaderOverride = func(p string) (*config.Config, error) {
		<-blockDiskCh
		return config.Load(p)
	}
	srv.statusProberOverride = func() map[string]serviceProbeSnapshot {
		<-blockDiskCh
		return map[string]serviceProbeSnapshot{
			"caddy":    {running: true, pid: "101"},
			"sing-box": {running: true, pid: "102"},
		}
	}
	// Force config cache TTL expiry so handleStatus hits the stalled configLoaderOverride
	srv.invalidateConfigCache()

	// 1. Trigger a background Watchdog audit write so the writer goroutine is already wedged in D-state
	srv.audit.Record("127.0.0.1", "WARP 巡检模拟慢盘写入")

	// 2. Wrong password login must still return 401 fast without blocking on stalled ban/audit disk writes
	t0 := time.Now()
	badReq := httptest.NewRequest(http.MethodPost, "/api/server/login", strings.NewReader(`{"username":"opsadmin","password":"WrongPassword"}`))
	badReq.RemoteAddr = "198.51.100.42:54321"
	badReq.Header.Set("Content-Type", "application/json")
	badRec := httptest.NewRecorder()
	srv.Mux.ServeHTTP(badRec, badReq)
	if badRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 on wrong password during disk stall, got %d: %s", badRec.Code, badRec.Body.String())
	}
	if elapsed := time.Since(t0); elapsed > 300*time.Millisecond {
		t.Fatalf("expected wrong-password login to complete fast during disk stall, took %v", elapsed)
	}

	// 3. Valid login must succeed with 200 + session cookie in <300ms despite 100% disk freeze
	t1 := time.Now()
	okReq := httptest.NewRequest(http.MethodPost, "/api/server/login", strings.NewReader(`{"username":"opsadmin","password":"Password123"}`))
	okReq.RemoteAddr = "198.51.100.42:54322"
	okReq.Header.Set("Content-Type", "application/json")
	okRec := httptest.NewRecorder()
	srv.Mux.ServeHTTP(okRec, okReq)
	if okRec.Code != http.StatusOK {
		t.Fatalf("expected 200 on valid login during disk stall, got %d: %s", okRec.Code, okRec.Body.String())
	}
	if elapsed := time.Since(t1); elapsed > 300*time.Millisecond {
		t.Fatalf("expected valid login to complete fast during disk stall, took %v", elapsed)
	}
	cookies := okRec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("expected session cookie to be issued during disk stall")
	}

	// 4. Post-login GET /api/server/status must return 200 within bounded select budget despite stalled config & systemctl
	t2 := time.Now()
	stReq := httptest.NewRequest(http.MethodGet, "/api/server/status", nil)
	stReq.RemoteAddr = "198.51.100.42:54323"
	for _, c := range cookies {
		stReq.AddCookie(c)
	}
	stRec := httptest.NewRecorder()
	srv.Mux.ServeHTTP(stRec, stReq)
	if stRec.Code != http.StatusOK {
		t.Fatalf("expected 200 from /api/server/status during disk+systemd stall, got %d: %s", stRec.Code, stRec.Body.String())
	}
	if elapsed := time.Since(t2); elapsed > 1500*time.Millisecond {
		t.Fatalf("expected /api/server/status within bounded fallback window, took %v", elapsed)
	}
	if !strings.Contains(stRec.Body.String(), "sub.example.com") {
		t.Fatalf("expected fallback cached config domain in status response, got: %s", stRec.Body.String())
	}

	// 5. Unfreeze disk and verify coalesced snapshots flush cleanly with 0600 permissions
	close(blockDiskCh)
	srv.audit.Flush()
	srv.limiter.Close()

	stAudit, err := os.Stat(auditPath)
	if err != nil || stAudit.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 flushed audit file after stall recovery, err=%v", err)
	}
	reloadedAudit := NewAuditManager(auditPath)
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

	srv := New(Options{
		ConfigPath:    cfgPath,
		SubStoreDir:   filepath.Join(tmpDir, "sub-store"),
		FleetFilePath: filepath.Join(tmpDir, "fleet.yaml"),
		Username:      "opsadmin",
		Password:      "Password123",
	})
	srv.sniff.EnableSystemProbe = false

	var legacyChecks atomic.Int32
	srv.warpWatchdogDeps = &WarpWatchdogDeps{
		HasLegacyFscarmen: func() bool {
			legacyChecks.Add(1)
			return false
		},
		ProbeRealTargets: func(time.Duration) (string, string, error) {
			return "198.51.100.10", "LAX", nil
		},
	}

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

	srv := New(Options{
		ConfigPath:    cfgPath,
		SubStoreDir:   filepath.Join(tmpDir, "sub-store"),
		FleetFilePath: filepath.Join(tmpDir, "fleet.yaml"),
		Username:      "opsadmin",
		Password:      "Password123",
	})
	srv.sniff.EnableSystemProbe = false
	srv.SubStore().AllowLoopbackRemote = true

	// Issue a valid admin session cookie
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

	// Case 1: WARP routing — expired exit IP cache must return stale IP immediately (<120ms) and refresh async
	srv.warpPortChecker = func() bool { return true }
	var warpFetchCalls atomic.Int32
	srv.warpExitFetcher = func(time.Duration) (string, string, string, bool) {
		warpFetchCalls.Add(1)
		time.Sleep(450 * time.Millisecond)
		return "198.51.100.200", "SJC", "", true
	}
	srv.warpCacheMu.Lock()
	srv.warpCachedIP = "198.51.100.100"
	srv.warpCachedLoc = "LAX"
	srv.warpCachedAt = time.Now().Add(-10 * time.Minute) // expired beyond TTL
	srv.warpCacheMu.Unlock()

	warpRec, warpElapsed := authedGet("/api/server/warp/routing")
	if warpRec.Code != http.StatusOK {
		t.Fatalf("expected 200 from /api/server/warp/routing, got %d", warpRec.Code)
	}
	if warpElapsed > 120*time.Millisecond {
		t.Fatalf("expected stale WARP routing to return immediately (<120ms), took %v", warpElapsed)
	}
	if !strings.Contains(warpRec.Body.String(), "198.51.100.100") {
		t.Fatalf("expected stale WARP IP 198.51.100.100 returned immediately, got: %s", warpRec.Body.String())
	}

	// Case 2: Security Heal — expired heal status cache must return stale snapshot (<120ms) and single-flight scan async
	var healCalls atomic.Int32
	srv.healScannerOverride = func(context.Context, string, string) heal.StatusReport {
		healCalls.Add(1)
		time.Sleep(450 * time.Millisecond)
		return heal.StatusReport{Posture: heal.PostureHealthy, PostureLabel: "fresh-scan"}
	}
	srv.storeHealStatusCache(&heal.StatusReport{Posture: heal.PostureHealthy, PostureLabel: "stale-cached"})
	srv.healCacheMu.Lock()
	srv.cachedHealAt = time.Now().Add(-10 * time.Minute) // expired beyond 3m TTL
	srv.healCacheMu.Unlock()

	healRec, healElapsed := authedGet("/api/server/heal/status")
	if healRec.Code != http.StatusOK {
		t.Fatalf("expected 200 from /api/server/heal/status, got %d", healRec.Code)
	}
	if healElapsed > 120*time.Millisecond {
		t.Fatalf("expected stale heal status to return immediately (<120ms), took %v", healElapsed)
	}
	if !strings.Contains(healRec.Body.String(), "stale-cached") {
		t.Fatalf("expected stale-cached heal posture returned immediately, got: %s", healRec.Body.String())
	}

	// Case 3: Subscriptions — expired remote subscription source must not block GET /api/server/subscriptions
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
	if subRec.Code != http.StatusOK {
		t.Fatalf("expected 200 from /api/server/subscriptions, got %d", subRec.Code)
	}
	if subElapsed > 120*time.Millisecond {
		t.Fatalf("expected /api/server/subscriptions to return without blocking on slow upstream warmup (<120ms), took %v", subElapsed)
	}

	// Wait for background single-flight refreshes to complete and verify caches updated cleanly
	time.Sleep(550 * time.Millisecond)
	warpAfter, _ := authedGet("/api/server/warp/routing")
	if !strings.Contains(warpAfter.Body.String(), "198.51.100.200") {
		t.Fatalf("expected async WARP refresh to update cached IP to 198.51.100.200, got: %s", warpAfter.Body.String())
	}
	healAfter, _ := authedGet("/api/server/heal/status")
	if !strings.Contains(healAfter.Body.String(), "fresh-scan") {
		t.Fatalf("expected async heal scan to update cached report to fresh-scan, got: %s", healAfter.Body.String())
	}
	if got := warpFetchCalls.Load(); got != 1 {
		t.Fatalf("expected single-flight WARP background refresh (1 call), got %d", got)
	}
	if got := healCalls.Load(); got != 1 {
		t.Fatalf("expected single-flight heal background refresh (1 call), got %d", got)
	}
}
