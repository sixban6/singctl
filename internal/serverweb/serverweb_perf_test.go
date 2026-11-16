package serverweb

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"singctl/internal/heal"
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
