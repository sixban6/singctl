// 文件职责：验证三引擎注册表与 singbox / smartdns / adguard 三个具体引擎的完整管控接口、统计与防注入校验。
package localdns_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"singctl/internal/adguard"
	"singctl/internal/common/sysinfo"
	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/localdns"
	"singctl/internal/platform/servicemgr"
	"singctl/internal/singbox"
	"singctl/internal/smartdns"
)

func sampleSingBoxConfigJSON() string {
	return `{
  "dns": {
    "servers": [
      {"tag": "dns_local", "type": "https", "server": "223.5.5.5", "server_port": 443, "path": "/dns-query"},
      {"tag": "dns_proxy", "type": "https", "server": "1.1.1.1", "server_port": 443, "path": "/dns-query"}
    ],
    "rules": [
      {"rule_set": ["geosite-ad1", "geosite-ad2"], "action": "reject"},
      {"rule_set": "block-builtin-pcdn", "action": "reject"}
    ]
  },
  "route": {
    "rule_set": [
      {"tag": "geosite-ad1", "type": "remote", "format": "binary", "url": "https://example.com/ad1.srs"},
      {"tag": "geosite-ad2", "type": "remote", "format": "binary", "url": "https://example.com/ad2.srs"},
      {"tag": "block-builtin-pcdn", "type": "inline", "rules": [{"domain_suffix": ["pcdn.example.com"]}]}
    ],
    "rules": [
      {"rule_set": ["geosite-ad1", "geosite-ad2"], "action": "reject"},
      {"rule_set": "block-builtin-pcdn", "action": "reject"}
    ]
  }
}`
}

func TestSingBoxEngine_FullControlsAndTelemetry(t *testing.T) {
	ctx := t.Context()
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "singctl.yaml")
	sbCfgPath := filepath.Join(tmpDir, "config.json")
	if err := os.WriteFile(sbCfgPath, []byte(sampleSingBoxConfigJSON()), 0600); err != nil {
		t.Fatal(err)
	}
	if err := singbox.SaveBaseSnapshot(sbCfgPath, sampleSingBoxConfigJSON()); err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 11, 22, 18, 0, 0, 0, time.UTC)
	cfg := &config.Config{
		Subs: []config.Subscription{{Name: "S1", URL: "https://sub.example.com/profile"}},
		DNS: config.ClientDNSConfig{
			Engine:       constant.DNSEngineSingBox,
			UpstreamMode: config.DNSUpstreamModeFastestIP,
			Upstreams:    []string{"https://223.5.5.5/dns-query", "https://1.12.12.12/dns-query"},
		},
	}
	if err := config.Save(cfgPath, cfg); err != nil {
		t.Fatal(err)
	}

	ring := localdns.NewStatsRing(true)
	ring.Record(now, "video.example.com", false, 0)
	ring.Record(now, "ad.example.com", true, 0)

	syncCalls := 0
	cacheCleared := false

	deps := localdns.EngineDeps{
		ConfigPath:        cfgPath,
		SingBoxConfigPath: sbCfgPath,
		AdGuardBinPath:    filepath.Join(tmpDir, "missing-agh"),
		SmartDNSBinPath:   filepath.Join(tmpDir, "missing-smartdns"),
		SingBoxStats:      ring,
		NowFunc:           func() time.Time { return now },
		SingBoxRunningFunc: func() bool {
			return true
		},
		SingBoxVersionFunc: func() string { return "1.14.4" },
		ReadMemInfo: func() (sysinfo.MemInfo, error) {
			return sysinfo.MemInfo{TotalBytes: 256 * 1024 * 1024, AvailableBytes: 120 * 1024 * 1024}, nil
		},
		ReadDiskSpace: func(string) (sysinfo.DiskSpace, error) {
			return sysinfo.DiskSpace{AvailBytes: 40 * 1024 * 1024}, nil
		},
		ProbeUpstreamListFunc: func(_ context.Context, upstreams []string, _ string, _ time.Duration) []adguard.UpstreamProbeItem {
			out := make([]adguard.UpstreamProbeItem, len(upstreams))
			for i, u := range upstreams {
				lat := int64(35)
				if strings.Contains(u, "1.12.12.12") {
					lat = 9
				}
				out[i] = adguard.UpstreamProbeItem{
					Address:   u,
					Name:      u,
					Protocol:  "DoH",
					Healthy:   true,
					LatencyMs: lat,
					Resolved:  "192.0.2.1",
				}
			}
			return out
		},
		SyncSingBoxEnhancedFunc: func(_ context.Context, p, _ string, dnsCfg config.ClientDNSConfig, subDomains []string, ts time.Time) (bool, error) {
			syncCalls++
			raw, err := os.ReadFile(p)
			if err != nil {
				return false, err
			}
			updated, changed, err := singbox.ApplyEnhancedSingBoxDNSJSON(string(raw), dnsCfg, subDomains, ts)
			if err != nil {
				return false, err
			}
			if changed {
				if err := os.WriteFile(p, []byte(updated), 0600); err != nil {
					return false, err
				}
			}
			return changed, nil
		},
		ClearSingBoxCacheFunc: func(context.Context, string, string) error {
			cacheCleared = true
			return nil
		},
	}

	reg := localdns.NewRegistry(cfg, deps)
	eng := reg.ActiveEngine()
	if eng == nil || eng.ID() != constant.DNSEngineSingBox {
		t.Fatalf("expected active singbox engine, got %v", eng)
	}

	// 1. Overview & capabilities contract
	ov := reg.Overview(ctx)
	if ov.ActiveEngine != constant.DNSEngineSingBox || !ov.Installed || !ov.Capabilities.HasQueryStats || !ov.Capabilities.HasBlockAAAA || ov.Capabilities.HasCustomFilterURL || ov.Capabilities.CanUninstall {
		t.Fatalf("unexpected singbox overview/capabilities: active=%q installed=%v caps=%+v", ov.ActiveEngine, ov.Installed, ov.Capabilities)
	}
	if ov.StatsSource != "singbox_telemetry" || ov.Stats.NumDNSQueries != 2 || ov.Stats.NumBlockedFiltering != 1 {
		t.Fatalf("unexpected singbox telemetry stats: source=%q stats=%+v", ov.StatsSource, ov.Stats)
	}
	if len(ov.Engines) != 3 {
		t.Fatalf("expected 3 engine options, got %d", len(ov.Engines))
	}

	// 2. SetUpstreams in fastest_ip mode places fastest upstream (1.12.12.12) first!
	upRes, err := eng.SetUpstreams(ctx, []string{"https://223.5.5.5/dns-query", "https://1.12.12.12/dns-query"}, config.DNSUpstreamModeFastestIP, false)
	if err != nil {
		t.Fatalf("SetUpstreams failed: %v", err)
	}
	if len(upRes.Upstreams) != 2 || upRes.Upstreams[0].Address != "https://1.12.12.12/dns-query" {
		t.Fatalf("expected fastest upstream promoted to index 0, got %+v", upRes.Upstreams)
	}
	// Malicious / loopback upstream rejected
	if _, err := eng.SetUpstreams(ctx, []string{"https://127.0.0.1/dns-query"}, "", false); err == nil {
		t.Fatal("expected loopback upstream to be rejected")
	}

	// 3. Pause protection 30 min -> config persisted & synced
	if err := eng.SetProtection(ctx, false, 30); err != nil {
		t.Fatalf("SetProtection pause failed: %v", err)
	}
	if !cfg.DNS.IsAdblockPaused(now) {
		t.Fatalf("expected adblock paused, AdblockDisabledUntil=%d", cfg.DNS.AdblockDisabledUntil)
	}
	// Resume protection
	if err := eng.SetProtection(ctx, true, 0); err != nil {
		t.Fatalf("SetProtection resume failed: %v", err)
	}
	if cfg.DNS.IsAdblockPaused(now) {
		t.Fatal("expected adblock resumed")
	}

	// 4. Filter toggle built-in tag succeeds; custom external URL rejected
	if err := eng.SetFilterState(ctx, "ruleset:geosite-ad2", "", false); err != nil {
		t.Fatalf("disable geosite-ad2 failed: %v", err)
	}
	if !slices.Contains(cfg.DNS.DisabledAdRuleSets, "geosite-ad2") {
		t.Fatalf("expected geosite-ad2 in DisabledAdRuleSets, got %v", cfg.DNS.DisabledAdRuleSets)
	}
	if err := eng.SetFilterState(ctx, "https://example.com/custom.txt", "Custom", true); err == nil {
		t.Fatal("expected custom filter URL to be rejected by singbox engine")
	}

	// 5. Whitelist, Rewrite, BlockAAAA & .singctl-base sync
	if err := eng.SetWhitelist(ctx, "good.example.com", true); err != nil {
		t.Fatalf("SetWhitelist failed: %v", err)
	}
	if err := eng.AddRewrite(ctx, "nas.example.com", "192.0.2.50"); err != nil {
		t.Fatalf("AddRewrite failed: %v", err)
	}
	if err := eng.AddRewrite(ctx, "bad\ndomain.example.com", "192.0.2.50"); err == nil {
		t.Fatal("expected injection domain rewrite rejected")
	}
	if err := eng.SetBlockAAAA(ctx, true); err != nil {
		t.Fatalf("SetBlockAAAA failed: %v", err)
	}
	baseAfter, err := singbox.LoadBaseSnapshot(sbCfgPath)
	if err != nil || !strings.Contains(baseAfter, "192.0.2.50") {
		t.Fatalf("expected .singctl-base synced with rewrite, err=%v", err)
	}

	// 6. Probe, ClearCache & ConfigPreview
	rep := eng.ProbeUpstreams(ctx, "qq.com")
	if !rep.Healthy || rep.FastestUpstream != "https://1.12.12.12/dns-query" {
		t.Fatalf("unexpected probe report: %+v", rep)
	}
	if err := eng.ClearCache(ctx); err != nil || !cacheCleared {
		t.Fatalf("ClearCache failed: err=%v cleared=%v", err, cacheCleared)
	}
	prev, err := eng.ConfigPreview(ctx)
	if err != nil || prev.Engine != constant.DNSEngineSingBox || !strings.Contains(prev.Content, "dns_local") {
		t.Fatalf("unexpected ConfigPreview: err=%v prev=%+v", err, prev)
	}
	if syncCalls == 0 {
		t.Fatal("expected live singbox enhanced sync calls")
	}
}

func TestSmartDNSEngine_ControlsAuditStatsAndPreview(t *testing.T) {
	ctx := t.Context()
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "singctl.yaml")
	binPath := filepath.Join(tmpDir, "smartdns")
	confPath := filepath.Join(tmpDir, "smartdns.conf")
	rulesDir := filepath.Join(tmpDir, "smartdns-rules.d")
	auditLog := filepath.Join(tmpDir, "smartdns-audit.log")

	if err := os.WriteFile(binPath, []byte("#!/bin/sh\necho 'smartdns 1.2025.46'\n"), 0755); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Truncate(time.Second)
	auditContent := "[" + now.Format("2006-01-02 15:04:05.000") + "] 127.0.0.1 query example.com, type 1, time 12ms, result 192.0.2.10\n" +
		"[" + now.Format("2006-01-02 15:04:05.000") + "] 127.0.0.1 query ads.example.com, type 1, time 1ms, result SOA\n" +
		"[" + now.Format("2006-01-02 15:04:05.000") + "] 127.0.0.1 query localhost, type 1, time 0ms, speed: -0.1ms, group default, result 127.0.0.1\n"
	if err := os.WriteFile(auditLog, []byte(auditContent), 0600); err != nil {
		t.Fatal(err)
	}

	mockSvc := servicemgr.NewMock()
	_ = mockSvc.Start(ctx, constant.SmartDNSServiceName)

	cfg := &config.Config{
		Subs: []config.Subscription{{Name: "S1", URL: "https://sub.example.com/feed"}},
		DNS: config.ClientDNSConfig{
			Engine:  constant.DNSEngineSmartDNS,
			DNSPort: 5353,
		},
	}
	if err := config.Save(cfgPath, cfg); err != nil {
		t.Fatal(err)
	}

	filterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("address /tracker.example.com/#\n0.0.0.0 banner.example.com\n"))
	}))
	defer filterSrv.Close()

	sdMgr := smartdns.NewManager(smartdns.ManagerOptions{
		BinaryPath:   binPath,
		ConfigFile:   confPath,
		RulesDir:     rulesDir,
		AuditLogPath: auditLog,
		LogFilePath:  filepath.Join(tmpDir, "smartdns.log"),
		PIDFilePath:  filepath.Join(tmpDir, "smartdns.pid"),
		ServiceName:  constant.SmartDNSServiceName,
		GOOS:         "linux",
		GOARCH:       "arm64",
		ServiceMgr:   mockSvc,
		HTTPClient:   filterSrv.Client(),
		ProbeDNSFunc: func(string, time.Duration) error { return nil },
	})

	deps := localdns.EngineDeps{
		ConfigPath:           cfgPath,
		AdGuardBinPath:       filepath.Join(tmpDir, "missing-agh"),
		SmartDNSBinPath:      binPath,
		SmartDNSConfigFile:   confPath,
		SmartDNSRulesDir:     rulesDir,
		SmartDNSAuditLogPath: auditLog,
		ServiceMgr:           mockSvc,
		SmartDNSManager:      sdMgr,
		SkipProbeForTest:     true,
		ReadMemInfo: func() (sysinfo.MemInfo, error) {
			return sysinfo.MemInfo{TotalBytes: 480 * 1024 * 1024, AvailableBytes: 205 * 1024 * 1024}, nil
		},
		ReadDiskSpace: func(string) (sysinfo.DiskSpace, error) {
			return sysinfo.DiskSpace{AvailBytes: 50 * 1024 * 1024}, nil
		},
	}

	reg := localdns.NewRegistry(cfg, deps)
	eng := reg.ActiveEngine()
	if eng == nil || eng.ID() != constant.DNSEngineSmartDNS {
		t.Fatalf("expected active smartdns engine, got %v", eng)
	}

	// Overview ingests SmartDNS audit log into 24h StatsRing
	ov := reg.Overview(ctx)
	if ov.ActiveEngine != constant.DNSEngineSmartDNS || ov.StatsSource != "smartdns_audit" {
		t.Fatalf("unexpected smartdns overview: active=%q source=%q", ov.ActiveEngine, ov.StatsSource)
	}
	if ov.Stats.NumDNSQueries != 2 || ov.Stats.NumBlockedFiltering != 1 {
		t.Fatalf("expected 2 queries / 1 blocked from audit log, got %+v", ov.Stats)
	}
	if !ov.Capabilities.HasCustomFilterURL || !ov.Capabilities.HasBlockAAAA || ov.Capabilities.HasNativeWebPanel {
		t.Fatalf("unexpected smartdns capabilities: %+v", ov.Capabilities)
	}

	// Controls: Whitelist, Rewrite, BlockAAAA, Custom Filter, Audit Sync, ConfigPreview
	if err := eng.SetWhitelist(ctx, "allow.example.com", true); err != nil {
		t.Fatalf("SetWhitelist failed: %v", err)
	}
	if err := eng.AddRewrite(ctx, "nas.example.com", "192.0.2.88"); err != nil {
		t.Fatalf("AddRewrite failed: %v", err)
	}
	if err := eng.SetBlockAAAA(ctx, true); err != nil {
		t.Fatalf("SetBlockAAAA failed: %v", err)
	}
	if err := eng.SetFilterState(ctx, filterSrv.URL+"/adblock.txt", "Test Filter", true); err != nil {
		t.Fatalf("SetFilterState failed: %v", err)
	}
	applied, mode, err := eng.SyncBlockRules(ctx, []config.BlockRule{{Target: "evil.example.com"}})
	if err != nil || !applied || mode == "" {
		t.Fatalf("SyncBlockRules failed: applied=%v mode=%q err=%v", applied, mode, err)
	}

	prev, err := eng.ConfigPreview(ctx)
	if err != nil || !strings.Contains(prev.Content, "force-AAAA-SOA yes") || !strings.Contains(prev.Content, "evil.example.com") {
		t.Fatalf("unexpected smartdns ConfigPreview: err=%v content=%s", err, prev.Content)
	}
}

func TestAdGuardEngine_OverviewCredentialsAndRedactedPreview(t *testing.T) {
	ctx := t.Context()
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "singctl.yaml")
	fakeBin := filepath.Join(tmpDir, "AdGuardHome")
	if err := os.WriteFile(fakeBin, []byte("#!/bin/sh\necho 'AdGuard Home, version v0.107.59'\n"), 0755); err != nil {
		t.Fatal(err)
	}

	mockAGH := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/control/status":
			_ = json.NewEncoder(w).Encode(map[string]any{"version": "v0.107.59", "running": true, "protection_enabled": true})
		case "/control/stats":
			_ = json.NewEncoder(w).Encode(map[string]any{"num_dns_queries": 500, "num_blocked_filtering": 50, "avg_processing_time": 0.008})
		case "/control/filtering/status":
			_ = json.NewEncoder(w).Encode(map[string]any{"enabled": true, "filters": []any{}, "user_rules": []string{}})
		case "/control/rewrite/list":
			_ = json.NewEncoder(w).Encode([]any{})
		case "/control/dns_info":
			_ = json.NewEncoder(w).Encode(map[string]any{"upstream_dns": []string{"https://223.5.5.5/dns-query"}, "upstream_mode": "parallel"})
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer mockAGH.Close()
	parsed, _ := url.Parse(mockAGH.URL)

	aghCfg := filepath.Join(tmpDir, "AdGuardHome.yaml")
	rawYAML := "http:\n  address: " + parsed.Host + "\nusers:\n  - name: root\n    password: $2a$10$secretbcryptvalue\ndns:\n  port: 5353\n"
	if err := os.WriteFile(aghCfg, []byte(rawYAML), 0600); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{
		DNS: config.ClientDNSConfig{
			Engine:   constant.DNSEngineAdGuard,
			DNSPort:  5353,
			Username: "root",
			Password: "TestPassword1234",
		},
	}
	if err := config.Save(cfgPath, cfg); err != nil {
		t.Fatal(err)
	}

	reg := localdns.NewRegistry(cfg, localdns.EngineDeps{
		ConfigPath:        cfgPath,
		AdGuardBinPath:    fakeBin,
		AdGuardConfigPath: aghCfg,
		SmartDNSBinPath:   filepath.Join(tmpDir, "missing-smartdns"),
		SkipProbeForTest:  true,
	})
	eng := reg.ActiveEngine()
	if eng == nil || eng.ID() != constant.DNSEngineAdGuard {
		t.Fatalf("expected active adguard engine, got %v", eng)
	}

	ov := reg.Overview(ctx)
	if ov.StatsSource != "adguard_api" || ov.Stats.NumDNSQueries != 500 || !ov.Capabilities.HasNativeWebPanel || ov.Capabilities.HasBlockAAAA {
		t.Fatalf("unexpected adguard overview: source=%q stats=%+v caps=%+v", ov.StatsSource, ov.Stats, ov.Capabilities)
	}

	credMgr, ok := eng.(localdns.CredentialManager)
	if !ok {
		t.Fatal("AdGuardEngine must implement CredentialManager")
	}
	creds, err := credMgr.Credentials(ctx)
	if err != nil || creds.Username != "root" || creds.Password != "TestPassword1234" {
		t.Fatalf("unexpected credentials: err=%v creds=%+v", err, creds)
	}

	prev, err := eng.ConfigPreview(ctx)
	if err != nil {
		t.Fatalf("ConfigPreview failed: %v", err)
	}
	if strings.Contains(prev.Content, "secretbcryptvalue") {
		t.Fatalf("ConfigPreview leaked password hash:\n%s", prev.Content)
	}

	if err := eng.SetBlockAAAA(ctx, true); err == nil {
		t.Fatal("expected AdGuardEngine.SetBlockAAAA to return unsupported error")
	}
}
