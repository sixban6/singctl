// 文件职责：验证双引擎注册表（SmartDNS / AdGuard Home）、未安装纯 DoH 兜底契约及各引擎完整管控接口与防注入校验。
package localdns_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
    "disable_cache": true,
    "optimistic": false,
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
  },
  "experimental": {
    "cache_file": {
      "enabled": true,
      "store_dns": false,
      "store_fakeip": false
    }
  }
}`
}

func TestRegistry_DualEngineUninstalledFallbackDoHContract(t *testing.T) {
	ctx := t.Context()
	tmpDir := t.TempDir()
	const mib = 1024 * 1024

	sbCfgPath := filepath.Join(tmpDir, "config.json")
	if err := os.WriteFile(sbCfgPath, []byte(sampleSingBoxConfigJSON()), 0600); err != nil {
		t.Fatal(err)
	}

	t.Run("n60pro_uninstalled_selects_smartdns_and_reports_fallback_doh_active", func(t *testing.T) {
		cfg := &config.Config{DNS: config.ClientDNSConfig{Engine: "singbox"}} // legacy value must normalize to auto
		reg := localdns.NewRegistry(cfg, localdns.EngineDeps{
			SingBoxConfigPath: sbCfgPath,
			AdGuardBinPath:    filepath.Join(tmpDir, "missing-agh"),
			AdGuardConfigPath: filepath.Join(tmpDir, "missing-agh.yaml"),
			SmartDNSBinPath:   filepath.Join(tmpDir, "missing-smartdns"),
			ReadMemInfo: func() (sysinfo.MemInfo, error) {
				return sysinfo.MemInfo{TotalBytes: 491040 * 1024, AvailableBytes: 210260 * 1024}, nil
			},
			ReadDiskSpace: func(string) (sysinfo.DiskSpace, error) {
				return sysinfo.DiskSpace{AvailBytes: 50 * mib}, nil
			},
		})

		if _, ok := reg.Get("singbox"); ok {
			t.Fatal("removed singbox engine must NOT be registered")
		}
		if len(reg.All()) != 2 {
			t.Fatalf("expected exactly 2 registered engines, got %d", len(reg.All()))
		}

		ov := reg.Overview(ctx)
		if ov.ConfiguredEngine != constant.DNSEngineAuto {
			t.Fatalf("ConfiguredEngine = %q, want auto", ov.ConfiguredEngine)
		}
		if ov.ActiveEngine != constant.DNSEngineSmartDNS || ov.ActiveEngineLabel != "SmartDNS" {
			t.Fatalf("ActiveEngine = %q (%q), want smartdns (SmartDNS)", ov.ActiveEngine, ov.ActiveEngineLabel)
		}
		if ov.RecommendedEngine != constant.DNSEngineSmartDNS {
			t.Fatalf("RecommendedEngine = %q, want smartdns", ov.RecommendedEngine)
		}
		if ov.Installed {
			t.Fatal("expected Installed=false when neither external engine is installed")
		}
		if !ov.FallbackDoHActive {
			t.Fatal("expected FallbackDoHActive=true when external engine is uninstalled")
		}
		if ov.StatsSource != "smartdns_audit" {
			t.Fatalf("StatsSource = %q, want smartdns_audit", ov.StatsSource)
		}
		if len(ov.Engines) != 2 {
			t.Fatalf("expected 2 engine options, got %d: %+v", len(ov.Engines), ov.Engines)
		}
		for _, opt := range ov.Engines {
			if opt.ID == "singbox" {
				t.Fatalf("Engines must never contain singbox: %+v", ov.Engines)
			}
		}

		st := reg.StatusSummary(ctx)
		if fb, _ := st["fallbackDoHActive"].(bool); !fb {
			t.Fatalf("StatusSummary expected fallbackDoHActive=true, got %+v", st)
		}
		if ae, _ := st["activeEngine"].(string); ae != constant.DNSEngineSmartDNS {
			t.Fatalf("StatusSummary activeEngine=%q, want smartdns", ae)
		}
	})

	t.Run("high_spec_uninstalled_selects_adguard_with_fallback_doh", func(t *testing.T) {
		cfg := &config.Config{DNS: config.ClientDNSConfig{Engine: constant.DNSEngineAuto}}
		reg := localdns.NewRegistry(cfg, localdns.EngineDeps{
			SingBoxConfigPath: sbCfgPath,
			AdGuardBinPath:    filepath.Join(tmpDir, "missing-agh"),
			AdGuardConfigPath: filepath.Join(tmpDir, "missing-agh.yaml"),
			SmartDNSBinPath:   filepath.Join(tmpDir, "missing-smartdns"),
			ReadMemInfo: func() (sysinfo.MemInfo, error) {
				return sysinfo.MemInfo{TotalBytes: 2048 * mib, AvailableBytes: 1500 * mib}, nil
			},
			ReadDiskSpace: func(string) (sysinfo.DiskSpace, error) {
				return sysinfo.DiskSpace{AvailBytes: 512 * mib}, nil
			},
		})
		ov := reg.Overview(ctx)
		if ov.ActiveEngine != constant.DNSEngineAdGuard || ov.ActiveEngineLabel != "AdGuard Home" || ov.Installed || !ov.FallbackDoHActive || ov.StatsSource != "adguard_api" || len(ov.Engines) != 2 {
			t.Fatalf("unexpected high-spec uninstalled overview: active=%q label=%q installed=%v fallback=%v source=%q engines=%d",
				ov.ActiveEngine, ov.ActiveEngineLabel, ov.Installed, ov.FallbackDoHActive, ov.StatsSource, len(ov.Engines))
		}
	})
}

func TestSmartDNSEngine_ControlsAuditStatsAndPreview(t *testing.T) {
	ctx := t.Context()
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "singctl.yaml")
	sbPath := filepath.Join(tmpDir, "config.json")
	binPath := filepath.Join(tmpDir, "smartdns")
	confPath := filepath.Join(tmpDir, "smartdns.conf")
	rulesDir := filepath.Join(tmpDir, "smartdns-rules.d")
	auditLog := filepath.Join(tmpDir, "smartdns-audit.log")

	sbLinked, _, _ := singbox.PatchDNSLocalJSON(sampleSingBoxConfigJSON(), true, 5353)
	if err := os.WriteFile(sbPath, []byte(sbLinked), 0600); err != nil {
		t.Fatal(err)
	}
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
		SingBoxConfigPath:    sbPath,
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

	// Overview ingests SmartDNS audit log into 24h StatsRing and shows FallbackDoHActive=false when running+linked
	ov := reg.Overview(ctx)
	if ov.ActiveEngine != constant.DNSEngineSmartDNS || ov.StatsSource != "smartdns_audit" || len(ov.Engines) != 2 {
		t.Fatalf("unexpected smartdns overview: active=%q source=%q engines=%d", ov.ActiveEngine, ov.StatsSource, len(ov.Engines))
	}
	if ov.FallbackDoHActive {
		t.Fatal("expected FallbackDoHActive=false when SmartDNS is installed, running, enabled and linked")
	}
	if ov.Stats.NumDNSQueries != 2 || ov.Stats.NumBlockedFiltering != 1 {
		t.Fatalf("expected 2 queries / 1 blocked from audit log, got %+v", ov.Stats)
	}
	if !ov.Capabilities.HasCustomFilterURL || ov.Capabilities.HasBlockAAAA || ov.Capabilities.HasNativeWebPanel {
		t.Fatalf("unexpected smartdns capabilities (hasBlockAAAA must be false): %+v", ov.Capabilities)
	}
	if !ov.BlockAAAA {
		t.Fatal("expected SmartDNS Overview BlockAAAA=true when gateway.ipv6_mode defaults to off")
	}

	// Controls: Whitelist, Rewrite, Custom Filter, Audit Sync, ConfigPreview
	if err := eng.SetWhitelist(ctx, "allow.example.com", true); err != nil {
		t.Fatalf("SetWhitelist failed: %v", err)
	}
	if err := eng.AddRewrite(ctx, "nas.example.com", "192.0.2.88"); err != nil {
		t.Fatalf("AddRewrite failed: %v", err)
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
		t.Fatalf("expected force-AAAA-SOA yes when ipv6_mode=off: err=%v content=%s", err, prev.Content)
	}

	// Single source of truth: gateway.ipv6_mode=cn_only or full MUST disable force-AAAA-SOA even if legacy dns.block_aaaa=true
	for _, v6Mode := range []string{config.GatewayIPv6CNOnly, config.GatewayIPv6Full} {
		cfg.Gateway.IPv6Mode = v6Mode
		cfg.DNS.BlockAAAA = true // legacy field must be ignored in favor of gateway.ipv6_mode
		if err := eng.SyncCommonConfig(ctx); err != nil {
			t.Fatalf("SyncCommonConfig(ipv6_mode=%s) failed: %v", v6Mode, err)
		}
		ovV6 := reg.Overview(ctx)
		if ovV6.BlockAAAA {
			t.Fatalf("ipv6_mode=%s: expected BlockAAAA=false, got true", v6Mode)
		}
		prevV6, err := eng.ConfigPreview(ctx)
		if err != nil || strings.Contains(prevV6.Content, "force-AAAA-SOA yes") {
			t.Fatalf("ipv6_mode=%s: expected force-AAAA-SOA yes absent, err=%v content=%s", v6Mode, err, prevV6.Content)
		}
	}
	// Switching back to off re-enables force-AAAA-SOA yes
	cfg.Gateway.IPv6Mode = config.GatewayIPv6Off
	cfg.DNS.BlockAAAA = false
	if err := eng.SyncCommonConfig(ctx); err != nil {
		t.Fatalf("SyncCommonConfig(ipv6_mode=off) failed: %v", err)
	}
	if prevOff, err := eng.ConfigPreview(ctx); err != nil || !strings.Contains(prevOff.Content, "force-AAAA-SOA yes") {
		t.Fatalf("ipv6_mode=off: expected force-AAAA-SOA yes present, err=%v content=%s", err, prevOff.Content)
	}

	// Verify UTC-skewed musl audit timestamp (e.g. OpenWrt static binary logging UTC while host is UTC-5) is normalized cleanly.
	fixedNow := time.Date(2026, 11, 23, 13, 0, 5, 0, time.FixedZone("EST", -5*3600))
	utcLogPath := filepath.Join(tmpDir, "smartdns-audit-utc.log")
	utcLine := "[2026-11-23 18:00:03,100] 127.0.0.1 query skew.example.com, type 1, time 10ms, speed: 5.0ms, group default, result 192.0.2.55\n"
	if err := os.WriteFile(utcLogPath, []byte(utcLine), 0600); err != nil {
		t.Fatal(err)
	}
	skewReg := localdns.NewRegistry(cfg, localdns.EngineDeps{
		ConfigPath:           cfgPath,
		AdGuardBinPath:       filepath.Join(tmpDir, "missing-agh"),
		SmartDNSBinPath:      binPath,
		SmartDNSConfigFile:   confPath,
		SmartDNSRulesDir:     rulesDir,
		SmartDNSAuditLogPath: utcLogPath,
		ServiceMgr:           mockSvc,
		SmartDNSManager:      sdMgr,
		SkipProbeForTest:     true,
		NowFunc:              func() time.Time { return fixedNow },
	})
	skewOv := skewReg.Overview(ctx)
	if skewOv.Stats.NumDNSQueries != 1 {
		t.Fatalf("expected UTC-skewed musl audit entry normalized into current 24h window, got stats=%+v", skewOv.Stats)
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
	if ov.StatsSource != "adguard_api" || ov.Stats.NumDNSQueries != 500 || !ov.Capabilities.HasNativeWebPanel || ov.Capabilities.HasBlockAAAA || len(ov.Engines) != 2 {
		t.Fatalf("unexpected adguard overview: source=%q stats=%+v caps=%+v engines=%d", ov.StatsSource, ov.Stats, ov.Capabilities, len(ov.Engines))
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
}
