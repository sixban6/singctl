// 文件职责：验证双引擎（SmartDNS / AdGuard Home）零断网两阶段原子切换、公共配置迁移、硬件门槛阻断、端口避让与失败自动回滚契约。
package localdns_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"singctl/internal/common/sysinfo"
	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/localdns"
	"singctl/internal/platform/servicemgr"
	"singctl/internal/singbox"
	"singctl/internal/singbox/sboption"
	"singctl/internal/smartdns"
)

func TestSwitchEngine_AutoToSmartDNS_ZeroDisconnectAndMigration(t *testing.T) {
	ctx := t.Context()
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "singctl.yaml")
	sbCfgPath := filepath.Join(tmpDir, "config.json")
	smartBin := filepath.Join(tmpDir, "smartdns")
	smartConf := filepath.Join(tmpDir, "smartdns.conf")
	smartRules := filepath.Join(tmpDir, "smartdns-rules.d")

	if err := os.WriteFile(sbCfgPath, []byte(sampleSingBoxConfigJSON()), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(smartBin, []byte("#!/bin/sh\necho 'smartdns 1.2025.46'\n"), 0755); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{
		Subs:    []config.Subscription{{Name: "Main", URL: "https://sub.example.com/s"}},
		Gateway: config.GatewayConfig{IPv6Mode: config.GatewayIPv6Off},
		DNS: config.ClientDNSConfig{
			Engine:    constant.DNSEngineAuto,
			DNSPort:   5353,
			Upstreams: []string{"https://223.5.5.5/dns-query", "https://1.12.12.12/dns-query"},
			Whitelist: []string{"trusted.example.com"},
			Rewrites:  []config.DNSRewriteRule{{Domain: "nas.example.com", Answer: "192.0.2.10"}},
		},
		CustomRules: config.CustomRulesConfig{
			Block: []config.BlockRule{{Target: "tracker.example.com"}},
		},
	}
	if err := config.Save(cfgPath, cfg); err != nil {
		t.Fatal(err)
	}

	mockSvc := servicemgr.NewMock()
	sdMgr := smartdns.NewManager(smartdns.ManagerOptions{
		BinaryPath:   smartBin,
		ConfigFile:   smartConf,
		RulesDir:     smartRules,
		AuditLogPath: filepath.Join(tmpDir, "audit.log"),
		LogFilePath:  filepath.Join(tmpDir, "smartdns.log"),
		PIDFilePath:  filepath.Join(tmpDir, "smartdns.pid"),
		ServiceName:  constant.SmartDNSServiceName,
		GOOS:         "linux",
		GOARCH:       "arm64",
		ServiceMgr:   mockSvc,
		ProbeDNSFunc: func(string, time.Duration) error { return nil },
	})

	var steps []string
	reg := localdns.NewRegistry(cfg, localdns.EngineDeps{
		ConfigPath:         cfgPath,
		SingBoxConfigPath:  sbCfgPath,
		AdGuardBinPath:     filepath.Join(tmpDir, "missing-agh"),
		SmartDNSBinPath:    smartBin,
		SmartDNSConfigFile: smartConf,
		SmartDNSRulesDir:   smartRules,
		ServiceMgr:         mockSvc,
		SmartDNSManager:    sdMgr,
		ReadMemInfo: func() (sysinfo.MemInfo, error) {
			return sysinfo.MemInfo{TotalBytes: 480 * 1024 * 1024, AvailableBytes: 205 * 1024 * 1024}, nil
		},
		ReadDiskSpace: func(string) (sysinfo.DiskSpace, error) {
			return sysinfo.DiskSpace{AvailBytes: 50 * 1024 * 1024}, nil
		},
		ProbeDNSFunc: func(string, time.Duration) error { return nil },
		ProbeResolutionFunc: func(addr, domain string, _ time.Duration) ([]string, time.Duration, error) {
			steps = append(steps, "probe:"+domain+"@"+addr)
			return []string{"192.0.2.1"}, 8 * time.Millisecond, nil
		},
		SyncSingBoxDNSLocalFunc: func(_ context.Context, p, _ string, useExternal bool, port int) (bool, error) {
			if useExternal {
				steps = append(steps, "link_external")
			} else {
				steps = append(steps, "safe_doh_bridge")
			}
			raw, _ := os.ReadFile(p)
			out, changed, err := singbox.PatchDNSLocalJSON(string(raw), useExternal, port)
			if err == nil && changed {
				_ = os.WriteFile(p, []byte(out), 0600)
			}
			return changed, err
		},
	})

	res, err := reg.SwitchEngine(ctx, localdns.SwitchRequest{TargetEngine: constant.DNSEngineSmartDNS})
	if err != nil {
		t.Fatalf("SwitchEngine to smartdns failed: %v", err)
	}
	if !res.OK || !res.Switched || res.ActiveEngine != constant.DNSEngineSmartDNS || res.ConfiguredEngine != constant.DNSEngineSmartDNS {
		t.Fatalf("unexpected SwitchResult: %+v", res)
	}
	if len(res.MigratedItems) == 0 {
		t.Fatal("expected migrated items reported")
	}

	// Verify sing-box dns_local now points to 127.0.0.1:5353 with optimistic=false & disable_cache=true
	linked, port := singbox.InspectSingBoxDNSLocal(sbCfgPath)
	if !linked || port != 5353 {
		t.Fatalf("expected sing-box linked to 127.0.0.1:5353, got linked=%v port=%d", linked, port)
	}
	sbRaw, _ := os.ReadFile(sbCfgPath)
	doc, _ := sboption.ParseDocument(sbRaw)
	if doc.DNS.Optimistic == nil || *doc.DNS.Optimistic || doc.DNS.DisableCache == nil || !*doc.DNS.DisableCache {
		t.Fatalf("expected optimistic=false disable_cache=true after switch, got opt=%v dc=%v", doc.DNS.Optimistic, doc.DNS.DisableCache)
	}

	// Verify SmartDNS rules & config migrated with 0600 permissions
	confBytes, err := os.ReadFile(smartConf)
	if err != nil || !strings.Contains(string(confBytes), "force-AAAA-SOA yes") {
		t.Fatalf("expected smartdns.conf migrated with BlockAAAA, err=%v", err)
	}
	rwBytes, err := os.ReadFile(filepath.Join(smartRules, "rewrites.conf"))
	if err != nil || !strings.Contains(string(rwBytes), "nas.example.com/192.0.2.10") {
		t.Fatalf("expected rewrites migrated to smartdns, err=%v content=%s", err, string(rwBytes))
	}

	// Verify persisted singctl.yaml has engine: smartdns and mode 0600
	loaded, err := config.Load(cfgPath)
	if err != nil || loaded.DNS.GetEngine() != constant.DNSEngineSmartDNS {
		t.Fatalf("expected persisted engine=smartdns, err=%v got=%q", err, loaded.DNS.GetEngine())
	}
	fi, _ := os.Stat(cfgPath)
	if fi.Mode().Perm() != 0600 {
		t.Fatalf("expected singctl.yaml mode 0600, got %o", fi.Mode().Perm())
	}

	// Verify ordering: probe happened BEFORE link_external
	probeIdx := -1
	linkIdx := -1
	for i, s := range steps {
		if strings.HasPrefix(s, "probe:qq.com") {
			probeIdx = i
		}
		if s == "link_external" {
			linkIdx = i
		}
	}
	if probeIdx < 0 || linkIdx < 0 || probeIdx > linkIdx {
		t.Fatalf("expected qq.com probe before linking sing-box, steps=%v", steps)
	}
}

func TestSwitchEngine_HardwareGuardsRejectionAndRollbackOnProbeFailure(t *testing.T) {
	ctx := t.Context()
	const mib = 1024 * 1024

	t.Run("disk_blocked_never_bypassed_even_with_force_low_memory", func(t *testing.T) {
		tmpDir := t.TempDir()
		cfg := &config.Config{}
		reg := localdns.NewRegistry(cfg, localdns.EngineDeps{
			ConfigPath:      filepath.Join(tmpDir, "singctl.yaml"),
			AdGuardBinPath:  filepath.Join(tmpDir, "missing-agh"),
			SmartDNSBinPath: filepath.Join(tmpDir, "missing-smartdns"),
			ReadMemInfo: func() (sysinfo.MemInfo, error) {
				return sysinfo.MemInfo{TotalBytes: 2048 * mib, AvailableBytes: 1500 * mib}, nil
			},
			ReadDiskSpace: func(string) (sysinfo.DiskSpace, error) {
				return sysinfo.DiskSpace{AvailBytes: 5 * mib}, nil
			},
		})
		if _, err := reg.SwitchEngine(ctx, localdns.SwitchRequest{
			TargetEngine:   constant.DNSEngineSmartDNS,
			ForceLowMemory: true,
		}); err == nil {
			t.Fatal("expected disk-insufficient switch to be blocked even with ForceLowMemory=true")
		}
	})

	t.Run("probe_failure_rolls_back_config_and_keeps_doh_fallback_with_optimistic_false", func(t *testing.T) {
		tmpDir := t.TempDir()
		cfgPath := filepath.Join(tmpDir, "singctl.yaml")
		sbCfgPath := filepath.Join(tmpDir, "config.json")
		smartBin := filepath.Join(tmpDir, "smartdns")
		smartConf := filepath.Join(tmpDir, "smartdns.conf")
		smartRules := filepath.Join(tmpDir, "smartdns-rules.d")

		sbWithLocal, _, _ := singbox.PatchDNSLocalJSON(sampleSingBoxConfigJSON(), true, 5353)
		if err := os.WriteFile(sbCfgPath, []byte(sbWithLocal), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(smartBin, []byte("#!/bin/sh\necho 'smartdns 1.2025.46'\n"), 0755); err != nil {
			t.Fatal(err)
		}

		cfg := &config.Config{
			DNS: config.ClientDNSConfig{
				Engine:  constant.DNSEngineAuto,
				DNSPort: 5353,
			},
		}
		if err := config.Save(cfgPath, cfg); err != nil {
			t.Fatal(err)
		}

		mockSvc := servicemgr.NewMock()
		sdMgr := smartdns.NewManager(smartdns.ManagerOptions{
			BinaryPath:   smartBin,
			ConfigFile:   smartConf,
			RulesDir:     smartRules,
			ServiceName:  constant.SmartDNSServiceName,
			GOOS:         "linux",
			GOARCH:       "arm64",
			ServiceMgr:   mockSvc,
			ProbeDNSFunc: func(string, time.Duration) error { return nil },
		})

		var linkedCalls atomic.Int32
		reg := localdns.NewRegistry(cfg, localdns.EngineDeps{
			ConfigPath:         cfgPath,
			SingBoxConfigPath:  sbCfgPath,
			AdGuardBinPath:     filepath.Join(tmpDir, "missing-agh"),
			SmartDNSBinPath:    smartBin,
			SmartDNSConfigFile: smartConf,
			SmartDNSRulesDir:   smartRules,
			ServiceMgr:         mockSvc,
			SmartDNSManager:    sdMgr,
			ReadMemInfo: func() (sysinfo.MemInfo, error) {
				return sysinfo.MemInfo{TotalBytes: 480 * mib, AvailableBytes: 205 * mib}, nil
			},
			ReadDiskSpace: func(string) (sysinfo.DiskSpace, error) {
				return sysinfo.DiskSpace{AvailBytes: 50 * mib}, nil
			},
			ProbeDNSFunc: func(string, time.Duration) error { return nil },
			ProbeResolutionFunc: func(string, string, time.Duration) ([]string, time.Duration, error) {
				return nil, 0, errors.New("dns resolution timeout")
			},
			SyncSingBoxDNSLocalFunc: func(_ context.Context, p, _ string, useExternal bool, port int) (bool, error) {
				if useExternal {
					linkedCalls.Add(1)
				}
				raw, _ := os.ReadFile(p)
				out, changed, err := singbox.PatchDNSLocalJSON(string(raw), useExternal, port)
				if err == nil && changed {
					_ = os.WriteFile(p, []byte(out), 0600)
				}
				return changed, err
			},
		})

		if _, err := reg.SwitchEngine(ctx, localdns.SwitchRequest{TargetEngine: constant.DNSEngineSmartDNS}); err == nil {
			t.Fatal("expected SwitchEngine to fail when qq.com probe fails")
		}
		if linkedCalls.Load() != 0 {
			t.Fatal("sing-box must NEVER be switched to unhealthy external engine")
		}
		if mockSvc.IsActive(ctx, constant.SmartDNSServiceName) {
			t.Fatal("rollback must stop failed SmartDNS service")
		}
		loaded, _ := config.Load(cfgPath)
		if loaded.DNS.GetEngine() != constant.DNSEngineAuto {
			t.Fatalf("expected rolled-back engine=auto, got %q", loaded.DNS.GetEngine())
		}
		sbAfter, _ := os.ReadFile(sbCfgPath)
		docAfter, _ := sboption.ParseDocument(sbAfter)
		if docAfter.DNS.Optimistic == nil || *docAfter.DNS.Optimistic || docAfter.DNS.DisableCache == nil || !*docAfter.DNS.DisableCache {
			t.Fatalf("rollback safe DoH bridge must enforce optimistic=false & disable_cache=true, got opt=%v dc=%v",
				docAfter.DNS.Optimistic, docAfter.DNS.DisableCache)
		}
	})

	t.Run("singbox_and_malicious_target_engine_rejected", func(t *testing.T) {
		reg := localdns.NewRegistry(&config.Config{}, localdns.EngineDeps{})
		for _, bad := range []string{"singbox", "SINGBOX", "unbound;rm -rf /"} {
			if _, err := reg.SwitchEngine(ctx, localdns.SwitchRequest{TargetEngine: bad}); err == nil {
				t.Fatalf("expected target engine %q to be rejected", bad)
			}
		}
	})
}

func TestSwitchEngine_AutoFallbackWhenPort5353OccupiedByMDNS(t *testing.T) {
	ctx := t.Context()
	const mib = 1024 * 1024

	t.Run("auto_shifts_to_5354_when_5353_in_use", func(t *testing.T) {
		tmpDir := t.TempDir()
		cfgPath := filepath.Join(tmpDir, "singctl.yaml")
		sbCfgPath := filepath.Join(tmpDir, "config.json")
		smartBin := filepath.Join(tmpDir, "smartdns")
		smartConf := filepath.Join(tmpDir, "smartdns.conf")
		smartRules := filepath.Join(tmpDir, "smartdns-rules.d")

		if err := os.WriteFile(sbCfgPath, []byte(sampleSingBoxConfigJSON()), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(smartBin, []byte("#!/bin/sh\necho 'smartdns Release48.5'\n"), 0755); err != nil {
			t.Fatal(err)
		}

		cfg := &config.Config{
			DNS: config.ClientDNSConfig{
				Engine:  constant.DNSEngineAuto,
				DNSPort: 5353,
			},
		}
		if err := config.Save(cfgPath, cfg); err != nil {
			t.Fatal(err)
		}

		mockSvc := servicemgr.NewMock()
		sdMgr := smartdns.NewManager(smartdns.ManagerOptions{
			BinaryPath:   smartBin,
			ConfigFile:   smartConf,
			RulesDir:     smartRules,
			AuditLogPath: filepath.Join(tmpDir, "audit.log"),
			LogFilePath:  filepath.Join(tmpDir, "smartdns.log"),
			PIDFilePath:  filepath.Join(tmpDir, "smartdns.pid"),
			ServiceName:  constant.SmartDNSServiceName,
			GOOS:         "linux",
			GOARCH:       "arm64",
			ServiceMgr:   mockSvc,
			ProbeDNSFunc: func(string, time.Duration) error { return nil },
		})

		var probedAddr string
		reg := localdns.NewRegistry(cfg, localdns.EngineDeps{
			ConfigPath:         cfgPath,
			SingBoxConfigPath:  sbCfgPath,
			AdGuardBinPath:     filepath.Join(tmpDir, "missing-agh"),
			SmartDNSBinPath:    smartBin,
			SmartDNSConfigFile: smartConf,
			SmartDNSRulesDir:   smartRules,
			ServiceMgr:         mockSvc,
			SmartDNSManager:    sdMgr,
			ReadMemInfo: func() (sysinfo.MemInfo, error) {
				return sysinfo.MemInfo{TotalBytes: 480 * mib, AvailableBytes: 205 * mib}, nil
			},
			ReadDiskSpace: func(string) (sysinfo.DiskSpace, error) {
				return sysinfo.DiskSpace{AvailBytes: 20 * mib}, nil
			},
			CheckPortAvailableFunc: func(port int) bool {
				return port != 5353 // simulate avahi-daemon mDNS occupying UDP 5353
			},
			ProbeDNSFunc: func(addr string, _ time.Duration) error {
				probedAddr = addr
				return nil
			},
			ProbeResolutionFunc: func(addr, _ string, _ time.Duration) ([]string, time.Duration, error) {
				probedAddr = addr
				return []string{"192.0.2.1"}, 5 * time.Millisecond, nil
			},
			SyncSingBoxDNSLocalFunc: func(_ context.Context, p, _ string, useExternal bool, port int) (bool, error) {
				raw, _ := os.ReadFile(p)
				out, changed, err := singbox.PatchDNSLocalJSON(string(raw), useExternal, port)
				if err == nil && changed {
					_ = os.WriteFile(p, []byte(out), 0600)
				}
				return changed, err
			},
		})

		res, err := reg.SwitchEngine(ctx, localdns.SwitchRequest{TargetEngine: constant.DNSEngineSmartDNS})
		if err != nil {
			t.Fatalf("SwitchEngine failed when 5353 occupied: %v", err)
		}
		if probedAddr != "127.0.0.1:5354" {
			t.Fatalf("expected SmartDNS probed on fallback port 127.0.0.1:5354, got %q", probedAddr)
		}
		confBytes, err := os.ReadFile(smartConf)
		if err != nil || !strings.Contains(string(confBytes), "bind 127.0.0.1:5354") {
			t.Fatalf("expected smartdns.conf bound to 127.0.0.1:5354, err=%v content=%s", err, string(confBytes))
		}
		linked, linkedPort := singbox.InspectSingBoxDNSLocal(sbCfgPath)
		if !linked || linkedPort != 5354 {
			t.Fatalf("expected sing-box dns_local linked to 5354, got linked=%v port=%d", linked, linkedPort)
		}
		loaded, err := config.Load(cfgPath)
		if err != nil || loaded.DNS.GetDNSPort() != 5354 {
			t.Fatalf("expected persisted dns_port=5354, err=%v got=%d", err, loaded.DNS.GetDNSPort())
		}
		if len(res.Warnings) == 0 || !strings.Contains(strings.Join(res.Warnings, ";"), "5354") {
			t.Fatalf("expected warning mentioning auto port fallback 5354, got %v", res.Warnings)
		}
	})

	t.Run("rollback_restores_original_dns_port_on_probe_failure", func(t *testing.T) {
		tmpDir := t.TempDir()
		cfgPath := filepath.Join(tmpDir, "singctl.yaml")
		sbCfgPath := filepath.Join(tmpDir, "config.json")
		smartBin := filepath.Join(tmpDir, "smartdns")
		smartConf := filepath.Join(tmpDir, "smartdns.conf")
		smartRules := filepath.Join(tmpDir, "smartdns-rules.d")

		_ = os.WriteFile(sbCfgPath, []byte(sampleSingBoxConfigJSON()), 0600)
		_ = os.WriteFile(smartBin, []byte("#!/bin/sh\necho 'smartdns Release48.5'\n"), 0755)
		cfg := &config.Config{DNS: config.ClientDNSConfig{Engine: constant.DNSEngineAuto, DNSPort: 5353}}
		_ = config.Save(cfgPath, cfg)

		mockSvc := servicemgr.NewMock()
		sdMgr := smartdns.NewManager(smartdns.ManagerOptions{
			BinaryPath:   smartBin,
			ConfigFile:   smartConf,
			RulesDir:     smartRules,
			ServiceName:  constant.SmartDNSServiceName,
			GOOS:         "linux",
			GOARCH:       "arm64",
			ServiceMgr:   mockSvc,
			ProbeDNSFunc: func(string, time.Duration) error { return nil },
		})

		reg := localdns.NewRegistry(cfg, localdns.EngineDeps{
			ConfigPath:             cfgPath,
			SingBoxConfigPath:      sbCfgPath,
			AdGuardBinPath:         filepath.Join(tmpDir, "missing-agh"),
			SmartDNSBinPath:        smartBin,
			SmartDNSConfigFile:     smartConf,
			SmartDNSRulesDir:       smartRules,
			ServiceMgr:             mockSvc,
			SmartDNSManager:        sdMgr,
			CheckPortAvailableFunc: func(port int) bool { return port != 5353 },
			ProbeDNSFunc:           func(string, time.Duration) error { return nil },
			ProbeResolutionFunc: func(string, string, time.Duration) ([]string, time.Duration, error) {
				return nil, 0, errors.New("probe failed")
			},
			SyncSingBoxDNSLocalFunc: func(context.Context, string, string, bool, int) (bool, error) {
				return true, nil
			},
		})

		if _, err := reg.SwitchEngine(ctx, localdns.SwitchRequest{TargetEngine: constant.DNSEngineSmartDNS}); err == nil {
			t.Fatal("expected SwitchEngine failure")
		}
		loaded, _ := config.Load(cfgPath)
		if loaded.DNS.GetDNSPort() != 5353 {
			t.Fatalf("expected rollback to restore original dns_port=5353, got %d", loaded.DNS.GetDNSPort())
		}
	})

	t.Run("waits_for_stopped_engine_to_release_port_before_shifting", func(t *testing.T) {
		tmpDir := t.TempDir()
		cfgPath := filepath.Join(tmpDir, "singctl.yaml")
		sbCfgPath := filepath.Join(tmpDir, "config.json")
		smartBin := filepath.Join(tmpDir, "smartdns")
		smartConf := filepath.Join(tmpDir, "smartdns.conf")
		smartRules := filepath.Join(tmpDir, "smartdns-rules.d")
		aghBin := filepath.Join(tmpDir, "AdGuardHome")
		aghConf := filepath.Join(tmpDir, "AdGuardHome.yaml")

		_ = os.WriteFile(sbCfgPath, []byte(sampleSingBoxConfigJSON()), 0600)
		_ = os.WriteFile(smartBin, []byte("#!/bin/sh\necho 'smartdns Release48.5'\n"), 0755)
		_ = os.WriteFile(aghBin, []byte("#!/bin/sh\necho 'AdGuard Home, version v0.107.74'\n"), 0755)
		_ = os.WriteFile(aghConf, []byte("http:\n  address: 127.0.0.1:3000\ndns:\n  bind_hosts:\n    - 127.0.0.1\n  port: 5353\n"), 0600)

		cfg := &config.Config{
			DNS: config.ClientDNSConfig{
				Engine:    constant.DNSEngineAdGuard,
				DNSPort:   5353,
				Upstreams: []string{"https://223.5.5.5/dns-query"},
			},
		}
		_ = config.Save(cfgPath, cfg)

		mockSvc := servicemgr.NewMock()
		_ = mockSvc.Start(ctx, "AdGuardHome")
		sdMgr := smartdns.NewManager(smartdns.ManagerOptions{
			BinaryPath:   smartBin,
			ConfigFile:   smartConf,
			RulesDir:     smartRules,
			ServiceName:  constant.SmartDNSServiceName,
			GOOS:         "linux",
			GOARCH:       "amd64",
			ServiceMgr:   mockSvc,
			ProbeDNSFunc: func(string, time.Duration) error { return nil },
		})

		var probes atomic.Int32
		var probedAddr string
		reg := localdns.NewRegistry(cfg, localdns.EngineDeps{
			ConfigPath:              cfgPath,
			SingBoxConfigPath:       sbCfgPath,
			AdGuardBinPath:          aghBin,
			AdGuardConfigPath:       aghConf,
			SmartDNSBinPath:         smartBin,
			SmartDNSConfigFile:      smartConf,
			SmartDNSRulesDir:        smartRules,
			ServiceMgr:              mockSvc,
			SmartDNSManager:         sdMgr,
			PortReleasePollInterval: time.Millisecond,
			ReadMemInfo: func() (sysinfo.MemInfo, error) {
				return sysinfo.MemInfo{TotalBytes: 2048 * mib, AvailableBytes: 1200 * mib}, nil
			},
			ReadDiskSpace: func(string) (sysinfo.DiskSpace, error) {
				return sysinfo.DiskSpace{AvailBytes: 1024 * mib}, nil
			},
			CheckPortAvailableFunc: func(port int) bool {
				if port == 5353 {
					// Simulate procd asynchronous stop releasing UDP 5353 on the 4th probe
					return probes.Add(1) >= 4
				}
				return true
			},
			ProbeDNSFunc: func(addr string, _ time.Duration) error {
				probedAddr = addr
				return nil
			},
			ProbeResolutionFunc: func(addr, _ string, _ time.Duration) ([]string, time.Duration, error) {
				probedAddr = addr
				return []string{"192.0.2.1"}, 2 * time.Millisecond, nil
			},
			SyncSingBoxDNSLocalFunc: func(_ context.Context, p, _ string, useExternal bool, port int) (bool, error) {
				raw, _ := os.ReadFile(p)
				out, changed, err := singbox.PatchDNSLocalJSON(string(raw), useExternal, port)
				if err == nil && changed {
					_ = os.WriteFile(p, []byte(out), 0600)
				}
				return changed, err
			},
		})

		res, err := reg.SwitchEngine(ctx, localdns.SwitchRequest{TargetEngine: constant.DNSEngineSmartDNS})
		if err != nil {
			t.Fatalf("SwitchEngine failed: %v", err)
		}
		if probedAddr != "127.0.0.1:5353" {
			t.Fatalf("expected SmartDNS to stay on 127.0.0.1:5353 after grace wait, got %q (warnings=%v)", probedAddr, res.Warnings)
		}
		if loaded, _ := config.Load(cfgPath); loaded.DNS.GetDNSPort() != 5353 {
			t.Fatalf("expected persisted dns_port=5353, got %d", loaded.DNS.GetDNSPort())
		}
		for _, w := range res.Warnings {
			if strings.Contains(w, "5354") {
				t.Fatalf("unexpected spurious port shift warning: %v", res.Warnings)
			}
		}
	})
}
