// 文件职责：验证三引擎零断网两阶段原子切换、公共配置迁移、硬件门槛阻断与失败自动回滚契约。
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
	"singctl/internal/smartdns"
)

func TestSwitchEngine_SingBoxToSmartDNS_ZeroDisconnectAndMigration(t *testing.T) {
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
		Subs: []config.Subscription{{Name: "Main", URL: "https://sub.example.com/s"}},
		DNS: config.ClientDNSConfig{
			Engine:    constant.DNSEngineSingBox,
			DNSPort:   5353,
			Upstreams: []string{"https://223.5.5.5/dns-query", "https://1.12.12.12/dns-query"},
			Whitelist: []string{"trusted.example.com"},
			Rewrites:  []config.DNSRewriteRule{{Domain: "nas.example.com", Answer: "192.0.2.10"}},
			BlockAAAA: true,
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
		SyncSingBoxEnhancedFunc: func(_ context.Context, p, _ string, dnsCfg config.ClientDNSConfig, subs []string, now time.Time) (bool, error) {
			steps = append(steps, "sync_enhanced")
			raw, _ := os.ReadFile(p)
			out, changed, err := singbox.ApplyEnhancedSingBoxDNSJSON(string(raw), dnsCfg, subs, now)
			if err == nil && changed {
				_ = os.WriteFile(p, []byte(out), 0600)
			}
			return changed, err
		},
		SyncSingBoxDNSLocalFunc: func(_ context.Context, p, _ string, useExternal bool, port int) (bool, error) {
			if useExternal {
				steps = append(steps, "link_external")
			} else {
				steps = append(steps, "unlink_external")
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

	// Verify sing-box dns_local now points to 127.0.0.1:5353
	linked, port := singbox.InspectSingBoxDNSLocal(sbCfgPath)
	if !linked || port != 5353 {
		t.Fatalf("expected sing-box linked to 127.0.0.1:5353, got linked=%v port=%d", linked, port)
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

func TestSwitchEngine_HardwareGuardsAndRollbackOnProbeFailure(t *testing.T) {
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

	t.Run("probe_failure_rolls_back_config_and_keeps_singbox_safe_zone", func(t *testing.T) {
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
			DNS: config.ClientDNSConfig{
				Engine:  constant.DNSEngineSingBox,
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
			SyncSingBoxEnhancedFunc: func(context.Context, string, string, config.ClientDNSConfig, []string, time.Time) (bool, error) {
				return true, nil
			},
			SyncSingBoxDNSLocalFunc: func(_ context.Context, _ string, _ string, useExternal bool, _ int) (bool, error) {
				if useExternal {
					linkedCalls.Add(1)
				}
				return true, nil
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
		if loaded.DNS.GetEngine() != constant.DNSEngineSingBox {
			t.Fatalf("expected rolled-back engine=singbox, got %q", loaded.DNS.GetEngine())
		}
	})

	t.Run("switch_smartdns_to_singbox_preserves_smartdns_conf", func(t *testing.T) {
		tmpDir := t.TempDir()
		cfgPath := filepath.Join(tmpDir, "singctl.yaml")
		sbCfgPath := filepath.Join(tmpDir, "config.json")
		smartBin := filepath.Join(tmpDir, "smartdns")
		smartConf := filepath.Join(tmpDir, "smartdns.conf")

		sbWithLocal, _, _ := singbox.PatchDNSLocalJSON(sampleSingBoxConfigJSON(), true, 5353)
		if err := os.WriteFile(sbCfgPath, []byte(sbWithLocal), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(smartBin, []byte("#!/bin/sh\necho 'smartdns 1.2025.46'\n"), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(smartConf, []byte("bind 127.0.0.1:5353\n"), 0600); err != nil {
			t.Fatal(err)
		}

		mockSvc := servicemgr.NewMock()
		_ = mockSvc.Start(ctx, constant.SmartDNSServiceName)
		sdMgr := smartdns.NewManager(smartdns.ManagerOptions{
			BinaryPath:  smartBin,
			ConfigFile:  smartConf,
			RulesDir:    filepath.Join(tmpDir, "rules"),
			ServiceName: constant.SmartDNSServiceName,
			GOOS:        "linux",
			GOARCH:      "arm64",
			ServiceMgr:  mockSvc,
		})

		cfg := &config.Config{
			DNS: config.ClientDNSConfig{
				Engine:  constant.DNSEngineSmartDNS,
				DNSPort: 5353,
			},
		}
		_ = config.Save(cfgPath, cfg)

		reg := localdns.NewRegistry(cfg, localdns.EngineDeps{
			ConfigPath:         cfgPath,
			SingBoxConfigPath:  sbCfgPath,
			AdGuardBinPath:     filepath.Join(tmpDir, "missing-agh"),
			SmartDNSBinPath:    smartBin,
			SmartDNSConfigFile: smartConf,
			ServiceMgr:         mockSvc,
			SmartDNSManager:    sdMgr,
			SyncSingBoxEnhancedFunc: func(_ context.Context, p, _ string, dnsCfg config.ClientDNSConfig, subs []string, now time.Time) (bool, error) {
				raw, _ := os.ReadFile(p)
				out, changed, err := singbox.ApplyEnhancedSingBoxDNSJSON(string(raw), dnsCfg, subs, now)
				if err == nil && changed {
					_ = os.WriteFile(p, []byte(out), 0600)
				}
				return changed, err
			},
		})

		res, err := reg.SwitchEngine(ctx, localdns.SwitchRequest{TargetEngine: constant.DNSEngineSingBox})
		if err != nil || !res.OK || res.ActiveEngine != constant.DNSEngineSingBox {
			t.Fatalf("switch to singbox failed: err=%v res=%+v", err, res)
		}
		if mockSvc.IsActive(ctx, constant.SmartDNSServiceName) {
			t.Fatal("expected smartdns service stopped when switching to singbox")
		}
		if _, err := os.Stat(smartConf); err != nil {
			t.Fatalf("smartdns.conf must be preserved on switch, got err=%v", err)
		}
		linked, _ := singbox.InspectSingBoxDNSLocal(sbCfgPath)
		if linked {
			t.Fatal("expected sing-box dns_local unlinked from 127.0.0.1 and upgraded to encrypted DoH")
		}
	})

	t.Run("invalid_target_engine_rejected", func(t *testing.T) {
		reg := localdns.NewRegistry(&config.Config{}, localdns.EngineDeps{})
		if _, err := reg.SwitchEngine(ctx, localdns.SwitchRequest{TargetEngine: "unbound;rm -rf /"}); err == nil {
			t.Fatal("expected invalid engine name rejected")
		}
	})
}
