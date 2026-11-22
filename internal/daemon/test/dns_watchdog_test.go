// 文件职责：验证看门狗三引擎本地 DNS 统一守护（外部容灾/恢复、singbox 主上游热切、暂停到期自动恢复与 SmartDNS 审计日志采集）。
package daemon_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"singctl/internal/adguard"
	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/daemon"
	"singctl/internal/localdns"
	"singctl/internal/platform/servicemgr"
	"singctl/internal/singbox"
	"singctl/internal/smartdns"
)

func baseSBJSONForDaemon() string {
	return `{
  "dns": {
    "servers": [
      {"tag": "dns_local", "type": "https", "server": "223.5.5.5", "server_port": 443, "path": "/dns-query"}
    ],
    "rules": [
      {"rule_set": ["geosite-ad1"], "action": "reject"}
    ]
  },
  "route": {
    "rule_set": [
      {"tag": "geosite-ad1", "type": "remote", "format": "binary", "url": "https://example.com/ad1.srs"}
    ],
    "rules": [
      {"rule_set": ["geosite-ad1"], "action": "reject"}
    ]
  }
}`
}

func TestDaemon_GuardLocalDNS_SingBoxFailoverAndPauseExpiry(t *testing.T) {
	ctx := t.Context()
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "singctl.yaml")
	sbPath := filepath.Join(tmpDir, "config.json")
	if err := os.WriteFile(sbPath, []byte(baseSBJSONForDaemon()), 0600); err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 11, 22, 20, 0, 0, 0, time.UTC)
	cfg := &config.Config{
		DNS: config.ClientDNSConfig{
			Engine:               constant.DNSEngineSingBox,
			Upstreams:            []string{"https://223.5.5.5/dns-query", "https://1.12.12.12/dns-query"},
			AdblockDisabledUntil: now.Add(-1 * time.Minute).Unix(), // already expired!
		},
	}
	if err := config.Save(cfgPath, cfg); err != nil {
		t.Fatal(err)
	}

	var syncCount atomic.Int32
	deps := localdns.EngineDeps{
		ConfigPath:        cfgPath,
		SingBoxConfigPath: sbPath,
		AdGuardBinPath:    filepath.Join(tmpDir, "missing-agh"),
		SmartDNSBinPath:   filepath.Join(tmpDir, "missing-sd"),
		NowFunc:           func() time.Time { return now },
		ProbeUpstreamListFunc: func(_ context.Context, upstreams []string, _ string, _ time.Duration) []adguard.UpstreamProbeItem {
			out := make([]adguard.UpstreamProbeItem, len(upstreams))
			for i, u := range upstreams {
				if u == "https://223.5.5.5/dns-query" {
					out[i] = adguard.UpstreamProbeItem{Address: u, Healthy: false, Error: "timeout"}
				} else {
					out[i] = adguard.UpstreamProbeItem{Address: u, Healthy: true, LatencyMs: 11, Resolved: "192.0.2.1"}
				}
			}
			return out
		},
		SyncSingBoxEnhancedFunc: func(_ context.Context, p, _ string, dnsCfg config.ClientDNSConfig, subs []string, ts time.Time) (bool, error) {
			syncCount.Add(1)
			raw, _ := os.ReadFile(p)
			out, changed, err := singbox.ApplyEnhancedSingBoxDNSJSON(string(raw), dnsCfg, subs, ts)
			if err == nil && changed {
				_ = os.WriteFile(p, []byte(out), 0600)
			}
			return changed, err
		},
	}

	d := daemon.NewDaemonWithOptions(cfg, daemon.DaemonOptions{
		ConfigPath:      cfgPath,
		SkipSignalSetup: true,
		DNSDeps:         &deps,
		Paths: daemon.Paths{
			PidFile:         filepath.Join(tmpDir, "dm.pid"),
			LogFile:         filepath.Join(tmpDir, "dm.log"),
			StateFile:       filepath.Join(tmpDir, "dm.state"),
			WebEmbeddedFile: filepath.Join(tmpDir, "web.emb"),
		},
	})

	// Round 1: expiry resumes adblock immediately; primary failure count = 1 (not yet failed over)
	d.GuardLocalDNSOnce(ctx)
	loaded1, _ := config.Load(cfgPath)
	if loaded1.DNS.AdblockDisabledUntil != 0 {
		t.Fatalf("expected expired AdblockDisabledUntil cleared to 0, got %d", loaded1.DNS.AdblockDisabledUntil)
	}
	if loaded1.DNS.Upstreams[0] != "https://223.5.5.5/dns-query" {
		t.Fatalf("expected primary NOT switched on single failure, got %v", loaded1.DNS.Upstreams)
	}

	// Round 2: consecutive failure #2 -> auto hot-switch primary to healthy fastest backup (1.12.12.12)!
	d.GuardLocalDNSOnce(ctx)
	loaded2, _ := config.Load(cfgPath)
	if loaded2.DNS.Upstreams[0] != "https://1.12.12.12/dns-query" {
		t.Fatalf("expected primary promoted to fastest healthy backup after 2 consecutive failures, got %v", loaded2.DNS.Upstreams)
	}
	if syncCount.Load() < 2 {
		t.Fatalf("expected live sing-box enhanced sync calls >= 2, got %d", syncCount.Load())
	}
}

type failRestartMockSvc struct {
	*servicemgr.MockManager
	failRestart atomic.Bool
}

func (f *failRestartMockSvc) Restart(ctx context.Context, name string) error {
	if f.failRestart.Load() {
		return errors.New("restart failed")
	}
	return f.MockManager.Restart(ctx, name)
}

func TestDaemon_GuardLocalDNS_SmartDNSFailoverFailbackAndAuditTail(t *testing.T) {
	ctx := t.Context()
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "singctl.yaml")
	sbPath := filepath.Join(tmpDir, "config.json")
	smartBin := filepath.Join(tmpDir, "smartdns")
	smartConf := filepath.Join(tmpDir, "smartdns.conf")
	smartRules := filepath.Join(tmpDir, "rules")
	auditLog := filepath.Join(tmpDir, "smartdns-audit.log")

	sbLinked, _, _ := singbox.PatchDNSLocalJSON(baseSBJSONForDaemon(), true, 5353)
	_ = os.WriteFile(sbPath, []byte(sbLinked), 0600)
	_ = os.WriteFile(smartBin, []byte("#!/bin/sh\necho smartdns\n"), 0755)

	now := time.Now().Truncate(time.Second)
	_ = os.WriteFile(auditLog, []byte("["+now.Format("2006-01-02 15:04:05.000")+"] 127.0.0.1 query qq.com, type 1, time 8ms, result 192.0.2.5\n"), 0600)

	cfg := &config.Config{
		DNS: config.ClientDNSConfig{
			Engine:  constant.DNSEngineSmartDNS,
			DNSPort: 5353,
		},
	}
	_ = config.Save(cfgPath, cfg)

	var smartHealthy atomic.Bool
	smartHealthy.Store(false)
	mockSvc := &failRestartMockSvc{MockManager: servicemgr.NewMock()}
	mockSvc.failRestart.Store(true)
	sdMgr := smartdns.NewManager(smartdns.ManagerOptions{
		BinaryPath:   smartBin,
		ConfigFile:   smartConf,
		RulesDir:     smartRules,
		AuditLogPath: auditLog,
		ServiceName:  constant.SmartDNSServiceName,
		GOOS:         "linux",
		GOARCH:       "arm64",
		ServiceMgr:   mockSvc,
		ProbeDNSFunc: func(string, time.Duration) error {
			if smartHealthy.Load() {
				return nil
			}
			return errors.New("connection refused")
		},
	})

	deps := localdns.EngineDeps{
		ConfigPath:           cfgPath,
		SingBoxConfigPath:    sbPath,
		AdGuardBinPath:       filepath.Join(tmpDir, "missing-agh"),
		SmartDNSBinPath:      smartBin,
		SmartDNSConfigFile:   smartConf,
		SmartDNSRulesDir:     smartRules,
		SmartDNSAuditLogPath: auditLog,
		ServiceMgr:           mockSvc,
		SmartDNSManager:      sdMgr,
		SyncSingBoxEnhancedFunc: func(_ context.Context, p, _ string, dnsCfg config.ClientDNSConfig, subs []string, ts time.Time) (bool, error) {
			raw, _ := os.ReadFile(p)
			out, changed, err := singbox.ApplyEnhancedSingBoxDNSJSON(string(raw), dnsCfg, subs, ts)
			if err == nil && changed {
				_ = os.WriteFile(p, []byte(out), 0600)
			}
			return changed, err
		},
		SyncSingBoxDNSLocalFunc: func(_ context.Context, p, _ string, useExternal bool, port int) (bool, error) {
			raw, _ := os.ReadFile(p)
			out, changed, err := singbox.PatchDNSLocalJSON(string(raw), useExternal, port)
			if err == nil && changed {
				_ = os.WriteFile(p, []byte(out), 0600)
			}
			return changed, err
		},
	}

	d := daemon.NewDaemonWithOptions(cfg, daemon.DaemonOptions{
		ConfigPath:      cfgPath,
		SkipSignalSetup: true,
		DNSDeps:         &deps,
		Paths: daemon.Paths{
			PidFile:         filepath.Join(tmpDir, "dm.pid"),
			LogFile:         filepath.Join(tmpDir, "dm.log"),
			StateFile:       filepath.Join(tmpDir, "dm.state"),
			WebEmbeddedFile: filepath.Join(tmpDir, "web.emb"),
		},
	})

	// 1. SmartDNS down -> emergency fallback sing-box to encrypted DoH + audit log drained
	d.GuardLocalDNSOnce(ctx)
	if linked, _ := singbox.InspectSingBoxDNSLocal(sbPath); linked {
		t.Fatal("expected sing-box dns_local emergency fallback to encrypted DoH when SmartDNS unhealthy")
	}
	if snap := d.SmartDNSStatsRing().Snapshot(now.Add(time.Minute), 0); snap.NumDNSQueries != 1 {
		t.Fatalf("expected SmartDNS audit log drained into StatsRing, got queries=%d", snap.NumDNSQueries)
	}

	// 2. SmartDNS recovers -> failback sing-box dns_local to 127.0.0.1:5353
	mockSvc.failRestart.Store(false)
	smartHealthy.Store(true)
	d.GuardLocalDNSOnce(ctx)
	if linked, port := singbox.InspectSingBoxDNSLocal(sbPath); !linked || port != 5353 {
		t.Fatalf("expected sing-box dns_local failback to 127.0.0.1:5353, got linked=%v port=%d", linked, port)
	}
}
