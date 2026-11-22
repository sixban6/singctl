// 文件职责：验证看门狗双引擎本地 DNS 守护（彻底消除 sing-box 主上游探测告警、SmartDNS 容灾降级/恢复且关闭乐观缓存、暂停到期自动恢复与审计日志采集）。
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
	"singctl/internal/singbox/sboption"
	"singctl/internal/smartdns"
)

func baseSBJSONForDaemon() string {
	return `{
  "dns": {
    "servers": [
      {"tag": "dns_local", "type": "https", "server": "223.5.5.5", "server_port": 443, "path": "/dns-query"}
    ],
    "disable_cache": true,
    "optimistic": false,
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
  },
  "experimental": {
    "cache_file": {
      "enabled": true,
      "store_dns": false
    }
  }
}`
}

func TestDaemon_GuardLocalDNS_NeverProbesSingBoxUpstream(t *testing.T) {
	ctx := t.Context()
	tmpDir := t.TempDir()
	sbPath := filepath.Join(tmpDir, "config.json")
	if err := os.WriteFile(sbPath, []byte(baseSBJSONForDaemon()), 0600); err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 11, 22, 20, 0, 0, 0, time.UTC)
	for _, engineVal := range []string{constant.DNSEngineAuto, "singbox"} {
		t.Run("engine_"+engineVal, func(t *testing.T) {
			cfgPath := filepath.Join(tmpDir, "singctl-"+engineVal+".yaml")
			cfg := &config.Config{
				DNS: config.ClientDNSConfig{
					Engine:    engineVal,
					Upstreams: []string{"https://223.5.5.5/dns-query", "https://1.12.12.12/dns-query"},
				},
			}
			if err := config.Save(cfgPath, cfg); err != nil {
				t.Fatal(err)
			}

			var probeCalled atomic.Int32
			deps := localdns.EngineDeps{
				ConfigPath:        cfgPath,
				SingBoxConfigPath: sbPath,
				AdGuardBinPath:    filepath.Join(tmpDir, "missing-agh"),
				SmartDNSBinPath:   filepath.Join(tmpDir, "missing-sd"),
				NowFunc:           func() time.Time { return now },
				ProbeUpstreamListFunc: func(_ context.Context, _ []string, _ string, _ time.Duration) []adguard.UpstreamProbeItem {
					probeCalled.Add(1)
					return nil
				},
			}

			d := daemon.NewDaemonWithOptions(cfg, daemon.DaemonOptions{
				ConfigPath:      cfgPath,
				SkipSignalSetup: true,
				DNSDeps:         &deps,
				Paths: daemon.Paths{
					PidFile:         filepath.Join(tmpDir, "dm-"+engineVal+".pid"),
					LogFile:         filepath.Join(tmpDir, "dm-"+engineVal+".log"),
					StateFile:       filepath.Join(tmpDir, "dm-"+engineVal+".state"),
					WebEmbeddedFile: filepath.Join(tmpDir, "web-"+engineVal+".emb"),
				},
			})

			d.GuardLocalDNSOnce(ctx)
			d.GuardLocalDNSOnce(ctx)
			if probeCalled.Load() != 0 {
				t.Fatalf("watchdog must NEVER probe sing-box primary upstream, got %d calls", probeCalled.Load())
			}
		})
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

func TestDaemon_GuardLocalDNS_SmartDNSFailoverFailbackPauseExpiryAndAuditTail(t *testing.T) {
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
			Engine:               constant.DNSEngineSmartDNS,
			DNSPort:              5353,
			AdblockDisabledUntil: now.Add(-1 * time.Minute).Unix(), // expired temporary pause
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
		NowFunc:              func() time.Time { return now },
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

	// 1. SmartDNS down -> emergency fallback sing-box to pure-IP DoH (optimistic=false!) + pause expiry auto-resumed + audit log drained
	d.GuardLocalDNSOnce(ctx)
	if linked, _ := singbox.InspectSingBoxDNSLocal(sbPath); linked {
		t.Fatal("expected sing-box dns_local emergency fallback to encrypted DoH when SmartDNS unhealthy")
	}
	rawSB, _ := os.ReadFile(sbPath)
	docSB, _ := sboption.ParseDocument(rawSB)
	if docSB.DNS.DisableCache == nil || !*docSB.DNS.DisableCache ||
		docSB.DNS.Optimistic == nil || *docSB.DNS.Optimistic ||
		docSB.Experimental.CacheFile.StoreDNS == nil || *docSB.Experimental.CacheFile.StoreDNS {
		t.Fatalf("emergency DoH fallback must keep disable_cache=true, optimistic=false, store_dns=false; got dc=%v opt=%v store=%v",
			docSB.DNS.DisableCache, docSB.DNS.Optimistic, docSB.Experimental.CacheFile.StoreDNS)
	}
	loadedCfg, _ := config.Load(cfgPath)
	if loadedCfg.DNS.AdblockDisabledUntil != 0 {
		t.Fatalf("expected expired SmartDNS AdblockDisabledUntil cleared to 0, got %d", loadedCfg.DNS.AdblockDisabledUntil)
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
