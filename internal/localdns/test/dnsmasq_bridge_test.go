// 文件职责：测试「基础模式」(零 sing-box) 下 OpenWrt dnsmasq 桥接至本地 SmartDNS/AdGuard 的备份、原子切换、幂等性与无痕还原。
package localdns_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"singctl/internal/common/sysinfo"
	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/localdns"
	"singctl/internal/platform/servicemgr"
)

func TestOpenWrtDnsmasqBridge_EnableIdempotentAndRestore(t *testing.T) {
	tmpDir := t.TempDir()
	backupPath := filepath.Join(tmpDir, "dnsmasq-bridge-backup.json")

	state := map[string]string{
		"dhcp.@dnsmasq[0].noresolv": "0",
		"dhcp.@dnsmasq[0].server":   "223.5.5.5 119.29.29.29",
	}
	var reloads int

	deps := localdns.DnsmasqBridgeDeps{
		IsOpenWrt:  func() bool { return true },
		BackupPath: backupPath,
		RunUCI: func(_ context.Context, args ...string) (string, error) {
			if len(args) >= 2 && args[0] == "-q" && args[1] == "get" && len(args) == 3 {
				return state[args[2]], nil
			}
			if len(args) >= 2 && args[0] == "set" {
				k, v, ok := strings.Cut(args[1], "=")
				if ok {
					state[k] = v
				}
				return "", nil
			}
			if len(args) >= 2 && args[0] == "delete" {
				delete(state, args[1])
				return "", nil
			}
			if len(args) >= 2 && args[0] == "add_list" {
				k, v, ok := strings.Cut(args[1], "=")
				if ok {
					if cur := strings.TrimSpace(state[k]); cur != "" {
						state[k] = cur + " " + v
					} else {
						state[k] = v
					}
				}
				return "", nil
			}
			return "", nil
		},
		ReloadDnsmasq: func(_ context.Context) error {
			reloads++
			return nil
		},
	}

	// 1. Enable bridge to 127.0.0.1#5353
	changed, err := localdns.SyncOpenWrtDnsmasqBridge(t.Context(), true, 5353, deps)
	if err != nil || !changed {
		t.Fatalf("enable bridge failed: changed=%v err=%v", changed, err)
	}
	if state["dhcp.@dnsmasq[0].noresolv"] != "1" || state["dhcp.@dnsmasq[0].server"] != "127.0.0.1#5353" {
		t.Fatalf("unexpected uci state after enable: %+v", state)
	}
	if !localdns.InspectOpenWrtDnsmasqBridge(t.Context(), 5353, deps) {
		t.Fatal("expected InspectOpenWrtDnsmasqBridge=true after enable")
	}
	if runtime.GOOS != "windows" {
		info, statErr := os.Stat(backupPath)
		if statErr != nil || info.Mode().Perm() != 0600 {
			t.Fatalf("expected 0600 backup file, stat=%v mode=%v", statErr, info)
		}
	}

	// 2. Idempotent second call must not reload again
	prevReloads := reloads
	changed2, err := localdns.SyncOpenWrtDnsmasqBridge(t.Context(), true, 5353, deps)
	if err != nil || changed2 || reloads != prevReloads {
		t.Fatalf("expected idempotent enable: changed=%v err=%v reloads=%d->%d", changed2, err, prevReloads, reloads)
	}

	// 3. Disable bridge must restore original dnsmasq servers and noresolv cleanly
	changed3, err := localdns.SyncOpenWrtDnsmasqBridge(t.Context(), false, 5353, deps)
	if err != nil || !changed3 {
		t.Fatalf("disable bridge failed: changed=%v err=%v", changed3, err)
	}
	if state["dhcp.@dnsmasq[0].noresolv"] != "0" || state["dhcp.@dnsmasq[0].server"] != "223.5.5.5 119.29.29.29" {
		t.Fatalf("original dnsmasq state not restored: %+v", state)
	}
	if _, statErr := os.Stat(backupPath); !os.IsNotExist(statErr) {
		t.Fatalf("expected backup file removed after restore")
	}
}

func TestRegistry_StatusSummary_ReflectsDnsmasqBridgeInBasicMode(t *testing.T) {
	tmpDir := t.TempDir()
	sdBin := filepath.Join(tmpDir, "smartdns")
	if err := os.WriteFile(sdBin, []byte("#!/bin/sh\necho smartdns 1.2026\n"), 0755); err != nil {
		t.Fatal(err)
	}
	sdConf := filepath.Join(tmpDir, "smartdns.conf")
	if err := os.WriteFile(sdConf, []byte("bind 127.0.0.1:5353\n"), 0600); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{
		Gateway: config.GatewayConfig{WorkMode: config.WorkModeBasic},
		DNS:     config.ClientDNSConfig{Engine: constant.DNSEngineSmartDNS, DNSPort: 5353},
	}
	reg := localdns.NewRegistry(cfg, localdns.EngineDeps{
		SmartDNSBinPath:    sdBin,
		SmartDNSConfigFile: sdConf,
		SingBoxConfigPath:  filepath.Join(tmpDir, "nonexistent-singbox.json"),
		ProbeDNSFunc: func(_ string, _ time.Duration) error { return nil },
		DnsmasqBridgeDeps: &localdns.DnsmasqBridgeDeps{
			IsOpenWrt: func() bool { return true },
			RunUCI: func(_ context.Context, args ...string) (string, error) {
				if len(args) == 3 && args[2] == "dhcp.@dnsmasq[0].noresolv" {
					return "1", nil
				}
				if len(args) == 3 && args[2] == "dhcp.@dnsmasq[0].server" {
					return "127.0.0.1#5353", nil
				}
				return "", nil
			},
		},
	})

	sum := reg.StatusSummary(t.Context())
	if linked, _ := sum["dnsmasqLinked"].(bool); !linked {
		t.Fatalf("expected dnsmasqLinked=true in Basic Mode status summary, got %+v", sum)
	}
	if wm, _ := sum["workMode"].(string); wm != config.WorkModeBasic {
		t.Fatalf("expected workMode=basic, got %+v", sum)
	}
}

func TestSwitchEngine_BasicModeSkipsSingBoxSyncWhenStopped(t *testing.T) {
	const mib = 1024 * 1024
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "singctl.yaml")
	sbCfgPath := filepath.Join(tmpDir, "stale-singbox.json")
	sdBin := filepath.Join(tmpDir, "smartdns")
	sdConf := filepath.Join(tmpDir, "smartdns.conf")
	backupPath := filepath.Join(tmpDir, "dnsmasq-bridge-backup.json")

	// Simulate ax3000t: stale sing-box config exists on disk while sing-box is stopped in Basic Mode.
	if err := os.WriteFile(sbCfgPath, []byte(`{"dns":{"servers":[{"type":"tailscale","tag":"dns_tailscale"}]}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sdBin, []byte("#!/bin/sh\necho smartdns 1.2026\n"), 0755); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{
		Gateway: config.GatewayConfig{WorkMode: config.WorkModeBasic},
		DNS:     config.ClientDNSConfig{DNSPort: 5353},
	}
	if err := config.Save(cfgPath, cfg); err != nil {
		t.Fatal(err)
	}

	uciState := map[string]string{"dhcp.@dnsmasq[0].noresolv": "0"}
	syncCalls := 0

	reg := localdns.NewRegistry(cfg, localdns.EngineDeps{
		ConfigPath:         cfgPath,
		SingBoxConfigPath:  sbCfgPath,
		SmartDNSBinPath:    sdBin,
		SmartDNSConfigDir:  tmpDir,
		SmartDNSConfigFile: sdConf,
		SmartDNSRulesDir:   filepath.Join(tmpDir, "rules.d"),
		ServiceMgr:         servicemgr.NewMock(),
		GOOS:               "linux",
		GOARCH:             "arm64",
		IsOpenWrt:          func() bool { return true },
		ReadMemInfo: func() (sysinfo.MemInfo, error) {
			return sysinfo.MemInfo{TotalBytes: 224 * mib, AvailableBytes: 72 * mib}, nil
		},
		ReadDiskSpace: func(string) (sysinfo.DiskSpace, error) {
			return sysinfo.DiskSpace{AvailBytes: 25 * mib}, nil
		},
		CheckPortAvailableFunc: func(int) bool { return true },
		ProbeDNSFunc:           func(string, time.Duration) error { return nil },
		ProbeResolutionFunc:    func(string, string, time.Duration) ([]string, time.Duration, error) { return []string{"192.0.2.1"}, 5 * time.Millisecond, nil },
		IsSingBoxRunningFunc:   func() bool { return false },
		SyncSingBoxDNSLocalFunc: func(_ context.Context, _, _ string, _ bool, _ int) (bool, error) {
			syncCalls++
			return false, errors.New("sing-box check failed: Tailscale is not included in this build")
		},
		DnsmasqBridgeDeps: &localdns.DnsmasqBridgeDeps{
			IsOpenWrt:  func() bool { return true },
			BackupPath: backupPath,
			RunUCI: func(_ context.Context, args ...string) (string, error) {
				if len(args) == 3 && args[0] == "-q" && args[1] == "get" {
					return uciState[args[2]], nil
				}
				if len(args) == 2 && args[0] == "set" {
					if k, v, ok := strings.Cut(args[1], "="); ok {
						uciState[k] = v
					}
				}
				if len(args) == 2 && args[0] == "delete" {
					delete(uciState, args[1])
				}
				if len(args) == 2 && args[0] == "add_list" {
					if k, v, ok := strings.Cut(args[1], "="); ok {
						uciState[k] = v
					}
				}
				return "", nil
			},
			ReloadDnsmasq: func(context.Context) error { return nil },
		},
	})

	res, err := reg.SwitchEngine(t.Context(), localdns.SwitchRequest{TargetEngine: constant.DNSEngineSmartDNS})
	if err != nil {
		t.Fatalf("SwitchEngine failed in Basic Mode: %v", err)
	}
	if syncCalls != 0 {
		t.Fatalf("expected 0 sing-box sync calls when sing-box is stopped in Basic Mode, got %d", syncCalls)
	}
	if len(res.Warnings) != 0 {
		t.Fatalf("expected zero warnings in Basic Mode switch, got %v", res.Warnings)
	}
	if uciState["dhcp.@dnsmasq[0].noresolv"] != "1" || uciState["dhcp.@dnsmasq[0].server"] != "127.0.0.1#5353" {
		t.Fatalf("expected OpenWrt dnsmasq bridged to 127.0.0.1#5353, got %+v", uciState)
	}
}
