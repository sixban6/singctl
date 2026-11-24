// 文件职责：测试历史基础模式遗留 OpenWrt dnsmasq 桥接快照的幂等无痕还原与审计/代理模式状态汇总。
package localdns_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/localdns"
)

func TestOpenWrtDnsmasqBridge_LegacyRestoreIdempotent(t *testing.T) {
	tmpDir := t.TempDir()
	backupPath := filepath.Join(tmpDir, "dnsmasq-bridge-backup.json")

	// Simulate legacy v1.14.182 host left with dnsmasq bridged to 127.0.0.1#5353
	if err := os.WriteFile(backupPath, []byte(`{"noresolv":"0","servers":["223.5.5.5","119.29.29.29"]}`), 0600); err != nil {
		t.Fatal(err)
	}
	state := map[string]string{
		"dhcp.@dnsmasq[0].noresolv": "1",
		"dhcp.@dnsmasq[0].server":   "127.0.0.1#5353",
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

	changed, err := localdns.RestoreLegacyOpenWrtDnsmasqBridge(t.Context(), 5353, deps)
	if err != nil || !changed || reloads != 1 {
		t.Fatalf("restore legacy bridge failed: changed=%v reloads=%d err=%v", changed, reloads, err)
	}
	if state["dhcp.@dnsmasq[0].noresolv"] != "0" || state["dhcp.@dnsmasq[0].server"] != "223.5.5.5 119.29.29.29" {
		t.Fatalf("original dnsmasq state not restored: %+v", state)
	}
	if _, statErr := os.Stat(backupPath); !os.IsNotExist(statErr) {
		t.Fatal("expected legacy backup file removed after restore")
	}

	// Second call is a pure idempotent no-op
	changed2, err := localdns.RestoreLegacyOpenWrtDnsmasqBridge(t.Context(), 5353, deps)
	if err != nil || changed2 || reloads != 1 {
		t.Fatalf("expected idempotent no-op second restore: changed=%v reloads=%d err=%v", changed2, reloads, err)
	}
}

func TestRegistry_StatusSummary_LegacyBasicMapsToAuditNoFalseLink(t *testing.T) {
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
		Gateway: config.GatewayConfig{WorkMode: "basic"}, // legacy config value
		DNS:     config.ClientDNSConfig{Engine: constant.DNSEngineSmartDNS, DNSPort: 5353},
	}
	reg := localdns.NewRegistry(cfg, localdns.EngineDeps{
		SmartDNSBinPath:    sdBin,
		SmartDNSConfigFile: sdConf,
		SingBoxConfigPath:  filepath.Join(tmpDir, "nonexistent-singbox.json"),
		ProbeDNSFunc:       func(_ string, _ time.Duration) error { return nil },
	})

	sum := reg.StatusSummary(t.Context())
	if wm, _ := sum["workMode"].(string); wm != config.WorkModeAudit {
		t.Fatalf("expected legacy basic normalized to workMode=audit, got %+v", sum)
	}
	if linked, _ := sum["singboxLinked"].(bool); linked {
		t.Fatalf("expected singboxLinked=false when sing-box config does not exist, got %+v", sum)
	}
}
