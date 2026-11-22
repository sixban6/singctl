// 文件职责：验证 singctl dns 三引擎子命令（switch / --engine 标志）与 sing-box 生成器探测注入契约。
package cmd_test

import (
	"path/filepath"
	"testing"

	"singctl/internal/cmd"
	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/localdns"
)

func TestDNSCmd_SupportsSwitchAndEngineFlags(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "singctl.yaml")
	root := cmd.NewDNSCmd(cfgPath)

	// 1. Verify "switch" subcommand exists with --engine and --force-low-memory
	switchCmd, _, err := root.Find([]string{"switch"})
	if err != nil || switchCmd == nil || switchCmd.Name() != "switch" {
		t.Fatalf("expected 'dns switch' subcommand, got cmd=%v err=%v", switchCmd, err)
	}
	if switchCmd.Flags().Lookup("engine") == nil {
		t.Fatal("expected --engine flag on 'dns switch'")
	}
	if switchCmd.Flags().Lookup("force-low-memory") == nil {
		t.Fatal("expected --force-low-memory flag on 'dns switch'")
	}

	// 2. Verify --engine flag exists on install / start / stop / restart / uninstall
	for _, sub := range []string{"install", "start", "stop", "restart", "uninstall"} {
		sc, _, findErr := root.Find([]string{sub})
		if findErr != nil || sc == nil || sc.Name() != sub {
			t.Fatalf("expected 'dns %s' subcommand, got %v %v", sub, sc, findErr)
		}
		if sc.Flags().Lookup("engine") == nil {
			t.Fatalf("expected --engine flag on 'dns %s'", sub)
		}
	}

	// 3. Verify localdns probe builder correctly bridges to singbox.ConfigGenerator.SetLocalDNSProbe
	tmpDir := t.TempDir()
	cfg := &config.Config{DNS: config.ClientDNSConfig{Engine: constant.DNSEngineAuto}}
	reg := localdns.NewRegistry(cfg, localdns.EngineDeps{
		AdGuardBinPath:  filepath.Join(tmpDir, "missing-agh"),
		SmartDNSBinPath: filepath.Join(tmpDir, "missing-sd"),
	})
	probe := reg.MakeSingBoxProbe()
	if probe(constant.DNSEngineAdGuard, 5353) || probe(constant.DNSEngineSmartDNS, 5353) {
		t.Fatal("expected missing external engines to report false from MakeSingBoxProbe")
	}
}
