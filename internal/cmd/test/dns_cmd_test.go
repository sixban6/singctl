// 文件职责：验证 singctl dns 双引擎子命令（switch / --engine 标志、拒绝 singbox 引擎）与 sing-box 生成器探测注入契约。
package cmd_test

import (
	"path/filepath"
	"strings"
	"testing"

	"singctl/internal/cmd"
	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/localdns"
)

func TestDNSCmd_SupportsSwitchAndDualEngineFlags(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "singctl.yaml")
	if err := config.Save(cfgPath, &config.Config{}); err != nil {
		t.Fatal(err)
	}
	root := cmd.NewDNSCmd(cfgPath)

	// 1. Verify "switch" subcommand exists with --engine and --force-low-memory and does NOT advertise singbox
	switchCmd, _, err := root.Find([]string{"switch"})
	if err != nil || switchCmd == nil || switchCmd.Name() != "switch" {
		t.Fatalf("expected 'dns switch' subcommand, got cmd=%v err=%v", switchCmd, err)
	}
	engFlag := switchCmd.Flags().Lookup("engine")
	if engFlag == nil {
		t.Fatal("expected --engine flag on 'dns switch'")
	}
	if strings.Contains(strings.ToLower(engFlag.Usage), "singbox") {
		t.Fatalf("dns switch --engine usage must not advertise removed singbox engine: %q", engFlag.Usage)
	}
	if switchCmd.Flags().Lookup("force-low-memory") == nil {
		t.Fatal("expected --force-low-memory flag on 'dns switch'")
	}

	// 2. Verify --engine flag exists on install / start / stop / restart / uninstall without advertising singbox
	for _, sub := range []string{"install", "start", "stop", "restart", "uninstall"} {
		sc, _, findErr := root.Find([]string{sub})
		if findErr != nil || sc == nil || sc.Name() != sub {
			t.Fatalf("expected 'dns %s' subcommand, got %v %v", sub, sc, findErr)
		}
		f := sc.Flags().Lookup("engine")
		if f == nil {
			t.Fatalf("expected --engine flag on 'dns %s'", sub)
		}
		if strings.Contains(strings.ToLower(f.Usage), "singbox") {
			t.Fatalf("dns %s --engine usage must not advertise singbox: %q", sub, f.Usage)
		}
	}

	// 3. Running `dns switch --engine singbox` must return an error
	root.SetArgs([]string{"switch", "--engine", "singbox"})
	if err := root.Execute(); err == nil {
		t.Fatal("expected 'dns switch --engine singbox' to be rejected")
	}

	// 4. Verify localdns probe builder correctly bridges to singbox.ConfigGenerator.SetLocalDNSProbe
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
