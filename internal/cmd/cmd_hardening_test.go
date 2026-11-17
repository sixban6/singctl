package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"singctl/configs"
	"singctl/internal/fleet"

	"github.com/spf13/cobra"
)

func TestFullCLICommandTree_NoFlagPanics_And_InternalMigrate(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "singctl.yaml")
	tplPath := filepath.Join(dir, "template.yaml")
	if err := os.WriteFile(cfgPath, []byte("hy2:\n  up: 35\n  down: 220\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tplPath, configs.ClientConfigYAML, 0600); err != nil {
		t.Fatal(err)
	}

	root := &cobra.Command{Use: "singctl"}
	root.PersistentFlags().StringP("config", "c", cfgPath, "config file")
	root.AddCommand(
		NewServerCmd(cfgPath, "v1.14.135"),
		NewFleetCmd(cfgPath),
		NewReinstallServerCmd(cfgPath),
		NewCfTokenCmd(cfgPath),
		NewSingboxCommand(cfgPath),
		NewDNSCmd(cfgPath),
		NewGFWCmd(),
		NewNetCmd(cfgPath),
		NewWebCmd("v1.14.135"),
		NewTailscaleCmd(cfgPath),
		NewDoctorCmd(cfgPath),
		NewInfoCommand("v1.14.135"),
		NewUpdateCmd(cfgPath, "v1.14.135"),
		NewVersionCmd("v1.14.135", "2026-05-01", "abcdef0"),
		NewDaemonCommand("v1.14.135"),
		NewTerminalCmd(cfgPath),
		NewSSHCmd(),
		NewFirewallCmd(),
		NewUtilCmd(),
		NewInternalMigrateCmd(),
	)

	// 1. version command
	root.SetArgs([]string{"version"})
	if err := root.Execute(); err != nil {
		t.Fatalf("version command failed: %v", err)
	}

	// 2. internal-migrate command (valid + missing args error)
	migErrCmd := NewInternalMigrateCmd()
	migErrCmd.SetArgs([]string{})
	if err := migErrCmd.Execute(); err == nil {
		t.Fatal("expected internal-migrate without flags to return error")
	}

	root.SetArgs([]string{"internal-migrate", "--config", cfgPath, "--template", tplPath})
	if err := root.Execute(); err != nil {
		t.Fatalf("internal-migrate failed: %v", err)
	}
	migrated, err := os.ReadFile(cfgPath)
	if err != nil || !strings.Contains(string(migrated), "up: 35") || !strings.Contains(string(migrated), "down: 220") {
		t.Fatalf("expected user hy2 values preserved after internal-migrate:\n%s", string(migrated))
	}

	// 3. ApplyPositionalFleetNewArgs edge cases
	var bs fleet.BootstrapInput
	ApplyPositionalFleetNewArgs([]string{"root@203.0.113.10:2222"}, &bs, false, false)
	if bs.Host != "203.0.113.10" || bs.Port != 2222 || bs.User != "root" {
		t.Fatalf("unexpected single-arg host parse: %+v", bs)
	}

	var bs2 fleet.BootstrapInput
	ApplyPositionalFleetNewArgs([]string{"jp1", "jp1.example.com:15500"}, &bs2, false, false)
	if bs2.ID != "jp1" || bs2.Host != "jp1.example.com" || bs2.Port != 15500 {
		t.Fatalf("unexpected two-arg id+host parse: %+v", bs2)
	}
}
