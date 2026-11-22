// 文件职责：验证 CLI 根入口装配（热重启重复首参清洗、早期 -c 解析、无状态命令免写盘及根命令分组构建）。
package cmd_test

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"singctl/internal/cmd"
)

func TestRootBootstrapHelpers_And_NewRootCmd(t *testing.T) {
	// 1. SanitizeLegacyRestartArgs strips duplicate executable argv[1]
	cleaned := cmd.SanitizeLegacyRestartArgs([]string{"/usr/bin/singctl", "/usr/bin/singctl", "--config", "/tmp/c.yaml", "web", "start"})
	wantArgs := []string{"/usr/bin/singctl", "--config", "/tmp/c.yaml", "web", "start"}
	if !slices.Equal(cleaned, wantArgs) {
		t.Fatalf("SanitizeLegacyRestartArgs = %v, want %v", cleaned, wantArgs)
	}
	normal := []string{"/usr/bin/singctl", "version"}
	if !slices.Equal(cmd.SanitizeLegacyRestartArgs(normal), normal) {
		t.Fatal("SanitizeLegacyRestartArgs mutated normal args")
	}

	// 2. ParseEarlyConfigPath supports -c, --config, -c=, --config=
	if got := cmd.ParseEarlyConfigPath([]string{"singctl", "-c", "/a/b.yaml", "sb"}, "/def"); got != "/a/b.yaml" {
		t.Fatalf("ParseEarlyConfigPath(-c) = %q", got)
	}
	if got := cmd.ParseEarlyConfigPath([]string{"singctl", "--config=/x/y.yaml"}, "/def"); got != "/x/y.yaml" {
		t.Fatalf("ParseEarlyConfigPath(--config=) = %q", got)
	}
	if got := cmd.ParseEarlyConfigPath([]string{"singctl", "version"}, "/def"); got != "/def" {
		t.Fatalf("ParseEarlyConfigPath(fallback) = %q", got)
	}

	// 3. IsStatelessCommand avoids creating default singctl.yaml on read-only/help/init/fleet invocations
	for _, stateless := range [][]string{
		{"singctl"},
		{"singctl", "version"},
		{"singctl", "--help"},
		{"singctl", "sr", "init"},
		{"singctl", "fleet", "list"},
	} {
		if !cmd.IsStatelessCommand(stateless) {
			t.Fatalf("expected stateless=true for %v", stateless)
		}
	}
	if cmd.IsStatelessCommand([]string{"singctl", "sb", "gen"}) {
		t.Fatal("expected sb gen to be stateful")
	}

	// 4. ExecuteWithArgs on `version` in temp dir must NOT create config file and must return nil
	nonExistentCfg := filepath.Join(t.TempDir(), "no-write", "singctl.yaml")
	err := cmd.ExecuteWithArgs([]string{"singctl", "-c", nonExistentCfg, "version"}, cmd.BuildInfo{
		Version:   "1.99.0-test",
		BuildTime: "2026-01-01",
		GitCommit: "abcdef0",
	})
	if err != nil {
		t.Fatalf("ExecuteWithArgs(version) failed: %v", err)
	}
	if _, statErr := os.Stat(nonExistentCfg); !os.IsNotExist(statErr) {
		t.Fatal("stateless version command unexpectedly wrote config file")
	}
}
