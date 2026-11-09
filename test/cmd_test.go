package test

import (
	"bytes"
	"github.com/spf13/cobra"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"singctl/internal/cmd"
	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/deploy"
	"strings"
	"testing"
)

// TestAllCommandsBilingual 验证所有命令和子命令的 Short 都包含中英文双语描述。
func TestAllCommandsBilingual(t *testing.T) {
	// 收集所有可测试的命令树
	commands := map[string]*cobra.Command{
		"tailscale": cmd.NewTailscaleCmd("/tmp/singctl.yaml"),
		"dns":       cmd.NewDNSCmd("/tmp/singctl.yaml"),
		"daemon":    cmd.NewDaemonCommand(),
		"firewall":  cmd.NewFirewallCmd(),
		"util":      cmd.NewUtilCmd(),
	}

	for name, parent := range commands {
		// 验证父命令 Short 包含中文
		if !containsChinese(parent.Short) {
			t.Errorf("%s parent Short missing Chinese: %q", name, parent.Short)
		}

		// 验证所有子命令 Short 包含 "/"（中英文分隔符）
		for _, sub := range parent.Commands() {
			if sub.Short == "" {
				t.Errorf("%s/%s has empty Short", name, sub.Use)
				continue
			}
			if !strings.Contains(sub.Short, "/") {
				t.Errorf("%s/%s Short should be bilingual (contain '/'), got: %q", name, sub.Use, sub.Short)
			}
		}
	}
}

// containsChinese 简单检查字符串是否包含中文字符
func containsChinese(s string) bool {
	for _, r := range s {
		if r >= 0x4E00 && r <= 0x9FFF {
			return true
		}
	}
	return false
}

func TestCopyGeneratedConfigToClipboardOnDarwinDefaultPath(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.json")
	clipboardPath := filepath.Join(tempDir, "clipboard.txt")
	configContent := `{"outbounds":[{"type":"direct"}]}`

	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("write config file: %v", err)
	}

	oldCommandRunner := cmd.CommandRunner
	oldRuntimeGOOS := cmd.RuntimeGOOS
	oldDefaultPath := cmd.DefaultSingBoxConfigPath
	t.Cleanup(func() {
		cmd.CommandRunner = oldCommandRunner
		cmd.RuntimeGOOS = oldRuntimeGOOS
		cmd.DefaultSingBoxConfigPath = oldDefaultPath
	})

	cmd.RuntimeGOOS = "darwin"
	cmd.DefaultSingBoxConfigPath = configPath
	cmd.CommandRunner = func(name string, args ...string) *exec.Cmd {
		cmd := exec.Command(os.Args[0], "-test.run=TestClipboardHelperProcess", "--", name)
		cmd.Env = append(os.Environ(),
			"GO_WANT_CLIPBOARD_HELPER=1",
			"GO_CLIPBOARD_CAPTURE_PATH="+clipboardPath,
		)
		return cmd
	}

	copied, err := cmd.CopyGeneratedConfigToClipboard(configPath)
	if err != nil {
		t.Fatalf("copyGeneratedConfigToClipboard returned error: %v", err)
	}
	if !copied {
		t.Fatal("expected generated config to be copied on darwin default path")
	}

	got, err := os.ReadFile(clipboardPath)
	if err != nil {
		t.Fatalf("read clipboard capture: %v", err)
	}
	if string(got) != configContent {
		t.Fatalf("unexpected clipboard content: got %q want %q", string(got), configContent)
	}
}

func TestCopyGeneratedConfigToClipboardSkipsUnsupportedCases(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.json")

	if err := os.WriteFile(configPath, []byte(`{"dns":{}}`), 0644); err != nil {
		t.Fatalf("write config file: %v", err)
	}

	oldCommandRunner := cmd.CommandRunner
	oldRuntimeGOOS := cmd.RuntimeGOOS
	oldDefaultPath := cmd.DefaultSingBoxConfigPath
	t.Cleanup(func() {
		cmd.CommandRunner = oldCommandRunner
		cmd.RuntimeGOOS = oldRuntimeGOOS
		cmd.DefaultSingBoxConfigPath = oldDefaultPath
	})

	commandCalled := false
	cmd.CommandRunner = func(name string, args ...string) *exec.Cmd {
		commandCalled = true
		return exec.Command("true")
	}

	cmd.RuntimeGOOS = "linux"
	cmd.DefaultSingBoxConfigPath = configPath
	copied, err := cmd.CopyGeneratedConfigToClipboard(configPath)
	if err != nil {
		t.Fatalf("unexpected error on linux: %v", err)
	}
	if copied {
		t.Fatal("expected clipboard copy to be skipped on linux")
	}

	cmd.RuntimeGOOS = "darwin"
	cmd.DefaultSingBoxConfigPath = filepath.Join(tempDir, "other-config.json")
	copied, err = cmd.CopyGeneratedConfigToClipboard(configPath)
	if err != nil {
		t.Fatalf("unexpected error on non-default path: %v", err)
	}
	if copied {
		t.Fatal("expected clipboard copy to be skipped for non-default output path")
	}
	if commandCalled {
		t.Fatal("pbcopy should not be invoked for skipped cases")
	}
}

func TestClipboardHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_CLIPBOARD_HELPER") != "1" {
		return
	}

	if len(os.Args) < 4 || os.Args[3] != "pbcopy" {
		os.Exit(2)
	}

	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		os.Exit(1)
	}

	if err := os.WriteFile(os.Getenv("GO_CLIPBOARD_CAPTURE_PATH"), data, 0644); err != nil {
		os.Exit(1)
	}

	os.Exit(0)
}

func TestPruneConfigBackups(t *testing.T) {
	tempDir := t.TempDir()
	targetPath := filepath.Join(tempDir, "config.json")

	names := []string{
		"config.json.backup.1700000001",
		"config.json.backup.1700000002",
		"config.json.backup.1700000003",
		"config.json.backup.1700000004",
		"config.json.backup.1700000005",
	}
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(tempDir, n), []byte("{}"), 0600); err != nil {
			t.Fatalf("write backup %s: %v", n, err)
		}
	}

	cmd.PruneConfigBackups(targetPath, 3)

	matches, err := filepath.Glob(targetPath + ".backup.*")
	if err != nil {
		t.Fatalf("glob backups: %v", err)
	}
	if len(matches) != 3 {
		t.Fatalf("expected 3 backups remaining, got %d: %v", len(matches), matches)
	}
	for _, expected := range names[2:] {
		if _, err := os.Stat(filepath.Join(tempDir, expected)); err != nil {
			t.Errorf("expected newest backup %s to be kept: %v", expected, err)
		}
	}
}

func TestGuardIOSOutputPath(t *testing.T) {
	localCfg := constant.SingBoxConfigFile

	t.Run("空路径放行(走默认导出路径)", func(t *testing.T) {
		if err := cmd.GuardIOSOutputPath(""); err != nil {
			t.Fatalf("empty path should pass: %v", err)
		}
	})

	t.Run("完全相同的路径拦截", func(t *testing.T) {
		err := cmd.GuardIOSOutputPath(localCfg)
		if err == nil {
			t.Fatal("writing local sing-box config should be rejected")
		}
		if !strings.Contains(err.Error(), "拒绝写入") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("Linux 官方路径跨平台拦截", func(t *testing.T) {
		// 即使在本机(macOS/Windows)上, /etc/sing-box/config.json 也可能因手工部署而真实存在
		if err := cmd.GuardIOSOutputPath("/etc/sing-box/config.json"); err == nil {
			t.Fatal("/etc/sing-box/config.json should be rejected on any OS")
		}
	})

	t.Run("相对路径绕过被拦截", func(t *testing.T) {
		wd, err := os.Getwd()
		if err != nil {
			t.Fatalf("getwd: %v", err)
		}
		rel, err := filepath.Rel(wd, localCfg)
		if err != nil {
			rel = strings.Repeat("../", 12) + strings.TrimPrefix(localCfg, "/")
		}
		if err := cmd.GuardIOSOutputPath(rel); err == nil {
			t.Fatalf("relative path %q escaping to local config should be rejected", rel)
		}
	})

	t.Run("其它路径放行", func(t *testing.T) {
		other := filepath.Join(t.TempDir(), "my-ios.json")
		if err := cmd.GuardIOSOutputPath(other); err != nil {
			t.Fatalf("other path should pass: %v", err)
		}
	})
}

func TestDefaultIOSOutputPath(t *testing.T) {
	got := cmd.DefaultIOSOutputPath()
	if !strings.HasSuffix(got, "singctl-ios.json") {
		t.Fatalf("default path should end with singctl-ios.json, got %q", got)
	}
	if strings.HasPrefix(got, string(filepath.Separator)+"etc") ||
		strings.Contains(got, "sing-box") && strings.HasSuffix(got, "config.json") {
		t.Fatalf("default path must not collide with local sing-box config, got %q", got)
	}
}

func TestShowUnifiedServerPanel(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			NodeDomain:     "node.example.com",
			SubstoreDomain: "sub.example.com",
			CFDNSKey:       "dummy_token",
			WebAdmin: config.WebAdminConfig{
				Enabled:  true,
				Port:     8092,
				Path:     "/sr/abcdef1234567890abcdef12",
				Username: "admin",
				Password: "TestPassword123",
			},
		},
	}

	sbs := &deploy.SingBoxServer{
		ShareLinkHy2:   "hysteria2://test-hy2-link",
		ShareLinkVless: "vless://test-vless-link",
	}

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	cmd.ShowUnifiedServerPanel(cfg, sbs, nil, "📌 SingCtl 服务端核心配置与连接信息")

	_ = w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	output := buf.String()

	// 1. Verify header title
	if !strings.Contains(output, "📌 SingCtl 服务端核心配置与连接信息") {
		t.Errorf("missing header title in output:\n%s", output)
	}

	// 2. Verify WebAdmin credentials & URL
	if !strings.Contains(output, "专属管理控制台 (核心 Web 后台入口)") {
		t.Errorf("missing WebAdmin panel header in output:\n%s", output)
	}
	if !strings.Contains(output, "https://sub.example.com/sr/abcdef1234567890abcdef12/") {
		t.Errorf("missing WebAdmin access URL in output:\n%s", output)
	}
	if !strings.Contains(output, "admin") || !strings.Contains(output, "TestPassword123") {
		t.Errorf("missing username or password in output:\n%s", output)
	}

	// 3. Verify node links
	if !strings.Contains(output, "hysteria2://test-hy2-link") || !strings.Contains(output, "vless://test-vless-link") {
		t.Errorf("missing node share links in output:\n%s", output)
	}

	// 4. Verify subscription URL
	if !strings.Contains(output, "https://sub.example.com/api/substore/download/singctl") {
		t.Errorf("missing subscription download URL in output:\n%s", output)
	}

	// 5. Verify maintenance commands
	if !strings.Contains(output, "singctl doctor") || !strings.Contains(output, "singctl sr info") {
		t.Errorf("missing maintenance commands in output:\n%s", output)
	}
}
