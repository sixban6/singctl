package test

import (
	"strings"
	"testing"

	"singctl/internal/cmd"

	"github.com/spf13/cobra"
)

// TestAllCommandsBilingual 验证所有命令和子命令的 Short 都包含中英文双语描述。
func TestAllCommandsBilingual(t *testing.T) {
	// 收集所有可测试的命令树
	commands := map[string]*cobra.Command{
		"tailscale": cmd.NewTailscaleCmd("/tmp/singctl.yaml"),
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
