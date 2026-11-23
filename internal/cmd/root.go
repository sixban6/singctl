// 文件职责：负责 SingCtl CLI 根命令装配、热重启重复首参清洗、默认配置初始化及三大场景分组挂载。
package cmd

import (
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"singctl/internal/common/fsx"
	"singctl/internal/common/memlimit"
	"singctl/internal/config"

	"github.com/spf13/cobra"
)

const (
	defaultUnixConfigPath           = "/etc/singctl/singctl.yaml"
	defaultDarwinHomebrewConfigPath = "/opt/homebrew/etc/singctl/singctl.yaml"
)

// BuildInfo 承载编译期通过 -ldflags 注入的版本元信息。
type BuildInfo struct {
	Version   string
	BuildTime string
	GitCommit string
}

// ResolveDefaultConfigPath 按当前操作系统推导默认 singctl.yaml 路径。
func ResolveDefaultConfigPath() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("LOCALAPPDATA"), "singctl", "singctl.yaml")
	}
	if runtime.GOOS == "darwin" {
		if _, err := os.Stat(defaultDarwinHomebrewConfigPath); err == nil {
			return defaultDarwinHomebrewConfigPath
		}
	}
	return defaultUnixConfigPath
}

// ParseEarlyConfigPath 在 Cobra 完整解析前快速扫描命令行参数提取 -c / --config 路径。
func ParseEarlyConfigPath(args []string, fallback string) string {
	for i := 1; i < len(args); i++ {
		arg := args[i]
		if (arg == "-c" || arg == "--config") && i+1 < len(args) {
			return args[i+1]
		}
		if v, ok := strings.CutPrefix(arg, "--config="); ok && v != "" {
			return v
		}
		if v, ok := strings.CutPrefix(arg, "-c="); ok && v != "" {
			return v
		}
	}
	return fallback
}

// IsStatelessCommand 判断当前调用是否为无状态只读/向导命令，避免污染只读目录或提前生成占位配置。
func IsStatelessCommand(args []string) bool {
	if len(args) <= 1 {
		return true
	}
	for i, arg := range args[1:] {
		idx := i + 1
		switch arg {
		case "init", "help", "-h", "--help", "version", "-v", "--version", "internal-migrate", "completion", "util", "gfw", "fleet", "fl":
			return true
		case "sr", "server":
			if idx+1 < len(args) && args[idx+1] == "init" {
				return true
			}
		}
	}
	return false
}

// SanitizeLegacyRestartArgs 自动修复历史版本 (<= v1.14.126) 热重启脚本遗漏 shift 导致的重复首参问题。
func SanitizeLegacyRestartArgs(args []string) []string {
	if len(args) >= 3 && args[0] != "" && (args[1] == args[0] || filepath.Base(args[1]) == filepath.Base(args[0])) {
		out := make([]string, 0, len(args)-1)
		out = append(out, args[0])
		out = append(out, args[2:]...)
		return out
	}
	return args
}

func initDefaultConfigFile(dstConfigPath string, args []string) {
	tpl := config.TemplateForCommandArgs(args)
	if err := fsx.WriteAtomic0600(dstConfigPath, tpl); err != nil {
		log.Printf("Warning: failed to write default config file: %v", err)
	}
}

// NewRootCmd 构建挂载全部服务端、客户端与系统运维子命令的根 Cobra 命令。
func NewRootCmd(defaultConfigPath, initialConfigPath string, info BuildInfo) *cobra.Command {
	cfgPath := initialConfigPath
	rootCmd := &cobra.Command{
		Use:   "singctl",
		Short: "Sing-box|TailScale|firewall 管理工具",
		Long: `SingCtl is a powerful tool for managing sing-box configurations and lifecycle.
It supports automatic configuration generation from subscription URLs,
DNS optimization, and complete service lifecycle management.`,
	}

	rootCmd.PersistentFlags().StringVarP(&cfgPath, "config", "c", defaultConfigPath, "config file")
	rootCmd.CompletionOptions.HiddenDefaultCmd = true

	rootCmd.SetHelpCommand(&cobra.Command{
		Use:   "help [command]",
		Short: "帮助  : 获取任意命令的帮助信息(简写singctl help)",
		Run: func(c *cobra.Command, args []string) {
			target, _, err := c.Root().Find(args)
			if target == nil || err != nil {
				c.Printf("Unknown help topic %#q\n", args)
				_ = c.Root().Usage()
				return
			}
			_ = target.Help()
		},
	})

	registerEditionGroups(rootCmd)
	rootCmd.AddGroup(
		&cobra.Group{ID: "client", Title: "【客户端透明代理 (Client Gateway)】"},
		&cobra.Group{ID: "system", Title: "【系统与运维工具 (System & Diagnostics)】"},
	)

	addGrouped := func(groupID string, cmds ...*cobra.Command) {
		for _, sub := range cmds {
			sub.GroupID = groupID
			rootCmd.AddCommand(sub)
		}
	}

	addGrouped("client",
		NewSingboxCommand(cfgPath),
		NewDNSCmd(cfgPath),
		NewGFWCmd(),
		NewNetCmd(cfgPath),
		NewWebCmd(info.Version),
		NewTailscaleCmd(cfgPath),
	)
	addGrouped("system",
		NewDoctorCmd(cfgPath),
		NewSafeCommitCmd(cfgPath),
		NewInfoCommand(info.Version),
		NewUpdateCmd(cfgPath, info.Version),
		NewVersionCmd(info.Version, info.BuildTime, info.GitCommit),
		NewDaemonCommand(info.Version),
		NewFirewallCmd(),
	)
	mountEditionCommands(rootCmd, cfgPath, info, addGrouped)
	rootCmd.AddCommand(NewInternalMigrateCmd())
	return rootCmd
}

// Execute 执行当前进程 CLI 入口（清洗参数、自适应 GOMEMLIMIT、按需建默认配置并调度子命令）。
func Execute(info BuildInfo) error {
	os.Args = SanitizeLegacyRestartArgs(os.Args)
	return ExecuteWithArgs(os.Args, info)
}

// ExecuteWithArgs 以显式参数切片运行根命令（便于离线单元测试）。
func ExecuteWithArgs(args []string, info BuildInfo) error {
	cleaned := SanitizeLegacyRestartArgs(args)
	memlimit.ApplyDefault(cleaned)

	defaultCfgPath := ResolveDefaultConfigPath()
	cfgPath := ParseEarlyConfigPath(cleaned, defaultCfgPath)
	if !IsStatelessCommand(cleaned) {
		if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
			initDefaultConfigFile(cfgPath, cleaned)
		}
	}

	rootCmd := NewRootCmd(defaultCfgPath, cfgPath, info)
	if len(cleaned) > 1 {
		rootCmd.SetArgs(cleaned[1:])
	} else {
		rootCmd.SetArgs([]string{})
	}
	return rootCmd.Execute()
}
