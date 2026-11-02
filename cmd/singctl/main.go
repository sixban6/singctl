package main

import (
	"log"
	"os"
	"path/filepath"
	"runtime"
	"singctl/configs"
	"singctl/internal/cmd"
	"singctl/internal/logger"

	"github.com/spf13/cobra"
)

var (
	Version   = "dev"
	BuildTime = "unknown"
	GitCommit = "unknown"
)

const (
	defaultUnixConfigPath           = "/etc/singctl/singctl.yaml"
	defaultDarwinHomebrewConfigPath = "/opt/homebrew/etc/singctl/singctl.yaml"
)

var configPath string

func init() {
	configPath = resolveDefaultConfigPath()
}

func resolveDefaultConfigPath() string {
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

func ensureConfigDir() error {
	dir := filepath.Dir(configPath)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		// 目录不存在，创建它（包括所有中间目录）
		return os.MkdirAll(dir, 0755)
	}
	return nil
}

func initConfigFile(dstConfigPath string) {
	if err := ensureConfigDir(); err != nil {
		log.Printf("Warning: failed to ensure config dir: %v", err)
		return
	}

	if err := os.WriteFile(dstConfigPath, configs.DefaultConfigYAML, 0600); err != nil {
		log.Printf("Warning: failed to write default config file: %v", err)
	}
}

func main() {
	// 判断是否是 init, help 或 version 等命令，避免在执行初始化向导前自动生成占位配置文件
	isInitOrHelp := false
	for i, arg := range os.Args {
		if arg == "init" || arg == "help" || arg == "-h" || arg == "--help" || arg == "version" || arg == "-v" || arg == "--version" {
			isInitOrHelp = true
			break
		}
		if (arg == "sr" || arg == "server") && i+1 < len(os.Args) && os.Args[i+1] == "init" {
			isInitOrHelp = true
			break
		}
	}

	if !isInitOrHelp {
		if _, err := os.Stat(configPath); os.IsNotExist(err) {
			initConfigFile(configPath)
		}
	}
	rootCmd := &cobra.Command{
		Use:   "singctl",
		Short: "Sing-box|TailScale|firewall 管理工具",
		Long: `SingCtl is a powerful tool for managing sing-box configurations and lifecycle.
It supports automatic configuration generation from subscription URLs,
DNS optimization, and complete service lifecycle management.`,
	}

	defaultConfigPath := resolveDefaultConfigPath()
	rootCmd.PersistentFlags().StringVarP(&configPath, "config", "c", defaultConfigPath, "config file")
	// 保留补全功能，但只是不想让它显示在 help 列表里，可以只隐藏它：
	rootCmd.CompletionOptions.HiddenDefaultCmd = true

	// 2. 覆写默认的 help 命令以修改解释文字
	helpCmd := &cobra.Command{
		Use:   "help [command]",
		Short: "帮助  : 获取任意命令的帮助信息(简写singctl help)",
		Run: func(c *cobra.Command, args []string) {
			// 复用 Cobra 底层自带的帮助渲染逻辑
			cmd, _, e := c.Root().Find(args)
			if cmd == nil || e != nil {
				c.Printf("Unknown help topic %#q\n", args)
				c.Root().Usage()
			} else {
				cmd.Help()
			}
		},
	}
	// 将我们自定义的 help 命令设置为根命令的 Help 命令
	rootCmd.SetHelpCommand(helpCmd)

	rootCmd.AddCommand(
		cmd.NewUpdateCmd(configPath, Version),
		cmd.NewVersionCmd(Version, BuildTime, GitCommit),
		cmd.NewInfoCommand(Version),
		cmd.NewSingboxCommand(configPath),
		cmd.NewTailscaleCmd(configPath),
		cmd.NewUtilCmd(),
		cmd.NewFirewallCmd(),
		cmd.NewServerCmd(configPath),
		cmd.NewReinstallServerCmd(configPath),
		cmd.NewCfTokenCmd(configPath),
		cmd.NewDaemonCommand(),
		cmd.NewWebCmd(Version),
		cmd.NewGFWCmd(),
		cmd.NewNetCmd(configPath),
		cmd.NewTerminalCmd(configPath),
		cmd.NewSSHCmd(),
		cmd.NewInternalMigrateCmd(),
	)

	if err := rootCmd.Execute(); err != nil {
		logger.Error("Command execution failed: %v", err)
		os.Exit(1)
	}
}
