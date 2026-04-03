package main

import (
	"log"
	"os"
	"path/filepath"
	"runtime"
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

func initConfigFile(srcConfigPath string, dstConfigPath string) {
	file, err := os.ReadFile(srcConfigPath)
	if err != nil {
		log.Fatalf("Init failed to read config file: %v", err)
	}
	err = ensureConfigDir()
	if err != nil {
		log.Fatalf("Init failed to ensure config dir: %v", err)
	}

	err = os.WriteFile(dstConfigPath, file, 0644)
	if err != nil {
		log.Fatalf("Init failed to write config file: %v", err)
	}
}

func main() {
	// 只在配置文件不存在时才初始化
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		// 获取可执行文件所在目录
		exePath, err := os.Executable()
		if err != nil {
			log.Fatalf("Failed to get executable path: %v", err)
		}
		exeDir := filepath.Dir(exePath)
		srcConfigPath := filepath.Join(exeDir, "configs", "singctl.yaml")

		initConfigFile(srcConfigPath, configPath)
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
		cmd.NewDaemonCommand(),
	)

	if err := rootCmd.Execute(); err != nil {
		logger.Error("Command execution failed: %v", err)
		os.Exit(1)
	}
}
