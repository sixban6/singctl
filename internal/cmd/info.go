package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
	"singctl/internal/config"
	"singctl/internal/daemon"
	"singctl/internal/logger"
)

// NewInfoCommand creates the info command
func NewInfoCommand(version string) *cobra.Command {
	return &cobra.Command{
		Use:   "info",
		Short: "Display system information",
		Long:  "Display sing-box installation path, configuration file path, singctl version and subscription information",
		RunE: func(cmd *cobra.Command, args []string) error {
			configPath := cmd.Flag("config").Value.String()
			return showSystemInfo(configPath, version)
		},
	}
}

func showSystemInfo(configPath, version string) error {
	// Header
	logger.Info("═══════════════════════════════════════════════════════════")
	logger.Success("           🎉 SINGCTL 系统信息 🎉")
	logger.Info("═══════════════════════════════════════════════════════════")

	// 1. Sing-box 信息
	logger.Info("")
	logger.Success("🎯 Sing-Box Information")
	logger.Info("───────────────────────────────────────────────────────────")

	// Sing-box 安装路径
	singboxPath := getSingBoxInstallDir()
	if _, err := os.Stat(singboxPath); err == nil {
		logger.Success("安装路径        : %s ✓", singboxPath)
	} else {
		logger.Warn("安装路径        : %s (不存在) ✗", singboxPath)
	}

	// Sing-box 配置文件路径
	singboxConfigPath := getSingBoxConfigPath()
	if _, err := os.Stat(singboxConfigPath); err == nil {
		logger.Success("配置文件路径    : %s ✓", singboxConfigPath)
	} else {
		logger.Warn("配置文件路径    : %s (不存在) ✗", singboxConfigPath)
	}

	// 2. SingCtl 信息
	logger.Info("")
	logger.Success("🚀 SingCtl Information")
	logger.Info("───────────────────────────────────────────────────────────")

	logger.Success("版本            : %s ✓", version)

	// SingCtl 安装路径
	exePath, err := os.Executable()
	if err != nil {
		logger.Warn("安装路径        : 未知 ✗")
	} else {
		logger.Success("安装路径        : %s ✓", exePath)
	}

	// SingCtl 配置文件路径
	if _, err := os.Stat(configPath); err == nil {
		logger.Success("配置文件路径    : %s ✓", configPath)
	} else {
		logger.Warn("配置文件路径    : %s (不存在) ✗", configPath)
	}

	// 3. 守护进程信息
	logger.Info("")
	logger.Success("🤖 守护进程信息")
	logger.Info("───────────────────────────────────────────────────────────")
	
	if daemon.IsDaemonRunning() {
		logger.Success("守护进程状态    : 运行中 ✓")
		
		// 显示重启统计
		limiter := daemon.NewRestartLimiter()
		logger.Info("重启统计        : %d/%d (最近1小时)", 
			limiter.GetRestartCount(), limiter.GetMaxRestarts())
	} else {
		logger.Warn("守护进程状态    : 未运行 ✗")
	}
	
	// 日志文件路径
	logPath := daemon.GetDaemonLogPath()
	if _, err := os.Stat(logPath); err == nil {
		logger.Success("日志文件路径    : %s ✓", logPath)
	} else {
		logger.Info("日志文件路径    : %s (未生成)", logPath)
	}

	// 4. 订阅连接信息
	logger.Info("")
	logger.Success("📡 订阅连接信息")
	logger.Info("───────────────────────────────────────────────────────────")

	cfg, err := config.Load(configPath)
	if err != nil {
		logger.Warn("订阅数量        : 无法读取配置文件 ✗")
		logger.Error("配置文件错误: %v", err)
	} else {
		if len(cfg.Subs) == 0 {
			logger.Warn("订阅数量        : 0 (未配置订阅) ✗")
		} else {
			logger.Success("订阅数量        : %d ✓", len(cfg.Subs))

			for i, sub := range cfg.Subs {
				name := sub.Name
				if name == "" {
					name = fmt.Sprintf("订阅 %d", i+1)
				}

				// 脱敏处理URL
				maskedURL := maskSubscriptionURL(sub.URL)
				logger.Info("  └─ %-12s: %s", name, maskedURL)

				if sub.SkipTlsVerify {
					logger.Info("      └─ 跳过TLS验证: 是")
				}
				if sub.RemoveEmoji {
					logger.Info("      └─ 移除Emoji  : 是")
				}
			}
		}
	}

	// Footer
	logger.Info("")
	logger.Info("═══════════════════════════════════════════════════════════")

	return nil
}

// getSingBoxInstallDir 返回适合当前系统的 sing-box 安装路径
func getSingBoxInstallDir() string {
	switch runtime.GOOS {
	case "windows":
		return filepath.Join(os.Getenv("LOCALAPPDATA"), "Programs", "sing-box", "sing-box.exe")
	case "linux":
		// 检查是否为 OpenWrt 系统
		if _, err := os.Stat("/etc/openwrt_release"); err == nil {
			return "/usr/bin/sing-box"
		}
		if _, err := os.Stat("/etc/openwrt_version"); err == nil {
			return "/usr/bin/sing-box"
		}
		return "/usr/local/bin/sing-box"
	default:
		// macOS等其他系统
		return "/usr/local/bin/sing-box"
	}
}

// getSingBoxConfigPath 返回 sing-box 配置文件路径
func getSingBoxConfigPath() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("LOCALAPPDATA"), "sing-box", "config.json")
	}
	return "/etc/sing-box/config.json"
}

// maskSubscriptionURL 对订阅URL进行脱敏处理
func maskSubscriptionURL(url string) string {
	if url == "" {
		return "未配置"
	}

	// 找到://后的部分
	parts := strings.Split(url, "//")
	if len(parts) < 2 {
		return "***"
	}

	scheme := parts[0] + "//"
	remaining := parts[1]

	// 按/分割获取域名部分
	pathParts := strings.Split(remaining, "/")
	if len(pathParts) == 0 {
		return "***"
	}

	domain := pathParts[0]

	// 域名脱敏，保留第一个字符和顶级域名
	domainParts := strings.Split(domain, ".")
	if len(domainParts) >= 2 {
		if len(domainParts[0]) > 1 {
			domainParts[0] = string(domainParts[0][0]) + strings.Repeat("*", len(domainParts[0])-1)
		}
		domain = strings.Join(domainParts, ".")
	}

	return scheme + domain + "/***"
}
