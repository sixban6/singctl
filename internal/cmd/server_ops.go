package cmd

import (
	"fmt"
	"os"
	"strings"

	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/deploy"
	"singctl/internal/deploy/masksite"
	"singctl/internal/logger"

	"github.com/spf13/cobra"
)

func newMaskSiteCmd(configPath string) *cobra.Command {
	var regen bool
	cmd := &cobra.Command{
		Use:     "mask-site",
		Aliases: []string{"mask", "camouflage"},
		Short:   "管理或重新生成 Caddy 伪装回落博客 / Manage or regenerate camouflage mask blog",
		RunE: func(cmd *cobra.Command, args []string) error {
			if regen || (len(args) > 0 && args[0] == "regen") {
				meta, err := deploy.RegenerateMaskSite()
				if err != nil {
					return err
				}
				logger.Success("Camouflage site regenerated successfully:")
				logger.Info("  Title:    %s", meta.BlogTitle)
				logger.Info("  Author:   %s (%s)", meta.AuthorName, meta.AuthorRole)
				logger.Info("  Category: %s", meta.Category)
				logger.Info("  Articles: %d posts generated", meta.ArticleCount)
				return nil
			}

			metaJson := masksite.ReadExistingMeta(constant.MaskSiteDir)
			if metaJson != "" {
				logger.Info("Current camouflage site metadata:\n%s", metaJson)
			} else {
				logger.Info("Camouflage site directory: %s", constant.MaskSiteDir)
			}
			logger.Info("To regenerate a brand new randomized persona and articles, run: singctl sr mask-site --regen")
			return nil
		},
	}
	cmd.Flags().BoolVarP(&regen, "regen", "r", false, "随机重新生成高熵伪装站点 (Randomly regenerate high-entropy camouflage blog)")
	return cmd
}

// NewCfTokenCmd creates the cf-token command for rotating Cloudflare API token
func NewCfTokenCmd(configPath string) *cobra.Command {
	return &cobra.Command{
		Use:     "cf-token <token>",
		Aliases: []string{"cf", "token", "cftoken"},
		Short:   "轮换 Cloudflare API Token 并重启 Caddy / Rotate Cloudflare API token and restart Caddy",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			newToken := strings.TrimSpace(args[0])
			if newToken == "" {
				return fmt.Errorf("cloudflare api token cannot be empty")
			}

			resolvedPath := resolveConfigPath(cmd, configPath)
			cfg, err := config.Load(resolvedPath)
			if err != nil {
				return fmt.Errorf("failed to load config: %w", err)
			}

			cfg.Server.CFDNSKey = newToken
			if err := config.Save(resolvedPath, cfg); err != nil {
				return fmt.Errorf("failed to save config: %w", err)
			}
			logger.Info("Cloudflare API token updated in config (%s)", resolvedPath)

			if err := deploy.RotateCloudflareToken(cfg); err != nil {
				return fmt.Errorf("failed to rotate cloudflare token: %w", err)
			}

			logger.Success("Cloudflare API token rotated successfully.")
			return nil
		},
	}
}

func newResetServerCmd(configPath string) *cobra.Command {
	return &cobra.Command{
		Use:   "reset [target]",
		Short: "重置服务端凭证并更新订阅 / Reset server credentials and update SubHub (sb|singbox)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := "sb"
			if len(args) > 0 {
				target = args[0]
			}

			switch target {
			case "sb", "singbox":
				resolvedPath := resolveConfigPath(cmd, configPath)
				return resetSingboxCredentials(resolvedPath)
			default:
				return fmt.Errorf("unknown target: %s (must be sb or singbox)", target)
			}
		},
	}
}

func resetSingboxCredentials(configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	if cfg.Server.GetNodeDomain() == "" {
		return fmt.Errorf("server.node_domain (or sb_domain) is required in config (%s)", configPath)
	}

	logger.Info("Resetting sing-box server credentials for domain: %s...", cfg.Server.GetNodeDomain())

	sbs, err := deploy.NewSingBoxServer(cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize sing-box server: %w", err)
	}

	if err := sbs.ResetCredentials(); err != nil {
		return fmt.Errorf("failed to reset sing-box credentials: %w", err)
	}

	sbt := deploy.NewSubstore(cfg, "")
	if err := sbt.UpdateSubstoreConfig(sbs); err != nil {
		logger.Warn("SubHub config update failed: %v", err)
		return fmt.Errorf("failed to update substore config: %w", err)
	}

	logger.Success("Sing-box credentials reset and SubHub subscriptions updated successfully.")
	return nil
}

func newSniCmd(configPath string) *cobra.Command {
	return &cobra.Command{
		Use:   "sni <domain>",
		Short: "更新 Reality SNI 域名 / Update Reality SNI domain and reload services",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			newSni := args[0]

			resolvedPath := resolveConfigPath(cmd, configPath)
			cfg, err := config.Load(resolvedPath)
			if err != nil {
				return fmt.Errorf("failed to load config: %w", err)
			}
			cfg.Server.Sni = newSni
			if err := config.Save(resolvedPath, cfg); err != nil {
				return fmt.Errorf("failed to save config: %w", err)
			}
			logger.Info("SNI updated to %s in config", newSni)

			if err := deploy.DeployCaddy(cfg); err != nil {
				return fmt.Errorf("caddy update failed: %w", err)
			}

			sbs, err := deploy.NewSingBoxServer(cfg)
			if err != nil {
				return err
			}
			if err := sbs.LoadExistingCredentials(); err != nil {
				logger.Warn("Could not load existing credentials, new ones will be generated: %v", err)
			}
			if err := sbs.DeploySingbox(); err != nil {
				return fmt.Errorf("sing-box update failed: %w", err)
			}

			sbt := deploy.NewSubstore(cfg, "")
			if err := sbt.UpdateSubstoreConfig(sbs); err != nil {
				logger.Warn("SubHub config update failed (non-fatal): %v", err)
			}

			logger.Success("SNI updated successfully to: %s", newSni)
			return nil
		},
	}
}

// NewSyncServerCmd creates the command to sync latest node credentials from sing-box to SubHub.
func NewSyncServerCmd(configPath string) *cobra.Command {
	var restart bool
	var tag string

	cmd := &cobra.Command{
		Use:     "sync [target]",
		Aliases: []string{"ss", "sync-substore"},
		Short:   "同步最新节点信息到 SubHub / Sync latest node info to SubHub (substore)",
		Args:    cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := "substore"
			if len(args) > 0 {
				target = args[0]
			}

			switch target {
			case "substore", "sub-store", "subhub", "sb", "singbox":
				resolvedPath := resolveConfigPath(cmd, configPath)
				return syncNodeToSubstore(resolvedPath, restart, tag)
			default:
				return fmt.Errorf("unknown target: %s (must be substore, subhub, sb, or singbox)", target)
			}
		},
	}

	cmd.Flags().BoolVarP(&restart, "restart", "r", true, "同步后自动重启 SubHub 服务保证缓存刷新 / Restart SubHub service after sync")
	cmd.Flags().StringVarP(&tag, "tag", "t", "", "节点名称/地区代号 (例如: los, sg)，若指定则同步更新并持久化到配置文件")
	return cmd
}

func syncNodeToSubstore(configPath string, restart bool, tag string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	if tag != "" {
		cfg.Server.NodeTag = tag
		if curData, rErr := os.ReadFile(configPath); rErr == nil {
			_ = config.MigrateConfig(configPath, curData)
		}
	}

	if cfg.Server.GetNodeDomain() == "" {
		return fmt.Errorf("server.node_domain (or sb_domain) is required in config (%s)", configPath)
	}

	logger.Info("正在从本地 sing-box 配置文件读取实际节点凭证与参数...")

	sbs, err := deploy.NewSingBoxServer(cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize sing-box server: %w", err)
	}

	if err := sbs.LoadExistingCredentials(); err != nil {
		return fmt.Errorf("failed to load existing sing-box credentials: %w", err)
	}

	_ = deploy.SyncCaddyfile(cfg)

	sbt := deploy.NewSubstore(cfg, "")
	sbt.SkipRestart = !restart
	if err := sbt.UpdateSubstoreConfig(sbs); err != nil {
		return fmt.Errorf("failed to update substore config: %w", err)
	}

	logger.Success("最新节点信息已成功同步至 SubHub！")
	fmt.Println("\n========================================================")
	fmt.Println("📡 已同步至 SubHub 的节点配置:")
	fmt.Printf("• Hysteria 2:    %s\n", sbs.ShareLinkHy2)
	fmt.Printf("• VLESS Reality: %s\n", sbs.ShareLinkVless)
	fmt.Println("========================================================")
	return nil
}

// NewInfoServerCmd creates the command to display server configuration, web admin panel, and node share links.
func NewInfoServerCmd(configPath string) *cobra.Command {
	return &cobra.Command{
		Use:     "info",
		Aliases: []string{"show", "status-info", "i"},
		Short:   "查看服务端核心配置、专属管理面板与节点订阅信息 / View server status, web admin panel and subscription info",
		RunE: func(cmd *cobra.Command, args []string) error {
			resolvedPath := resolveConfigPath(cmd, configPath)
			return showServerInfo(resolvedPath)
		},
	}
}

func showServerInfo(configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	if cfg.Server.GetNodeDomain() == "" {
		return fmt.Errorf("server.node_domain (or sb_domain) is required in config (%s)", configPath)
	}

	if cfg.Server.EnsureWebAdminCredentials() {
		_ = config.Save(configPath, cfg)
	}

	sbs, err := deploy.NewSingBoxServer(cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize sing-box server: %w", err)
	}

	if err := sbs.LoadExistingCredentials(); err != nil {
		logger.Warn("未能从现有 sing-box 配置文件加载凭证: %v", err)
	}

	sbt := deploy.NewSubstore(cfg, "")
	showUnifiedServerPanel(cfg, sbs, sbt, "📌 SingCtl 服务端核心配置与连接信息")
	return nil
}

func showUnifiedInstallSummary(cfg *config.Config, sbs *deploy.SingBoxServer, sbt *deploy.Substore) {
	showUnifiedServerPanel(cfg, sbs, sbt, "🎉 SingCtl 服务端全组件部署成功！")
}

func showUnifiedServerPanel(cfg *config.Config, sbs *deploy.SingBoxServer, sbt *deploy.Substore, title string) {
	domain := cfg.Server.GetSubstoreDomain()
	if domain == "" {
		domain = cfg.Server.GetNodeDomain()
	}
	adminPath := cfg.Server.GetWebAdminPath()
	adminURL := ""
	if domain != "" && adminPath != "" {
		adminURL = fmt.Sprintf("https://%s%s/", domain, adminPath)
	}

	subURL := ""
	if sbt != nil {
		subURL = sbt.GetSubscriptionURL()
	} else if domain != "" {
		subURL = fmt.Sprintf("https://%s/api/substore/download/singctl", domain)
	}

	versions := deploy.GetCoreServiceVersions()
	caddyVer := versions["caddy"]
	if caddyVer != "" {
		caddyVer = "v" + caddyVer
	} else {
		caddyVer = "已就绪"
	}

	sbVer := versions["singbox"]
	if sbVer != "" {
		sbVer = "v" + sbVer
	} else {
		sbVer = "已就绪"
	}

	ssVer := versions["subhub"]
	if ssVer != "" {
		ssVer = "v" + ssVer
	} else {
		ssVer = "已就绪"
	}

	warpVer := versions["warp"]
	if warpVer != "" {
		warpVer = "v" + warpVer
	} else {
		warpVer = "已就绪"
	}

	fmt.Println("\n══════════════════════════════════════════════════════════════════════════")
	fmt.Printf("                     %s\n", title)
	fmt.Println("══════════════════════════════════════════════════════════════════════════")
	fmt.Printf(" [✓] Caddy %-11s : TLS 证书申请成功，443 端口反代已就绪\n", caddyVer)
	fmt.Printf(" [✓] sing-box %-9s: VLESS Reality & Hysteria 2 双协议已启动\n", sbVer)
	fmt.Printf(" [✓] SubHub %-10s : Go 原生多协议订阅聚合转换已就绪 (端口 3001)\n", ssVer)
	fmt.Printf(" [✓] WARP 出口 %-8s: 本地分流出口已就绪 (端口 40000)\n", warpVer)
	fmt.Println("──────────────────────────────────────────────────────────────────────────")
	fmt.Println(" 🌐 专属管理控制台 (核心 Web 后台入口):")
	if adminURL != "" {
		fmt.Printf("   • 访问链接 : %s\n", adminURL)
	} else {
		fmt.Println("   • 访问链接 : [未配置后台路径]")
	}
	fmt.Printf("   • 管理账号 : %s\n", cfg.Server.GetWebAdminUsername())
	if config.IsHashedPassword(cfg.Server.GetWebAdminPassword()) {
		fmt.Println("   • 登录密码 : [已加密保护] (已确认保存并完成 bcrypt 单向加密，可在后台修改)")
	} else {
		fmt.Printf("   • 登录密码 : %s (登录后台后可随时修改)\n", cfg.Server.GetWebAdminPassword())
		fmt.Println("   • 请立即把密码写入密码管理器。终端滚动记录和截图都会留下这行。")
	}
	fmt.Println("   • 安全机制 : 纯会话 Cookie 认证，公网端口严密关闭，防爆破 3次错封IP 保护")
	fmt.Println("──────────────────────────────────────────────────────────────────────────")
	fmt.Println(" 📦 客户端全平台聚合订阅:")
	if subURL != "" {
		fmt.Printf("   • 订阅地址 : %s\n", subURL)
	} else {
		fmt.Printf("   • 订阅地址 : https://%s/api/substore/download/singctl\n", domain)
	}
	fmt.Println("   • 快速导入 : 登录上述管理控制台，可一键唤醒导入 Shadowrocket、")
	fmt.Println("                Clash Verge、Sing-box，或在网页端直接扫码导入。")

	if sbs != nil && (sbs.ShareLinkHy2 != "" || sbs.ShareLinkVless != "") {
		fmt.Println("──────────────────────────────────────────────────────────────────────────")
		fmt.Println(" 📡 服务端节点直连分享链接 (Node Share Links):")
		if sbs.ShareLinkHy2 != "" {
			fmt.Printf("   • Hysteria 2    : %s\n", sbs.ShareLinkHy2)
		}
		if sbs.ShareLinkVless != "" {
			fmt.Printf("   • VLESS Reality : %s\n", sbs.ShareLinkVless)
		}
	}

	fmt.Println("──────────────────────────────────────────────────────────────────────────")
	fmt.Println(" 🛡️ 伪装回落与辅助入口 (Mask Site & Fallback):")
	if serverIP := cfg.Server.GetServerIP(); serverIP != "" {
		fmt.Printf("   • 公网 IP 直连  : https://%s (Let's Encrypt 原生免费公网 IP 证书)\n", deploy.FormatIPForCaddy(serverIP))
	}
	if nodeDomain := cfg.Server.GetNodeDomain(); nodeDomain != "" {
		fmt.Printf("   • 节点域名伪装  : https://%s\n", nodeDomain)
	}
	if cfg.Server.WebTerminal.Enabled && cfg.Server.WebTerminal.Path != "" {
		terminalDomain := cfg.Server.GetNodeDomain()
		if terminalDomain == "" {
			terminalDomain = cfg.Server.GetSubstoreDomain()
		}
		if terminalDomain != "" {
			fmt.Printf("   • Web 运维终端   : https://%s%s/ (mTLS 双向认证保护)\n", terminalDomain, cfg.Server.WebTerminal.Path)
		}
	}

	fmt.Println("──────────────────────────────────────────────────────────────────────────")
	fmt.Println(" 💡 核心运维常用命令:")
	fmt.Println("   • 实时流量与分流雷达: singctl sr top")
	fmt.Println("   • 全链路健康体检   : singctl doctor")
	fmt.Println("   • 查看控制台访问信息: singctl sr info")
	fmt.Println("   • 多节点全球舰队管控: singctl fleet (list|sync|doctor|reset|update)")
	fmt.Println("   • 一键平滑升级组件 : singctl sr update [component|all]")
	fmt.Println("   • 一键解封受限 IP  : singctl sr web unban [IP|all]")
	fmt.Println("══════════════════════════════════════════════════════════════════════════")
	fmt.Println()
}
