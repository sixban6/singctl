package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"singctl/internal/config"
	"singctl/internal/deploy"
	"singctl/internal/logger"
	"singctl/internal/serverweb"

	"github.com/spf13/cobra"
)

// newServerWebCmd 创建服务端 UI 管理面板命令 (singctl sr ui)
func NewServerWebCmd(configPath string, version ...string) *cobra.Command {
	ver := "dev"
	if len(version) > 0 && strings.TrimSpace(version[0]) != "" {
		ver = strings.TrimSpace(version[0])
	}
	var listen string
	var username string
	var password string

	root := &cobra.Command{
		Use:     "ui",
		Aliases: []string{"web", "w"},
		Short:   "服务端管理面板服务 (singctl-ui) / Server Admin UI service (start|stop|restart|status|unban)",
		Long: `启动或管理 SingCtl 服务端管理面板 (singctl-ui.service)，通过 Caddy 自动反向代理与随机安全路径访问。

  singctl sr ui                    # 前台运行 (供 systemd 直接调用)
  singctl sr ui start              # 安装并启动 singctl-ui 守护服务
  singctl sr ui stop               # 停止 singctl-ui 守护服务
  singctl sr ui restart            # 重启 singctl-ui 守护服务并同步 Caddy 路由
  singctl sr ui status             # 查看运行状态与访问链接
  singctl sr ui unban [IP|all]     # 解封被限制登录的 IP`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				return fmt.Errorf("未知子命令: %q (可用: start, stop, restart, status, unban)", args[0])
			}

			resolvedConfig := resolveConfigPath(cmd, configPath)
			u, p := resolveServerWebCredentials(resolvedConfig, username, password)
			if cfg, err := config.Load(resolvedConfig); err == nil && cfg != nil {
				_ = deploy.SyncCaddyfile(cfg)
			}
			server := serverweb.New(serverweb.Options{
				ConfigPath: resolvedConfig,
				Listen:     listen,
				Username:   u,
				Password:   p,
				Version:    ver,
			})
			logger.Info("服务端管理面板前台运行中, 按 Ctrl+C 停止; 守护服务请使用: singctl sr ui start")
			return server.ListenAndServe()
		},
	}

	root.PersistentFlags().StringVarP(&listen, "listen", "l", serverweb.DefaultListenAddr,
		"监听地址 / Listen address (默认 127.0.0.1:8092)")
	root.PersistentFlags().StringVarP(&username, "username", "u", "",
		"管理员账号(留空自动从配置读取或生成) / Server UI username")
	root.PersistentFlags().StringVarP(&password, "password", "p", "",
		"管理密码(留空自动从配置读取或生成) / Server UI password")

	optsHelper := func() serverweb.Options {
		resolvedConfig := resolveConfigPath(root, configPath)
		u, p := resolveServerWebCredentials(resolvedConfig, username, password)
		return serverweb.Options{
			ConfigPath: resolvedConfig,
			Listen:     listen,
			Username:   u,
			Password:   p,
			Version:    ver,
		}
	}

	root.AddCommand(
		newServerWebStartCmd(optsHelper),
		newServerWebStopCmd(),
		newServerWebRestartCmd(optsHelper),
		newServerWebStatusCmd(configPath),
		newServerWebUnbanCmd(configPath),
	)

	return root
}

func resolveServerWebCredentials(cfgPath, userFlag, passFlag string) (string, string) {
	username := userFlag
	password := passFlag
	if password == "" {
		password = os.Getenv("SINGCTL_SERVER_WEB_PASSWORD")
	}
	if cfg, err := config.Load(cfgPath); err == nil && cfg != nil {
		if cfg.Server.EnsureWebAdminCredentials() {
			_ = config.Save(cfgPath, cfg)
		}
		if username == "" {
			username = cfg.Server.GetWebAdminUsername()
		}
		if password == "" {
			password = cfg.Server.GetWebAdminPassword()
		}
	}
	if username == "" {
		username = "admin"
	}
	return username, password
}

func printServerUIAccessSummary(o serverweb.Options) {
	if cfg, err := config.Load(o.ConfigPath); err == nil && cfg != nil {
		if err := deploy.SyncCaddyfile(cfg); err != nil {
			logger.Warn("同步 Caddy 路由失败 (非致命): %v", err)
		}
		domain := cfg.Server.GetSubstoreDomain()
		if domain == "" {
			domain = cfg.Server.GetNodeDomain()
		}
		adminPath := cfg.Server.GetWebAdminPath()
		if domain != "" && adminPath != "" {
			logger.Success("  ➜  HTTPS 面板专属访问地址: https://%s%s/", domain, adminPath)
		}
		logger.Info("  ➜  管理员账号: %s", o.Username)
		if o.Password != "" && cfg.Server.WebAdmin.PasswordPendingAck && !config.IsHashedPassword(o.Password) {
			logger.Info("  ➜  管理密码: %s", o.Password)
			logger.Info("  ➜  此密码在你于面板确认已保存之前才会显示。请写入密码管理器，终端记录和截图都会留下它。")
		}
	}
}

func newServerWebStartCmd(opts func() serverweb.Options) *cobra.Command {
	return &cobra.Command{
		Use:   "start",
		Short: "安装并启动 singctl-ui 守护服务 / Install and start singctl-ui service",
		RunE: func(_ *cobra.Command, _ []string) error {
			o := opts()
			if err := serverweb.InstallService(o.ConfigPath); err != nil {
				return err
			}
			logger.Success("服务端管理面板 (singctl-ui) 已启动")
			printServerUIAccessSummary(o)
			return nil
		},
	}
}

func newServerWebRestartCmd(opts func() serverweb.Options) *cobra.Command {
	return &cobra.Command{
		Use:     "restart",
		Aliases: []string{"r"},
		Short:   "重启 singctl-ui 守护服务 / Restart singctl-ui service",
		RunE: func(_ *cobra.Command, _ []string) error {
			o := opts()
			if err := serverweb.RestartService(); err != nil {
				return err
			}
			if !serverweb.IsRunning(o.ConfigPath) {
				if err := serverweb.InstallService(o.ConfigPath); err != nil {
					return err
				}
			}
			logger.Success("服务端管理面板 (singctl-ui) 已重启")
			printServerUIAccessSummary(o)
			return nil
		},
	}
}

func newServerWebStopCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "stop",
		Short: "停止 singctl-ui 守护服务 / Stop singctl-ui service",
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := serverweb.StopService(); err != nil {
				return err
			}
			logger.Success("服务端管理面板 (singctl-ui) 已停止")
			return nil
		},
	}
}

func newServerWebStatusCmd(configPath string) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "查看 singctl-ui 运行状态与访问地址 / Show singctl-ui service status",
		RunE: func(cmd *cobra.Command, _ []string) error {
			resolvedCfg := resolveConfigPath(cmd, configPath)
			if !serverweb.IsRunning(resolvedCfg) {
				logger.Warn("服务端管理面板 (singctl-ui) 当前未运行 (可执行 'singctl sr ui start' 启动)")
				return nil
			}
			logger.Success("服务端管理面板 (singctl-ui) 运行中")
			if cfg, err := config.Load(resolvedCfg); err == nil && cfg != nil {
				logger.Info("  ➜  本地监听: http://127.0.0.1:%d", cfg.Server.GetWebAdminPort())
				domain := cfg.Server.GetSubstoreDomain()
				if domain == "" {
					domain = cfg.Server.GetNodeDomain()
				}
				adminPath := cfg.Server.GetWebAdminPath()
				if domain != "" && adminPath != "" {
					logger.Success("  ➜  HTTPS 面板专属访问地址: https://%s%s/", domain, adminPath)
				}
				logger.Info("  ➜  管理员账号: %s", cfg.Server.GetWebAdminUsername())
			}
			return nil
		},
	}
}

func newServerWebUnbanCmd(configPath string) *cobra.Command {
	return &cobra.Command{
		Use:   "unban [IP|all]",
		Short: "解封被限制登录的 IP (默认解封全部) / Unban locked IP address (default all)",
		RunE: func(cmd *cobra.Command, args []string) error {
			targetIP := "all"
			if len(args) > 0 && strings.TrimSpace(args[0]) != "" {
				targetIP = strings.TrimSpace(args[0])
			}

			resolvedConfig := resolveConfigPath(cmd, configPath)
			port := 8092
			var adminUser, adminPass string
			if cfg, err := config.Load(resolvedConfig); err == nil && cfg != nil {
				port = cfg.Server.GetWebAdminPort()
				adminUser = cfg.Server.GetWebAdminUsername()
				adminPass = cfg.Server.GetWebAdminPassword()
			} else if err != nil {
				logger.Warn("读取配置失败，尝试直接清理本地持久化封禁记录: %v", err)
			}

			banFile := serverweb.ResolveBanFilePath(resolvedConfig)
			cliToken := ""
			if rawTok, err := os.ReadFile(serverweb.ResolveCLITokenPath(resolvedConfig)); err == nil {
				cliToken = strings.TrimSpace(string(rawTok))
			}

			url := fmt.Sprintf("http://127.0.0.1:%d/api/server/unban", port)
			bodyBytes, _ := json.Marshal(map[string]string{"ip": targetIP})
			req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(bodyBytes))
			if err != nil {
				return err
			}
			req.Header.Set("Content-Type", "application/json")
			if cliToken != "" {
				req.Header.Set("Authorization", "Bearer "+cliToken)
			} else if adminPass != "" && !config.IsHashedPassword(adminPass) {
				req.SetBasicAuth(adminUser, adminPass)
			}

			client := &http.Client{Timeout: 3 * time.Second}
			resp, err := client.Do(req)
			if err != nil {
				if fErr := serverweb.UnbanPersistedIP(banFile, targetIP); fErr == nil {
					logger.Success("服务端管理面板当前未连接，已直接清理本地封禁文件 (%s)", targetIP)
					return nil
				}
				logger.Warn("向服务端管理面板发送解封请求失败: %v", err)
				logger.Info("提示: 重启服务可直接重置全部封禁: singctl sr ui restart")
				return nil
			}
			defer resp.Body.Close()

			if resp.StatusCode == http.StatusOK {
				logger.Success("已成功解封 IP: %s", targetIP)
			} else {
				_ = serverweb.UnbanPersistedIP(banFile, targetIP)
				logger.Warn("在线解封响应状态 %s，已同步清理磁盘封禁记录；如仍受限可执行 singctl sr ui restart", resp.Status)
			}
			return nil
		},
	}
}
