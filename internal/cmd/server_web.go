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
	"singctl/internal/logger"
	"singctl/internal/serverweb"

	"github.com/spf13/cobra"
)

// newServerWebCmd 创建服务端 Web 管理命令
func newServerWebCmd(configPath string) *cobra.Command {
	var listen string
	var username string
	var password string

	root := &cobra.Command{
		Use:     "web",
		Aliases: []string{"w", "ui"},
		Short:   "服务端Web管理面板 / Server WebUI admin dashboard",
		Long: `启动 SingCtl 服务端 Web 管理界面，通过 Caddy 自动反向代理与随机安全路径访问。
在浏览器中查看节点链接与二维码、管理组件状态、热切 SNI 伪装域名、在线修改账号密码、轮换 Cloudflare Token 及实时查看日志。

  singctl sr web                   # 前台运行
  singctl sr web start             # 后台启动 (默认通过 Caddy HTTPS 自动反代)
  singctl sr web stop              # 停止后台服务
  singctl sr web status            # 查看后台运行状态与访问链接
  singctl sr web -l 127.0.0.1:8092 # 指定监听端口`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				return fmt.Errorf("未知子命令: %q (可用: start, stop, status)", args[0])
			}

			resolvedConfig := resolveConfigPath(cmd, configPath)
			u, p := resolveServerWebCredentials(resolvedConfig, username, password)
			server := serverweb.New(serverweb.Options{
				ConfigPath: resolvedConfig,
				Listen:     listen,
				Username:   u,
				Password:   p,
				Version:    "1.0.0",
			})
			logger.Info("服务端 WebUI 前台运行中, 按 Ctrl+C 停止; 后台模式请使用: singctl sr web start")
			return server.ListenAndServe()
		},
	}

	root.PersistentFlags().StringVarP(&listen, "listen", "l", "127.0.0.1:8092",
		"监听地址 / Listen address (默认 127.0.0.1:8092)")
	root.PersistentFlags().StringVarP(&username, "username", "u", "",
		"管理员账号(留空自动从配置读取或生成) / Server Web UI username")
	root.PersistentFlags().StringVarP(&password, "password", "p", "",
		"管理密码(留空自动从配置读取或生成) / Server Web UI password")

	root.AddCommand(
		newServerWebStartCmd(func() serverweb.Options {
			resolvedConfig := resolveConfigPath(root, configPath)
			u, p := resolveServerWebCredentials(resolvedConfig, username, password)
			return serverweb.Options{
				ConfigPath: resolvedConfig,
				Listen:     listen,
				Username:   u,
				Password:   p,
				Version:    "1.0.0",
			}
		}),
		newServerWebStopCmd(),
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

func newServerWebStartCmd(opts func() serverweb.Options) *cobra.Command {
	return &cobra.Command{
		Use:   "start",
		Short: "后台启动服务端 WebUI / Start Server WebUI in background",
		RunE: func(cmd *cobra.Command, args []string) error {
			o := opts()
			if serverweb.IsBackgroundChild() {
				o.OnReady = serverweb.ChildReady
				return serverweb.New(o).ListenAndServe()
			}
			if err := serverweb.StartBackground(o); err != nil {
				return err
			}
			if cfg, err := config.Load(o.ConfigPath); err == nil && cfg != nil {
				domain := cfg.Server.GetSubstoreDomain()
				if domain == "" {
					domain = cfg.Server.GetNodeDomain()
				}
				adminPath := cfg.Server.GetWebAdminPath()
				if domain != "" && adminPath != "" {
					logger.Success("  ➜  HTTPS Caddy 专属访问地址: https://%s%s/", domain, adminPath)
				}
				logger.Info("  ➜  管理员账号: %s", o.Username)
				if o.Password != "" {
					logger.Info("  ➜  管理密码: %s", o.Password)
				}
			}
			return nil
		},
	}
}

func newServerWebStopCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "stop",
		Short: "停止后台服务端 WebUI / Stop background Server WebUI",
		RunE: func(cmd *cobra.Command, args []string) error {
			stopped, err := serverweb.StopServerWeb()
			if err != nil {
				return err
			}
			if stopped {
				logger.Success("服务端 WebUI 已停止")
			} else {
				logger.Info("服务端 WebUI 未在运行")
			}
			return nil
		},
	}
}

func newServerWebStatusCmd(configPath string) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "查看后台服务端 WebUI 状态 / Show background Server WebUI status",
		RunE: func(cmd *cobra.Command, args []string) error {
			st, running := serverweb.ServerWebStatus()
			if !running {
				logger.Info("服务端 WebUI 未在运行")
				return nil
			}
			logger.Success("服务端 WebUI 后台运行中 (pid=%d)", st.Pid)
			logger.Info("  ➜  本地监听: http://%s", st.Listen)
			if cfg, err := config.Load(resolveConfigPath(cmd, configPath)); err == nil && cfg != nil {
				domain := cfg.Server.GetSubstoreDomain()
				if domain == "" {
					domain = cfg.Server.GetNodeDomain()
				}
				adminPath := cfg.Server.GetWebAdminPath()
				if domain != "" && adminPath != "" {
					logger.Success("  ➜  HTTPS Caddy 专属访问地址: https://%s%s/", domain, adminPath)
				}
				logger.Info("  ➜  管理员账号: %s", cfg.Server.GetWebAdminUsername())
			}
			logger.Info("日志: %s   状态: %s", serverweb.ServerWebLogPath(), serverweb.ServerWebStatePath())
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
			if cfg, err := config.Load(resolvedConfig); err == nil && cfg != nil {
				port = cfg.Server.GetWebAdminPort()
			}

			url := fmt.Sprintf("http://127.0.0.1:%d/api/server/unban", port)
			bodyBytes, _ := json.Marshal(map[string]string{"ip": targetIP})
			req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(bodyBytes))
			if err != nil {
				return err
			}
			req.Header.Set("Content-Type", "application/json")

			client := &http.Client{Timeout: 3 * time.Second}
			resp, err := client.Do(req)
			if err != nil {
				logger.Warn("向服务端 Web 发送解封请求失败: %v", err)
				logger.Info("提示: 重启服务可直接重置全部封禁: systemctl restart singctl-serverweb")
				return nil
			}
			defer resp.Body.Close()

			if resp.StatusCode == http.StatusOK {
				logger.Success("已成功解封 IP: %s", targetIP)
			} else {
				logger.Warn("解封请求响应状态: %s", resp.Status)
			}
			return nil
		},
	}
}
