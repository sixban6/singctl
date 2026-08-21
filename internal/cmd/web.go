package cmd

import (
	"fmt"
	"os"

	"singctl/internal/logger"
	"singctl/internal/webui"

	"github.com/spf13/cobra"
)

// NewWebCmd 创建 Web 管理界面命令
func NewWebCmd(version string) *cobra.Command {
	var listen string
	var password string

	root := &cobra.Command{
		Use:     "web",
		Aliases: []string{"w"},
		Short:   "网页  : 启动Web管理界面(简写singctl w)",
		Long: `启动 SingCtl Web 管理界面,在浏览器中管理 sing-box、守护进程、Tailscale、防火墙和配置。

  singctl web                          # 前台运行(Ctrl+C 停止,适合调试)
  singctl web start                    # 后台启动(推荐)
  singctl web stop                     # 停止后台 WebUI (简写 singctl w s)
  singctl web status                   # 查看后台运行状态
  singctl web -l 192.168.1.1:8090      # 指定监听地址
  singctl web --password secret        # 启用 Basic Auth(admin/secret)

也可通过环境变量 SINGCTL_WEB_PASSWORD 设置口令。
OpenWrt 开机自启请参考 docs/webui.md 的 procd 配置。`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				return fmt.Errorf("未知子命令: %q (可用: start, stop, status)", args[0])
			}

			configPath := cmd.Flag("config").Value.String()
			server := webui.New(webui.Options{
				ConfigPath: configPath,
				Listen:     listen,
				Password:   resolveWebPassword(password),
				Version:    version,
			})
			logger.Info("前台运行中,按 Ctrl+C 停止;后台模式请使用: singctl web start")
			return server.ListenAndServe()
		},
	}

	// PersistentFlags: 子命令(start/stop/status)同样可以指定 -l/-p
	root.PersistentFlags().StringVarP(&listen, "listen", "l", ":8090",
		"监听地址 / Listen address (e.g. :8090 or 127.0.0.1:8090)")
	root.PersistentFlags().StringVarP(&password, "password", "p", "",
		"访问口令(用户名固定 admin,留空则不鉴权) / Web UI password (username: admin)")

	root.AddCommand(
		newWebStartCmd(func() webui.Options {
			return webui.Options{
				ConfigPath: root.Flag("config").Value.String(),
				Listen:     listen,
				Password:   resolveWebPassword(password),
				Version:    version,
			}
		}),
		newWebStopCmd(),
		newWebStatusCmd(),
	)

	return root
}

func resolveWebPassword(password string) string {
	if password == "" {
		return os.Getenv("SINGCTL_WEB_PASSWORD")
	}
	return password
}

func newWebStartCmd(opts func() webui.Options) *cobra.Command {
	return &cobra.Command{
		Use:   "start",
		Short: "后台启动 WebUI / Start WebUI in background",
		RunE: func(cmd *cobra.Command, args []string) error {
			// 子进程路径:直接运行服务,Listen 成功后握手通知父进程
			if webui.IsBackgroundChild() {
				webui.InstallChildSignalCleanup()
				o := opts()
				o.OnReady = webui.ChildReady
				return webui.New(o).ListenAndServe()
			}
			// 父进程路径:fork 后台子进程并等待就绪
			return webui.StartBackground(opts())
		},
	}
}

func newWebStopCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "stop",
		Aliases: []string{"s"},
		Short:   "停止后台 WebUI / Stop background WebUI",
		RunE: func(cmd *cobra.Command, args []string) error {
			stopped, err := webui.StopWeb()
			if err != nil {
				return err
			}
			if stopped {
				logger.Success("WebUI 已停止")
			} else {
				logger.Warn("WebUI 未在运行")
			}
			return nil
		},
	}
}

func newWebStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "status",
		Aliases: []string{"st"},
		Short:   "查看后台 WebUI 状态 / Show background WebUI status",
		RunE: func(cmd *cobra.Command, args []string) error {
			st, running := webui.WebStatus()
			if !running {
				logger.Info("WebUI 未在后台运行 (启动: singctl web start)")
				return nil
			}
			logger.Success("WebUI 后台运行中 (pid=%d)", st.Pid)
			for _, u := range webui.ListenURLs(st.Listen) {
				logger.Info("  ➜  http://%s", u)
			}
			logger.Info("日志: %s   状态: %s", webui.WebLogPath(), webui.WebStatePath())
			return nil
		},
	}
}
