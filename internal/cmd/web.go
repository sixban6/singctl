// 文件职责：提供客户端 WebUI (`singctl web` / `singctl w`) 前后台启停、状态查询及单进程合体模式无缝兼容子命令。
package cmd

import (
	"fmt"
	"os"

	"singctl/internal/daemon"
	"singctl/internal/logger"
	"singctl/internal/webui"

	"github.com/spf13/cobra"
)

// WebCmdDeps 显式注入 Web 子命令的后台状态与重启依赖（供离线单测驱动合体模式分支）。
type WebCmdDeps struct {
	Background webui.BackgroundDeps
}

// NewWebCmd 创建 Web 管理界面命令
func NewWebCmd(version string) *cobra.Command {
	return NewWebCmdWithDeps(version, WebCmdDeps{})
}

// NewWebCmdWithDeps 使用显式依赖创建 Web 管理界面命令。
func NewWebCmdWithDeps(version string, deps WebCmdDeps) *cobra.Command {
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
		}, deps.Background),
		newWebStopCmd(deps.Background),
		newWebRestartCmd(func() string {
			return root.Flag("config").Value.String()
		}, deps.Background),
		newWebStatusCmd(deps.Background),
	)

	return root
}

func resolveWebPassword(password string) string {
	if password != "" {
		return password
	}
	// 逆序扫描环境变量（兼容旧版 <= v1.14.126 ScheduleDetachedRestart 使用 append 追加同名 SINGCTL_WEB_PASSWORD 的场景，取最新非空值）
	env := os.Environ()
	for i := len(env) - 1; i >= 0; i-- {
		if k, v, ok := cutEnv(env[i]); ok && k == "SINGCTL_WEB_PASSWORD" && v != "" {
			return v
		}
	}
	return os.Getenv("SINGCTL_WEB_PASSWORD")
}

func cutEnv(kv string) (string, string, bool) {
	for i := 0; i < len(kv); i++ {
		if kv[i] == '=' {
			return kv[:i], kv[i+1:], true
		}
	}
	return "", "", false
}

func newWebStartCmd(opts func() webui.Options, bgDeps webui.BackgroundDeps) *cobra.Command {
	return &cobra.Command{
		Use:   "start",
		Short: "后台启动 WebUI / Start WebUI in background",
		RunE: func(cmd *cobra.Command, args []string) error {
			// 子进程路径:直接运行服务,Listen 成功后握手通知父进程并记录原始配置/监听/口令
			if webui.IsBackgroundChild() {
				webui.InstallChildSignalCleanup()
				o := opts()
				o.OnReady = func(actualListen string) {
					webui.ChildReadyWithOptions(o, actualListen)
				}
				return webui.New(o).ListenAndServe()
			}
			// 父进程路径:若已内嵌于守护进程则幂等返回成功，否则 fork 后台子进程并等待就绪
			if bgDeps.EmbeddedStatus == nil && bgDeps.RestartDaemon == nil {
				return webui.StartBackground(opts())
			}
			return webui.StartBackgroundWithDeps(opts(), bgDeps)
		},
	}
}

func newWebRestartCmd(configPath func() string, bgDeps webui.BackgroundDeps) *cobra.Command {
	return &cobra.Command{
		Use:     "restart",
		Aliases: []string{"r"},
		Short:   "平滑重启后台 WebUI / Restart background WebUI",
		RunE: func(cmd *cobra.Command, args []string) error {
			if !webui.IsWebRunningOrManagedWithDeps(bgDeps) {
				logger.Warn("WebUI 未在运行，请使用: singctl web start")
				return nil
			}
			st, _ := webui.WebStatusWithDeps(bgDeps)
			if err := webui.RestartWebWithDeps(configPath(), bgDeps); err != nil {
				return err
			}
			if st.Embedded {
				logger.Success("已联动平滑重启合体守护进程与内嵌 WebUI")
			}
			return nil
		},
	}
}

func newWebStopCmd(bgDeps webui.BackgroundDeps) *cobra.Command {
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
				return nil
			}
			if st, ok := webui.WebStatusWithDeps(bgDeps); ok && st.Embedded {
				logger.Warn("WebUI 运行中 (内嵌于守护进程 pid=%d, 低内存单进程合体模式)；如需一并停止请执行: singctl dm stop", st.Pid)
				return nil
			}
			logger.Warn("WebUI 未在运行")
			return nil
		},
	}
}

func newWebStatusCmd(bgDeps webui.BackgroundDeps) *cobra.Command {
	return &cobra.Command{
		Use:     "status",
		Aliases: []string{"st"},
		Short:   "查看后台 WebUI 状态 / Show background WebUI status",
		RunE: func(cmd *cobra.Command, args []string) error {
			st, running := webui.WebStatusWithDeps(bgDeps)
			if !running {
				logger.Info("WebUI 未在后台运行 (启动: singctl web start)")
				return nil
			}
			if st.Embedded {
				logger.Success("WebUI 运行中 (内嵌于守护进程 pid=%d, 低内存单进程合体模式)", st.Pid)
				for _, u := range webui.ListenURLs(st.Listen) {
					logger.Info("  ➜  http://%s", u)
				}
				logger.Info("日志: %s   状态: %s", daemon.GetDaemonLogPath(), daemon.GetWebEmbeddedPath())
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
