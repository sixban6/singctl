// 文件职责：提供客户端 WebUI (`singctl web` / `singctl w`) 前后台启停、状态查询及单进程合体模式无缝兼容子命令。
package cmd

import (
	"context"
	"fmt"
	"os/signal"
	"syscall"

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
	var managed bool
	var noService bool
	var clearPassword bool

	root := &cobra.Command{
		Use:     "web",
		Aliases: []string{"w"},
		Short:   "网页  : 启动Web管理界面(简写singctl w)",
		Long: `启动 SingCtl Web 管理界面,在浏览器中管理 sing-box、守护进程、Tailscale、防火墙和配置。

  singctl web                          # 前台运行(Ctrl+C 停止,适合调试)
  singctl web start                    # 后台启动(Linux/OpenWrt 自动注册开机自启与崩溃拉起守护)
  singctl web stop                     # 停止后台 WebUI (简写 singctl w s)
  singctl web status                   # 查看后台运行状态
  singctl web -l 192.168.1.1:8090      # 指定监听地址
  singctl web --password secret        # 启用 Basic Auth(admin/secret)

也可通过环境变量 SINGCTL_WEB_PASSWORD 设置口令。`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				return fmt.Errorf("未知子命令: %q (可用: start, stop, status)", args[0])
			}

			configPath := cmd.Flag("config").Value.String()
			opts := webui.Options{
				ConfigPath: configPath,
				Listen:     listen,
				Password:   webui.ResolveWebPassword(password, configPath),
				Version:    version,
			}
			if managed {
				cleanup, managedBy := webui.SetupManagedRuntime(opts)
				defer cleanup()
				opts.OnReady = func(actualListen string) {
					webui.WriteManagedReadyState(opts, actualListen, managedBy)
				}
				sigCtx, stopSig := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
				defer stopSig()
				return webui.New(opts).ServeContext(sigCtx)
			}
			server := webui.New(opts)
			logger.Info("前台运行中,按 Ctrl+C 停止;后台模式请使用: singctl web start")
			return server.ListenAndServe()
		},
	}

	// PersistentFlags: 子命令(start/stop/status)同样可以指定 -l/-p
	root.PersistentFlags().StringVarP(&listen, "listen", "l", ":8090",
		"监听地址 / Listen address (e.g. :8090 or 127.0.0.1:8090)")
	root.PersistentFlags().StringVarP(&password, "password", "p", "",
		"访问口令(用户名固定 admin,留空则不鉴权) / Web UI password (username: admin)")
	root.Flags().BoolVar(&managed, "managed", false, "由 procd/systemd 系统服务托管运行（内部标志）")
	_ = root.Flags().MarkHidden("managed")

	startCmd := newWebStartCmd(func() webui.Options {
		cfgPath := root.Flag("config").Value.String()
		resolvedPw := webui.ResolveWebPassword(password, cfgPath)
		if clearPassword {
			resolvedPw = ""
		}
		return webui.Options{
			ConfigPath:    cfgPath,
			Listen:        listen,
			Password:      resolvedPw,
			NoService:     noService,
			ClearPassword: clearPassword,
			Version:       version,
		}
	}, deps.Background)
	startCmd.Flags().BoolVar(&noService, "no-service", false, "禁用 procd/systemd 自动托管，仅以独立后台进程启动")
	startCmd.Flags().BoolVar(&clearPassword, "clear-password", false, "清空已保存的 0600 访问口令文件")

	root.AddCommand(
		startCmd,
		newWebStopCmd(deps.Background),
		newWebRestartCmd(func() string {
			return root.Flag("config").Value.String()
		}, deps.Background),
		newWebStatusCmd(deps.Background),
	)

	return root
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
			// 父进程路径:若已内嵌于守护进程则幂等返回成功，否则自动走系统服务托管或独立后台模式
			if bgDeps.EmbeddedStatus == nil && bgDeps.RestartDaemon == nil && bgDeps.ServiceMgr == nil {
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
			stopped, err := webui.StopWebWithDeps(bgDeps)
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
			if st.ManagedBy != "" {
				if st.Pid > 0 {
					logger.Success("WebUI 后台运行中 (%s 系统服务托管, pid=%d)", st.ManagedBy, st.Pid)
				} else {
					logger.Success("WebUI 后台运行中 (%s 系统服务托管)", st.ManagedBy)
				}
			} else {
				logger.Success("WebUI 后台运行中 (pid=%d)", st.Pid)
			}
			for _, u := range webui.ListenURLs(st.Listen) {
				logger.Info("  ➜  http://%s", u)
			}
			logger.Info("日志: %s   状态: %s", webui.WebLogPath(), webui.WebStatePath())
			return nil
		},
	}
}
