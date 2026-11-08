package cmd

import (
	"strings"

	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/deploy"
	"singctl/internal/logger"
	"singctl/internal/subhub"

	"github.com/spf13/cobra"
)

func newServerSubCmd(configPath string, version ...string) *cobra.Command {
	ver := "dev"
	if len(version) > 0 && strings.TrimSpace(version[0]) != "" {
		ver = strings.TrimSpace(version[0])
	}

	var listen string

	root := &cobra.Command{
		Use:     "sub",
		Aliases: []string{"substore", "subhub"},
		Short:   "原生多协议订阅聚合引擎管理 / Native SubHub subscription engine (serve|start|stop|restart|status|rotate-key)",
	}

	serveCmd := &cobra.Command{
		Use:   "serve",
		Short: "前台运行 SubHub 订阅转换 HTTP 服务 / Run SubHub HTTP server in foreground",
		RunE: func(cmd *cobra.Command, _ []string) error {
			resolvedCfg := resolveConfigPath(cmd, configPath)
			srv := subhub.NewServer(subhub.Options{
				Listen:     listen,
				ConfigPath: resolvedCfg,
				DataDir:    constant.SubStoreDir,
				FilePath:   constant.SubStoreFile,
				Version:    ver,
			})
			return srv.Start()
		},
	}
	serveCmd.Flags().StringVarP(&listen, "listen", "l", subhub.DefaultListenAddr, "HTTP 监听地址 / Listen address")

	startCmd := &cobra.Command{
		Use:   "start",
		Short: "安装并启动 singctl-sub 后台守护进程 / Install and start singctl-sub service",
		RunE: func(cmd *cobra.Command, _ []string) error {
			resolvedCfg := resolveConfigPath(cmd, configPath)
			cfg, _ := config.Load(resolvedCfg)
			sbt := deploy.NewSubstore(cfg, "")
			sbt.ConfigPath = resolvedCfg
			return sbt.DeploySubstore()
		},
	}

	stopCmd := &cobra.Command{
		Use:   "stop",
		Short: "停止 singctl-sub 后台守护进程 / Stop singctl-sub service",
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := subhub.StopService(); err != nil {
				return err
			}
			logger.Success("SubHub 订阅服务已停止")
			return nil
		},
	}

	restartCmd := &cobra.Command{
		Use:     "restart",
		Aliases: []string{"r"},
		Short:   "重启 singctl-sub 后台守护进程 / Restart singctl-sub service",
		RunE: func(cmd *cobra.Command, _ []string) error {
			resolvedCfg := resolveConfigPath(cmd, configPath)
			if err := subhub.RestartService(); err != nil {
				return err
			}
			if !subhub.IsRunning() {
				cfg, _ := config.Load(resolvedCfg)
				sbt := deploy.NewSubstore(cfg, "")
				sbt.ConfigPath = resolvedCfg
				return sbt.DeploySubstore()
			}
			logger.Success("SubHub 订阅服务已重启")
			return nil
		},
	}

	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "查看 SubHub 运行状态与订阅地址 / Show SubHub service status and subscription URL",
		RunE: func(cmd *cobra.Command, _ []string) error {
			resolvedCfg := resolveConfigPath(cmd, configPath)
			cfg, _ := config.Load(resolvedCfg)
			st := subhub.NewStore(constant.SubStoreDir, constant.SubStoreFile)
			sources, _ := st.ListSources()

			if subhub.IsRunning() {
				verStr := deploy.GetInstalledSubhubVersion()
				if verStr != "" {
					logger.Success("SubHub 原生订阅引擎运行中 (v%s, 监听 http://%s)", verStr, subhub.DefaultListenAddr)
				} else {
					logger.Success("SubHub 原生订阅引擎运行中 (监听 http://%s)", subhub.DefaultListenAddr)
				}
			} else {
				logger.Warn("SubHub 原生订阅引擎当前未运行 (可执行 'singctl sr sub start' 启动)")
			}

			logger.Info("  ➜  已配置订阅源数量: %d", len(sources))
			sbt := deploy.NewSubstore(cfg, "")
			if subURL := sbt.GetSubscriptionURL(); subURL != "" {
				logger.Info("  ➜  客户端聚合订阅链接: %s", subURL)
			}
			return nil
		},
	}

	rotateKeyCmd := &cobra.Command{
		Use:   "rotate-key",
		Short: "轮换订阅访问密钥并同步更新 Caddy 路由 / Rotate subscription secret key and reload Caddy",
		RunE: func(cmd *cobra.Command, _ []string) error {
			resolvedCfg := resolveConfigPath(cmd, configPath)
			cfg, _ := config.Load(resolvedCfg)
			st := subhub.NewStore(constant.SubStoreDir, constant.SubStoreFile)
			newKey, err := st.RotateKey()
			if err != nil {
				return err
			}
			if cfg != nil {
				if err := deploy.SyncCaddyfile(cfg); err != nil {
					logger.Warn("同步更新 Caddyfile 路由警告: %v", err)
				}
			}
			sbt := deploy.NewSubstore(cfg, newKey)
			logger.Success("订阅密钥已成功轮换！旧订阅链接已立即失效。")
			if subURL := sbt.GetSubscriptionURL(); subURL != "" {
				logger.Info("  ➜  最新全平台订阅链接: %s", subURL)
			}
			return nil
		},
	}

	root.AddCommand(serveCmd, startCmd, stopCmd, restartCmd, statusCmd, rotateKeyCmd)
	return root
}
