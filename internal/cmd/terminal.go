package cmd

import (
	"fmt"
	"strings"

	"singctl/internal/config"
	"singctl/internal/logger"
	"singctl/internal/terminal"

	"github.com/spf13/cobra"
)

// NewTerminalCmd creates the terminal management command
func NewTerminalCmd(configPath string) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "term [command]",
		Aliases: []string{"terminal", "gotty"},
		Short:   "终端  : 管理基于 mTLS 双向认证的 Web 终端 (GoTTY + Tmux)",
		Long: `管理基于 GoTTY + Tmux + Caddy mTLS 双向 TLS 认证的持久化 Web 运维终端。
未持有客户端证书的访问直接返回 404，与原有代理流量完全隔离、互不干扰。`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	cmd.AddCommand(
		newInstallTerminalCmd(configPath),
		newUninstallTerminalCmd(configPath),
		newStatusTerminalCmd(configPath),
		newCertTerminalCmd(configPath),
	)

	return cmd
}

func newInstallTerminalCmd(configPath string) *cobra.Command {
	var path string
	var port int
	var password string
	var force bool

	cmd := &cobra.Command{
		Use:     "install",
		Aliases: []string{"i"},
		Short:   "一键安装并配置 Web 终端 (GoTTY + Tmux + mTLS)",
		RunE: func(cmd *cobra.Command, args []string) error {
			resolvedPath := resolveConfigPath(cmd, configPath)
			cfg, err := config.Load(resolvedPath)
			if err != nil {
				return fmt.Errorf("加载配置失败: %w", err)
			}

			opts := terminal.InstallOptions{
				Path:     path,
				Port:     port,
				Password: password,
				Force:    force,
			}

			res, err := terminal.Install(cfg, resolvedPath, opts)
			if err != nil {
				return err
			}

			printInstallSummary(res)
			return nil
		},
	}

	cmd.Flags().StringVar(&path, "path", "", "隐蔽访问路径 (默认自动生成高强度随机路径，如 /term-8f9a2b)")
	cmd.Flags().IntVar(&port, "port", terminal.DefaultTerminalPort, "GoTTY 本地监听端口 (仅监听 127.0.0.1)")
	cmd.Flags().StringVar(&password, "password", "", "客户端证书 (.p12) 导出密码 (默认自动生成)")
	cmd.Flags().BoolVarP(&force, "force", "f", false, "强制重新生成证书与覆盖安装")

	return cmd
}

func newUninstallTerminalCmd(configPath string) *cobra.Command {
	return &cobra.Command{
		Use:     "uninstall",
		Aliases: []string{"u"},
		Short:   "卸载 Web 终端与相关证书，恢复 Caddy 路由",
		RunE: func(cmd *cobra.Command, args []string) error {
			resolvedPath := resolveConfigPath(cmd, configPath)
			cfg, err := config.Load(resolvedPath)
			if err != nil {
				return fmt.Errorf("加载配置失败: %w", err)
			}

			return terminal.Uninstall(cfg, resolvedPath)
		},
	}
}

func newStatusTerminalCmd(configPath string) *cobra.Command {
	return &cobra.Command{
		Use:     "status",
		Aliases: []string{"s"},
		Short:   "查看 Web 终端运行状态与访问路径",
		RunE: func(cmd *cobra.Command, args []string) error {
			resolvedPath := resolveConfigPath(cmd, configPath)
			cfg, err := config.Load(resolvedPath)
			if err != nil {
				return fmt.Errorf("加载配置失败: %w", err)
			}

			st, err := terminal.Status(cfg)
			if err != nil {
				return err
			}

			printStatusSummary(st)
			return nil
		},
	}
}

func newCertTerminalCmd(configPath string) *cobra.Command {
	return &cobra.Command{
		Use:     "cert",
		Aliases: []string{"c", "client-cert"},
		Short:   "查看/导出客户端 mTLS 证书 (.p12) 与导入指引",
		RunE: func(cmd *cobra.Command, args []string) error {
			resolvedPath := resolveConfigPath(cmd, configPath)
			cfg, err := config.Load(resolvedPath)
			if err != nil {
				return fmt.Errorf("加载配置失败: %w", err)
			}

			st, err := terminal.Status(cfg)
			if err != nil {
				return err
			}

			b64, err := terminal.ExportCert()
			if err != nil {
				return err
			}

			printCertExport(st, b64)
			return nil
		},
	}
}

func printInstallSummary(res *terminal.InstallResult) {
	sshPort := res.SSHPort
	if sshPort <= 0 {
		sshPort = terminal.DetectSSHPort()
	}
	portFlag := ""
	if sshPort != 22 {
		portFlag = fmt.Sprintf("-P %d ", sshPort)
	}

	sshPathPrefix := strings.TrimPrefix(res.SSHTunnelPath, "/")
	if sshPathPrefix == "" {
		sshPathPrefix = "ssh-ws"
	}

	fmt.Println()
	logger.Success("🎉 GoTTY + Tmux + wstunnel + Caddy mTLS 双模式运维环境部署成功！")
	fmt.Println("═══════════════════════════════════════════════════════════════════════════")
	fmt.Printf("🌐 Web 终端地址   : %s\n", res.URL)
	fmt.Printf("🚀 SSH 穿透路径   : %s\n", res.SSHTunnelPath)
	fmt.Printf("🎯 本地 SSH 目标  : 127.0.0.1:%d\n", sshPort)
	fmt.Printf("🔒 安全认证模式   : mTLS 双向 TLS 证书 (无证书访问直接返回 404)\n")
	fmt.Printf("📦 客户端证书包   : %s (导入密码: %s)\n", res.P12Path, res.Password)
	fmt.Printf("📜 原生证书/私钥  : %s , %s\n", res.ClientCrtPath, res.ClientKeyPath)
	fmt.Println("═══════════════════════════════════════════════════════════════════════════")
	fmt.Println()
	fmt.Println("📱【方案一：Web 终端 (手机 / 平板 / 浏览器极简登录)】")
	fmt.Printf("  1. 下载客户端证书: scp %sroot@%s:%s ./client.p12\n", portFlag, res.Domain, res.P12Path)
	fmt.Printf("  2. 双击 client.p12，输入密码 [%s]，导入系统钥匙串\n", res.Password)
	fmt.Printf("  3. 浏览器打开: %s，确认证书即可无感登录并持久化运行！\n\n", res.URL)
	fmt.Println("⚡【方案二：WezTerm / 本地终端原生 SSH 穿透 443 + mTLS (推荐，体验最佳)】")
	fmt.Println("  1. Mac 本地安装 wstunnel (如已安装可跳过):")
	fmt.Println("     brew install wstunnel")
	fmt.Println("  2. 从 VPS 一键下载客户端证书与私钥至本地 ~/.ssh/:")
	fmt.Printf("     mkdir -p ~/.ssh && scp %sroot@%s:%s %s ~/.ssh/\n\n", portFlag, res.Domain, res.ClientCrtPath, res.ClientKeyPath)
	fmt.Println("  3. 在 Mac 终端执行以下一键命令，自动配置 ~/.ssh/config:")
	fmt.Printf(`     cat << 'EOF' >> ~/.ssh/config

Host vps-ws
    HostName 127.0.0.1
    Port %d
    User root
    ProxyCommand wstunnel client --log-lvl off --tls-certificate ~/.ssh/client.crt --tls-private-key ~/.ssh/client.key --http-upgrade-path-prefix %s -L stdio://127.0.0.1:%d wss://%s
EOF
`, sshPort, sshPathPrefix, sshPort, res.Domain)
	fmt.Println()
	fmt.Println("  4. 在 WezTerm 中直接敲原生命令直连:")
	fmt.Println("     ssh vps-ws")
	fmt.Println("     (享受所有快捷键、动态窗口缩放、文件拖拽与原生 SSH 极速体验！)")
	fmt.Println("═══════════════════════════════════════════════════════════════════════════")
	fmt.Println()
}

func printStatusSummary(st *terminal.StatusResult) {
	fmt.Println()
	logger.Info("═══════════════════════════════════════════════════════════")
	logger.Info("📊 Web 终端与 SSH 穿透 (GoTTY + wstunnel + mTLS) 运行状态")
	logger.Info("═══════════════════════════════════════════════════════════")
	if st.Enabled {
		logger.Success("配置启用状态  : 已启用 (Enabled)")
	} else {
		logger.Warn("配置启用状态  : 未启用 (Disabled)")
	}

	if st.ServiceActive {
		logger.Success("GoTTY Web服务 : 正在运行 (gotty.service active, 127.0.0.1:%d)", st.Port)
	} else {
		logger.Warn("GoTTY Web服务 : 未运行 (gotty.service inactive)")
	}

	if st.WstunnelActive {
		logger.Success("wstunnel 服务 : 正在运行 (wstunnel.service active, 127.0.0.1:%d -> 127.0.0.1:%d)", st.SSHTunnelPort, st.SSHPort)
	} else {
		logger.Warn("wstunnel 服务 : 未运行 (wstunnel.service inactive)")
	}

	if st.URL != "" {
		fmt.Printf("🌐 Web 访问 URL: %s\n", st.URL)
	}
	fmt.Printf("🚪 SSH 穿透路径: %s\n", st.SSHTunnelPath)

	if st.P12Exists {
		logger.Success("客户端证书包  : 已就绪 (%s)", st.P12Path)
		if st.Password != "" {
			fmt.Printf("🔑 证书导入密码: %s\n", st.Password)
		}
	} else {
		logger.Warn("客户端证书包  : 未找到 (%s)", st.P12Path)
	}

	if st.ClientCrtExists {
		logger.Success("原生证书密钥  : 已就绪 (%s, %s)", st.ClientCrtPath, st.ClientKeyPath)
	}
	fmt.Println("═══════════════════════════════════════════════════════════")
	fmt.Println()
}

func printCertExport(st *terminal.StatusResult, b64 string) {
	sshPort := st.SSHPort
	if sshPort <= 0 {
		sshPort = terminal.DetectSSHPort()
	}
	portFlag := ""
	if sshPort != 22 {
		portFlag = fmt.Sprintf("-P %d ", sshPort)
	}

	sshPathPrefix := strings.TrimPrefix(st.SSHTunnelPath, "/")
	if sshPathPrefix == "" {
		sshPathPrefix = "ssh-ws"
	}

	fmt.Println()
	logger.Info("═══════════════════════════════════════════════════════════")
	logger.Info("🔐 mTLS 客户端证书与 SSH-over-WSS 配置导出")
	logger.Info("═══════════════════════════════════════════════════════════")
	fmt.Printf("📁 证书路径: %s\n", st.P12Path)
	if st.Password != "" {
		fmt.Printf("🔑 导入密码: %s\n", st.Password)
	}
	fmt.Println()
	fmt.Println("📱【方案一：Web 终端 (.p12 证书)】")
	fmt.Printf("  scp %sroot@%s:%s ./client.p12\n\n", portFlag, st.Domain, st.P12Path)
	fmt.Println("⚡【方案二：WezTerm 原生 SSH (client.crt + client.key)】")
	fmt.Printf("  mkdir -p ~/.ssh && scp %sroot@%s:%s %s ~/.ssh/\n\n", portFlag, st.Domain, st.ClientCrtPath, st.ClientKeyPath)
	fmt.Println("  追加到本地 ~/.ssh/config:")
	fmt.Printf(`  cat << 'EOF' >> ~/.ssh/config

Host vps-ws
    HostName 127.0.0.1
    Port %d
    User root
    ProxyCommand wstunnel client --log-lvl off --tls-certificate ~/.ssh/client.crt --tls-private-key ~/.ssh/client.key --http-upgrade-path-prefix %s -L stdio://127.0.0.1:%d wss://%s
EOF
`, sshPort, sshPathPrefix, sshPort, st.Domain)
	fmt.Println("═══════════════════════════════════════════════════════════")
	fmt.Println()
}
