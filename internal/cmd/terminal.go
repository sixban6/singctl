package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
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

// detectSSHPort tries to detect the SSH daemon port on the server
func detectSSHPort() int {
	// 1. Check SSH_CONNECTION environment variable (e.g., "client_ip client_port server_ip server_port")
	if conn := os.Getenv("SSH_CONNECTION"); conn != "" {
		parts := strings.Fields(conn)
		if len(parts) >= 4 {
			if p, err := strconv.Atoi(parts[3]); err == nil && p > 0 {
				return p
			}
		}
	}

	// 2. Check /etc/ssh/sshd_config
	if data, err := os.ReadFile("/etc/ssh/sshd_config"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(strings.ToLower(line), "port ") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					if p, err := strconv.Atoi(fields[1]); err == nil && p > 0 {
						return p
					}
				}
			}
		}
	}

	// 3. Check /etc/ssh/sshd_config.d/*.conf
	matches, _ := filepath.Glob("/etc/ssh/sshd_config.d/*.conf")
	for _, match := range matches {
		if data, err := os.ReadFile(match); err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(strings.ToLower(line), "port ") {
					fields := strings.Fields(line)
					if len(fields) >= 2 {
						if p, err := strconv.Atoi(fields[1]); err == nil && p > 0 {
							return p
						}
					}
				}
			}
		}
	}

	return 22
}

func printInstallSummary(res *terminal.InstallResult) {
	sshPort := detectSSHPort()
	scpCmd := fmt.Sprintf("scp root@%s:%s ./client.p12", res.Domain, res.P12Path)
	if sshPort != 22 {
		scpCmd = fmt.Sprintf("scp -P %d root@%s:%s ./client.p12", sshPort, res.Domain, res.P12Path)
	}

	fmt.Println()
	logger.Success("🎉 GoTTY + Tmux + Caddy mTLS 双向认证终端部署成功！")
	fmt.Println("═══════════════════════════════════════════════════════════")
	fmt.Printf("🌐 终端访问地址 : %s\n", res.URL)
	fmt.Printf("🔒 安全认证模式 : mTLS (强制双向客户端证书，无证书直接 404)\n")
	fmt.Printf("📦 客户端证书   : %s\n", res.P12Path)
	fmt.Printf("🔑 证书导入密码 : %s\n", res.Password)
	fmt.Println("═══════════════════════════════════════════════════════════")
	fmt.Println()
	fmt.Println("📥 如何将客户端证书导入电脑/手机：")
	fmt.Printf("  方法 1 (推荐 SCP 下载):\n")
	fmt.Printf("    %s\n\n", scpCmd)
	fmt.Printf("  方法 2 (本地终端一键 Base64 还原):\n")
	fmt.Printf("    在本地 Mac/Linux 执行: echo \"%s\" | base64 -d > client.p12\n\n", res.P12Base64)
	fmt.Println("💡 客户端使用步骤：")
	fmt.Printf("  1. 双击 client.p12，输入密码 [%s]，导入系统钥匙串 (macOS 放入「登录」钥匙串即可)\n", res.Password)
	fmt.Printf("  2. 打开浏览器访问: %s\n", res.URL)
	fmt.Println("  3. 浏览器弹窗提示选择客户端证书「AdminClient」，确认后即可无感登录并持久化运行！")
	fmt.Println("  4. 验证防扫描：在浏览器无痕模式访问，将直接收到 404，彻底隐藏终端存在。")
	fmt.Println("═══════════════════════════════════════════════════════════")
	fmt.Println()
}

func printStatusSummary(st *terminal.StatusResult) {
	fmt.Println()
	logger.Info("═══════════════════════════════════════════════════════════")
	logger.Info("📊 Web 终端 (GoTTY + mTLS) 运行状态")
	logger.Info("═══════════════════════════════════════════════════════════")
	if st.Enabled {
		logger.Success("配置启用状态: 已启用 (Enabled)")
	} else {
		logger.Warn("配置启用状态: 未启用 (Disabled)")
	}

	if st.ServiceActive {
		logger.Success("服务运行状态: 正在运行 (gotty.service active)")
	} else {
		logger.Warn("服务运行状态: 未运行 (gotty.service inactive)")
	}

	if st.URL != "" {
		fmt.Printf("🌐 访问 URL   : %s\n", st.URL)
	}
	fmt.Printf("🔌 本地端口   : 127.0.0.1:%d\n", st.Port)
	fmt.Printf("🚪 访问路径   : %s\n", st.Path)

	if st.P12Exists {
		logger.Success("客户端证书   : 已存在 (%s)", st.P12Path)
		if st.Password != "" {
			fmt.Printf("🔑 证书导入密码: %s\n", st.Password)
		}
	} else {
		logger.Warn("客户端证书   : 未找到 (%s)", st.P12Path)
	}
	fmt.Println("═══════════════════════════════════════════════════════════")
	fmt.Println()
}

func printCertExport(st *terminal.StatusResult, b64 string) {
	sshPort := detectSSHPort()
	scpCmd := fmt.Sprintf("scp root@%s:%s ./client.p12", st.Domain, st.P12Path)
	if sshPort != 22 {
		scpCmd = fmt.Sprintf("scp -P %d root@%s:%s ./client.p12", sshPort, st.Domain, st.P12Path)
	}

	fmt.Println()
	logger.Info("═══════════════════════════════════════════════════════════")
	logger.Info("🔐 mTLS 客户端证书 (.p12) 导出")
	logger.Info("═══════════════════════════════════════════════════════════")
	fmt.Printf("📁 证书路径: %s\n", st.P12Path)
	if st.Password != "" {
		fmt.Printf("🔑 导入密码: %s\n", st.Password)
	}
	fmt.Println()
	fmt.Println("📥 下载方式 1 (推荐 SCP 下载):")
	fmt.Printf("  %s\n\n", scpCmd)
	fmt.Println("📋 下载方式 2 (本地终端 Base64 一键还原):")
	fmt.Printf("  echo \"%s\" | base64 -d > client.p12\n\n", b64)
	fmt.Println("💡 客户端使用指引:")
	if st.Password != "" {
		fmt.Printf("  双击 client.p12，输入密码 [%s]，导入系统钥匙串即可。\n", st.Password)
	} else {
		fmt.Println("  双击 client.p12，导入系统钥匙串即可。")
	}
	fmt.Println("═══════════════════════════════════════════════════════════")
	fmt.Println()
}
