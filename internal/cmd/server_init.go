package cmd

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"singctl/internal/config"
	"singctl/internal/deploy"
	"singctl/internal/logger"

	"github.com/spf13/cobra"
)

func newInitServerCmd(configPath string) *cobra.Command {
	var (
		domain         string
		cfToken        string
		tag            string
		sni            string
		substoreDomain string
		adminUser      string
		autoYes        bool
	)

	cmd := &cobra.Command{
		Use:     "init",
		Aliases: []string{"setup", "wizard"},
		Short:   "服务端向导式初始化配置 / Interactive or flag-based server setup wizard",
		Long: `向导式或命令行参数初始化服务端配置文件 (/etc/singctl/singctl.yaml)。
支持非交互式一键设置，也支持终端交互式引导提问，自动生成并校验合法的 0600 权限配置。`,
		RunE: func(cmd *cobra.Command, args []string) error {
			resolvedPath := resolveConfigPath(cmd, configPath)

			// 加载或创建配置对象
			cfg, err := config.Load(resolvedPath)
			if err != nil {
				cfg = &config.Config{}
			}

			// 交互式读取终端输入 (优先使用 /dev/tty 以免在管道中运行时读取到 EOF)
			var inputReader io.Reader = os.Stdin
			if tty, err := os.Open("/dev/tty"); err == nil {
				defer tty.Close()
				inputReader = tty
			}
			reader := bufio.NewReader(inputReader)

			// 1. 域名 (node_domain)
			if domain == "" {
				current := cfg.Server.GetNodeDomain()
				prompt := "请输入节点主域名 (如 node.example.com)"
				if current != "" {
					prompt += fmt.Sprintf(" [回车保留: %s]", current)
				}
				fmt.Printf("\n➜ %s: ", prompt)
				input, _ := reader.ReadString('\n')
				input = strings.TrimSpace(input)
				if input != "" {
					domain = input
				} else {
					domain = current
				}
			}
			if domain == "" {
				return fmt.Errorf("节点域名 (node_domain) 不能为空")
			}

			// 2. Cloudflare API Token (cf_dns_key)
			if cfToken == "" {
				current := cfg.Server.CFDNSKey
				prompt := "请输入 Cloudflare API Token (用于申请 TLS 证书)"
				if current != "" {
					masked := current
					if len(current) > 8 {
						masked = current[:4] + "..." + current[len(current)-4:]
					}
					prompt += fmt.Sprintf(" [回车保留: %s]", masked)
				}
				fmt.Printf("➜ %s: ", prompt)
				input, _ := reader.ReadString('\n')
				input = strings.TrimSpace(input)
				if input != "" {
					cfToken = input
				} else {
					cfToken = current
				}
			}
			if cfToken == "" {
				return fmt.Errorf("Cloudflare API Token (cf_dns_key) 不能为空")
			}

			// 3. 节点标识 Tag (node_tag)
			if tag == "" && !autoYes {
				current := cfg.Server.NodeTag
				prompt := "请输入节点地区标识 (如 sg, hk, los, 留空根据公网 IP 自动识别)"
				if current != "" {
					prompt += fmt.Sprintf(" [回车保留: %s]", current)
				}
				fmt.Printf("➜ %s: ", prompt)
				input, _ := reader.ReadString('\n')
				input = strings.TrimSpace(input)
				if input != "" {
					tag = input
				} else {
					tag = current
				}
			}

			// 4. Reality SNI 伪装域名
			if sni == "" && !autoYes {
				current := cfg.Server.Sni
				if current == "" {
					current = "swdist.apple.com"
				}
				prompt := fmt.Sprintf("请输入 VLESS Reality 伪装域名 SNI [回车默认: %s]", current)
				fmt.Printf("➜ %s: ", prompt)
				input, _ := reader.ReadString('\n')
				input = strings.TrimSpace(input)
				if input != "" {
					sni = input
				} else {
					sni = current
				}
			} else if sni == "" && autoYes {
				if cfg.Server.Sni != "" {
					sni = cfg.Server.Sni
				} else {
					sni = "swdist.apple.com"
				}
			}

			// 5. Sub-Store 独立域名 (可选)
			if substoreDomain == "" && !autoYes {
				current := cfg.Server.GetSubstoreDomain()
				prompt := "Sub-Store 专属域名 (可选，留空则与节点域名共用)"
				if current != "" && current != domain {
					prompt += fmt.Sprintf(" [回车保留: %s]", current)
				}
				fmt.Printf("➜ %s: ", prompt)
				input, _ := reader.ReadString('\n')
				input = strings.TrimSpace(input)
				if input != "" {
					substoreDomain = input
				} else if current != domain {
					substoreDomain = current
				}
			}

			// 6. 服务端 Web 管理面板账号 (自定义，禁止固定为 admin)
			if adminUser == "" && !autoYes {
				current := cfg.Server.GetWebAdminUsername()
				if current == "admin" || current == "" {
					current = "singctl"
				}
				prompt := fmt.Sprintf("服务端 Web 管理面板用户名 (禁止默认 admin) [回车默认: %s]", current)
				fmt.Printf("➜ %s: ", prompt)
				input, _ := reader.ReadString('\n')
				input = strings.TrimSpace(input)
				if input != "" {
					adminUser = input
				} else {
					adminUser = current
				}
			}

			// 应用配置
			cfg.Server.NodeDomain = domain
			cfg.Server.CFDNSKey = cfToken
			cfg.Server.NodeTag = tag
			cfg.Server.Sni = sni
			cfg.Server.SubstoreDomain = substoreDomain
			if adminUser != "" {
				cfg.Server.WebAdmin.Username = adminUser
			}
			cfg.Server.EnsureWebAdminCredentials()

			// 保存配置
			if err := config.Save(resolvedPath, cfg); err != nil {
				return fmt.Errorf("保存配置文件失败: %w", err)
			}
			logger.Success("配置文件保存成功: %s (权限: 0600)", resolvedPath)

			// 立即触发预检
			fmt.Println()
			_, _ = deploy.RunPreflight(cfg, true)

			fmt.Println("========================================================")
			fmt.Println("🎉 服务端初始化完成！")
			fmt.Println("接下来请直接运行一键全量部署:")
			fmt.Println("   singctl sr install")
			fmt.Println("========================================================")
			return nil
		},
	}

	cmd.Flags().StringVarP(&domain, "domain", "d", "", "节点主域名 / Node domain (e.g. node.example.com)")
	cmd.Flags().StringVarP(&cfToken, "cf-token", "t", "", "Cloudflare API Token")
	cmd.Flags().StringVar(&tag, "tag", "", "节点地区代号标识 (e.g. los, sg, hk)")
	cmd.Flags().StringVar(&sni, "sni", "", "Reality 伪装 SNI 域名 (默认 swdist.apple.com)")
	cmd.Flags().StringVar(&substoreDomain, "substore-domain", "", "Sub-Store 独立域名 (可选)")
	cmd.Flags().StringVar(&adminUser, "admin-user", "", "服务端 Web 管理员用户名 (拒绝默认 admin)")
	cmd.Flags().BoolVarP(&autoYes, "yes", "y", false, "自动使用默认值，跳过可选询问")

	return cmd
}

func newPreflightServerCmd(configPath string) *cobra.Command {
	return &cobra.Command{
		Use:     "preflight",
		Aliases: []string{"check", "verify"},
		Short:   "执行服务端部署前环境与网络预检 / Run preflight checks",
		RunE: func(cmd *cobra.Command, args []string) error {
			resolvedPath := resolveConfigPath(cmd, configPath)
			cfg, err := config.Load(resolvedPath)
			if err != nil {
				return fmt.Errorf("无法加载配置文件: %w", err)
			}
			_, err = deploy.RunPreflight(cfg, true)
			return err
		},
	}
}
