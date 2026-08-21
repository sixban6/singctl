package cmd

import (
	"os"

	"singctl/internal/webui"

	"github.com/spf13/cobra"
)

// NewWebCmd 创建 Web 管理界面命令
func NewWebCmd(version string) *cobra.Command {
	var listen string
	var password string

	cmd := &cobra.Command{
		Use:     "web",
		Aliases: []string{"w"},
		Short:   "网页  : 启动Web管理界面(简写singctl w)",
		Long: `启动 SingCtl Web 管理界面,在浏览器中管理 sing-box、守护进程、Tailscale、防火墙和配置。

  singctl web                          # 监听 :8090
  singctl web -l 192.168.1.1:8090      # 指定监听地址
  singctl web --password secret        # 启用 Basic Auth(admin/secret)

也可通过环境变量 SINGCTL_WEB_PASSWORD 设置口令。`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if password == "" {
				password = os.Getenv("SINGCTL_WEB_PASSWORD")
			}

			// 在 RunE 时读取 --config,确保命令行指定的配置路径生效
			configPath := cmd.Flag("config").Value.String()

			server := webui.New(webui.Options{
				ConfigPath: configPath,
				Listen:     listen,
				Password:   password,
				Version:    version,
			})
			return server.ListenAndServe()
		},
	}

	cmd.Flags().StringVarP(&listen, "listen", "l", ":8090",
		"监听地址 / Listen address (e.g. :8090 or 127.0.0.1:8090)")
	cmd.Flags().StringVarP(&password, "password", "p", "",
		"访问口令(用户名固定 admin,留空则不鉴权) / Web UI password (username: admin)")

	return cmd
}
