package cmd

import (
	"cmp"
	"fmt"
	"os"
	"strings"

	"singctl/internal/constant"
	"singctl/internal/fleet"
	"singctl/internal/logger"
	"singctl/internal/subhub"

	"github.com/spf13/cobra"
)

// NewFleetCmd creates the multi-node fleet orchestration command (`singctl fleet` / `singctl fl`).
func NewFleetCmd(configPath string) *cobra.Command {
	var fleetFile string
	var subhubDir string

	cmd := &cobra.Command{
		Use:     "fleet",
		Aliases: []string{"fl", "cluster"},
		Short:   "舰队  : 多节点全球服务器编排与订阅自动汇总 (简写 singctl fl)",
		Long:    "无 Agent 轻量级多节点集群管控：支持一键纳管多台 VPS、并发健康体检、全网一键轮换密码并自动汇总至主控 SubHub 总订阅。",
	}

	cmd.PersistentFlags().StringVar(&fleetFile, "fleet-file", "", "指定舰队配置文件路径 (默认与 singctl.yaml 同目录 fleet.yaml)")
	cmd.PersistentFlags().StringVar(&subhubDir, "subhub-dir", "", "指定本地 SubHub 数据目录 (服务端默认自动关联 /etc/sub-store)")

	buildManager := func(c *cobra.Command) *fleet.Manager {
		resolvedCfg := resolveConfigPath(c, configPath)
		fPath := fleetFile
		if fPath == "" {
			fPath = fleet.ResolveFleetFilePath(resolvedCfg)
		}
		var subStore *subhub.Store
		if strings.TrimSpace(subhubDir) != "" {
			subStore = subhub.NewStore(strings.TrimSpace(subhubDir), "")
		} else if st, err := os.Stat(constant.SubStoreDir); err == nil && st.IsDir() {
			subStore = subhub.NewStore("", "")
		}
		return fleet.NewManager(fleet.NewStore(fPath), subStore)
	}

	// 1. list
	listCmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls", "status"},
		Short:   "查看已纳管的全部舰队子节点与状态汇总",
		RunE: func(c *cobra.Command, args []string) error {
			mgr := buildManager(c)
			nodes, err := mgr.Store.ListPublic()
			if err != nil {
				return err
			}
			if len(nodes) == 0 {
				logger.Info("当前尚未纳管任何子节点。可使用 'singctl fleet add <id> --alias <ssh别名>' 或在 Web 面板添加。")
				return nil
			}
			fmt.Println("\n══════════════════════════════════════════════════════════════════════════════════════")
			fmt.Printf(" %-12s %-14s %-20s %-8s %-7s %-8s %-10s %-6s\n",
				"ID", "名称", "地址/SSH别名", "状态", "延迟", "健康分", "版本", "节点数")
			fmt.Println("──────────────────────────────────────────────────────────────────────────────────────")
			for _, n := range nodes {
				state := "离线"
				if n.Online {
					state = "在线 ✓"
				}
				target := cmp.Or(n.SSHAlias, n.Host)
				if len(target) > 18 {
					target = target[:15] + "..."
				}
				score := "-"
				if n.DoctorScore > 0 {
					score = fmt.Sprintf("%d/100", n.DoctorScore)
				}
				rtt := "-"
				if n.LatencyMs > 0 {
					rtt = fmt.Sprintf("%dms", n.LatencyMs)
				}
				fmt.Printf(" %-12s %-14s %-20s %-8s %-7s %-8s %-10s %-6d\n",
					n.ID, truncateDisplay(n.Name, 12), target, state, rtt, score, cmp.Or(n.SingctlVersion, "-"), n.SyncedNodes)
			}
			fmt.Println("══════════════════════════════════════════════════════════════════════════════════════")
			return nil
		},
	}

	// 2. add
	var (
		addName     string
		addHost     string
		addAlias    string
		addPort     int
		addUser     string
		addKey      string
		addPassword string
		addSync     bool
	)
	addCmd := &cobra.Command{
		Use:   "add <id>",
		Short: "纳管一台已部署 SingCtl 的远端服务器并自动汇总订阅",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			mgr := buildManager(c)
			in := fleet.UpsertInput{
				ID:       args[0],
				Name:     addName,
				Host:     addHost,
				Port:     addPort,
				User:     addUser,
				SSHAlias: addAlias,
				KeyPath:  addKey,
				Password: addPassword,
			}
			node, err := mgr.Store.Upsert(in)
			if err != nil {
				return err
			}
			logger.Success("已保存舰队子节点 [%s (%s)]", node.Name, node.ID)
			if addSync {
				logger.Info("正在通过 SSH 探测并同步远端代理节点...")
				res := mgr.SyncNode(c.Context(), node.ID)
				if res.Success {
					logger.Success("[%s] %s", res.Name, res.Message)
				} else {
					logger.Warn("[%s] 首次同步未成功: %s", node.Name, res.Message)
				}
			}
			return nil
		},
	}
	addCmd.Flags().StringVar(&addName, "name", "", "子节点显示名称 (例如: 美西洛杉矶)")
	addCmd.Flags().StringVar(&addHost, "host", "", "服务器公网 IP 或域名")
	addCmd.Flags().StringVar(&addAlias, "alias", "", "使用本地 ~/.ssh/config 中已配置的 SSH 别名 (例如: vps_us)")
	addCmd.Flags().IntVar(&addPort, "port", 22, "SSH 端口")
	addCmd.Flags().StringVar(&addUser, "user", "root", "SSH 用户名")
	addCmd.Flags().StringVar(&addKey, "key", "", "本地 SSH 私钥路径 (例如 ~/.ssh/id_ed25519)")
	addCmd.Flags().StringVar(&addPassword, "password", "", "SSH 密码 (推荐使用密钥或 --alias)")
	addCmd.Flags().BoolVar(&addSync, "sync", true, "添加后立即拉取该机器节点并写入主订阅")

	// 3. remove
	removeCmd := &cobra.Command{
		Use:     "remove <id>",
		Aliases: []string{"rm", "del", "delete"},
		Short:   "移除指定子节点并自动从主订阅清理对应节点",
		Args:    cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			mgr := buildManager(c)
			if err := mgr.RemoveNode(args[0]); err != nil {
				return err
			}
			logger.Success("已移除子节点 [%s] 并清理关联聚合订阅源。", args[0])
			return nil
		},
	}

	// 4. batch actions: sync / doctor / reset / update
	makeBatchCmd := func(use string, aliases []string, short string, action string, showDetail bool) *cobra.Command {
		return &cobra.Command{
			Use:     use + " [id...]",
			Aliases: aliases,
			Short:   short,
			RunE: func(c *cobra.Command, args []string) error {
				mgr := buildManager(c)
				logger.Info("正在并发执行舰队指令 [%s] ...", action)
				results, err := mgr.RunAcross(c.Context(), action, args)
				if err != nil {
					return err
				}
				if len(results) == 0 {
					logger.Warn("未匹配到任何已纳管的子节点。")
					return nil
				}
				for _, r := range results {
					if r.Success {
						logger.Success("✓ [%s (%s)] %s", r.Name, r.ID, r.Message)
					} else {
						logger.Error("✗ [%s (%s)] %s", r.Name, r.ID, r.Message)
					}
					if showDetail && strings.TrimSpace(r.Output) != "" {
						fmt.Println(r.Output)
						fmt.Println()
					}
				}
				return nil
			},
		}
	}

	syncCmd := makeBatchCmd("sync", nil, "并发拉取所有子节点最新 HY2/Reality 链接并汇总至本机 SubHub", "sync", false)
	doctorCmd := makeBatchCmd("doctor", []string{"doc", "check"}, "并发对所有子节点执行全链路健康体检与流媒体解锁对比", "doctor", false)
	var verboseDoctor bool
	doctorCmd.Flags().BoolVarP(&verboseDoctor, "verbose", "v", false, "输出每台子节点的完整体检报告明细")
	origDocRunE := doctorCmd.RunE
	doctorCmd.RunE = func(c *cobra.Command, args []string) error {
		if !verboseDoctor {
			return origDocRunE(c, args)
		}
		mgr := buildManager(c)
		results, err := mgr.RunAcross(c.Context(), "doctor", args)
		if err != nil {
			return err
		}
		for _, r := range results {
			if r.Success {
				logger.Success("✓ [%s (%s)] %s", r.Name, r.ID, r.Message)
			} else {
				logger.Error("✗ [%s (%s)] %s", r.Name, r.ID, r.Message)
			}
			if r.Output != "" {
				fmt.Println(r.Output)
			}
		}
		return nil
	}

	resetCmd := makeBatchCmd("reset", nil, "全网一键轮换所有子节点代理密码/Reality密钥并自动同步至总订阅", "reset", false)
	updateCmd := makeBatchCmd("update", []string{"up", "upgrade"}, "全网并发升级所有子节点的 SingCtl 至官方最新版", "update", false)

	// 5. bootstrap
	var (
		bsIn        fleet.BootstrapInput
		bsHardenSSH bool
	)
	bootstrapCmd := &cobra.Command{
		Use:   "bootstrap <id>",
		Short: "新购裸机一键 SSH 安全加固(22→2222免密禁密码) + 部署四核服务端并纳管进总订阅",
		Long: `在主控节点上远程开荒一台全新空白 VPS，全自动完成 SSH 免密加固、四核部署并汇入本机总订阅。

位置参数 <id> 说明:
  <id> 是你为这台新机器自定义的唯一短代号（非固定参数，支持 1~32 位字母/数字/连字符，如 jp1、hk、sg2）。
  • 默认同时作为该机器生成节点的标签（如 sec_jp1_hy2），同国多台机器不会撞名；
  • 后续可随时用该代号单独点名运维，如:
      singctl fl doc jp1     # 仅体检 jp1
      singctl fl reset jp1   # 仅重置 jp1 节点凭据
      singctl fl rm jp1      # 下线移除 jp1`,
		Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			bsIn.ID = args[0]
			bsIn.HardenSSH = &bsHardenSSH
			if bsIn.CFDNSKey == "" {
				bsIn.CFDNSKey = os.Getenv("CF_DNS_API_TOKEN")
			}
			mgr := buildManager(c)
			logger.Info("正在连接新机器 [%s] 执行 SSH 免密加固与全自动四核部署 (预计耗时 40~90 秒)...", bsIn.ID)
			res, err := mgr.BootstrapNode(c.Context(), bsIn)
			if err != nil {
				return err
			}
			if !res.Success {
				return fmt.Errorf("%s", res.Message)
			}
			logger.Success("🎉 [%s] %s", res.Name, res.Message)
			return nil
		},
	}
	bootstrapCmd.Flags().StringVar(&bsIn.Name, "name", "", "子节点显示名称")
	bootstrapCmd.Flags().StringVar(&bsIn.Host, "host", "", "新服务器公网 IP 或主机名")
	bootstrapCmd.Flags().StringVar(&bsIn.SSHAlias, "alias", "", "本地 ~/.ssh/config 别名")
	bootstrapCmd.Flags().IntVar(&bsIn.Port, "port", 22, "初始 SSH 端口 (新购裸机通常为 22)")
	bootstrapCmd.Flags().StringVar(&bsIn.User, "user", "root", "SSH 用户名")
	bootstrapCmd.Flags().StringVar(&bsIn.KeyPath, "key", "", "初始 SSH 私钥路径 (若新机使用密码登录可留空)")
	bootstrapCmd.Flags().StringVar(&bsIn.Password, "password", "", "初始 SSH 登录密码 (加固完成后自动擦除明文并切为密钥免密)")
	bootstrapCmd.Flags().BoolVar(&bsHardenSSH, "harden-ssh", true, "自动注入主控+本机公钥、验证切换 SSH 端口并禁用密码登录")
	bootstrapCmd.Flags().IntVar(&bsIn.TargetSSHPort, "target-port", fleet.DefaultTargetSSHPort, "SSH 安全加固目标端口 (默认收敛至 2222)")
	bootstrapCmd.Flags().StringVar(&bsIn.ExtraAuthorizedKeys, "extra-pubkey", "", "(可选) 额外写入新机的管理员 SSH 公钥字符串")
	bootstrapCmd.Flags().StringVar(&bsIn.NodeDomain, "domain", "", "绑定至该新节点的解析域名 (必填)")
	bootstrapCmd.Flags().StringVar(&bsIn.SubstoreDomain, "sub-domain", "", "(可选) 独立订阅域名")
	bootstrapCmd.Flags().StringVar(&bsIn.CFDNSKey, "cf-token", "", "Cloudflare DNS API Token (也可通过环境变量 CF_DNS_API_TOKEN 传入)")
	bootstrapCmd.Flags().StringVar(&bsIn.NodeTag, "tag", "", "(可选) 节点代号如 us/jp/sg")
	bootstrapCmd.Flags().StringVar(&bsIn.SNI, "sni", "swdist.apple.com", "Reality SNI 伪装域名")

	cmd.AddCommand(listCmd, addCmd, removeCmd, syncCmd, doctorCmd, resetCmd, updateCmd, bootstrapCmd)
	return cmd
}

func truncateDisplay(s string, maxRunes int) string {
	runes := []rune(s)
	if len(runes) <= maxRunes {
		return s
	}
	return string(runes[:maxRunes-1]) + "…"
}
