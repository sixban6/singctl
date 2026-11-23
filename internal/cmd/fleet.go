//go:build !lite

// 文件职责：提供 CLI 多节点舰队根命令 (`singctl fleet`) 装配及子节点列表、纳管与下线子命令。
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

type fleetCmdContext struct {
	defaultConfigPath string
	fleetFile         string
	subhubDir         string
}

func (fc *fleetCmdContext) buildManager(c *cobra.Command) *fleet.Manager {
	resolvedCfg := resolveConfigPath(c, fc.defaultConfigPath)
	fPath := fc.fleetFile
	if fPath == "" {
		fPath = fleet.ResolveFleetFilePath(resolvedCfg)
	}
	var subStore *subhub.Store
	if strings.TrimSpace(fc.subhubDir) != "" {
		subStore = subhub.NewStore(strings.TrimSpace(fc.subhubDir), "")
	} else if st, err := os.Stat(constant.SubStoreDir); err == nil && st.IsDir() {
		subStore = subhub.NewStore("", "")
	}
	mgr := fleet.NewManager(fleet.NewStore(fPath), subStore)
	if resolvedCfg != "" {
		mgr.ConfigPath = resolvedCfg
	}
	return mgr
}

// NewFleetCmd 创建多节点舰队编排命令 (`singctl fleet` / `singctl fl`)。
func NewFleetCmd(configPath string) *cobra.Command {
	fc := &fleetCmdContext{defaultConfigPath: configPath}

	cmd := &cobra.Command{
		Use:     "fleet",
		Aliases: []string{"fl", "cluster"},
		Short:   "舰队  : 多节点全球服务器编排与订阅自动汇总 (简写 singctl fl)",
		Long:    "无 Agent 轻量级多节点集群管控：支持一键纳管多台 VPS、并发健康体检、全网一键轮换密码并自动汇总至主控 SubHub 总订阅。",
	}

	cmd.PersistentFlags().StringVar(&fc.fleetFile, "fleet-file", "", "指定舰队配置文件路径 (默认与 singctl.yaml 同目录 fleet.yaml)")
	cmd.PersistentFlags().StringVar(&fc.subhubDir, "subhub-dir", "", "指定本地 SubHub 数据目录 (服务端默认自动关联 /etc/sub-store)")

	cmd.AddCommand(
		newFleetListCmd(fc),
		newFleetAddCmd(fc),
		newFleetRemoveCmd(fc),
		newFleetBatchCmd(fc, "sync", nil, "并发拉取所有子节点最新 HY2/Reality 链接并汇总至本机 SubHub", "sync", false),
		newFleetBatchCmd(fc, "probe", []string{"ping"}, "零 SSH 日志毫秒级 HTTPS :443 网关探活与证书余期巡检", "probe", false),
		newFleetDoctorCmd(fc),
		newFleetBatchCmd(fc, "reset", nil, "全网一键轮换所有子节点代理密码/Reality密钥并自动同步至总订阅", "reset", false),
		newFleetBatchCmd(fc, "update", []string{"up", "upgrade"}, "全网并发升级所有子节点的 SingCtl 至官方最新版", "update", false),
		newFleetBootstrapCmd(fc),
		newFleetHealCmd(fc),
	)
	return cmd
}

func newFleetListCmd(fc *fleetCmdContext) *cobra.Command {
	var listProbe bool
	listCmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls", "status"},
		Short:   "查看已纳管的全部舰队子节点与状态汇总 (支持 --probe 秒级 HTTPS 探活)",
		RunE: func(c *cobra.Command, args []string) error {
			mgr := fc.buildManager(c)
			if listProbe {
				_, _ = mgr.ProbeNodes(c.Context(), nil)
			}
			nodes, err := mgr.Store.ListPublic()
			if err != nil {
				return err
			}
			if len(nodes) == 0 {
				logger.Info("当前尚未纳管任何子节点。可使用 'singctl fleet add <id> --alias <ssh别名>' 或在 Web 面板添加。")
				return nil
			}
			printFleetNodesTable(nodes)
			return nil
		},
	}
	listCmd.Flags().BoolVar(&listProbe, "probe", false, "展示前并发执行一次零 SSH 日志的 HTTPS :443 毫秒级探活")
	return listCmd
}

func printFleetNodesTable(nodes []fleet.Node) {
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
}

func newFleetAddCmd(fc *fleetCmdContext) *cobra.Command {
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
			mgr := fc.buildManager(c)
			node, err := mgr.Store.Upsert(fleet.UpsertInput{
				ID:       args[0],
				Name:     addName,
				Host:     addHost,
				Port:     addPort,
				User:     addUser,
				SSHAlias: addAlias,
				KeyPath:  addKey,
				Password: addPassword,
			})
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
	return addCmd
}

func newFleetRemoveCmd(fc *fleetCmdContext) *cobra.Command {
	var keepDNS bool
	removeCmd := &cobra.Command{
		Use:     "remove <id>",
		Aliases: []string{"rm", "del", "delete"},
		Short:   "移除指定子节点并自动清理总订阅源及关联 DNS 解析",
		Args:    cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			mgr := fc.buildManager(c)
			dnsDeleted, err := mgr.RemoveNodeWithOptions(c.Context(), args[0], keepDNS)
			if err != nil {
				return err
			}
			if dnsDeleted {
				logger.Success("已移除子节点 [%s]，并同步清理聚合订阅源与自动创建的 Cloudflare DNS 记录。", args[0])
			} else {
				logger.Success("已移除子节点 [%s] 并清理关联聚合订阅源。", args[0])
			}
			return nil
		},
	}
	removeCmd.Flags().BoolVar(&keepDNS, "keep-dns", false, "保留该节点在 Cloudflare 自动创建的 DNS 解析记录")
	return removeCmd
}

func truncateDisplay(s string, maxRunes int) string {
	runes := []rune(s)
	if len(runes) <= maxRunes {
		return s
	}
	return string(runes[:maxRunes-1]) + "…"
}
