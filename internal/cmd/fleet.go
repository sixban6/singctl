package cmd

import (
	"bufio"
	"cmp"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"

	"singctl/internal/constant"
	"singctl/internal/fleet"
	"singctl/internal/heal"
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
		mgr := fleet.NewManager(fleet.NewStore(fPath), subStore)
		if resolvedCfg != "" {
			mgr.ConfigPath = resolvedCfg
		}
		return mgr
	}

	// 1. list
	var listProbe bool
	listCmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls", "status"},
		Short:   "查看已纳管的全部舰队子节点与状态汇总 (支持 --probe 秒级 HTTPS 探活)",
		RunE: func(c *cobra.Command, args []string) error {
			mgr := buildManager(c)
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
	listCmd.Flags().BoolVar(&listProbe, "probe", false, "展示前并发执行一次零 SSH 日志的 HTTPS :443 毫秒级探活")

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
	var keepDNS bool
	removeCmd := &cobra.Command{
		Use:     "remove <id>",
		Aliases: []string{"rm", "del", "delete"},
		Short:   "移除指定子节点并自动清理总订阅源及关联 DNS 解析",
		Args:    cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			mgr := buildManager(c)
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

	probeCmd := makeBatchCmd("probe", []string{"ping"}, "零 SSH 日志毫秒级 HTTPS :443 网关探活与证书余期巡检", "probe", false)
	resetCmd := makeBatchCmd("reset", nil, "全网一键轮换所有子节点代理密码/Reality密钥并自动同步至总订阅", "reset", false)
	updateCmd := makeBatchCmd("update", []string{"up", "upgrade"}, "全网并发升级所有子节点的 SingCtl 至官方最新版", "update", false)

	// 5. bootstrap
	var (
		bsIn        fleet.BootstrapInput
		bsHardenSSH bool
		bsYes       bool
	)
	bootstrapCmd := &cobra.Command{
		Use:   "bootstrap [id]",
		Short: "新购裸机智能零配置开荒：复用主控凭据 + 自动创建 .cdn 灰云 DNS + SSH(22→2222免密) + 四核部署纳管",
		Long: `在主控节点上远程开荒一台全新空白 VPS，默认自动复用本机 /etc/singctl/singctl.yaml 配置：
  • 自动探测新机 IP 地理位置，智能分配不冲突代号与中文名称（如 sg1 / 新加坡、jp2 / 日本·东京 #2）
  • 自动复用主控 cf_dns_key 查询根域名，创建 <id>.cdn.<根域名> 灰云（仅 DNS）解析记录（下线 rm 时自动清理）
  • 自动完成 SSH 双公钥注入、22→2222 端口防锁死切换、禁用密码登录并擦除明文密码
  • 自动部署四核服务端并将 HY2 / VLESS-Reality 节点汇入本机总订阅

极简用法示例:
  1) 零参数交互向导（推荐，密码不回显、不进命令历史）:
     singctl fl bootstrap

  2) 一行非交互命令（仅需新机 IP 与初始密码）:
     singctl fl bootstrap --host 203.0.113.10 --password '<新机初始密码>'

  3) 显式自定义代号与域名（完全兼容手动指定）:
     singctl fl bootstrap jp1 --name "日本东京" --host 203.0.113.10 --password '<密码>' --domain jp1.cdn.example.com`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			if len(args) > 0 {
				bsIn.ID = args[0]
			}
			bsIn.HardenSSH = &bsHardenSSH
			if bsIn.CFDNSKey == "" {
				bsIn.CFDNSKey = os.Getenv("CF_DNS_API_TOKEN")
			}
			mgr := buildManager(c)

			// 零参数交互向导模式：当未传 --host 且未传 --alias 时自动唤醒
			if strings.TrimSpace(bsIn.Host) == "" && strings.TrimSpace(bsIn.SSHAlias) == "" {
				if !isInteractiveTerminal() {
					return errors.New("请通过 --host <IP> 指定新服务器公网 IP，或在交互式终端直接运行 'singctl fl bootstrap'")
				}
				fmt.Println("\n🚀 SingCtl 舰队智能零配置开荒向导（自动复用主控配置与 Cloudflare DNS）")
				fmt.Println("──────────────────────────────────────────────────────────────────────")
				hostVal, pErr := promptLine("1. 新服务器公网 IP 地址: ")
				if pErr != nil || strings.TrimSpace(hostVal) == "" {
					return errors.New("已取消：新服务器公网 IP 不能为空")
				}
				bsIn.Host = strings.TrimSpace(hostVal)

				if bsIn.Password == "" && bsIn.KeyPath == "" {
					sec, sErr := promptPasswordNoEcho("2. root 初始 SSH 密码 (输入不回显，若已配免密直接回车): ")
					if sErr != nil {
						return sErr
					}
					bsIn.Password = strings.TrimSpace(sec)
				}
			}

			plan, err := mgr.PreviewBootstrapNode(c.Context(), bsIn)
			if err != nil {
				return err
			}
			// 将预览推导出的 ID/Name/Domain 回填，避免重复探测 GeoIP
			bsIn.ID = plan.ID
			bsIn.Name = plan.Name

			if isInteractiveTerminal() && !bsYes && !c.Flags().Changed("host") {
				dnsDesc := plan.Domain + " (自动创建 Cloudflare 灰云解析)"
				if !plan.DomainAutoDerive {
					dnsDesc = plan.Domain
				}
				cfDesc := "复用主控 cf_dns_key"
				if !plan.InheritCFToken {
					cfDesc = "使用显式传入 Token"
				}
				fmt.Println("──────────────────────────────────────────────────────────────────────")
				fmt.Printf("  • 节点代号与名称 : %s (%s)\n", plan.ID, plan.Name)
				fmt.Printf("  • 目标主机与端口 : %s (SSH %d → %d 免密禁密码)\n", plan.Host, cmp.Or(bsIn.Port, 22), plan.TargetSSHPort)
				fmt.Printf("  • 绑定节点域名   : %s\n", cmp.Or(dnsDesc, "待指定"))
				fmt.Printf("  • 继承主控参数   : %s | SNI=%s | HY2=%d/%d Mbps\n", cfDesc, plan.SNI, plan.Hy2Up, plan.Hy2Down)
				fmt.Println("──────────────────────────────────────────────────────────────────────")
				ans, _ := promptLine("确认开始全自动加固与部署? [Y/n]: ")
				ans = strings.ToLower(strings.TrimSpace(ans))
				if ans != "" && ans != "y" && ans != "yes" {
					logger.Warn("已取消新节点开荒操作。")
					return nil
				}
			}

			logger.Info("正在连接新机器 [%s (%s)] -> 域名: %s | SSH 收敛端口: %d (预计耗时 40~90 秒)...",
				plan.Name, plan.ID, cmp.Or(plan.Domain, "自动分配"), plan.TargetSSHPort)
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
	bootstrapCmd.Flags().StringVar(&bsIn.Name, "name", "", "(可选) 子节点显示名称，留空按 IP 归属地自动生成中文名")
	bootstrapCmd.Flags().StringVar(&bsIn.Host, "host", "", "新服务器公网 IP 或主机名 (不传则进入免回显交互向导)")
	bootstrapCmd.Flags().StringVar(&bsIn.SSHAlias, "alias", "", "本地 ~/.ssh/config 别名")
	bootstrapCmd.Flags().IntVar(&bsIn.Port, "port", 22, "初始 SSH 端口 (新购裸机通常为 22)")
	bootstrapCmd.Flags().StringVar(&bsIn.User, "user", "root", "SSH 用户名")
	bootstrapCmd.Flags().StringVar(&bsIn.KeyPath, "key", "", "初始 SSH 私钥路径 (若新机使用密码登录可留空)")
	bootstrapCmd.Flags().StringVar(&bsIn.Password, "password", "", "初始 SSH 登录密码 (加固完成后自动擦除明文并切为密钥免密)")
	bootstrapCmd.Flags().BoolVar(&bsHardenSSH, "harden-ssh", true, "自动注入主控+本机公钥、验证切换 SSH 端口并禁用密码登录")
	bootstrapCmd.Flags().IntVar(&bsIn.TargetSSHPort, "target-port", fleet.DefaultTargetSSHPort, "SSH 安全加固目标端口 (默认收敛至 2222)")
	bootstrapCmd.Flags().StringVar(&bsIn.ExtraAuthorizedKeys, "extra-pubkey", "", "(可选) 额外写入新机的管理员 SSH 公钥字符串")
	bootstrapCmd.Flags().StringVar(&bsIn.NodeDomain, "domain", "", "(可选) 绑定域名，留空自动从主控根域名分配 <id>.cdn.<根域名> 并创建灰云解析")
	bootstrapCmd.Flags().StringVar(&bsIn.SubstoreDomain, "sub-domain", "", "(可选) 独立订阅域名")
	bootstrapCmd.Flags().StringVar(&bsIn.CFDNSKey, "cf-token", "", "(可选) Cloudflare DNS Token，留空自动复用主控配置")
	bootstrapCmd.Flags().StringVar(&bsIn.NodeTag, "tag", "", "(可选) 节点代号，留空与自动推导的 <id> 一致")
	bootstrapCmd.Flags().StringVar(&bsIn.SNI, "sni", "", "(可选) Reality SNI 伪装域名，留空自动复用主控配置")
	bootstrapCmd.Flags().BoolVar(&bsIn.SkipDNS, "skip-dns", false, "跳过自动调用 Cloudflare API 创建/更新 DNS 记录")
	bootstrapCmd.Flags().BoolVarP(&bsYes, "yes", "y", false, "交互模式下跳过最终确认直接执行")

	// 6. heal (fleet-wide 3-layer security self-healing + availability-safe rolling reboot)
	var (
		flHealCheckOnly    bool
		flHealNoReboot     bool
		flHealEnableTimers bool
		flHealSchedule     string
		flHealIncludeLocal bool
	)
	healCmd := &cobra.Command{
		Use:     "heal [id...]",
		Aliases: []string{"auto-heal", "patch", "sec-heal"},
		Short:   "全舰队三层安全自愈：并发热修复组件/系统漏洞 + 单台串行滚动重启 + 异常熔断保护",
		Long: `协调全舰队节点执行高可用安全自愈：
  1) 并发修复所有子节点与主控的核心组件更新、系统安全补丁与残留 .so 动态库（零断流）
  2) 对需重启生效新内核的子节点，严格执行【单台串行滚动重启】——确认前一台恢复满分健康后才重启下一台
  3) 内置【故障熔断】：任一子节点重启后超时未恢复健康，立即中止剩余节点重启，确保全网永不集体失联`,
		RunE: func(c *cobra.Command, args []string) error {
			mgr := buildManager(c)
			resolvedCfg := resolveConfigPath(c, configPath)

			if flHealCheckOnly {
				logger.Info("正在并发扫描全舰队节点的三层安全态势...")
			} else {
				logger.Info("正在对全舰队执行三层无感安全自愈（内核更新采用单台串行滚动重启 + 故障熔断）...")
			}

			rep, err := mgr.HealFleet(c.Context(), fleet.FleetHealOptions{
				CheckOnly:    flHealCheckOnly,
				AllowReboot:  !flHealNoReboot,
				EnableTimers: flHealEnableTimers,
				Schedule:     flHealSchedule,
				TargetIDs:    args,
			})
			if err != nil {
				return err
			}

			for _, r := range rep.Results {
				if r.Success {
					extra := ""
					if r.Rebooted {
						extra = fmt.Sprintf(" [已平滑滚动重启 · 健康分 %d/100]", r.DoctorScoreAfterReboot)
					} else if r.RebootRequired {
						extra = " [待维护窗口重启生效内核]"
					}
					logger.Success("✓ 子节点 [%s (%s)] %s%s", r.Name, r.ID, r.Summary, extra)
				} else {
					logger.Error("✗ 子节点 [%s (%s)] %s", r.Name, r.ID, r.Summary)
				}
			}
			if rep.CircuitBreakerHit {
				logger.Error("🚨 熔断告警: %s", rep.CircuitBreakerNote)
			}

			// Also heal Master locally when no specific worker ID was targeted (without surprise reboot of Master)
			if len(args) == 0 && flHealIncludeLocal {
				if flHealEnableTimers {
					p := heal.Scan(c.Context(), resolvedCfg, "").Policy
					p.AutoHealEnabled = true
					if strings.TrimSpace(flHealSchedule) != "" {
						p.Schedule = strings.TrimSpace(flHealSchedule)
					}
					_, _ = heal.ApplyPolicy(resolvedCfg, p)
				}
				localRes, lErr := heal.Run(c.Context(), heal.RunOptions{
					ConfigPath:  resolvedCfg,
					CheckOnly:   flHealCheckOnly,
					AllowReboot: false,
					Trigger:     "fleet",
				})
				if lErr == nil {
					if flHealCheckOnly {
						logger.Info("✓ 主控本机态势: %s (待修复组件=%d, 系统补丁=%d, 需重启=%v)",
							localRes.Status.PostureLabel,
							localRes.Status.Core.PendingCount,
							localRes.Status.OS.SecurityCount,
							localRes.Status.Kernel.RebootRequired,
						)
					} else {
						logger.Success("✓ 主控本机: %s", localRes.Execution.Summary)
					}
				}
			}
			return nil
		},
	}
	healCmd.Flags().BoolVar(&flHealCheckOnly, "check", false, "仅扫描全舰队安全态势，不执行变更或重启")
	healCmd.Flags().BoolVar(&flHealNoReboot, "no-reboot", false, "仅热修复组件与动态库，跳过子节点的串行滚动重启")
	healCmd.Flags().BoolVar(&flHealEnableTimers, "enable-timer", false, "为所有子节点及主控统一开启每日凌晨 04:00 自动安全自愈定时器")
	healCmd.Flags().StringVar(&flHealSchedule, "schedule", "", "自定义自动巡检时间 (默认 '*-*-* 04:00:00')")
	healCmd.Flags().BoolVar(&flHealIncludeLocal, "include-master", true, "全量执行时同步自愈主控本机 (主控不自动重启)")

	cmd.AddCommand(listCmd, addCmd, removeCmd, syncCmd, probeCmd, doctorCmd, resetCmd, updateCmd, bootstrapCmd, healCmd)
	return cmd
}

func isInteractiveTerminal() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

func promptLine(prompt string) (string, error) {
	fmt.Print(prompt)
	r := bufio.NewReader(os.Stdin)
	line, err := r.ReadString('\n')
	return strings.TrimRight(line, "\r\n"), err
}

func promptPasswordNoEcho(prompt string) (string, error) {
	fmt.Print(prompt)
	if runtime.GOOS != "windows" {
		if tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0); err == nil {
			defer tty.Close()
			disable := exec.Command("stty", "-echo")
			disable.Stdin = tty
			if disable.Run() == nil {
				restore := func() {
					en := exec.Command("stty", "echo")
					en.Stdin = tty
					_ = en.Run()
				}
				sigCh := make(chan os.Signal, 1)
				signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
				done := make(chan struct{})
				go func() {
					select {
					case <-sigCh:
						restore()
						fmt.Fprintln(tty)
						os.Exit(130)
					case <-done:
					}
				}()
				r := bufio.NewReader(tty)
				line, rErr := r.ReadString('\n')
				close(done)
				signal.Stop(sigCh)
				restore()
				fmt.Fprintln(tty)
				return strings.TrimRight(line, "\r\n"), rErr
			}
		}
	}
	r := bufio.NewReader(os.Stdin)
	line, err := r.ReadString('\n')
	return strings.TrimRight(line, "\r\n"), err
}

func truncateDisplay(s string, maxRunes int) string {
	runes := []rune(s)
	if len(runes) <= maxRunes {
		return s
	}
	return string(runes[:maxRunes-1]) + "…"
}
