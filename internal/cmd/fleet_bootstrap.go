//go:build !lite

// 文件职责：提供舰队新裸机零配置开荒 (`singctl fleet new`) 子命令、交互向导与位置参数解析。
package cmd

import (
	"bufio"
	"cmp"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"singctl/internal/fleet"
	"singctl/internal/logger"

	"github.com/spf13/cobra"
)

const fleetBootstrapLongDesc = `在主控节点上远程开荒一台全新空白 VPS，默认自动复用本机 /etc/singctl/singctl.yaml 配置：
  • 自动探测新机 IP 地理位置，智能分配不冲突代号与中文名称（如 sg1 / 新加坡、jp2 / 日本·东京 #2）
  • 自动复用主控 cf_dns_key 查询根域名，创建 <id>.cdn.<根域名> 灰云（仅 DNS）解析记录（下线 rm 时自动清理）
  • 自动完成 SSH 双公钥注入、22→2222 端口防锁死切换、禁用密码登录并擦除明文密码
  • 自动部署四核服务端并将 HY2 / VLESS-Reality 节点汇入本机总订阅

极简用法示例:
  1) 零参数交互向导（推荐，密码不回显、不进命令历史）:
     singctl fl new

  2) 一行非交互命令（直接传 IP 或 IP:SSH端口）:
     singctl fl new 203.0.113.10 --password '<新机初始密码>'
     singctl fl new 203.0.113.10:15500 --hy2-port 11501 --vless-port 11502 --password '<新机初始密码>'

  3) 显式自定义代号与域名（完全兼容手动指定）:
     singctl fl new jp1 203.0.113.10 --name "日本东京" --password '<密码>' --domain jp1.cdn.example.com`

func newFleetBootstrapCmd(fc *fleetCmdContext) *cobra.Command {
	var (
		bsIn        fleet.BootstrapInput
		bsHardenSSH bool
		bsYes       bool
	)
	bootstrapCmd := &cobra.Command{
		Use:     "new [host[:port] | id] [host[:port]]",
		Aliases: []string{"init", "bs", "bootstrap"},
		Short:   "新购裸机智能零配置开荒：复用主控凭据 + 自动创建 .cdn 灰云 DNS + SSH(22→2222免密) + 四核部署纳管",
		Long:    fleetBootstrapLongDesc,
		Args:    cobra.MaximumNArgs(2),
		RunE: func(c *cobra.Command, args []string) error {
			return runFleetBootstrap(c, fc, args, &bsIn, &bsHardenSSH, bsYes)
		},
	}
	registerFleetBootstrapFlags(bootstrapCmd, &bsIn, &bsHardenSSH, &bsYes)
	return bootstrapCmd
}

func registerFleetBootstrapFlags(cmd *cobra.Command, bsIn *fleet.BootstrapInput, bsHardenSSH, bsYes *bool) {
	cmd.Flags().StringVar(&bsIn.Name, "name", "", "(可选) 子节点显示名称，留空按 IP 归属地自动生成中文名")
	cmd.Flags().StringVar(&bsIn.Host, "host", "", "新服务器公网 IP 或主机名 (不传则进入免回显交互向导)")
	cmd.Flags().StringVar(&bsIn.SSHAlias, "alias", "", "本地 ~/.ssh/config 别名")
	cmd.Flags().IntVar(&bsIn.Port, "port", 22, "初始 SSH 端口 (新购裸机通常为 22)")
	cmd.Flags().StringVar(&bsIn.User, "user", "root", "SSH 用户名")
	cmd.Flags().StringVar(&bsIn.KeyPath, "key", "", "初始 SSH 私钥路径 (若新机使用密码登录可留空)")
	cmd.Flags().StringVar(&bsIn.Password, "password", "", "初始 SSH 登录密码 (加固完成后自动擦除明文并切为密钥免密)")
	cmd.Flags().BoolVar(bsHardenSSH, "harden-ssh", true, "自动注入主控+本机公钥、验证切换 SSH 端口并禁用密码登录")
	cmd.Flags().IntVar(&bsIn.TargetSSHPort, "target-port", fleet.DefaultTargetSSHPort, "SSH 安全加固目标端口 (默认收敛至 2222)")
	cmd.Flags().StringVar(&bsIn.ExtraAuthorizedKeys, "extra-pubkey", "", "(可选) 额外写入新机的管理员 SSH 公钥字符串")
	cmd.Flags().StringVar(&bsIn.NodeDomain, "domain", "", "(可选) 绑定域名，留空自动从主控根域名分配 <id>.cdn.<根域名> 并创建灰云解析")
	cmd.Flags().IntVar(&bsIn.Hy2Port, "hy2-port", 443, "(可选) Hysteria 2 (UDP QUIC) 对外监听与订阅端口，默认 443")
	cmd.Flags().IntVar(&bsIn.VlessPort, "vless-port", 443, "(可选) VLESS Reality (TCP) 与 HTTPS 网关对外监听与订阅端口，默认 443")
	cmd.Flags().StringVar(&bsIn.SubstoreDomain, "sub-domain", "", "(可选) 独立订阅域名")
	cmd.Flags().StringVar(&bsIn.CFDNSKey, "cf-token", "", "(可选) Cloudflare DNS Token，留空自动复用主控配置")
	cmd.Flags().StringVar(&bsIn.NodeTag, "tag", "", "(可选) 节点代号，留空与自动推导的 <id> 一致")
	cmd.Flags().StringVar(&bsIn.SNI, "sni", "", "(可选) Reality SNI 伪装域名，留空自动复用主控配置")
	cmd.Flags().BoolVar(&bsIn.SkipDNS, "skip-dns", false, "跳过自动调用 Cloudflare API 创建/更新 DNS 记录")
	cmd.Flags().BoolVar(&bsIn.Reprovision, "reprovision", false, "针对已重装系统的已纳管节点执行原地重开（复用原代号与域名，重写配置并轮换节点凭据）")
	cmd.Flags().BoolVarP(bsYes, "yes", "y", false, "交互模式下跳过最终确认直接执行")
}

func runFleetBootstrap(c *cobra.Command, fc *fleetCmdContext, args []string, bsIn *fleet.BootstrapInput, bsHardenSSH *bool, bsYes bool) error {
	portChanged := c.Flags().Changed("port")
	userChanged := c.Flags().Changed("user")
	applyPositionalFleetNewArgs(args, bsIn, portChanged, userChanged)
	normalizeBootstrapHostFields(bsIn, portChanged, userChanged)

	bsIn.HardenSSH = bsHardenSSH
	if bsIn.CFDNSKey == "" {
		bsIn.CFDNSKey = os.Getenv("CF_DNS_API_TOKEN")
	}
	mgr := fc.buildManager(c)

	usedWizard := false
	if strings.TrimSpace(bsIn.Host) == "" && strings.TrimSpace(bsIn.SSHAlias) == "" {
		if err := promptFleetBootstrapWizard(bsIn, portChanged, userChanged); err != nil {
			return err
		}
		usedWizard = true
	}

	plan, err := mgr.PreviewBootstrapNode(c.Context(), *bsIn)
	if err != nil {
		return err
	}
	bsIn.ID = plan.ID
	bsIn.Name = plan.Name

	if isInteractiveTerminal() && !bsYes && usedWizard {
		if !confirmFleetBootstrapPlan(plan, bsIn.Port) {
			logger.Warn("已取消新节点开荒操作。")
			return nil
		}
	}

	logger.Info("正在连接新机器 [%s (%s)] -> 域名: %s | SSH 收敛端口: %d (预计耗时 40~90 秒)...",
		plan.Name, plan.ID, cmp.Or(plan.Domain, "自动分配"), plan.TargetSSHPort)
	res, err := mgr.BootstrapNode(c.Context(), *bsIn)
	if err != nil {
		return err
	}
	if !res.Success {
		return fmt.Errorf("%s", res.Message)
	}
	logger.Success("🎉 [%s] %s", res.Name, res.Message)
	return nil
}

func promptFleetBootstrapWizard(bsIn *fleet.BootstrapInput, portChanged, userChanged bool) error {
	if !isInteractiveTerminal() {
		return errors.New("请指定新服务器公网 IP (如 'singctl fl new 203.0.113.10')，或在交互式终端直接运行 'singctl fl new'")
	}
	fmt.Println("\n🚀 SingCtl 舰队智能零配置开荒向导（自动复用主控配置与 Cloudflare DNS）")
	fmt.Println("──────────────────────────────────────────────────────────────────────")
	hostVal, pErr := promptLine("1. 新服务器公网 IP 地址 (支持 ip:port): ")
	if pErr != nil || strings.TrimSpace(hostVal) == "" {
		return errors.New("已取消：新服务器公网 IP 不能为空")
	}
	bsIn.Host = strings.TrimSpace(hostVal)
	normalizeBootstrapHostFields(bsIn, portChanged, userChanged)

	if bsIn.Password == "" && bsIn.KeyPath == "" {
		sec, sErr := promptPasswordNoEcho("2. root 初始 SSH 密码 (输入不回显，若已配免密直接回车): ")
		if sErr != nil {
			return sErr
		}
		bsIn.Password = strings.TrimSpace(sec)
	}
	return nil
}

func confirmFleetBootstrapPlan(plan fleet.BootstrapPlan, initialPort int) bool {
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
	fmt.Printf("  • 目标主机与端口 : %s (SSH %d → %d 免密禁密码 | HY2端口 %d | VLESS端口 %d)\n",
		plan.Host, cmp.Or(initialPort, 22), plan.TargetSSHPort, plan.Hy2Port, plan.VlessPort)
	fmt.Printf("  • 绑定节点域名   : %s\n", cmp.Or(dnsDesc, "待指定"))
	fmt.Printf("  • 继承主控参数   : %s | SNI=%s | HY2=%d/%d Mbps\n", cfDesc, plan.SNI, plan.Hy2Up, plan.Hy2Down)
	fmt.Println("──────────────────────────────────────────────────────────────────────")
	ans, _ := promptLine("确认开始全自动加固与部署? [Y/n]: ")
	ans = strings.ToLower(strings.TrimSpace(ans))
	return ans == "" || ans == "y" || ans == "yes"
}

func normalizeBootstrapHostFields(bsIn *fleet.BootstrapInput, portChanged, userChanged bool) {
	if h, p, u, ok := SplitHostPortUser(bsIn.Host); ok {
		bsIn.Host = h
		if p > 0 && !portChanged {
			bsIn.Port = p
		}
		if u != "" && !userChanged {
			bsIn.User = u
		}
	}
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

// ApplyPositionalFleetNewArgs 解析 `singctl fl new` 的位置参数：
//   - `singctl fl new 203.0.113.10:15500` -> Host="203.0.113.10", Port=15500
//   - `singctl fl new 203.0.113.10`       -> Host="203.0.113.10"
//   - `singctl fl new jp1`                -> ID="jp1"
//   - `singctl fl new jp1 203.0.113.10:15500` -> ID="jp1", Host="203.0.113.10", Port=15500
func ApplyPositionalFleetNewArgs(args []string, bsIn *fleet.BootstrapInput, portFlagChanged, userFlagChanged bool) {
	applyPositionalFleetNewArgs(args, bsIn, portFlagChanged, userFlagChanged)
}

func applyPositionalFleetNewArgs(args []string, bsIn *fleet.BootstrapInput, portFlagChanged, userFlagChanged bool) {
	if len(args) == 0 || bsIn == nil {
		return
	}
	if len(args) == 1 {
		arg := strings.TrimSpace(args[0])
		if looksLikeHostOrIPArg(arg) && strings.TrimSpace(bsIn.Host) == "" {
			applyHostArgToBootstrap(arg, bsIn, portFlagChanged, userFlagChanged)
			return
		}
		bsIn.ID = arg
		return
	}
	bsIn.ID = strings.TrimSpace(args[0])
	if strings.TrimSpace(bsIn.Host) == "" {
		applyHostArgToBootstrap(strings.TrimSpace(args[1]), bsIn, portFlagChanged, userFlagChanged)
	}
}

func applyHostArgToBootstrap(raw string, bsIn *fleet.BootstrapInput, portFlagChanged, userFlagChanged bool) {
	if h, p, u, ok := SplitHostPortUser(raw); ok {
		bsIn.Host = h
		if p > 0 && !portFlagChanged {
			bsIn.Port = p
		}
		if u != "" && !userFlagChanged {
			bsIn.User = u
		}
		return
	}
	bsIn.Host = raw
}

func looksLikeHostOrIPArg(arg string) bool {
	arg = strings.TrimSpace(arg)
	if arg == "" {
		return false
	}
	return strings.ContainsAny(arg, ".:@") || net.ParseIP(arg) != nil
}

// SplitHostPortUser 解析形如 `[user@]host[:port]` 的连接目标表达式。
func SplitHostPortUser(raw string) (host string, port int, user string, ok bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", 0, "", false
	}
	if u, rest, hasAt := strings.Cut(s, "@"); hasAt && u != "" && rest != "" {
		user = strings.TrimSpace(u)
		s = strings.TrimSpace(rest)
	}
	if h, pStr, err := net.SplitHostPort(s); err == nil && h != "" && pStr != "" {
		if p, pErr := strconv.Atoi(pStr); pErr == nil && p > 0 && p <= 65535 {
			return strings.Trim(h, "[]"), p, user, true
		}
	}
	if user != "" {
		return strings.Trim(s, "[]"), 0, user, true
	}
	return s, 0, "", false
}
