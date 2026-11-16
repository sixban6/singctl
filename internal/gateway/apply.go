package gateway

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"singctl/internal/config"
	"singctl/internal/logger"
)

const (
	defaultStateDir       = "/tmp/singctl-side-state"
	defaultFW4IncludeRoot = "/usr/share/nftables.d"
	fw4IncludeFileName    = "singctl-side.nft"
	ruleCommentTag        = "singctl-side"
	legacySideChainFwd    = "SINGCTL_SIDE_FWD"
	legacySideChainNat    = "SINGCTL_SIDE_NAT"
)

// Controller 负责旁路由模式（Side Router）内核转发、默认路由自愈与防火墙规则的原子挂载与可逆卸载。
type Controller struct {
	StateDir       string
	FW4IncludeRoot string
	Prober         func() TopologyInfo
	Exec           func(name string, args ...string) ([]byte, error)
}

// NewController 创建默认旁路由控制器。
func NewController() *Controller {
	return &Controller{
		StateDir:       defaultStateDir,
		FW4IncludeRoot: defaultFW4IncludeRoot,
		Prober:         ProbeTopology,
	}
}

func (c *Controller) stateDir() string {
	return cmp.Or(strings.TrimSpace(c.StateDir), defaultStateDir)
}

func (c *Controller) fw4IncludeRoot() string {
	return cmp.Or(strings.TrimSpace(c.FW4IncludeRoot), defaultFW4IncludeRoot)
}

func (c *Controller) probe() TopologyInfo {
	if c.Prober != nil {
		return c.Prober()
	}
	return ProbeTopology()
}

func (c *Controller) runCmd(ctx context.Context, name string, args ...string) ([]byte, error) {
	if c.Exec != nil {
		return c.Exec(name, args...)
	}
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

func (c *Controller) hasCommand(name string) bool {
	if c.Exec != nil {
		return true
	}
	_, err := exec.LookPath(name)
	return err == nil
}

// Apply 根据客户端 gateway 配置执行模式对齐：
//   - 当 mode == "main"（默认）时：绝不注入任何旁路由规则，仅清理可能残留的历史旁路由表与快照；
//   - 当 mode == "side" 时：校验主路由 IP、自愈旁路由默认路由、快照并设置 sysctl、原子挂载 singctl-side 规则与跨表放行规则。
func (c *Controller) Apply(ctx context.Context, cfg config.GatewayConfig) error {
	if !cfg.IsSideRouter() {
		return c.Teardown(ctx)
	}
	if runtime.GOOS != "linux" && c.Exec == nil {
		return nil
	}

	topo := c.probe()
	plan, err := ResolveAndValidate(cfg, topo)
	if err != nil {
		return err
	}
	if plan.LANIface == "" {
		return fmt.Errorf("未能识别旁路由局域网网卡，请在 singctl.yaml 的 gateway.lan_iface 中显式指定")
	}

	if err := os.MkdirAll(c.stateDir(), 0700); err != nil {
		return fmt.Errorf("创建旁路由状态目录失败: %w", err)
	}

	// 1. 默认路由对齐与防 DHCP 网关污染自愈
	if plan.LANIface != "" {
		if _, rErr := c.runCmd(ctx, "ip", "-4", "route", "replace", "default", "via", plan.MainRouterIP, "dev", plan.LANIface); rErr != nil {
			if out, fbErr := c.runCmd(ctx, "ip", "-4", "route", "replace", "default", "via", plan.MainRouterIP); fbErr != nil {
				return fmt.Errorf("设置旁路由上级默认网关 %s 失败: %w (%s)", plan.MainRouterIP, fbErr, strings.TrimSpace(string(out)))
			}
		}
	}

	// 2. 快照并应用可逆 sysctl 内核转发参数
	if err := c.applySysctls(ctx, plan.LANIface); err != nil {
		logger.Warn("旁路由部分 sysctl 参数设置受限(容器只读项已跳过): %v", err)
	}

	// 3. 清理旧表后挂载独立隔离的旁路由规则表 + 宿主跨表放行项
	c.cleanupFirewallOnly(ctx)
	if c.hasCommand("nft") {
		nftPath := filepath.Join(c.stateDir(), "singctl-side.nft")
		nftContent := BuildSideRouterNFT(plan)
		if err := os.WriteFile(nftPath, []byte(nftContent), 0600); err != nil {
			return fmt.Errorf("写入旁路由 nft 规则文件失败: %w", err)
		}
		if out, err := c.runCmd(ctx, "nft", "-c", "-f", nftPath); err != nil {
			return fmt.Errorf("旁路由 nftables 语法预检失败: %w (%s)", err, strings.TrimSpace(string(out)))
		}
		if out, err := c.runCmd(ctx, "nft", "-f", nftPath); err != nil {
			return fmt.Errorf("加载旁路由 nftables 规则失败: %w (%s)", err, strings.TrimSpace(string(out)))
		}
		c.applyFW4PassThrough(ctx, plan.LANIface)
	} else if c.hasCommand("iptables") {
		if err := c.applyLegacyIptablesSideRules(ctx, plan); err != nil {
			return err
		}
	}

	// 4. 若宿主存在 iptables filter 表（如 Debian 安装了 Docker 将 FORWARD 默认设为 DROP），在链首插入带注释的高优放行
	if c.hasCommand("iptables") {
		c.applyIptablesFilterPassThrough(ctx, plan.LANIface)
	}

	logger.Success("已启用旁路由模式 (本机单臂口: %s %s -> 上级主路由: %s)", plan.LANIface, plan.LANIP, plan.MainRouterIP)
	return nil
}

// Teardown 卸载旁路由专属防火墙表、撤回跨表放行规则并按快照还原 sysctl 参数。
func (c *Controller) Teardown(ctx context.Context) error {
	if runtime.GOOS != "linux" && c.Exec == nil {
		return nil
	}
	c.cleanupFirewallOnly(ctx)
	c.restoreSysctls(ctx)
	_ = os.RemoveAll(c.stateDir())
	return nil
}

func (c *Controller) applySysctls(ctx context.Context, lanIface string) error {
	origPath := filepath.Join(c.stateDir(), "sysctl.orig.json")
	_, hasBridge := os.Stat("/proc/sys/net/bridge/bridge-nf-call-iptables")
	desired := BuildSideRouterSysctls(lanIface, hasBridge == nil)

	// 仅在首次挂载且快照不存在时保存初始值，避免多次 restart 把已改过的值覆盖成原值
	if _, err := os.Stat(origPath); os.IsNotExist(err) {
		origMap := make(map[string]string, len(desired))
		for _, kv := range desired {
			if out, rErr := c.runCmd(ctx, "sysctl", "-n", kv.Key); rErr == nil {
				val := strings.TrimSpace(string(out))
				if val != "" {
					origMap[kv.Key] = val
				}
			}
		}
		if b, mErr := json.Marshal(origMap); mErr == nil {
			_ = os.WriteFile(origPath, b, 0600)
		}
	}

	var firstErr error
	for _, kv := range desired {
		if _, err := c.runCmd(ctx, "sysctl", "-w", kv.Key+"="+kv.Value); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (c *Controller) restoreSysctls(ctx context.Context) {
	origPath := filepath.Join(c.stateDir(), "sysctl.orig.json")
	raw, err := os.ReadFile(origPath)
	if err != nil {
		return
	}
	var origMap map[string]string
	if err := json.Unmarshal(raw, &origMap); err != nil {
		return
	}
	for k, v := range origMap {
		_, _ = c.runCmd(ctx, "sysctl", "-w", k+"="+v)
	}
	_ = os.Remove(origPath)
}

func (c *Controller) applyIptablesFilterPassThrough(ctx context.Context, lanIface string) {
	rules := [][]string{
		{"-I", "INPUT", "1", "-m", "mark", "--mark", "0x1", "-m", "comment", "--comment", ruleCommentTag, "-j", "ACCEPT"},
		{"-I", "FORWARD", "1", "-i", lanIface, "-m", "comment", "--comment", ruleCommentTag, "-j", "ACCEPT"},
		{"-I", "FORWARD", "1", "-o", lanIface, "-m", "comment", "--comment", ruleCommentTag, "-j", "ACCEPT"},
	}
	for _, r := range rules {
		checkArgs := append([]string{"-C"}, r[1], r[3])
		if r[1] == "INPUT" {
			checkArgs = []string{"-C", "INPUT", "-m", "mark", "--mark", "0x1", "-m", "comment", "--comment", ruleCommentTag, "-j", "ACCEPT"}
		} else {
			checkArgs = []string{"-C", "FORWARD", r[3], r[4], "-m", "comment", "--comment", ruleCommentTag, "-j", "ACCEPT"}
		}
		if _, err := c.runCmd(ctx, "iptables", checkArgs...); err != nil {
			_, _ = c.runCmd(ctx, "iptables", r...)
		}
	}
}

func (c *Controller) applyFW4PassThrough(ctx context.Context, lanIface string) {
	if st, err := os.Stat(c.fw4IncludeRoot()); err == nil && st.IsDir() {
		includes := []struct {
			chain   string
			content string
		}{
			{
				chain:   "input",
				content: fmt.Sprintf("meta mark 0x1 accept comment %q\n", ruleCommentTag),
			},
			{
				chain:   "forward",
				content: fmt.Sprintf("iifname %q accept comment %q\noifname %q accept comment %q\n", lanIface, ruleCommentTag, lanIface, ruleCommentTag),
			},
		}
		for _, inc := range includes {
			dir := filepath.Join(c.fw4IncludeRoot(), "chain-pre", inc.chain)
			if mkErr := os.MkdirAll(dir, 0755); mkErr != nil {
				logger.Warn("创建 fw4 include 目录 %s 失败: %v", dir, mkErr)
				continue
			}
			path := filepath.Join(dir, fw4IncludeFileName)
			if wErr := os.WriteFile(path, []byte(inc.content), 0600); wErr != nil {
				logger.Warn("写入 fw4 持久化规则 %s 失败: %v", path, wErr)
			}
		}
	}

	if _, err := c.runCmd(ctx, "nft", "list", "table", "inet", "fw4"); err != nil {
		return
	}
	_, _ = c.runCmd(ctx, "nft", "insert", "rule", "inet", "fw4", "input", "meta", "mark", "0x1", "accept", "comment", ruleCommentTag)
	_, _ = c.runCmd(ctx, "nft", "insert", "rule", "inet", "fw4", "forward", "iifname", lanIface, "accept", "comment", ruleCommentTag)
	_, _ = c.runCmd(ctx, "nft", "insert", "rule", "inet", "fw4", "forward", "oifname", lanIface, "accept", "comment", ruleCommentTag)
}

func (c *Controller) applyLegacyIptablesSideRules(ctx context.Context, plan ResolvedPlan) error {
	if plan.LANIP != "" {
		_, _ = c.runCmd(ctx, "iptables", "-t", "mangle", "-I", "PREROUTING", "1", "!", "-i", "lo", "-d", plan.LANIP, "-p", "udp", "--dport", "53", "-m", "comment", "--comment", ruleCommentTag, "-j", "TPROXY", "--on-port", "7895", "--tproxy-mark", "0x1")
		_, _ = c.runCmd(ctx, "iptables", "-t", "mangle", "-I", "PREROUTING", "1", "!", "-i", "lo", "-d", plan.LANIP, "-p", "tcp", "--dport", "53", "-m", "comment", "--comment", ruleCommentTag, "-j", "TPROXY", "--on-port", "7895", "--tproxy-mark", "0x1")
	}
	_, _ = c.runCmd(ctx, "iptables", "-t", "mangle", "-N", legacySideChainFwd)
	_, _ = c.runCmd(ctx, "iptables", "-t", "mangle", "-F", legacySideChainFwd)
	_, _ = c.runCmd(ctx, "iptables", "-t", "mangle", "-A", legacySideChainFwd, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu")
	_, _ = c.runCmd(ctx, "iptables", "-t", "mangle", "-I", "FORWARD", "1", "-j", legacySideChainFwd)

	_, _ = c.runCmd(ctx, "iptables", "-t", "nat", "-N", legacySideChainNat)
	_, _ = c.runCmd(ctx, "iptables", "-t", "nat", "-F", legacySideChainNat)
	_, _ = c.runCmd(ctx, "iptables", "-t", "nat", "-A", legacySideChainNat, "-o", plan.LANIface, "-s", plan.LANCIDR, "!", "-d", plan.LANCIDR, "-j", "MASQUERADE")
	_, _ = c.runCmd(ctx, "iptables", "-t", "nat", "-I", "POSTROUTING", "1", "-j", legacySideChainNat)
	return nil
}

func (c *Controller) cleanupFirewallOnly(ctx context.Context) {
	root := c.fw4IncludeRoot()
	for _, chain := range []string{"input", "forward"} {
		_ = os.Remove(filepath.Join(root, "chain-pre", chain, fw4IncludeFileName))
	}

	if c.hasCommand("nft") {
		_, _ = c.runCmd(ctx, "nft", "delete", "table", "inet", "singctl-side")
		// 清理 fw4 中带 singctl-side 注释的规则句柄
		for _, chain := range []string{"input", "forward"} {
			out, err := c.runCmd(ctx, "nft", "-a", "list", "chain", "inet", "fw4", chain)
			if err != nil {
				continue
			}
			for line := range strings.SplitSeq(string(out), "\n") {
				if !strings.Contains(line, ruleCommentTag) {
					continue
				}
				if _, after, ok := strings.Cut(line, "# handle "); ok {
					handle := strings.Fields(after)
					if len(handle) > 0 {
						_, _ = c.runCmd(ctx, "nft", "delete", "rule", "inet", "fw4", chain, "handle", handle[0])
					}
				}
			}
		}
	}

	if c.hasCommand("iptables") {
		// 按规则规格循环移除带 singctl-side 注释的 INPUT/FORWARD 项
		if out, err := c.runCmd(ctx, "iptables", "-S", "INPUT"); err == nil {
			c.deleteCommentedIptablesRules(ctx, "filter", out)
		}
		if out, err := c.runCmd(ctx, "iptables", "-S", "FORWARD"); err == nil {
			c.deleteCommentedIptablesRules(ctx, "filter", out)
		}
		if out, err := c.runCmd(ctx, "iptables", "-t", "mangle", "-S", "PREROUTING"); err == nil {
			c.deleteCommentedIptablesRules(ctx, "mangle", out)
		}
		_, _ = c.runCmd(ctx, "iptables", "-t", "mangle", "-D", "FORWARD", "-j", legacySideChainFwd)
		_, _ = c.runCmd(ctx, "iptables", "-t", "mangle", "-F", legacySideChainFwd)
		_, _ = c.runCmd(ctx, "iptables", "-t", "mangle", "-X", legacySideChainFwd)
		_, _ = c.runCmd(ctx, "iptables", "-t", "nat", "-D", "POSTROUTING", "-j", legacySideChainNat)
		_, _ = c.runCmd(ctx, "iptables", "-t", "nat", "-F", legacySideChainNat)
		_, _ = c.runCmd(ctx, "iptables", "-t", "nat", "-X", legacySideChainNat)
	}
}

func (c *Controller) deleteCommentedIptablesRules(ctx context.Context, table string, rawSpecs []byte) {
	for line := range strings.SplitSeq(string(rawSpecs), "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "-A ") || !strings.Contains(trimmed, ruleCommentTag) {
			continue
		}
		delSpec := "-D " + strings.TrimPrefix(trimmed, "-A ")
		fields := strings.Fields(delSpec)
		for i := range fields {
			fields[i] = strings.Trim(fields[i], `"`)
		}
		args := append([]string{"-t", table}, fields...)
		_, _ = c.runCmd(ctx, "iptables", args...)
	}
}
