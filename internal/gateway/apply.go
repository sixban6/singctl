package gateway

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
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
	proxyRouteTable       = "100"
	proxyLocalRouteTable  = "101"
)

var defaultThrowCIDRs = []string{
	"0.0.0.0/8",
	"10.0.0.0/8",
	"100.64.0.0/10",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"172.16.0.0/12",
	"192.168.0.0/16",
}

// Controller 负责旁路由模式（Side Router）内核转发、默认路由自愈与防火墙规则的原子挂载与可逆卸载。
type Controller struct {
	StateDir        string
	FW4IncludeRoot  string
	ResolvGuardPath string
	IPv6BackupPath  string
	Prober          func() TopologyInfo
	IsOpenWrt       func() bool
	Exec            func(name string, args ...string) ([]byte, error)
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
//   - 当 mode == "main"（默认）时：绝不注入任何旁路由规则，仅清理可能残留的历史旁路由表与快照；若显式配置了 IPv6 模式则同步宿主 IPv6；
//   - 当 mode == "side" 时：校验主路由 IP、自愈旁路由默认路由、快照并设置 sysctl、原子挂载 singctl-side 规则与跨表放行规则。
func (c *Controller) Apply(ctx context.Context, cfg config.GatewayConfig) error {
	if !cfg.IsSideRouter() {
		if err := c.Teardown(ctx); err != nil {
			return err
		}
		if cfg.EffectiveIPv6Mode() != config.GatewayIPv6Off && (runtime.GOOS == "linux" || c.Exec != nil) {
			_, err := c.SyncIPv6Host(ctx, cfg)
			return err
		}
		return nil
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

	// 2. 快照并应用可逆 sysctl 内核转发参数，同时确保旁路由本机 DNS 上游文件非空且无自环污染
	if err := c.applySysctls(ctx, plan.LANIface); err != nil {
		logger.Warn("旁路由部分 sysctl 参数设置受限(容器只读项已跳过): %v", err)
	}
	c.ensureSideRouterResolvUpstream(ctx, plan.LANIP)

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

	// 5. 若 TProxy 策略路由表 100 已在运行（如 WebUI 热切旁路由模式），确保其包含私网/CGNAT throw 逃生路由，
	// 避免宿主启用 net.ipv4.conf.all.src_valid_mark=1 时被内核 martian source 静默丢包。
	c.ensureProxyTableThrowRoutes(ctx, plan.LANCIDR)

	logger.Success("已启用旁路由模式 (本机单臂口: %s %s -> 上级主路由: %s)", plan.LANIface, plan.LANIP, plan.MainRouterIP)
	return nil
}

// Teardown 卸载旁路由专属防火墙表、撤回跨表放行规则并按快照还原 sysctl 参数与上游 DNS 文件。
func (c *Controller) Teardown(ctx context.Context) error {
	if runtime.GOOS != "linux" && c.Exec == nil {
		return nil
	}
	c.cleanupFirewallOnly(ctx)
	c.restoreSideRouterResolvUpstream(ctx)
	c.restoreSysctls(ctx)
	_ = os.RemoveAll(c.stateDir())
	return nil
}

type resolvOrigSnapshot struct {
	Path    string `json:"path"`
	Existed bool   `json:"existed"`
	Content string `json:"content"`
}

func isOpenWrtSystem() bool {
	for _, p := range []string{"/etc/openwrt_release", "/etc/openwrt_version"} {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

// isRFC1918Private 判断地址是否属于 RFC1918 私网段（10/8、172.16/12、192.168/16）。
func isRFC1918Private(addr netip.Addr) bool {
	if !addr.Is4() {
		return false
	}
	b := addr.As4()
	return b[0] == 10 ||
		(b[0] == 172 && b[1]&0xF0 == 16) ||
		(b[0] == 192 && b[1] == 168)
}

// ensureSideRouterResolvUpstream 确保旁路由本机上游 resolv 文件可用，且不会绕过 sing-box 把 DNS 明文外发：
//   - OpenWrt 单臂旁路由删除 WAN 口后 /tmp/resolv.conf.d/resolv.conf.auto 常为空，或被主路由 DHCP 静态租约写成本机 IP，
//     会导致 dnsmasq 因无可用上游直接向局域网回 REFUSED（无法触发 output 链进入 sing-box -> AdGuard Home 闭环）；
//   - 更关键的是：TProxy 策略路由表 100 为通过 Tailscale/WireGuard 的 src_valid_mark=1 反向源校验，必须携带 RFC1918
//     throw 逃生路由。若 dnsmasq 上游是私网网关（如 192.168.1.1），其发往 :53 的报文会命中 throw 直接跳出表 100 明文外发，
//     既绕过 sing-box/AdGuard Home 造成 DNS 泄漏，若主路由 DNS 又指回旁路由还会形成双向死循环；
//   - 因此旁路由模式下把私网/回环/自身上游收敛为公网引导 DNS（223.5.5.5），让 output 链标记后的 :53 报文命中
//     local default dev lo 回环进 sing-box。保留 CGNAT（100.64/10，如 Tailscale MagicDNS）等非 RFC1918 上游。
func (c *Controller) ensureSideRouterResolvUpstream(ctx context.Context, lanIP string) {
	targetPath := strings.TrimSpace(c.ResolvGuardPath)
	isDnsmasqResolvFile := false

	if targetPath != "" {
		isDnsmasqResolvFile = strings.HasSuffix(targetPath, "resolv.conf.auto")
	} else {
		if c.Exec != nil {
			return
		}
		if isOpenWrtSystem() {
			isDnsmasqResolvFile = true
			if out, err := c.runCmd(ctx, "uci", "-q", "get", "dhcp.@dnsmasq[0].resolvfile"); err == nil {
				targetPath = strings.TrimSpace(string(out))
			}
			targetPath = cmp.Or(targetPath, "/tmp/resolv.conf.d/resolv.conf.auto")
		} else {
			targetPath = "/etc/resolv.conf"
		}
	}

	raw, readErr := os.ReadFile(targetPath)
	existed := readErr == nil
	content := string(raw)

	hasUsableUpstream := false
	for line := range strings.SplitSeq(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		addr, err := netip.ParseAddr(fields[1])
		if err != nil || addr.IsUnspecified() {
			continue
		}
		if lanIP != "" && addr.String() == lanIP {
			continue
		}
		if isRFC1918Private(addr) || addr.IsLinkLocalUnicast() {
			continue
		}
		if isDnsmasqResolvFile && addr.IsLoopback() {
			continue
		}
		hasUsableUpstream = true
		break
	}
	if hasUsableUpstream {
		return
	}

	snapPath := filepath.Join(c.stateDir(), "resolv.orig.json")
	if _, err := os.Stat(snapPath); os.IsNotExist(err) {
		snap := resolvOrigSnapshot{
			Path:    targetPath,
			Existed: existed,
			Content: content,
		}
		if b, mErr := json.Marshal(snap); mErr == nil {
			_ = os.WriteFile(snapPath, b, 0600)
		}
	}

	if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
		return
	}
	guardContent := "# Managed by singctl side-router guard\nnameserver 223.5.5.5\nnameserver 119.29.29.29\n"
	if err := os.WriteFile(targetPath, []byte(guardContent), 0644); err != nil {
		logger.Warn("写入旁路由上游 DNS 引导文件 %s 失败: %v", targetPath, err)
		return
	}
	if isDnsmasqResolvFile {
		_, _ = c.runCmd(ctx, "killall", "-HUP", "dnsmasq")
	}
}

func (c *Controller) restoreSideRouterResolvUpstream(ctx context.Context) {
	snapPath := filepath.Join(c.stateDir(), "resolv.orig.json")
	raw, err := os.ReadFile(snapPath)
	if err != nil {
		return
	}
	var snap resolvOrigSnapshot
	if err := json.Unmarshal(raw, &snap); err != nil || snap.Path == "" {
		return
	}
	if snap.Existed {
		_ = os.WriteFile(snap.Path, []byte(snap.Content), 0644)
	} else {
		_ = os.Remove(snap.Path)
	}
	_ = os.Remove(snapPath)
	if strings.HasSuffix(snap.Path, "resolv.conf.auto") || isOpenWrtSystem() {
		_, _ = c.runCmd(ctx, "killall", "-HUP", "dnsmasq")
	}
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
		{"-I", "INPUT", "1", "-m", "mark", "--mark", "0x2", "-m", "comment", "--comment", ruleCommentTag, "-j", "ACCEPT"},
		{"-I", "FORWARD", "1", "-i", lanIface, "-m", "comment", "--comment", ruleCommentTag, "-j", "ACCEPT"},
		{"-I", "FORWARD", "1", "-o", lanIface, "-m", "comment", "--comment", ruleCommentTag, "-j", "ACCEPT"},
	}
	for _, r := range rules {
		var checkArgs []string
		if r[1] == "INPUT" {
			checkArgs = []string{"-C", "INPUT", "-m", "mark", "--mark", r[5], "-m", "comment", "--comment", ruleCommentTag, "-j", "ACCEPT"}
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
				chain: "input",
				content: fmt.Sprintf(
					"meta mark 0x1 accept comment %q\nmeta mark 0x2 accept comment %q\niifname %q accept comment %q\n",
					ruleCommentTag, ruleCommentTag, lanIface, ruleCommentTag,
				),
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
	_, _ = c.runCmd(ctx, "nft", "insert", "rule", "inet", "fw4", "input", "meta", "mark", "0x2", "accept", "comment", ruleCommentTag)
	_, _ = c.runCmd(ctx, "nft", "insert", "rule", "inet", "fw4", "input", "iifname", lanIface, "accept", "comment", ruleCommentTag)
	_, _ = c.runCmd(ctx, "nft", "insert", "rule", "inet", "fw4", "forward", "iifname", lanIface, "accept", "comment", ruleCommentTag)
	_, _ = c.runCmd(ctx, "nft", "insert", "rule", "inet", "fw4", "forward", "oifname", lanIface, "accept", "comment", ruleCommentTag)
}

func (c *Controller) ensureProxyTableThrowRoutes(ctx context.Context, lanCIDR string) {
	out, err := c.runCmd(ctx, "ip", "-4", "route", "show", "table", proxyRouteTable)
	if err != nil || !strings.Contains(string(out), "local ") {
		return
	}
	for _, cidr := range defaultThrowCIDRs {
		_, _ = c.runCmd(ctx, "ip", "-4", "route", "replace", "throw", cidr, "table", proxyRouteTable)
	}
	if trimmed := strings.TrimSpace(lanCIDR); trimmed != "" {
		_, _ = c.runCmd(ctx, "ip", "-4", "route", "replace", "throw", trimmed, "table", proxyRouteTable)
	}
	_, _ = c.runCmd(ctx, "ip", "-4", "route", "replace", "local", "default", "dev", "lo", "table", proxyLocalRouteTable)
}

func (c *Controller) applyLegacyIptablesSideRules(ctx context.Context, plan ResolvedPlan) error {
	if plan.InterceptLocalDNS && plan.LANIP != "" {
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
