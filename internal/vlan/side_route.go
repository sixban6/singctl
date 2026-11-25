// 文件职责：负责 VLAN 子网「交由旁路由分流 (side_router)」的 0600 策略清单持久化、防内网穿透防火墙规则生成与 Linux ip rule/table 188 运行时同步。
package vlan

import (
	"cmp"
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"singctl/internal/common/fsx"
	"singctl/internal/constant"
)

const (
	// SideRouteTableID 为主路由将指定 VLAN 公网流量策略路由至旁路由的独立内核路由表编号。
	SideRouteTableID = 188
	// SideRoutePrefBase 与 SideRoutePrefMax 定义受管 ip rule 优先级区间（绝不干扰系统 local/main 及 Tailscale rule 5270）。
	SideRoutePrefBase = 18810
	SideRoutePrefMax  = 18890

	// DefaultFW4NftablesDir 为 OpenWrt 22+/24+ firewall4 标准持久化 include 根目录。
	DefaultFW4NftablesDir = "/usr/share/nftables.d"
	fw4SideNoMasqRelPath  = "chain-pre/srcnat_lan/singctl-side-nomasq.nft"
	// DefaultFW3SideNoMasqScript 为 OpenWrt 21 firewall3 (iptables) 子网免伪装持久化 include 脚本路径。
	DefaultFW3SideNoMasqScript = "/etc/singctl/vlan-side-nomasq.fw3.sh"
	fw3SideNoMasqUCISec        = "singctl_vlan_nomasq"

	sideRouteNoMasqComment = "singctl-side-nomasq"
)

// SyncFW3SideNoMasqInclude 持久化 OpenWrt 21 firewall3 子网免伪装脚本并绑定 firewall include，确保 fw3 restart 后持久生效。
func SyncFW3SideNoMasqInclude(scriptPath string, cidrs []string, run CommandRunner) error {
	norm, err := NormalizeBypassCIDRs(cidrs)
	if err != nil {
		return err
	}
	if run == nil {
		if runtime.GOOS != "linux" {
			return nil
		}
		run = defaultSideRouteRunner
	}
	path := cmp.Or(strings.TrimSpace(scriptPath), DefaultFW3SideNoMasqScript)
	uciSec := "firewall." + fw3SideNoMasqUCISec
	if len(norm) == 0 {
		_ = os.Remove(path)
		if _, gErr := run(context.Background(), "uci", "-q", "get", uciSec); gErr == nil {
			_, _ = run(context.Background(), "uci", "delete", uciSec)
			_, _ = run(context.Background(), "uci", "commit", "firewall")
		}
		return nil
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	_ = os.Chmod(dir, 0700)

	var b strings.Builder
	b.WriteString("# Managed by singctl VLAN side-router L3 real-IP passthrough (OpenWrt fw3 include)\n")
	b.WriteString("iptables -w 2 -t nat -S postrouting_lan_rule 2>/dev/null | while IFS= read -r line; do\n")
	b.WriteString("  case \"$line\" in\n")
	b.WriteString("    \"-A postrouting_lan_rule \"*" + sideRouteNoMasqComment + "*)\n")
	b.WriteString("      spec=\"${line#-A postrouting_lan_rule }\"\n")
	b.WriteString("      eval \"set -- $spec\"\n")
	b.WriteString("      iptables -w 2 -t nat -D postrouting_lan_rule \"$@\" 2>/dev/null || true\n")
	b.WriteString("      ;;\n")
	b.WriteString("  esac\n")
	b.WriteString("done\n")
	for _, cidr := range norm {
		b.WriteString(fmt.Sprintf("iptables -w 2 -t nat -I postrouting_lan_rule 1 -s %s -m comment --comment %s -j ACCEPT\n", cidr, sideRouteNoMasqComment))
	}
	if err := fsx.WriteAtomic0600(path, []byte(b.String())); err != nil {
		return err
	}

	_, _ = run(context.Background(), "uci", "set", uciSec+"=include")
	_, _ = run(context.Background(), "uci", "set", uciSec+".type=script")
	_, _ = run(context.Background(), "uci", "set", uciSec+".path="+path)
	_, _ = run(context.Background(), "uci", "set", uciSec+".reload=1")
	_, _ = run(context.Background(), "uci", "commit", "firewall")
	return nil
}

// SyncFW4SideNoMasqInclude 持久化 OpenWrt 24 firewall4 (srcnat_lan chain-pre) 子网免伪装规则，确保 fw4 restart 后 0ms 间隙持久生效。
func SyncFW4SideNoMasqInclude(fw4Root string, cidrs []string) error {
	norm, err := NormalizeBypassCIDRs(cidrs)
	if err != nil {
		return err
	}
	root := cmp.Or(strings.TrimSpace(fw4Root), DefaultFW4NftablesDir)
	st, err := os.Stat(root)
	if err != nil || !st.IsDir() {
		return nil
	}
	target := filepath.Join(root, fw4SideNoMasqRelPath)
	if len(norm) == 0 {
		_ = os.Remove(target)
		return nil
	}
	dir := filepath.Dir(target)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	_ = os.Chmod(dir, 0700)

	var b strings.Builder
	b.WriteString("# Managed by singctl VLAN side-router L3 real-IP passthrough\n")
	b.WriteString("ip saddr { ")
	b.WriteString(strings.Join(norm, ", "))
	b.WriteString(` } accept comment "`)
	b.WriteString(sideRouteNoMasqComment)
	b.WriteString("\"\n")
	return fsx.WriteAtomic0600(target, []byte(b.String()))
}

var sideRouteThrowCIDRs = []string{
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"100.64.0.0/10",
}

// CommandRunner 抽象外部系统命令执行器（测试可注入替身，nil 默认回退 exec.CommandContext）。
type CommandRunner func(ctx context.Context, name string, args ...string) ([]byte, error)

// VLANSideRouteSpec 描述需要经由旁路由策略分流的 VLAN 子网清单与下一跳旁路由 IP。
type VLANSideRouteSpec struct {
	SideRouterIP string   `json:"sideRouterIp"`
	CIDRs        []string `json:"cidrs"`
}

func validateSideRouterNextHopIP(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", nil
	}
	if hasControlOrInject(s) || strings.ContainsAny(s, " \t") {
		return "", fmt.Errorf("旁路由下一跳 IP %q 包含非法字符", raw)
	}
	addr, err := netip.ParseAddr(s)
	if err != nil || !addr.Is4() {
		return "", fmt.Errorf("旁路由下一跳 IP %q 不是合法的 IPv4 地址", raw)
	}
	if addr.IsLoopback() || addr.IsUnspecified() || addr.IsMulticast() || addr.IsLinkLocalUnicast() || addr == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return "", fmt.Errorf("不允许将回环或保留 IP (%s) 设为旁路由下一跳", s)
	}
	return addr.String(), nil
}

// NormalizeSideRouteSpec 严格校验、去重并排序 VLAN 旁路由策略路由清单。
func NormalizeSideRouteSpec(raw VLANSideRouteSpec) (VLANSideRouteSpec, error) {
	nextHop, err := validateSideRouterNextHopIP(raw.SideRouterIP)
	if err != nil {
		return VLANSideRouteSpec{}, err
	}
	cidrs, err := NormalizeBypassCIDRs(raw.CIDRs)
	if err != nil {
		return VLANSideRouteSpec{}, err
	}
	if len(cidrs) > SideRoutePrefMax-SideRoutePrefBase+1 {
		return VLANSideRouteSpec{}, fmt.Errorf("旁路由托管 VLAN 数量超出上限 (%d)", SideRoutePrefMax-SideRoutePrefBase+1)
	}
	if len(cidrs) == 0 {
		cidrs = nil
	}
	return VLANSideRouteSpec{
		SideRouterIP: nextHop,
		CIDRs:        cidrs,
	}, nil
}

// WriteSideRouteSpec 以 0600 权限原子落盘 VLAN 旁路由策略清单文件。
func WriteSideRouteSpec(path string, spec VLANSideRouteSpec) error {
	cleanPath := strings.TrimSpace(path)
	if cleanPath == "" {
		return fmt.Errorf("side routes file path must not be empty")
	}
	norm, err := NormalizeSideRouteSpec(spec)
	if err != nil {
		return err
	}
	dir := filepath.Dir(cleanPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	_ = os.Chmod(dir, 0700)

	var b strings.Builder
	b.WriteString("# Managed by singctl VLAN side-router PBR\n")
	if norm.SideRouterIP != "" {
		b.WriteString("# side_router_ip=")
		b.WriteString(norm.SideRouterIP)
		b.WriteByte('\n')
	}
	for _, c := range norm.CIDRs {
		b.WriteString(c)
		b.WriteByte('\n')
	}
	return fsx.WriteAtomic0600(cleanPath, []byte(b.String()))
}

// ReadSideRouteSpec 读取已持久化的 VLAN 旁路由策略清单（缺失或损坏时安全返回零值）。
func ReadSideRouteSpec(path string) VLANSideRouteSpec {
	raw, err := os.ReadFile(strings.TrimSpace(path))
	if err != nil {
		return VLANSideRouteSpec{}
	}
	var spec VLANSideRouteSpec
	for line := range strings.SplitSeq(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if after, ok := strings.CutPrefix(trimmed, "# side_router_ip="); ok {
			spec.SideRouterIP = strings.TrimSpace(after)
			continue
		}
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		spec.CIDRs = append(spec.CIDRs, trimmed)
	}
	norm, err := NormalizeSideRouteSpec(spec)
	if err != nil {
		return VLANSideRouteSpec{}
	}
	return norm
}

var sideRouteRuntimeMu sync.Mutex

func defaultSideRouteRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	if runtime.GOOS != "linux" {
		return nil, nil
	}
	if name == "iptables" && !slices.Contains(args, "-w") {
		_ = os.MkdirAll("/var/run", 0755)
		args = append([]string{"-w", "2"}, args...)
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return exec.CommandContext(cctx, name, args...).CombinedOutput()
}

func syncDefaultSideNoMasqIncludes(cidrs []string, run CommandRunner) {
	_ = SyncFW4SideNoMasqInclude(DefaultFW4NftablesDir, cidrs)
	if st, err := os.Stat(DefaultFW4NftablesDir); err == nil && st.IsDir() {
		return
	}
	if _, fw3Err := os.Stat("/sbin/fw3"); fw3Err == nil {
		_ = SyncFW3SideNoMasqInclude(DefaultFW3SideNoMasqScript, cidrs, run)
	}
}

func deleteManagedSideRouteRules(ctx context.Context, run CommandRunner) {
	out, err := run(ctx, "ip", "-4", "rule", "show")
	if err != nil {
		return
	}
	tableToken := "lookup " + strconv.Itoa(SideRouteTableID)
	for line := range strings.SplitSeq(string(out), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		prefRaw, rest, ok := strings.Cut(trimmed, ":")
		if !ok {
			continue
		}
		pref, pErr := strconv.Atoi(strings.TrimSpace(prefRaw))
		if pErr != nil {
			continue
		}
		inBand := pref >= SideRoutePrefBase-10 && pref <= SideRoutePrefMax+9
		if inBand || strings.Contains(rest, tableToken) {
			_, _ = run(ctx, "ip", "-4", "rule", "del", "pref", strconv.Itoa(pref))
		}
	}
}

func deleteManagedNFTRulesByComment(ctx context.Context, chain, out, comment string, run CommandRunner) {
	for line := range strings.SplitSeq(out, "\n") {
		if !strings.Contains(line, comment) {
			continue
		}
		_, after, ok := strings.Cut(line, "# handle ")
		if !ok {
			continue
		}
		if h := strings.Fields(after); len(h) > 0 {
			_, _ = run(ctx, "nft", "delete", "rule", "inet", "fw4", chain, "handle", h[0])
		}
	}
}

func deleteManagedNFTRules(ctx context.Context, chain, out string, run CommandRunner) {
	deleteManagedNFTRulesByComment(ctx, chain, out, sideRouteNoMasqComment, run)
}

func syncSideRouteLANNoMasq(ctx context.Context, cidrs []string, run CommandRunner) {
	if out, err := run(ctx, "nft", "-a", "list", "chain", "inet", "fw4", "srcnat_lan"); err == nil && strings.Contains(string(out), "chain srcnat_lan") {
		deleteManagedNFTRules(ctx, "srcnat_lan", string(out), run)
		for _, cidr := range cidrs {
			_, _ = run(ctx, "nft", "insert", "rule", "inet", "fw4", "srcnat_lan",
				"ip", "saddr", cidr, "accept", "comment", sideRouteNoMasqComment)
		}
	}

	if out, err := run(ctx, "nft", "-a", "list", "chain", "inet", "fw4", "forward"); err == nil && strings.Contains(string(out), "chain forward") {
		fwdText := string(out)
		deleteManagedNFTRules(ctx, "forward", fwdText, run)
		if len(cidrs) > 0 && (strings.Contains(fwdText, "flow add @") || strings.Contains(fwdText, "flow offload @")) {
			for _, cidr := range cidrs {
				_, _ = run(ctx, "nft", "insert", "rule", "inet", "fw4", "forward",
					"ip", "daddr", cidr, "ct", "state", "established,related", "accept", "comment", sideRouteNoMasqComment)
				_, _ = run(ctx, "nft", "insert", "rule", "inet", "fw4", "forward",
					"ip", "saddr", cidr, "ct", "state", "established,related", "accept", "comment", sideRouteNoMasqComment)
			}
		}
	}

	if out, err := run(ctx, "iptables", "-t", "nat", "-S", "postrouting_lan_rule"); err == nil && strings.Contains(string(out), "postrouting_lan_rule") {
		for line := range strings.SplitSeq(string(out), "\n") {
			trimmed := strings.TrimSpace(line)
			if !strings.HasPrefix(trimmed, "-A postrouting_lan_rule ") || !strings.Contains(trimmed, sideRouteNoMasqComment) {
				continue
			}
			fields := strings.Fields(strings.TrimPrefix(trimmed, "-A postrouting_lan_rule "))
			for i := range fields {
				fields[i] = strings.Trim(fields[i], `"`)
			}
			delArgs := append([]string{"-t", "nat", "-D", "postrouting_lan_rule"}, fields...)
			_, _ = run(ctx, "iptables", delArgs...)
		}
		for _, cidr := range cidrs {
			_, _ = run(ctx, "iptables", "-t", "nat", "-I", "postrouting_lan_rule", "1",
				"-s", cidr, "-m", "comment", "--comment", sideRouteNoMasqComment, "-j", "ACCEPT")
		}
	}
}

// ApplyRuntimeSideRoutes 原子对齐内核策略路由表 188 与源子网 ip rule 优先级队列。
func ApplyRuntimeSideRoutes(ctx context.Context, spec VLANSideRouteSpec, run CommandRunner) error {
	if ctx == nil {
		ctx = context.Background()
	}
	norm, err := NormalizeSideRouteSpec(spec)
	if err != nil {
		return err
	}
	isDefaultRunner := run == nil
	if isDefaultRunner {
		if runtime.GOOS != "linux" || os.Geteuid() != 0 {
			return nil
		}
		run = defaultSideRouteRunner
	}

	sideRouteRuntimeMu.Lock()
	defer sideRouteRuntimeMu.Unlock()

	deleteManagedSideRouteRules(ctx, run)
	_, _ = run(ctx, "ip", "-4", "route", "flush", "table", strconv.Itoa(SideRouteTableID))
	if norm.SideRouterIP == "" || len(norm.CIDRs) == 0 {
		if isDefaultRunner {
			syncDefaultSideNoMasqIncludes(nil, run)
			syncDefaultSideDNSIncludes(norm.SideRouterIP, nil, run)
		}
		syncSideRouteLANNoMasq(ctx, nil, run)
		applyRuntimeSideDNSBypassLocked(ctx, norm.SideRouterIP, nil, run)
		return nil
	}

	tableStr := strconv.Itoa(SideRouteTableID)
	for _, throwCIDR := range sideRouteThrowCIDRs {
		if out, err := run(ctx, "ip", "-4", "route", "replace", "throw", throwCIDR, "table", tableStr); err != nil {
			return fmt.Errorf("configure throw %s in table %s failed: %w (%s)", throwCIDR, tableStr, err, strings.TrimSpace(string(out)))
		}
	}
	if out, err := run(ctx, "ip", "-4", "route", "replace", "default", "via", norm.SideRouterIP, "table", tableStr); err != nil {
		return fmt.Errorf("configure default via %s in table %s failed: %w (%s)", norm.SideRouterIP, tableStr, err, strings.TrimSpace(string(out)))
	}
	for i, cidr := range norm.CIDRs {
		prefStr := strconv.Itoa(SideRoutePrefBase + i)
		if out, err := run(ctx, "ip", "-4", "rule", "add", "from", cidr, "lookup", tableStr, "pref", prefStr); err != nil {
			return fmt.Errorf("add ip rule from %s table %s failed: %w (%s)", cidr, tableStr, err, strings.TrimSpace(string(out)))
		}
	}
	if isDefaultRunner {
		syncDefaultSideNoMasqIncludes(norm.CIDRs, run)
		syncDefaultSideDNSIncludes(norm.SideRouterIP, norm.CIDRs, run)
	}
	syncSideRouteLANNoMasq(ctx, norm.CIDRs, run)
	applyRuntimeSideDNSBypassLocked(ctx, norm.SideRouterIP, norm.CIDRs, run)
	return nil
}

// SuspendRuntimeSideRoutes 临时摘除 table 188 的 ip rule 优先级匹配，使托管子网毫秒级回退主路由直连（保留持久化清单以便恢复）。
func SuspendRuntimeSideRoutes(ctx context.Context, run CommandRunner) error {
	if ctx == nil {
		ctx = context.Background()
	}
	isDefaultRunner := run == nil
	if isDefaultRunner {
		if runtime.GOOS != "linux" || os.Geteuid() != 0 {
			return nil
		}
		run = defaultSideRouteRunner
	}

	sideRouteRuntimeMu.Lock()
	defer sideRouteRuntimeMu.Unlock()

	deleteManagedSideRouteRules(ctx, run)
	if isDefaultRunner {
		syncDefaultSideNoMasqIncludes(nil, run)
		syncDefaultSideDNSIncludes("", nil, run)
	}
	syncSideRouteLANNoMasq(ctx, nil, run)
	applyRuntimeSideDNSBypassLocked(ctx, "", nil, run)
	return nil
}

// ApplySideRoutesWithRetry 带退避重试应用旁路由策略路由（应对 netifd 异步迁移 br-lan->br-lan.1 导致的短时网关不可达窗口）。
func ApplySideRoutesWithRetry(ctx context.Context, spec VLANSideRouteSpec, maxAttempts int, retryDelay time.Duration, applyFn func(context.Context, VLANSideRouteSpec) error) error {
	if applyFn == nil {
		return fmt.Errorf("applyFn is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if maxAttempts <= 0 {
		maxAttempts = 1
	}
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := applyFn(ctx, spec)
		if err == nil {
			return nil
		}
		lastErr = err
		if attempt+1 >= maxAttempts {
			break
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if retryDelay > 0 {
			timer := time.NewTimer(retryDelay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
	}
	return lastErr
}

// SyncRuntimeSideRoutes 持久化 0600 旁路由策略清单并在 Linux 运行时同步生效内核策略路由。
func SyncRuntimeSideRoutes(ctx context.Context, listPath string, spec VLANSideRouteSpec) error {
	norm, err := NormalizeSideRouteSpec(spec)
	if err != nil {
		return err
	}
	if err := WriteSideRouteSpec(listPath, norm); err != nil {
		return err
	}
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return nil
	}
	return ApplyRuntimeSideRoutes(ctx, norm, nil)
}

// buildSideRouterFirewallCommands 编译交由旁路由分流子网所需的安全转发规则（严格排在自定义 DNS 53 放行规则之后）：
//  1. 彻底拦截从本子网去往 lan 区域私网/CGNAT 网段的横向探测与管理端口访问；
//  2. 放行从本子网经表 188 策略路由由 lan (br-lan) 发往旁路由的公网互联网流量。
func buildSideRouterFirewallCommands(fwUCI *UCIConfig, zoneName, segID string, enabled bool) []string {
	isoRef := "singctl_side_iso_" + segID
	fwdRef := "singctl_side_fwd_" + segID

	var cmds []string
	if fwUCI != nil {
		if fwUCI.ByName(isoRef) != nil {
			cmds = append(cmds, fmt.Sprintf("delete firewall.%s", isoRef))
		}
		if fwUCI.ByName(fwdRef) != nil {
			cmds = append(cmds, fmt.Sprintf("delete firewall.%s", fwdRef))
		}
	}
	if !enabled {
		return cmds
	}

	cmds = append(cmds,
		fmt.Sprintf("set firewall.%s=rule", isoRef),
		fmt.Sprintf("set firewall.%s.name=%s", isoRef, quoteUCI("SingCtl-Side-Isolate-LAN-"+segID)),
		fmt.Sprintf("set firewall.%s.src=%s", isoRef, quoteUCI(zoneName)),
		fmt.Sprintf("set firewall.%s.dest='lan'", isoRef),
		fmt.Sprintf("set firewall.%s.dest_ip='10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10'", isoRef),
		fmt.Sprintf("set firewall.%s.proto='all'", isoRef),
		fmt.Sprintf("set firewall.%s.target='REJECT'", isoRef),
		fmt.Sprintf("set firewall.%s=rule", fwdRef),
		fmt.Sprintf("set firewall.%s.name=%s", fwdRef, quoteUCI("SingCtl-Side-Forward-"+segID)),
		fmt.Sprintf("set firewall.%s.src=%s", fwdRef, quoteUCI(zoneName)),
		fmt.Sprintf("set firewall.%s.dest='lan'", fwdRef),
		fmt.Sprintf("set firewall.%s.proto='all'", fwdRef),
		fmt.Sprintf("set firewall.%s.target='ACCEPT'", fwdRef),
	)
	return cmds
}

func (s *Service) sideRoutesFile() string {
	if p := strings.TrimSpace(s.env.SideRoutesFile); p != "" {
		return p
	}
	if bp := strings.TrimSpace(s.env.ProxyBypassFile); bp != "" {
		return filepath.Join(filepath.Dir(bp), filepath.Base(constant.VLANSideRoutesFile))
	}
	return constant.VLANSideRoutesFile
}

func (s *Service) syncSideRoutes(ctx context.Context, spec VLANSideRouteSpec) error {
	if s.env.SyncSideRoutes != nil {
		return s.env.SyncSideRoutes(ctx, spec)
	}
	return SyncRuntimeSideRoutes(ctx, s.sideRoutesFile(), spec)
}

func collectSegmentProxyAndSideCIDRs(segments []Segment, excludeID string, req SaveSegmentRequest, newCIDR string) (bypassCIDRs, sideCIDRs []string) {
	for _, seg := range segments {
		if seg.ID == excludeID || seg.CIDR == "" {
			continue
		}
		if seg.ProxyMode == ProxyModeDirect || seg.ProxyMode == ProxyModeSideRouter {
			bypassCIDRs = append(bypassCIDRs, seg.CIDR)
		}
		if seg.ProxyMode == ProxyModeSideRouter {
			sideCIDRs = append(sideCIDRs, seg.CIDR)
		}
	}
	if newCIDR != "" {
		if req.ProxyMode == ProxyModeDirect || req.ProxyMode == ProxyModeSideRouter {
			bypassCIDRs = append(bypassCIDRs, newCIDR)
		}
		if req.ProxyMode == ProxyModeSideRouter {
			sideCIDRs = append(sideCIDRs, newCIDR)
		}
	}
	bypassCIDRs, _ = NormalizeBypassCIDRs(bypassCIDRs)
	sideCIDRs, _ = NormalizeBypassCIDRs(sideCIDRs)
	return bypassCIDRs, sideCIDRs
}

func ensureSideRouterEffectiveDNS(ov *Overview, req *SaveSegmentRequest) {
	if req == nil || req.ProxyMode != ProxyModeSideRouter || ov == nil {
		return
	}
	sideIP := strings.TrimSpace(ov.SideRouterIP)
	if sideIP == "" {
		return
	}
	if len(effectiveCustomDNS(req.DHCPDNS, req.IPAddr)) == 0 {
		req.DHCPDNS = []string{sideIP}
	}
}
