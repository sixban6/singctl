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

	sideRouteNoMasqComment = "singctl-side-nomasq"
)

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
		args = append([]string{"-w", "2"}, args...)
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return exec.CommandContext(cctx, name, args...).CombinedOutput()
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

func syncSideRouteLANNoMasq(ctx context.Context, cidrs []string, run CommandRunner) {
	if out, err := run(ctx, "nft", "-a", "list", "chain", "inet", "fw4", "srcnat_lan"); err == nil && strings.Contains(string(out), "chain srcnat_lan") {
		for line := range strings.SplitSeq(string(out), "\n") {
			if !strings.Contains(line, sideRouteNoMasqComment) {
				continue
			}
			_, after, ok := strings.Cut(line, "# handle ")
			if !ok {
				continue
			}
			if h := strings.Fields(after); len(h) > 0 {
				_, _ = run(ctx, "nft", "delete", "rule", "inet", "fw4", "srcnat_lan", "handle", h[0])
			}
		}
		for _, cidr := range cidrs {
			_, _ = run(ctx, "nft", "insert", "rule", "inet", "fw4", "srcnat_lan",
				"ip", "saddr", cidr, "accept", "comment", sideRouteNoMasqComment)
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
	if run == nil {
		if runtime.GOOS != "linux" {
			return nil
		}
		run = defaultSideRouteRunner
	}

	sideRouteRuntimeMu.Lock()
	defer sideRouteRuntimeMu.Unlock()

	deleteManagedSideRouteRules(ctx, run)
	_, _ = run(ctx, "ip", "-4", "route", "flush", "table", strconv.Itoa(SideRouteTableID))
	if norm.SideRouterIP == "" || len(norm.CIDRs) == 0 {
		syncSideRouteLANNoMasq(ctx, nil, run)
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
	syncSideRouteLANNoMasq(ctx, norm.CIDRs, run)
	return nil
}

// SuspendRuntimeSideRoutes 临时摘除 table 188 的 ip rule 优先级匹配，使托管子网毫秒级回退主路由直连（保留持久化清单以便恢复）。
func SuspendRuntimeSideRoutes(ctx context.Context, run CommandRunner) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if run == nil {
		if runtime.GOOS != "linux" {
			return nil
		}
		run = defaultSideRouteRunner
	}

	sideRouteRuntimeMu.Lock()
	defer sideRouteRuntimeMu.Unlock()

	deleteManagedSideRouteRules(ctx, run)
	syncSideRouteLANNoMasq(ctx, nil, run)
	return nil
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
	if runtime.GOOS != "linux" {
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
	return cmp.Or(strings.TrimSpace(s.env.SideRoutesFile), constant.VLANSideRoutesFile)
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
