// 文件职责：实现网络与内核维度的深度体检算子（防火墙后端与隔离链、策略路由表 100/101 与 throw 逃生路由、软硬件流量卸载冲突、双栈连通性探针）。
package doctor

import (
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"singctl/internal/config"
)

const (
	// ProbeURLDomestic 为国内直连连通性探针 URL。
	ProbeURLDomestic = "https://www.baidu.com"
	// ProbeURLOverseas 为海外代理连通性探针 URL。
	ProbeURLOverseas = "https://www.gstatic.com/generate_204"
	// ProbeURLDomesticIPv6 为国内 IPv6 连通性探针 URL（命中 geosite-cn，兼容 cn_only 模式的 AAAA 放行策略）。
	ProbeURLDomesticIPv6 = "https://ipv6.baidu.com"
	// ProbeURLOverseasIPv6 为海外 IPv6 连通性探针 URL（配合强制 tcp6 拨号验证纯 IPv6 代理出站）。
	ProbeURLOverseasIPv6 = "https://www.gstatic.com/generate_204"
)

type firewallBackendChecker struct{}

func (firewallBackendChecker) ID() string { return "firewall_backend" }

func (firewallBackendChecker) Run(ctx context.Context, env *Env) CheckResult {
	res := CheckResult{
		ID:       "firewall_backend",
		Category: "network",
		Title:    "防火墙后端与隔离链",
	}

	hasNFT := env.lookPathOK("nft")
	hasIPT := env.lookPathOK("iptables")
	hasIP6T := env.lookPathOK("ip6tables")
	hasIPSet := env.lookPathOK("ipset")
	ipv6Mode := env.effectiveIPv6Mode()

	if !hasNFT && !hasIPT {
		res.Status = StatusFail
		res.Summary = "未检测到 nft 或 iptables 防火墙工具"
		res.Advice = "请安装 nftables 或 iptables + ipset 以启用透明代理"
		return res
	}

	if hasNFT {
		out, err := env.RunCmd(ctx, "nft", "list", "tables")
		tablesText := string(out)
		if err == nil && strings.Contains(tablesText, "inet sing-box") {
			return evaluateNFTables(ctx, env, tablesText)
		}
	}

	if hasIPT {
		return evaluateIPTables(ctx, env, hasIP6T, hasIPSet, ipv6Mode)
	}

	res.Status = StatusFail
	res.Summary = "nftables 透明代理表 inet sing-box 未挂载"
	res.Detail = "后端: nftables | inet sing-box: 未加载"
	res.Advice = "请执行 'singctl sb start' 重新应用透明代理防火墙规则"
	return res
}

func evaluateNFTables(ctx context.Context, env *Env, tablesText string) CheckResult {
	res := CheckResult{
		ID:       "firewall_backend",
		Category: "network",
		Title:    "防火墙后端与隔离链",
		Status:   StatusPass,
	}

	var details []string
	var advices []string
	details = append(details, "后端: nftables")

	if tblOut, err := env.RunCmd(ctx, "nft", "list", "table", "inet", "sing-box"); err == nil {
		txt := string(tblOut)
		if strings.Contains(txt, "prerouting") && strings.Contains(txt, "output") {
			details = append(details, "inet sing-box(prerouting+output): 已挂载")
		} else {
			res.Status = worstStatus(res.Status, StatusWarn)
			details = append(details, "inet sing-box 链不完整")
			advices = append(advices, "建议重载 sing-box 透明代理规则以补齐 prerouting/output 链")
		}
	} else {
		details = append(details, "inet sing-box: 已挂载")
	}

	// 检测 Tailscale-P2P 隔离链与 Audit-Throttle 限速表状态。
	p2pActive := false
	if out, err := env.RunCmd(ctx, "nft", "list", "chain", "inet", "fw4", "singctl_ts_jit_guard"); err == nil && strings.Contains(string(out), "singctl_ts_jit_guard") {
		p2pActive = true
	}
	throttleActive := strings.Contains(tablesText, "singctl_audit_throttle")

	details = append(details, fmt.Sprintf("Tailscale-P2P: %s", activeLabel(p2pActive)))
	details = append(details, fmt.Sprintf("Audit-Throttle: %s", activeLabel(throttleActive)))

	if env.Config != nil && env.Config.Tailscale.P2PAssist.Enabled && !p2pActive {
		res.Status = worstStatus(res.Status, StatusWarn)
		advices = append(advices, "已开启 Tailscale P2P 防护但未检测到 singctl_ts_jit_guard 链，建议重新同步防护规则")
	}
	if env.Config != nil && len(env.Config.Audit.Throttles) > 0 && !throttleActive {
		res.Status = worstStatus(res.Status, StatusWarn)
		advices = append(advices, "已配置设备限速策略但未检测到 singctl_audit_throttle 表，建议同步刷新限速表")
	}

	res.Detail = strings.Join(details, " | ")
	res.Advice = strings.Join(advices, "；")
	if res.Status == StatusPass {
		res.Summary = "nftables 透明代理表 inet sing-box 与扩展隔离链运行正常"
	} else {
		res.Summary = "nftables 透明代理主表在线，但部分扩展隔离链存在告警"
	}
	return res
}

func evaluateIPTables(ctx context.Context, env *Env, hasIP6T, hasIPSet bool, ipv6Mode string) CheckResult {
	res := CheckResult{
		ID:       "firewall_backend",
		Category: "network",
		Title:    "防火墙后端与隔离链",
		Status:   StatusPass,
	}

	v4Out, v4Err := env.RunCmd(ctx, "iptables", "-t", "mangle", "-S")
	v4Text := string(v4Out)
	v4OK := v4Err == nil && strings.Contains(v4Text, "SING_BOX") && strings.Contains(v4Text, "SING_BOX_OUTPUT")

	if !v4OK {
		res.Status = StatusFail
		res.Summary = "未检测到 iptables 透明代理隔离链 SING_BOX / SING_BOX_OUTPUT"
		res.Detail = fmt.Sprintf("后端: iptables (ipset=%v)", hasIPSet)
		res.Advice = "请执行 'singctl sb start' 重新应用透明代理防火墙规则"
		return res
	}

	var details []string
	var advices []string
	backendLabel := "iptables+ipset"
	if !hasIPSet {
		backendLabel = "iptables(无 ipset)"
		res.Status = worstStatus(res.Status, StatusWarn)
		advices = append(advices, "未检测到 ipset，建议安装以提升局域网网段放行效率")
	}
	details = append(details, "后端: "+backendLabel, "IPv4 SING_BOX/SING_BOX_OUTPUT: 已挂载")

	v6OK := false
	if hasIP6T {
		if v6Out, err := env.RunCmd(ctx, "ip6tables", "-t", "mangle", "-S"); err == nil {
			v6Text := string(v6Out)
			v6OK = strings.Contains(v6Text, "SING_BOX") && strings.Contains(v6Text, "SING_BOX_OUTPUT")
		}
	}
	details = append(details, fmt.Sprintf("IPv6 SING_BOX: %s", activeLabel(v6OK)))
	if ipv6Mode != config.GatewayIPv6Off && !v6OK {
		res.Status = worstStatus(res.Status, StatusWarn)
		advices = append(advices, fmt.Sprintf("当前 gateway.ipv6_mode=%s 但 ip6tables SING_BOX 隔离链未挂载", ipv6Mode))
	}

	filterOut, _ := env.RunCmd(ctx, "iptables", "-S")
	filterText := string(filterOut)
	p2pActive := strings.Contains(filterText, "SINGCTL_TS_JIT")
	throttleActive := strings.Contains(filterText, "SINGCTL_AUDIT_THROTTLE")
	details = append(details,
		fmt.Sprintf("Tailscale-P2P: %s", activeLabel(p2pActive)),
		fmt.Sprintf("Audit-Throttle: %s", activeLabel(throttleActive)),
	)

	res.Detail = strings.Join(details, " | ")
	res.Advice = strings.Join(advices, "；")
	if res.Status == StatusPass {
		res.Summary = "iptables+ipset 透明代理隔离链及扩展防护链完整在线"
	} else {
		res.Summary = "iptables 透明代理主链在线，但存在 IPv6 或 ipset 警告"
	}
	return res
}

type policyRoutingChecker struct{}

func (policyRoutingChecker) ID() string { return "policy_routing" }

var requiredThrowCIDRs = []string{
	"10.0.0.0/8",
	"100.64.0.0/10",
	"127.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
}

func (policyRoutingChecker) Run(ctx context.Context, env *Env) CheckResult {
	res := CheckResult{
		ID:       "policy_routing",
		Category: "network",
		Title:    "策略路由与私网逃生表 (100/101)",
		Status:   StatusPass,
	}

	if !env.lookPathOK("ip") {
		res.Status = StatusFail
		res.Summary = "未找到 iproute2 (ip) 命令，无法核验策略路由"
		return res
	}

	ruleOut, err := env.RunCmd(ctx, "ip", "rule", "show")
	if err != nil {
		res.Status = StatusFail
		res.Summary = "执行 ip rule show 失败"
		res.Detail = err.Error()
		return res
	}
	ruleText := string(ruleOut)
	hasRule100 := hasPolicyRule(ruleText, "100")
	hasRule101 := hasPolicyRule(ruleText, "101")

	if !hasRule100 {
		res.Status = StatusFail
		res.Summary = "缺少 TProxy 策略路由规则 (fwmark 0x1 -> table 100)"
		res.Detail = "ip rule show 未匹配 lookup 100"
		res.Advice = "请执行 'singctl sb start' 重建策略路由表 100/101"
		return res
	}

	t100Out, t100Err := env.RunCmd(ctx, "ip", "route", "show", "table", "100")
	t100Text := string(t100Out)
	if t100Err != nil || !hasLocalDefaultLo(t100Text) {
		res.Status = StatusFail
		res.Summary = "策略路由表 100 缺少 local default dev lo"
		res.Detail = strings.TrimSpace(t100Text)
		res.Advice = "请重启 sing-box 恢复表 100 透明代理路由"
		return res
	}

	var details []string
	var advices []string
	details = append(details, "table 100: local default dev lo 就绪")

	var missingThrows []string
	for _, cidr := range requiredThrowCIDRs {
		if !hasThrowRoute(t100Text, cidr) {
			missingThrows = append(missingThrows, cidr)
		}
	}
	if len(missingThrows) > 0 {
		res.Status = worstStatus(res.Status, StatusWarn)
		details = append(details, "缺少 throw 逃生路由: "+strings.Join(missingThrows, ", "))
		advices = append(advices, "表 100 缺少私网 throw 逃生路由，启用 src_valid_mark=1（如 Tailscale）时可能导致局域网丢包")
	} else {
		details = append(details, "私网 throw 逃生路由完整")
	}

	t101Out, t101Err := env.RunCmd(ctx, "ip", "route", "show", "table", "101")
	t101Text := string(t101Out)
	switch {
	case !hasRule101 || t101Err != nil || !hasLocalDefaultLo(t101Text):
		res.Status = worstStatus(res.Status, StatusWarn)
		details = append(details, "table 101 本机出站重路由未就绪")
		advices = append(advices, "缺少 table 101 策略路由，可能导致本机直连上游光猫 53 端口的 DNS 未被接管")
	case strings.Contains(t101Text, "throw "):
		res.Status = worstStatus(res.Status, StatusWarn)
		details = append(details, "table 101 意外包含 throw 路由")
		advices = append(advices, "table 101 应保持纯净 local default dev lo 以防本机私网 DNS 逃逸")
	default:
		details = append(details, "table 101: 纯净 local default dev lo 就绪")
	}

	if env.effectiveIPv6Mode() != config.GatewayIPv6Off {
		v6RuleOut, v6RuleErr := env.RunCmd(ctx, "ip", "-6", "rule", "show")
		v6T100Out, v6T100Err := env.RunCmd(ctx, "ip", "-6", "route", "show", "table", "100")
		if v6RuleErr != nil || !hasPolicyRule(string(v6RuleOut), "100") || v6T100Err != nil || !hasLocalDefaultLo(string(v6T100Out)) {
			res.Status = worstStatus(res.Status, StatusWarn)
			details = append(details, "IPv6 table 100 策略路由未就绪")
			advices = append(advices, "已开启 IPv6 双栈分流但 IPv6 策略路由表 100 未生效")
		} else {
			details = append(details, "IPv6 table 100 就绪")
		}
	}

	res.Detail = strings.Join(details, " | ")
	res.Advice = strings.Join(advices, "；")
	if res.Status == StatusPass {
		res.Summary = "策略路由表 100/101 与私网 throw 逃生路由全部完整"
	} else {
		res.Summary = "策略路由主干在线，但存在逃生路由或表 101 告警"
	}
	return res
}

type hwOffloadConflictChecker struct{}

func (hwOffloadConflictChecker) ID() string { return "hw_offload_conflict" }

func (hwOffloadConflictChecker) Run(ctx context.Context, env *Env) CheckResult {
	res := CheckResult{
		ID:       "hw_offload_conflict",
		Category: "network",
		Title:    "软硬件流量卸载冲突检测",
		Status:   StatusPass,
	}

	sbRunning, _ := inspectSingBoxProcess(ctx, env)
	var conflicts []string
	var hasUCIOffload, hasMtkHnat, hasXtFlowOffload bool

	if env.IsOpenWrt() && env.lookPathOK("uci") {
		if out, err := env.RunCmd(ctx, "uci", "-q", "get", "firewall.@defaults[0].flow_offloading"); err == nil && strings.TrimSpace(string(out)) == "1" {
			hasUCIOffload = true
			conflicts = append(conflicts, "uci flow_offloading=1 (软件流量卸载)")
		}
		if out, err := env.RunCmd(ctx, "uci", "-q", "get", "firewall.@defaults[0].flow_offloading_hw"); err == nil && strings.TrimSpace(string(out)) == "1" {
			hasUCIOffload = true
			conflicts = append(conflicts, "uci flow_offloading_hw=1 (硬件流量卸载)")
		}
	}

	modulesPath := "/proc/modules"
	if env.ProcRoot != "" {
		modulesPath = filepath.Join(env.ProcRoot, "modules")
	}
	if rawMods, err := env.ReadFile(modulesPath); err == nil {
		for line := range strings.SplitSeq(string(rawMods), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}
			switch fields[0] {
			case "mtkhnat":
				hasMtkHnat = true
				conflicts = append(conflicts, "内核模块 mtkhnat 已加载")
			case "xt_FLOWOFFLOAD":
				hasXtFlowOffload = true
				conflicts = append(conflicts, "内核模块 xt_FLOWOFFLOAD 已加载")
			}
		}
	}

	if len(conflicts) == 0 {
		res.Summary = "未检测到软硬件流量卸载冲突，TProxy 流量路径纯净"
		return res
	}

	res.Detail = strings.Join(conflicts, " | ")
	if sbRunning {
		res.Status = StatusWarn
		res.Summary = "检测到软/硬件流量卸载与运行中的 sing-box TProxy 存在绕行冲突"
		var advices []string
		if hasUCIOffload {
			advices = append(advices, "请在 OpenWrt 防火墙中关闭软件/硬件流量卸载（uci set firewall.@defaults[0].flow_offloading='0' && uci set firewall.@defaults[0].flow_offloading_hw='0' && uci commit firewall）并重载防火墙")
			res.FixAction = "disable-flow-offload"
			res.FixLabel = "一键关闭 UCI 流量卸载"
		}
		if hasMtkHnat {
			advices = append(advices, "请在路由固件加速设置中禁用 MediaTek mtkhnat 硬件加速模块")
		}
		if hasXtFlowOffload && !hasUCIOffload {
			advices = append(advices, "请检查并关闭启用 xt_FLOWOFFLOAD 的防火墙或加速插件（如 TurboACC）")
		}
		res.Advice = strings.Join(advices, "；")
		return res
	}

	res.Summary = "检测到流量卸载配置/模块，但 sing-box 当前未运行（暂未产生冲突）"
	return res
}

type dualStackConnectivityChecker struct{}

func (dualStackConnectivityChecker) ID() string { return "dual_stack_connectivity" }

type probeOutcome struct {
	code      int
	latencyMs int64
	err       error
}

func (dualStackConnectivityChecker) Run(ctx context.Context, env *Env) CheckResult {
	res := CheckResult{
		ID:       "dual_stack_connectivity",
		Category: "network",
		Title:    "双栈分流连通性探针",
		Status:   StatusPass,
	}

	ipv6Mode := env.effectiveIPv6Mode()
	var domV4, ovsV4, domV6, ovsV6 probeOutcome
	needDomV6 := ipv6Mode == config.GatewayIPv6CNOnly || ipv6Mode == config.GatewayIPv6Full
	needOvsV6 := ipv6Mode == config.GatewayIPv6Full

	var wg sync.WaitGroup
	wg.Go(func() {
		c, ms, err := env.HTTPProbe(ctx, ProbeURLDomestic)
		domV4 = probeOutcome{code: c, latencyMs: ms, err: err}
	})
	wg.Go(func() {
		c, ms, err := env.HTTPProbe(ctx, ProbeURLOverseas)
		ovsV4 = probeOutcome{code: c, latencyMs: ms, err: err}
	})
	if needDomV6 {
		wg.Go(func() {
			c, ms, err := env.HTTPProbeIPv6(ctx, ProbeURLDomesticIPv6)
			domV6 = probeOutcome{code: c, latencyMs: ms, err: err}
		})
	}
	if needOvsV6 {
		wg.Go(func() {
			c, ms, err := env.HTTPProbeIPv6(ctx, ProbeURLOverseasIPv6)
			ovsV6 = probeOutcome{code: c, latencyMs: ms, err: err}
		})
	}
	wg.Wait()

	domOK := domV4.err == nil && domV4.code >= 200 && domV4.code < 400
	ovsOK := ovsV4.err == nil && ovsV4.code >= 200 && ovsV4.code < 400
	domV6OK := domV6.err == nil && domV6.code >= 200 && domV6.code < 400
	ovsV6OK := ovsV6.err == nil && ovsV6.code >= 200 && ovsV6.code < 400

	var details []string
	if domOK {
		details = append(details, fmt.Sprintf("国内直连: HTTP %d (%dms)", domV4.code, domV4.latencyMs))
	} else {
		details = append(details, fmt.Sprintf("国内直连失败: %v", probeErrDesc(domV4)))
	}
	if ovsOK {
		details = append(details, fmt.Sprintf("海外代理: HTTP %d (%dms)", ovsV4.code, ovsV4.latencyMs))
	} else {
		details = append(details, fmt.Sprintf("海外代理失败: %v", probeErrDesc(ovsV4)))
	}

	switch ipv6Mode {
	case config.GatewayIPv6Off:
		details = append(details, "IPv6: 纯 IPv4 模式 (off)")
	case config.GatewayIPv6CNOnly:
		if domV6OK {
			details = append(details, fmt.Sprintf("国内 IPv6(cn_only): HTTP %d (%dms)", domV6.code, domV6.latencyMs))
		} else {
			details = append(details, fmt.Sprintf("国内 IPv6(cn_only) 不可达: %v", probeErrDesc(domV6)))
		}
	case config.GatewayIPv6Full:
		if domV6OK && ovsV6OK {
			details = append(details, fmt.Sprintf("双栈 IPv6(full): 国内 %dms / 海外 %dms", domV6.latencyMs, ovsV6.latencyMs))
		} else {
			details = append(details, fmt.Sprintf("双栈 IPv6(full): 国内=%v 海外=%v", domV6OK, ovsV6OK))
		}
	}

	res.Detail = strings.Join(details, " | ")
	switch {
	case !domOK && !ovsOK:
		res.Status = StatusFail
		res.Summary = "国内直连与海外代理均不可达，网络链路可能中断"
		res.Advice = "请优先检查 WAN 口连接、本地 DNS 及透明代理防火墙规则"
	case !domOK:
		res.Status = StatusFail
		res.Summary = "国内直连探测异常，海外代理正常"
		res.Advice = "请检查本地防劫持 DNS 与直连分流规则"
	case !ovsOK:
		res.Status = StatusFail
		res.Summary = "国内直连正常，但海外代理链路不可达"
		res.Advice = "请检查代理节点可用性、订阅更新与 sing-box 运行日志"
	case needDomV6 && !domV6OK:
		res.Status = StatusWarn
		res.Summary = fmt.Sprintf("国内/海外 IPv4 正常，但 %s 模式下国内 IPv6 不可达", ipv6Mode)
		res.Advice = "请确认光猫/WAN 口已获取公网 IPv6 前缀且 SmartDNS 未残留 force-AAAA-SOA yes"
	case needOvsV6 && !ovsV6OK:
		res.Status = StatusWarn
		res.Summary = "国内/海外 IPv4 正常，但 full 模式下海外 IPv6 不可达"
		res.Advice = "若代理节点不支持 IPv6 出站，建议将 gateway.ipv6_mode 切为 cn_only"
	default:
		res.Status = StatusPass
		res.Summary = fmt.Sprintf("国内直连 %dms | 海外代理 %dms | IPv6(%s) 正常", domV4.latencyMs, ovsV4.latencyMs, ipv6Mode)
	}
	return res
}

func activeLabel(active bool) string {
	if active {
		return "已激活"
	}
	return "未激活"
}

func hasPolicyRule(ruleText, table string) bool {
	for line := range strings.SplitSeq(ruleText, "\n") {
		fields := strings.Fields(line)
		if slices.Contains(fields, "lookup") && slices.Contains(fields, table) {
			return true
		}
		if slices.Contains(fields, "table") && slices.Contains(fields, table) {
			return true
		}
	}
	return false
}

func hasLocalDefaultLo(routeText string) bool {
	for line := range strings.SplitSeq(routeText, "\n") {
		if strings.Contains(line, "local") && strings.Contains(line, "dev lo") &&
			(strings.Contains(line, "default") || strings.Contains(line, "0.0.0.0/0") || strings.Contains(line, "::/0")) {
			return true
		}
	}
	return false
}

func hasThrowRoute(routeText, cidr string) bool {
	for line := range strings.SplitSeq(routeText, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "throw" && fields[1] == cidr {
			return true
		}
	}
	return false
}

func probeErrDesc(p probeOutcome) string {
	if p.err != nil {
		return p.err.Error()
	}
	return fmt.Sprintf("HTTP %d", p.code)
}
