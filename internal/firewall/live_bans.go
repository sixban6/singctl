// 文件职责：严格校验封禁/白名单目标（内置防自锁护栏）并执行实时 nftables 黑白名单增删批处理指令。
package firewall

import (
	"fmt"
	"net/netip"
	"net/url"
	"os/exec"
	"runtime"
	"singctl/internal/config"
	"singctl/internal/common/netx"
	"slices"
	"strings"
)

// ValidateBanTarget 严格校验待手动封禁的 IP/CIDR，拦截私网、Tailscale、基础 DNS、本机与当前操作者 IP，杜绝自锁。
func ValidateBanTarget(rawTarget, scope, callerIP string, cfg *config.Config) (normalized string, isV6 bool, err error) {
	s := strings.TrimSpace(rawTarget)
	if s == "" {
		return "", false, fmt.Errorf("封禁目标不能为空")
	}
	if strings.ContainsAny(s, " \t\r\n;|&$`\"'<>/*") && !strings.Contains(s, "/") {
		return "", false, fmt.Errorf("封禁目标包含非法字符: %q", rawTarget)
	}
	if strings.Contains(s, "*") {
		return "", false, fmt.Errorf("封禁目标不支持通配符")
	}

	var prefix netip.Prefix
	if p, parseErr := netip.ParsePrefix(s); parseErr == nil {
		addr := p.Addr().Unmap()
		bits := p.Bits()
		if p.Addr().Is4In6() && bits >= 96 {
			bits -= 96
		}
		prefix = netip.PrefixFrom(addr, bits).Masked()
	} else if addr, parseErr := netip.ParseAddr(s); parseErr == nil {
		addr = addr.Unmap()
		prefix = netip.PrefixFrom(addr, addr.BitLen())
	} else {
		return "", false, fmt.Errorf("无效的 IP 或 CIDR 格式: %q", rawTarget)
	}

	isV6 = prefix.Addr().Is6()
	if strings.EqualFold(scope, "forever") && isV6 {
		return "", true, fmt.Errorf("永久黑名单集合当前仅支持 IPv4 地址或网段")
	}
	if strings.EqualFold(scope, "dynamic") && !prefix.IsSingleIP() {
		return "", isV6, fmt.Errorf("7 天动态黑名单仅支持单个 IP；如需封禁网段请选择「永久威胁段」")
	}

	if !prefix.IsSingleIP() {
		if !isV6 && prefix.Bits() < 16 {
			return "", false, fmt.Errorf("安全拦截: IPv4 封禁网段掩码须在 /16~/32 之间 (%s)", prefix)
		}
		if isV6 && prefix.Bits() < 32 {
			return "", true, fmt.Errorf("安全拦截: IPv6 封禁网段掩码须在 /32~/128 之间 (%s)", prefix)
		}
	}

	for _, rp := range reservedAntiLockPrefixes {
		if prefix.Overlaps(rp) {
			return "", isV6, fmt.Errorf("安全拦截: 禁止封禁回环、局域网私网、Tailscale 或 FakeIP 保留地址 (%s)", prefix)
		}
	}
	for _, bIP := range protectedPublicDNSIPs {
		if addr, err := netip.ParseAddr(bIP); err == nil && prefix.Contains(addr.Unmap()) {
			return "", isV6, fmt.Errorf("安全拦截: 禁止封禁公共 DNS 基础设施地址 (%s)", bIP)
		}
	}
	if lanIP := netx.GetPrimaryLANIPv4(); lanIP != "" {
		if addr, err := netip.ParseAddr(lanIP); err == nil && prefix.Contains(addr.Unmap()) {
			return "", isV6, fmt.Errorf("安全拦截: 禁止封禁网关自身地址 (%s)", lanIP)
		}
	}
	if caller := strings.TrimSpace(callerIP); caller != "" {
		if addr, err := netip.ParseAddr(caller); err == nil && prefix.Contains(addr.Unmap()) {
			return "", isV6, fmt.Errorf("安全拦截: 目标命中您当前访问 WebUI 的源地址 (%s)，已阻止自锁", caller)
		}
	}
	if cfg != nil {
		checkProtected := func(rawHost, label string) error {
			if addr, err := netip.ParseAddr(strings.TrimSpace(rawHost)); err == nil && prefix.Contains(addr.Unmap()) {
				return fmt.Errorf("安全拦截: 目标包含正在使用的%s (%s)", label, rawHost)
			}
			return nil
		}
		if cfg.Server.ServerIP != "" {
			if err := checkProtected(cfg.Server.ServerIP, "自建节点"); err != nil {
				return "", isV6, err
			}
		}
		for _, sub := range cfg.Subs {
			if u, err := url.Parse(strings.TrimSpace(sub.URL)); err == nil && u.Hostname() != "" {
				if err := checkProtected(u.Hostname(), "订阅节点"); err != nil {
					return "", isV6, err
				}
			}
		}
	}

	if prefix.IsSingleIP() {
		return prefix.Addr().String(), isV6, nil
	}
	return prefix.String(), isV6, nil
}

// ValidateWhitelistTarget 规范化白名单 IP/CIDR，防止非法字符或注入。
func ValidateWhitelistTarget(rawTarget string) (normalized string, isV6 bool, err error) {
	s := strings.TrimSpace(rawTarget)
	if s == "" {
		return "", false, fmt.Errorf("白名单目标不能为空")
	}
	if strings.Contains(s, "*") {
		return "", false, fmt.Errorf("白名单暂不支持通配符，请输入精确 IP 或 CIDR")
	}
	if p, err := netip.ParsePrefix(s); err == nil {
		addr := p.Addr().Unmap()
		bits := p.Bits()
		if p.Addr().Is4In6() && bits >= 96 {
			bits -= 96
		}
		p = netip.PrefixFrom(addr, bits).Masked()
		if p.IsSingleIP() {
			return p.Addr().String(), p.Addr().Is6(), nil
		}
		return p.String(), p.Addr().Is6(), nil
	}
	if addr, err := netip.ParseAddr(s); err == nil {
		addr = addr.Unmap()
		return addr.String(), addr.Is6(), nil
	}
	return "", false, fmt.Errorf("无效的 IP 或 CIDR 格式: %q", rawTarget)
}

// IsBuiltinWhitelist 检查是否属于不可移除的内置私网/Tailscale 防锁死白名单。
func IsBuiltinWhitelist(norm string) bool {
	return slices.Contains(defaultWhitelistV4, strings.TrimSpace(norm))
}

// AddBanLive 在不重载整表的前提下将 IP/CIDR 实时注入内核黑名单集合。
func AddBanLive(target, scope string, timeoutDays int, callerIP string, cfg *config.Config) (string, bool, error) {
	norm, isV6, err := ValidateBanTarget(target, scope, callerIP, cfg)
	if err != nil {
		return "", false, err
	}
	if runtime.GOOS != "linux" {
		return norm, isV6, nil
	}
	snap, snapErr := readLiveSecurityTable()
	if snapErr != nil || snap == nil || !snap.Active {
		return norm, isV6, nil
	}
	days := timeoutDays
	if days <= 0 {
		days = snap.BanTimeoutDays
	}
	days = min(30, max(1, days))

	var setName, elemExpr string
	if strings.EqualFold(scope, "forever") {
		setName = "blocklist_ip4_forever"
		elemExpr = norm
	} else {
		if isV6 {
			setName = "blocklist_ip6"
		} else {
			setName = "blocklist_ip4"
		}
		elemExpr = fmt.Sprintf("%s timeout %dd", norm, days)
	}
	script := fmt.Sprintf("add element inet security %s { %s }\n", setName, elemExpr)
	if err := execNFTBatch(script); err != nil {
		return "", isV6, err
	}
	return norm, isV6, nil
}

// RemoveBanLive 在不重置计数器与其余封禁记录的情况下，从指定内核黑名单集合实时解封单条 IP/CIDR。
func RemoveBanLive(target, scope string) error {
	trimmed := strings.TrimSpace(target)
	if trimmed == "" {
		return fmt.Errorf("解封目标不能为空")
	}
	if runtime.GOOS != "linux" {
		return nil
	}
	snap, err := readLiveSecurityTable()
	if err != nil || snap == nil || !snap.Active {
		return nil
	}

	var candidates []string
	switch strings.ToLower(strings.TrimSpace(scope)) {
	case "forever":
		candidates = []string{"blocklist_ip4_forever"}
	case "dynamic_v6":
		candidates = []string{"blocklist_ip6"}
	case "dynamic_v4":
		candidates = []string{"blocklist_ip4"}
	default:
		if addr, err := netip.ParseAddr(trimmed); err == nil && addr.Is6() {
			candidates = []string{"blocklist_ip6"}
		} else if strings.Contains(trimmed, "/") || strings.Contains(trimmed, "-") {
			candidates = []string{"blocklist_ip4_forever"}
		} else {
			candidates = []string{"blocklist_ip4", "blocklist_ip4_forever"}
		}
	}

	var lastErr error
	for _, setName := range candidates {
		script := fmt.Sprintf("delete element inet security %s { %s }\n", setName, trimmed)
		if err := execNFTBatch(script); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}
	if lastErr != nil && !strings.Contains(lastErr.Error(), "No such file or directory") {
		return lastErr
	}
	return nil
}

// ClearDynamicBansLive 清空当前 7 天动态扫描黑名单（保留永久威胁段与规则计数器）。
func ClearDynamicBansLive(family string) error {
	if runtime.GOOS != "linux" {
		return nil
	}
	snap, err := readLiveSecurityTable()
	if err != nil || snap == nil || !snap.Active {
		return nil
	}
	var sb strings.Builder
	switch strings.ToLower(strings.TrimSpace(family)) {
	case "ipv4", "v4":
		sb.WriteString("flush set inet security blocklist_ip4\n")
	case "ipv6", "v6":
		sb.WriteString("flush set inet security blocklist_ip6\n")
	default:
		sb.WriteString("flush set inet security blocklist_ip4\nflush set inet security blocklist_ip6\n")
	}
	return execNFTBatch(sb.String())
}

// SyncWhitelistElementLive 在当前已运行表上实时增删白名单成员；若遇到旧表缺少 whitelist_ip6 则返回 needReload=true 提示调用方热重载。
func SyncWhitelistElementLive(norm string, isV6 bool, add bool) (needReload bool, err error) {
	if runtime.GOOS != "linux" {
		return false, nil
	}
	snap, err := readLiveSecurityTable()
	if err != nil || snap == nil || !snap.Active {
		return false, nil
	}
	setName := "whitelist_ip"
	if isV6 {
		setName = "whitelist_ip6"
	}
	op := "add"
	if !add {
		op = "delete"
	}
	script := fmt.Sprintf("%s element inet security %s { %s }\n", op, setName, norm)
	err = execNFTBatch(script)
	if err != nil {
		msg := err.Error()
		if isV6 && (strings.Contains(msg, "No such file or directory") || strings.Contains(msg, "Could not process rule")) {
			return true, nil
		}
		if !add && strings.Contains(msg, "No such file or directory") {
			return false, nil
		}
		return false, err
	}
	return false, nil
}

func execNFTBatch(script string) error {
	nftBin, err := exec.LookPath("nft")
	if err != nil {
		return fmt.Errorf("未检测到 nft 命令")
	}
	cmd := exec.Command(nftBin, "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft 执行失败: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}
