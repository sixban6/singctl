package audit

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os/exec"
	"runtime"
	"slices"
	"sort"
	"strings"
	"time"

	"singctl/internal/config"
	"singctl/internal/singbox"
	"singctl/internal/util/netinfo"
)

const (
	// ThrottleNFTTable 是审计“限速不拉黑”专用的隔离 nftables 表名（绝不修改 fw4 或 sing-box 现有表）。
	ThrottleNFTTable = "singctl_audit_throttle"

	MinThrottleRateKBps = 1
	MaxThrottleRateKBps = 102400
)

// ThrottleApplyResult 记录限速规则在内核防火墙层的下发结果。
type ThrottleApplyResult struct {
	Applied     bool   `json:"applied"`
	ActiveRules int    `json:"activeRules"`
	ActiveIPs   int    `json:"activeIps"`
	Message     string `json:"message,omitempty"`
}

// NormalizeThrottleTarget 规范化并安全校验待限速的目标（仅允许单域名、公网 IP 或严苛掩码 CIDR）。
func NormalizeThrottleTarget(cfg *config.Config, rawTarget string, port int) (normalized string, isIP bool, err error) {
	if port < 0 || port > 65535 {
		return "", false, fmt.Errorf("无效的目标端口: %d (范围 0~65535)", port)
	}
	trimmed := strings.TrimSpace(rawTarget)
	if trimmed == "" {
		return "", false, fmt.Errorf("限速目标不能为空")
	}
	if strings.HasPrefix(strings.ToLower(trimmed), "ruleset:") {
		return "", false, fmt.Errorf("限速策略暂不支持整套 ruleset 规则集，请针对具体域名或公网 IP 限速")
	}
	if strings.Contains(trimmed, "*") {
		return "", false, fmt.Errorf("限速目标不支持通配符 (%s)，请填写具体域名或公网 IP", rawTarget)
	}

	safeNorm, isIP, err := ValidateTargetSafety(cfg, trimmed)
	if err != nil {
		return "", false, err
	}
	normalized = strings.TrimSuffix(strings.TrimSuffix(safeNorm, "/32"), "/128")
	return normalized, isIP, nil
}

// UpsertThrottleRule 新增或更新 cfg.Audit.Throttles 中的匹配规则（按目标与端口去重）。
func UpsertThrottleRule(cfg *config.Config, rule config.AuditThrottleRule) (config.AuditThrottleRule, error) {
	if cfg == nil {
		return config.AuditThrottleRule{}, fmt.Errorf("配置不能为空")
	}
	if rule.RateKBps < MinThrottleRateKBps || rule.RateKBps > MaxThrottleRateKBps {
		return config.AuditThrottleRule{}, fmt.Errorf("限速速率须在 %d~%d KB/s 之间", MinThrottleRateKBps, MaxThrottleRateKBps)
	}
	norm, _, err := NormalizeThrottleTarget(cfg, rule.Target, rule.Port)
	if err != nil {
		return config.AuditThrottleRule{}, err
	}
	rule.Target = norm
	if strings.TrimSpace(rule.CreatedAt) == "" {
		rule.CreatedAt = time.Now().Format("2006-01-02 15:04:05")
	}

	for i, existing := range cfg.Audit.Throttles {
		existingNorm := normalizeStoredThrottleTarget(existing.Target)
		if strings.EqualFold(existingNorm, norm) && existing.Port == rule.Port {
			if rule.Comment == "" {
				rule.Comment = existing.Comment
			}
			cfg.Audit.Throttles[i] = rule
			return rule, nil
		}
	}
	cfg.Audit.Throttles = append(cfg.Audit.Throttles, rule)
	return rule, nil
}

// RemoveThrottleRule 从 cfg.Audit.Throttles 移除匹配的限速规则。
func RemoveThrottleRule(cfg *config.Config, target string, port int) bool {
	if cfg == nil || len(cfg.Audit.Throttles) == 0 {
		return false
	}
	norm := normalizeStoredThrottleTarget(target)
	if norm == "" {
		return false
	}
	removed := false
	next := make([]config.AuditThrottleRule, 0, len(cfg.Audit.Throttles))
	for _, r := range cfg.Audit.Throttles {
		if strings.EqualFold(normalizeStoredThrottleTarget(r.Target), norm) && (port < 0 || r.Port == port) {
			removed = true
			continue
		}
		next = append(next, r)
	}
	cfg.Audit.Throttles = next
	return removed
}

func normalizeStoredThrottleTarget(raw string) string {
	norm, _ := singbox.NormalizeBlockTarget(raw)
	if norm == "" {
		return strings.ToLower(strings.TrimSpace(raw))
	}
	return strings.TrimSuffix(strings.TrimSuffix(norm, "/32"), "/128")
}

func matchThrottleRateKBps(cfg *config.Config, target string, port int) int {
	if cfg == nil || len(cfg.Audit.Throttles) == 0 {
		return 0
	}
	normTarget := normalizeStoredThrottleTarget(target)
	if normTarget == "" {
		return 0
	}
	targetAddr, addrErr := netip.ParseAddr(normTarget)

	bestWildcardRate := 0
	for _, rule := range cfg.Audit.Throttles {
		if rule.RateKBps <= 0 {
			continue
		}
		ruleTarget := normalizeStoredThrottleTarget(rule.Target)
		if ruleTarget == "" {
			continue
		}
		matched := false
		if addrErr == nil {
			if p, ok := parseAuditIPPrefix(ruleTarget); ok {
				matched = p.Contains(targetAddr.Unmap())
			}
		} else {
			matched = normTarget == ruleTarget || strings.HasSuffix(normTarget, "."+ruleTarget)
		}
		if !matched {
			continue
		}
		if rule.Port > 0 && rule.Port == port {
			return rule.RateKBps
		}
		if rule.Port == 0 && bestWildcardRate == 0 {
			bestWildcardRate = rule.RateKBps
		}
	}
	return bestWildcardRate
}

// Throttler 负责将 audit.throttles 编译并幂等下发到 Linux nftables 隔离限速表。
type Throttler struct {
	lookupIPs func(ctx context.Context, host string) ([]netip.Addr, error)
	runNFT    func(ctx context.Context, script string) error
	deleteNFT func(ctx context.Context) error
}

// NewThrottler 创建默认限速执行器（使用系统 DNS 解析与 nftables -f -）。
func NewThrottler() *Throttler {
	return &Throttler{
		lookupIPs: func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		},
		runNFT: func(ctx context.Context, script string) error {
			if runtime.GOOS != "linux" {
				return fmt.Errorf("nftables 限速仅支持 Linux/OpenWrt 环境")
			}
			nftBin, err := exec.LookPath("nft")
			if err != nil {
				return fmt.Errorf("未检测到 nft 命令，跳过内核限速规则下发")
			}
			cmd := exec.CommandContext(ctx, nftBin, "-f", "-")
			cmd.Stdin = strings.NewReader(script)
			out, err := cmd.CombinedOutput()
			if err != nil {
				return fmt.Errorf("nft 执行失败: %v (%s)", err, strings.TrimSpace(string(out)))
			}
			return nil
		},
		deleteNFT: func(ctx context.Context) error {
			if runtime.GOOS != "linux" {
				return nil
			}
			nftBin, err := exec.LookPath("nft")
			if err != nil {
				return nil
			}
			out, err := exec.CommandContext(ctx, nftBin, "delete", "table", "inet", ThrottleNFTTable).CombinedOutput()
			if err != nil {
				msg := strings.TrimSpace(string(out))
				if strings.Contains(msg, "No such file or directory") || strings.Contains(msg, "does not exist") {
					return nil
				}
				return fmt.Errorf("清理 nftables 限速表失败: %v (%s)", err, msg)
			}
			return nil
		},
	}
}

// BuildNFTScript 将 cfg.Audit.Throttles 编译为完整的原子 nftables 限速脚本文本。
func (t *Throttler) BuildNFTScript(ctx context.Context, cfg *config.Config) (script string, activeRules int, activeIPs int) {
	if cfg == nil || len(cfg.Audit.Throttles) == 0 {
		return "", 0, 0
	}

	protectedIPs := collectProtectedPublicIPs(cfg)
	type resolvedThrottleLine struct {
		expr string
		isV6 bool
		port int
		rate int
	}

	var lines []resolvedThrottleLine
	seenTargets := make(map[string]struct{})

	for _, rule := range cfg.Audit.Throttles {
		if rule.RateKBps < MinThrottleRateKBps || rule.RateKBps > MaxThrottleRateKBps {
			continue
		}
		norm, isIP, err := NormalizeThrottleTarget(cfg, rule.Target, rule.Port)
		if err != nil {
			continue
		}

		var destExprs []struct {
			expr string
			isV6 bool
		}
		if isIP {
			prefix, ok := parseAuditIPPrefix(norm)
			if !ok {
				continue
			}
			if prefix.IsSingleIP() {
				addr := prefix.Addr()
				if slices.Contains(protectedIPs, addr) {
					continue
				}
				destExprs = append(destExprs, struct {
					expr string
					isV6 bool
				}{expr: addr.String(), isV6: addr.Is6()})
			} else {
				overlapsProtected := false
				for _, pIP := range protectedIPs {
					if prefix.Contains(pIP) {
						overlapsProtected = true
						break
					}
				}
				if overlapsProtected {
					continue
				}
				destExprs = append(destExprs, struct {
					expr string
					isV6 bool
				}{expr: prefix.String(), isV6: prefix.Addr().Is6()})
			}
		} else if t != nil && t.lookupIPs != nil {
			lookupCtx, cancel := context.WithTimeout(ctx, 2500*time.Millisecond)
			addrs, lookupErr := t.lookupIPs(lookupCtx, norm)
			cancel()
			if lookupErr != nil || len(addrs) == 0 {
				continue
			}
			sort.Slice(addrs, func(i, j int) bool {
				return addrs[i].String() < addrs[j].String()
			})
			for _, addr := range addrs {
				addr = addr.Unmap()
				if _, ok := directIPPublicAddr(addr.String()); !ok {
					continue
				}
				if slices.Contains(protectedIPs, addr) {
					continue
				}
				destExprs = append(destExprs, struct {
					expr string
					isV6 bool
				}{expr: addr.String(), isV6: addr.Is6()})
			}
		}

		if len(destExprs) == 0 {
			continue
		}
		activeRules++
		for _, de := range destExprs {
			dedupKey := fmt.Sprintf("%s|%d|%d", de.expr, rule.Port, rule.RateKBps)
			if _, dup := seenTargets[dedupKey]; dup {
				continue
			}
			seenTargets[dedupKey] = struct{}{}
			activeIPs++
			lines = append(lines, resolvedThrottleLine{
				expr: de.expr,
				isV6: de.isV6,
				port: rule.Port,
				rate: rule.RateKBps,
			})
		}
	}

	if activeRules == 0 || len(lines) == 0 {
		return "", 0, 0
	}

	var sb strings.Builder
	sb.WriteString("add table inet ")
	sb.WriteString(ThrottleNFTTable)
	sb.WriteByte('\n')
	sb.WriteString("flush table inet ")
	sb.WriteString(ThrottleNFTTable)
	sb.WriteByte('\n')
	sb.WriteString("table inet ")
	sb.WriteString(ThrottleNFTTable)
	sb.WriteString(" {\n")
	sb.WriteString("  chain prerouting {\n")
	sb.WriteString("    type filter hook prerouting priority -160; policy accept;\n")
	sb.WriteString("    iifname \"lo\" return\n")
	for _, ln := range lines {
		family := "ip"
		if ln.isV6 {
			family = "ip6"
		}
		burst := min(max(16, ln.rate*3), 256)
		if ln.port > 0 {
			fmt.Fprintf(&sb, "    %s daddr %s meta l4proto { tcp, udp } th dport %d limit rate over %d kbytes/second burst %d kbytes drop\n",
				family, ln.expr, ln.port, ln.rate, burst)
		} else {
			fmt.Fprintf(&sb, "    %s daddr %s meta l4proto { tcp, udp } limit rate over %d kbytes/second burst %d kbytes drop\n",
				family, ln.expr, ln.rate, burst)
		}
	}
	sb.WriteString("  }\n")
	sb.WriteString("}\n")
	return sb.String(), activeRules, activeIPs
}

// Apply 编译并将 cfg.Audit.Throttles 幂等下发到内核 nftables 表；无规则时自动清理表。
func (t *Throttler) Apply(ctx context.Context, cfg *config.Config) ThrottleApplyResult {
	if t == nil {
		t = NewThrottler()
	}
	script, rules, ips := t.BuildNFTScript(ctx, cfg)
	if rules == 0 || script == "" {
		if cfg != nil && len(cfg.Audit.Throttles) > 0 {
			return ThrottleApplyResult{
				Applied:     false,
				ActiveRules: 0,
				ActiveIPs:   0,
				Message:     "限速策略已保存，暂未解析到可下发的公网 IP（后台将定期重试解析）",
			}
		}
		if t.deleteNFT != nil {
			if err := t.deleteNFT(ctx); err != nil {
				return ThrottleApplyResult{Applied: false, Message: err.Error()}
			}
		}
		return ThrottleApplyResult{
			Applied:     true,
			ActiveRules: 0,
			ActiveIPs:   0,
			Message:     "已清理全部上行限速规则",
		}
	}
	if t.runNFT == nil {
		return ThrottleApplyResult{Applied: false, ActiveRules: rules, ActiveIPs: ips, Message: "未配置 nftables 执行器"}
	}
	if err := t.runNFT(ctx, script); err != nil {
		return ThrottleApplyResult{
			Applied:     false,
			ActiveRules: rules,
			ActiveIPs:   ips,
			Message:     err.Error(),
		}
	}
	return ThrottleApplyResult{
		Applied:     true,
		ActiveRules: rules,
		ActiveIPs:   ips,
		Message:     fmt.Sprintf("已下发 %d 条内核限速策略 (覆盖 %d 个公网目标 IP)", rules, ips),
	}
}

// ApplyThrottleRules 使用默认执行器将 cfg.Audit.Throttles 同步至内核 nftables 表。
func ApplyThrottleRules(ctx context.Context, cfg *config.Config) ThrottleApplyResult {
	return NewThrottler().Apply(ctx, cfg)
}

func collectProtectedPublicIPs(cfg *config.Config) []netip.Addr {
	var out []netip.Addr
	appendIP := func(raw string) {
		addr, err := netip.ParseAddr(strings.TrimSpace(raw))
		if err != nil {
			return
		}
		addr = addr.Unmap()
		if !slices.Contains(out, addr) {
			out = append(out, addr)
		}
	}
	for _, bIP := range ProtectedBootstrapIPs {
		appendIP(bIP)
	}
	if lanIP := netinfo.GetPrimaryLANIPv4(); lanIP != "" {
		appendIP(lanIP)
	}
	if cfg != nil {
		appendIP(cfg.Server.ServerIP)
		for _, sub := range cfg.Subs {
			if u, err := url.Parse(strings.TrimSpace(sub.URL)); err == nil && u.Hostname() != "" {
				appendIP(u.Hostname())
			}
		}
	}
	return out
}
