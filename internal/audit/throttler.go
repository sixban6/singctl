// 文件职责：管理客户端审计“限速不拉黑”策略的防自锁校验、双栈韧性 DNS 解析缓存与 nftables/iptables 双后端自动分派。
package audit

import (
	"cmp"
	"context"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"singctl/internal/common/netx"
	"singctl/internal/common/execx"
	"singctl/internal/config"
	"singctl/internal/singbox"
)

const (
	// ThrottleNFTTable 是审计“限速不拉黑”专用的隔离 nftables 表名（绝不修改 fw4 或 sing-box 现有表）。
	ThrottleNFTTable = "singctl_audit_throttle"

	// DefaultThrottleDNSCacheTTL 定义域名解析公网 IP 缓存的有效期，用于在后台定期刷新遇到瞬时 DNS 抖动时无感兜底。
	DefaultThrottleDNSCacheTTL = 30 * time.Minute

	MinThrottleRateKBps = 1
	MaxThrottleRateKBps = 102400

	throttleIPv4LookupTimeout = 3 * time.Second
	throttleIPv6LookupTimeout = 1500 * time.Millisecond
)

// ThrottleApplyResult 记录限速规则在内核防火墙层的下发结果。
type ThrottleApplyResult struct {
	Applied     bool   `json:"applied"`
	ActiveRules int    `json:"activeRules"`
	ActiveIPs   int    `json:"activeIps"`
	Message     string `json:"message,omitempty"`
}

type resolvedThrottleLine struct {
	expr string
	isV6 bool
	port int
	rate int
}

type throttleBackend interface {
	Name() string
	Apply(ctx context.Context, lines []resolvedThrottleLine) error
	Clear(ctx context.Context) error
}

type throttleDNSCacheEntry struct {
	addrs     []netip.Addr
	updatedAt time.Time
}

// ThrottleDNSCache 维护按目标域名隔离的并发安全公网 IP 缓存，抵御周期性刷新中的瞬时 DNS 抖动。
type ThrottleDNSCache struct {
	mu      sync.RWMutex
	ttl     time.Duration
	entries map[string]throttleDNSCacheEntry
}

// NewThrottleDNSCache 创建一个并发安全的限速域名公网 IP 缓存（ttl<=0 时回退默认 30 分钟）。
func NewThrottleDNSCache(ttl time.Duration) *ThrottleDNSCache {
	if ttl <= 0 {
		ttl = DefaultThrottleDNSCacheTTL
	}
	return &ThrottleDNSCache{
		ttl:     ttl,
		entries: make(map[string]throttleDNSCacheEntry),
	}
}

func (c *ThrottleDNSCache) set(host string, addrs []netip.Addr, now time.Time) {
	if c == nil || host == "" || len(addrs) == 0 {
		return
	}
	c.mu.Lock()
	c.entries[strings.ToLower(host)] = throttleDNSCacheEntry{
		addrs:     slices.Clone(addrs),
		updatedAt: now,
	}
	c.mu.Unlock()
}

func (c *ThrottleDNSCache) get(host string, now time.Time) ([]netip.Addr, bool) {
	if c == nil || host == "" {
		return nil, false
	}
	c.mu.RLock()
	ent, ok := c.entries[strings.ToLower(host)]
	c.mu.RUnlock()
	if !ok || len(ent.addrs) == 0 {
		return nil, false
	}
	if now.Sub(ent.updatedAt) >= c.ttl {
		return nil, false
	}
	return slices.Clone(ent.addrs), true
}

var defaultThrottleDNSCache = NewThrottleDNSCache(DefaultThrottleDNSCacheTTL)

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

// ThrottlerDeps 定义上行限速执行器的可替换外部依赖（nil 字段自动回退生产默认实现）。
type ThrottlerDeps struct {
	LookupIPs   func(ctx context.Context, host string) ([]netip.Addr, error)
	LookupNetIP func(ctx context.Context, network, host string) ([]netip.Addr, error)
	RunNFT      func(ctx context.Context, script string) error
	DeleteNFT   func(ctx context.Context) error
	LookPath    func(file string) (string, error)
	RunCmd      func(ctx context.Context, name string, args ...string) ([]byte, error)
	GOOS        string
	Now         func() time.Time
	CacheTTL    time.Duration
	Cache       *ThrottleDNSCache
}

// Throttler 负责将 audit.throttles 编译并幂等下发到 Linux nftables 或 iptables/ip6tables 隔离限速表/链。
type Throttler struct {
	lookupIPs     func(ctx context.Context, host string) ([]netip.Addr, error)
	lookupNetIP   func(ctx context.Context, network, host string) ([]netip.Addr, error)
	runNFT        func(ctx context.Context, script string) error
	deleteNFT     func(ctx context.Context) error
	lookPath      func(file string) (string, error)
	runCmd        func(ctx context.Context, name string, args ...string) ([]byte, error)
	goos          string
	now           func() time.Time
	cache         *ThrottleDNSCache
	customNFTOnly bool
}

// NewThrottlerWithDeps 基于给定依赖创建限速执行器（未注入字段自动回退默认实现）。
func NewThrottlerWithDeps(deps ThrottlerDeps) *Throttler {
	def := NewThrottler()
	if deps.LookupNetIP != nil {
		def.lookupNetIP = deps.LookupNetIP
	}
	if deps.LookupIPs != nil {
		def.lookupIPs = deps.LookupIPs
	} else {
		def.lookupIPs = def.lookupSplitDualStack
	}
	if deps.RunNFT != nil {
		def.runNFT = deps.RunNFT
	}
	if deps.DeleteNFT != nil {
		def.deleteNFT = deps.DeleteNFT
	}
	if deps.LookPath != nil {
		def.lookPath = deps.LookPath
	}
	if deps.RunCmd != nil {
		def.runCmd = deps.RunCmd
	}
	if strings.TrimSpace(deps.GOOS) != "" {
		def.goos = strings.TrimSpace(deps.GOOS)
	}
	if deps.Now != nil {
		def.now = deps.Now
	}
	if deps.Cache != nil {
		def.cache = deps.Cache
	} else if deps.CacheTTL > 0 {
		def.cache = NewThrottleDNSCache(deps.CacheTTL)
	}
	// 仅显式注入了旧式 nft 回调而未注入 LookPath/RunCmd 时，保持单后端兼容（保障历史单测在非 Linux 上直走 mock）。
	if (deps.RunNFT != nil || deps.DeleteNFT != nil) && deps.LookPath == nil && deps.RunCmd == nil {
		def.customNFTOnly = true
	}
	return def
}

// NewThrottler 创建默认限速执行器（支持双栈分离 DNS 解析 + 30 分钟缓存 + nftables/iptables 自动探测）。
func NewThrottler() *Throttler {
	t := &Throttler{
		lookupNetIP: net.DefaultResolver.LookupNetIP,
		runNFT:      defaultRunNFT,
		deleteNFT:   defaultDeleteNFT,
		lookPath:    exec.LookPath,
		runCmd: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			return exec.CommandContext(ctx, name, execx.WithXtablesWait(name, args)...).CombinedOutput()
		},
		goos:  runtime.GOOS,
		now:   time.Now,
		cache: NewThrottleDNSCache(DefaultThrottleDNSCacheTTL),
	}
	t.lookupIPs = t.lookupSplitDualStack
	return t
}

func (t *Throttler) lookupSplitDualStack(ctx context.Context, host string) ([]netip.Addr, error) {
	resolver := t.lookupNetIP
	if resolver == nil {
		resolver = net.DefaultResolver.LookupNetIP
	}

	var (
		v4Addrs []netip.Addr
		v4Err   error
		v6Addrs []netip.Addr
		v6Err   error
		wg      sync.WaitGroup
	)

	// 优先查询 IPv4（3s 超时，失败自动重试 1 次），避免慢/SERVFAIL 的 AAAA 查询拖垮整条解析。
	wg.Go(func() {
		for attempt := range 2 {
			if ctx.Err() != nil {
				v4Err = ctx.Err()
				return
			}
			qCtx, cancel := context.WithTimeout(ctx, throttleIPv4LookupTimeout)
			addrs, err := resolver(qCtx, "ip4", host)
			cancel()
			if err == nil && len(addrs) > 0 {
				v4Addrs = addrs
				v4Err = nil
				return
			}
			v4Err = err
			if attempt == 0 && ctx.Err() != nil {
				return
			}
		}
	})

	// 并发短超时（1.5s）补充查询 IPv6，超时或 SERVFAIL 不阻塞也不导致整次解析失败。
	wg.Go(func() {
		if ctx.Err() != nil {
			v6Err = ctx.Err()
			return
		}
		qCtx, cancel := context.WithTimeout(ctx, throttleIPv6LookupTimeout)
		defer cancel()
		v6Addrs, v6Err = resolver(qCtx, "ip6", host)
	})

	wg.Wait()

	merged := make([]netip.Addr, 0, len(v4Addrs)+len(v6Addrs))
	seen := make(map[netip.Addr]struct{}, len(v4Addrs)+len(v6Addrs))
	for _, list := range [][]netip.Addr{v4Addrs, v6Addrs} {
		for _, a := range list {
			u := a.Unmap()
			if _, dup := seen[u]; dup {
				continue
			}
			seen[u] = struct{}{}
			merged = append(merged, u)
		}
	}
	if len(merged) == 0 {
		return nil, cmp.Or(v4Err, v6Err, fmt.Errorf("未解析到 %s 的 IP 记录", host))
	}
	return merged, nil
}

func (t *Throttler) hasBinary(name string) bool {
	lp := t.lookPath
	if lp == nil {
		lp = exec.LookPath
	}
	_, err := lp(name)
	return err == nil
}

func (t *Throttler) selectBackend() (throttleBackend, error) {
	if t.customNFTOnly {
		return &nftThrottleBackend{runNFT: t.runNFT, deleteNFT: t.deleteNFT}, nil
	}
	if t.goos != "linux" {
		return nil, fmt.Errorf("内核限速仅支持 Linux/OpenWrt 环境")
	}
	if t.hasBinary("nft") {
		return &nftThrottleBackend{runNFT: t.runNFT, deleteNFT: t.deleteNFT}, nil
	}
	if t.hasBinary("iptables") {
		return &iptablesThrottleBackend{runCmd: t.runCmd, hasBinary: t.hasBinary}, nil
	}
	return nil, fmt.Errorf("未检测到 nft 或 iptables 命令，跳过内核限速规则下发")
}

func (t *Throttler) resolveThrottleLines(ctx context.Context, cfg *config.Config) ([]resolvedThrottleLine, int, int) {
	if cfg == nil || len(cfg.Audit.Throttles) == 0 {
		return nil, 0, 0
	}
	nowFn := time.Now
	if t != nil && t.now != nil {
		nowFn = t.now
	}
	now := nowFn()

	protectedIPs := collectProtectedPublicIPs(cfg)
	var lines []resolvedThrottleLine
	seenTargets := make(map[string]struct{})
	activeRules := 0
	activeIPs := 0

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
			addrs, lookupErr := t.lookupIPs(ctx, norm)
			validAddrs := filterPublicThrottleAddrs(addrs, protectedIPs)
			if lookupErr == nil && len(validAddrs) > 0 {
				t.cache.set(norm, validAddrs, now)
			} else if cached, ok := t.cache.get(norm, now); ok {
				validAddrs = filterPublicThrottleAddrs(cached, protectedIPs)
			}
			for _, addr := range validAddrs {
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
		return nil, 0, 0
	}
	return lines, activeRules, activeIPs
}

func filterPublicThrottleAddrs(addrs []netip.Addr, protectedIPs []netip.Addr) []netip.Addr {
	if len(addrs) == 0 {
		return nil
	}
	out := make([]netip.Addr, 0, len(addrs))
	for _, raw := range addrs {
		addr := raw.Unmap()
		if _, ok := directIPPublicAddr(addr.String()); !ok {
			continue
		}
		if slices.Contains(protectedIPs, addr) {
			continue
		}
		if !slices.Contains(out, addr) {
			out = append(out, addr)
		}
	}
	slices.SortFunc(out, func(a, b netip.Addr) int {
		return strings.Compare(a.String(), b.String())
	})
	return out
}

// Apply 编译并将 cfg.Audit.Throttles 幂等下发到内核防火墙（自动优先 nftables，无 nft 时降级至 iptables/ip6tables）；无规则时自动清理。
func (t *Throttler) Apply(ctx context.Context, cfg *config.Config) ThrottleApplyResult {
	if t == nil {
		t = NewThrottler()
	}
	lines, rules, ips := t.resolveThrottleLines(ctx, cfg)
	if rules == 0 || len(lines) == 0 {
		if cfg != nil && len(cfg.Audit.Throttles) > 0 {
			return ThrottleApplyResult{
				Applied:     false,
				ActiveRules: 0,
				ActiveIPs:   0,
				Message:     "限速策略已保存，暂未解析到可下发的公网 IP（后台将定期重试解析）",
			}
		}
		if err := t.clearActiveBackend(ctx); err != nil {
			return ThrottleApplyResult{Applied: false, Message: err.Error()}
		}
		return ThrottleApplyResult{
			Applied:     true,
			ActiveRules: 0,
			ActiveIPs:   0,
			Message:     "已清理全部上行限速规则",
		}
	}

	backend, err := t.selectBackend()
	if err != nil {
		return ThrottleApplyResult{
			Applied:     false,
			ActiveRules: rules,
			ActiveIPs:   ips,
			Message:     err.Error(),
		}
	}
	if err := backend.Apply(ctx, lines); err != nil {
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
		Message:     fmt.Sprintf("已下发 %d 条内核限速策略 (覆盖 %d 个公网目标 IP, %s)", rules, ips, backend.Name()),
	}
}

func (t *Throttler) clearActiveBackend(ctx context.Context) error {
	if t.customNFTOnly {
		if t.deleteNFT != nil {
			return t.deleteNFT(ctx)
		}
		return nil
	}
	if t.goos != "linux" {
		return nil
	}
	if t.hasBinary("nft") && t.deleteNFT != nil {
		if err := t.deleteNFT(ctx); err != nil {
			return err
		}
	}
	if t.hasBinary("iptables") {
		ipt := &iptablesThrottleBackend{runCmd: t.runCmd, hasBinary: t.hasBinary}
		if err := ipt.Clear(ctx); err != nil {
			return err
		}
	}
	return nil
}

// ApplyThrottleRules 使用默认执行器（含 30 分钟公网 IP 韧性缓存与双后端自动探测）将 cfg.Audit.Throttles 同步至内核防火墙。
func ApplyThrottleRules(ctx context.Context, cfg *config.Config) ThrottleApplyResult {
	return NewThrottlerWithDeps(ThrottlerDeps{
		Cache: defaultThrottleDNSCache,
	}).Apply(ctx, cfg)
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
	if lanIP := netx.GetPrimaryLANIPv4(); lanIP != "" {
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
