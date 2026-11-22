// 文件职责：实现引擎 1（sing-box 加强版防劫持 DNS）的上游优选、去广告暂停/单规则集开关、白名单、内网重写与实时遥测统计。
package localdns

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strings"
	"time"

	"singctl/internal/adguard"
	"singctl/internal/common/proc"
	"singctl/internal/common/sysinfo"
	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/singbox"
)

const (
	statsSourceSingBox      = "singbox_telemetry"
	statsSourceLabelSingBox = "sing-box 连接与拦截实时遥测"
)

// SingBoxEngine 实现基于 sing-box 原生加密 DoH/DoT + 规则集的零额外开销防劫持 DNS 引擎。
type SingBoxEngine struct {
	cfg   *config.Config
	deps  EngineDeps
	stats *StatsRing
}

// NewSingBoxEngine 创建 sing-box 加强版 DNS 引擎实例。
func NewSingBoxEngine(cfg *config.Config, deps EngineDeps) *SingBoxEngine {
	if cfg == nil {
		cfg = &config.Config{}
	}
	ring := deps.SingBoxStats
	if ring == nil {
		ring = NewStatsRing(true)
	}
	return &SingBoxEngine{
		cfg:   cfg,
		deps:  deps,
		stats: ring,
	}
}

func (e *SingBoxEngine) ID() string { return constant.DNSEngineSingBox }

func (e *SingBoxEngine) Meta() EngineMeta {
	return EngineMeta{
		ID:       constant.DNSEngineSingBox,
		Name:     "sing-box 加强版",
		Tagline:  "零额外进程与闪存开销，内置纯 IP 加密 DoH/DoT、白名单与分流去广告",
		DiskHint: "0 KB",
		RAMHint:  "0 MB",
	}
}

func (e *SingBoxEngine) Capabilities() Capabilities {
	return Capabilities{
		HasNativeWebPanel:  false,
		HasConfigPreview:   true,
		HasQueryStats:      true,
		HasFilterLists:     true,
		HasCustomFilterURL: false,
		HasPauseProtection: true,
		HasBlockAAAA:       true,
		CanClearCache:      true,
		CanUninstall:       false,
	}
}

func (e *SingBoxEngine) IsInstalled() bool { return true }

func (e *SingBoxEngine) now() time.Time {
	if e.deps.NowFunc != nil {
		return e.deps.NowFunc()
	}
	return time.Now()
}

func (e *SingBoxEngine) sbConfigPath() string {
	return cmp.Or(strings.TrimSpace(e.deps.SingBoxConfigPath), constant.SingBoxConfigFile)
}

func (e *SingBoxEngine) sbWorkConfigPath() string {
	if strings.TrimSpace(e.deps.SingBoxWorkConfigPath) != "" {
		return strings.TrimSpace(e.deps.SingBoxWorkConfigPath)
	}
	if strings.TrimSpace(e.deps.SingBoxConfigPath) == "" || strings.TrimSpace(e.deps.SingBoxConfigPath) == constant.SingBoxConfigFile {
		return constant.SingBoxWorkConfigFile
	}
	return ""
}

func (e *SingBoxEngine) effectiveUpstreams() []string {
	if len(e.cfg.DNS.Upstreams) > 0 {
		return slices.Clone(e.cfg.DNS.Upstreams)
	}
	return adguard.DefaultUpstreams()
}

func (e *SingBoxEngine) isSingBoxRunning() bool {
	if e.deps.SingBoxRunningFunc != nil {
		return e.deps.SingBoxRunningFunc()
	}
	return proc.PgrepMatch("sing-box")
}

func (e *SingBoxEngine) singBoxVersion() string {
	if e.deps.SingBoxVersionFunc != nil {
		return e.deps.SingBoxVersionFunc()
	}
	return ""
}

func (e *SingBoxEngine) saveConfig() error {
	if e.deps.SaveConfig != nil {
		return e.deps.SaveConfig(e.cfg)
	}
	if strings.TrimSpace(e.deps.ConfigPath) == "" {
		return nil
	}
	return config.Save(e.deps.ConfigPath, e.cfg)
}

func (e *SingBoxEngine) syncLive(ctx context.Context) error {
	sbPath := e.sbConfigPath()
	workPath := e.sbWorkConfigPath()
	subs := singbox.ExtractSubscriptionDomains(e.cfg)
	now := e.now()

	if e.deps.SyncSingBoxEnhancedFunc != nil {
		if _, err := e.deps.SyncSingBoxEnhancedFunc(ctx, sbPath, workPath, e.cfg.DNS, subs, now); err != nil {
			return err
		}
	} else {
		if _, err := singbox.SyncLiveSingBoxEnhancedDNS(ctx, sbPath, workPath, e.cfg.DNS, subs, now); err != nil {
			return err
		}
	}

	// 同步 .config.json.singctl-base，保证后续三路合并基线一致
	if baseRaw, err := singbox.LoadBaseSnapshot(sbPath); err == nil && strings.TrimSpace(baseRaw) != "" {
		if updatedBase, changed, applyErr := singbox.ApplyEnhancedSingBoxDNSJSON(baseRaw, e.cfg.DNS, subs, now); applyErr == nil && changed {
			_ = singbox.SaveBaseSnapshot(sbPath, updatedBase)
		}
	}
	return nil
}

func (e *SingBoxEngine) Status(_ context.Context) EngineStatus {
	ups := e.effectiveUpstreams()
	primary := "https://223.5.5.5/dns-query"
	if len(ups) > 0 {
		primary = ups[0]
	}
	running := e.isSingBoxRunning()
	return EngineStatus{
		Supported:  true,
		Installed:  true,
		Running:    running,
		DNSHealthy: running,
		WebHealthy: false,
		Version:    e.singBoxVersion(),
		DNSAddr:    primary,
	}
}

func singBoxUpstreamModeLabel(mode string) string {
	switch mode {
	case config.DNSUpstreamModeParallel:
		return "多上游备选池（优先采用首条可用加密 DoH/DoT 上游，失活自动切换）"
	case config.DNSUpstreamModeLoadBalance:
		return "加密上游均衡池（按配置顺序托管加密 DoH/DoT 上游）"
	default:
		return "最快加密上游优选（保存时实测延迟并将最快加密上游置顶，看门狗自动故障热切）"
	}
}

func managedAdRuleSetMeta(tag string) (name, desc string, recommended bool) {
	switch tag {
	case "geosite-ad1":
		return "内置轻量去广告规则集 (geosite-ad1)", "低内存友好的核心广告与追踪域名规则集，由 sing-box 原生零额外进程拦截", true
	case "geosite-ad2":
		return "内置深度去广告规则集 (geosite-ad2)", "覆盖更广的补充广告规则集（<=512MB 低内存设备自动按需裁剪以防 OOM）", false
	case singbox.BuiltinPCDNRuleSetTag:
		return "内置防 PCDN 偷跑规则集 (block-builtin-pcdn)", "阻断常见 PCDN 商业宽带偷跑节点域名，保护家庭宽带上行与防封号", true
	default:
		return tag, "sing-box 内置受管规则集", false
	}
}

func (e *SingBoxEngine) buildRuleSetFilters() ([]adguard.FilterItem, []adguard.PresetStatus) {
	tags := singbox.ManagedAdRuleSetTags()
	filters := make([]adguard.FilterItem, 0, len(tags))
	presets := make([]adguard.PresetStatus, 0, len(tags))
	for i, tag := range tags {
		name, desc, rec := managedAdRuleSetMeta(tag)
		enabled := !slices.Contains(e.cfg.DNS.DisabledAdRuleSets, tag)
		ruleURL := "ruleset:" + tag
		filters = append(filters, adguard.FilterItem{
			ID:      int64(i + 1),
			Enabled: enabled,
			Name:    name,
			URL:     ruleURL,
		})
		presets = append(presets, adguard.PresetStatus{
			FilterPreset: adguard.FilterPreset{
				ID:          tag,
				Name:        name,
				Desc:        desc,
				URL:         ruleURL,
				Recommended: rec,
			},
			Installed: true,
			Enabled:   enabled,
		})
	}
	return filters, presets
}

func (e *SingBoxEngine) Overview(ctx context.Context, singboxLinked bool) *OverviewSnapshot {
	now := e.now()
	st := e.Status(ctx)
	mode := e.cfg.DNS.GetUpstreamMode()
	ups := e.effectiveUpstreams()
	upInfos := make([]adguard.UpstreamServerInfo, 0, len(ups))
	for _, u := range ups {
		upInfos = append(upInfos, adguard.DescribeUpstream(u))
	}

	filters, presets := e.buildRuleSetFilters()
	wl := slices.Clone(e.cfg.DNS.Whitelist)
	if wl == nil {
		wl = []string{}
	}
	subs := singbox.ExtractSubscriptionDomains(e.cfg)
	if subs == nil {
		subs = []string{}
	}
	rewrites := make([]adguard.RewriteEntry, 0, len(e.cfg.DNS.Rewrites))
	for _, r := range e.cfg.DNS.Rewrites {
		rewrites = append(rewrites, adguard.RewriteEntry{Domain: r.Domain, Answer: r.Answer})
	}

	paused := e.cfg.DNS.IsAdblockPaused(now)
	var disabledMs int64
	var disabledUntil string
	if paused && e.cfg.DNS.AdblockDisabledUntil > now.Unix() {
		disabledMs = (e.cfg.DNS.AdblockDisabledUntil - now.Unix()) * 1000
		disabledUntil = time.Unix(e.cfg.DNS.AdblockDisabledUntil, 0).UTC().Format(time.RFC3339)
	}

	isOpenWrt := false
	if e.deps.IsOpenWrt != nil {
		isOpenWrt = e.deps.IsOpenWrt()
	} else {
		isOpenWrt = sysinfo.IsOpenWrt()
	}

	stats := e.stats.Snapshot(now, e.stats.FallbackLatencyMs())
	// singbox 引擎自身即承载 dns_local 加密解析，仅当被外指至未运行外部端口时才算未联动
	linked := !singboxLinked

	return &OverviewSnapshot{
		OverviewSnapshot: adguard.OverviewSnapshot{
			Supported:                    true,
			Installed:                    true,
			Enabled:                      true,
			Running:                      st.Running,
			DNSHealthy:                   st.DNSHealthy,
			WebHealthy:                   false,
			SingBoxLinked:                linked,
			IsOpenWrt:                    isOpenWrt,
			Version:                      st.Version,
			DNSAddr:                      st.DNSAddr,
			ProtectionEnabled:            !paused,
			ProtectionDisabledDurationMs: disabledMs,
			ProtectionDisabledUntil:      disabledUntil,
			UpstreamMode:                 mode,
			UpstreamModeLabel:            singBoxUpstreamModeLabel(mode),
			Upstreams:                    upInfos,
			UpstreamPresets:              adguard.CuratedUpstreamPresets(),
			Stats:                        stats,
			Filters:                      filters,
			TotalRulesCount:              len(filters),
			Presets:                      presets,
			WhitelistedDomains:           wl,
			AutoWhitelistedSubs:          subs,
			AuditManagedCount:            len(e.cfg.CustomRules.Block),
			Rewrites:                     rewrites,
		},
		BlockAAAA:        e.cfg.DNS.BlockAAAA,
		StatsSource:      statsSourceSingBox,
		StatsSourceLabel: statsSourceLabelSingBox,
		Capabilities:     e.Capabilities(),
	}
}

func (e *SingBoxEngine) ConfigPreview(ctx context.Context) (*ConfigPreview, error) {
	sbPath := e.sbConfigPath()
	pretty, err := singbox.ExtractSingBoxDNSSectionPretty(sbPath)
	if err != nil {
		return nil, err
	}
	st := e.Status(ctx)
	summary := fmt.Sprintf("sing-box 加强版内置加密 DNS | 主上游: %s | 屏蔽 AAAA: %v | 去广告暂停: %v",
		st.DNSAddr, e.cfg.DNS.BlockAAAA, e.cfg.DNS.IsAdblockPaused(e.now()))
	return &ConfigPreview{
		Engine:         constant.DNSEngineSingBox,
		Title:          "sing-box 加强版生效 DNS 配置段",
		Path:           sbPath,
		Content:        pretty,
		RuntimeSummary: summary,
	}, nil
}

func (e *SingBoxEngine) Install(ctx context.Context, _ InstallOptions) error {
	return e.syncLive(ctx)
}

func (e *SingBoxEngine) Start(ctx context.Context) error { return e.syncLive(ctx) }
func (e *SingBoxEngine) Stop(context.Context) error      { return nil }
func (e *SingBoxEngine) Disable(context.Context) error   { return nil }
func (e *SingBoxEngine) Restart(ctx context.Context) error {
	return e.syncLive(ctx)
}

func (e *SingBoxEngine) Uninstall(context.Context, bool) error {
	return errors.New("sing-box 加强版属于内置零开销核心 DNS 引擎，不支持卸载")
}

func (e *SingBoxEngine) EnsureHealthy(context.Context) error { return nil }

func (e *SingBoxEngine) SetProtection(ctx context.Context, enabled bool, durationMinutes int) error {
	if enabled {
		e.cfg.DNS.AdblockDisabledUntil = 0
	} else if durationMinutes > 0 {
		e.cfg.DNS.AdblockDisabledUntil = e.now().Add(time.Duration(durationMinutes) * time.Minute).Unix()
	} else {
		e.cfg.DNS.AdblockDisabledUntil = -1
	}
	if err := e.saveConfig(); err != nil {
		return err
	}
	return e.syncLive(ctx)
}

func (e *SingBoxEngine) ClearCache(ctx context.Context) error {
	if e.deps.ClearSingBoxCacheFunc != nil {
		return e.deps.ClearSingBoxCacheFunc(ctx, e.sbConfigPath(), e.sbWorkConfigPath())
	}
	return singbox.ClearSingBoxDNSCache(ctx, e.sbConfigPath(), e.sbWorkConfigPath())
}

func (e *SingBoxEngine) probeList(ctx context.Context, upstreams []string, domain string) []adguard.UpstreamProbeItem {
	if e.deps.ProbeUpstreamListFunc != nil {
		return e.deps.ProbeUpstreamListFunc(ctx, upstreams, domain, 3200*time.Millisecond)
	}
	return adguard.ProbeUpstreamList(ctx, upstreams, domain, 3200*time.Millisecond)
}

func (e *SingBoxEngine) ProbeUpstreams(ctx context.Context, domain string) *adguard.ProbeReport {
	targetDomain := cmp.Or(strings.TrimSpace(domain), "qq.com")
	upstreams := e.effectiveUpstreams()
	mode := e.cfg.DNS.GetUpstreamMode()
	items := e.probeList(ctx, upstreams, targetDomain)

	report := &adguard.ProbeReport{
		DNSAddr:           cmp.Or(firstOrEmpty(upstreams), "https://223.5.5.5/dns-query"),
		Domain:            targetDomain,
		UpstreamMode:      mode,
		UpstreamModeLabel: singBoxUpstreamModeLabel(mode),
		Upstreams:         items,
	}

	bestIdx := -1
	var healthyLatSum int64
	var healthyCount int64
	for i := range items {
		if !items[i].Healthy {
			continue
		}
		healthyLatSum += items[i].LatencyMs
		healthyCount++
		if bestIdx == -1 || items[i].LatencyMs < items[bestIdx].LatencyMs {
			bestIdx = i
		}
	}
	if bestIdx >= 0 {
		items[bestIdx].Fastest = true
		report.Healthy = true
		report.Resolved = items[bestIdx].Resolved
		report.LatencyMs = items[bestIdx].LatencyMs
		report.FastestUpstream = items[bestIdx].Address
		report.FastestName = items[bestIdx].Name
		report.FastestLatencyMs = items[bestIdx].LatencyMs
		e.stats.SetFallbackLatencyMs(float64(healthyLatSum) / float64(healthyCount))
	} else {
		report.Error = "所有已配置加密上游探测均失败，请检查网络连接或更换纯 IP 加密上游"
	}
	return report
}

func validateSingBoxUpstream(raw string) (normalized string, note string, err error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", "", errors.New("加密上游地址不能为空")
	}
	lower := strings.ToLower(s)
	if strings.HasPrefix(lower, "https://") || strings.HasPrefix(lower, "tls://") {
		if norm, _, convNote, normErr := adguard.NormalizeAndValidateUpstream(s); normErr == nil {
			return norm, convNote, nil
		}
	}
	parsed, err := singbox.ParseEncryptedDNSServer(s)
	if err != nil {
		return "", "", err
	}
	if addr, ipErr := netip.ParseAddr(parsed.Server); ipErr == nil {
		addr = addr.Unmap()
		if addr.IsLoopback() || addr.IsPrivate() || addr.IsUnspecified() || addr.IsLinkLocalUnicast() || addr.IsMulticast() {
			return "", "", fmt.Errorf("禁止将回环、私网或保留地址 (%s) 设为防劫持加密上游", addr.String())
		}
	}
	return s, "", nil
}

func normalizeConfigUpstreamMode(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case config.DNSUpstreamModeParallel:
		return config.DNSUpstreamModeParallel
	case config.DNSUpstreamModeLoadBalance:
		return config.DNSUpstreamModeLoadBalance
	case config.DNSUpstreamModeFastestIP, "fastest_addr", "":
		return config.DNSUpstreamModeFastestIP
	default:
		return config.DNSUpstreamModeFastestIP
	}
}

func (e *SingBoxEngine) SetUpstreams(ctx context.Context, rawUpstreams []string, rawMode string, resetDefault bool) (*UpstreamUpdateResult, error) {
	if resetDefault {
		rawUpstreams = adguard.DefaultUpstreams()
		rawMode = config.DNSUpstreamModeFastestIP
	}
	mode := normalizeConfigUpstreamMode(rawMode)
	if len(rawUpstreams) == 0 {
		return nil, errors.New("至少需要保留 1 条加密上游 DNS 服务器")
	}

	seen := make(map[string]struct{}, len(rawUpstreams))
	cleaned := make([]string, 0, len(rawUpstreams))
	var notes []string
	for _, raw := range rawUpstreams {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		norm, note, err := validateSingBoxUpstream(raw)
		if err != nil {
			return nil, err
		}
		key := strings.ToLower(norm)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		cleaned = append(cleaned, norm)
		if note != "" {
			notes = append(notes, note)
		}
	}
	if len(cleaned) == 0 {
		return nil, errors.New("至少需要保留 1 条有效的加密上游 DNS 服务器")
	}
	if len(cleaned) > 12 {
		return nil, errors.New("上游 DNS 服务器数量请勿超过 12 条")
	}

	if !e.deps.SkipProbeForTest {
		items := e.probeList(ctx, cleaned, "qq.com")
		bestIdx := -1
		var firstErr string
		for i, it := range items {
			if it.Healthy {
				if bestIdx == -1 || it.LatencyMs < items[bestIdx].LatencyMs {
					bestIdx = i
				}
			} else if firstErr == "" && it.Error != "" {
				firstErr = fmt.Sprintf("%s (%s)", it.Address, it.Error)
			}
		}
		if bestIdx < 0 {
			return nil, fmt.Errorf("所选加密上游均无法完成解析验证，已拦截保存以防断网：%s", cmp.Or(firstErr, "连接超时"))
		}
		e.stats.SetFallbackLatencyMs(float64(items[bestIdx].LatencyMs))
		if mode == config.DNSUpstreamModeFastestIP && bestIdx > 0 {
			fastest := cleaned[bestIdx]
			cleaned = append([]string{fastest}, append(cleaned[:bestIdx], cleaned[bestIdx+1:]...)...)
			notes = append(notes, fmt.Sprintf("已按实测最低延迟 (%dms) 自动将 %s 设为 sing-box 主加密上游", items[bestIdx].LatencyMs, fastest))
		}
	}

	e.cfg.DNS.Upstreams = cleaned
	e.cfg.DNS.UpstreamMode = mode
	if err := e.saveConfig(); err != nil {
		return nil, err
	}
	if err := e.syncLive(ctx); err != nil {
		return nil, err
	}

	infos := make([]adguard.UpstreamServerInfo, 0, len(cleaned))
	for _, u := range cleaned {
		infos = append(infos, adguard.DescribeUpstream(u))
	}
	return &UpstreamUpdateResult{
		Upstreams:         infos,
		UpstreamMode:      mode,
		UpstreamModeLabel: singBoxUpstreamModeLabel(mode),
		Notes:             notes,
	}, nil
}

func normalizeSafeDomain(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", errors.New("域名不能为空")
	}
	for _, r := range s {
		if r <= 0x20 || r == 0x7f {
			return "", errors.New("域名包含非法空白或控制字符")
		}
	}
	s = strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(s, "*."), "."), "."))
	if err := singbox.ValidateDNSRewriteRule(config.DNSRewriteRule{Domain: s, Answer: "192.0.2.1"}); err != nil {
		return "", fmt.Errorf("请输入合法的域名（如 example.com）: %w", err)
	}
	return s, nil
}

func (e *SingBoxEngine) SetWhitelist(ctx context.Context, rawDomain string, allow bool) error {
	dom, err := normalizeSafeDomain(rawDomain)
	if err != nil {
		return err
	}
	updated := make([]string, 0, len(e.cfg.DNS.Whitelist)+1)
	for _, existing := range e.cfg.DNS.Whitelist {
		if strings.EqualFold(strings.TrimSpace(existing), dom) {
			continue
		}
		updated = append(updated, existing)
	}
	if allow {
		updated = append(updated, dom)
	}
	e.cfg.DNS.Whitelist = updated
	if err := e.saveConfig(); err != nil {
		return err
	}
	return e.syncLive(ctx)
}

func (e *SingBoxEngine) AddRewrite(ctx context.Context, domain, answer string) error {
	rule := config.DNSRewriteRule{
		Domain: strings.ToLower(strings.TrimSpace(domain)),
		Answer: strings.TrimSpace(answer),
	}
	if err := singbox.ValidateDNSRewriteRule(rule); err != nil {
		return err
	}
	updated := make([]config.DNSRewriteRule, 0, len(e.cfg.DNS.Rewrites)+1)
	for _, existing := range e.cfg.DNS.Rewrites {
		if strings.EqualFold(existing.Domain, rule.Domain) && existing.Answer == rule.Answer {
			continue
		}
		updated = append(updated, existing)
	}
	updated = append(updated, rule)
	e.cfg.DNS.Rewrites = updated
	if err := e.saveConfig(); err != nil {
		return err
	}
	return e.syncLive(ctx)
}

func (e *SingBoxEngine) DeleteRewrite(ctx context.Context, domain, answer string) error {
	d := strings.ToLower(strings.TrimSpace(domain))
	a := strings.TrimSpace(answer)
	if d == "" || a == "" {
		return errors.New("域名与目标记录不能为空")
	}
	e.cfg.DNS.Rewrites = slices.DeleteFunc(slices.Clone(e.cfg.DNS.Rewrites), func(r config.DNSRewriteRule) bool {
		return strings.EqualFold(strings.TrimSpace(r.Domain), d) && strings.TrimSpace(r.Answer) == a
	})
	if err := e.saveConfig(); err != nil {
		return err
	}
	return e.syncLive(ctx)
}

func (e *SingBoxEngine) SetFilterState(ctx context.Context, filterURL, _ string, enabled bool) error {
	tag := strings.TrimSpace(filterURL)
	tag = strings.TrimPrefix(tag, "ruleset:")
	if !slices.Contains(singbox.ManagedAdRuleSetTags(), tag) {
		return fmt.Errorf("sing-box 加强版仅支持开关内置规则集 (%s)，不支持外部 URL 规则集；如需自定义外部规则库请切换 SmartDNS 或 AdGuard Home",
			strings.Join(singbox.ManagedAdRuleSetTags(), ", "))
	}
	updated := slices.DeleteFunc(slices.Clone(e.cfg.DNS.DisabledAdRuleSets), func(t string) bool {
		return t == tag
	})
	if !enabled {
		updated = append(updated, tag)
	}
	e.cfg.DNS.DisabledAdRuleSets = updated
	if err := e.saveConfig(); err != nil {
		return err
	}
	return e.syncLive(ctx)
}

func (e *SingBoxEngine) RemoveFilter(context.Context, string) error {
	return errors.New("sing-box 内置规则集不支持删除，可通过开关停用")
}

func (e *SingBoxEngine) RefreshFilters(ctx context.Context) error {
	return e.syncLive(ctx)
}

func (e *SingBoxEngine) SetBlockAAAA(ctx context.Context, enabled bool) error {
	e.cfg.DNS.BlockAAAA = enabled
	if err := e.saveConfig(); err != nil {
		return err
	}
	return e.syncLive(ctx)
}

func (e *SingBoxEngine) SyncBlockRules(context.Context, []config.BlockRule) (bool, string, error) {
	return true, "singbox_native", nil
}

func (e *SingBoxEngine) SyncCommonConfig(ctx context.Context) error {
	sbPath := e.sbConfigPath()
	if _, err := os.Stat(sbPath); os.IsNotExist(err) {
		return nil
	}
	return e.syncLive(ctx)
}

func firstOrEmpty(list []string) string {
	if len(list) == 0 {
		return ""
	}
	return list[0]
}
