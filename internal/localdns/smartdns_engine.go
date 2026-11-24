// 文件职责：实现 SmartDNS 极速版防劫持 DNS 引擎的初始化、配置编译（AAAA 策略由 gateway.ipv6_mode 自动派生）、内存盘逐包审计与快照聚合。
package localdns

import (
	"cmp"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"singctl/internal/adguard"
	"singctl/internal/common/sysinfo"
	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/singbox"
	"singctl/internal/smartdns"
)

const (
	statsSourceSmartDNS      = "smartdns_audit"
	statsSourceLabelSmartDNS = "SmartDNS 内存盘逐包审计"
)

// SmartDNSEngine 封装 internal/smartdns.Manager，实现统一双引擎契约与 24h 内存盘审计统计。
type SmartDNSEngine struct {
	cfg    *config.Config
	deps   EngineDeps
	mgr    *smartdns.Manager
	stats  *StatsRing
	tailer *smartdns.AuditLogTailer
}

// NewSmartDNSEngine 创建 SmartDNS 极速版防劫持 DNS 引擎适配器。
func NewSmartDNSEngine(cfg *config.Config, deps EngineDeps) *SmartDNSEngine {
	if cfg == nil {
		cfg = &config.Config{}
	}
	auditLog := cmp.Or(strings.TrimSpace(deps.SmartDNSAuditLogPath), constant.SmartDNSAuditLogPath)
	ring := deps.SmartDNSStats
	if ring == nil {
		ring = NewStatsRing(true)
	}
	tailer := deps.SmartDNSTailer
	if tailer == nil {
		tailer = smartdns.NewAuditLogTailer(auditLog)
	}
	e := &SmartDNSEngine{
		cfg:    cfg,
		deps:   deps,
		stats:  ring,
		tailer: tailer,
	}
	if deps.SmartDNSManager != nil {
		e.mgr = deps.SmartDNSManager
	} else {
		e.mgr = e.buildManager()
	}
	return e
}

// shouldSmartDNSBlockAAAA 按单一数据源规则从 gateway.ipv6_mode 派生 SmartDNS 的 force-AAAA-SOA 开关：
// 仅当 ipv6_mode 为 off（纯 IPv4）时开启 AAAA 屏蔽；cn_only / full 双栈模式自动放行 AAAA。
func shouldSmartDNSBlockAAAA(cfg *config.Config) bool {
	if cfg == nil {
		return true
	}
	return cfg.Gateway.EffectiveIPv6Mode() == config.GatewayIPv6Off
}

func (e *SmartDNSEngine) binPath() string {
	return cmp.Or(strings.TrimSpace(e.deps.SmartDNSBinPath), constant.SmartDNSInstallPath)
}

func (e *SmartDNSEngine) configFilePath() string {
	return cmp.Or(strings.TrimSpace(e.deps.SmartDNSConfigFile), constant.SmartDNSConfigFile)
}

func (e *SmartDNSEngine) rulesDirPath() string {
	if strings.TrimSpace(e.deps.SmartDNSRulesDir) != "" {
		return strings.TrimSpace(e.deps.SmartDNSRulesDir)
	}
	if strings.TrimSpace(e.deps.SmartDNSConfigFile) != "" {
		return filepath.Join(filepath.Dir(e.deps.SmartDNSConfigFile), "smartdns-rules.d")
	}
	return constant.SmartDNSRulesDir
}

func (e *SmartDNSEngine) serviceName() string {
	return cmp.Or(strings.TrimSpace(e.deps.SmartDNSServiceName), constant.SmartDNSServiceName)
}

func (e *SmartDNSEngine) now() time.Time {
	if e.deps.NowFunc != nil {
		return e.deps.NowFunc()
	}
	return time.Now()
}

func (e *SmartDNSEngine) buildManager() *smartdns.Manager {
	opts := smartdns.ManagerOptions{
		BinaryPath:    e.binPath(),
		ConfigDir:     cmp.Or(strings.TrimSpace(e.deps.SmartDNSConfigDir), constant.SmartDNSConfigDir),
		ConfigFile:    e.configFilePath(),
		RulesDir:      e.rulesDirPath(),
		AuditLogPath:  cmp.Or(strings.TrimSpace(e.deps.SmartDNSAuditLogPath), constant.SmartDNSAuditLogPath),
		LogFilePath:   cmp.Or(strings.TrimSpace(e.deps.SmartDNSLogFilePath), smartdns.DefaultLogFilePath),
		PIDFilePath:   cmp.Or(strings.TrimSpace(e.deps.SmartDNSPIDFilePath), smartdns.DefaultPIDFilePath),
		ServiceName:   e.serviceName(),
		GOOS:          e.deps.GOOS,
		GOARCH:        e.deps.GOARCH,
		ServiceMgr:    e.deps.ServiceMgr,
		ReadMemInfo:   e.deps.ReadMemInfo,
		ReadDiskSpace: e.deps.ReadDiskSpace,
		HTTPClient:    e.deps.HTTPClient,
		ProbeDNSFunc:  e.deps.ProbeDNSFunc,
		Config:        e.buildConfigInput(),
	}
	if e.deps.SmartDNSExtraOpt != nil {
		if e.deps.SmartDNSExtraOpt.DownloadFunc != nil {
			opts.DownloadFunc = e.deps.SmartDNSExtraOpt.DownloadFunc
		}
		if e.deps.SmartDNSExtraOpt.ExecVerifyFunc != nil {
			opts.ExecVerifyFunc = e.deps.SmartDNSExtraOpt.ExecVerifyFunc
		}
		if e.deps.SmartDNSExtraOpt.ReleaseAPIBase != "" {
			opts.ReleaseAPIBase = e.deps.SmartDNSExtraOpt.ReleaseAPIBase
		}
		if e.deps.SmartDNSExtraOpt.SystemdDir != "" {
			opts.SystemdDir = e.deps.SmartDNSExtraOpt.SystemdDir
		}
		if e.deps.SmartDNSExtraOpt.ProcdDir != "" {
			opts.ProcdDir = e.deps.SmartDNSExtraOpt.ProcdDir
		}
	}
	return smartdns.NewManager(opts)
}

func extractSmartDNSAuditBlockDomains(blocks []config.BlockRule) []string {
	out := make([]string, 0, len(blocks))
	seen := make(map[string]struct{}, len(blocks))
	for _, b := range blocks {
		raw := strings.TrimSpace(b.Target)
		if raw == "" || strings.HasPrefix(strings.ToLower(raw), "ruleset:") {
			continue
		}
		if strings.TrimSpace(b.SourceIP) != "" {
			// SmartDNS 全局拦截不支持单源设备精细匹配，交由 sing-box 路由层处理
			continue
		}
		clean := strings.TrimPrefix(strings.TrimPrefix(strings.ToLower(raw), "*."), ".")
		if net.ParseIP(clean) != nil || strings.Contains(clean, "/") {
			continue
		}
		dom, err := smartdns.ValidateDomain(clean)
		if err != nil {
			continue
		}
		if _, dup := seen[dom]; dup {
			continue
		}
		seen[dom] = struct{}{}
		out = append(out, dom)
	}
	return out
}

func (e *SmartDNSEngine) buildConfigInput() smartdns.ConfigInput {
	now := e.now()
	ups := e.cfg.DNS.Upstreams
	if len(ups) == 0 {
		ups = smartdns.DefaultUpstreams()
	}

	effectiveWL := singbox.EffectiveAdBlockWhitelist(e.cfg)
	wl := make([]string, 0, len(effectiveWL))
	seenWL := make(map[string]struct{}, len(effectiveWL))
	for _, raw := range effectiveWL {
		if dom, err := smartdns.ValidateDomain(strings.TrimPrefix(strings.TrimSpace(raw), "*.")); err == nil {
			if _, dup := seenWL[dom]; !dup {
				seenWL[dom] = struct{}{}
				wl = append(wl, dom)
			}
		}
	}

	rewrites := make([]smartdns.RewriteEntry, 0, len(e.cfg.DNS.Rewrites))
	for _, r := range e.cfg.DNS.Rewrites {
		dom := strings.TrimPrefix(strings.TrimSpace(r.Domain), "*.")
		if validDom, err := smartdns.ValidateDomain(dom); err == nil {
			if validAns, aErr := smartdns.ValidateRewriteAnswer(r.Answer); aErr == nil {
				rewrites = append(rewrites, smartdns.RewriteEntry{Domain: validDom, Answer: validAns})
			}
		}
	}

	var totalRAM uint64
	if e.deps.ReadMemInfo != nil {
		if mi, err := e.deps.ReadMemInfo(); err == nil {
			totalRAM = mi.TotalBytes
		}
	} else {
		totalRAM = sysinfo.TotalRAMBytes()
	}

	return smartdns.ConfigInput{
		DNSPort:             e.cfg.DNS.GetDNSPort(),
		Upstreams:           slices.Clone(ups),
		UpstreamMode:        smartdns.NormalizeUpstreamMode(e.cfg.DNS.UpstreamMode),
		Whitelist:           wl,
		Rewrites:            rewrites,
		AuditBlockedDomains: extractSmartDNSAuditBlockDomains(e.cfg.CustomRules.Block),
		EnabledFilters:      slices.Clone(e.cfg.DNS.SmartDNSFilters),
		BlockAAAA:           shouldSmartDNSBlockAAAA(e.cfg),
		ProtectionPaused:    e.cfg.DNS.IsAdblockPaused(now),
		MirrorURL:           e.cfg.GitHub.MirrorURL,
		IsLowMemory:         e.cfg.EffectiveLowMemory(totalRAM),
		IsUltraLowMemory:    totalRAM > 0 && totalRAM <= smartdns.UltraLowTotalRAMBytes,
	}
}

func (e *SmartDNSEngine) ID() string { return constant.DNSEngineSmartDNS }

func (e *SmartDNSEngine) Meta() EngineMeta {
	return EngineMeta{
		ID:       constant.DNSEngineSmartDNS,
		Name:     "SmartDNS",
		Tagline:  "C 语言极速多上游并发测速引擎，中小内存与小闪存路由首选，内存盘审计零磨损",
		DiskHint: "~3 MB",
		RAMHint:  "~10 MB",
	}
}

func (e *SmartDNSEngine) Capabilities() Capabilities {
	return Capabilities{
		HasNativeWebPanel:  false,
		HasConfigPreview:   true,
		HasQueryStats:      true,
		HasFilterLists:     true,
		HasCustomFilterURL: true,
		HasPauseProtection: true,
		HasBlockAAAA:       false,
		CanClearCache:      true,
		CanUninstall:       true,
	}
}

func (e *SmartDNSEngine) IsInstalled() bool {
	info, err := os.Stat(e.binPath())
	return err == nil && !info.IsDir()
}

func normalizeAuditEntryTime(ts, now time.Time) time.Time {
	if ts.IsZero() {
		return now
	}
	if diff := now.Sub(ts); diff >= -30*time.Minute && diff <= 30*time.Minute {
		return ts
	}
	// OpenWrt 静态 musl 版 SmartDNS 若未继承 TZ 会以 UTC 墙钟写审计日志；
	// 若按 UTC 解释恰好落在当前时间 30 分钟窗口内，则自动还原为准确时间戳。
	asUTC := time.Date(ts.Year(), ts.Month(), ts.Day(), ts.Hour(), ts.Minute(), ts.Second(), ts.Nanosecond(), time.UTC)
	if diff := now.Sub(asUTC); diff >= -30*time.Minute && diff <= 30*time.Minute {
		return asUTC
	}
	return ts
}

// DrainAuditLog 增量消费 SmartDNS tmpfs 审计日志并写入共享 24h 环形统计器。
func (e *SmartDNSEngine) DrainAuditLog() int {
	if e == nil || e.tailer == nil || e.stats == nil {
		return 0
	}
	entries, err := e.tailer.ReadNew()
	if err != nil || len(entries) == 0 {
		return 0
	}
	now := e.now()
	recorded := 0
	for _, entry := range entries {
		if entry.Domain == "localhost" {
			continue
		}
		e.stats.Record(normalizeAuditEntryTime(entry.Timestamp, now), entry.Domain, entry.Blocked, entry.LatencyMs)
		recorded++
	}
	return recorded
}

func (e *SmartDNSEngine) saveConfig() error {
	if e.deps.SaveConfig != nil {
		return e.deps.SaveConfig(e.cfg)
	}
	if strings.TrimSpace(e.deps.ConfigPath) == "" {
		return nil
	}
	return config.Save(e.deps.ConfigPath, e.cfg)
}

func (e *SmartDNSEngine) Status(_ context.Context) EngineStatus {
	st := e.mgr.Status()
	return EngineStatus{
		Supported:  st.Supported,
		Installed:  st.Installed,
		Running:    st.Running,
		DNSHealthy: st.DNSHealthy,
		WebHealthy: false,
		Version:    st.Version,
		DNSAddr:    st.DNSAddr,
	}
}

func smartDNSUpstreamModeLabel(mode string) string {
	switch smartdns.NormalizeUpstreamMode(mode) {
	case "parallel":
		return "多上游首包竞速（first-ping 优先返回最快测速结果）"
	case "load_balance":
		return "极速响应（fastest-response 跳过测速直接采用最快应答）"
	default:
		return "最快 IP 优选（fastest-ip 并发测速 ping/TCP 优选延迟最低的目标 IP）"
	}
}

func (e *SmartDNSEngine) buildFiltersAndPresets() ([]adguard.FilterItem, []adguard.PresetStatus) {
	curated := smartdns.CuratedFilterPresets()
	enabledSet := make(map[string]bool, len(e.cfg.DNS.SmartDNSFilters))
	for _, u := range e.cfg.DNS.SmartDNSFilters {
		enabledSet[strings.TrimSpace(u)] = true
	}

	presets := make([]adguard.PresetStatus, 0, len(curated))
	filters := make([]adguard.FilterItem, 0, len(curated)+len(e.cfg.DNS.SmartDNSFilters))
	curatedURLs := make(map[string]bool, len(curated))

	var idCounter int64 = 1
	for _, p := range curated {
		curatedURLs[p.URL] = true
		on := enabledSet[p.URL]
		presets = append(presets, adguard.PresetStatus{
			FilterPreset: adguard.FilterPreset{
				ID:          p.ID,
				Name:        p.Name,
				Desc:        p.Desc,
				URL:         p.URL,
				Recommended: p.Recommended,
			},
			Installed: on,
			Enabled:   on,
		})
		if on {
			filters = append(filters, adguard.FilterItem{
				ID:      idCounter,
				Enabled: true,
				Name:    p.Name,
				URL:     p.URL,
			})
			idCounter++
		}
	}
	for _, rawURL := range e.cfg.DNS.SmartDNSFilters {
		u := strings.TrimSpace(rawURL)
		if u == "" || curatedURLs[u] {
			continue
		}
		filters = append(filters, adguard.FilterItem{
			ID:      idCounter,
			Enabled: true,
			Name:    u,
			URL:     u,
		})
		idCounter++
	}
	return filters, presets
}

func (e *SmartDNSEngine) Overview(_ context.Context, singboxLinked bool) *OverviewSnapshot {
	e.DrainAuditLog()
	now := e.now()
	st := e.mgr.Status()

	ups := e.cfg.DNS.Upstreams
	if len(ups) == 0 {
		ups = smartdns.DefaultUpstreams()
	}
	mode := smartdns.NormalizeUpstreamMode(e.cfg.DNS.UpstreamMode)
	upInfos := make([]adguard.UpstreamServerInfo, 0, len(ups))
	for _, u := range ups {
		upInfos = append(upInfos, adguard.DescribeUpstream(u))
	}

	filters, presets := e.buildFiltersAndPresets()
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

	return &OverviewSnapshot{
		OverviewSnapshot: adguard.OverviewSnapshot{
			Supported:                    st.Supported,
			Installed:                    st.Installed,
			Enabled:                      e.cfg.DNS.IsEnabled(),
			Running:                      st.Running,
			DNSHealthy:                   st.DNSHealthy,
			WebHealthy:                   false,
			SingBoxLinked:                singboxLinked,
			IsOpenWrt:                    isOpenWrt,
			Version:                      st.Version,
			DNSAddr:                      st.DNSAddr,
			ProtectionEnabled:            !paused,
			ProtectionDisabledDurationMs: disabledMs,
			ProtectionDisabledUntil:      disabledUntil,
			UpstreamMode:                 mode,
			UpstreamModeLabel:            smartDNSUpstreamModeLabel(mode),
			Upstreams:                    upInfos,
			UpstreamPresets:              adguard.CuratedUpstreamPresets(),
			Stats:                        e.stats.Snapshot(now, 0),
			Filters:                      filters,
			TotalRulesCount:              len(filters),
			Presets:                      presets,
			WhitelistedDomains:           wl,
			AutoWhitelistedSubs:          subs,
			AuditManagedCount:            len(extractSmartDNSAuditBlockDomains(e.cfg.CustomRules.Block)),
			Rewrites:                     rewrites,
		},
		BlockAAAA:        shouldSmartDNSBlockAAAA(e.cfg),
		StatsSource:      statsSourceSmartDNS,
		StatsSourceLabel: statsSourceLabelSmartDNS,
		Capabilities:     e.Capabilities(),
	}
}

func (e *SmartDNSEngine) ConfigPreview(ctx context.Context) (*ConfigPreview, error) {
	content, err := e.mgr.EffectiveConfigPreview()
	if err != nil {
		return nil, err
	}
	st := e.Status(ctx)
	summary := fmt.Sprintf("SmartDNS 隔离回环模式 | 监听: %s | 版本: %s | 屏蔽 AAAA: %v | 启用规则集: %d",
		st.DNSAddr, cmp.Or(st.Version, "未检测到"), shouldSmartDNSBlockAAAA(e.cfg), len(e.cfg.DNS.SmartDNSFilters))
	return &ConfigPreview{
		Engine:         constant.DNSEngineSmartDNS,
		Title:          "SmartDNS 生效配置与受管规则预览",
		Path:           e.configFilePath(),
		Content:        content,
		RuntimeSummary: summary,
	}, nil
}
