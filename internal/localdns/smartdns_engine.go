// 文件职责：实现引擎 2（SmartDNS 极速版防劫持 DNS）的配置编译、规则同步、内存盘逐包审计统计与服务托管适配。
package localdns

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"singctl/internal/adguard"
	"singctl/internal/common/sysinfo"
	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/platform/servicemgr"
	"singctl/internal/singbox"
	"singctl/internal/smartdns"
)

const (
	statsSourceSmartDNS      = "smartdns_audit"
	statsSourceLabelSmartDNS = "SmartDNS 内存盘逐包审计"
)

// SmartDNSEngine 封装 internal/smartdns.Manager，实现统一三引擎契约与 24h 内存盘审计统计。
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

	subs := singbox.ExtractSubscriptionDomains(e.cfg)
	wl := make([]string, 0, len(e.cfg.DNS.Whitelist)+len(subs))
	seenWL := make(map[string]struct{}, len(e.cfg.DNS.Whitelist)+len(subs))
	for _, raw := range append(slices.Clone(e.cfg.DNS.Whitelist), subs...) {
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
		BlockAAAA:           e.cfg.DNS.BlockAAAA,
		ProtectionPaused:    e.cfg.DNS.IsAdblockPaused(now),
		MirrorURL:           e.cfg.GitHub.MirrorURL,
		IsLowMemory:         e.cfg.EffectiveLowMemory(totalRAM),
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
		HasBlockAAAA:       true,
		CanClearCache:      true,
		CanUninstall:       true,
	}
}

func (e *SmartDNSEngine) IsInstalled() bool {
	info, err := os.Stat(e.binPath())
	return err == nil && !info.IsDir()
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
	for _, entry := range entries {
		e.stats.Record(entry.Timestamp, entry.Domain, entry.Blocked, entry.LatencyMs)
	}
	return len(entries)
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
		BlockAAAA:        e.cfg.DNS.BlockAAAA,
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
		st.DNSAddr, cmp.Or(st.Version, "未检测到"), e.cfg.DNS.BlockAAAA, len(e.cfg.DNS.SmartDNSFilters))
	return &ConfigPreview{
		Engine:         constant.DNSEngineSmartDNS,
		Title:          "SmartDNS 生效配置与受管规则预览",
		Path:           e.configFilePath(),
		Content:        content,
		RuntimeSummary: summary,
	}, nil
}

func (e *SmartDNSEngine) Install(ctx context.Context, opts InstallOptions) error {
	_, err := e.mgr.Install(ctx, smartdns.InstallOptions{
		Config:         e.buildConfigInput(),
		ForceDownload:  opts.ForceDownload,
		ForceLowMemory: opts.ForceLowMemory,
		SkipWaitReady:  opts.SkipWaitReady,
	})
	return err
}

func (e *SmartDNSEngine) Start(ctx context.Context) error {
	if err := e.mgr.ApplyConfig(ctx, e.buildConfigInput()); err != nil {
		return err
	}
	return e.mgr.Start()
}

func (e *SmartDNSEngine) Stop(context.Context) error { return e.mgr.Stop() }

func (e *SmartDNSEngine) Disable(ctx context.Context) error {
	_ = e.mgr.Stop()
	svcMgr := e.deps.ServiceMgr
	if svcMgr == nil {
		host := servicemgr.DetectHost()
		switch host.Kind {
		case servicemgr.InitProcd:
			svcMgr = servicemgr.NewProcd(nil, "")
		case servicemgr.InitSystemd:
			svcMgr = servicemgr.NewSystemd(nil)
		default:
			svcMgr = servicemgr.NewNoop()
		}
	}
	return svcMgr.Disable(ctx, e.serviceName())
}

func (e *SmartDNSEngine) Restart(ctx context.Context) error {
	if err := e.mgr.ApplyConfig(ctx, e.buildConfigInput()); err != nil {
		return err
	}
	return e.mgr.Restart()
}

func (e *SmartDNSEngine) Uninstall(ctx context.Context, _ bool) error {
	return e.mgr.Uninstall(ctx)
}

func (e *SmartDNSEngine) EnsureHealthy(context.Context) error {
	return e.mgr.EnsureHealthy()
}

func (e *SmartDNSEngine) SetProtection(ctx context.Context, enabled bool, durationMinutes int) error {
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
	return e.mgr.ApplyConfig(ctx, e.buildConfigInput())
}

func (e *SmartDNSEngine) ClearCache(context.Context) error {
	return e.mgr.ClearCache()
}

func (e *SmartDNSEngine) ProbeUpstreams(ctx context.Context, domain string) *adguard.ProbeReport {
	targetDomain := cmp.Or(strings.TrimSpace(domain), "qq.com")
	dnsAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(e.cfg.DNS.GetDNSPort()))
	upstreams := e.cfg.DNS.Upstreams
	if len(upstreams) == 0 {
		upstreams = smartdns.DefaultUpstreams()
	}
	mode := smartdns.NormalizeUpstreamMode(e.cfg.DNS.UpstreamMode)

	report := &adguard.ProbeReport{
		DNSAddr:           dnsAddr,
		Domain:            targetDomain,
		UpstreamMode:      mode,
		UpstreamModeLabel: smartDNSUpstreamModeLabel(mode),
		Upstreams:         []adguard.UpstreamProbeItem{},
	}

	probeDNS := e.deps.ProbeDNSFunc
	if probeDNS == nil {
		probeDNS = smartdns.ProbeDNS
	}
	probeRes := e.deps.ProbeResolutionFunc
	if probeRes == nil {
		probeRes = adguard.ProbeUpstreamResolution
	}
	probeList := e.deps.ProbeUpstreamListFunc
	if probeList == nil {
		probeList = adguard.ProbeUpstreamList
	}

	var (
		wg        sync.WaitGroup
		localErr  error
		localIPs  []string
		localCost time.Duration
		items     []adguard.UpstreamProbeItem
	)
	wg.Go(func() {
		if err := probeDNS(dnsAddr, 1200*time.Millisecond); err != nil {
			localErr = fmt.Errorf("本地 SmartDNS (%s) 未响应: %v", dnsAddr, err)
			return
		}
		localIPs, localCost, localErr = probeRes(dnsAddr, targetDomain, 3500*time.Millisecond)
	})
	wg.Go(func() {
		items = probeList(ctx, upstreams, targetDomain, 3200*time.Millisecond)
	})
	wg.Wait()

	bestIdx := -1
	for i := range items {
		if items[i].Healthy && (bestIdx == -1 || items[i].LatencyMs < items[bestIdx].LatencyMs) {
			bestIdx = i
		}
	}
	if bestIdx >= 0 {
		items[bestIdx].Fastest = true
		report.FastestUpstream = items[bestIdx].Address
		report.FastestName = items[bestIdx].Name
		report.FastestLatencyMs = items[bestIdx].LatencyMs
	}
	report.Upstreams = items

	if localErr != nil || len(localIPs) == 0 {
		report.Healthy = false
		if localErr != nil {
			report.Error = localErr.Error()
		} else {
			report.Error = "本地 SmartDNS 未返回有效解析记录"
		}
		return report
	}
	report.Healthy = true
	report.Resolved = localIPs[0]
	report.LatencyMs = max(int64(1), localCost.Milliseconds())
	return report
}

func (e *SmartDNSEngine) SetUpstreams(ctx context.Context, rawUpstreams []string, rawMode string, resetDefault bool) (*UpstreamUpdateResult, error) {
	if resetDefault {
		rawUpstreams = smartdns.DefaultUpstreams()
		rawMode = config.DNSUpstreamModeFastestIP
	}
	mode := smartdns.NormalizeUpstreamMode(rawMode)
	if len(rawUpstreams) == 0 {
		return nil, errors.New("至少需要保留 1 条加密上游 DNS 服务器")
	}

	seen := make(map[string]struct{}, len(rawUpstreams))
	cleaned := make([]string, 0, len(rawUpstreams))
	var notes []string
	for _, raw := range rawUpstreams {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		lower := strings.ToLower(s)
		if strings.HasPrefix(lower, "https://") || strings.HasPrefix(lower, "tls://") {
			if norm, _, note, err := adguard.NormalizeAndValidateUpstream(s); err == nil {
				s = norm
				if note != "" {
					notes = append(notes, note)
				}
			}
		}
		if _, err := smartdns.FormatUpstreamDirective(s); err != nil {
			return nil, err
		}
		key := strings.ToLower(s)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		cleaned = append(cleaned, s)
	}
	if len(cleaned) == 0 {
		return nil, errors.New("至少需要保留 1 条有效的加密上游 DNS 服务器")
	}
	if len(cleaned) > 12 {
		return nil, errors.New("上游 DNS 服务器数量请勿超过 12 条")
	}

	if !e.deps.SkipProbeForTest {
		probeList := e.deps.ProbeUpstreamListFunc
		if probeList == nil {
			probeList = adguard.ProbeUpstreamList
		}
		items := probeList(ctx, cleaned, "qq.com", 2800*time.Millisecond)
		anyHealthy := false
		var firstErr string
		for _, it := range items {
			if it.Healthy {
				anyHealthy = true
				break
			}
			if firstErr == "" && it.Error != "" {
				firstErr = fmt.Sprintf("%s (%s)", it.Address, it.Error)
			}
		}
		if !anyHealthy {
			return nil, fmt.Errorf("所选加密上游均无法完成解析验证，已拦截保存以防断网：%s", cmp.Or(firstErr, "连接超时"))
		}
	}

	e.cfg.DNS.Upstreams = cleaned
	e.cfg.DNS.UpstreamMode = mode
	if err := e.saveConfig(); err != nil {
		return nil, err
	}
	if err := e.mgr.ApplyConfig(ctx, e.buildConfigInput()); err != nil {
		return nil, err
	}

	infos := make([]adguard.UpstreamServerInfo, 0, len(cleaned))
	for _, u := range cleaned {
		infos = append(infos, adguard.DescribeUpstream(u))
	}
	return &UpstreamUpdateResult{
		Upstreams:         infos,
		UpstreamMode:      mode,
		UpstreamModeLabel: smartDNSUpstreamModeLabel(mode),
		Notes:             notes,
	}, nil
}

func (e *SmartDNSEngine) SetWhitelist(ctx context.Context, rawDomain string, allow bool) error {
	dom, err := smartdns.ValidateDomain(strings.TrimPrefix(strings.TrimSpace(rawDomain), "*."))
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
	return e.mgr.ApplyConfig(ctx, e.buildConfigInput())
}

func (e *SmartDNSEngine) AddRewrite(ctx context.Context, domain, answer string) error {
	dom, err := smartdns.ValidateDomain(strings.TrimPrefix(strings.TrimSpace(domain), "*."))
	if err != nil {
		return err
	}
	ans, err := smartdns.ValidateRewriteAnswer(answer)
	if err != nil {
		return err
	}
	rule := config.DNSRewriteRule{Domain: dom, Answer: ans}
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
	return e.mgr.ApplyConfig(ctx, e.buildConfigInput())
}

func (e *SmartDNSEngine) DeleteRewrite(ctx context.Context, domain, answer string) error {
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
	return e.mgr.ApplyConfig(ctx, e.buildConfigInput())
}

func (e *SmartDNSEngine) SetFilterState(ctx context.Context, filterURL, _ string, enabled bool) error {
	cleanURL, err := smartdns.ValidateFilterURL(filterURL)
	if err != nil {
		return err
	}
	updated := slices.DeleteFunc(slices.Clone(e.cfg.DNS.SmartDNSFilters), func(u string) bool {
		return strings.TrimSpace(u) == cleanURL
	})
	if enabled {
		updated = append(updated, cleanURL)
	}
	e.cfg.DNS.SmartDNSFilters = updated
	if err := e.saveConfig(); err != nil {
		return err
	}
	return e.mgr.ApplyConfig(ctx, e.buildConfigInput())
}

func (e *SmartDNSEngine) RemoveFilter(ctx context.Context, filterURL string) error {
	return e.SetFilterState(ctx, filterURL, "", false)
}

func (e *SmartDNSEngine) RefreshFilters(ctx context.Context) error {
	return e.mgr.ApplyConfig(ctx, e.buildConfigInput())
}

func (e *SmartDNSEngine) SetBlockAAAA(ctx context.Context, enabled bool) error {
	e.cfg.DNS.BlockAAAA = enabled
	if err := e.saveConfig(); err != nil {
		return err
	}
	return e.mgr.ApplyConfig(ctx, e.buildConfigInput())
}

func (e *SmartDNSEngine) SyncBlockRules(ctx context.Context, blocks []config.BlockRule) (bool, string, error) {
	if !e.IsInstalled() {
		return false, "not_installed", nil
	}
	in := e.buildConfigInput()
	in.AuditBlockedDomains = extractSmartDNSAuditBlockDomains(blocks)
	if err := e.mgr.ApplyConfig(ctx, in); err != nil {
		return false, "smartdns_error", err
	}
	return true, "smartdns_rules", nil
}

func (e *SmartDNSEngine) SyncCommonConfig(ctx context.Context) error {
	return e.mgr.ApplyConfig(ctx, e.buildConfigInput())
}
