// 文件职责：实现引擎 3（AdGuard Home 可视版防劫持 DNS）的薄适配包装、凭据接口与脱敏配置摘要预览。
package localdns

import (
	"cmp"
	"context"
	"fmt"
	"os"
	"slices"
	"strings"

	"singctl/internal/adguard"
	"singctl/internal/common/sysinfo"
	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/singbox"
)

const (
	statsSourceAdGuard      = "adguard_api"
	statsSourceLabelAdGuard = "AdGuard Home 逐包 DNS 统计"
)

// AdGuardEngine 薄包装现有 internal/adguard.Manager，100% 保留原有统计、规则与原生管理面板能力。
type AdGuardEngine struct {
	cfg  *config.Config
	deps EngineDeps
	mgr  *adguard.Manager
}

// NewAdGuardEngine 创建 AdGuard Home 可视版防劫持 DNS 引擎适配器。
func NewAdGuardEngine(cfg *config.Config, deps EngineDeps) *AdGuardEngine {
	if cfg == nil {
		cfg = &config.Config{}
	}
	var mgr *adguard.Manager
	if deps.AdGuardManager != nil {
		mgr = deps.AdGuardManager
	} else {
		mgr = adguard.NewManager(cfg, deps.ConfigPath)
		mgr.SetPathsForTest(deps.AdGuardBinPath, deps.AdGuardConfigPath)
		if deps.ReadMemInfo != nil {
			readMem := deps.ReadMemInfo
			mgr.SetReadMemInfoForTest(func() sysinfo.MemInfo {
				mi, err := readMem()
				if err != nil {
					return sysinfo.MemInfo{}
				}
				return mi
			})
		}
	}
	return &AdGuardEngine{
		cfg:  cfg,
		deps: deps,
		mgr:  mgr,
	}
}

func (e *AdGuardEngine) ID() string { return constant.DNSEngineAdGuard }

func (e *AdGuardEngine) Meta() EngineMeta {
	return EngineMeta{
		ID:       constant.DNSEngineAdGuard,
		Name:     "AdGuard Home",
		Tagline:  "功能最全的独立防劫持面板，内置原生查询日志、客户端细粒度策略与全量规则库",
		DiskHint: "~80 MB",
		RAMHint:  "~100 MB",
	}
}

func (e *AdGuardEngine) Capabilities() Capabilities {
	return Capabilities{
		HasNativeWebPanel:  true,
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

func (e *AdGuardEngine) configFilePath() string {
	if p := e.mgr.ConfigFilePath(); p != "" {
		return p
	}
	return cmp.Or(strings.TrimSpace(e.deps.AdGuardConfigPath), constant.AdGuardConfigFile)
}

func (e *AdGuardEngine) IsInstalled() bool {
	if strings.TrimSpace(e.deps.AdGuardBinPath) != "" {
		info, err := os.Stat(e.deps.AdGuardBinPath)
		return err == nil && !info.IsDir()
	}
	return adguard.IsInstalled()
}

// LowMemoryGuardWarning 返回 AdGuard Home 自身的低内存防 OOM 提示（兼容老接口字段）。
func (e *AdGuardEngine) LowMemoryGuardWarning() string {
	return e.mgr.LowMemoryGuardWarning()
}

func (e *AdGuardEngine) Status(_ context.Context) EngineStatus {
	st := e.mgr.Status()
	return EngineStatus{
		Supported:  adguard.IsSupportedPlatform(),
		Installed:  st.Installed,
		Running:    st.Running,
		DNSHealthy: st.DNSHealthy,
		WebHealthy: st.WebHealthy,
		Version:    st.Version,
		DNSAddr:    st.DNSAddr,
		WebAddr:    st.WebAddr,
		WebURL:     st.WebURL,
	}
}

func (e *AdGuardEngine) Overview(ctx context.Context, singboxLinked bool) *OverviewSnapshot {
	base := e.mgr.Overview(ctx, singboxLinked)
	if base == nil {
		base = &adguard.OverviewSnapshot{}
	}
	return &OverviewSnapshot{
		OverviewSnapshot: *base,
		BlockAAAA:        false,
		StatsSource:      statsSourceAdGuard,
		StatsSourceLabel: statsSourceLabelAdGuard,
		Capabilities:     e.Capabilities(),
	}
}

func redactAdGuardYAML(raw string) string {
	var b strings.Builder
	for line := range strings.SplitSeq(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)
		if strings.HasPrefix(lower, "password:") ||
			strings.HasPrefix(lower, "private_key:") ||
			strings.HasPrefix(lower, "certificate_chain:") {
			indentLen := len(line) - len(strings.TrimLeft(line, " \t"))
			key, _, _ := strings.Cut(trimmed, ":")
			b.WriteString(line[:indentLen])
			b.WriteString(key)
			b.WriteString(": \"******\"\n")
			continue
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return strings.TrimRight(b.String(), "\n") + "\n"
}

func (e *AdGuardEngine) ConfigPreview(ctx context.Context) (*ConfigPreview, error) {
	cfgPath := e.configFilePath()
	st := e.Status(ctx)
	var content string
	if raw, err := os.ReadFile(cfgPath); err == nil {
		content = redactAdGuardYAML(string(raw))
	} else if os.IsNotExist(err) {
		content = "# AdGuardHome.yaml 尚未生成（安装并启动 AdGuard Home 后自动创建）\n"
	} else {
		return nil, fmt.Errorf("读取 AdGuardHome.yaml 失败: %w", err)
	}
	summary := fmt.Sprintf("AdGuard Home 独立引擎 | DNS: %s | Web 面板: %s | 版本: %s",
		st.DNSAddr, st.WebURL, cmp.Or(st.Version, "未检测到"))
	return &ConfigPreview{
		Engine:         constant.DNSEngineAdGuard,
		Title:          "AdGuard Home 生效配置摘要（已脱敏）",
		Path:           cfgPath,
		Content:        content,
		RuntimeSummary: summary,
	}, nil
}

func (e *AdGuardEngine) Credentials(_ context.Context) (*CredentialsInfo, error) {
	st := e.mgr.Status()
	return &CredentialsInfo{
		WebURL:   st.WebURL,
		Username: st.Username,
		Password: st.Password,
	}, nil
}

func (e *AdGuardEngine) ResetCredentials(_ context.Context, newUsername string) (*CredentialsInfo, error) {
	user, pass, err := e.mgr.ResetCredentials(newUsername)
	if err != nil {
		return nil, err
	}
	if e.deps.SaveConfig != nil {
		_ = e.deps.SaveConfig(e.cfg)
	}
	st := e.mgr.Status()
	return &CredentialsInfo{
		WebURL:   st.WebURL,
		Username: user,
		Password: pass,
	}, nil
}

func (e *AdGuardEngine) Install(_ context.Context, opts InstallOptions) error {
	_, err := e.mgr.Install(adguard.InstallOptions{
		ConfigPath:     e.deps.ConfigPath,
		Username:       opts.Username,
		NonInteractive: opts.NonInteractive,
		ForceDownload:  opts.ForceDownload,
		ForceLowMemory: opts.ForceLowMemory,
	})
	return err
}

func (e *AdGuardEngine) Start(context.Context) error   { return e.mgr.Start() }
func (e *AdGuardEngine) Stop(context.Context) error    { return e.mgr.Stop() }
func (e *AdGuardEngine) Disable(context.Context) error { return e.mgr.Disable() }
func (e *AdGuardEngine) Restart(context.Context) error { return e.mgr.Restart() }

func (e *AdGuardEngine) Uninstall(_ context.Context, purge bool) error {
	return e.mgr.Uninstall(purge)
}

func (e *AdGuardEngine) EnsureHealthy(context.Context) error {
	return e.mgr.EnsureHealthy()
}

func (e *AdGuardEngine) SetProtection(ctx context.Context, enabled bool, durationMinutes int) error {
	return e.mgr.SetProtection(ctx, enabled, durationMinutes)
}

func (e *AdGuardEngine) ClearCache(ctx context.Context) error {
	return e.mgr.ClearCache(ctx)
}

func (e *AdGuardEngine) ProbeUpstreams(ctx context.Context, domain string) *adguard.ProbeReport {
	return e.mgr.ProbeAllUpstreams(ctx, domain)
}

func (e *AdGuardEngine) SetUpstreams(ctx context.Context, upstreams []string, mode string, resetDefault bool) (*UpstreamUpdateResult, error) {
	if resetDefault {
		upstreams = adguard.DefaultUpstreams()
		mode = "parallel"
	}
	infos, normMode, notes, err := e.mgr.SetDNSUpstreams(ctx, upstreams, mode, e.deps.SkipProbeForTest)
	if err != nil {
		return nil, err
	}
	return &UpstreamUpdateResult{
		Upstreams:         infos,
		UpstreamMode:      normMode,
		UpstreamModeLabel: adguard.UpstreamModeDescription(normMode),
		Notes:             notes,
	}, nil
}

func (e *AdGuardEngine) SetWhitelist(ctx context.Context, domain string, allow bool) error {
	return e.mgr.SetDomainWhitelist(ctx, domain, allow)
}

func (e *AdGuardEngine) AddRewrite(ctx context.Context, domain, answer string) error {
	return e.mgr.AddRewrite(ctx, domain, answer)
}

func (e *AdGuardEngine) DeleteRewrite(ctx context.Context, domain, answer string) error {
	return e.mgr.DeleteRewrite(ctx, domain, answer)
}

func (e *AdGuardEngine) SetFilterState(ctx context.Context, filterURL, name string, enabled bool) error {
	return e.mgr.SetFilterState(ctx, filterURL, name, enabled)
}

func (e *AdGuardEngine) RemoveFilter(ctx context.Context, filterURL string) error {
	return e.mgr.RemoveFilter(ctx, filterURL)
}

func (e *AdGuardEngine) RefreshFilters(ctx context.Context) error {
	return e.mgr.RefreshFilters(ctx)
}

func (e *AdGuardEngine) SyncBlockRules(ctx context.Context, blocks []config.BlockRule) (bool, string, error) {
	return e.mgr.SyncBlockRules(ctx, blocks)
}

func (e *AdGuardEngine) SyncCommonConfig(ctx context.Context) error {
	if len(e.cfg.DNS.Upstreams) > 0 {
		mode := e.cfg.DNS.GetUpstreamMode()
		if mode == config.DNSUpstreamModeFastestIP {
			mode = "fastest_addr"
		}
		_, _, _, _ = e.mgr.SetDNSUpstreams(ctx, e.cfg.DNS.Upstreams, mode, true)
	}
	var subURLs []string
	for _, s := range e.cfg.Subs {
		if strings.TrimSpace(s.URL) != "" {
			subURLs = append(subURLs, s.URL)
		}
	}
	if len(subURLs) > 0 {
		_ = e.mgr.SyncSubscriptionWhitelist(ctx, subURLs)
	}
	for _, dom := range e.cfg.DNS.Whitelist {
		_ = e.mgr.SetDomainWhitelist(ctx, dom, true)
	}
	if len(e.cfg.DNS.Rewrites) > 0 {
		existing := e.mgr.Overview(ctx, false).Rewrites
		for _, rw := range e.cfg.DNS.Rewrites {
			dup := slices.ContainsFunc(existing, func(x adguard.RewriteEntry) bool {
				return strings.EqualFold(x.Domain, rw.Domain) && x.Answer == rw.Answer
			})
			if !dup {
				_ = e.mgr.AddRewrite(ctx, rw.Domain, rw.Answer)
			}
		}
	}
	if len(e.cfg.CustomRules.Block) > 0 {
		_, _, _ = e.mgr.SyncBlockRules(ctx, e.cfg.CustomRules.Block)
	}
	return nil
}

// HarvestCommonConfig 在切出 AdGuard Home 前将当前生效的上游、白名单与重写无损回写至 cfg.DNS。
func (e *AdGuardEngine) HarvestCommonConfig(ctx context.Context) []string {
	var migrated []string
	ov := e.mgr.Overview(ctx, false)
	if ov == nil {
		return nil
	}
	if len(ov.Upstreams) > 0 {
		ups := make([]string, 0, len(ov.Upstreams))
		for _, u := range ov.Upstreams {
			if strings.TrimSpace(u.Address) != "" {
				ups = append(ups, u.Address)
			}
		}
		if len(ups) > 0 {
			e.cfg.DNS.Upstreams = ups
			migrated = append(migrated, fmt.Sprintf("加密上游 (%d 条)", len(ups)))
		}
	}
	if len(ov.WhitelistedDomains) > 0 {
		e.cfg.DNS.Whitelist = slices.Clone(ov.WhitelistedDomains)
		migrated = append(migrated, fmt.Sprintf("域名白名单 (%d 条)", len(ov.WhitelistedDomains)))
	}
	if len(ov.Rewrites) > 0 {
		rws := make([]config.DNSRewriteRule, 0, len(ov.Rewrites))
		for _, r := range ov.Rewrites {
			rule := config.DNSRewriteRule{Domain: r.Domain, Answer: r.Answer}
			if singbox.ValidateDNSRewriteRule(rule) == nil {
				rws = append(rws, rule)
			}
		}
		if len(rws) > 0 {
			e.cfg.DNS.Rewrites = rws
			migrated = append(migrated, fmt.Sprintf("内网解析重写 (%d 条)", len(rws)))
		}
	}
	return migrated
}
