// 文件职责：实现 SmartDNS 引擎的生命周期托管、上游探测与写操作控制面（上游、白名单、重写、规则集与审计阻断同步）。
package localdns

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"singctl/internal/adguard"
	"singctl/internal/config"
	"singctl/internal/platform/servicemgr"
	"singctl/internal/smartdns"
)

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
	var duplicates []string
	var notes []string
	for _, raw := range rawUpstreams {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		lower := strings.ToLower(s)
		if strings.HasPrefix(lower, "https://") || strings.HasPrefix(lower, "tls://") || strings.HasPrefix(lower, "quic://") || strings.HasPrefix(lower, "h3://") {
			if norm, _, note, err := adguard.NormalizeAndValidateUpstream(s); err == nil {
				s = norm
				if note != "" {
					notes = append(notes, note)
				}
			}
		} else if strings.HasPrefix(lower, "udp://") {
			hostPart := strings.TrimPrefix(lower, "udp://")
			if ip := net.ParseIP(strings.TrimSpace(hostPart)); ip != nil && ip.To4() != nil {
				s = "udp://" + ip.To4().String() + ":53"
			}
		}
		if _, err := smartdns.FormatUpstreamDirective(s); err != nil {
			return nil, err
		}
		key := strings.ToLower(s)
		if _, dup := seen[key]; dup {
			duplicates = append(duplicates, s)
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
	if err := adguard.ValidatePureIPFallbackInvariant(cleaned); err != nil {
		return nil, err
	}

	prevSet := make(map[string]struct{})
	prevList := e.cfg.DNS.Upstreams
	if len(prevList) == 0 {
		prevList = smartdns.DefaultUpstreams()
	}
	prevMode := smartdns.NormalizeUpstreamMode(e.cfg.DNS.UpstreamMode)
	for _, prev := range prevList {
		prevSet[strings.ToLower(strings.TrimSpace(prev))] = struct{}{}
	}
	if !e.deps.SkipProbeForTest && !resetDefault && len(duplicates) > 0 && mode == prevMode && adguard.SameUpstreamSet(cleaned, prevList) {
		return nil, fmt.Errorf("上游 %s 已在当前列表中，无需重复添加", strings.Join(duplicates, "、"))
	}
	if len(duplicates) > 0 {
		notes = append(notes, fmt.Sprintf("已自动跳过重复上游（%s）", strings.Join(duplicates, "、")))
	}

	if !e.deps.SkipProbeForTest || e.deps.LookupIPFunc != nil || e.deps.BypassFirewallFunc != nil {
		bypassIPs := adguard.ResolveUpstreamBypassIPs(ctx, cleaned, e.deps.LookupIPFunc)
		if e.deps.BypassFirewallFunc != nil {
			e.deps.BypassFirewallFunc(bypassIPs)
		} else {
			adguard.EnsureRuntimeFirewallBypass(bypassIPs)
		}
	}

	if !e.deps.SkipProbeForTest {
		probeTargets := make([]string, 0, len(cleaned))
		for _, addr := range cleaned {
			lower := strings.ToLower(addr)
			if strings.HasPrefix(lower, "https://") || strings.HasPrefix(lower, "tls://") || strings.HasPrefix(lower, "udp://") {
				probeTargets = append(probeTargets, addr)
			} else if _, existed := prevSet[lower]; !existed {
				notes = append(notes, fmt.Sprintf("%s 已交由 SmartDNS 接管（跳过直连探测）", addr))
			}
		}

		if len(probeTargets) > 0 {
			probeList := e.deps.ProbeUpstreamListFunc
			if probeList == nil {
				probeList = adguard.ProbeUpstreamList
			}
			items := probeList(ctx, probeTargets, "qq.com", 2800*time.Millisecond)
			anyHealthy := false
			var firstErr string
			for _, it := range items {
				key := strings.ToLower(strings.TrimSpace(it.Address))
				if _, existed := prevSet[key]; !existed && len(prevSet) > 0 && !it.Healthy {
					return nil, fmt.Errorf("新增上游 %s 探测失败，已拦截添加：%s", it.Address, cmp.Or(it.Error, "连接超时"))
				}
				if it.Healthy {
					anyHealthy = true
				} else if firstErr == "" && it.Error != "" {
					firstErr = fmt.Sprintf("%s (%s)", it.Address, it.Error)
				}
			}
			if !anyHealthy {
				return nil, fmt.Errorf("所选加密上游均无法完成解析验证，已拦截保存以防断网：%s", cmp.Or(firstErr, "连接超时"))
			}
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
	cleanURL, err := smartdns.ValidateFilterURL(smartdns.MigrateLegacyFilterURL(filterURL))
	if err != nil {
		return err
	}
	updated := slices.DeleteFunc(slices.Clone(e.cfg.DNS.SmartDNSFilters), func(u string) bool {
		return smartdns.MigrateLegacyFilterURL(u) == cleanURL
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
