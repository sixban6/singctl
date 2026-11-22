// 文件职责：提供 AdGuard Home Web Control API 客户端、过滤规则库预设以及五路并发 Overview 快照聚合。
package adguard

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"singctl/internal/common/sysinfo"

	"gopkg.in/yaml.v3"
)

var (
	validRewriteDomainRe = regexp.MustCompile(`^(\*\.)?[A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?(\.[A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?)*$`)

	adguardControlHTTPClient = &http.Client{
		Timeout: 4 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        16,
			MaxIdleConnsPerHost: 8,
			IdleConnTimeout:     60 * time.Second,
		},
	}
)

// FilterPreset 描述内置精选的去广告/防追踪规则集预设。
type FilterPreset struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Desc        string `json:"desc"`
	URL         string `json:"url"`
	Recommended bool   `json:"recommended"`
}

// PresetStatus 在 FilterPreset 基础上附加当前安装与启用状态。
type PresetStatus struct {
	FilterPreset
	Installed  bool `json:"installed"`
	Enabled    bool `json:"enabled"`
	RulesCount int  `json:"rulesCount"`
}

// DomainStatItem 表示查询或拦截排行榜单项。
type DomainStatItem struct {
	Domain string `json:"domain"`
	Count  int64  `json:"count"`
}

// ControlStats 汇总 24 小时核心解析与拦截指标。
type ControlStats struct {
	NumDNSQueries       int64            `json:"numDnsQueries"`
	NumBlockedFiltering int64            `json:"numBlockedFiltering"`
	BlockedPercent      float64          `json:"blockedPercent"`
	AvgProcessingMs     float64          `json:"avgProcessingMs"`
	TopBlockedDomains   []DomainStatItem `json:"topBlockedDomains"`
	TopQueriedDomains   []DomainStatItem `json:"topQueriedDomains"`
}

// FilterItem 描述单个过滤规则订阅源的状态。
type FilterItem struct {
	ID          int64  `json:"id"`
	Enabled     bool   `json:"enabled"`
	Name        string `json:"name"`
	URL         string `json:"url"`
	RulesCount  int    `json:"rulesCount"`
	LastUpdated string `json:"lastUpdated,omitempty"`
}

// RewriteEntry 描述一条局域网自定义域名解析重写规则。
type RewriteEntry struct {
	Domain string `json:"domain" yaml:"domain"`
	Answer string `json:"answer" yaml:"answer"`
}

// OverviewSnapshot 汇总客户端控制台展示 AdGuard Home 所需的全部状态与配置。
type OverviewSnapshot struct {
	Supported                    bool                 `json:"supported"`
	Installed                    bool                 `json:"installed"`
	Enabled                      bool                 `json:"enabled"`
	Running                      bool                 `json:"running"`
	DNSHealthy                   bool                 `json:"dnsHealthy"`
	WebHealthy                   bool                 `json:"webHealthy"`
	SingBoxLinked                bool                 `json:"singboxLinked"`
	IsOpenWrt                    bool                 `json:"isOpenWrt"`
	LowMemoryBlocked             bool                 `json:"lowMemoryBlocked,omitempty"`
	LowMemoryWarning             string               `json:"lowMemoryWarning,omitempty"`
	Version                      string               `json:"version"`
	DNSAddr                      string               `json:"dnsAddr"`
	WebAddr                      string               `json:"webAddr"`
	WebURL                       string               `json:"webUrl"`
	Username                     string               `json:"username"`
	HasPassword                  bool                 `json:"hasPassword"`
	ProtectionEnabled            bool                 `json:"protectionEnabled"`
	ProtectionDisabledDurationMs int64                `json:"protectionDisabledDurationMs,omitempty"`
	ProtectionDisabledUntil      string               `json:"protectionDisabledUntil,omitempty"`
	UpstreamLatencyMs            int64                `json:"upstreamLatencyMs,omitempty"`
	UpstreamMode                 string               `json:"upstreamMode"`
	UpstreamModeLabel            string               `json:"upstreamModeLabel"`
	Upstreams                    []UpstreamServerInfo `json:"upstreams"`
	UpstreamPresets              []UpstreamPreset     `json:"upstreamPresets"`
	Stats                        ControlStats         `json:"stats"`
	Filters                      []FilterItem         `json:"filters"`
	TotalRulesCount              int                  `json:"totalRulesCount"`
	Presets                      []PresetStatus       `json:"presets"`
	WhitelistedDomains           []string             `json:"whitelistedDomains"`
	AutoWhitelistedSubs          []string             `json:"autoWhitelistedSubs"`
	AuditManagedCount            int                  `json:"auditManagedCount"`
	Rewrites                     []RewriteEntry       `json:"rewrites"`
}

// CuratedFilterPresets 返回面向家庭网关与软路由精选的低误杀规则库预设列表。
func CuratedFilterPresets() []FilterPreset {
	return []FilterPreset{
		{
			ID:          "adguard-base",
			Name:        "AdGuard DNS 官方基础规则",
			Desc:        "官方综合去广告与防追踪基准规则，极低误杀，首次安装默认开启",
			URL:         "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt",
			Recommended: true,
		},
		{
			ID:          "anti-ad",
			Name:        "Anti-AD 中文增强过滤",
			Desc:        "针对国内智能电视、视频贴片与常见 App 隐私追踪行为深度优化",
			URL:         "https://anti-ad.net/easylist.txt",
			Recommended: true,
		},
		{
			ID:          "hagezi-light",
			Name:        "HaGeZi Light 轻量安全精选",
			Desc:        "小内存软路由友好，覆盖常见恶意域名、钓鱼与核心追踪器",
			URL:         "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/light.txt",
			Recommended: false,
		},
		{
			ID:          "adguard-cname",
			Name:        "AdGuard CNAME 伪装追踪拦截",
			Desc:        "精准识别并阻断伪装成一阶子域名的第三方数据采集追踪器",
			URL:         "https://adguardteam.github.io/HostlistsRegistry/assets/filter_64.txt",
			Recommended: false,
		},
	}
}

func (m *Manager) controlRequest(ctx context.Context, method, apiPath string, reqBody any, out any) (int, error) {
	webAddr := ReadCurrentHTTPAddress(m.aghConfigFile)
	if webAddr == "" {
		return 0, errors.New("AdGuard Home 管理监听地址未就绪")
	}
	user := m.cfg.DNS.GetUsername()
	pass := m.cfg.DNS.GetPassword()
	if pass == "" {
		return 0, errors.New("未找到 AdGuard Home 明文凭据，请点击「重置管理密码」同步凭据")
	}

	var bodyReader io.Reader
	if reqBody != nil {
		b, err := json.Marshal(reqBody)
		if err != nil {
			return 0, err
		}
		bodyReader = bytes.NewReader(b)
	}

	reqCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()

	targetURL := fmt.Sprintf("http://%s%s", webAddr, apiPath)
	req, err := http.NewRequestWithContext(reqCtx, method, targetURL, bodyReader)
	if err != nil {
		return 0, err
	}
	req.SetBasicAuth(user, pass)
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := adguardControlHTTPClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	respBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg := strings.TrimSpace(string(respBytes))
		if msg == "" {
			msg = resp.Status
		}
		return resp.StatusCode, fmt.Errorf("AdGuard API %s 返回 %d: %s", apiPath, resp.StatusCode, msg)
	}
	if out != nil && len(bytes.TrimSpace(respBytes)) > 0 {
		if err := json.Unmarshal(respBytes, out); err != nil {
			return resp.StatusCode, fmt.Errorf("解析 AdGuard API %s 响应失败: %w", apiPath, err)
		}
	}
	return resp.StatusCode, nil
}

// Overview 采集完整的本地 AdGuard Home 状态、24h 统计、过滤规则、白名单与重写规则快照。
func (m *Manager) Overview(ctx context.Context, singboxLinked bool) *OverviewSnapshot {
	st := m.Status()
	autoSubs := m.extractConfiguredSubHosts()
	lowMemWarn := m.LowMemoryGuardWarning()

	snap := &OverviewSnapshot{
		Supported:           IsSupportedPlatform(),
		Installed:           st.Installed,
		Enabled:             m.cfg.DNS.IsEnabled(),
		Running:             st.Running,
		DNSHealthy:          st.DNSHealthy,
		WebHealthy:          st.WebHealthy,
		SingBoxLinked:       singboxLinked,
		IsOpenWrt:           sysinfo.IsOpenWrt(),
		LowMemoryBlocked:    lowMemWarn != "",
		LowMemoryWarning:    lowMemWarn,
		Version:             st.Version,
		DNSAddr:             st.DNSAddr,
		WebAddr:             st.WebAddr,
		WebURL:              st.WebURL,
		Username:            st.Username,
		HasPassword:         st.Password != "",
		ProtectionEnabled:   true,
		UpstreamMode:        "parallel",
		UpstreamModeLabel:   UpstreamModeDescription("parallel"),
		Upstreams:           []UpstreamServerInfo{},
		UpstreamPresets:     CuratedUpstreamPresets(),
		Filters:             []FilterItem{},
		Presets:             buildPresetStatuses(nil),
		WhitelistedDomains:  []string{},
		AutoWhitelistedSubs: autoSubs,
		Rewrites:            []RewriteEntry{},
		Stats: ControlStats{
			TopBlockedDomains: []DomainStatItem{},
			TopQueriedDomains: []DomainStatItem{},
		},
	}

	if !st.Installed {
		return snap
	}

	apiOK := false
	if st.WebHealthy && st.Password != "" {
		type statusPayload struct {
			Version                    string `json:"version"`
			Running                    bool   `json:"running"`
			ProtectionEnabled          bool   `json:"protection_enabled"`
			ProtectionDisabledDuration int64  `json:"protection_disabled_duration"`
			ProtectionDisabledUntil    string `json:"protection_disabled_until"`
		}
		type statsPayload struct {
			NumDNSQueries       int64              `json:"num_dns_queries"`
			NumBlockedFiltering int64              `json:"num_blocked_filtering"`
			AvgProcessingTime   float64            `json:"avg_processing_time"`
			TopBlockedDomains   []map[string]int64 `json:"top_blocked_domains"`
			TopQueriedDomains   []map[string]int64 `json:"top_queried_domains"`
		}
		type filterPayload struct {
			Enabled bool `json:"enabled"`
			Filters []struct {
				ID          int64  `json:"id"`
				Enabled     bool   `json:"enabled"`
				URL         string `json:"url"`
				Name        string `json:"name"`
				RulesCount  int    `json:"rules_count"`
				LastUpdated string `json:"last_updated"`
			} `json:"filters"`
			UserRules []string `json:"user_rules"`
		}
		type dnsInfoPayload struct {
			UpstreamDNS  []string `json:"upstream_dns"`
			UpstreamMode string   `json:"upstream_mode"`
		}

		var (
			statusResp statusPayload
			statusErr  error
			statsResp  statsPayload
			statsErr   error
			filterResp filterPayload
			filterErr  error
			rewrites   []RewriteEntry
			rewriteErr error
			dnsInfo    dnsInfoPayload
			dnsInfoErr error
			wg         sync.WaitGroup
		)

		wg.Add(5)
		go func() {
			defer wg.Done()
			_, statusErr = m.controlRequest(ctx, http.MethodGet, "/control/status", nil, &statusResp)
		}()
		go func() {
			defer wg.Done()
			_, statsErr = m.controlRequest(ctx, http.MethodGet, "/control/stats", nil, &statsResp)
		}()
		go func() {
			defer wg.Done()
			_, filterErr = m.controlRequest(ctx, http.MethodGet, "/control/filtering/status", nil, &filterResp)
		}()
		go func() {
			defer wg.Done()
			_, rewriteErr = m.controlRequest(ctx, http.MethodGet, "/control/rewrite/list", nil, &rewrites)
		}()
		go func() {
			defer wg.Done()
			_, dnsInfoErr = m.controlRequest(ctx, http.MethodGet, "/control/dns_info", nil, &dnsInfo)
		}()
		wg.Wait()

		if statusErr == nil {
			apiOK = true
			if statusResp.Version != "" {
				snap.Version = statusResp.Version
			}
			snap.ProtectionEnabled = statusResp.ProtectionEnabled
			snap.ProtectionDisabledDurationMs = statusResp.ProtectionDisabledDuration
			snap.ProtectionDisabledUntil = statusResp.ProtectionDisabledUntil
		}

		if statsErr == nil {
			snap.Stats.NumDNSQueries = statsResp.NumDNSQueries
			snap.Stats.NumBlockedFiltering = statsResp.NumBlockedFiltering
			if statsResp.NumDNSQueries > 0 {
				pct := (float64(statsResp.NumBlockedFiltering) / float64(statsResp.NumDNSQueries)) * 100
				snap.Stats.BlockedPercent = math.Round(pct*10) / 10
			}
			ms := statsResp.AvgProcessingTime * 1000
			snap.Stats.AvgProcessingMs = math.Round(ms*10) / 10
			snap.Stats.TopBlockedDomains = flattenStatMapSlice(statsResp.TopBlockedDomains, 12)
			snap.Stats.TopQueriedDomains = flattenStatMapSlice(statsResp.TopQueriedDomains, 8)
		}

		if filterErr == nil {
			items := make([]FilterItem, 0, len(filterResp.Filters))
			totalRules := 0
			for _, f := range filterResp.Filters {
				items = append(items, FilterItem{
					ID:          f.ID,
					Enabled:     f.Enabled,
					Name:        f.Name,
					URL:         f.URL,
					RulesCount:  f.RulesCount,
					LastUpdated: f.LastUpdated,
				})
				if f.Enabled {
					totalRules += f.RulesCount
				}
			}
			snap.Filters = items
			snap.TotalRulesCount = totalRules
			snap.Presets = buildPresetStatuses(items)
			wl, auditCnt := parseUserRulesSummary(filterResp.UserRules, autoSubs)
			snap.WhitelistedDomains = wl
			snap.AuditManagedCount = auditCnt
		}

		if rewriteErr == nil && rewrites != nil {
			snap.Rewrites = rewrites
		}

		if dnsInfoErr == nil {
			mode := NormalizeUpstreamMode(dnsInfo.UpstreamMode)
			snap.UpstreamMode = mode
			snap.UpstreamModeLabel = UpstreamModeDescription(mode)
			cleaned := filterNonCommentUpstreams(dnsInfo.UpstreamDNS)
			infos := make([]UpstreamServerInfo, 0, len(cleaned))
			for _, u := range cleaned {
				infos = append(infos, DescribeUpstream(u))
			}
			snap.Upstreams = infos
		}
	}

	if !apiOK {
		m.populateSnapshotFromYAML(snap, autoSubs)
	}
	if len(snap.Upstreams) == 0 {
		list, mode := readUpstreamsFromYAML(m.aghConfigFile)
		if len(list) == 0 {
			list = DefaultUpstreams()
		}
		snap.UpstreamMode = mode
		snap.UpstreamModeLabel = UpstreamModeDescription(mode)
		infos := make([]UpstreamServerInfo, 0, len(list))
		for _, u := range list {
			infos = append(infos, DescribeUpstream(u))
		}
		snap.Upstreams = infos
	}

	return snap
}

func (m *Manager) populateSnapshotFromYAML(snap *OverviewSnapshot, autoSubs []string) {
	raw, err := os.ReadFile(m.aghConfigFile)
	if err != nil {
		return
	}
	var doc struct {
		Filters []struct {
			ID      int64  `yaml:"id"`
			Enabled bool   `yaml:"enabled"`
			URL     string `yaml:"url"`
			Name    string `yaml:"name"`
		} `yaml:"filters"`
		UserRules []string `yaml:"user_rules"`
		Filtering struct {
			ProtectionEnabled bool           `yaml:"protection_enabled"`
			Rewrites          []RewriteEntry `yaml:"rewrites"`
		} `yaml:"filtering"`
	}
	if yaml.Unmarshal(raw, &doc) != nil {
		return
	}
	snap.ProtectionEnabled = doc.Filtering.ProtectionEnabled
	items := make([]FilterItem, 0, len(doc.Filters))
	for _, f := range doc.Filters {
		items = append(items, FilterItem{
			ID:      f.ID,
			Enabled: f.Enabled,
			Name:    f.Name,
			URL:     f.URL,
		})
	}
	snap.Filters = items
	snap.Presets = buildPresetStatuses(items)
	wl, auditCnt := parseUserRulesSummary(doc.UserRules, autoSubs)
	snap.WhitelistedDomains = wl
	snap.AuditManagedCount = auditCnt
	if doc.Filtering.Rewrites != nil {
		snap.Rewrites = doc.Filtering.Rewrites
	}
}

func flattenStatMapSlice(raw []map[string]int64, limit int) []DomainStatItem {
	out := make([]DomainStatItem, 0, min(len(raw), limit))
	for _, m := range raw {
		for k, v := range m {
			domain := strings.TrimSpace(k)
			if domain != "" {
				out = append(out, DomainStatItem{Domain: domain, Count: v})
			}
		}
		if len(out) >= limit {
			break
		}
	}
	return out
}

func buildPresetStatuses(installed []FilterItem) []PresetStatus {
	presets := CuratedFilterPresets()
	byURL := make(map[string]FilterItem, len(installed))
	for _, f := range installed {
		byURL[strings.TrimSpace(f.URL)] = f
	}
	out := make([]PresetStatus, 0, len(presets))
	for _, p := range presets {
		ps := PresetStatus{FilterPreset: p}
		if hit, ok := byURL[p.URL]; ok {
			ps.Installed = true
			ps.Enabled = hit.Enabled
			ps.RulesCount = hit.RulesCount
		}
		out = append(out, ps)
	}
	return out
}

func (m *Manager) extractConfiguredSubHosts() []string {
	if m.cfg == nil {
		return []string{}
	}
	seen := make(map[string]struct{})
	var hosts []string
	for _, s := range m.cfg.Subs {
		u, err := url.Parse(strings.TrimSpace(s.URL))
		if err != nil || u.Host == "" {
			continue
		}
		h := strings.ToLower(strings.TrimSpace(u.Hostname()))
		if h == "" || net.ParseIP(h) != nil || h == "localhost" {
			continue
		}
		if _, ok := seen[h]; !ok {
			seen[h] = struct{}{}
			hosts = append(hosts, h)
		}
	}
	if hosts == nil {
		return []string{}
	}
	return hosts
}

func parseUserRulesSummary(rules []string, autoSubHosts []string) (whitelisted []string, auditCount int) {
	autoSet := make(map[string]struct{}, len(autoSubHosts))
	for _, h := range autoSubHosts {
		autoSet[strings.ToLower(strings.TrimSpace(h))] = struct{}{}
	}

	seenWL := make(map[string]struct{})
	inManaged := false
	for _, line := range rules {
		trimmed := strings.TrimSpace(line)
		if trimmed == managedBlockStartMarker {
			inManaged = true
			continue
		}
		if trimmed == managedBlockEndMarker {
			inManaged = false
			continue
		}
		if inManaged {
			if trimmed != "" && !strings.HasPrefix(trimmed, "!") {
				auditCount++
			}
			continue
		}
		if domain := parseWhitelistDomainRule(trimmed); domain != "" {
			if _, isAuto := autoSet[domain]; isAuto {
				continue
			}
			if _, dup := seenWL[domain]; !dup {
				seenWL[domain] = struct{}{}
				whitelisted = append(whitelisted, domain)
			}
		}
	}
	if whitelisted == nil {
		whitelisted = []string{}
	}
	return whitelisted, auditCount
}

func parseWhitelistDomainRule(rule string) string {
	if !strings.HasPrefix(rule, "@@||") {
		return ""
	}
	rest := strings.TrimPrefix(rule, "@@||")
	if idx := strings.IndexAny(rest, "^$"); idx >= 0 {
		rest = rest[:idx]
	}
	return normalizeAdGuardTarget(rest)
}
