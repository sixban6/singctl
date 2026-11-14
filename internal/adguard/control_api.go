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
	"slices"
	"strings"
	"time"

	"singctl/internal/util/netinfo"

	"gopkg.in/yaml.v3"
)

var validRewriteDomainRe = regexp.MustCompile(`^(\*\.)?[A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?(\.[A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?)*$`)

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
	Supported                    bool           `json:"supported"`
	Installed                    bool           `json:"installed"`
	Enabled                      bool           `json:"enabled"`
	Running                      bool           `json:"running"`
	DNSHealthy                   bool           `json:"dnsHealthy"`
	WebHealthy                   bool           `json:"webHealthy"`
	SingBoxLinked                bool           `json:"singboxLinked"`
	IsOpenWrt                    bool           `json:"isOpenWrt"`
	Version                      string         `json:"version"`
	DNSAddr                      string         `json:"dnsAddr"`
	WebAddr                      string         `json:"webAddr"`
	WebURL                       string         `json:"webUrl"`
	Username                     string         `json:"username"`
	HasPassword                  bool           `json:"hasPassword"`
	ProtectionEnabled            bool           `json:"protectionEnabled"`
	ProtectionDisabledDurationMs int64          `json:"protectionDisabledDurationMs,omitempty"`
	ProtectionDisabledUntil      string         `json:"protectionDisabledUntil,omitempty"`
	UpstreamLatencyMs            int64          `json:"upstreamLatencyMs,omitempty"`
	Stats                        ControlStats   `json:"stats"`
	Filters                      []FilterItem   `json:"filters"`
	TotalRulesCount              int            `json:"totalRulesCount"`
	Presets                      []PresetStatus `json:"presets"`
	WhitelistedDomains           []string       `json:"whitelistedDomains"`
	AutoWhitelistedSubs          []string       `json:"autoWhitelistedSubs"`
	AuditManagedCount            int            `json:"auditManagedCount"`
	Rewrites                     []RewriteEntry `json:"rewrites"`
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

	client := &http.Client{Timeout: 4 * time.Second}
	resp, err := client.Do(req)
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

	snap := &OverviewSnapshot{
		Supported:           IsSupportedPlatform(),
		Installed:           st.Installed,
		Enabled:             m.cfg.DNS.IsEnabled(),
		Running:             st.Running,
		DNSHealthy:          st.DNSHealthy,
		WebHealthy:          st.WebHealthy,
		SingBoxLinked:       singboxLinked,
		IsOpenWrt:           netinfo.IsOpenWrt(),
		Version:             st.Version,
		DNSAddr:             st.DNSAddr,
		WebAddr:             st.WebAddr,
		WebURL:              st.WebURL,
		Username:            st.Username,
		HasPassword:         st.Password != "",
		ProtectionEnabled:   true,
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

	// 若 Web Control API 在线且拥有凭据，优先读取实时运行态数据
	apiOK := false
	if st.WebHealthy && st.Password != "" {
		var statusResp struct {
			Version                    string `json:"version"`
			Running                    bool   `json:"running"`
			ProtectionEnabled          bool   `json:"protection_enabled"`
			ProtectionDisabledDuration int64  `json:"protection_disabled_duration"`
			ProtectionDisabledUntil    string `json:"protection_disabled_until"`
		}
		if _, err := m.controlRequest(ctx, http.MethodGet, "/control/status", nil, &statusResp); err == nil {
			apiOK = true
			if statusResp.Version != "" {
				snap.Version = statusResp.Version
			}
			snap.ProtectionEnabled = statusResp.ProtectionEnabled
			snap.ProtectionDisabledDurationMs = statusResp.ProtectionDisabledDuration
			snap.ProtectionDisabledUntil = statusResp.ProtectionDisabledUntil
		}

		var statsResp struct {
			NumDNSQueries       int64              `json:"num_dns_queries"`
			NumBlockedFiltering int64              `json:"num_blocked_filtering"`
			AvgProcessingTime   float64            `json:"avg_processing_time"`
			TopBlockedDomains   []map[string]int64 `json:"top_blocked_domains"`
			TopQueriedDomains   []map[string]int64 `json:"top_queried_domains"`
		}
		if _, err := m.controlRequest(ctx, http.MethodGet, "/control/stats", nil, &statsResp); err == nil {
			snap.Stats.NumDNSQueries = statsResp.NumDNSQueries
			snap.Stats.NumBlockedFiltering = statsResp.NumBlockedFiltering
			if statsResp.NumDNSQueries > 0 {
				pct := (float64(statsResp.NumBlockedFiltering) / float64(statsResp.NumDNSQueries)) * 100
				snap.Stats.BlockedPercent = math.Round(pct*10) / 10
			}
			// AdGuard Home avg_processing_time 单位为秒 (例如 0.0124s = 12.4ms)
			ms := statsResp.AvgProcessingTime * 1000
			snap.Stats.AvgProcessingMs = math.Round(ms*10) / 10
			snap.Stats.TopBlockedDomains = flattenStatMapSlice(statsResp.TopBlockedDomains, 12)
			snap.Stats.TopQueriedDomains = flattenStatMapSlice(statsResp.TopQueriedDomains, 8)
		}

		var filterResp struct {
			Enabled   bool `json:"enabled"`
			Filters   []struct {
				ID          int64  `json:"id"`
				Enabled     bool   `json:"enabled"`
				URL         string `json:"url"`
				Name        string `json:"name"`
				RulesCount  int    `json:"rules_count"`
				LastUpdated string `json:"last_updated"`
			} `json:"filters"`
			UserRules []string `json:"user_rules"`
		}
		if _, err := m.controlRequest(ctx, http.MethodGet, "/control/filtering/status", nil, &filterResp); err == nil {
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

		var rewrites []RewriteEntry
		if _, err := m.controlRequest(ctx, http.MethodGet, "/control/rewrite/list", nil, &rewrites); err == nil && rewrites != nil {
			snap.Rewrites = rewrites
		}
	}

	// 若服务未运行或 API 暂不可达，从磁盘 AdGuardHome.yaml 回退读取静态规则/过滤器/重写列表
	if !apiOK {
		m.populateSnapshotFromYAML(snap, autoSubs)
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

// SetProtection 切换 AdGuard Home 的广告过滤保护开关（支持倒计时自动恢复，如暂停 5/30/60 分钟）。
// 注意：该操作仅暂停过滤规则，绝不停止 127.0.0.1:5353 加密 DoH 解析引擎，网关全程零断网。
func (m *Manager) SetProtection(ctx context.Context, enabled bool, durationMinutes int) error {
	payload := map[string]any{
		"enabled": enabled,
	}
	if !enabled && durationMinutes > 0 {
		payload["duration"] = int64(durationMinutes) * 60 * 1000
	}
	status, err := m.controlRequest(ctx, http.MethodPost, "/control/protection", payload, nil)
	if err == nil {
		return nil
	}
	// 兼容旧版 AdGuard Home 无 /control/protection 端点时回退 /control/dns_config
	if status == http.StatusNotFound {
		_, fbErr := m.controlRequest(ctx, http.MethodPost, "/control/dns_config", map[string]any{
			"protection_enabled": enabled,
		}, nil)
		return fbErr
	}
	return err
}

// ClearCache 一键清空 AdGuard Home 本地 DNS 内存缓存。
func (m *Manager) ClearCache(ctx context.Context) error {
	_, err := m.controlRequest(ctx, http.MethodPost, "/control/cache_clear", nil, nil)
	return err
}

// SetDomainWhitelist 将指定域名加入或移出 AdGuard Home 高优放行白名单 (@@||domain^$important)。
func (m *Manager) SetDomainWhitelist(ctx context.Context, rawDomain string, allow bool) error {
	domain := normalizeAdGuardTarget(rawDomain)
	if domain == "" || !validRewriteDomainRe.MatchString(domain) {
		return errors.New("请输入合法的域名（如 example.com）")
	}
	targetRule := fmt.Sprintf("@@||%s^$important", domain)

	// 优先走热 API
	var filterResp struct {
		UserRules []string `json:"user_rules"`
	}
	if _, err := m.controlRequest(ctx, http.MethodGet, "/control/filtering/status", nil, &filterResp); err == nil {
		updated := updateWhitelistInRules(filterResp.UserRules, domain, targetRule, allow)
		_, setErr := m.controlRequest(ctx, http.MethodPost, "/control/filtering/set_rules", map[string]any{
			"rules": updated,
		}, nil)
		return setErr
	}

	// 离线回退修改 AdGuardHome.yaml
	return m.mutateYAMLUserRules(func(existing []string) []string {
		return updateWhitelistInRules(existing, domain, targetRule, allow)
	})
}

func updateWhitelistInRules(existing []string, domain, targetRule string, allow bool) []string {
	out := make([]string, 0, len(existing)+1)
	found := false
	for _, line := range existing {
		if parseWhitelistDomainRule(strings.TrimSpace(line)) == domain {
			if allow && !found {
				out = append(out, targetRule)
				found = true
			}
			continue
		}
		out = append(out, line)
	}
	if allow && !found {
		// 插在受管黑名单区块之前，保持可读性
		insertIdx := slices.IndexFunc(out, func(s string) bool {
			return strings.TrimSpace(s) == managedBlockStartMarker
		})
		if insertIdx >= 0 {
			out = slices.Insert(out, insertIdx, targetRule)
		} else {
			out = append(out, targetRule)
		}
	}
	return out
}

// SyncSubscriptionWhitelist 确保 singctl.yaml 中最新的机场/自建订阅域名全部位于 AdGuard 白名单中，防止规则误杀订阅拉取。
func (m *Manager) SyncSubscriptionWhitelist(ctx context.Context, subURLs []string) error {
	if !m.isBinaryPresent() {
		if _, err := os.Stat(m.aghConfigFile); os.IsNotExist(err) {
			return nil
		}
	}
	subRules := extractSubWhitelistRules(subURLs)
	if len(subRules) == 0 {
		return nil
	}

	mergeFn := func(existing []string) []string {
		existingSet := make(map[string]struct{}, len(existing))
		for _, line := range existing {
			existingSet[strings.TrimSpace(line)] = struct{}{}
		}
		out := slices.Clone(existing)
		for _, r := range subRules {
			if _, ok := existingSet[r]; !ok {
				out = slices.Insert(out, 0, r)
			}
		}
		return out
	}

	var filterResp struct {
		UserRules []string `json:"user_rules"`
	}
	if _, err := m.controlRequest(ctx, http.MethodGet, "/control/filtering/status", nil, &filterResp); err == nil {
		merged := mergeFn(filterResp.UserRules)
		if slices.Equal(merged, filterResp.UserRules) {
			return nil
		}
		_, setErr := m.controlRequest(ctx, http.MethodPost, "/control/filtering/set_rules", map[string]any{
			"rules": merged,
		}, nil)
		return setErr
	}
	return m.mutateYAMLUserRules(mergeFn)
}

func (m *Manager) mutateYAMLUserRules(fn func([]string) []string) error {
	raw, err := os.ReadFile(m.aghConfigFile)
	if err != nil {
		return err
	}
	var root yaml.Node
	if err := yaml.Unmarshal(raw, &root); err != nil {
		return err
	}
	if len(root.Content) == 0 || root.Content[0].Kind != yaml.MappingNode {
		return errors.New("invalid AdGuardHome.yaml")
	}
	doc := root.Content[0]
	var existing []string
	for i := 0; i+1 < len(doc.Content); i += 2 {
		if doc.Content[i].Value == "user_rules" && doc.Content[i+1].Kind == yaml.SequenceNode {
			for _, item := range doc.Content[i+1].Content {
				existing = append(existing, item.Value)
			}
			break
		}
	}
	updated := fn(existing)
	if slices.Equal(existing, updated) {
		return nil
	}
	setYAMLStringSlice(doc, "user_rules", updated)
	out, err := yaml.Marshal(&root)
	if err != nil {
		return err
	}
	return WriteConfigAtomically(m.aghConfigFile, out)
}

// AddRewrite 新增局域网自定义 DNS 重写映射（如 nas.lan -> 192.168.1.10）。
func (m *Manager) AddRewrite(ctx context.Context, domain, answer string) error {
	d := strings.ToLower(strings.TrimSpace(domain))
	a := strings.TrimSpace(answer)
	if d == "" || !validRewriteDomainRe.MatchString(d) {
		return errors.New("域名格式不合法（支持如 nas.lan 或 *.home）")
	}
	if a == "" || strings.ContainsAny(a, " \t\r\n") {
		return errors.New("解析目标不能为空（填写内网 IP、CNAME 域名或 A/AAAA）")
	}
	_, err := m.controlRequest(ctx, http.MethodPost, "/control/rewrite/add", RewriteEntry{
		Domain: d,
		Answer: a,
	}, nil)
	return err
}

// DeleteRewrite 删除指定的 DNS 重写映射。
func (m *Manager) DeleteRewrite(ctx context.Context, domain, answer string) error {
	d := strings.TrimSpace(domain)
	a := strings.TrimSpace(answer)
	if d == "" || a == "" {
		return errors.New("域名与目标记录不能为空")
	}
	_, err := m.controlRequest(ctx, http.MethodPost, "/control/rewrite/delete", RewriteEntry{
		Domain: d,
		Answer: a,
	}, nil)
	return err
}

func validateFilterURL(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	u, err := url.Parse(trimmed)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return "", errors.New("规则订阅地址必须为有效的 http:// 或 https:// URL")
	}
	return trimmed, nil
}

// SetFilterState 启用、禁用或首次添加去广告过滤规则源。
func (m *Manager) SetFilterState(ctx context.Context, rawURL, name string, enabled bool) error {
	cleanURL, err := validateFilterURL(rawURL)
	if err != nil {
		return err
	}
	cleanName := strings.TrimSpace(name)
	if cleanName == "" {
		for _, p := range CuratedFilterPresets() {
			if p.URL == cleanURL {
				cleanName = p.Name
				break
			}
		}
	}
	if cleanName == "" {
		if u, pErr := url.Parse(cleanURL); pErr == nil {
			cleanName = u.Host
		} else {
			cleanName = "Custom Filter"
		}
	}

	var filterResp struct {
		Filters []struct {
			URL  string `json:"url"`
			Name string `json:"name"`
		} `json:"filters"`
	}
	if _, err := m.controlRequest(ctx, http.MethodGet, "/control/filtering/status", nil, &filterResp); err != nil {
		return err
	}

	exists := false
	existingName := cleanName
	for _, f := range filterResp.Filters {
		if strings.TrimSpace(f.URL) == cleanURL {
			exists = true
			if strings.TrimSpace(f.Name) != "" {
				existingName = f.Name
			}
			break
		}
	}

	if !exists {
		if !enabled {
			return nil
		}
		_, addErr := m.controlRequest(ctx, http.MethodPost, "/control/filtering/add_url", map[string]any{
			"name":      cleanName,
			"url":       cleanURL,
			"whitelist": false,
		}, nil)
		return addErr
	}

	_, setErr := m.controlRequest(ctx, http.MethodPost, "/control/filtering/set_url", map[string]any{
		"url": cleanURL,
		"data": map[string]any{
			"name":    existingName,
			"url":     cleanURL,
			"enabled": enabled,
		},
		"whitelist": false,
	}, nil)
	return setErr
}

// RemoveFilter 移除指定的过滤规则订阅源。
func (m *Manager) RemoveFilter(ctx context.Context, rawURL string) error {
	cleanURL, err := validateFilterURL(rawURL)
	if err != nil {
		return err
	}
	_, err = m.controlRequest(ctx, http.MethodPost, "/control/filtering/remove_url", map[string]any{
		"url":       cleanURL,
		"whitelist": false,
	}, nil)
	return err
}

// RefreshFilters 立即在线刷新所有已启用的去广告规则库。
func (m *Manager) RefreshFilters(ctx context.Context) error {
	_, err := m.controlRequest(ctx, http.MethodPost, "/control/filtering/refresh", map[string]any{
		"whitelist": false,
	}, nil)
	return err
}
