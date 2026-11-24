// 文件职责：提供 AdGuard Home 过滤保护开关、缓存清理、域名白名单、订阅防误杀同步、DNS 重写与规则订阅源增删改动作。
package adguard

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"

	"singctl/internal/constant"

	"gopkg.in/yaml.v3"
)

// SetProtection 切换 AdGuard Home 的广告过滤保护开关（支持倒计时自动恢复，如暂停 5/30/60 分钟）。
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

func (m *Manager) effectiveSafeWhitelistDomains() []string {
	blocked := make(map[string]struct{})
	if m.cfg != nil {
		for _, b := range m.cfg.CustomRules.Block {
			if strings.TrimSpace(b.SourceIP) != "" {
				continue
			}
			if dom := normalizeAdGuardTarget(b.Target); dom != "" {
				blocked[dom] = struct{}{}
			}
		}
	}
	out := make([]string, 0, len(constant.DefaultAdBlockSafeDomains)+8)
	for _, d := range constant.DefaultAdBlockSafeDomains {
		norm := normalizeAdGuardTarget(d)
		if norm == "" {
			continue
		}
		if _, isBlocked := blocked[norm]; isBlocked {
			continue
		}
		out = append(out, norm)
	}
	if m.cfg != nil {
		out = append(out, m.cfg.DNS.Whitelist...)
	}
	return out
}

// SyncSubscriptionWhitelist 确保 singctl.yaml 中最新的订阅域名、内置防 Anti-AD 误杀基线（剔除显式拉黑项）与用户白名单全部位于 AdGuard 高优放行列表。
func (m *Manager) SyncSubscriptionWhitelist(ctx context.Context, subURLs []string) error {
	if !m.isBinaryPresent() {
		if _, err := os.Stat(m.aghConfigFile); os.IsNotExist(err) {
			return nil
		}
	}
	subRules := extractSubWhitelistRules(subURLs, m.effectiveSafeWhitelistDomains()...)
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

// ValidateFilterURL 校验去广告过滤规则源 URL 是否为合法的 HTTP(S) 地址。
func ValidateFilterURL(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	u, err := url.Parse(trimmed)
	scheme := ""
	if u != nil {
		scheme = strings.ToLower(u.Scheme)
	}
	if err != nil || (scheme != "https" && scheme != "http") || strings.TrimSpace(u.Hostname()) == "" {
		return "", errors.New("规则订阅地址必须为有效的 http:// 或 https:// URL")
	}
	return trimmed, nil
}

// SetFilterState 启用、禁用或首次添加去广告过滤规则源。
func (m *Manager) SetFilterState(ctx context.Context, rawURL, name string, enabled bool) error {
	cleanURL, err := ValidateFilterURL(rawURL)
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
	cleanURL, err := ValidateFilterURL(rawURL)
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
