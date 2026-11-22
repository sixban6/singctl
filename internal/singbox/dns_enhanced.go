// 文件职责：提供客户端本地 DNS 通用防注入校验工具（内网解析重写校验与订阅域名提取，供双引擎共享复用）。
package singbox

import (
	"fmt"
	"net/netip"
	"net/url"
	"slices"
	"strings"

	"singctl/internal/config"
)

func hasControlOrWhitespace(s string) bool {
	for _, r := range s {
		if r <= 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

func isValidHostname(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return false
	}
	for label := range strings.SplitSeq(host, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := range len(label) {
			c := label[i]
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
				return false
			}
		}
	}
	return true
}

// ValidateDNSRewriteRule 严格校验内网自定义 DNS 重写规则（防换行/RR/命令注入）。
func ValidateDNSRewriteRule(rule config.DNSRewriteRule) error {
	rawDomain := strings.TrimSpace(rule.Domain)
	rawAnswer := strings.TrimSpace(rule.Answer)
	if rawDomain == "" || rawAnswer == "" {
		return fmt.Errorf("DNS 重写规则域名与应答 IP 均不能为空")
	}
	if hasControlOrWhitespace(rawDomain) || hasControlOrWhitespace(rawAnswer) {
		return fmt.Errorf("DNS 重写规则包含非法空白或控制字符")
	}

	d := strings.ToLower(strings.TrimSuffix(rawDomain, "."))
	if rest, ok := strings.CutPrefix(d, "*."); ok {
		d = rest
	}
	if strings.Contains(d, "*") || !isValidHostname(d) {
		return fmt.Errorf("DNS 重写域名 %q 非法", rule.Domain)
	}

	addr, parseErr := netip.ParseAddr(rawAnswer)
	if parseErr != nil || addr.Zone() != "" {
		return fmt.Errorf("DNS 重写目标 %q 不是合法 IPv4/IPv6 地址", rule.Answer)
	}
	return nil
}

// ExtractSubscriptionDomains 从客户端订阅列表中提取去重后的合法域名集合（用于防广告/PCDN 误杀）。
func ExtractSubscriptionDomains(cfg *config.Config) []string {
	if cfg == nil || len(cfg.Subs) == 0 {
		return nil
	}
	out := make([]string, 0, len(cfg.Subs))
	for _, sub := range cfg.Subs {
		rawURL := strings.TrimSpace(sub.URL)
		if rawURL == "" {
			continue
		}
		u, err := url.Parse(rawURL)
		if err != nil {
			continue
		}
		host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(u.Hostname()), "."))
		if host == "" || host == "localhost" {
			continue
		}
		if !isValidHostname(host) {
			continue
		}
		if !slices.Contains(out, host) {
			out = append(out, host)
		}
	}
	return out
}
