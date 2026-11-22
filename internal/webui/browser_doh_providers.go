// 文件职责：维护公共 DoH/DoT 提供商域名/IP 指纹库、DNS 归属族系归一化及连接特征匹配纯函数。
package webui

import (
	"cmp"
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

var publicDoHHostProviders = map[string]string{
	"cloudflare-dns.com":          "Cloudflare DoH",
	"mozilla.cloudflare-dns.com":  "Cloudflare DoH (Firefox)",
	"one.one.one.one":             "Cloudflare DoH",
	"chrome.cloudflare-dns.com":   "Cloudflare DoH",
	"security.cloudflare-dns.com": "Cloudflare DoH (Security)",
	"family.cloudflare-dns.com":   "Cloudflare DoH (Family)",
	"odoh.cloudflare-dns.com":     "Cloudflare ODoH",
	"dns.google":                  "Google Public DoH",
	"dns.google.com":              "Google Public DoH",
	"dns64.dns.google":            "Google Public DoH64",
	"dns.quad9.net":               "Quad9 DoH",
	"dns9.quad9.net":              "Quad9 DoH",
	"dns10.quad9.net":             "Quad9 DoH",
	"dns11.quad9.net":             "Quad9 DoH",
	"dns.alidns.com":              "阿里公共 DNS (AliDNS DoH)",
	"doh.pub":                     "腾讯 DNSPod DoH",
	"sm2.doh.pub":                 "腾讯 DNSPod DoH",
	"dns.pub":                     "腾讯 DNSPod DoH",
	"dot.pub":                     "腾讯 DNSPod DoT",
	"doh.360.cn":                  "360 安全 DNS (DoH)",
	"dot.360.cn":                  "360 安全 DNS (DoT)",
	"dns.360.cn":                  "360 安全 DNS",
	"dns.nextdns.io":              "NextDNS DoH",
	"doh.dns.nextdns.io":          "NextDNS DoH",
	"dns.adguard-dns.com":         "AdGuard Public DoH",
	"dns.adguard.com":             "AdGuard Public DoH",
	"unfiltered.adguard-dns.com":  "AdGuard Public DoH",
	"family.adguard-dns.com":      "AdGuard Public DoH",
	"doh.opendns.com":             "OpenDNS DoH",
	"doh.umbrella.com":            "Cisco Umbrella / OpenDNS DoH",
	"dns.opendns.com":             "OpenDNS DoH",
	"doh.dns.sb":                  "DNS.SB DoH",
	"dns.sb":                      "DNS.SB DoH",
	"doh.cleanbrowsing.org":       "CleanBrowsing DoH",
	"dns.mullvad.net":             "Mullvad DoH",
	"doh.mullvad.net":             "Mullvad DoH",
	"doh.dns.apple.com":           "Apple Encrypted DNS",
	"mask.icloud.com":             "Apple iCloud Private Relay",
	"mask-h2.icloud.com":          "Apple iCloud Private Relay",
	"dns.controld.com":            "Control D DoH",
	"freedns.controld.com":        "Control D DoH",
}

var publicDoHIPProviders = map[string]string{
	"1.1.1.1":              "Cloudflare DoH",
	"1.0.0.1":              "Cloudflare DoH",
	"1.1.1.2":              "Cloudflare DoH",
	"1.0.0.2":              "Cloudflare DoH",
	"1.1.1.3":              "Cloudflare DoH",
	"1.0.0.3":              "Cloudflare DoH",
	"2606:4700:4700::1111": "Cloudflare DoH",
	"2606:4700:4700::1001": "Cloudflare DoH",
	"8.8.8.8":              "Google Public DoH",
	"8.8.4.4":              "Google Public DoH",
	"2001:4860:4860::8888": "Google Public DoH",
	"2001:4860:4860::8844": "Google Public DoH",
	"9.9.9.9":              "Quad9 DoH",
	"149.112.112.112":      "Quad9 DoH",
	"2620:fe::fe":          "Quad9 DoH",
	"2620:fe::9":           "Quad9 DoH",
	"223.5.5.5":            "阿里公共 DNS (AliDNS DoH)",
	"223.6.6.6":            "阿里公共 DNS (AliDNS DoH)",
	"2400:3200::1":         "阿里公共 DNS (AliDNS DoH)",
	"2400:3200:baba::1":    "阿里公共 DNS (AliDNS DoH)",
	"119.29.29.29":         "腾讯 DNSPod DoH",
	"1.12.12.12":           "腾讯 DNSPod DoH",
	"120.53.53.53":         "腾讯 DNSPod DoH",
	"2402:4e00::":          "腾讯 DNSPod DoH",
	"94.140.14.14":         "AdGuard Public DoH",
	"94.140.15.15":         "AdGuard Public DoH",
	"2a10:50c0::ad1:ff":    "AdGuard Public DoH",
	"2a10:50c0::ad2:ff":    "AdGuard Public DoH",
	"208.67.222.222":       "OpenDNS DoH",
	"208.67.220.220":       "OpenDNS DoH",
}

func normalizeIPString(raw string) string {
	s := strings.TrimSpace(raw)
	s = strings.TrimPrefix(s, "[")
	s = strings.TrimSuffix(s, "]")
	if zoneIdx := strings.LastIndexByte(s, '%'); zoneIdx > 0 {
		s = s[:zoneIdx]
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return ""
	}
	return addr.Unmap().String()
}

func isPrivateLANAddr(rawIP string) bool {
	addr, err := netip.ParseAddr(normalizeIPString(rawIP))
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	if addr.IsLoopback() || tsCGNATPrefix.Contains(addr) || tsULA6Prefix.Contains(addr) {
		return false
	}
	return addr.IsPrivate() || addr.IsLinkLocalUnicast()
}

func collectMapKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func matchDoHHost(host string) string {
	h := strings.ToLower(strings.TrimSpace(host))
	h = strings.TrimSuffix(h, ".")
	if h == "" {
		return ""
	}
	if p, ok := publicDoHHostProviders[h]; ok {
		return p
	}
	for dom, p := range publicDoHHostProviders {
		if strings.HasSuffix(h, "."+dom) {
			return p
		}
	}
	return ""
}

func normalizeDNSOrgFamily(isp, rawIP string) string {
	lower := strings.ToLower(strings.TrimSpace(isp))
	normIP := normalizeIPString(rawIP)
	if strings.Contains(lower, "google") || strings.HasPrefix(normIP, "8.8.") || strings.HasPrefix(normIP, "2001:4860:") {
		return "google"
	}
	if strings.Contains(lower, "cloudflare") || strings.HasPrefix(normIP, "1.1.1.") || strings.HasPrefix(normIP, "1.0.0.") || strings.HasPrefix(normIP, "172.68.") || strings.HasPrefix(normIP, "172.69.") || strings.HasPrefix(normIP, "172.70.") || strings.HasPrefix(normIP, "172.71.") || strings.HasPrefix(normIP, "2400:cb00:") || strings.HasPrefix(normIP, "2606:4700:") {
		return "cloudflare"
	}
	if strings.Contains(lower, "quad9") || strings.Contains(lower, "woodynet") || normIP == "9.9.9.9" || normIP == "149.112.112.112" {
		return "quad9"
	}
	if strings.Contains(lower, "alibaba") || strings.Contains(lower, "alicloud") || strings.Contains(lower, "alidns") || strings.Contains(lower, "aliyun") || strings.Contains(lower, "阿里") || strings.HasPrefix(normIP, "223.5.") || strings.HasPrefix(normIP, "223.6.") {
		return "alibaba"
	}
	if strings.Contains(lower, "tencent") || strings.Contains(lower, "dnspod") || strings.Contains(lower, "腾讯") || normIP == "119.29.29.29" || normIP == "1.12.12.12" || normIP == "120.53.53.53" {
		return "tencent"
	}
	if strings.Contains(lower, "adguard") || normIP == "94.140.14.14" || normIP == "94.140.15.15" {
		return "adguard"
	}
	if strings.Contains(lower, "nextdns") {
		return "nextdns"
	}
	if strings.Contains(lower, "opendns") || strings.Contains(lower, "cisco") || normIP == "208.67.222.222" || normIP == "208.67.220.220" {
		return "opendns"
	}
	if strings.Contains(lower, "baidu") || strings.Contains(lower, "百度") || normIP == "180.76.76.76" {
		return "baidu"
	}
	if strings.Contains(lower, "360") {
		return "360"
	}
	if strings.Contains(lower, "114") || strings.Contains(lower, "nanjing xinfeng") {
		return "114dns"
	}
	if strings.Contains(lower, "chinanet") || strings.Contains(lower, "chinatelecom") || strings.Contains(lower, "电信") {
		return "chinanet"
	}
	if strings.Contains(lower, "unicom") || strings.Contains(lower, "联通") {
		return "unicom"
	}
	if strings.Contains(lower, "cmcc") || strings.Contains(lower, "china mobile") || strings.Contains(lower, "移动") {
		return "cmcc"
	}
	return lower
}

func dedupBrowserSamples(samples []browserDoHEDNSSample) []browserDoHEDNSSample {
	seen := map[string]struct{}{}
	out := make([]browserDoHEDNSSample, 0, len(samples))
	for _, item := range samples {
		ip := normalizeIPString(item.DNSIP)
		if ip == "" {
			continue
		}
		if _, exists := seen[ip]; exists {
			continue
		}
		seen[ip] = struct{}{}
		item.DNSIP = ip
		item.CountryCode = strings.ToUpper(strings.TrimSpace(item.CountryCode))
		item.Country = strings.TrimSpace(item.Country)
		item.ISP = strings.TrimSpace(item.ISP)
		out = append(out, item)
	}
	return out
}

type matchedPublicDoHConn struct {
	Endpoint   browserDoHEndpointMatch
	Key        string
	IsRejected bool
}

func matchPublicDoHConn(c BrowserDoHClashConn, clientIPSet map[string]struct{}) (matchedPublicDoHConn, bool) {
	src := normalizeIPString(c.SourceIP)
	if src == "" {
		return matchedPublicDoHConn{}, false
	}
	if _, mine := clientIPSet[src]; !mine {
		return matchedPublicDoHConn{}, false
	}
	port := strings.TrimSpace(c.DestPort)
	if port != "443" && port != "853" {
		return matchedPublicDoHConn{}, false
	}
	destIP := normalizeIPString(c.DestIP)
	host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(cmp.Or(c.Host, c.SniffHost)), "."))

	provider := matchDoHHost(c.Host)
	if provider == "" {
		provider = matchDoHHost(c.SniffHost)
	}
	if provider == "" && (host == "" || host == destIP) {
		provider = publicDoHIPProviders[destIP]
	}
	if provider == "" {
		return matchedPublicDoHConn{}, false
	}

	key := strings.TrimSpace(c.ID)
	if key == "" {
		key = fmt.Sprintf("%s|%s|%s|%s", src, destIP, port, host)
	}
	isRejected := strings.EqualFold(strings.TrimSpace(c.Rule), "REJECT") ||
		slices.ContainsFunc(c.Chains, func(ch string) bool {
			l := strings.ToLower(strings.TrimSpace(ch))
			return l == "reject" || l == "block"
		})

	return matchedPublicDoHConn{
		Endpoint: browserDoHEndpointMatch{
			Provider: provider,
			Host:     host,
			DestIP:   destIP,
			DestPort: port,
			SourceIP: src,
			Network:  c.Network,
			Rule:     c.Rule,
		},
		Key:        key,
		IsRejected: isRejected,
	}, true
}
