// 文件职责：提供零外部依赖的 URL 敏感信息脱敏纯函数（剥离认证口令、隐藏公网 IP 段与路径 Token 并保持合法 UTF-8）。
package redact

import (
	"net"
	"strings"
)

// MaskURL 对订阅或含密钥的 URL 进行安全脱敏展示。
func MaskURL(rawURL string) string {
	if rawURL == "" {
		return "未配置"
	}

	schemeIdx := strings.Index(rawURL, "://")
	if schemeIdx < 0 {
		return "***"
	}

	scheme := rawURL[:schemeIdx+3]
	remaining := rawURL[schemeIdx+3:]
	if remaining == "" {
		return "***"
	}

	authority := remaining
	for _, sep := range []byte{'/', '?', '#'} {
		if idx := strings.IndexByte(authority, sep); idx >= 0 {
			authority = authority[:idx]
		}
	}
	if atIdx := strings.LastIndexByte(authority, '@'); atIdx >= 0 {
		authority = authority[atIdx+1:]
	}
	if authority == "" {
		return "***"
	}

	host := authority
	portSuffix := ""
	if h, p, err := net.SplitHostPort(authority); err == nil && h != "" {
		host = h
		portSuffix = ":" + p
	}
	hostClean := strings.Trim(host, "[]")

	if ip := net.ParseIP(hostClean); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			parts := strings.Split(v4.String(), ".")
			return scheme + parts[0] + ".***.***.***" + portSuffix + "/***"
		}
		return scheme + "[***]" + portSuffix + "/***"
	}

	domainParts := strings.Split(hostClean, ".")
	if len(domainParts) >= 2 {
		runes := []rune(domainParts[0])
		if len(runes) > 1 {
			domainParts[0] = string(runes[0]) + strings.Repeat("*", len(runes)-1)
		}
		return scheme + strings.Join(domainParts, ".") + portSuffix + "/***"
	}

	runes := []rune(hostClean)
	if len(runes) > 1 {
		return scheme + string(runes[0]) + strings.Repeat("*", len(runes)-1) + portSuffix + "/***"
	}
	return scheme + "***" + portSuffix + "/***"
}
