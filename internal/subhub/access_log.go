// 文件职责：负责客户端订阅拉取访问日志的 0600 有界持久化、User-Agent 应用识别与防盗刷风险评估。
package subhub

import (
	"cmp"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"singctl/internal/common/fsx"
)

const (
	accessAuditFileName = ".access_audit.json"
	maxAccessAuditLogs  = 100
)

// AccessLogEntry records a single client subscription pull or unauthorized key probe.
type AccessLogEntry struct {
	Timestamp   string `json:"timestamp"`
	IP          string `json:"ip"`
	CountryCode string `json:"countryCode,omitempty"`
	Geo         string `json:"geo,omitempty"`
	Flag        string `json:"flag,omitempty"`
	ClientApp   string `json:"clientApp"`
	UserAgent   string `json:"userAgent,omitempty"`
	Target      string `json:"target"`
	Collection  string `json:"collection,omitempty"`
	NodeCount   int    `json:"nodeCount"`
	Status      string `json:"status"` // "ok" | "denied"
}

// SubscriptionRiskSummary 描述订阅拉取防盗刷风险评估摘要。
type SubscriptionRiskSummary struct {
	Level              string   `json:"level"` // "safe" | "warn" | "high"
	UniqueIPs24h       int      `json:"uniqueIps24h"`
	UniqueCountries24h int      `json:"uniqueCountries24h"`
	DeniedHits24h      int      `json:"deniedHits24h"`
	SuspiciousUAHits   int      `json:"suspiciousUaHits24h"`
	Reasons            []string `json:"reasons"`
}

var suspiciousSubUAKeywords = []string{
	"python-requests", "python-urllib", "curl/", "wget/",
	"go-http-client", "axios/", "node-fetch", "headless",
	"spider", "censys", "shodan", "scrapy",
}

func (s *Store) accessAuditPath() string {
	return filepath.Join(s.DataDir, accessAuditFileName)
}

// RecordAccess appends a subscription access event to the bounded 0600 audit log on disk.
func (s *Store) RecordAccess(entry AccessLogEntry) {
	if entry.Timestamp == "" {
		entry.Timestamp = time.Now().Format(time.RFC3339)
	}
	if len(entry.UserAgent) > 96 {
		entry.UserAgent = entry.UserAgent[:96]
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	path := s.accessAuditPath()
	var list []AccessLogEntry
	if raw, err := os.ReadFile(path); err == nil && len(raw) > 0 {
		_ = json.Unmarshal(raw, &list)
	}

	list = slices.Insert(list, 0, entry)
	if len(list) > maxAccessAuditLogs {
		list = list[:maxAccessAuditLogs]
	}

	if err := os.MkdirAll(s.DataDir, 0755); err != nil {
		return
	}
	out, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return
	}
	_ = fsx.WriteAtomic0600(path, out)
}

// ListAccessLogs returns the recent subscription access audit entries (newest first).
func (s *Store) ListAccessLogs() ([]AccessLogEntry, error) {
	s.mu.Lock()
	path := s.accessAuditPath()
	raw, err := os.ReadFile(path)
	s.mu.Unlock()

	if err != nil {
		if os.IsNotExist(err) {
			return []AccessLogEntry{}, nil
		}
		return nil, err
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return []AccessLogEntry{}, nil
	}
	var list []AccessLogEntry
	if err := json.Unmarshal(raw, &list); err != nil {
		return []AccessLogEntry{}, nil
	}
	return list, nil
}

// ClearAccessLogs clears all stored subscription access audit entries.
func (s *Store) ClearAccessLogs() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	path := s.accessAuditPath()
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func extractRequestIPAndCountry(r *http.Request) (ip string, country string) {
	country = strings.ToUpper(strings.TrimSpace(cmp.Or(
		r.Header.Get("X-Geo-Country"),
		r.Header.Get("CF-IPCountry"),
	)))
	if country == "XX" || country == "T1" {
		country = ""
	}

	for _, hdr := range []string{"X-Real-IP", "CF-Connecting-IP", "X-Forwarded-For"} {
		val := strings.TrimSpace(r.Header.Get(hdr))
		if val == "" {
			continue
		}
		first := strings.TrimSpace(strings.Split(val, ",")[0])
		if parsed := net.ParseIP(first); parsed != nil {
			return parsed.String(), country
		}
	}

	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err != nil {
		host = strings.TrimSpace(r.RemoteAddr)
	}
	return host, country
}

// IdentifyClientApp classifies a client's User-Agent into a concise human-readable app label.
func IdentifyClientApp(ua string) string {
	lower := strings.ToLower(strings.TrimSpace(ua))
	switch {
	case lower == "":
		return "Unknown"
	case strings.Contains(lower, "shadowrocket"):
		return "Shadowrocket"
	case strings.Contains(lower, "flclash"):
		return "FlClash"
	case strings.Contains(lower, "clash-verge") || strings.Contains(lower, "clashverge"):
		return "Clash Verge"
	case strings.Contains(lower, "stash"):
		return "Stash"
	case strings.Contains(lower, "mihomo") || strings.Contains(lower, "clash.meta") || strings.Contains(lower, "metacubex"):
		return "Clash.Meta"
	case strings.Contains(lower, "clash"):
		return "Clash"
	case strings.Contains(lower, "sfi/"):
		return "Sing-box iOS"
	case strings.Contains(lower, "sfa/"):
		return "Sing-box Android"
	case strings.Contains(lower, "sfm/"):
		return "Sing-box macOS"
	case strings.Contains(lower, "sing-box"):
		return "Sing-box"
	case strings.Contains(lower, "surge"):
		return "Surge"
	case strings.Contains(lower, "loon"):
		return "Loon"
	case strings.Contains(lower, "quantumult"):
		return "Quantumult X"
	case strings.Contains(lower, "v2ray") || strings.Contains(lower, "hiddify") || strings.Contains(lower, "nekobox"):
		return "V2Ray / Hiddify"
	case strings.Contains(lower, "singctl"):
		return "SingCtl"
	case strings.Contains(lower, "curl/"):
		return "curl"
	case strings.Contains(lower, "mozilla/"):
		return "Browser"
	default:
		if idx := strings.IndexByte(ua, '/'); idx > 0 && idx <= 24 {
			return strings.TrimSpace(ua[:idx])
		}
		if len(ua) > 20 {
			return strings.TrimSpace(ua[:20])
		}
		return strings.TrimSpace(ua)
	}
}

// IsSuspiciousSubUA 判断订阅请求 User-Agent 是否为空或带常见脚本/爬虫抓取特征。
func IsSuspiciousSubUA(ua string) bool {
	lower := strings.ToLower(strings.TrimSpace(ua))
	if lower == "" {
		return true
	}
	for _, kw := range suspiciousSubUAKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

// EvaluateAccessRisk 基于过去 24 小时订阅拉取日志评估外泄或爬虫盗刷风险等级。
func EvaluateAccessRisk(logs []AccessLogEntry) SubscriptionRiskSummary {
	cutoff := time.Now().Add(-24 * time.Hour)
	ipSet := make(map[string]struct{})
	countrySet := make(map[string]struct{})
	deniedHits := 0
	suspiciousUA := 0

	for _, entry := range logs {
		if ts, err := time.Parse(time.RFC3339, entry.Timestamp); err == nil && ts.Before(cutoff) {
			continue
		}
		if entry.Status == "denied" {
			deniedHits++
			continue
		}
		if entry.IP != "" {
			ipSet[entry.IP] = struct{}{}
		}
		if cc := strings.ToUpper(strings.TrimSpace(entry.CountryCode)); cc != "" && cc != "XX" && cc != "LOCAL" {
			countrySet[cc] = struct{}{}
		}
		if IsSuspiciousSubUA(entry.UserAgent) {
			suspiciousUA++
		}
	}

	uniqueIPs := len(ipSet)
	uniqueCountries := len(countrySet)
	reasons := make([]string, 0, 4)
	level := "safe"

	if uniqueIPs >= 10 {
		level = "high"
		reasons = append(reasons, fmt.Sprintf("24 小时内共有 %d 个不同公网 IP 成功拉取订阅，远超个人多设备常规范围", uniqueIPs))
	} else if uniqueIPs >= 6 {
		level = "warn"
		reasons = append(reasons, fmt.Sprintf("24 小时内共有 %d 个不同公网 IP 拉取订阅，建议核对是否均为本人设备", uniqueIPs))
	}

	if uniqueCountries >= 4 {
		level = "high"
		reasons = append(reasons, fmt.Sprintf("24 小时内跨 %d 个国家/地区拉取订阅，存在订阅链接外泄或被第三方测速台抓取风险", uniqueCountries))
	} else if uniqueCountries >= 3 && level == "safe" {
		level = "warn"
		reasons = append(reasons, fmt.Sprintf("24 小时内跨 %d 个国家/地区拉取订阅（若设备挂代理更新订阅属正常现象）", uniqueCountries))
	}

	if suspiciousUA >= 2 && uniqueIPs >= 4 {
		level = "high"
		reasons = append(reasons, fmt.Sprintf("检测到 %d 次脚本/爬虫特征 User-Agent 批量拉取订阅", suspiciousUA))
	} else if suspiciousUA >= 1 && level == "safe" {
		level = "warn"
		reasons = append(reasons, fmt.Sprintf("检测到 %d 次非标准客户端（脚本/空 UA）拉取订阅", suspiciousUA))
	}

	if deniedHits >= 3 && level == "safe" {
		level = "warn"
		reasons = append(reasons, fmt.Sprintf("24 小时内拦截了 %d 次错误订阅密钥试探", deniedHits))
	}

	return SubscriptionRiskSummary{
		Level:              level,
		UniqueIPs24h:       uniqueIPs,
		UniqueCountries24h: uniqueCountries,
		DeniedHits24h:      deniedHits,
		SuspiciousUAHits:   suspiciousUA,
		Reasons:            reasons,
	}
}
