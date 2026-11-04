package fleet

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"singctl/internal/config"
)

// GeoInfo describes a probed public IP location for automatic fleet node naming.
type GeoInfo struct {
	Tag         string `json:"tag"`
	CountryCode string `json:"countryCode"`
	City        string `json:"city"`
	DisplayName string `json:"displayName"`
}

// GeoProberFunc resolves a host/IP to its geographic tag and friendly Chinese display name.
type GeoProberFunc func(ctx context.Context, host string) GeoInfo

var countryCodeZH = map[string]string{
	"JP": "日本",
	"SG": "新加坡",
	"HK": "中国香港",
	"TW": "中国台湾",
	"MO": "中国澳门",
	"KR": "韩国",
	"US": "美国",
	"CA": "加拿大",
	"GB": "英国",
	"DE": "德国",
	"FR": "法国",
	"NL": "荷兰",
	"AU": "澳大利亚",
	"MY": "马来西亚",
	"TH": "泰国",
	"VN": "越南",
	"IN": "印度",
	"RU": "俄罗斯",
	"CH": "瑞士",
	"SE": "瑞典",
	"TR": "土耳其",
	"AE": "阿联酋",
	"BR": "巴西",
}

var cityKeywordZH = []struct {
	substr string
	zh     string
}{
	{"tokyo", "东京"},
	{"osaka", "大阪"},
	{"singapore", "新加坡"},
	{"hong kong", "香港"},
	{"taipei", "台北"},
	{"seoul", "首尔"},
	{"los angeles", "洛杉矶"},
	{"san jose", "圣何塞"},
	{"santa clara", "圣何塞"},
	{"fremont", "弗里蒙特"},
	{"san francisco", "旧金山"},
	{"seattle", "西雅图"},
	{"new york", "纽约"},
	{"newark", "纽瓦克"},
	{"chicago", "芝加哥"},
	{"dallas", "达拉斯"},
	{"phoenix", "凤凰城"},
	{"miami", "迈阿密"},
	{"ashburn", "阿什本"},
	{"london", "伦敦"},
	{"frankfurt", "法兰克福"},
	{"amsterdam", "阿姆斯特丹"},
	{"paris", "巴黎"},
	{"sydney", "悉尼"},
}

// DefaultGeoProber queries lightweight GeoIP endpoints to determine tag and Chinese display name.
func DefaultGeoProber(ctx context.Context, host string) GeoInfo {
	fallback := GeoInfo{Tag: "node", DisplayName: "边缘节点"}
	ipStr := strings.TrimSpace(host)
	if parsed := net.ParseIP(ipStr); parsed == nil {
		ips, err := net.LookupIP(ipStr)
		if err != nil || len(ips) == 0 {
			return fallback
		}
		ipStr = ips[0].String()
	}
	parsed := net.ParseIP(ipStr)
	if parsed == nil || parsed.IsLoopback() || parsed.IsPrivate() {
		return fallback
	}

	probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 2500 * time.Millisecond}

	// Provider 1: ip-api.com
	if req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, "http://ip-api.com/json/"+ipStr+"?fields=status,country,countryCode,city", nil); err == nil {
		req.Header.Set("User-Agent", "curl/8.5.0")
		if resp, err := client.Do(req); err == nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
			_ = resp.Body.Close()
			var r struct {
				Status      string `json:"status"`
				CountryCode string `json:"countryCode"`
				City        string `json:"city"`
			}
			if json.Unmarshal(body, &r) == nil && strings.EqualFold(r.Status, "success") {
				return buildGeoInfo(r.City, r.CountryCode)
			}
		}
	}

	// Provider 2: ipwho.is HTTPS fallback
	if req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, "https://ipwho.is/"+ipStr, nil); err == nil {
		req.Header.Set("User-Agent", "curl/8.5.0")
		if resp, err := client.Do(req); err == nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
			_ = resp.Body.Close()
			var r struct {
				Success     bool   `json:"success"`
				CountryCode string `json:"country_code"`
				City        string `json:"city"`
			}
			if json.Unmarshal(body, &r) == nil && r.Success {
				return buildGeoInfo(r.City, r.CountryCode)
			}
		}
	}

	return fallback
}

func buildGeoInfo(city, countryCode string) GeoInfo {
	cc := strings.ToUpper(strings.TrimSpace(countryCode))
	tag := config.CityCountryToTag(city, cc)
	if tag == "" {
		tag = "node"
	}

	countryZH := countryCodeZH[cc]
	cityLower := strings.ToLower(strings.TrimSpace(city))
	cityZH := ""
	for _, item := range cityKeywordZH {
		if strings.Contains(cityLower, item.substr) {
			cityZH = item.zh
			break
		}
	}

	var display string
	switch {
	case countryZH != "" && cityZH != "" && countryZH != cityZH && !strings.Contains(countryZH, cityZH):
		display = countryZH + "·" + cityZH
	case countryZH != "":
		display = countryZH
	case cityZH != "":
		display = cityZH
	case cc != "":
		display = cc + " 节点"
	default:
		display = "边缘节点"
	}

	return GeoInfo{
		Tag:         tag,
		CountryCode: cc,
		City:        strings.TrimSpace(city),
		DisplayName: display,
	}
}

var (
	cleanIDCharsRe  = regexp.MustCompile(`[^a-z0-9_-]+`)
	trailingDigitRe = regexp.MustCompile(`[0-9]+$`)
)

// AllocateUniqueIDAndName assigns a collision-free numbered node ID (e.g., sg1, sg2) and human-readable display name.
func AllocateUniqueIDAndName(preferredID, preferredName, geoTag, geoDisplayName string, takenIDs map[string]bool) (string, string) {
	explicitID := strings.ToLower(strings.TrimSpace(preferredID))
	explicitName := strings.TrimSpace(preferredName)

	if explicitID != "" {
		name := cmp.Or(explicitName, geoDisplayName, explicitID)
		return explicitID, name
	}

	baseTag := strings.Trim(cleanIDCharsRe.ReplaceAllString(strings.ToLower(strings.TrimSpace(geoTag)), "-"), "-")
	if baseTag == "" || !validNodeIDRe.MatchString(baseTag) {
		baseTag = "node"
	}
	baseDisplay := cmp.Or(explicitName, strings.TrimSpace(geoDisplayName), strings.ToUpper(baseTag))

	startIdx := 1
	if takenIDs[baseTag] {
		// 若已存在历史无序号节点（如 sg），新节点直接从 sg2 起步，避免产生歧义
		startIdx = 2
	}

	for i := startIdx; i <= 999; i++ {
		cand := fmt.Sprintf("%s%d", baseTag, i)
		if len(cand) > 32 {
			cand = cand[:32]
		}
		if !takenIDs[cand] {
			if explicitName != "" {
				return cand, explicitName
			}
			if i == 1 {
				return cand, baseDisplay
			}
			return cand, fmt.Sprintf("%s #%d", baseDisplay, i)
		}
	}
	return fmt.Sprintf("%s-%d", baseTag, time.Now().Unix()%10000), baseDisplay
}

// FormatAutoCDNSubdomain formats an auto-derived CDN edge subdomain such as "sg1.cdn.example.com".
func FormatAutoCDNSubdomain(nodeID, rootZone string) string {
	zone := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(rootZone)), ".")
	if zone == "" {
		return ""
	}
	label := NormalizeCDNNodeLabel(nodeID)
	return fmt.Sprintf("%s.cdn.%s", label, zone)
}

// NormalizeCDNNodeLabel ensures an auto-derived subdomain label ends with an index (e.g. "sg" -> "sg1", "sg2" -> "sg2").
func NormalizeCDNNodeLabel(nodeID string) string {
	clean := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(nodeID)), ".cdn")
	clean = strings.Trim(cleanIDCharsRe.ReplaceAllString(clean, "-"), "-")
	if clean == "" {
		return "node1"
	}
	if !trailingDigitRe.MatchString(clean) {
		clean += "1"
	}
	return clean
}
