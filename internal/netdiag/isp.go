package netdiag

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"time"
)

type ipAPIResponse struct {
	Status      string `json:"status"`
	Country     string `json:"country"`
	CountryCode string `json:"countryCode"`
	RegionName  string `json:"regionName"`
	City        string `json:"city"`
	ISP         string `json:"isp"`
	Org         string `json:"org"`
	AS          string `json:"as"`
	Query       string `json:"query"`
}

type ipSBResponse struct {
	IP          string `json:"ip"`
	Country     string `json:"country"`
	CountryCode string `json:"country_code"`
	Region      string `json:"region"`
	City        string `json:"city"`
	ISP         string `json:"isp"`
	ASN         int    `json:"asn"`
	ASNOrg      string `json:"asn_organization"`
}

// GetPublicISP 获取本地公网 IP 及运营商画像
// 优先获取国内物理真实宽带出口（绕开翻墙代理规则），再解析精准画像
func GetPublicISP(ctx context.Context) (*ISPInfo, error) {
	// 1. 优先探测国内真实的物理宽带出口 IP (3322 / cip.cc)
	if ip := fetchDomesticIP(ctx); ip != "" {
		if info, err := GetTargetISP(ctx, ip); err == nil && info.IP != "" {
			return info, nil
		}
	}

	// 2. 尝试 cip.cc 直接返回的国内画像
	if info, err := fetchFromCipCC(ctx); err == nil && info.IP != "" {
		return info, nil
	}

	client := &http.Client{
		Timeout: 3 * time.Second,
	}

	// 3. 备选方案: 直接查询当前出口 ip-api.com
	if info, err := fetchFromIPAPI(ctx, client); err == nil && info.IP != "" {
		return info, nil
	}

	// 4. 备选方案: api.ip.sb
	if info, err := fetchFromIPSB(ctx, client); err == nil && info.IP != "" {
		return info, nil
	}

	return nil, fmt.Errorf("failed to fetch public ISP info from all sources")
}

func fetchDomesticIP(ctx context.Context) string {
	endpoints := []string{
		"http://members.3322.org/dyndns/getip",
		"http://ip.3322.net",
	}

	for _, ep := range endpoints {
		// 优先调用 curl（免疫应用防火墙如 LuLu 拦截）
		if _, err := exec.LookPath("curl"); err == nil {
			out, err := exec.CommandContext(ctx, "curl", "-s", "--max-time", "2", ep).Output()
			if err == nil {
				ip := strings.TrimSpace(string(out))
				if net.ParseIP(ip) != nil {
					return ip
				}
			}
		}

		// 原生 http 探测兜底
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, ep, nil)
		if err == nil {
			client := &http.Client{Timeout: 1500 * time.Millisecond}
			if resp, err := client.Do(req); err == nil {
				defer resp.Body.Close()
				if b, err := io.ReadAll(resp.Body); err == nil {
					ip := strings.TrimSpace(string(b))
					if net.ParseIP(ip) != nil {
						return ip
					}
				}
			}
		}
	}

	return ""
}

func fetchFromCipCC(ctx context.Context) (*ISPInfo, error) {
	var body string

	// 1. 优先调用系统 curl（避免第三方应用防火墙如 LuLu/Little Snitch 拦截新二进制的 TCP 握手）
	if _, err := exec.LookPath("curl"); err == nil {
		out, err := exec.CommandContext(ctx, "curl", "-s", "-H", "User-Agent: curl/7.68.0", "--max-time", "3", "http://cip.cc").Output()
		if err == nil && len(out) > 0 {
			body = string(out)
		}
	}

	// 2. 备选方案: 原生 Go http.Client
	if body == "" {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://cip.cc", nil)
		if err == nil {
			req.Header.Set("User-Agent", "curl/7.68.0")
			client := &http.Client{Timeout: 2 * time.Second}
			if resp, err := client.Do(req); err == nil {
				defer resp.Body.Close()
				if b, err := io.ReadAll(resp.Body); err == nil {
					body = string(b)
				}
			}
		}
	}

	if body == "" {
		return nil, fmt.Errorf("cip.cc failed")
	}

	return parseCipCCOutput(body)
}

func parseCipCCOutput(output string) (*ISPInfo, error) {
	lines := strings.Split(output, "\n")
	info := &ISPInfo{Country: "中国", CountryCode: "CN"}

	for _, line := range lines {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])

		switch key {
		case "IP":
			info.IP = val
		case "地址":
			fields := strings.Fields(val)
			if len(fields) >= 1 {
				info.Country = fields[0]
			}
			if len(fields) >= 2 {
				info.Region = fields[1]
			}
			if len(fields) >= 3 {
				info.City = fields[2]
			}
		case "运营商":
			info.ISP = val
			info.Org = val
		case "数据二", "数据三":
			if info.ISP == "" && strings.Contains(val, "|") {
				subParts := strings.Split(val, "|")
				if len(subParts) >= 2 {
					info.ISP = strings.TrimSpace(subParts[1])
					info.Org = info.ISP
				}
			}
		}
	}

	if info.IP == "" {
		return nil, fmt.Errorf("invalid cip.cc response")
	}

	info.Type = CategorizeISP(info.ISP, info.Org, "", info.CountryCode)
	return info, nil
}

// GetTargetISP 查询指定 IP 的运营商画像
func GetTargetISP(ctx context.Context, ip string) (*ISPInfo, error) {
	var body []byte

	// 1. 优先尝试系统 curl（免疫 macOS 本地应用防火墙 LuLu/Little Snitch 拦截）
	if _, err := exec.LookPath("curl"); err == nil {
		targetURL := fmt.Sprintf("http://ip-api.com/json/%s?fields=status,message,country,countryCode,regionName,city,isp,org,as,query", ip)
		out, err := exec.CommandContext(ctx, "curl", "-s", "--max-time", "3", targetURL).Output()
		if err == nil && len(out) > 0 {
			body = out
		}
	}

	// 2. 备选原生 http.Client
	if len(body) == 0 {
		client := &http.Client{Timeout: 3 * time.Second}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("http://ip-api.com/json/%s?fields=status,message,country,countryCode,regionName,city,isp,org,as,query", ip), nil)
		if err == nil {
			if resp, err := client.Do(req); err == nil {
				defer resp.Body.Close()
				body, _ = io.ReadAll(resp.Body)
			}
		}
	}

	if len(body) == 0 {
		return nil, fmt.Errorf("lookup failed for %s", ip)
	}

	var data ipAPIResponse
	if err := json.Unmarshal(body, &data); err != nil || data.Status != "success" {
		return nil, fmt.Errorf("lookup failed for %s", ip)
	}

	info := &ISPInfo{
		IP:          data.Query,
		Country:     data.Country,
		CountryCode: data.CountryCode,
		Region:      data.RegionName,
		City:        data.City,
		ISP:         data.ISP,
		Org:         data.Org,
		ASN:         data.AS,
	}
	info.Type = CategorizeISP(info.ISP, info.Org, info.ASN, info.CountryCode)
	return info, nil
}

func fetchFromIPAPI(ctx context.Context, client *http.Client) (*ISPInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://ip-api.com/json/?fields=status,message,country,countryCode,regionName,city,isp,org,as,query", nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var data ipAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil || data.Status != "success" {
		return nil, fmt.Errorf("ip-api unmarshal error")
	}

	info := &ISPInfo{
		IP:          data.Query,
		Country:     data.Country,
		CountryCode: data.CountryCode,
		Region:      data.RegionName,
		City:        data.City,
		ISP:         data.ISP,
		Org:         data.Org,
		ASN:         data.AS,
	}
	info.Type = CategorizeISP(info.ISP, info.Org, info.ASN, info.CountryCode)
	return info, nil
}

func fetchFromIPSB(ctx context.Context, client *http.Client) (*ISPInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.ip.sb/geoip", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (singctl netdiag)")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var data ipSBResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil || data.IP == "" {
		return nil, fmt.Errorf("ip.sb unmarshal error")
	}

	asnStr := ""
	if data.ASN > 0 {
		asnStr = fmt.Sprintf("AS%d %s", data.ASN, data.ASNOrg)
	}

	info := &ISPInfo{
		IP:          data.IP,
		Country:     data.Country,
		CountryCode: data.CountryCode,
		Region:      data.Region,
		City:        data.City,
		ISP:         data.ISP,
		Org:         data.ASNOrg,
		ASN:         asnStr,
	}
	info.Type = CategorizeISP(info.ISP, info.Org, info.ASN, info.CountryCode)
	return info, nil
}

// CategorizeISP 根据 ISP 字段、ASN、组织及国家分类
func CategorizeISP(isp, org, asn, countryCode string) ISPType {
	combined := strings.ToLower(fmt.Sprintf("%s %s %s", isp, org, asn))

	if strings.Contains(combined, "电信") || strings.Contains(combined, "telecom") || strings.Contains(combined, "chinanet") || strings.Contains(combined, "as4134") || strings.Contains(combined, "as4809") || strings.Contains(combined, "ct-") {
		return ISPTelecom
	}
	if strings.Contains(combined, "联通") || strings.Contains(combined, "unicom") || strings.Contains(combined, "cncgroup") || strings.Contains(combined, "as4837") || strings.Contains(combined, "as9929") || strings.Contains(combined, "as10099") || strings.Contains(combined, "cu-") {
		return ISPUnicom
	}
	if strings.Contains(combined, "移动") || strings.Contains(combined, "铁通") || strings.Contains(combined, "mobile") || strings.Contains(combined, "cmcc") || strings.Contains(combined, "as9808") || strings.Contains(combined, "as58807") || strings.Contains(combined, "tiexintong") {
		return ISPMobile
	}
	if strings.Contains(combined, "广电") || strings.Contains(combined, "教育网") || strings.Contains(combined, "cernet") || strings.Contains(combined, "education") || strings.Contains(combined, "broadnet") || strings.Contains(combined, "as4538") || strings.Contains(combined, "gwbn") {
		return ISPBroadnet
	}

	if countryCode != "" && countryCode != "CN" {
		return ISPOverseas
	}
	return ISPOverseas
}
