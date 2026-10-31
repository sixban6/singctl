package netinfo

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

// DefaultClientSubnet 默认兜底的 EDNS Client Subnet（上海电信官方主干 DNS 网段）
const DefaultClientSubnet = "202.96.199.0/24"

// publicAnycastCIDRs 国内外常见的全国/全球性 Anycast 公共 DNS 网段。
// 这些地址不具备省份/城市级运营商代表性，不能直接用作 EDNS client_subnet。
var publicAnycastCIDRs = []string{
	"223.5.5.0/24",     // 阿里公共 DNS
	"223.6.6.0/24",     // 阿里公共 DNS
	"119.29.29.0/24",   // 腾讯 DNSPod 公共 DNS
	"119.28.28.0/24",   // 腾讯 DNSPod 公共 DNS
	"114.114.114.0/24", // 114 公共 DNS
	"114.114.115.0/24", // 114 公共 DNS
	"180.76.76.0/24",   // 百度公共 DNS
	"180.184.1.0/24",   // 火山引擎公共 DNS
	"180.184.2.0/24",   // 火山引擎公共 DNS
	"1.2.4.0/24",       // CNNIC SDNS
	"210.2.4.0/24",     // CNNIC SDNS
	"117.50.10.0/24",   // OneDNS
	"117.50.20.0/24",   // OneDNS
	"8.8.8.0/24",       // Google Public DNS
	"8.8.4.0/24",       // Google Public DNS
	"1.1.1.0/24",       // Cloudflare DNS
	"1.0.0.0/24",       // Cloudflare DNS
	"9.9.9.0/24",       // Quad9 DNS
	"149.112.112.0/24", // Quad9 DNS
	"208.67.222.0/24",  // OpenDNS
	"208.67.220.0/24",  // OpenDNS
	"94.140.14.0/24",   // AdGuard DNS
	"94.140.15.0/24",   // AdGuard DNS
}

// IsPublicAnycastDNS 判断 IP 是否属于无地域属性的全国/全球公共 Anycast DNS。
func IsPublicAnycastDNS(ipStr string) bool {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return false
	}
	for _, cidr := range publicAnycastCIDRs {
		if _, network, err := net.ParseCIDR(cidr); err == nil && network.Contains(ip) {
			return true
		}
	}
	return false
}

// ToIPv4Subnet24 将任意 IPv4 地址掩码归一化为标准 /24 网段（如 202.101.172.35 -> 202.101.172.0/24），
// 抹去主机位（最后一段置 0），确保不暴露具体单机 IP。
func ToIPv4Subnet24(ipStr string) string {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return ""
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return ""
	}
	masked := ip4.Mask(net.CIDRMask(24, 32))
	return fmt.Sprintf("%s/24", masked.String())
}

// ResolveClientSubnet 计算用于 dns_local 的最佳 EDNS Client Subnet：
//  1. 若 dnsServer 本身是运营商下发的省市级公网 DNS（非私网、非公共 Anycast DNS），直接取其 /24 网段（零网络开销、100% 同城同运营商）。
//  2. 若 dnsServer 是内网私有 IP（如在局域网 Linux/Mac 终端运行）或公共 Anycast DNS（如 223.5.5.5），
//     则通过国内直连通道快速识别当前宽带所属「省份/城市 + 运营商」，丢弃用户真实公网 IP，
//     并映射为该省市对应主运营商（电信/联通/移动）的官方主干 DNS /24 网段。
//  3. 离线兜底返回上海电信 202.96.199.0/24。
func ResolveClientSubnet(ctx context.Context, dnsServer string) string {
	if isRegionalISPDNS(dnsServer) {
		if sub := ToIPv4Subnet24(dnsServer); sub != "" {
			return sub
		}
	}

	probeCtx, cancel := context.WithTimeout(ctx, 2500*time.Millisecond)
	defer cancel()

	if region, city, isp := detectDomesticCarrierRegion(probeCtx); region != "" || city != "" || isp != "" {
		if sub := LookupRegionalISPSubnet(region, city, isp); sub != "" {
			return sub
		}
	}

	return DefaultClientSubnet
}

func isRegionalISPDNS(ipStr string) bool {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return false
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	if ip4.IsLoopback() || ip4.IsUnspecified() || ip4.IsMulticast() {
		return false
	}
	if IsPrivateIP(ip4.String()) || isLocalNetwork(ip4) || IsPublicAnycastDNS(ip4.String()) {
		return false
	}
	return true
}

// ispSubnets 某省/市对应的三大运营商代表性官方主 DNS（不含 /24 后缀，由 LookupRegionalISPSubnet 统一转为 .0/24）
type ispSubnets struct {
	Telecom string
	Unicom  string
	Mobile  string
}

// regionalISPDNSTable 全国 31 个省/直辖市及主要城市的三大运营商（电信/联通/移动）官方主 DNS 表。
// 使用各省市运营商公开的省市级 DNS 网段作为 EDNS client_subnet，既能让 CDN 精准定位到同城同 ISP 节点，
// 又完全不暴露用户个人的家庭宽带公网 IP。
var regionalISPDNSTable = map[string]ispSubnets{
	// ── 华东 ──
	"上海": {"202.96.209.0/24", "210.22.70.0/24", "211.136.112.0/24"},
	"浙江": {"202.101.172.0/24", "221.12.1.0/24", "211.140.13.0/24"},
	"杭州": {"202.101.172.0/24", "221.12.1.0/24", "211.140.13.0/24"},
	"宁波": {"202.101.172.0/24", "221.12.33.0/24", "211.140.13.0/24"},
	"温州": {"202.101.172.0/24", "221.12.1.0/24", "211.140.13.0/24"},
	"江苏": {"218.2.135.0/24", "221.6.4.0/24", "221.131.143.0/24"},
	"南京": {"218.2.135.0/24", "221.6.4.0/24", "221.131.143.0/24"},
	"苏州": {"61.177.7.0/24", "221.6.4.0/24", "221.131.143.0/24"},
	"无锡": {"218.2.135.0/24", "221.6.4.0/24", "221.131.143.0/24"},
	"安徽": {"61.132.163.0/24", "218.104.78.0/24", "211.138.180.0/24"},
	"合肥": {"61.132.163.0/24", "218.104.78.0/24", "211.138.180.0/24"},
	"福建": {"218.85.157.0/24", "218.104.128.0/24", "211.138.151.0/24"},
	"福州": {"218.85.157.0/24", "218.104.128.0/24", "211.138.151.0/24"},
	"厦门": {"218.85.152.0/24", "218.104.128.0/24", "211.138.151.0/24"},
	"江西": {"202.101.224.0/24", "220.248.192.0/24", "211.141.90.0/24"},
	"南昌": {"202.101.224.0/24", "220.248.192.0/24", "211.141.90.0/24"},
	"山东": {"219.146.1.0/24", "202.102.128.0/24", "211.137.191.0/24"},
	"济南": {"219.146.1.0/24", "202.102.128.0/24", "211.137.191.0/24"},
	"青岛": {"219.146.0.0/24", "202.102.128.0/24", "211.137.191.0/24"},

	// ── 华南 ──
	"广东": {"202.96.128.0/24", "210.21.196.0/24", "211.136.192.0/24"},
	"广州": {"202.96.128.0/24", "210.21.196.0/24", "211.136.192.0/24"},
	"深圳": {"202.96.134.0/24", "210.21.196.0/24", "211.136.192.0/24"},
	"东莞": {"202.96.128.0/24", "210.21.196.0/24", "211.136.192.0/24"},
	"佛山": {"202.96.128.0/24", "210.21.196.0/24", "211.136.192.0/24"},
	"广西": {"202.103.224.0/24", "221.7.128.0/24", "211.138.240.0/24"},
	"南宁": {"202.103.224.0/24", "221.7.128.0/24", "211.138.240.0/24"},
	"海南": {"202.100.192.0/24", "221.11.132.0/24", "211.138.164.0/24"},
	"海口": {"202.100.192.0/24", "221.11.132.0/24", "211.138.164.0/24"},

	// ── 华北 ──
	"北京":   {"219.141.136.0/24", "202.106.0.0/24", "221.130.33.0/24"},
	"天津":   {"219.150.32.0/24", "202.99.96.0/24", "211.137.160.0/24"},
	"河北":   {"219.148.162.0/24", "202.99.160.0/24", "211.138.13.0/24"},
	"石家庄":  {"219.148.162.0/24", "202.99.160.0/24", "211.138.13.0/24"},
	"山西":   {"219.149.194.0/24", "202.99.192.0/24", "211.138.106.0/24"},
	"太原":   {"219.149.194.0/24", "202.99.192.0/24", "211.138.106.0/24"},
	"内蒙古":  {"202.99.224.0/24", "202.99.224.0/24", "211.138.91.0/24"},
	"呼和浩特": {"202.99.224.0/24", "202.99.224.0/24", "211.138.91.0/24"},

	// ── 华中 ──
	"湖北":  {"202.103.24.0/24", "218.104.111.0/24", "211.137.58.0/24"},
	"武汉":  {"202.103.24.0/24", "218.104.111.0/24", "211.137.58.0/24"},
	"湖南":  {"222.246.129.0/24", "58.20.127.0/24", "211.142.210.0/24"},
	"长沙":  {"222.246.129.0/24", "58.20.127.0/24", "211.142.210.0/24"},
	"河南":  {"222.88.88.0/24", "202.102.224.0/24", "211.138.24.0/24"},
	"郑州":  {"222.88.88.0/24", "202.102.224.0/24", "211.138.24.0/24"},

	// ── 西南 ──
	"四川": {"61.139.2.0/24", "119.6.6.0/24", "211.137.96.0/24"},
	"成都": {"61.139.2.0/24", "119.6.6.0/24", "211.137.96.0/24"},
	"重庆": {"61.128.128.0/24", "221.5.203.0/24", "218.201.4.0/24"},
	"云南": {"222.172.200.0/24", "221.3.131.0/24", "211.139.29.0/24"},
	"昆明": {"222.172.200.0/24", "221.3.131.0/24", "211.139.29.0/24"},
	"贵州": {"202.98.192.0/24", "221.13.28.0/24", "211.139.5.0/24"},
	"贵阳": {"202.98.192.0/24", "221.13.28.0/24", "211.139.5.0/24"},
	"西藏": {"202.98.224.0/24", "221.13.65.0/24", "211.139.73.0/24"},
	"拉萨": {"202.98.224.0/24", "221.13.65.0/24", "211.139.73.0/24"},

	// ── 西北 ──
	"陕西":   {"218.30.19.0/24", "221.11.1.0/24", "211.137.130.0/24"},
	"西安":   {"218.30.19.0/24", "221.11.1.0/24", "211.137.130.0/24"},
	"甘肃":   {"202.100.64.0/24", "221.7.34.0/24", "218.203.160.0/24"},
	"兰州":   {"202.100.64.0/24", "221.7.34.0/24", "218.203.160.0/24"},
	"青海":   {"202.100.128.0/24", "221.207.58.0/24", "211.138.75.0/24"},
	"西宁":   {"202.100.128.0/24", "221.207.58.0/24", "211.138.75.0/24"},
	"宁夏":   {"222.75.152.0/24", "221.199.13.0/24", "218.203.123.0/24"},
	"银川":   {"222.75.152.0/24", "221.199.13.0/24", "218.203.123.0/24"},
	"新疆":   {"61.128.114.0/24", "221.7.1.0/24", "218.202.152.0/24"},
	"乌鲁木齐": {"61.128.114.0/24", "221.7.1.0/24", "218.202.152.0/24"},

	// ── 东北 ──
	"辽宁":   {"219.148.204.0/24", "202.96.64.0/24", "211.137.32.0/24"},
	"沈阳":   {"219.148.204.0/24", "202.96.64.0/24", "211.137.32.0/24"},
	"大连":   {"219.148.204.0/24", "202.96.69.0/24", "211.137.32.0/24"},
	"吉林":   {"219.149.6.0/24", "202.98.0.0/24", "211.137.241.0/24"},
	"长春":   {"219.149.6.0/24", "202.98.0.0/24", "211.137.241.0/24"},
	"黑龙江":  {"219.147.198.0/24", "202.97.224.0/24", "211.137.241.0/24"},
	"哈尔滨":  {"219.147.198.0/24", "202.97.224.0/24", "211.137.241.0/24"},
}

// englishToChineseRegion 常见英文省市名到中文标准键的映射（兼容 ip-api.com 等英文返回）
var englishToChineseRegion = map[string]string{
	"shanghai": "上海", "zhejiang": "浙江", "hangzhou": "杭州", "ningbo": "宁波", "wenzhou": "温州",
	"jiangsu": "江苏", "nanjing": "南京", "suzhou": "苏州", "wuxi": "无锡",
	"anhui": "安徽", "hefei": "合肥", "fujian": "福建", "fuzhou": "福州", "xiamen": "厦门",
	"jiangxi": "江西", "nanchang": "南昌", "shandong": "山东", "jinan": "济南", "qingdao": "青岛",
	"guangdong": "广东", "guangzhou": "广州", "shenzhen": "深圳", "dongguan": "东莞", "foshan": "佛山",
	"guangxi": "广西", "nanning": "南宁", "hainan": "海南", "haikou": "海口",
	"beijing": "北京", "tianjin": "天津", "hebei": "河北", "shijiazhuang": "石家庄",
	"shanxi": "山西", "taiyuan": "太原", "inner mongolia": "内蒙古", "nei mongol": "内蒙古", "hohhot": "呼和浩特",
	"hubei": "湖北", "wuhan": "武汉", "hunan": "湖南", "changsha": "长沙", "henan": "河南", "zhengzhou": "郑州",
	"sichuan": "四川", "chengdu": "成都", "chongqing": "重庆", "yunnan": "云南", "kunming": "昆明",
	"guizhou": "贵州", "guiyang": "贵阳", "tibet": "西藏", "xizang": "西藏", "lhasa": "拉萨",
	"shaanxi": "陕西", "xi'an": "西安", "xian": "西安", "gansu": "甘肃", "lanzhou": "兰州",
	"qinghai": "青海", "xining": "西宁", "ningxia": "宁夏", "yinchuan": "银川",
	"xinjiang": "新疆", "urumqi": "乌鲁木齐",
	"liaoning": "辽宁", "shenyang": "沈阳", "dalian": "大连",
	"jilin": "吉林", "changchun": "长春", "heilongjiang": "黑龙江", "harbin": "哈尔滨",
}

// LookupRegionalISPSubnet 根据「省份/地区 + 城市 + 运营商」查询对应的省市级主运营商 DNS /24 网段。
func LookupRegionalISPSubnet(region, city, isp string) string {
	carrier := classifyCarrier(isp)
	for _, candidate := range []string{normalizeRegionKey(city), normalizeRegionKey(region)} {
		if candidate == "" {
			continue
		}
		if entry, ok := regionalISPDNSTable[candidate]; ok {
			return pickCarrierSubnet(entry, carrier)
		}
		for key, entry := range regionalISPDNSTable {
			if strings.Contains(candidate, key) || strings.Contains(key, candidate) {
				return pickCarrierSubnet(entry, carrier)
			}
		}
	}

	// 若未匹配到具体省市，按运营商返回国家级核心骨干代表网段
	switch carrier {
	case "unicom":
		return "202.106.0.0/24" // 联通骨干（北京联通）
	case "mobile":
		return "211.136.112.0/24" // 移动骨干（上海移动）
	default:
		return DefaultClientSubnet // 电信骨干（上海电信）
	}
}

func normalizeRegionKey(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	lower := strings.ToLower(s)
	for eng, zh := range englishToChineseRegion {
		if lower == eng || strings.Contains(lower, eng) {
			return zh
		}
	}
	for _, suffix := range []string{"壮族自治区", "回族自治区", "维吾尔自治区", "自治区", "特别行政区", "省", "市"} {
		s = strings.TrimSuffix(s, suffix)
	}
	return s
}

func classifyCarrier(isp string) string {
	lower := strings.ToLower(isp)
	switch {
	case strings.Contains(lower, "联通") || strings.Contains(lower, "unicom") || strings.Contains(lower, "cnc") || strings.Contains(lower, "as4837"):
		return "unicom"
	case strings.Contains(lower, "移动") || strings.Contains(lower, "铁通") || strings.Contains(lower, "mobile") || strings.Contains(lower, "cmcc") || strings.Contains(lower, "as9808"):
		return "mobile"
	default:
		return "telecom"
	}
}

func pickCarrierSubnet(e ispSubnets, carrier string) string {
	switch carrier {
	case "unicom":
		if e.Unicom != "" {
			return e.Unicom
		}
	case "mobile":
		if e.Mobile != "" {
			return e.Mobile
		}
	}
	if e.Telecom != "" {
		return e.Telecom
	}
	return DefaultClientSubnet
}

// detectDomesticCarrierRegion 通过国内直连服务探测当前宽带的省份、城市与运营商名称（不保存用户个人公网 IP）。
// 依次尝试：
//  1. myip.ipip.net（国内极速直连，单行返回如 "当前 IP：x.x.x.x  来自于：中国 浙江 杭州  电信"）
//  2. cip.cc（国内直连，返回地址与运营商）
//  3. members.3322.org + ip-api.com
func detectDomesticCarrierRegion(ctx context.Context) (region, city, isp string) {
	if r, c, i := fetchFromIPIPNet(ctx); r != "" || c != "" {
		return r, c, i
	}
	if r, c, i := fetchFromCipCCLite(ctx); r != "" || c != "" {
		return r, c, i
	}
	if r, c, i := fetchFrom3322AndIPAPI(ctx); r != "" || c != "" {
		return r, c, i
	}
	return "", "", ""
}

func fetchFromIPIPNet(ctx context.Context) (region, city, isp string) {
	body := httpGetText(ctx, "http://myip.ipip.net", 1500*time.Millisecond)
	if body == "" {
		return "", "", ""
	}
	return parseIPIPNetOutput(body)
}

// parseIPIPNetOutput 解析 `当前 IP：115.196.x.x  来自于：中国 浙江 杭州  电信`
func parseIPIPNetOutput(body string) (region, city, isp string) {
	idx := strings.Index(body, "来自于：")
	if idx < 0 {
		idx = strings.Index(body, "来自于:")
	}
	if idx < 0 {
		return "", "", ""
	}
	tail := strings.TrimSpace(body[idx:])
	tail = strings.TrimPrefix(tail, "来自于：")
	tail = strings.TrimPrefix(tail, "来自于:")
	fields := strings.Fields(tail)
	// 典型格式: ["中国", "浙江", "杭州", "电信"] 或 ["中国", "上海", "上海", "联通"]
	if len(fields) >= 2 {
		region = fields[1]
	}
	if len(fields) >= 3 {
		city = fields[2]
	}
	if len(fields) >= 4 {
		isp = fields[len(fields)-1]
	} else if len(fields) == 3 {
		isp = fields[2]
	}
	return region, city, isp
}

func fetchFromCipCCLite(ctx context.Context) (region, city, isp string) {
	body := httpGetText(ctx, "http://cip.cc", 1500*time.Millisecond)
	if body == "" {
		return "", "", ""
	}
	for _, line := range strings.Split(body, "\n") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		switch key {
		case "地址":
			fields := strings.Fields(val)
			if len(fields) >= 2 {
				region = fields[1]
			}
			if len(fields) >= 3 {
				city = fields[2]
			}
		case "运营商":
			isp = val
		}
	}
	return region, city, isp
}

func fetchFrom3322AndIPAPI(ctx context.Context) (region, city, isp string) {
	ip := strings.TrimSpace(httpGetText(ctx, "http://members.3322.org/dyndns/getip", 1200*time.Millisecond))
	if net.ParseIP(ip) == nil {
		return "", "", ""
	}
	raw := httpGetText(ctx, fmt.Sprintf("http://ip-api.com/json/%s?lang=zh-CN&fields=status,regionName,city,isp", ip), 1500*time.Millisecond)
	if raw == "" {
		return "", "", ""
	}
	var resp struct {
		Status     string `json:"status"`
		RegionName string `json:"regionName"`
		City       string `json:"city"`
		ISP        string `json:"isp"`
	}
	if err := json.Unmarshal([]byte(raw), &resp); err != nil || resp.Status != "success" {
		return "", "", ""
	}
	return resp.RegionName, resp.City, resp.ISP
}

func httpGetText(ctx context.Context, url string, timeout time.Duration) string {
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err == nil {
		req.Header.Set("User-Agent", "curl/8.0.0")
		client := &http.Client{Timeout: timeout}
		if resp, err := client.Do(req); err == nil {
			defer resp.Body.Close()
			if b, err := io.ReadAll(io.LimitReader(resp.Body, 4096)); err == nil && len(b) > 0 {
				return string(b)
			}
		}
	}

	if _, err := exec.LookPath("curl"); err == nil {
		if out, err := exec.CommandContext(reqCtx, "curl", "-s", "-H", "User-Agent: curl/8.0.0", "--max-time", "2", url).Output(); err == nil && len(out) > 0 {
			return string(out)
		}
	}
	return ""
}
