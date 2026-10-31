package netdiag

import (
	"fmt"
	"strings"
)

// BackboneTag 跳点特征
type BackboneTag struct {
	Tag     string
	Carrier string
	Route   string
	ASN     string
	Notes   string
}

// InspectHop 根据 IP 和主机名识别骨干网特征
func InspectHop(ip, host string) (tag string, carrier string, route string, asn string) {
	cleanIP := strings.TrimSpace(ip)
	lowerHost := strings.ToLower(host)

	// 1. 电信 CN2 (AS4809) - 59.43.*.*
	if strings.HasPrefix(cleanIP, "59.43.") || strings.Contains(lowerHost, "59.43.") {
		return "CN2 (59.43)", "中国电信", "CN2", "AS4809"
	}

	// 2. 电信 163 (AS4134) - 202.97.*.*
	if strings.HasPrefix(cleanIP, "202.97.") || strings.Contains(lowerHost, "202.97.") {
		return "163 (202.97)", "中国电信", "163", "AS4134"
	}

	// 3. 联通 9929 / A 网 (AS9929) - 218.105.*.*, 210.51.*.*
	if strings.HasPrefix(cleanIP, "218.105.") || strings.HasPrefix(cleanIP, "210.51.") ||
		strings.Contains(lowerHost, "218.105.") || strings.Contains(lowerHost, "210.51.") {
		return "9929 (CU-Premium)", "中国联通", "9929", "AS9929"
	}

	// 4. 联通 169 (AS4837) - 219.158.*.*
	if strings.HasPrefix(cleanIP, "219.158.") || strings.Contains(lowerHost, "219.158.") {
		return "4837 (CU-169)", "中国联通", "4837", "AS4837"
	}

	// 5. 移动 CMIN2 (AS58807) - 223.120.*.*
	if strings.HasPrefix(cleanIP, "223.120.") || strings.Contains(lowerHost, "223.120.") {
		return "CMIN2 (223.120)", "中国移动", "CMIN2", "AS58807"
	}

	// 6. 移动 CMI (AS9808) - 221.183.*.*, 221.179.*.*, 183.91.*.*
	if strings.HasPrefix(cleanIP, "221.183.") || strings.HasPrefix(cleanIP, "221.179.") || strings.HasPrefix(cleanIP, "183.91.") ||
		strings.Contains(lowerHost, "cmi.chinamobile") {
		return "CMI (AS9808)", "中国移动", "CMI", "AS9808"
	}

	// 7. 联通国际 CUG (AS10099)
	if strings.Contains(lowerHost, "10099") || strings.Contains(lowerHost, "cug.chinaunicom") {
		return "CUG (AS10099)", "中国联通", "10099", "AS10099"
	}

	// 8. 国际常见 Tier 1 / IXP 识别
	switch {
	case strings.Contains(lowerHost, "ntt.net") || strings.Contains(lowerHost, "gin.ntt"):
		return "NTT", "国际中转", "NTT", "AS2914"
	case strings.Contains(lowerHost, "pccw") || strings.Contains(lowerHost, "btn.net"):
		return "PCCW", "国际中转", "PCCW", "AS3491"
	case strings.Contains(lowerHost, "telia") || strings.Contains(lowerHost, "arelion"):
		return "Arelion/Telia", "国际中转", "Arelion", "AS1299"
	case strings.Contains(lowerHost, "he.net") || strings.Contains(lowerHost, "hurricane"):
		return "HE", "国际中转", "HE", "AS6939"
	case strings.Contains(lowerHost, "cogentco.com"):
		return "Cogent", "国际中转", "Cogent", "AS174"
	case strings.Contains(lowerHost, "tatacommunications"):
		return "Tata", "国际中转", "Tata", "AS6453"
	case strings.Contains(lowerHost, "softbank"):
		return "Softbank (软银)", "日本直连", "Softbank", "AS17676"
	case strings.Contains(lowerHost, "iij.net"):
		return "IIJ", "日本直连", "IIJ", "AS2497"
	case strings.Contains(lowerHost, "level3") || strings.Contains(lowerHost, "lumen"):
		return "Lumen", "国际中转", "Lumen", "AS3356"
	}

	return "", "", "", ""
}

// ClassifyRoute 分析整条路由跳点，判定整体跨境线路类别
func ClassifyRoute(hops []HopInfo) (identified string, routeType string, details string) {
	var (
		has59_43  bool
		has202_97 bool
		has4837   bool
		has9929   bool
		has10099  bool
		hasCMI    bool
		hasCMIN2  bool
		overseas  []string
	)

	for _, hop := range hops {
		if hop.IP == "" || hop.IP == "*" {
			continue
		}
		ip := hop.IP
		tag, _, route, _ := InspectHop(ip, hop.Host)

		if strings.HasPrefix(ip, "59.43.") || route == "CN2" {
			has59_43 = true
		}
		if strings.HasPrefix(ip, "202.97.") || route == "163" {
			has202_97 = true
		}
		if strings.HasPrefix(ip, "219.158.") || route == "4837" {
			has4837 = true
		}
		if strings.HasPrefix(ip, "218.105.") || strings.HasPrefix(ip, "210.51.") || route == "9929" {
			has9929 = true
		}
		if route == "10099" {
			has10099 = true
		}
		if route == "CMI" || strings.HasPrefix(ip, "221.183.") || strings.HasPrefix(ip, "221.179.") {
			hasCMI = true
		}
		if route == "CMIN2" || strings.HasPrefix(ip, "223.120.") {
			hasCMIN2 = true
		}
		if tag == "NTT" || tag == "PCCW" || tag == "Arelion/Telia" || tag == "HE" || tag == "Cogent" || tag == "Softbank (软银)" || tag == "IIJ" {
			overseas = append(overseas, tag)
		}
	}

	// 1. 电信路线判别
	if has59_43 && !has202_97 {
		return "电信 CN2 GIA (AS4809 精品骨干网)", "CN2_GIA", "全程途经 59.43.*.* 节点，无 202.97 拥堵骨干跳点，晚高峰稳定性极高"
	}
	if has59_43 && has202_97 {
		return "电信 CN2 GT (AS4809 半程优化)", "CN2_GT", "国内省级节点走 163 (202.97)，国际出海口接入 CN2 (59.43)，晚高峰表现居中"
	}
	if has202_97 && !has59_43 {
		return "电信 163 传统骨干网 (AS4134)", "163", "全程途经 202.97.*.*，晚高峰国际出口拥堵严重，丢包率较高"
	}

	// 2. 联通路线判别
	if has9929 || has10099 {
		if has10099 {
			return "联通 CUG 10099 / 9929 (政企精品网)", "CU9929", "途经 AS10099/AS9929 精品出口，晚高峰极其平稳，媲美 CN2 GIA"
		}
		return "联通 9929 A网 (AS9929 CU-Premium)", "CU9929", "途经 218.105/210.51 节点，专线级品质，晚高峰极度稳定"
	}
	if has4837 {
		return "联通 169 普通骨干网 (AS4837)", "CU4837", "途经 219.158.*.*，容量大性价比高，晚高峰中等负载"
	}

	// 3. 移动路线判别
	if hasCMIN2 {
		return "移动 CMIN2 (AS58807 精品骨干网)", "CMIN2", "途经 223.120.*.*，移动高端精品线路，晚高峰极速稳定"
	}
	if hasCMI {
		return "移动 CMI (AS9808 国际骨干网)", "CMI", "途经 221.183/221.179，亚太地区（港/新/日）直连极佳，欧美一般"
	}

	// 4. 国际中转/直连
	if len(overseas) > 0 {
		transit := overseas[0]
		return fmt.Sprintf("国际转接 / 直连 (%s)", transit), "TIER1", fmt.Sprintf("出境后经由 %s 骨干网传输，受国际互联及本地运营商出口影响", transit)
	}

	return "普通国际互联线路", "UNKNOWN", "未检测到典型的三网精品骨干跳点，走普通公网 BGP 互联"
}
