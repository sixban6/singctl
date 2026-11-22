// 文件职责：维护全球 ISO-3166-1 国家/地区中文名称映射、国旗 Emoji 转换及内网/文档保留地址判定纯函数。
package serverweb

import (
	"cmp"
	"fmt"
	"net"
	"strings"
)

// 全球常见及高频扫描来源国家/地区 ISO-3166-1 二位码中文名称表
var commonCountryNames = map[string]string{
	"CN": "中国",
	"HK": "中国香港",
	"TW": "中国台湾",
	"MO": "中国澳门",
	"US": "美国",
	"JP": "日本",
	"SG": "新加坡",
	"KR": "韩国",
	"KP": "朝鲜",
	"GB": "英国",
	"DE": "德国",
	"FR": "法国",
	"NL": "荷兰",
	"RU": "俄罗斯",
	"CA": "加拿大",
	"AU": "澳大利亚",
	"NZ": "新西兰",
	"IN": "印度",
	"BR": "巴西",
	"VN": "越南",
	"ID": "印度尼西亚",
	"TH": "泰国",
	"MY": "马来西亚",
	"PH": "菲律宾",
	"PK": "巴基斯坦",
	"BD": "孟加拉国",
	"LK": "斯里兰卡",
	"NP": "尼泊尔",
	"MM": "缅甸",
	"KH": "柬埔寨",
	"LA": "老挝",
	"MN": "蒙古",
	"KZ": "哈萨克斯坦",
	"UZ": "乌兹别克斯坦",
	"KG": "吉尔吉斯斯坦",
	"TJ": "塔吉克斯坦",
	"TM": "土库曼斯坦",
	"IT": "意大利",
	"ES": "西班牙",
	"PT": "葡萄牙",
	"SE": "瑞典",
	"NO": "挪威",
	"FI": "芬兰",
	"DK": "丹麦",
	"IS": "冰岛",
	"CH": "瑞士",
	"AT": "奥地利",
	"BE": "比利时",
	"LU": "卢森堡",
	"IE": "爱尔兰",
	"PL": "波兰",
	"CZ": "捷克",
	"SK": "斯洛伐克",
	"HU": "匈牙利",
	"RO": "罗马尼亚",
	"BG": "保加利亚",
	"UA": "乌克兰",
	"BY": "白俄罗斯",
	"MD": "摩尔多瓦",
	"LT": "立陶宛",
	"LV": "拉脱维亚",
	"EE": "爱沙尼亚",
	"GR": "希腊",
	"TR": "土耳其",
	"CY": "塞浦路斯",
	"MT": "马耳他",
	"RS": "塞尔维亚",
	"HR": "克罗地亚",
	"SI": "斯洛文尼亚",
	"BA": "波黑",
	"AL": "阿尔巴尼亚",
	"MK": "北马其顿",
	"ME": "黑山",
	"GE": "格鲁吉亚",
	"AM": "亚美尼亚",
	"AZ": "阿塞拜疆",
	"IL": "以色列",
	"AE": "阿联酋",
	"SA": "沙特阿拉伯",
	"IR": "伊朗",
	"IQ": "伊拉克",
	"QA": "卡塔尔",
	"KW": "科威特",
	"OM": "阿曼",
	"BH": "巴林",
	"JO": "约旦",
	"LB": "黎巴嫩",
	"SY": "叙利亚",
	"YE": "也门",
	"AF": "阿富汗",
	"ZA": "南非",
	"EG": "埃及",
	"NG": "尼日利亚",
	"KE": "肯尼亚",
	"ET": "埃塞俄比亚",
	"MA": "摩洛哥",
	"DZ": "阿尔及利亚",
	"TN": "突尼斯",
	"GH": "加纳",
	"TZ": "坦桑尼亚",
	"UG": "乌干达",
	"MU": "毛里求斯",
	"SC": "塞舌尔",
	"MX": "墨西哥",
	"AR": "阿根廷",
	"CL": "智利",
	"CO": "哥伦比亚",
	"PE": "秘鲁",
	"VE": "委内瑞拉",
	"EC": "厄瓜多尔",
	"UY": "乌拉圭",
	"PY": "巴拉圭",
	"BO": "玻利维亚",
	"PA": "巴拿马",
	"CR": "哥斯达黎加",
	"DO": "多米尼加",
	"GT": "危地马拉",
	"HN": "洪都拉斯",
	"SV": "萨尔瓦多",
	"NI": "尼加拉瓜",
	"CU": "古巴",
	"PR": "波多黎各",
	"JM": "牙买加",
	"TT": "特立尼达和多巴哥",
	"BS": "巴哈马",
	"BZ": "伯利兹",
}

// CountryCodeToFlag 将 2 位 ISO 国家代码转换为对应的国旗 Emoji
func CountryCodeToFlag(code string) string {
	code = strings.ToUpper(strings.TrimSpace(code))
	if len(code) != 2 || code[0] < 'A' || code[0] > 'Z' || code[1] < 'A' || code[1] > 'Z' {
		return ""
	}
	r1 := rune(code[0]) - 'A' + 0x1F1E6
	r2 := rune(code[1]) - 'A' + 0x1F1E6
	return string([]rune{r1, r2})
}

func resolveCountryDisplayName(countryCode, rawCountry string) string {
	code := strings.ToUpper(strings.TrimSpace(countryCode))
	if cn, ok := commonCountryNames[code]; ok {
		return cn
	}
	return cmp.Or(strings.TrimSpace(rawCountry), code)
}

func FormatGeoLabel(countryCode, country, city string) string {
	countryDisplay := resolveCountryDisplayName(countryCode, country)
	city = strings.TrimSpace(city)
	if city != "" && countryDisplay != "" && !strings.EqualFold(city, country) && city != countryDisplay {
		return fmt.Sprintf("%s · %s", countryDisplay, city)
	}
	if countryDisplay != "" {
		return countryDisplay
	}
	return city
}

func isPrivateOrLoopbackIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return true
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsLinkLocalUnicast()
}

// isRFC5737DocumentationIP 判断是否为测试专用保留网段 (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
func isRFC5737DocumentationIP(ipStr string) bool {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return false
	}
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	return (v4[0] == 192 && v4[1] == 0 && v4[2] == 2) ||
		(v4[0] == 198 && v4[1] == 51 && v4[2] == 100) ||
		(v4[0] == 203 && v4[1] == 0 && v4[2] == 113)
}
