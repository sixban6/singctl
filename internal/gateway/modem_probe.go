// 文件职责：负责多跳私网链路追踪、HTTP 登录页跟随跳转探测及运营商真光猫与家用路由器指纹分类。
package gateway

import (
	"cmp"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

var metaRefreshURLRe = regexp.MustCompile(`(?is)<meta[^>]*http-equiv\s*=\s*["']?refresh["']?[^>]*content\s*=\s*["']?[^"']*?url\s*=\s*([^"'>;\s]+)`)

func extractMetaRefreshPath(body, ip string) string {
	m := metaRefreshURLRe.FindStringSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	raw := strings.TrimSpace(strings.Trim(m[1], `"'`))
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	if u.Host != "" && u.Hostname() != ip {
		return ""
	}
	path := u.EscapedPath()
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if u.RawQuery != "" {
		path += "?" + u.RawQuery
	}
	return path
}

func fetchProbePage(ctx context.Context, cli *http.Client, targetURL string) (int, http.Header, string, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return 0, nil, "", 0, err
	}
	start := time.Now()
	resp, err := cli.Do(req)
	if err != nil {
		return 0, nil, "", 0, err
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	ms := int(time.Since(start).Milliseconds())
	if ms < 1 {
		ms = 1
	}
	return resp.StatusCode, resp.Header, string(bodyBytes), ms, nil
}

func defaultModemHTTPProbe(ctx context.Context, scheme, ip string, port int) (int, http.Header, string, int, error) {
	tr := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives: true,
	}
	defer tr.CloseIdleConnections()

	cli := &http.Client{
		Transport: tr,
		Timeout:   900 * time.Millisecond,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	baseURL := fmt.Sprintf("%s://%s:%d", scheme, ip, port)
	curURL := baseURL + "/"
	mergedHdrs := make(http.Header)
	var bodies []string
	var lastCode, totalMS int

	for hop := range 3 {
		code, hdrs, body, ms, err := fetchProbePage(ctx, cli, curURL)
		if err != nil {
			if hop == 0 {
				return 0, nil, "", 0, err
			}
			break
		}
		lastCode = code
		totalMS += ms
		for k, vals := range hdrs {
			for _, v := range vals {
				mergedHdrs.Add(k, v)
			}
		}
		if body != "" {
			bodies = append(bodies, body)
		}

		nextPath := ""
		if code >= 300 && code < 400 {
			if loc := strings.TrimSpace(hdrs.Get("Location")); loc != "" {
				if locURL, lErr := url.Parse(loc); lErr == nil && (locURL.Host == "" || locURL.Hostname() == ip) {
					nextPath = cmp.Or(locURL.RequestURI(), "/")
				}
			}
		} else if code == http.StatusOK && len(body) < 2048 {
			nextPath = extractMetaRefreshPath(body, ip)
		}
		if nextPath == "" {
			break
		}
		if !strings.HasPrefix(nextPath, "/") {
			nextPath = "/" + nextPath
		}
		if baseURL+nextPath == curURL {
			break
		}
		curURL = baseURL + nextPath
	}

	if totalMS < 1 {
		totalMS = 1
	}
	return lastCode, mergedHdrs, strings.Join(bodies, "\n"), totalMS, nil
}

func defaultTracePrivateHops(ctx context.Context, hasCmd func(string) bool, runCmd func(context.Context, string, ...string) ([]byte, error)) []string {
	if !hasCmd("traceroute") {
		return nil
	}
	// Give traceroute sufficient time to finish naturally so stdout isn't lost to buffering on timeout.
	tCtx, cancel := context.WithTimeout(ctx, 5500*time.Millisecond)
	defer cancel()
	out, err := runCmd(tCtx, "traceroute", "-n", "-m", "5", "-q", "1", "-w", "1", "223.5.5.5")
	if len(out) == 0 && err != nil {
		return nil
	}
	return ParseTraceroutePrivateHops(string(out))
}

// ParseTraceroutePrivateHops 解析 traceroute 文本输出，按跳数顺序提取进入公网/CGNAT 前的去重私网 IPv4 列表。
func ParseTraceroutePrivateHops(raw string) []string {
	var hops []string
	for line := range strings.SplitSeq(raw, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 2 {
			continue
		}
		hopNum, err := strconv.Atoi(fields[0])
		if err != nil || hopNum <= 0 {
			continue
		}
		for _, f := range fields[1:] {
			tok := strings.Trim(f, "(),:")
			addr, pErr := netip.ParseAddr(tok)
			if pErr != nil || !addr.Is4() {
				continue
			}
			if addr.IsLoopback() || addr.IsUnspecified() || addr.IsMulticast() {
				break
			}
			if !isRFC1918Private(addr) {
				return hops
			}
			ipStr := addr.String()
			if !slices.Contains(hops, ipStr) {
				hops = append(hops, ipStr)
			}
			break
		}
	}
	return hops
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

var (
	ponKeywordRe        = regexp.MustCompile(`(?i)\b(?:epon|gpon|xg-pon|xgs-pon|10g-epon|loid)\b`)
	huaweiONTModelRe    = regexp.MustCompile(`(?i)\b(?:(?:hg|hs|hn|eg)8\d{3}[a-z0-9]*|k662[a-z0-9]*|b610[a-z0-9]*|v173[a-z0-9]*)\b`)
	zteONTModelRe       = regexp.MustCompile(`(?i)\b(?:zxhn|f460[a-z0-9]*|f6\d{2}[a-z0-9]*|f7\d{3}[a-z0-9]*|g7\d{3}[a-z0-9]*)\b`)
	zteTitleRe          = regexp.MustCompile(`(?is)<title[^>]*>[^<]*\bzte\b[^<]*</title>`)
	fiberhomeONTModelRe = regexp.MustCompile(`(?i)\b(?:fiberhome|hg6\d{3}[a-z0-9]*|an5506[a-z0-9-]*)\b`)
)

func extractCookieNamesLower(headers http.Header) string {
	vals := headers.Values("Set-Cookie")
	if len(vals) == 0 {
		return ""
	}
	names := make([]string, 0, len(vals))
	for _, raw := range vals {
		firstSeg := strings.TrimSpace(strings.SplitN(raw, ";", 2)[0])
		if eqIdx := strings.IndexByte(firstSeg, '='); eqIdx > 0 {
			names = append(names, strings.ToLower(strings.TrimSpace(firstSeg[:eqIdx])))
		}
	}
	return strings.Join(names, " ")
}

// ClassifyGatewayEndpoint 基于 HTTP 响应头与页面源码片段严格区分真光猫（modem）与普通家用路由器（router）。
func ClassifyGatewayEndpoint(headers http.Header, body string) (deviceKind string, vendorHint string) {
	lowerBody := strings.ToLower(body)
	serverHdr := strings.ToLower(headers.Get("Server"))
	cookieNames := extractCookieNamesLower(headers)

	// 0. 优先识别明确的家用/商用路由器专属接口与 Cookie 名（排除随机 Hex 值，避免被移动端 UA 正则或普通英文子串截胡）
	switch {
	case strings.Contains(cookieNames, "sessionid_r3") ||
		containsAny(lowerBody, "/api/system/routerstatus", "/html/smallguide.html") ||
		(strings.Contains(lowerBody, "/api/system/deviceinfo") && strings.Contains(lowerBody, "isrepeater")):
		return DeviceKindRouter, "华为家用路由器"
	case containsAny(lowerBody, "miwifi", "xiaoqiang") || strings.Contains(body, "小米路由器"):
		return DeviceKindRouter, "小米家用路由器"
	case containsAny(lowerBody, "asuswrt", "router.asus.com"):
		return DeviceKindRouter, "华硕家用路由器"
	case containsAny(lowerBody, "tp-link", "tplink", "ikuai", "mikrotik", "routeros"):
		return DeviceKindRouter, "上级家用/商用路由器"
	}

	// 1. 匹配高置信度运营商/光猫词边界特征（覆盖基于定制 LuCI 的电信天翼光猫）
	switch {
	case containsAny(body, "中国电信智能网关", "天翼网关") ||
		containsAny(lowerBody, "logo_tianyi", "telecomadmin") ||
		(strings.Contains(body, "中国电信") && (containsAny(lowerBody, "haspots", "/boaform/admin/formlogin", "usereg.asp") || ponKeywordRe.MatchString(lowerBody))) ||
		(strings.Contains(serverHdr, "boa") && containsAny(lowerBody, "/boaform/admin/formlogin", "usereg.asp")):
		return DeviceKindModem, "中国电信天翼智能光猫"

	case containsAny(lowerBody, "cmccadmin") ||
		(strings.Contains(body, "中国移动") && (containsAny(lowerBody, "haspots") || containsAny(body, "智能网关", "宽带网关", "光猫") || ponKeywordRe.MatchString(lowerBody))):
		return DeviceKindModem, "中国移动定制光猫"

	case containsAny(lowerBody, "cuadmin") ||
		(strings.Contains(body, "中国联通") && (containsAny(lowerBody, "haspots", "wo-home") || containsAny(body, "网关", "光猫") || ponKeywordRe.MatchString(lowerBody))):
		return DeviceKindModem, "中国联通定制光猫"

	case containsAny(lowerBody, "optixstar", "echolife", "ontauthentication", "/asp/getrandcount.asp") || huaweiONTModelRe.MatchString(lowerBody):
		return DeviceKindModem, "华为 OptiXstar / EchoLife 光猫"

	case zteONTModelRe.MatchString(lowerBody) || zteTitleRe.MatchString(lowerBody):
		return DeviceKindModem, "中兴 / ZTE 光猫"

	case fiberhomeONTModelRe.MatchString(lowerBody) || strings.Contains(body, "烽火"):
		return DeviceKindModem, "烽火 / FiberHome 光猫"

	case containsAny(lowerBody, "tewa-", "haspots") || ponKeywordRe.MatchString(lowerBody) || containsAny(body, "天邑", "光猫"):
		return DeviceKindModem, "运营商定制光猫"
	}

	// 2. 通用 OpenWrt / LuCI 路由器兜底与未知设备
	switch {
	case containsAny(lowerBody, "luci", "openwrt", "immortalwrt"):
		return DeviceKindRouter, "OpenWrt 路由器"
	default:
		return DeviceKindUnknown, "标准 Web 网关/光猫"
	}
}
