// 文件职责：负责 SubHub 订阅原始载荷（URI 列表 / Base64 包装 / Sing-box JSON / Clash YAML）的策略链解码、协议链接归一化与类型安全转换。
//
// 架构设计原则：
//   - 开闭原则（OCP）：通过 subscriptionPayloadDecoder 切片定义有序格式解析链，后续新增订阅格式（如 SIP008、Surfboard）
//     只需新增独立策略器并挂载到 defaultPayloadDecoders，无需改写主解析入口。
//   - 纯函数式解码核心：全部解析逻辑零磁盘、零网络副作用，配合 maxRemoteSubBytes 边界防御防止恶意超大载荷 OOM。
package subhub

import (
	"cmp"
	"context"
	"encoding/base64"
	"encoding/json"
	"math"
	"net/url"
	"strconv"
	"strings"

	"github.com/sixban6/singgen/pkg/model"
	"github.com/sixban6/singgen/pkg/singgen"
	"gopkg.in/yaml.v3"
)

// subscriptionPayloadDecoder 描述单种订阅格式的匹配规则与解码器实现。
type subscriptionPayloadDecoder struct {
	Name   string
	Match  func(text string) bool
	Decode func(ctx context.Context, text string) ([]model.Node, []string)
}

var supportedURISchemes = []string{
	"vless://",
	"vmess://",
	"trojan://",
	"hysteria2://",
	"hy2://",
	"ss://",
	"tuic://",
	"anytls://",
}

// ParseRawSubscriptionPayload parses raw URI lists, Base64 URI blobs, Clash YAML, or Sing-box JSON into nodes and canonical URIs.
func ParseRawSubscriptionPayload(ctx context.Context, raw []byte) ([]model.Node, []string) {
	return decodeRawSubscriptionWithChain(ctx, raw)
}

// decodeRawSubscriptionWithChain 执行标准化预处理（尺寸护栏 + Base64 解包）后，按优先级顺序尝试可扩展解码器链。
func decodeRawSubscriptionWithChain(ctx context.Context, raw []byte, extraDecoders ...subscriptionPayloadDecoder) ([]model.Node, []string) {
	if len(raw) == 0 || len(raw) > maxRemoteSubBytes {
		return nil, nil
	}
	text := strings.TrimSpace(string(raw))
	if text == "" {
		return nil, nil
	}
	if decoded, ok := decodeBase64Flexible(text); ok {
		text = strings.TrimSpace(decoded)
	}

	chain := make([]subscriptionPayloadDecoder, 0, len(extraDecoders)+3)
	// 调用方注入的自定义扩展解码器优先尝试，保证 OCP 横向扩展优先级
	chain = append(chain, extraDecoders...)
	chain = append(chain, defaultPayloadDecoders()...)

	for _, dec := range chain {
		_ = dec.Name
		if dec.Match != nil && !dec.Match(text) {
			continue
		}
		if nodes, uris := dec.Decode(ctx, text); len(nodes) > 0 || len(uris) > 0 {
			return nodes, uris
		}
	}
	return nil, nil
}

func defaultPayloadDecoders() []subscriptionPayloadDecoder {
	return []subscriptionPayloadDecoder{
		{
			Name: "uri_lines",
			Match: func(text string) bool {
				return strings.Contains(text, "://")
			},
			Decode: decodeURILinesPayload,
		},
		{
			Name: "singbox_json",
			Match: func(text string) bool {
				return strings.HasPrefix(text, "{") && strings.Contains(text, `"outbounds"`)
			},
			Decode: func(_ context.Context, text string) ([]model.Node, []string) {
				nodes := parseSingBoxJSONOutbounds(text)
				if len(nodes) == 0 {
					return nil, nil
				}
				return nodes, synthURIsFromNodes(nodes)
			},
		},
		{
			Name: "clash_yaml",
			Match: func(text string) bool {
				return strings.Contains(text, "proxies:")
			},
			Decode: func(_ context.Context, text string) ([]model.Node, []string) {
				nodes := parseClashYAMLProxies(text)
				if len(nodes) == 0 {
					return nil, nil
				}
				return nodes, synthURIsFromNodes(nodes)
			},
		},
	}
}

func decodeURILinesPayload(ctx context.Context, text string) ([]model.Node, []string) {
	var uris []string
	for line := range strings.SplitSeq(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		l := strings.TrimSpace(line)
		if l == "" || strings.HasPrefix(l, "#") || strings.HasPrefix(l, "//") {
			continue
		}
		if hasSupportedScheme(l) {
			uris = append(uris, normalizeShareURI(l))
		}
	}
	if len(uris) == 0 {
		return nil, nil
	}

	parser := singgen.NewContextParser(singgen.GenerateOptions{})
	cleanInput := strings.Join(uris, "\n")
	if nodes, err := parser.Parse(ctx, []byte(cleanInput)); err == nil && len(nodes) > 0 {
		return nodes, uris
	}
	// 单行降级容错：防止某一条畸形链接导致整批健康节点解析失败
	var lineNodes []model.Node
	for _, u := range uris {
		if n, lErr := parser.Parse(ctx, []byte(u)); lErr == nil && len(n) > 0 {
			lineNodes = append(lineNodes, n...)
		}
	}
	return lineNodes, uris
}

func synthURIsFromNodes(nodes []model.Node) []string {
	synthURIs := make([]string, 0, len(nodes))
	for _, n := range nodes {
		if u := NodeToURI(n); u != "" {
			synthURIs = append(synthURIs, u)
		}
	}
	return synthURIs
}

func hasSupportedScheme(line string) bool {
	lower := strings.ToLower(strings.TrimSpace(line))
	for _, p := range supportedURISchemes {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	return false
}

func decodeRawBase64Bytes(s string) ([]byte, bool) {
	compact := strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, strings.TrimSpace(s))
	if compact == "" {
		return nil, false
	}
	stripped := strings.TrimRight(compact, "=")
	for _, enc := range []*base64.Encoding{
		base64.RawStdEncoding,
		base64.RawURLEncoding,
		base64.StdEncoding,
		base64.URLEncoding,
	} {
		target := compact
		if enc == base64.RawStdEncoding || enc == base64.RawURLEncoding {
			target = stripped
		}
		if b, err := enc.DecodeString(target); err == nil && len(b) > 0 {
			return b, true
		}
	}
	return nil, false
}

func decodeBase64Flexible(s string) (string, bool) {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" || strings.Contains(trimmed, "://") || strings.Contains(trimmed, "proxies:") || strings.HasPrefix(trimmed, "{") {
		return "", false
	}
	if b, ok := decodeRawBase64Bytes(trimmed); ok {
		decoded := string(b)
		if strings.Contains(decoded, "://") || strings.Contains(decoded, "proxies:") || strings.Contains(decoded, `"outbounds"`) {
			return decoded, true
		}
	}
	return "", false
}

// normalizeShareURI ensures legacy ss:// links, URL-safe SIP002 ss:// userinfo, and raw non-ASCII
// fragments are normalized into RFC 3986 ASCII URIs compatible with singgen and all proxy clients.
func normalizeShareURI(rawLine string) string {
	line := strings.TrimSpace(rawLine)
	if line == "" {
		return ""
	}
	lower := strings.ToLower(line)
	if strings.HasPrefix(lower, "vmess://") {
		return line
	}

	mainPart := line
	frag := ""
	hasFrag := false
	if idx := strings.IndexByte(line, '#'); idx >= 0 {
		mainPart = line[:idx]
		frag = line[idx+1:]
		hasFrag = true
		needsEscape := false
		for _, r := range frag {
			if r <= ' ' || r >= 128 {
				needsEscape = true
				break
			}
		}
		if needsEscape {
			if unesc, err := url.PathUnescape(frag); err == nil {
				frag = unesc
			}
			frag = url.PathEscape(frag)
		}
	}

	if strings.HasPrefix(lower, "ss://") {
		beforeQuery := mainPart
		querySuffix := ""
		if qIdx := strings.IndexByte(mainPart, '?'); qIdx >= 0 {
			beforeQuery = mainPart[:qIdx]
			querySuffix = mainPart[qIdx:]
		}
		ssBody := beforeQuery[5:]
		if !strings.Contains(ssBody, "@") {
			// Legacy ss://BASE64(method:password@host:port)#tag
			if unesc, err := url.PathUnescape(ssBody); err == nil {
				ssBody = unesc
			}
			if decoded, ok := decodeRawBase64Bytes(ssBody); ok {
				decStr := string(decoded)
				if lastAt := strings.LastIndexByte(decStr, '@'); lastAt > 0 && strings.Contains(decStr[:lastAt], ":") {
					credPlain := decStr[:lastAt]
					hostPort := decStr[lastAt+1:]
					b64 := strings.ReplaceAll(base64.RawStdEncoding.EncodeToString([]byte(credPlain)), "/", "%2F")
					mainPart = "ss://" + b64 + "@" + hostPort + querySuffix
				}
			}
		} else {
			// SIP002 ss://userinfo@host:port — normalize URL-safe '-'/'_' Base64 into StdEncoding with %2F
			lastAt := strings.LastIndexByte(ssBody, '@')
			userPart := ssBody[:lastAt]
			hostPort := ssBody[lastAt+1:]
			if !strings.Contains(userPart, ":") && strings.ContainsAny(userPart, "-_") {
				unescUser := userPart
				if u, err := url.PathUnescape(userPart); err == nil {
					unescUser = u
				}
				if decoded, ok := decodeRawBase64Bytes(unescUser); ok && strings.Contains(string(decoded), ":") {
					b64 := strings.ReplaceAll(base64.RawStdEncoding.EncodeToString(decoded), "/", "%2F")
					mainPart = "ss://" + b64 + "@" + hostPort + querySuffix
				}
			}
		}
	}

	if hasFrag {
		return mainPart + "#" + frag
	}
	return mainPart
}

func parseSingBoxJSONOutbounds(jsonText string) []model.Node {
	var doc struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	if err := json.Unmarshal([]byte(jsonText), &doc); err != nil || len(doc.Outbounds) == 0 {
		return nil
	}

	var nodes []model.Node
	for _, ob := range doc.Outbounds {
		typ := strings.ToLower(asString(ob["type"]))
		switch typ {
		case "", "direct", "block", "dns", "selector", "urltest":
			continue
		}

		server := asString(ob["server"])
		port := asUint16(ob["server_port"])
		if server == "" || port == 0 {
			continue
		}

		n := model.Node{
			Tag:   asString(ob["tag"]),
			Addr:  server,
			Port:  port,
			Extra: make(map[string]any),
		}

		if tlsObj, ok := ob["tls"].(map[string]any); ok {
			n.Security.TLS = asBool(tlsObj["enabled"])
			n.Security.SkipVerify = asBool(tlsObj["insecure"])
			n.Security.ServerName = asString(tlsObj["server_name"])
			switch alpn := tlsObj["alpn"].(type) {
			case []any:
				for _, item := range alpn {
					if s := asString(item); s != "" {
						n.Security.ALPN = append(n.Security.ALPN, s)
					}
				}
			case string:
				if s := strings.TrimSpace(alpn); s != "" {
					n.Security.ALPN = []string{s}
				}
			}
			if utlsObj, ok := tlsObj["utls"].(map[string]any); ok {
				if fp := asString(utlsObj["fingerprint"]); fp != "" {
					n.Extra["fingerprint"] = fp
				}
			}
			if realityObj, ok := tlsObj["reality"].(map[string]any); ok {
				pk := asString(realityObj["public_key"])
				if asBool(realityObj["enabled"]) || pk != "" {
					n.Security.TLS = true
					n.Extra["security"] = "reality"
					n.Extra["public_key"] = pk
					n.Extra["short_id"] = asString(realityObj["short_id"])
				}
			}
		}

		if trObj, ok := ob["transport"].(map[string]any); ok {
			n.Transport.Net = asString(trObj["type"])
			n.Transport.Path = cmp.Or(asString(trObj["path"]), asString(trObj["service_name"]))
			switch h := trObj["host"].(type) {
			case string:
				n.Transport.Host = strings.TrimSpace(h)
			case []any:
				if len(h) > 0 {
					n.Transport.Host = asString(h[0])
				}
			}
			if n.Transport.Host == "" {
				if hdrs, ok := trObj["headers"].(map[string]any); ok {
					n.Transport.Host = cmp.Or(asString(hdrs["Host"]), asString(hdrs["host"]))
				}
			}
		}

		switch typ {
		case "vless":
			n.Type = "vless"
			n.UUID = asString(ob["uuid"])
			if flow := asString(ob["flow"]); flow != "" {
				n.Extra["flow"] = flow
			}
		case "hysteria2":
			n.Type = "hysteria2"
			n.Password = asString(ob["password"])
			n.Security.TLS = true
			if obfsObj, ok := ob["obfs"].(map[string]any); ok {
				if obfsType := asString(obfsObj["type"]); obfsType != "" {
					n.Extra["obfs"] = map[string]string{
						"type":     obfsType,
						"password": asString(obfsObj["password"]),
					}
				}
			}
		case "anytls":
			n.Type = "anytls"
			n.Password = asString(ob["password"])
			n.Security.TLS = true
			for _, k := range []string{"idle_session_check_interval", "idle_session_timeout"} {
				if v := asString(ob[k]); v != "" {
					n.Extra[k] = v
				}
			}
			if minIdle := asUint16(ob["min_idle_session"]); minIdle > 0 {
				n.Extra["min_idle_session"] = int(minIdle)
			}
		case "shadowsocks", "ss":
			n.Type = "shadowsocks"
			n.Password = asString(ob["password"])
			n.Extra["method"] = cmp.Or(asString(ob["method"]), "aes-256-gcm")
		case "trojan":
			n.Type = "trojan"
			n.Password = asString(ob["password"])
			n.Security.TLS = true
		case "vmess":
			n.Type = "vmess"
			n.UUID = asString(ob["uuid"])
		case "tuic":
			n.Type = "tuic"
			n.UUID = asString(ob["uuid"])
			n.Password = asString(ob["password"])
			n.Security.TLS = true
			if cc := asString(ob["congestion_control"]); cc != "" {
				n.Extra["congestion_control"] = cc
			}
			if udpMode := asString(ob["udp_relay_mode"]); udpMode != "" {
				n.Extra["udp_relay_mode"] = udpMode
			}
		default:
			continue
		}
		nodes = append(nodes, n)
	}
	return nodes
}

func parseClashYAMLProxies(yamlText string) []model.Node {
	var doc struct {
		Proxies []map[string]any `yaml:"proxies"`
	}
	if err := yaml.Unmarshal([]byte(yamlText), &doc); err != nil || len(doc.Proxies) == 0 {
		return nil
	}

	var nodes []model.Node
	for _, p := range doc.Proxies {
		typ := strings.ToLower(asString(p["type"]))
		name := asString(p["name"])
		server := asString(p["server"])
		port := asUint16(p["port"])
		if server == "" || port == 0 {
			continue
		}

		n := model.Node{
			Tag:   name,
			Addr:  server,
			Port:  port,
			Extra: make(map[string]any),
		}
		n.Security.SkipVerify = asBool(p["skip-cert-verify"])
		n.Security.ServerName = cmp.Or(asString(p["servername"]), asString(p["sni"]))
		if alpn, ok := p["alpn"].([]any); ok {
			for _, a := range alpn {
				if s := asString(a); s != "" {
					n.Security.ALPN = append(n.Security.ALPN, s)
				}
			}
		}
		if netType := asString(p["network"]); netType != "" {
			n.Transport.Net = netType
		}
		if wsOpts, ok := p["ws-opts"].(map[string]any); ok {
			n.Transport.Path = asString(wsOpts["path"])
			if hdrs, ok := wsOpts["headers"].(map[string]any); ok {
				n.Transport.Host = asString(hdrs["Host"])
			}
		}

		switch typ {
		case "vless":
			n.Type = "vless"
			n.UUID = asString(p["uuid"])
			n.Security.TLS = asBool(p["tls"])
			if flow := asString(p["flow"]); flow != "" {
				n.Extra["flow"] = flow
			}
			if fp := asString(p["client-fingerprint"]); fp != "" {
				n.Extra["fingerprint"] = fp
			}
			if ro, ok := p["reality-opts"].(map[string]any); ok {
				n.Security.TLS = true
				n.Extra["security"] = "reality"
				n.Extra["public_key"] = asString(ro["public-key"])
				n.Extra["short_id"] = asString(ro["short-id"])
			}
		case "hysteria2":
			n.Type = "hysteria2"
			n.Password = asString(p["password"])
			n.Security.TLS = true
			if obfs := asString(p["obfs"]); obfs != "" {
				n.Extra["obfs"] = map[string]string{
					"type":     obfs,
					"password": asString(p["obfs-password"]),
				}
			}
		case "trojan":
			n.Type = "trojan"
			n.Password = asString(p["password"])
			n.Security.TLS = true
		case "ss":
			n.Type = "shadowsocks"
			n.Password = asString(p["password"])
			n.Extra["method"] = asString(p["cipher"])
		case "vmess":
			n.Type = "vmess"
			n.UUID = asString(p["uuid"])
			n.Security.TLS = asBool(p["tls"])
		case "tuic":
			n.Type = "tuic"
			n.UUID = asString(p["uuid"])
			n.Password = asString(p["password"])
			n.Security.TLS = true
		case "anytls":
			n.Type = "anytls"
			n.Password = asString(p["password"])
			n.Security.TLS = true
		default:
			continue
		}
		nodes = append(nodes, n)
	}
	return nodes
}

func asString(v any) string {
	switch x := v.(type) {
	case string:
		return strings.TrimSpace(x)
	case int:
		return strconv.Itoa(x)
	case int64:
		return strconv.FormatInt(x, 10)
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) || x < -1e15 || x > 1e15 {
			return ""
		}
		return strconv.FormatInt(int64(x), 10)
	default:
		return ""
	}
}

func asUint16(v any) uint16 {
	switch x := v.(type) {
	case int:
		if x > 0 && x <= 65535 {
			return uint16(x)
		}
	case int64:
		if x > 0 && x <= 65535 {
			return uint16(x)
		}
	case float64:
		if x > 0 && x <= 65535 {
			return uint16(x)
		}
	case string:
		if p, err := strconv.Atoi(strings.TrimSpace(x)); err == nil && p > 0 && p <= 65535 {
			return uint16(p)
		}
	}
	return 0
}

func asBool(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return strings.EqualFold(x, "true") || x == "1"
	default:
		return false
	}
}
