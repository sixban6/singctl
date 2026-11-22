// 文件职责：集中声明内置 7 种代理协议（VLESS/Hysteria2/Trojan/SS/VMess/TUIC/AnyTLS）的编解码实现。
package subhub

import (
	"cmp"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/sixban6/singgen/pkg/model"
)

func applyClashTransport(p map[string]any, tr model.Transport) {
	netType := strings.ToLower(tr.Net)
	if netType == "" || netType == "tcp" {
		return
	}
	p["network"] = netType
	switch netType {
	case "ws":
		wsOpts := map[string]any{}
		if tr.Path != "" {
			wsOpts["path"] = tr.Path
		}
		if tr.Host != "" {
			wsOpts["headers"] = map[string]string{"Host": tr.Host}
		}
		if len(wsOpts) > 0 {
			p["ws-opts"] = wsOpts
		}
	case "grpc":
		if tr.Path != "" {
			p["grpc-opts"] = map[string]any{"grpc-service-name": tr.Path}
		}
	}
}

func appendSurgeSNIAndSkipVerify(parts []string, sec model.Security) []string {
	if sec.ServerName != "" {
		parts = append(parts, fmt.Sprintf("sni=%s", sec.ServerName))
	}
	if sec.SkipVerify {
		parts = append(parts, "skip-cert-verify=true")
	}
	return parts
}

func builtinProtocolCodecs() []protocolCodec {
	return []protocolCodec{
		{
			Type:       "vless",
			URISchemes: []string{"vless://"},
			DecodeSingBox: func(ob map[string]any, n *model.Node) bool {
				n.UUID = asString(ob["uuid"])
				if flow := asString(ob["flow"]); flow != "" {
					n.Extra["flow"] = flow
				}
				return true
			},
			DecodeClash: func(p map[string]any, n *model.Node) bool {
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
				return true
			},
			EncodeClash: func(n model.Node, p map[string]any, _ RenderOptions) (map[string]any, bool) {
				p["type"] = "vless"
				p["uuid"] = n.UUID
				if flow, ok := n.Extra["flow"].(string); ok && flow != "" {
					p["flow"] = flow
				}
				if n.Security.TLS {
					p["tls"] = true
					p["skip-cert-verify"] = n.Security.SkipVerify
					if n.Security.ServerName != "" {
						p["servername"] = n.Security.ServerName
					}
					if len(n.Security.ALPN) > 0 {
						p["alpn"] = n.Security.ALPN
					}
					fp, _ := n.Extra["fingerprint"].(string)
					p["client-fingerprint"] = cmp.Or(fp, "chrome")
					if sec, _ := n.Extra["security"].(string); sec == "reality" {
						ro := map[string]any{}
						if pk, _ := n.Extra["public_key"].(string); pk != "" {
							ro["public-key"] = pk
						}
						if sid, _ := n.Extra["short_id"].(string); sid != "" {
							ro["short-id"] = sid
						}
						p["reality-opts"] = ro
					}
				}
				applyClashTransport(p, n.Transport)
				return p, true
			},
			EncodeLoonLine: func(n model.Node, tag string, _ RenderOptions) (string, bool) {
				parts := []string{
					fmt.Sprintf("%s = VLESS", tag),
					n.Addr,
					strconv.Itoa(int(n.Port)),
					fmt.Sprintf("\"%s\"", n.UUID),
					"transport=tcp",
				}
				if flow, _ := n.Extra["flow"].(string); flow != "" {
					parts = append(parts, fmt.Sprintf("flow=%s", flow))
				}
				if n.Security.TLS {
					parts = append(parts, "over-tls=true")
					if n.Security.ServerName != "" {
						parts = append(parts, fmt.Sprintf("tls-name=%s", n.Security.ServerName))
					}
					parts = append(parts, fmt.Sprintf("skip-cert-verify=%t", n.Security.SkipVerify))
					if sec, _ := n.Extra["security"].(string); sec == "reality" {
						if pk, _ := n.Extra["public_key"].(string); pk != "" {
							parts = append(parts, fmt.Sprintf("public-key=\"%s\"", pk))
						}
						if sid, _ := n.Extra["short_id"].(string); sid != "" {
							parts = append(parts, fmt.Sprintf("short-id=%s", sid))
						}
					}
				}
				parts = append(parts, "udp=true")
				return strings.Join(parts, ", "), true
			},
			EncodeURI: func(n model.Node, hostPort, frag string) string {
				q := url.Values{}
				q.Set("encryption", "none")
				q.Set("type", cmp.Or(n.Transport.Net, "tcp"))
				if flow, _ := n.Extra["flow"].(string); flow != "" {
					q.Set("flow", flow)
				}
				if sec, _ := n.Extra["security"].(string); sec == "reality" {
					q.Set("security", "reality")
					if pk, _ := n.Extra["public_key"].(string); pk != "" {
						q.Set("pbk", pk)
					}
					if sid, _ := n.Extra["short_id"].(string); sid != "" {
						q.Set("sid", sid)
					}
					fp, _ := n.Extra["fingerprint"].(string)
					q.Set("fp", cmp.Or(fp, "chrome"))
				} else if n.Security.TLS {
					q.Set("security", "tls")
					if n.Security.SkipVerify {
						q.Set("allowInsecure", "1")
					}
				}
				if n.Security.ServerName != "" {
					q.Set("sni", n.Security.ServerName)
				}
				if len(n.Security.ALPN) > 0 {
					q.Set("alpn", strings.Join(n.Security.ALPN, ","))
				}
				if n.Transport.Host != "" {
					q.Set("host", n.Transport.Host)
				}
				if n.Transport.Path != "" {
					q.Set("path", n.Transport.Path)
				}
				return fmt.Sprintf("vless://%s@%s?%s#%s", url.PathEscape(n.UUID), hostPort, q.Encode(), frag)
			},
		},
		{
			Type:       "hysteria2",
			URISchemes: []string{"hysteria2://", "hy2://"},
			DecodeSingBox: func(ob map[string]any, n *model.Node) bool {
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
				return true
			},
			DecodeClash: func(p map[string]any, n *model.Node) bool {
				n.Password = asString(p["password"])
				n.Security.TLS = true
				if obfs := asString(p["obfs"]); obfs != "" {
					n.Extra["obfs"] = map[string]string{
						"type":     obfs,
						"password": asString(p["obfs-password"]),
					}
				}
				return true
			},
			EncodeClash: func(n model.Node, p map[string]any, opts RenderOptions) (map[string]any, bool) {
				p["type"] = "hysteria2"
				p["password"] = n.Password
				p["skip-cert-verify"] = n.Security.SkipVerify
				if n.Security.ServerName != "" {
					p["sni"] = n.Security.ServerName
				}
				if len(n.Security.ALPN) > 0 {
					p["alpn"] = n.Security.ALPN
				}
				if obfsMap, ok := n.Extra["obfs"].(map[string]string); ok && obfsMap["type"] != "" {
					p["obfs"] = obfsMap["type"]
					if obfsMap["password"] != "" {
						p["obfs-password"] = obfsMap["password"]
					}
				}
				if opts.UpMbps > 0 {
					p["up"] = fmt.Sprintf("%d Mbps", opts.UpMbps)
				}
				if opts.DownMbps > 0 {
					p["down"] = fmt.Sprintf("%d Mbps", opts.DownMbps)
				}
				return p, true
			},
			EncodeSurgeLine: func(n model.Node, tag string, opts RenderOptions) (string, bool) {
				parts := []string{
					fmt.Sprintf("%s = hysteria2", tag),
					n.Addr,
					strconv.Itoa(int(n.Port)),
					fmt.Sprintf("password=%s", n.Password),
				}
				parts = appendSurgeSNIAndSkipVerify(parts, n.Security)
				if opts.DownMbps > 0 {
					parts = append(parts, fmt.Sprintf("download-bandwidth=%d", opts.DownMbps))
				}
				return strings.Join(parts, ", "), true
			},
			EncodeLoonLine: func(n model.Node, tag string, _ RenderOptions) (string, bool) {
				parts := []string{
					fmt.Sprintf("%s = Hysteria2", tag),
					n.Addr,
					strconv.Itoa(int(n.Port)),
					fmt.Sprintf("\"%s\"", n.Password),
				}
				if n.Security.ServerName != "" {
					parts = append(parts, fmt.Sprintf("tls-name=%s", n.Security.ServerName))
				}
				parts = append(parts, fmt.Sprintf("skip-cert-verify=%t", n.Security.SkipVerify), "udp=true")
				return strings.Join(parts, ", "), true
			},
			EncodeURI: func(n model.Node, hostPort, frag string) string {
				q := url.Values{}
				if n.Security.ServerName != "" {
					q.Set("sni", n.Security.ServerName)
				}
				if len(n.Security.ALPN) > 0 {
					q.Set("alpn", strings.Join(n.Security.ALPN, ","))
				}
				if n.Security.SkipVerify {
					q.Set("insecure", "1")
				} else {
					q.Set("insecure", "0")
				}
				if obfsMap, ok := n.Extra["obfs"].(map[string]string); ok && obfsMap["type"] != "" {
					q.Set("obfs", obfsMap["type"])
					if obfsMap["password"] != "" {
						q.Set("obfs-password", obfsMap["password"])
					}
				}
				return fmt.Sprintf("hysteria2://%s@%s/?%s#%s", url.User(n.Password).String(), hostPort, q.Encode(), frag)
			},
		},
		{
			Type:       "trojan",
			URISchemes: []string{"trojan://"},
			DecodeSingBox: func(ob map[string]any, n *model.Node) bool {
				n.Password = asString(ob["password"])
				n.Security.TLS = true
				return true
			},
			DecodeClash: func(p map[string]any, n *model.Node) bool {
				n.Password = asString(p["password"])
				n.Security.TLS = true
				return true
			},
			EncodeClash: func(n model.Node, p map[string]any, _ RenderOptions) (map[string]any, bool) {
				p["type"] = "trojan"
				p["password"] = n.Password
				p["skip-cert-verify"] = n.Security.SkipVerify
				if n.Security.ServerName != "" {
					p["sni"] = n.Security.ServerName
				}
				if len(n.Security.ALPN) > 0 {
					p["alpn"] = n.Security.ALPN
				}
				applyClashTransport(p, n.Transport)
				return p, true
			},
			EncodeSurgeLine: func(n model.Node, tag string, _ RenderOptions) (string, bool) {
				parts := []string{
					fmt.Sprintf("%s = trojan", tag),
					n.Addr,
					strconv.Itoa(int(n.Port)),
					fmt.Sprintf("password=%s", n.Password),
				}
				parts = appendSurgeSNIAndSkipVerify(parts, n.Security)
				return strings.Join(parts, ", "), true
			},
			EncodeLoonLine: func(n model.Node, tag string, _ RenderOptions) (string, bool) {
				parts := []string{
					fmt.Sprintf("%s = trojan", tag),
					n.Addr,
					strconv.Itoa(int(n.Port)),
					fmt.Sprintf("\"%s\"", n.Password),
				}
				if n.Security.ServerName != "" {
					parts = append(parts, fmt.Sprintf("tls-name=%s", n.Security.ServerName))
				}
				parts = append(parts, fmt.Sprintf("skip-cert-verify=%t", n.Security.SkipVerify), "udp=true")
				return strings.Join(parts, ", "), true
			},
			EncodeURI: func(n model.Node, hostPort, frag string) string {
				q := url.Values{}
				if n.Security.ServerName != "" {
					q.Set("sni", n.Security.ServerName)
				}
				if len(n.Security.ALPN) > 0 {
					q.Set("alpn", strings.Join(n.Security.ALPN, ","))
				}
				if n.Security.SkipVerify {
					q.Set("allowInsecure", "1")
				}
				if n.Transport.Net != "" && n.Transport.Net != "tcp" {
					q.Set("type", n.Transport.Net)
					if n.Transport.Host != "" {
						q.Set("host", n.Transport.Host)
					}
					if n.Transport.Path != "" {
						q.Set("path", n.Transport.Path)
					}
				}
				return fmt.Sprintf("trojan://%s@%s?%s#%s", url.User(n.Password).String(), hostPort, q.Encode(), frag)
			},
		},
		{
			Type:       "shadowsocks",
			Aliases:    []string{"ss"},
			URISchemes: []string{"ss://"},
			DecodeSingBox: func(ob map[string]any, n *model.Node) bool {
				n.Password = asString(ob["password"])
				n.Extra["method"] = cmp.Or(asString(ob["method"]), "aes-256-gcm")
				return true
			},
			DecodeClash: func(p map[string]any, n *model.Node) bool {
				n.Password = asString(p["password"])
				n.Extra["method"] = asString(p["cipher"])
				return true
			},
			EncodeClash: func(n model.Node, p map[string]any, _ RenderOptions) (map[string]any, bool) {
				p["type"] = "ss"
				cipher, _ := n.Extra["method"].(string)
				p["cipher"] = cmp.Or(cipher, "aes-256-gcm")
				p["password"] = n.Password
				return p, true
			},
			EncodeSurgeLine: func(n model.Node, tag string, _ RenderOptions) (string, bool) {
				method, _ := n.Extra["method"].(string)
				parts := []string{
					fmt.Sprintf("%s = ss", tag),
					n.Addr,
					strconv.Itoa(int(n.Port)),
					fmt.Sprintf("encrypt-method=%s", cmp.Or(method, "aes-256-gcm")),
					fmt.Sprintf("password=%s", n.Password),
					"udp-relay=true",
				}
				return strings.Join(parts, ", "), true
			},
			EncodeLoonLine: func(n model.Node, tag string, _ RenderOptions) (string, bool) {
				method, _ := n.Extra["method"].(string)
				parts := []string{
					fmt.Sprintf("%s = Shadowsocks", tag),
					n.Addr,
					strconv.Itoa(int(n.Port)),
					cmp.Or(method, "aes-256-gcm"),
					fmt.Sprintf("\"%s\"", n.Password),
					"udp=true",
				}
				return strings.Join(parts, ", "), true
			},
			EncodeURI: func(n model.Node, hostPort, frag string) string {
				method, _ := n.Extra["method"].(string)
				b64 := base64.RawStdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", cmp.Or(method, "aes-256-gcm"), n.Password)))
				cred := strings.ReplaceAll(b64, "/", "%2F")
				return fmt.Sprintf("ss://%s@%s#%s", cred, hostPort, frag)
			},
		},
		{
			Type:       "vmess",
			URISchemes: []string{"vmess://"},
			DecodeSingBox: func(ob map[string]any, n *model.Node) bool {
				n.UUID = asString(ob["uuid"])
				return true
			},
			DecodeClash: func(p map[string]any, n *model.Node) bool {
				n.UUID = asString(p["uuid"])
				n.Security.TLS = asBool(p["tls"])
				return true
			},
			EncodeClash: func(n model.Node, p map[string]any, _ RenderOptions) (map[string]any, bool) {
				p["type"] = "vmess"
				p["uuid"] = n.UUID
				p["alterId"] = 0
				p["cipher"] = "auto"
				if n.Security.TLS {
					p["tls"] = true
					p["skip-cert-verify"] = n.Security.SkipVerify
					if n.Security.ServerName != "" {
						p["servername"] = n.Security.ServerName
					}
				}
				applyClashTransport(p, n.Transport)
				return p, true
			},
			EncodeSurgeLine: func(n model.Node, tag string, _ RenderOptions) (string, bool) {
				parts := []string{
					fmt.Sprintf("%s = vmess", tag),
					n.Addr,
					strconv.Itoa(int(n.Port)),
					fmt.Sprintf("username=%s", n.UUID),
					"vmess-aead=true",
				}
				if n.Security.TLS {
					parts = append(parts, "tls=true")
					if n.Security.ServerName != "" {
						parts = append(parts, fmt.Sprintf("sni=%s", n.Security.ServerName))
					}
				}
				return strings.Join(parts, ", "), true
			},
			EncodeURI: func(n model.Node, _, _ string) string {
				dto := map[string]any{
					"v":    "2",
					"ps":   n.Tag,
					"add":  n.Addr,
					"port": strconv.Itoa(int(n.Port)),
					"id":   n.UUID,
					"aid":  "0",
					"scy":  "auto",
					"net":  cmp.Or(n.Transport.Net, "tcp"),
					"type": "none",
					"host": n.Transport.Host,
					"path": n.Transport.Path,
					"tls":  "",
					"sni":  n.Security.ServerName,
				}
				if n.Security.TLS {
					dto["tls"] = "tls"
				}
				if len(n.Security.ALPN) > 0 {
					dto["alpn"] = strings.Join(n.Security.ALPN, ",")
				}
				raw, err := json.Marshal(dto)
				if err != nil {
					return ""
				}
				return "vmess://" + base64.StdEncoding.EncodeToString(raw)
			},
		},
		{
			Type:       "tuic",
			URISchemes: []string{"tuic://"},
			DecodeSingBox: func(ob map[string]any, n *model.Node) bool {
				n.UUID = asString(ob["uuid"])
				n.Password = asString(ob["password"])
				n.Security.TLS = true
				if cc := asString(ob["congestion_control"]); cc != "" {
					n.Extra["congestion_control"] = cc
				}
				if udpMode := asString(ob["udp_relay_mode"]); udpMode != "" {
					n.Extra["udp_relay_mode"] = udpMode
				}
				return true
			},
			DecodeClash: func(p map[string]any, n *model.Node) bool {
				n.UUID = asString(p["uuid"])
				n.Password = asString(p["password"])
				n.Security.TLS = true
				return true
			},
			EncodeClash: func(n model.Node, p map[string]any, _ RenderOptions) (map[string]any, bool) {
				p["type"] = "tuic"
				p["uuid"] = n.UUID
				p["password"] = n.Password
				p["skip-cert-verify"] = n.Security.SkipVerify
				if n.Security.ServerName != "" {
					p["sni"] = n.Security.ServerName
				}
				if len(n.Security.ALPN) > 0 {
					p["alpn"] = n.Security.ALPN
				} else {
					p["alpn"] = []string{"h3"}
				}
				if cc, _ := n.Extra["congestion_control"].(string); cc != "" {
					p["congestion-controller"] = cc
				}
				return p, true
			},
			EncodeSurgeLine: func(n model.Node, tag string, _ RenderOptions) (string, bool) {
				parts := []string{
					fmt.Sprintf("%s = tuic-v5", tag),
					n.Addr,
					strconv.Itoa(int(n.Port)),
					fmt.Sprintf("uuid=%s", n.UUID),
					fmt.Sprintf("password=%s", n.Password),
				}
				if n.Security.ServerName != "" {
					parts = append(parts, fmt.Sprintf("sni=%s", n.Security.ServerName))
				}
				return strings.Join(parts, ", "), true
			},
			EncodeURI: func(n model.Node, hostPort, frag string) string {
				q := url.Values{}
				if n.Security.ServerName != "" {
					q.Set("sni", n.Security.ServerName)
				}
				if len(n.Security.ALPN) > 0 {
					q.Set("alpn", strings.Join(n.Security.ALPN, ","))
				}
				if n.Security.SkipVerify {
					q.Set("insecure", "1")
				}
				if cc, _ := n.Extra["congestion_control"].(string); cc != "" {
					q.Set("congestion_control", cc)
				}
				if udpMode, _ := n.Extra["udp_relay_mode"].(string); udpMode != "" {
					q.Set("udp_relay_mode", udpMode)
				}
				return fmt.Sprintf("tuic://%s@%s/?%s#%s", url.UserPassword(n.UUID, n.Password).String(), hostPort, q.Encode(), frag)
			},
		},
		{
			Type:       "anytls",
			URISchemes: []string{"anytls://"},
			DecodeSingBox: func(ob map[string]any, n *model.Node) bool {
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
				return true
			},
			DecodeClash: func(p map[string]any, n *model.Node) bool {
				n.Password = asString(p["password"])
				n.Security.TLS = true
				return true
			},
			EncodeClash: func(n model.Node, p map[string]any, _ RenderOptions) (map[string]any, bool) {
				p["type"] = "anytls"
				p["password"] = n.Password
				p["skip-cert-verify"] = n.Security.SkipVerify
				if n.Security.ServerName != "" {
					p["sni"] = n.Security.ServerName
				}
				if len(n.Security.ALPN) > 0 {
					p["alpn"] = n.Security.ALPN
				}
				p["client-fingerprint"] = "chrome"
				return p, true
			},
			EncodeSurgeLine: func(n model.Node, tag string, _ RenderOptions) (string, bool) {
				parts := []string{
					fmt.Sprintf("%s = anytls", tag),
					n.Addr,
					strconv.Itoa(int(n.Port)),
					fmt.Sprintf("password=%s", n.Password),
				}
				parts = appendSurgeSNIAndSkipVerify(parts, n.Security)
				return strings.Join(parts, ", "), true
			},
			EncodeURI: func(n model.Node, hostPort, frag string) string {
				q := url.Values{}
				if n.Security.ServerName != "" {
					q.Set("sni", n.Security.ServerName)
				}
				if len(n.Security.ALPN) > 0 {
					q.Set("alpn", strings.Join(n.Security.ALPN, ","))
				}
				if n.Security.SkipVerify {
					q.Set("insecure", "1")
				} else {
					q.Set("insecure", "0")
				}
				for _, extraKey := range []string{"idle_session_check_interval", "idle_session_timeout", "min_idle_session"} {
					if val := strings.TrimSpace(fmt.Sprint(n.Extra[extraKey])); val != "" && val != "<nil>" && val != "0" {
						q.Set(extraKey, val)
					}
				}
				return fmt.Sprintf("anytls://%s@%s/?%s#%s", url.User(n.Password).String(), hostPort, q.Encode(), frag)
			},
		},
	}
}
