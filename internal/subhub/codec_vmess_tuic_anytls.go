// 文件职责：实现 VMess、TUIC v5 与 AnyTLS 三种协议的多客户端双向编解码器。
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

func vmessCodec() protocolCodec {
	return protocolCodec{
		Type:            "vmess",
		URISchemes:      []string{"vmess://"},
		DecodeSingBox:   decodeVMessSingBox,
		DecodeClash:     decodeVMessClash,
		EncodeClash:     encodeVMessClash,
		EncodeSurgeLine: encodeVMessSurge,
		EncodeURI:       encodeVMessURI,
	}
}

func decodeVMessSingBox(ob map[string]any, n *model.Node) bool {
	n.UUID = asString(ob["uuid"])
	return true
}

func decodeVMessClash(p map[string]any, n *model.Node) bool {
	n.UUID = asString(p["uuid"])
	n.Security.TLS = asBool(p["tls"])
	return true
}

func encodeVMessClash(n model.Node, p map[string]any, _ RenderOptions) (map[string]any, bool) {
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
}

func encodeVMessSurge(n model.Node, tag string, _ RenderOptions) (string, bool) {
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
}

func encodeVMessURI(n model.Node, _, _ string) string {
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
}

func tuicCodec() protocolCodec {
	return protocolCodec{
		Type:            "tuic",
		URISchemes:      []string{"tuic://"},
		DecodeSingBox:   decodeTUICSingBox,
		DecodeClash:     decodeTUICClash,
		EncodeClash:     encodeTUICClash,
		EncodeSurgeLine: encodeTUICSurge,
		EncodeURI:       encodeTUICURI,
	}
}

func decodeTUICSingBox(ob map[string]any, n *model.Node) bool {
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
}

func decodeTUICClash(p map[string]any, n *model.Node) bool {
	n.UUID = asString(p["uuid"])
	n.Password = asString(p["password"])
	n.Security.TLS = true
	return true
}

func encodeTUICClash(n model.Node, p map[string]any, _ RenderOptions) (map[string]any, bool) {
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
	if cc := nodeExtraString(n, "congestion_control"); cc != "" {
		p["congestion-controller"] = cc
	}
	return p, true
}

func encodeTUICSurge(n model.Node, tag string, _ RenderOptions) (string, bool) {
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
}

func encodeTUICURI(n model.Node, hostPort, frag string) string {
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
	if cc := nodeExtraString(n, "congestion_control"); cc != "" {
		q.Set("congestion_control", cc)
	}
	if udpMode := nodeExtraString(n, "udp_relay_mode"); udpMode != "" {
		q.Set("udp_relay_mode", udpMode)
	}
	return fmt.Sprintf("tuic://%s@%s/?%s#%s", url.UserPassword(n.UUID, n.Password).String(), hostPort, q.Encode(), frag)
}

func anytlsCodec() protocolCodec {
	return protocolCodec{
		Type:            "anytls",
		URISchemes:      []string{"anytls://"},
		DecodeSingBox:   decodeAnyTLSSingBox,
		DecodeClash:     decodeAnyTLSClash,
		EncodeClash:     encodeAnyTLSClash,
		EncodeSurgeLine: encodeAnyTLSSurge,
		EncodeURI:       encodeAnyTLSURI,
	}
}

func decodeAnyTLSSingBox(ob map[string]any, n *model.Node) bool {
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
}

func decodeAnyTLSClash(p map[string]any, n *model.Node) bool {
	n.Password = asString(p["password"])
	n.Security.TLS = true
	return true
}

func encodeAnyTLSClash(n model.Node, p map[string]any, _ RenderOptions) (map[string]any, bool) {
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
}

func encodeAnyTLSSurge(n model.Node, tag string, _ RenderOptions) (string, bool) {
	parts := []string{
		fmt.Sprintf("%s = anytls", tag),
		n.Addr,
		strconv.Itoa(int(n.Port)),
		fmt.Sprintf("password=%s", n.Password),
	}
	parts = appendSurgeSNIAndSkipVerify(parts, n.Security)
	return strings.Join(parts, ", "), true
}

func encodeAnyTLSURI(n model.Node, hostPort, frag string) string {
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
}
