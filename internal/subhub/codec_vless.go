// 文件职责：实现 VLESS（含 XTLS Vision 与 Reality 扩展参数）的多客户端双向编解码器。
package subhub

import (
	"cmp"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/sixban6/singgen/pkg/model"
)

func vlessCodec() protocolCodec {
	return protocolCodec{
		Type:           "vless",
		URISchemes:     []string{"vless://"},
		DecodeSingBox:  decodeVLESSSingBox,
		DecodeClash:    decodeVLESSClash,
		EncodeClash:    encodeVLESSClash,
		EncodeLoonLine: encodeVLESSLoon,
		EncodeURI:      encodeVLESSURI,
	}
}

func decodeVLESSSingBox(ob map[string]any, n *model.Node) bool {
	n.UUID = asString(ob["uuid"])
	if flow := asString(ob["flow"]); flow != "" {
		n.Extra["flow"] = flow
	}
	return true
}

func decodeVLESSClash(p map[string]any, n *model.Node) bool {
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
}

func encodeVLESSClash(n model.Node, p map[string]any, _ RenderOptions) (map[string]any, bool) {
	p["type"] = "vless"
	p["uuid"] = n.UUID
	if flow := nodeExtraString(n, "flow"); flow != "" {
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
		p["client-fingerprint"] = cmp.Or(nodeExtraString(n, "fingerprint"), "chrome")
		if nodeExtraString(n, "security") == "reality" {
			ro := map[string]any{}
			if pk := nodeExtraString(n, "public_key"); pk != "" {
				ro["public-key"] = pk
			}
			if sid := nodeExtraString(n, "short_id"); sid != "" {
				ro["short-id"] = sid
			}
			p["reality-opts"] = ro
		}
	}
	applyClashTransport(p, n.Transport)
	return p, true
}

func encodeVLESSLoon(n model.Node, tag string, _ RenderOptions) (string, bool) {
	parts := []string{
		fmt.Sprintf("%s = VLESS", tag),
		n.Addr,
		strconv.Itoa(int(n.Port)),
		fmt.Sprintf("\"%s\"", n.UUID),
		"transport=tcp",
	}
	if flow := nodeExtraString(n, "flow"); flow != "" {
		parts = append(parts, fmt.Sprintf("flow=%s", flow))
	}
	if n.Security.TLS {
		parts = append(parts, "over-tls=true")
		if n.Security.ServerName != "" {
			parts = append(parts, fmt.Sprintf("tls-name=%s", n.Security.ServerName))
		}
		parts = append(parts, fmt.Sprintf("skip-cert-verify=%t", n.Security.SkipVerify))
		if nodeExtraString(n, "security") == "reality" {
			if pk := nodeExtraString(n, "public_key"); pk != "" {
				parts = append(parts, fmt.Sprintf("public-key=\"%s\"", pk))
			}
			if sid := nodeExtraString(n, "short_id"); sid != "" {
				parts = append(parts, fmt.Sprintf("short-id=%s", sid))
			}
		}
	}
	parts = append(parts, "udp=true")
	return strings.Join(parts, ", "), true
}

func encodeVLESSURI(n model.Node, hostPort, frag string) string {
	q := url.Values{}
	q.Set("encryption", "none")
	q.Set("type", cmp.Or(n.Transport.Net, "tcp"))
	if flow := nodeExtraString(n, "flow"); flow != "" {
		q.Set("flow", flow)
	}
	if nodeExtraString(n, "security") == "reality" {
		q.Set("security", "reality")
		if pk := nodeExtraString(n, "public_key"); pk != "" {
			q.Set("pbk", pk)
		}
		if sid := nodeExtraString(n, "short_id"); sid != "" {
			q.Set("sid", sid)
		}
		q.Set("fp", cmp.Or(nodeExtraString(n, "fingerprint"), "chrome"))
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
}
