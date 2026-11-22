// 文件职责：实现 Trojan 与 Shadowsocks（含 SS-2022 密钥编码保护）的多客户端双向编解码器。
package subhub

import (
	"cmp"
	"encoding/base64"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/sixban6/singgen/pkg/model"
)

func trojanCodec() protocolCodec {
	return protocolCodec{
		Type:            "trojan",
		URISchemes:      []string{"trojan://"},
		DecodeSingBox:   decodeTrojanSingBox,
		DecodeClash:     decodeTrojanClash,
		EncodeClash:     encodeTrojanClash,
		EncodeSurgeLine: encodeTrojanSurge,
		EncodeLoonLine:  encodeTrojanLoon,
		EncodeURI:       encodeTrojanURI,
	}
}

func decodeTrojanSingBox(ob map[string]any, n *model.Node) bool {
	n.Password = asString(ob["password"])
	n.Security.TLS = true
	return true
}

func decodeTrojanClash(p map[string]any, n *model.Node) bool {
	n.Password = asString(p["password"])
	n.Security.TLS = true
	return true
}

func encodeTrojanClash(n model.Node, p map[string]any, _ RenderOptions) (map[string]any, bool) {
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
}

func encodeTrojanSurge(n model.Node, tag string, _ RenderOptions) (string, bool) {
	parts := []string{
		fmt.Sprintf("%s = trojan", tag),
		n.Addr,
		strconv.Itoa(int(n.Port)),
		fmt.Sprintf("password=%s", n.Password),
	}
	parts = appendSurgeSNIAndSkipVerify(parts, n.Security)
	return strings.Join(parts, ", "), true
}

func encodeTrojanLoon(n model.Node, tag string, _ RenderOptions) (string, bool) {
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
}

func encodeTrojanURI(n model.Node, hostPort, frag string) string {
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
}

func shadowsocksCodec() protocolCodec {
	return protocolCodec{
		Type:            "shadowsocks",
		Aliases:         []string{"ss"},
		URISchemes:      []string{"ss://"},
		DecodeSingBox:   decodeShadowsocksSingBox,
		DecodeClash:     decodeShadowsocksClash,
		EncodeClash:     encodeShadowsocksClash,
		EncodeSurgeLine: encodeShadowsocksSurge,
		EncodeLoonLine:  encodeShadowsocksLoon,
		EncodeURI:       encodeShadowsocksURI,
	}
}

func decodeShadowsocksSingBox(ob map[string]any, n *model.Node) bool {
	n.Password = asString(ob["password"])
	n.Extra["method"] = cmp.Or(asString(ob["method"]), "aes-256-gcm")
	return true
}

func decodeShadowsocksClash(p map[string]any, n *model.Node) bool {
	n.Password = asString(p["password"])
	n.Extra["method"] = asString(p["cipher"])
	return true
}

func encodeShadowsocksClash(n model.Node, p map[string]any, _ RenderOptions) (map[string]any, bool) {
	p["type"] = "ss"
	p["cipher"] = cmp.Or(nodeExtraString(n, "method"), "aes-256-gcm")
	p["password"] = n.Password
	return p, true
}

func encodeShadowsocksSurge(n model.Node, tag string, _ RenderOptions) (string, bool) {
	method := cmp.Or(nodeExtraString(n, "method"), "aes-256-gcm")
	parts := []string{
		fmt.Sprintf("%s = ss", tag),
		n.Addr,
		strconv.Itoa(int(n.Port)),
		fmt.Sprintf("encrypt-method=%s", method),
		fmt.Sprintf("password=%s", n.Password),
		"udp-relay=true",
	}
	return strings.Join(parts, ", "), true
}

func encodeShadowsocksLoon(n model.Node, tag string, _ RenderOptions) (string, bool) {
	method := cmp.Or(nodeExtraString(n, "method"), "aes-256-gcm")
	parts := []string{
		fmt.Sprintf("%s = Shadowsocks", tag),
		n.Addr,
		strconv.Itoa(int(n.Port)),
		method,
		fmt.Sprintf("\"%s\"", n.Password),
		"udp=true",
	}
	return strings.Join(parts, ", "), true
}

func encodeShadowsocksURI(n model.Node, hostPort, frag string) string {
	method := cmp.Or(nodeExtraString(n, "method"), "aes-256-gcm")
	b64 := base64.RawStdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", method, n.Password)))
	cred := strings.ReplaceAll(b64, "/", "%2F")
	return fmt.Sprintf("ss://%s@%s#%s", cred, hostPort, frag)
}
