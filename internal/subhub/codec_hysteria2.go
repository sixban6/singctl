// 文件职责：实现 Hysteria2（含 Salamander 混淆与上下行带宽参数）的多客户端双向编解码器。
package subhub

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/sixban6/singgen/pkg/model"
)

func hysteria2Codec() protocolCodec {
	return protocolCodec{
		Type:            "hysteria2",
		URISchemes:      []string{"hysteria2://", "hy2://"},
		DecodeSingBox:   decodeHysteria2SingBox,
		DecodeClash:     decodeHysteria2Clash,
		EncodeClash:     encodeHysteria2Clash,
		EncodeSurgeLine: encodeHysteria2Surge,
		EncodeLoonLine:  encodeHysteria2Loon,
		EncodeURI:       encodeHysteria2URI,
	}
}

func decodeHysteria2SingBox(ob map[string]any, n *model.Node) bool {
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
}

func decodeHysteria2Clash(p map[string]any, n *model.Node) bool {
	n.Password = asString(p["password"])
	n.Security.TLS = true
	if obfs := asString(p["obfs"]); obfs != "" {
		n.Extra["obfs"] = map[string]string{
			"type":     obfs,
			"password": asString(p["obfs-password"]),
		}
	}
	return true
}

func encodeHysteria2Clash(n model.Node, p map[string]any, opts RenderOptions) (map[string]any, bool) {
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
}

func encodeHysteria2Surge(n model.Node, tag string, opts RenderOptions) (string, bool) {
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
}

func encodeHysteria2Loon(n model.Node, tag string, _ RenderOptions) (string, bool) {
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
}

func encodeHysteria2URI(n model.Node, hostPort, frag string) string {
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
}
