// 文件职责：声明式汇总 SubHub 内置 7 种代理协议编解码器，并提供协议间共享的传输层/TLS 序列化辅助。
package subhub

import (
	"fmt"
	"strings"

	"github.com/sixban6/singgen/pkg/model"
)

func builtinProtocolCodecs() []protocolCodec {
	return []protocolCodec{
		vlessCodec(),
		hysteria2Codec(),
		trojanCodec(),
		shadowsocksCodec(),
		vmessCodec(),
		tuicCodec(),
		anytlsCodec(),
	}
}

func nodeExtraString(n model.Node, key string) string {
	if n.Extra == nil {
		return ""
	}
	v, _ := n.Extra[key].(string)
	return v
}

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
