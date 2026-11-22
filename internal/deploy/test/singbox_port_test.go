// 文件职责：验证服务端 Reality 握手端口通过结构化模型写入，不依赖模板空格缩进字符串替换。
package deploy_test

import (
	"encoding/json"
	"testing"

	"singctl/internal/deploy"
)

func TestSetRealityHandshakePort_IndentationIndependentAndLossless(t *testing.T) {
	compactServerJSON := `{"inbounds":[{"type":"vless","tag":"vless-in","listen":"127.0.0.1","listen_port":8443,"tls":{"enabled":true,"server_name":"node.example.com","reality":{"enabled":true,"handshake":{"server":"127.0.0.1","server_port":443},"private_key":"priv","short_id":["0102"]}}},{"type":"hysteria2","tag":"HYSTERIA2","listen_port":52021}],"outbounds":[{"tag":"DC","type":"direct"}]}`

	updated, err := deploy.SetRealityHandshakePort(compactServerJSON, 9443)
	if err != nil {
		t.Fatalf("SetRealityHandshakePort failed: %v", err)
	}

	var parsed struct {
		Inbounds []struct {
			Tag string `json:"tag"`
			TLS struct {
				Reality struct {
					Handshake struct {
						Server     string `json:"server"`
						ServerPort int    `json:"server_port"`
					} `json:"handshake"`
					ShortID []string `json:"short_id"`
				} `json:"reality"`
			} `json:"tls"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal([]byte(updated), &parsed); err != nil {
		t.Fatalf("invalid output JSON: %v", err)
	}
	if parsed.Inbounds[0].TLS.Reality.Handshake.ServerPort != 9443 {
		t.Fatalf("expected handshake.server_port updated to 9443 on compact JSON, got %d",
			parsed.Inbounds[0].TLS.Reality.Handshake.ServerPort)
	}
	if len(parsed.Inbounds[0].TLS.Reality.ShortID) != 1 || parsed.Inbounds[0].TLS.Reality.ShortID[0] != "0102" {
		t.Fatalf("expected sibling reality fields preserved intact, got %+v", parsed.Inbounds[0].TLS.Reality)
	}
}
