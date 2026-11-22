// 文件职责：验证 SubHub 订阅原始载荷策略链解码（URI / Base64 / Sing-box JSON / Clash YAML / OCP 扩展）表驱动边界测试。
package subhub_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"sync"
	"testing"

	"singctl/internal/subhub"

	"github.com/sixban6/singgen/pkg/model"
)

func TestSubHubPayload_TableDrivenBoundaries(t *testing.T) {
	ctx := t.Context()

	t.Run("empty_nil_and_oversized_inputs", func(t *testing.T) {
		for _, in := range [][]byte{nil, {}, []byte("   \r\n\t  ")} {
			nodes, uris := subhub.DecodeRawSubscriptionWithChain(ctx, in)
			if len(nodes) != 0 || len(uris) != 0 {
				t.Fatalf("expected empty result for blank input, got nodes=%d uris=%d", len(nodes), len(uris))
			}
		}

		oversized := bytes.Repeat([]byte("A"), subhub.MaxRemoteSubBytes+64)
		nodes, uris := subhub.DecodeRawSubscriptionWithChain(ctx, oversized)
		if len(nodes) != 0 || len(uris) != 0 {
			t.Fatalf("expected oversized payload to return empty, got nodes=%d uris=%d", len(nodes), len(uris))
		}
	})

	t.Run("uri_lines_and_base64_and_normalization", func(t *testing.T) {
		legacySSCred := base64.RawStdEncoding.EncodeToString([]byte("aes-256-gcm:test-pass@node1.example.com:8388"))
		plain := "# comment\n// ignore\n" +
			"vless://11111111-1111-1111-1111-111111111111@node1.example.com:443?security=tls&sni=node1.example.com#测试节点\n" +
			"ss://" + legacySSCred + "#SS节点\n" +
			"not-a-valid-line\n"

		nodes, uris := subhub.DecodeRawSubscriptionWithChain(ctx, []byte(plain))
		if len(uris) != 2 || len(nodes) == 0 {
			t.Fatalf("expected 2 normalized URIs and parsed nodes, got nodes=%d uris=%v", len(nodes), uris)
		}

		b64Payload := base64.RawURLEncoding.EncodeToString([]byte(plain))
		bNodes, bURIs := subhub.DecodeRawSubscriptionWithChain(ctx, []byte(b64Payload))
		if len(bURIs) != 2 || len(bNodes) == 0 {
			t.Fatalf("expected base64 decoded 2 URIs and parsed nodes, got nodes=%d uris=%v", len(bNodes), bURIs)
		}
	})

	t.Run("singbox_json_and_clash_yaml_and_malformed", func(t *testing.T) {
		singboxJSON := `{
			"outbounds": [
				{"type": "direct", "tag": "direct"},
				{"type": "vless", "tag": "us1", "server": "198.51.100.10", "server_port": 443, "uuid": "11111111-1111-1111-1111-111111111111", "tls": {"enabled": true, "server_name": "node1.example.com"}},
				{"type": "hysteria2", "tag": "jp1", "server": "203.0.113.20", "server_port": 443, "password": "test-pass", "tls": {"enabled": true, "server_name": "node2.example.com"}}
			]
		}`
		nodes, uris := subhub.DecodeRawSubscriptionWithChain(ctx, []byte(singboxJSON))
		if len(nodes) != 2 || len(uris) != 2 {
			t.Fatalf("expected 2 singbox nodes+uris, got nodes=%d uris=%d", len(nodes), len(uris))
		}

		clashYAML := "proxies:\n  - name: hk1\n    type: trojan\n    server: node1.example.com\n    port: 443\n    password: test-pass\n"
		cNodes, cURIs := subhub.DecodeRawSubscriptionWithChain(ctx, []byte(clashYAML))
		if len(cNodes) != 1 || len(cURIs) != 1 {
			t.Fatalf("expected 1 clash node+uri, got nodes=%d uris=%d", len(cNodes), len(cURIs))
		}

		badHTML := "<html><body>403 Forbidden</body></html>"
		bNodes, bURIs := subhub.DecodeRawSubscriptionWithChain(ctx, []byte(badHTML))
		if len(bNodes) != 0 || len(bURIs) != 0 {
			t.Fatalf("expected html error page to yield 0 nodes, got nodes=%d uris=%d", len(bNodes), len(bURIs))
		}
	})

	t.Run("custom_ocp_decoder_extension_and_race_safety", func(t *testing.T) {
		customDecoder := subhub.SubscriptionPayloadDecoder{
			Name:  "custom_token",
			Match: func(text string) bool { return text == "CUSTOM-SCHEME" },
			Decode: func(_ context.Context, _ string) ([]model.Node, []string) {
				return []model.Node{{Type: "trojan", Tag: "custom", Addr: "198.51.100.1", Port: 443, Password: "test"}}, []string{"trojan://test@198.51.100.1:443#custom"}
			},
		}
		nodes, uris := subhub.DecodeRawSubscriptionWithChain(ctx, []byte("CUSTOM-SCHEME"), customDecoder)
		if len(nodes) != 1 || len(uris) != 1 || nodes[0].Tag != "custom" {
			t.Fatalf("expected custom decoder extension to win, got nodes=%+v uris=%v", nodes, uris)
		}

		sample := "vless://11111111-1111-1111-1111-111111111111@node1.example.com:443#n1\n"
		var wg sync.WaitGroup
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				ns, us := subhub.DecodeRawSubscriptionWithChain(ctx, []byte(sample))
				if len(ns) == 0 || len(us) != 1 {
					t.Errorf("concurrent decode failed: nodes=%d uris=%d", len(ns), len(us))
				}
			}()
		}
		wg.Wait()
	})
}
