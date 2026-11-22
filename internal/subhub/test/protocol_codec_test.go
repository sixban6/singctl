// 文件职责：覆盖 SubHub 内置 7 协议双向编解码器注册表、多客户端渲染与自定义协议 OCP 扩展单测。
package subhub_test

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"sync"
	"testing"

	"singctl/internal/subhub"

	"github.com/sixban6/singgen/pkg/model"
	"gopkg.in/yaml.v3"
)

func TestProtocolCodec_AllBuiltinProtocolsRoundTripAndBoundaries(t *testing.T) {
	ctx := t.Context()
	defaultProtocols := subhub.DefaultProtocols()

	t.Run("default_registry_resolves_all_7_protocols_and_aliases", func(t *testing.T) {
		for _, typ := range []string{"vless", "hysteria2", "trojan", "shadowsocks", "ss", "vmess", "tuic", "anytls"} {
			if _, ok := defaultProtocols.Resolve(typ); !ok {
				t.Fatalf("expected defaultProtocols to resolve %q", typ)
			}
		}
		if _, ok := defaultProtocols.Resolve("unknown_proto"); ok {
			t.Fatal("expected unknown_proto not to resolve")
		}
		for _, u := range []string{
			"vless://11111111-1111-1111-1111-111111111111@node1.example.com:443#v",
			"hy2://test-pass@node1.example.com:443#h",
			"anytls://test-pass@node1.example.com:443#a",
			"tuic://11111111-1111-1111-1111-111111111111:test-pass@node1.example.com:443#t",
		} {
			if !defaultProtocols.HasSupportedScheme(u) {
				t.Fatalf("expected supported scheme for %s", u)
			}
		}
		if defaultProtocols.HasSupportedScheme("socks://198.51.100.1:1080#s") {
			t.Fatal("expected unsupported scheme socks:// to return false")
		}
	})

	t.Run("singbox_json_and_clash_yaml_decode_all_7_protocols", func(t *testing.T) {
		sbJSON := `{
			"outbounds": [
				{"type": "direct", "tag": "direct"},
				{"type": "vless", "tag": "vless-1", "server": "198.51.100.10", "server_port": 443, "uuid": "11111111-1111-1111-1111-111111111111", "flow": "xtls-rprx-vision", "tls": {"enabled": true, "server_name": "node1.example.com", "alpn": ["h2"], "utls": {"fingerprint": "firefox"}, "reality": {"enabled": true, "public_key": "pub123", "short_id": "abcd"}}},
				{"type": "hysteria2", "tag": "hy2-1", "server": "198.51.100.11", "server_port": 8443, "password": "test-pass", "obfs": {"type": "salamander", "password": "obfs-pass"}, "tls": {"enabled": true, "server_name": "hy2.example.com"}},
				{"type": "trojan", "tag": "trojan-1", "server": "198.51.100.12", "server_port": 443, "password": "test-pass", "tls": {"enabled": true, "server_name": "tr.example.com"}, "transport": {"type": "ws", "path": "/ws", "headers": {"Host": "ws.example.com"}}},
				{"type": "shadowsocks", "tag": "ss-1", "server": "198.51.100.13", "server_port": 8388, "password": "test-pass", "method": "2022-blake3-aes-128-gcm"},
				{"type": "vmess", "tag": "vmess-1", "server": "198.51.100.14", "server_port": 443, "uuid": "11111111-1111-1111-1111-111111111111", "tls": {"enabled": true, "server_name": "vm.example.com"}, "transport": {"type": "grpc", "service_name": "grpc-svc"}},
				{"type": "tuic", "tag": "tuic-1", "server": "198.51.100.15", "server_port": 443, "uuid": "11111111-1111-1111-1111-111111111111", "password": "test-pass", "congestion_control": "bbr", "udp_relay_mode": "native", "tls": {"enabled": true, "server_name": "tuic.example.com"}},
				{"type": "anytls", "tag": "anytls-1", "server": "198.51.100.16", "server_port": 443, "password": "test-pass", "idle_session_check_interval": "30s", "idle_session_timeout": "30s", "min_idle_session": 5, "tls": {"enabled": true, "server_name": "any.example.com"}},
				{"type": "unknown_proto", "tag": "skip-me", "server": "198.51.100.17", "server_port": 443}
			]
		}`
		nodes, uris := subhub.ParseRawSubscriptionPayload(ctx, []byte(sbJSON))
		if len(nodes) != 7 || len(uris) != 7 {
			t.Fatalf("expected 7 parsed sing-box nodes & uris, got nodes=%d uris=%d", len(nodes), len(uris))
		}
		if nodes[0].Extra["security"] != "reality" || nodes[1].Extra["obfs"] == nil || nodes[3].Extra["method"] != "2022-blake3-aes-128-gcm" {
			t.Fatalf("unexpected decoded singbox extra metadata: %+v", nodes)
		}
		if nodes[5].Extra["congestion_control"] != "bbr" || nodes[6].Extra["min_idle_session"] != 5 {
			t.Fatalf("unexpected tuic/anytls extra metadata: %+v / %+v", nodes[5].Extra, nodes[6].Extra)
		}

		clashYAML := `proxies:
  - {name: vless-c, type: vless, server: 203.0.113.10, port: 443, uuid: 11111111-1111-1111-1111-111111111111, tls: true, servername: v.example.com, flow: xtls-rprx-vision, client-fingerprint: chrome, reality-opts: {public-key: pub123, short-id: abcd}}
  - {name: hy2-c, type: hysteria2, server: 203.0.113.11, port: 8443, password: test-pass, sni: h.example.com, obfs: salamander, obfs-password: opw}
  - {name: tr-c, type: trojan, server: 203.0.113.12, port: 443, password: test-pass, sni: t.example.com, network: ws, ws-opts: {path: /ws, headers: {Host: ws.example.com}}}
  - {name: ss-c, type: ss, server: 203.0.113.13, port: 8388, password: test-pass, cipher: aes-256-gcm}
  - {name: vm-c, type: vmess, server: 203.0.113.14, port: 443, uuid: 11111111-1111-1111-1111-111111111111, tls: true, servername: vm.example.com}
  - {name: tuic-c, type: tuic, server: 203.0.113.15, port: 443, uuid: 11111111-1111-1111-1111-111111111111, password: test-pass, sni: tuic.example.com}
  - {name: any-c, type: anytls, server: 203.0.113.16, port: 443, password: test-pass, sni: any.example.com}
  - {name: invalid-port, type: trojan, server: 203.0.113.17, port: 0, password: test-pass}
  - {name: unknown-c, type: wireguard, server: 203.0.113.18, port: 51820}
`
		cNodes, cURIs := subhub.ParseRawSubscriptionPayload(ctx, []byte(clashYAML))
		if len(cNodes) != 7 || len(cURIs) != 7 {
			t.Fatalf("expected 7 parsed clash nodes & uris, got nodes=%d uris=%d", len(cNodes), len(cURIs))
		}
	})

	t.Run("encode_all_targets_with_exact_protocol_coverage_and_boundaries", func(t *testing.T) {
		nodes := []model.Node{
			{
				Type: "vless", Tag: "v1,test", Addr: "198.51.100.10", Port: 443,
				UUID:      "11111111-1111-1111-1111-111111111111",
				Security:  model.Security{TLS: true, ServerName: "v.example.com", ALPN: []string{"h2"}},
				Transport: model.Transport{Net: "ws", Host: "ws.example.com", Path: "/ws"},
				Extra:     map[string]any{"flow": "xtls-rprx-vision", "security": "reality", "public_key": "pk1", "short_id": "sid1"},
			},
			{
				Type: "hysteria2", Tag: "hy2-1", Addr: "198.51.100.11", Port: 8443,
				Password: "test-pass",
				Security: model.Security{TLS: true, SkipVerify: true, ServerName: "hy2.example.com", ALPN: []string{"h3"}},
				Extra:    map[string]any{"obfs": map[string]string{"type": "salamander", "password": "opw"}},
			},
			{
				Type: "trojan", Tag: "tr-1", Addr: "198.51.100.12", Port: 443,
				Password:  "test-pass",
				Security:  model.Security{TLS: true, ServerName: "tr.example.com"},
				Transport: model.Transport{Net: "grpc", Path: "grpc-svc"},
			},
			{
				Type: "ss", Tag: "ss-1", Addr: "198.51.100.13", Port: 8388,
				Password: "test-pass",
			},
			{
				Type: "vmess", Tag: "vm-1", Addr: "198.51.100.14", Port: 443,
				UUID:     "11111111-1111-1111-1111-111111111111",
				Security: model.Security{TLS: true, ServerName: "vm.example.com", ALPN: []string{"h2"}},
			},
			{
				Type: "tuic", Tag: "tuic-1", Addr: "198.51.100.15", Port: 443,
				UUID:     "11111111-1111-1111-1111-111111111111",
				Password: "test-pass",
				Security: model.Security{TLS: true, SkipVerify: true, ServerName: "tuic.example.com"},
				Extra:    map[string]any{"congestion_control": "bbr", "udp_relay_mode": "native"},
			},
			{
				Type: "anytls", Tag: "any-1", Addr: "198.51.100.16", Port: 443,
				Password: "test-pass",
				Security: model.Security{TLS: true, ServerName: "any.example.com"},
				Extra:    map[string]any{"idle_session_check_interval": "30s", "min_idle_session": 3},
			},
			{Type: "unknown_proto", Tag: "skip", Addr: "198.51.100.17", Port: 443},
			{Type: "trojan", Tag: "bad-port", Addr: "198.51.100.18", Port: 0},
		}

		for i := range 7 {
			u := subhub.NodeToURI(nodes[i])
			if u == "" {
				t.Fatalf("expected non-empty URI for protocol %s", nodes[i].Type)
			}
		}
		if got := subhub.NodeToURI(nodes[7]); got != "" {
			t.Fatalf("expected empty URI for unknown_proto, got %q", got)
		}
		vmURI := subhub.NodeToURI(nodes[4])
		rawVM, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(vmURI, "vmess://"))
		if err != nil {
			t.Fatalf("invalid vmess base64: %v", err)
		}
		var vmMap map[string]any
		if err := json.Unmarshal(rawVM, &vmMap); err != nil || vmMap["tls"] != "tls" {
			t.Fatalf("unexpected vmess payload: %s", string(rawVM))
		}
		ssURI := subhub.NodeToURI(model.Node{Type: "ss", Tag: "t", Addr: "198.51.100.13", Port: 8388, Password: "p?"})
		if !strings.HasPrefix(ssURI, "ss://") || strings.Contains(ssURI, "/@") {
			t.Fatalf("unexpected ss URI: %s", ssURI)
		}

		bundle := &subhub.ResolvedBundle{Name: "test-bundle", Nodes: nodes}

		clashRes, err := subhub.RenderBundle(ctx, bundle, subhub.RenderOptions{Target: subhub.TargetClashMeta, UpMbps: 100, DownMbps: 200})
		if err != nil {
			t.Fatalf("RenderBundle ClashMeta: %v", err)
		}
		var clashDoc struct {
			Proxies []map[string]any `yaml:"proxies"`
		}
		if err := yaml.Unmarshal(clashRes.Body, &clashDoc); err != nil {
			t.Fatalf("unmarshal clash yaml: %v", err)
		}
		if len(clashDoc.Proxies) != 7 {
			t.Fatalf("expected 7 ClashMeta proxies, got %d", len(clashDoc.Proxies))
		}
		if clashDoc.Proxies[0]["client-fingerprint"] != "chrome" {
			t.Fatalf("expected default client-fingerprint=chrome, got %v", clashDoc.Proxies[0]["client-fingerprint"])
		}
		if clashDoc.Proxies[3]["cipher"] != "aes-256-gcm" {
			t.Fatalf("expected default ss cipher=aes-256-gcm, got %v", clashDoc.Proxies[3]["cipher"])
		}

		surgeRes, err := subhub.RenderBundle(ctx, bundle, subhub.RenderOptions{Target: subhub.TargetSurge, DownMbps: 200})
		if err != nil {
			t.Fatalf("RenderBundle Surge: %v", err)
		}
		surgeBody := string(surgeRes.Body)
		for _, want := range []string{"= hysteria2,", "= trojan,", "= ss,", "= vmess,", "= tuic-v5,", "= anytls,"} {
			if !strings.Contains(surgeBody, want) {
				t.Fatalf("expected Surge output to contain %q\n%s", want, surgeBody)
			}
		}
		if strings.Contains(surgeBody, "vless") {
			t.Fatalf("expected Surge output not to render vless\n%s", surgeBody)
		}

		loonRes, err := subhub.RenderBundle(ctx, bundle, subhub.RenderOptions{Target: subhub.TargetLoon})
		if err != nil {
			t.Fatalf("RenderBundle Loon: %v", err)
		}
		loonBody := string(loonRes.Body)
		for _, want := range []string{"= Hysteria2,", "= VLESS,", "= trojan,", "= Shadowsocks,"} {
			if !strings.Contains(loonBody, want) {
				t.Fatalf("expected Loon output to contain %q\n%s", want, loonBody)
			}
		}
		for _, skip := range []string{"tuic-1", "vm-1", "any-1"} {
			if strings.Contains(loonBody, skip) {
				t.Fatalf("expected Loon output not to render %q\n%s", skip, loonBody)
			}
		}

		fbRes, err := subhub.RenderBundle(ctx, bundle, subhub.RenderOptions{Target: subhub.TargetFormat("unknown")})
		if err != nil {
			t.Fatalf("RenderBundle fallback: %v", err)
		}
		if fbRes.Format != subhub.TargetBase64 {
			t.Fatalf("expected fallback format TargetBase64, got %s", fbRes.Format)
		}
	})

	t.Run("ocp_custom_protocol_registration_without_editing_core", func(t *testing.T) {
		customReg := subhub.NewProtocolRegistry(subhub.ProtocolCodec{
			Type:       "customproto",
			Aliases:    []string{"cp"},
			URISchemes: []string{"customproto://", "cp://"},
			DecodeSingBox: func(ob map[string]any, n *model.Node) bool {
				n.Password = subhub.AsString(ob["token"])
				return n.Password != ""
			},
			DecodeClash: func(p map[string]any, n *model.Node) bool {
				n.Password = subhub.AsString(p["token"])
				return n.Password != ""
			},
			EncodeURI: func(n model.Node, hostPort, escapedFrag string) string {
				return "customproto://" + url.User(n.Password).String() + "@" + hostPort + "#" + escapedFrag
			},
			EncodeClash: func(n model.Node, base map[string]any, _ subhub.RenderOptions) (map[string]any, bool) {
				base["type"] = "customproto"
				base["token"] = n.Password
				return base, true
			},
			EncodeSurgeLine: func(n model.Node, tag string, _ subhub.RenderOptions) (string, bool) {
				return tag + " = customproto, " + n.Addr, true
			},
			EncodeLoonLine: func(n model.Node, tag string, _ subhub.RenderOptions) (string, bool) {
				return tag + " = CustomProto, " + n.Addr, true
			},
		})

		if !customReg.HasSupportedScheme("cp://secret@198.51.100.1:443#n") {
			t.Fatal("expected custom scheme cp:// to be recognized")
		}
		var sbNode model.Node
		if !customReg.DecodeSingBox("cp", map[string]any{"token": "tok1"}, &sbNode) || sbNode.Type != "customproto" || sbNode.Password != "tok1" {
			t.Fatalf("DecodeSingBox customproto failed: %+v", sbNode)
		}
		var clashNode model.Node
		if !customReg.DecodeClash("customproto", map[string]any{"token": "tok2"}, &clashNode) || clashNode.Password != "tok2" {
			t.Fatalf("DecodeClash customproto failed: %+v", clashNode)
		}
		sbNode.Addr = "198.51.100.1"
		sbNode.Port = 443
		if got := customReg.EncodeURI(sbNode, "198.51.100.1:443", "n1"); got != "customproto://tok1@198.51.100.1:443#n1" {
			t.Fatalf("unexpected custom EncodeURI: %s", got)
		}
		if p, ok := customReg.EncodeClash(sbNode, map[string]any{"name": "n1"}, subhub.RenderOptions{}); !ok || p["token"] != "tok1" {
			t.Fatalf("unexpected custom EncodeClash: ok=%v p=%v", ok, p)
		}
		if line, ok := customReg.EncodeSurgeLine(sbNode, "n1", subhub.RenderOptions{}); !ok || !strings.Contains(line, "customproto") {
			t.Fatalf("unexpected custom EncodeSurgeLine: ok=%v line=%q", ok, line)
		}
		if line, ok := customReg.EncodeLoonLine(sbNode, "n1", subhub.RenderOptions{}); !ok || !strings.Contains(line, "CustomProto") {
			t.Fatalf("unexpected custom EncodeLoonLine: ok=%v line=%q", ok, line)
		}
	})

	t.Run("concurrent_registry_and_render_race_safe", func(t *testing.T) {
		bundle := &subhub.ResolvedBundle{
			Name: "race",
			Nodes: []model.Node{
				{Type: "hysteria2", Tag: "h1", Addr: "198.51.100.11", Port: 443, Password: "p"},
				{Type: "vless", Tag: "v1", Addr: "198.51.100.10", Port: 443, UUID: "11111111-1111-1111-1111-111111111111"},
			},
		}
		var wg sync.WaitGroup
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for _, target := range []subhub.TargetFormat{subhub.TargetBase64, subhub.TargetPlain, subhub.TargetClashMeta, subhub.TargetSurge, subhub.TargetLoon} {
					if _, err := subhub.RenderBundle(ctx, bundle, subhub.RenderOptions{Target: target}); err != nil {
						t.Errorf("concurrent RenderBundle(%s) failed: %v", target, err)
					}
				}
			}()
		}
		wg.Wait()
	})
}
