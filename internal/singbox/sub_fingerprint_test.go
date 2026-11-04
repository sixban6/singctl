package singbox

import (
	"testing"
)

func TestProxyOutboundsFingerprintDeterministic(t *testing.T) {
	cfgA := `{
  "outbounds": [
    {"type": "selector", "tag": "DIY-Node", "outbounds": ["node_b", "node_a"]},
    {"type": "hysteria2", "tag": "node_b", "server": "b.example.com", "server_port": 443, "password": "p2"},
    {"type": "vless", "tag": "node_a", "server": "a.example.com", "server_port": 443, "uuid": "u1"},
    {"type": "direct", "tag": "DirectConn"}
  ]
}`
	// Reordered outbounds & changed selector default order, but identical concrete proxy nodes
	cfgB := `{
  "outbounds": [
    {"type": "direct", "tag": "DirectConn"},
    {"type": "vless", "tag": "node_a", "uuid": "u1", "server_port": 443, "server": "a.example.com"},
    {"type": "hysteria2", "tag": "node_b", "password": "p2", "server_port": 443, "server": "b.example.com"},
    {"type": "selector", "tag": "DIY-Node", "outbounds": ["node_a", "node_b"]}
  ]
}`
	// Rotated password on node_b
	cfgC := `{
  "outbounds": [
    {"type": "vless", "tag": "node_a", "server": "a.example.com", "server_port": 443, "uuid": "u1"},
    {"type": "hysteria2", "tag": "node_b", "server": "b.example.com", "server_port": 443, "password": "NEW_PASSWORD"}
  ]
}`

	hashA, countA, err := ProxyOutboundsFingerprint(cfgA)
	if err != nil || countA != 2 {
		t.Fatalf("cfgA fingerprint failed: count=%d err=%v", countA, err)
	}
	hashB, countB, err := ProxyOutboundsFingerprint(cfgB)
	if err != nil || countB != 2 {
		t.Fatalf("cfgB fingerprint failed: count=%d err=%v", countB, err)
	}
	if hashA != hashB {
		t.Fatalf("expected identical fingerprint regardless of outbound slice order: %s vs %s", hashA, hashB)
	}

	hashC, countC, err := ProxyOutboundsFingerprint(cfgC)
	if err != nil || countC != 2 {
		t.Fatalf("cfgC fingerprint failed: count=%d err=%v", countC, err)
	}
	if hashC == hashA {
		t.Fatal("expected password rotation to change proxy outbound fingerprint")
	}
}
