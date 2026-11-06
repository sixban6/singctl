package deploy

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestGenerateWireguardKeypair(t *testing.T) {
	privKey, pubKey, err := generateWireguardKeypair()
	if err != nil {
		t.Fatalf("generateWireguardKeypair failed: %v", err)
	}

	privBytes, err := base64.StdEncoding.DecodeString(privKey)
	if err != nil {
		t.Fatalf("failed to decode privKey: %v", err)
	}
	if len(privBytes) != 32 {
		t.Errorf("expected 32 byte private key, got %d", len(privBytes))
	}

	pubBytes, err := base64.StdEncoding.DecodeString(pubKey)
	if err != nil {
		t.Fatalf("failed to decode pubKey: %v", err)
	}
	if len(pubBytes) != 32 {
		t.Errorf("expected 32 byte public key, got %d", len(pubBytes))
	}
}

func TestBuildAndNormalizeWireproxyConfig(t *testing.T) {
	confV4Only := buildWireproxyConfig("172.16.0.2/32", "test-priv", "test-pub", false)
	if !strings.Contains(confV4Only, "Endpoint = 162.159.192.1:2408") {
		t.Fatalf("expected IPv4 endpoint in config: %s", confV4Only)
	}
	if strings.Contains(confV4Only, "PersistentKeepalive") {
		t.Fatalf("did not expect PersistentKeepalive in wireproxy config: %s", confV4Only)
	}
	if !strings.Contains(confV4Only, "ResolveStrategy = ipv4") {
		t.Fatalf("expected ResolveStrategy = ipv4 in config: %s", confV4Only)
	}
	if strings.Contains(confV4Only, "2606:4700:4700::1111") {
		t.Fatalf("did not expect IPv6 DNS on IPv4-only host: %s", confV4Only)
	}

	legacyConf := `[Interface]
Address = 172.16.0.2/32, 2606:4700:110::1/128
MTU = 1420
PrivateKey = dummy
DNS = 1.1.1.1,8.8.8.8

[Peer]
PublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=
Endpoint = engage.cloudflareclient.com:2408
PersistentKeepalive = 25

[Socks5]
BindAddress = 127.0.0.1:40000

[Resolve]
ResolveStrategy = auto
`
	normalized, changed := NormalizeWireproxyConfigContent(legacyConf)
	if !changed {
		t.Fatalf("expected legacy wireproxy config to be marked changed")
	}
	if !strings.Contains(normalized, "Endpoint = 162.159.192.1:2408") {
		t.Errorf("expected Endpoint normalized to IPv4, got:\n%s", normalized)
	}
	if strings.Contains(normalized, "PersistentKeepalive = 25") {
		t.Errorf("expected PersistentKeepalive = 25 removed, got:\n%s", normalized)
	}
	if !strings.Contains(normalized, "ResolveStrategy = ipv4") {
		t.Errorf("expected ResolveStrategy = ipv4, got:\n%s", normalized)
	}

	// Second pass should be idempotent
	_, changedAgain := NormalizeWireproxyConfigContent(normalized)
	if changedAgain {
		t.Errorf("expected NormalizeWireproxyConfigContent to be idempotent")
	}
}
