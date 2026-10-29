package deploy

import (
	"encoding/base64"
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
