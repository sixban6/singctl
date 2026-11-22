// 文件职责：验证 cryptobak 灾备快照信封的 PBKDF2-HMAC-SHA256 + AES-256-GCM 加解密、AAD 防降级与防篡改边界。
package cryptobak_test

import (
	"encoding/json"
	"strings"
	"testing"

	"singctl/internal/common/cryptobak"
)

func TestEncryptAndDecrypt_RoundTripAndTamperRejection(t *testing.T) {
	type sampleBundle struct {
		Version     string            `json:"version"`
		SingctlYAML string            `json:"singctlYaml"`
		Keys        map[string][]byte `json:"keys"`
	}

	orig := sampleBundle{
		Version:     "1.20.0",
		SingctlYAML: "server:\n  node_domain: node.example.com\n",
		Keys:        map[string][]byte{"node1": []byte("dummy-test-key")},
	}

	// 1. Short passphrase rejected
	if _, err := cryptobak.Encrypt("SINGCTL-BAK-V1", "short", orig); err == nil {
		t.Fatal("expected passphrase < 8 chars to fail")
	}

	// 2. Round-trip success + no plaintext leakage in envelope
	rawEnv, err := cryptobak.Encrypt("SINGCTL-BAK-V1", "StrongPassphrase!2026", orig)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	if strings.Contains(string(rawEnv), "node.example.com") || strings.Contains(string(rawEnv), "dummy-test-key") {
		t.Fatalf("plaintext leaked in encrypted envelope: %s", string(rawEnv))
	}

	got, err := cryptobak.Decrypt[sampleBundle]("SINGCTL-BAK-V1", "StrongPassphrase!2026", rawEnv)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if got.SingctlYAML != orig.SingctlYAML || string(got.Keys["node1"]) != "dummy-test-key" {
		t.Fatalf("decrypted payload mismatch: %+v", got)
	}

	// 3. Wrong passphrase rejected by AES-GCM tag
	if _, err := cryptobak.Decrypt[sampleBundle]("SINGCTL-BAK-V1", "WrongPassphrase!9999", rawEnv); err == nil {
		t.Fatal("expected wrong passphrase to fail GCM authentication")
	}

	// 4. Cross-format AAD mismatch (e.g. client backup fed to server restore) rejected
	if _, err := cryptobak.Decrypt[sampleBundle]("SINGCTL-CLIENT-BAK-V1", "StrongPassphrase!2026", rawEnv); err == nil {
		t.Fatal("expected mismatched format version to fail")
	}

	// 5. Malformed JSON & out-of-range PBKDF2 iterations rejected (DoS / downgrade protection)
	if _, err := cryptobak.Decrypt[sampleBundle]("SINGCTL-BAK-V1", "StrongPassphrase!2026", []byte("{bad")); err == nil {
		t.Fatal("expected malformed JSON to fail")
	}
	var tampered cryptobak.Envelope
	_ = json.Unmarshal(rawEnv, &tampered)
	tampered.Iterations = 100 // dangerously low KDF iterations
	lowIterBytes, _ := json.Marshal(tampered)
	if _, err := cryptobak.Decrypt[sampleBundle]("SINGCTL-BAK-V1", "StrongPassphrase!2026", lowIterBytes); err == nil {
		t.Fatal("expected out-of-bounds KDF iterations to be rejected")
	}
}
