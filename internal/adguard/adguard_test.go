package adguard

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"singctl/internal/config"

	"gopkg.in/yaml.v3"
)

func TestSelectAssetName(t *testing.T) {
	cases := []struct {
		goos, goarch string
		want         string
		wantErr      bool
	}{
		{"linux", "amd64", "AdGuardHome_linux_amd64.tar.gz", false},
		{"linux", "arm64", "AdGuardHome_linux_arm64.tar.gz", false},
		{"linux", "arm", "AdGuardHome_linux_armv7.tar.gz", false},
		{"darwin", "arm64", "AdGuardHome_darwin_arm64.zip", false},
		{"windows", "amd64", "", true},
	}
	for _, tc := range cases {
		got, err := SelectAssetName(tc.goos, tc.goarch)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("SelectAssetName(%s,%s) expected error, got %q", tc.goos, tc.goarch, got)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Fatalf("SelectAssetName(%s,%s) = %q, %v; want %q", tc.goos, tc.goarch, got, err, tc.want)
		}
	}
}

func TestPromptAdminUsername(t *testing.T) {
	if got := PromptAdminUsername(strings.NewReader("\n")); got != "root" {
		t.Fatalf("empty enter should default to root, got %q", got)
	}
	if got := PromptAdminUsername(strings.NewReader("alice_01\n")); got != "alice_01" {
		t.Fatalf("expected alice_01, got %q", got)
	}
	if got := PromptAdminUsername(strings.NewReader("bad user;rm\n")); got != "root" {
		t.Fatalf("invalid username should fallback to root, got %q", got)
	}
}

func TestBuildInitialConfigYAMLAndSyncExisting(t *testing.T) {
	hash, err := config.HashPassword("TestPass12345678")
	if err != nil {
		t.Fatal(err)
	}

	yamlBytes, err := BuildInitialConfigYAML(ConfigParams{
		LANIP:        "192.168.1.1",
		WebPort:      3000,
		DNSPort:      5353,
		Username:     "", // should default to root
		PasswordHash: hash,
		IsOpenWrt:    true,
		SubURLs:      []string{"https://sub.example.com/key/download"},
	})
	if err != nil {
		t.Fatalf("BuildInitialConfigYAML failed: %v", err)
	}

	// Never bind 0.0.0.0
	if bytes.Contains(yamlBytes, []byte("0.0.0.0")) {
		t.Fatalf("generated YAML must never contain 0.0.0.0:\n%s", string(yamlBytes))
	}

	var parsed map[string]any
	if err := yaml.Unmarshal(yamlBytes, &parsed); err != nil {
		t.Fatalf("unmarshal YAML: %v", err)
	}

	httpMap := parsed["http"].(map[string]any)
	if httpMap["address"] != "192.168.1.1:3000" {
		t.Fatalf("http.address = %v, want 192.168.1.1:3000", httpMap["address"])
	}

	users := parsed["users"].([]any)
	firstUser := users[0].(map[string]any)
	if firstUser["name"] != "root" {
		t.Fatalf("user.name = %v, want root", firstUser["name"])
	}

	dnsMap := parsed["dns"].(map[string]any)
	if dnsMap["port"] != 5353 || dnsMap["ratelimit"] != 0 {
		t.Fatalf("unexpected dns port/ratelimit: %+v", dnsMap)
	}

	queryLogMap := parsed["querylog"].(map[string]any)
	if queryLogMap["file_enabled"] != false {
		t.Fatalf("OpenWrt querylog.file_enabled should be false to protect flash, got %v", queryLogMap["file_enabled"])
	}

	userRules := parsed["user_rules"].([]any)
	if len(userRules) != 1 || userRules[0] != "@@||sub.example.com^$important" {
		t.Fatalf("unexpected user_rules: %+v", userRules)
	}

	// Write and verify 0600 permissions + non-destructive SyncExistingConfig
	cfgFile := filepath.Join(t.TempDir(), "AdGuardHome", "AdGuardHome.yaml")
	if err := WriteConfigAtomically(cfgFile, yamlBytes); err != nil {
		t.Fatalf("WriteConfigAtomically failed: %v", err)
	}
	fi, err := os.Stat(cfgFile)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0600 {
		t.Fatalf("expected 0600 permission on AdGuardHome.yaml, got %o", perm)
	}

	changed, err := SyncExistingConfig(cfgFile, SyncOptions{
		LANIP:   "192.168.50.1",
		WebPort: 3002,
		DNSPort: 5353,
	})
	if err != nil || !changed {
		t.Fatalf("SyncExistingConfig expected changed=true, got changed=%v err=%v", changed, err)
	}
	if gotAddr := ReadCurrentHTTPAddress(cfgFile); gotAddr != "192.168.50.1:3002" {
		t.Fatalf("ReadCurrentHTTPAddress = %q, want 192.168.50.1:3002", gotAddr)
	}
}

func TestProbeDNS_MockServer(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	go func() {
		buf := make([]byte, 512)
		n, addr, err := pc.ReadFrom(buf)
		if err != nil || n < 12 {
			return
		}
		resp := make([]byte, n)
		copy(resp, buf[:n])
		resp[2] |= 0x80 // QR = 1 (Response)
		_, _ = pc.WriteTo(resp, addr)
	}()

	if err := ProbeDNS(pc.LocalAddr().String(), time.Second); err != nil {
		t.Fatalf("ProbeDNS against mock server failed: %v", err)
	}
}
