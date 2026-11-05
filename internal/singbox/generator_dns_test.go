package singbox

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"singctl/internal/adguard"
	"singctl/internal/config"
)

func TestGenerator_InjectLocalDNS_AdGuardHome(t *testing.T) {
	payload := encodeURISub(
		"hysteria2://dummy-pass@hk1.example.com:443?sni=hk1.example.com#HK-Primary",
	)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(payload))
	}))
	defer ts.Close()

	t.Cleanup(func() {
		adguard.SetInstalledCheckForTest(nil)
	})

	extractDNSLocal := func(t *testing.T, rawJSON string) map[string]any {
		t.Helper()
		var root struct {
			DNS struct {
				Servers []map[string]any `json:"servers"`
			} `json:"dns"`
		}
		if err := json.Unmarshal([]byte(rawJSON), &root); err != nil {
			t.Fatalf("unmarshal json: %v", err)
		}
		for _, srv := range root.DNS.Servers {
			if srv["tag"] == "dns_local" {
				return srv
			}
		}
		t.Fatal("dns_local server not found in generated config")
		return nil
	}

	t.Run("linux routes dns_local to AdGuardHome when installed and enabled", func(t *testing.T) {
		adguard.SetInstalledCheckForTest(func() bool { return true })
		cfg := &config.Config{
			Subs: []config.Subscription{{Name: "main", URL: ts.URL}},
			DNS:  config.ClientDNSConfig{DNSPort: 5353},
		}
		gen := NewConfigGenerator(cfg)
		gen.SetCacheDir(t.TempDir())

		out, err := gen.GenerateForPlatform("linux")
		if err != nil {
			t.Fatalf("GenerateForPlatform(linux) failed: %v", err)
		}
		srv := extractDNSLocal(t, out)
		if srv["server"] != "127.0.0.1" || int(srv["server_port"].(float64)) != 5353 || srv["type"] != "udp" {
			t.Fatalf("unexpected dns_local: %+v", srv)
		}

		if sbBin, err := exec.LookPath("sing-box"); err == nil && sbBin != "" {
			checkJSON := out
			if runtime.GOOS != "linux" {
				// macOS/Windows 上的 sing-box check 不支持 Linux 专属 TProxy/default_mark，
				// 用 darwin 基准配置叠加相同的 dns_local 结构校验 DNS schema 合法性
				darwinBase, err := gen.GenerateForPlatform("darwin")
				if err != nil {
					t.Fatalf("GenerateForPlatform(darwin) failed: %v", err)
				}
				checkJSON, err = gen.InjectLocalDNS(darwinBase, "linux")
				if err != nil {
					t.Fatalf("InjectLocalDNS failed: %v", err)
				}
			}
			cfgFile := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(cfgFile, []byte(checkJSON), 0600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.CommandContext(t.Context(), sbBin, "check", "-c", cfgFile)
			if checkOut, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("sing-box check failed: %v\n%s", err, string(checkOut))
			}
		}
	})

	t.Run("ios never routes dns_local to loopback AdGuardHome", func(t *testing.T) {
		adguard.SetInstalledCheckForTest(func() bool { return true })
		cfg := &config.Config{
			Subs: []config.Subscription{{Name: "main", URL: ts.URL}},
		}
		gen := NewConfigGenerator(cfg)
		gen.SetCacheDir(t.TempDir())

		out, err := gen.GenerateForPlatform(PlatformIOS)
		if err != nil {
			t.Fatalf("GenerateForPlatform(ios) failed: %v", err)
		}
		srv := extractDNSLocal(t, out)
		if srv["server"] == "127.0.0.1" {
			t.Fatalf("iOS config must not point dns_local to 127.0.0.1, got %+v", srv)
		}
	})

	t.Run("linux skips AdGuardHome when dns.enabled is false", func(t *testing.T) {
		adguard.SetInstalledCheckForTest(func() bool { return true })
		disabled := false
		cfg := &config.Config{
			Subs: []config.Subscription{{Name: "main", URL: ts.URL}},
			DNS:  config.ClientDNSConfig{Enabled: &disabled, DNSPort: 5353},
		}
		gen := NewConfigGenerator(cfg)
		gen.SetCacheDir(t.TempDir())

		out, err := gen.GenerateForPlatform("linux")
		if err != nil {
			t.Fatalf("GenerateForPlatform(linux) failed: %v", err)
		}
		srv := extractDNSLocal(t, out)
		if srv["server"] == "127.0.0.1" {
			t.Fatalf("expected dns_local not to be 127.0.0.1 when disabled, got %+v", srv)
		}
	})
}

func TestGenerator_GameUDPAndDNSIsolation(t *testing.T) {
	payload := encodeURISub(
		"hysteria2://dummy-pass@los.example.com:443?sni=los.example.com#sec_los_hy2",
		"hysteria2://dummy-pass@hk1.example.com:443?sni=hk1.example.com#HK-01",
		"hysteria2://dummy-pass@hk5.example.com:443?sni=hk5.example.com#香港 001【5倍】",
	)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(payload))
	}))
	defer ts.Close()

	cfg := &config.Config{
		Subs: []config.Subscription{{Name: "main", URL: ts.URL}},
	}
	gen := NewConfigGenerator(cfg)
	gen.SetCacheDir(t.TempDir())

	for _, platform := range []string{"linux", PlatformIOS, "darwin"} {
		out, err := gen.GenerateForPlatform(platform)
		if err != nil {
			t.Fatalf("GenerateForPlatform(%s) failed: %v", platform, err)
		}
		var parsed struct {
			DNS struct {
				Servers []struct {
					Tag    string `json:"tag"`
					Detour string `json:"detour"`
				} `json:"servers"`
			} `json:"dns"`
			Outbounds []struct {
				Tag       string   `json:"tag"`
				Outbounds []string `json:"outbounds"`
			} `json:"outbounds"`
		}
		if err := json.Unmarshal([]byte(out), &parsed); err != nil {
			t.Fatal(err)
		}

		byTag := make(map[string][]string)
		for _, ob := range parsed.Outbounds {
			byTag[ob.Tag] = ob.Outbounds
		}

		// 1. 冗余分组已被彻底精简移除，仅保留 6 个核心控制/节点池组
		for _, removed := range []string{"DIY-Node", "DNS", "HoK", "YouTube", "OpenAI", "Google", "Netflix", "Steam"} {
			if _, exists := byTag[removed]; exists {
				t.Fatalf("[%s] redundant group %q should be removed", platform, removed)
			}
		}

		// 2. Auto 测速组必须自动剔除【5倍】高倍率节点，而 Select 保留供手动选
		autoGroup := byTag["Auto"]
		for _, item := range autoGroup {
			if item == "香港 001【5倍】" {
				t.Fatalf("[%s] Auto group must exclude high-multiplier nodes, got %v", platform, autoGroup)
			}
		}

		// 3. VPS 自建池、Proxy 与 AI 默认首选 VPS，Game-UDP 默认首选 DirectConn
		if len(byTag["VPS"]) == 0 {
			t.Fatalf("[%s] expected VPS group to contain sec_ nodes", platform)
		}
		if got := byTag["Proxy"]; len(got) == 0 || got[0] != "VPS" {
			t.Fatalf("[%s] Proxy should default to VPS, got %v", platform, got)
		}
		if got := byTag["AI"]; len(got) == 0 || got[0] != "VPS" {
			t.Fatalf("[%s] AI should default to VPS, got %v", platform, got)
		}
		if got := byTag["Game-UDP"]; len(got) == 0 || got[0] != "DirectConn" {
			t.Fatalf("[%s] Game-UDP should default to DirectConn, got %v", platform, got)
		}

		// 4. dns_proxy 独立绑 VPS，dns_hok 独立绑 Auto (彻底解耦且隔离 DirectConn)
		detours := make(map[string]string)
		for _, srv := range parsed.DNS.Servers {
			detours[srv.Tag] = srv.Detour
		}
		if detours["dns_proxy"] != "VPS" {
			t.Fatalf("[%s] dns_proxy detour = %q, want VPS", platform, detours["dns_proxy"])
		}
		if detours["dns_hok"] != "Auto" {
			t.Fatalf("[%s] dns_hok detour = %q, want Auto", platform, detours["dns_hok"])
		}
	}
}
