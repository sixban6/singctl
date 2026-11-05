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

		// 1. Auto 测速组必须自动剔除【5倍】高倍率节点，而 Select 保留供手动选
		autoGroup := byTag["Auto"]
		for _, item := range autoGroup {
			if item == "香港 001【5倍】" {
				t.Fatalf("[%s] Auto group must exclude high-multiplier nodes, got %v", platform, autoGroup)
			}
		}

		// 2. DNS 分组绝不能包含 DirectConn 或 Proxy，且首选 Auto (1倍低延迟节点)
		dnsGroup := byTag["DNS"]
		if len(dnsGroup) == 0 || dnsGroup[0] != "Auto" {
			t.Fatalf("[%s] DNS group should prioritize Auto, got %v", platform, dnsGroup)
		}
		for _, item := range dnsGroup {
			if item == "DirectConn" || item == "Proxy" {
				t.Fatalf("[%s] DNS group must be isolated from %s to prevent 8.8.8.8 GFW blackhole, got %v", platform, item, dnsGroup)
			}
		}

		// 3. HoK 分组首选 DIY-Node 自建免流节点，且 dns_hok 走 DNS (亚洲低延迟解析)
		hokGroup := byTag["HoK"]
		if len(hokGroup) == 0 || hokGroup[0] != "DIY-Node" {
			t.Fatalf("[%s] HoK group should prioritize DIY-Node, got %v", platform, hokGroup)
		}
		for _, srv := range parsed.DNS.Servers {
			if srv.Tag == "dns_hok" && srv.Detour != "DNS" {
				t.Fatalf("[%s] dns_hok detour = %q, want DNS", platform, srv.Detour)
			}
		}

		// 4. Game-UDP 分组存在且默认首选 DirectConn
		gameGroup := byTag["Game-UDP"]
		if len(gameGroup) == 0 || gameGroup[0] != "DirectConn" {
			t.Fatalf("[%s] Game-UDP group should default to DirectConn, got %v", platform, gameGroup)
		}
	}
}
