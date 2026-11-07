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

		var fullCfg struct {
			DNS struct {
				DisableCache bool `json:"disable_cache"`
				Optimistic   bool `json:"optimistic"`
			} `json:"dns"`
			Experimental struct {
				CacheFile struct {
					StoreDNS    bool `json:"store_dns"`
					StoreFakeIP bool `json:"store_fakeip"`
				} `json:"cache_file"`
			} `json:"experimental"`
		}
		if err := json.Unmarshal([]byte(out), &fullCfg); err != nil {
			t.Fatalf("unmarshal full config: %v", err)
		}
		if !fullCfg.DNS.DisableCache || fullCfg.DNS.Optimistic {
			t.Fatalf("expected sing-box dns disable_cache=true and optimistic=false when AdGuardHome is active, got %+v", fullCfg.DNS)
		}
		if fullCfg.Experimental.CacheFile.StoreDNS || fullCfg.Experimental.CacheFile.StoreFakeIP {
			t.Fatalf("expected store_dns=false and store_fakeip=false when AdGuardHome is active, got %+v", fullCfg.Experimental.CacheFile)
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

		// 1. 冗余旧分组已被精简移除，保留两层清晰结构：分流组(Proxy/AI/Game/Game-UDP) + 节点池(#VPS/#Auto/#Nodes)
		for _, removed := range []string{"DIY-Node", "VPS", "Auto", "Select", "DNS", "HoK", "YouTube", "OpenAI", "Google", "Netflix", "Steam"} {
			if _, exists := byTag[removed]; exists {
				t.Fatalf("[%s] redundant group %q should be removed", platform, removed)
			}
		}

		// 2. #Auto 测速池必须自动剔除【5倍】高倍率节点，而 #Nodes 保留供手动选
		autoPool := byTag["#Auto"]
		if len(autoPool) == 0 {
			t.Fatalf("[%s] expected #Auto pool to be non-empty", platform)
		}
		for _, item := range autoPool {
			if item == "香港 001【5倍】" {
				t.Fatalf("[%s] #Auto pool must exclude high-multiplier nodes, got %v", platform, autoPool)
			}
		}

		// 3. 验证 4 个分流控制组默认首选项
		if len(byTag["#VPS"]) == 0 {
			t.Fatalf("[%s] expected #VPS pool to contain sec_ nodes", platform)
		}
		if got := byTag["Proxy"]; len(got) == 0 || got[0] != "#VPS" {
			t.Fatalf("[%s] Proxy should default to #VPS, got %v", platform, got)
		}
		if got := byTag["AI"]; len(got) == 0 || got[0] != "#VPS" {
			t.Fatalf("[%s] AI should default to #VPS, got %v", platform, got)
		}
		if got := byTag["Game"]; len(got) == 0 || got[0] != "#Auto" {
			t.Fatalf("[%s] Game should default to #Auto, got %v", platform, got)
		}
		if got := byTag["Game-UDP"]; len(got) == 0 || got[0] != "DirectConn" {
			t.Fatalf("[%s] Game-UDP should default to DirectConn, got %v", platform, got)
		}

		// 4. dns_proxy 独立绑 #VPS，dns_hok 独立绑 #Auto
		detours := make(map[string]string)
		for _, srv := range parsed.DNS.Servers {
			detours[srv.Tag] = srv.Detour
		}
		if detours["dns_proxy"] != "#VPS" {
			t.Fatalf("[%s] dns_proxy detour = %q, want #VPS", platform, detours["dns_proxy"])
		}
		if detours["dns_hok"] != "#Auto" {
			t.Fatalf("[%s] dns_hok detour = %q, want #Auto", platform, detours["dns_hok"])
		}
	}
}
