// 文件职责：测试客户端 WebUI 本地域名管理接口（GET/PUT/POST/DELETE/verify）、托管重写防误删与输入安全校验。
package webui_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"singctl/internal/config"
	"singctl/internal/homedomain"
	"singctl/internal/webui"
)

func TestHomeDomainAPI_CRUDSettingsVerifyAndManagedProtection(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "singctl.yaml")
	sbCfgPath := filepath.Join(dir, "config.json")

	initCfg := &config.Config{
		DNS: config.ClientDNSConfig{
			Rewrites: []config.DNSRewriteRule{
				{Domain: "custom.example.com", Answer: "198.51.100.5"},
			},
		},
	}
	if err := config.Save(cfgPath, initCfg); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(sbCfgPath, []byte(`{
		"dns": {
			"servers": [
				{"tag": "dns_proxy", "type": "https", "server": "1.1.1.1"},
				{"tag": "dns_local", "type": "udp", "server": "127.0.0.1", "server_port": 5353}
			],
			"rules": [{"domain_suffix": ["openai.com"], "server": "dns_proxy"}],
			"final": "dns_proxy"
		},
		"route": {
			"rules": [{"protocol": "dns", "action": "hijack-dns"}],
			"final": "#VPS"
		}
	}`), 0600)

	srv := webui.New(webui.Options{
		ConfigPath:        cfgPath,
		SingBoxConfigPath: sbCfgPath,
		HomeDomainForTest: &webui.HomeDomainTestHooks{
			Discovery: func(context.Context) homedomain.DiscoverySnapshot {
				return homedomain.DiscoverySnapshot{
					Self: homedomain.SelfRouterInfo{
						Hostname:          "n4120",
						SuggestedAlias:    "n4120",
						LANIP:             "192.0.2.1",
						TailscaleIP:       "100.64.0.1",
						TailscaleOnline:   true,
						AdvertisedSubnets: []string{"192.0.2.0/24"},
					},
					LANDevices: []homedomain.DiscoveredLANDevice{
						{IP: "192.0.2.10", MAC: "aa:bb:cc:dd:ee:01", Hostname: "MyNAS", SuggestedAlias: "mynas", Online: true},
					},
					TailscalePeers: []homedomain.DiscoveredTailscalePeer{
						{Hostname: "ax3000t", SuggestedAlias: "ax3000t", TailscaleIP: "100.64.0.22", Online: true, OS: "linux"},
					},
				}
			},
			DnsmasqDeps: homedomain.DnsmasqDeps{
				IsOpenWrt: func() bool { return false },
			},
			ProbeFunc: func(_ context.Context, _, domain string, _ time.Duration) ([]string, time.Duration, error) {
				if strings.HasPrefix(domain, "nas.") {
					return []string{"192.0.2.10"}, 2 * time.Millisecond, nil
				}
				return []string{"100.64.0.22"}, 2 * time.Millisecond, nil
			},
			ResponderStatus: func() homedomain.ResponderStatus {
				return homedomain.ResponderStatus{Running: true, ListenAddr: "100.64.0.1:53", Suffix: "home", RecordCount: 2}
			},
		},
	})

	doJSON := func(method, path string, payload any) *httptest.ResponseRecorder {
		var body []byte
		if payload != nil {
			body, _ = json.Marshal(payload)
		}
		req := httptest.NewRequest(method, path, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		srv.Mux.ServeHTTP(rec, req)
		return rec
	}

	// 1. GET /api/home-domain
	rec := doJSON(http.MethodGet, "/api/home-domain", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/home-domain status=%d body=%s", rec.Code, rec.Body.String())
	}
	var snap map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &snap); err != nil {
		t.Fatal(err)
	}
	if snap["suffix"] != "home" {
		t.Fatalf("expected default suffix home, got %v", snap["suffix"])
	}

	// 2. POST /api/home-domain/devices -> add nas (wildcard) + ax3000t
	rec = doJSON(http.MethodPost, "/api/home-domain/devices", map[string]any{
		"alias":       "nas",
		"displayName": "家庭NAS",
		"ip":          "192.0.2.10",
		"mac":         "aa:bb:cc:dd:ee:01",
		"source":      "lan",
		"wildcard":    true,
		"services":    []map[string]any{{"label": "DSM", "scheme": "http", "port": 5000}},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST nas failed status=%d body=%s", rec.Code, rec.Body.String())
	}
	// Invalid alias rejected with 400
	recBad := doJSON(http.MethodPost, "/api/home-domain/devices", map[string]any{
		"alias": "bad.dot",
		"ip":    "192.0.2.11",
	})
	if recBad.Code != http.StatusBadRequest {
		t.Fatalf("invalid alias expected 400, got %d", recBad.Code)
	}

	// Verify sing-box config patched with home suffix rule
	sbRaw, _ := os.ReadFile(sbCfgPath)
	if !strings.Contains(string(sbRaw), `"home"`) {
		t.Fatalf("expected sing-box config patched with home suffix, got:\n%s", string(sbRaw))
	}

	// 3. PUT /api/home-domain/settings -> reject .local (400), accept home.arpa (200)
	recBadSfx := doJSON(http.MethodPut, "/api/home-domain/settings", map[string]any{
		"enabled":      true,
		"suffix":       "local",
		"tailscaleDns": true,
		"followDhcp":   true,
	})
	if recBadSfx.Code != http.StatusBadRequest {
		t.Fatalf(".local suffix expected 400, got %d", recBadSfx.Code)
	}
	recSfx := doJSON(http.MethodPut, "/api/home-domain/settings", map[string]any{
		"enabled":      true,
		"suffix":       "home.arpa",
		"tailscaleDns": true,
		"followDhcp":   true,
	})
	if recSfx.Code != http.StatusOK {
		t.Fatalf("PUT home.arpa failed status=%d body=%s", recSfx.Code, recSfx.Body.String())
	}

	// Verify manual rewrite preserved and managed rewrite migrated to home.arpa
	reloaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.HomeDomain.EffectiveSuffix() != "home.arpa" {
		t.Fatalf("expected home.arpa persisted, got %s", reloaded.HomeDomain.EffectiveSuffix())
	}
	hasManual := false
	hasMigrated := false
	for _, rw := range reloaded.DNS.Rewrites {
		if rw.Domain == "custom.example.com" {
			hasManual = true
		}
		if rw.Domain == "nas.home.arpa" {
			hasMigrated = true
		}
		if rw.Domain == "nas.home" {
			t.Fatalf("stale managed rewrite nas.home should be cleaned up")
		}
	}
	if !hasManual || !hasMigrated {
		t.Fatalf("expected manual + migrated rewrites, got %+v", reloaded.DNS.Rewrites)
	}

	// 4. Managed rewrite protected from direct deletion via POST /api/dns/rewrites
	recProt := doJSON(http.MethodPost, "/api/dns/rewrites", map[string]any{
		"action": "delete",
		"domain": "nas.home.arpa",
		"answer": "192.0.2.10",
	})
	if recProt.Code != http.StatusBadRequest {
		t.Fatalf("deleting managed home-domain rewrite via /api/dns/rewrites must return 400, got %d body=%s", recProt.Code, recProt.Body.String())
	}

	// 5. POST /api/home-domain/verify
	recVer := doJSON(http.MethodPost, "/api/home-domain/verify", nil)
	if recVer.Code != http.StatusOK {
		t.Fatalf("POST /api/home-domain/verify status=%d body=%s", recVer.Code, recVer.Body.String())
	}
	var verRep homedomain.VerifyReport
	if err := json.Unmarshal(recVer.Body.Bytes(), &verRep); err != nil || !verRep.OverallOK {
		t.Fatalf("expected overallOk=true verify report, got %+v err=%v", verRep, err)
	}

	// 6. DELETE /api/home-domain/devices/nas
	recDel := doJSON(http.MethodDelete, "/api/home-domain/devices/nas", nil)
	if recDel.Code != http.StatusOK {
		t.Fatalf("DELETE /api/home-domain/devices/nas status=%d body=%s", recDel.Code, recDel.Body.String())
	}
	reloaded2, _ := config.Load(cfgPath)
	if len(reloaded2.HomeDomain.Devices) != 0 {
		t.Fatalf("expected 0 devices after delete, got %+v", reloaded2.HomeDomain.Devices)
	}
}
