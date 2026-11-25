// 文件职责：验证单设备允许/禁止外网（全量 Direct）切换器、IPv4/IPv6 防自锁校验、sing-box 原地同步、存量连接斩断及 Collector 状态聚合。
package audit_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"singctl/internal/audit"
	"singctl/internal/config"
)

func TestDeviceOverseasAccess_EnforcerAndCollector(t *testing.T) {
	ctx := t.Context()

	t.Run("enforcer_validation_persistence_sync_and_kill_connections", func(t *testing.T) {
		tmpDir := t.TempDir()
		cfgPath := filepath.Join(tmpDir, "singctl.yaml")
		sbPath := filepath.Join(tmpDir, "config.json")
		aghPath := filepath.Join(tmpDir, "AdGuardHome.yaml")

		initialCfg := &config.Config{
			Subs: []config.Subscription{{Name: "main", URL: "https://sub.example.com/1"}},
		}
		if err := config.Save(cfgPath, initialCfg); err != nil {
			t.Fatal(err)
		}
		seedSB := `{
			"outbounds": [{"tag": "Proxy", "type": "direct"}, {"tag": "#DC", "type": "direct"}],
			"dns": {"servers": [{"tag": "dns_local", "type": "udp", "server": "223.5.5.5"}], "rules": [{"domain_suffix": ["cn"], "server": "dns_local"}]},
			"route": {"rules": [{"action": "sniff"}, {"domain_suffix": ["cn"], "outbound": "#DC"}]}
		}`
		if err := os.WriteFile(sbPath, []byte(seedSB), 0600); err != nil {
			t.Fatal(err)
		}

		var mu sync.Mutex
		var deletedIDs []string
		mockClash := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet && r.URL.Path == "/connections" {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"connections": []map[string]any{
						{"id": "c-tv-1", "metadata": map[string]any{"sourceIP": "192.168.1.50", "host": "video.example.com", "destinationIP": "203.0.113.10"}},
						{"id": "c-pc-2", "metadata": map[string]any{"sourceIP": "192.168.1.99", "host": "web.example.com", "destinationIP": "203.0.113.20"}},
					},
				})
				return
			}
			if r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/connections/") {
				id := strings.TrimPrefix(r.URL.Path, "/connections/")
				mu.Lock()
				deletedIDs = append(deletedIDs, id)
				mu.Unlock()
				w.WriteHeader(http.StatusNoContent)
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))
		defer mockClash.Close()

		enforcer := audit.NewEnforcer(initialCfg, cfgPath)
		enforcer.SetPathsForTest(sbPath, aghPath, []string{mockClash.URL}, "")

		// Reject invalid, loopback, public IPs
		for _, badIP := range []string{"", "not-an-ip", "127.0.0.1", "::1", "0.0.0.0", "8.8.8.8", "1.1.1.1"} {
			if _, err := enforcer.SetDeviceOverseasAccess(ctx, badIP, false); err == nil {
				t.Fatalf("expected invalid/unsafe device IP %q to be rejected", badIP)
			}
		}

		// Disable overseas (force direct) for 192.168.1.50
		resOff, err := enforcer.SetDeviceOverseasAccess(ctx, "192.168.1.50", false)
		if err != nil {
			t.Fatalf("SetDeviceOverseasAccess(false) failed: %v", err)
		}
		if !resOff.OK || resOff.AllowOverseas || resOff.DeviceIP != "192.168.1.50" || !resOff.ConfigSaved || !resOff.SingBoxSynced {
			t.Fatalf("unexpected resOff: %+v", resOff)
		}
		if resOff.KilledConnections != 1 {
			t.Fatalf("expected 1 killed connection for 192.168.1.50, got %d (deleted=%v)", resOff.KilledConnections, deletedIDs)
		}
		mu.Lock()
		if len(deletedIDs) != 1 || deletedIDs[0] != "c-tv-1" {
			t.Fatalf("expected only c-tv-1 deleted, got %v", deletedIDs)
		}
		mu.Unlock()

		fi, err := os.Stat(cfgPath)
		if err != nil || fi.Mode().Perm() != 0600 {
			t.Fatalf("expected 0600 permissions on singctl.yaml, got %v", fi.Mode().Perm())
		}
		sbBytes, err := os.ReadFile(sbPath)
		if err != nil || !strings.Contains(string(sbBytes), "192.168.1.50/32") {
			t.Fatalf("expected 192.168.1.50/32 in sing-box config.json, err=%v body=%s", err, string(sbBytes))
		}

		// Re-enable overseas access
		resOn, err := enforcer.SetDeviceOverseasAccess(ctx, "192.168.1.50", true)
		if err != nil {
			t.Fatalf("SetDeviceOverseasAccess(true) failed: %v", err)
		}
		if !resOn.OK || !resOn.AllowOverseas || len(resOn.DirectDevices) != 0 {
			t.Fatalf("unexpected resOn: %+v", resOn)
		}
		sbBytes2, _ := os.ReadFile(sbPath)
		if strings.Contains(string(sbBytes2), "192.168.1.50") {
			t.Fatalf("expected 192.168.1.50 removed from config.json, got:\n%s", string(sbBytes2))
		}
	})

	t.Run("collector_populates_allow_overseas_per_device", func(t *testing.T) {
		mockClash := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"connections": []map[string]any{
					{
						"id":       "1",
						"upload":   1000,
						"download": 2000,
						"chains":   []string{"#DC"},
						"metadata": map[string]any{"sourceIP": "192.168.1.50", "host": "api.example.com", "network": "tcp", "destinationPort": "443"},
					},
					{
						"id":       "2",
						"upload":   1000,
						"download": 2000,
						"chains":   []string{"Proxy"},
						"metadata": map[string]any{"sourceIP": "192.168.1.60", "host": "www.example.com", "network": "tcp", "destinationPort": "443"},
					},
				},
			})
		}))
		defer mockClash.Close()

		cfg := &config.Config{
			Audit: config.AuditConfig{
				DirectDevices: []string{"192.168.1.50"},
			},
		}
		col := audit.NewCollectorWithOptions(cfg, audit.CollectorOptions{})
		col.SetEndpointsForTest([]string{mockClash.URL}, "", filepath.Join(t.TempDir(), "audit-state.json"))
		rep := col.CollectWithConfig(ctx, cfg, audit.CollectOptions{})
		if len(rep.Devices) != 2 {
			t.Fatalf("expected 2 devices, got %d", len(rep.Devices))
		}
		byIP := map[string]bool{}
		for _, d := range rep.Devices {
			byIP[d.DeviceIP] = d.AllowOverseas
		}
		if byIP["192.168.1.50"] != false || byIP["192.168.1.60"] != true {
			t.Fatalf("unexpected AllowOverseas map: %+v", byIP)
		}
	})
}
