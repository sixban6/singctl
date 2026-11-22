// 文件职责：验证 Config 零反射深拷贝（Clone）全字段隔离与 config.Store 原子快照仓库的指纹重载、坏配置兜底及高并发读写安全。
package config_test

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"singctl/internal/config"
)

func boolPtr(v bool) *bool { return &v }

func TestConfigClone_DeepIsolation(t *testing.T) {
	orig := &config.Config{
		Subs: []config.Subscription{
			{
				Name:    "sub-a",
				URL:     "https://sub.example.com/a",
				Include: "US",
				Rename:  []config.RenameRule{{Match: "a", Replace: "b"}},
			},
		},
		GitHub: config.GitHubConfig{MirrorURL: "https://gh-proxy.com"},
		Hy2:    config.Hy2Config{Up: 50, Down: 300},
		DNS: config.ClientDNSConfig{
			Enabled:  boolPtr(true),
			DNSPort:  5353,
			WebPort:  3000,
			Username: "root",
			Password: "secret",
		},
		Gateway: config.GatewayConfig{Mode: "side", MainRouterIP: "192.168.1.1"},
		Tailscale: config.TailscaleConfig{
			AuthKey: "ts-test-key",
			Subnets: "192.168.1.0/24",
			P2PAssist: config.TailscaleP2PAssistConfig{
				Enabled:       true,
				PayloadFilter: boolPtr(true),
				Peers: []config.TailscaleP2PPeerConfig{
					{
						ID:                "peer-1",
						Name:              "macbook",
						AllowedLANTargets: []string{"192.168.1.10/32"},
					},
				},
			},
		},
		Server: config.ServerConfig{
			NodeDomain: "node.example.com",
			WarpRouting: config.WarpRoutingConfig{
				Mode:          config.WarpModeSplit,
				Presets:       map[string]bool{"openai": true},
				WarpDomains:   []string{"openai.com"},
				WarpCIDRs:     []string{"198.51.100.0/24"},
				DirectDomains: []string{"example.com"},
				DirectCIDRs:   []string{"203.0.113.0/24"},
			},
		},
		Watchdog: config.WatchdogConfig{
			Interval:             180,
			PreserveManualConfig: boolPtr(true),
			Failover: config.WatchdogFailoverConfig{
				Enabled:   boolPtr(true),
				Groups:    []string{"Proxy", "AI"},
				ProbeURLs: []string{"https://www.gstatic.com/generate_204"},
			},
		},
		Firewall: config.FirewallConfig{
			Mode:            "standard",
			Whitelist:       []string{"192.168.1.0/24"},
			ExtraForeverBan: []string{"198.51.100.99"},
			ProtectedPorts:  []int{22, 443},
		},
		Audit: config.AuditConfig{
			Whitelist: []string{"example.com"},
			PCDNBlock: boolPtr(false),
			Throttles: []config.AuditThrottleRule{{Target: "192.168.1.50", RateKBps: 512}},
		},
		CustomRules: config.CustomRulesConfig{
			Block: []config.BlockRule{{Target: "bad.example.com", Reason: "test"}},
			Outbounds: []config.OutboundRule{
				{
					Tag:                       "Custom",
					Outbounds:                 []string{"US-1"},
					InterruptExistConnections: boolPtr(false),
				},
			},
			Route: []map[string]any{{"domain": []string{"a.example.com"}, "outbound": "direct"}},
			DNS:   []map[string]any{{"server": "local", "domain": []any{"b.example.com"}}},
		},
		TrafficRouting: config.TrafficRoutingConfig{
			Presets: map[string]config.TrafficRuleOverride{
				"ai": {Enabled: boolPtr(true), Outbound: "AI"},
			},
		},
	}
	orig.SetSourcePath("/etc/singctl/singctl.yaml")

	cloned := orig.Clone()
	if cloned == nil || cloned == orig {
		t.Fatalf("expected non-nil distinct Config clone, got %v", cloned)
	}
	if cloned.SourcePath() != orig.SourcePath() {
		t.Fatalf("expected sourcePath preserved, got %q", cloned.SourcePath())
	}

	// Mutate every slice, map, and pointer in cloned and verify orig stays intact.
	cloned.Subs[0].Name = "mutated"
	cloned.Subs[0].Rename[0].Replace = "z"
	*cloned.DNS.Enabled = false
	*cloned.Tailscale.P2PAssist.PayloadFilter = false
	cloned.Tailscale.P2PAssist.Peers[0].AllowedLANTargets[0] = "10.0.0.1/32"
	cloned.Server.WarpRouting.Presets["openai"] = false
	cloned.Server.WarpRouting.WarpDomains[0] = "mutated.example.com"
	cloned.Server.WarpRouting.WarpCIDRs[0] = "192.0.2.0/24"
	cloned.Server.WarpRouting.DirectDomains[0] = "mutated2.example.com"
	cloned.Server.WarpRouting.DirectCIDRs[0] = "192.0.2.1/32"
	*cloned.Watchdog.PreserveManualConfig = false
	*cloned.Watchdog.Failover.Enabled = false
	cloned.Watchdog.Failover.Groups[0] = "Direct"
	cloned.Watchdog.Failover.ProbeURLs[0] = "https://example.com"
	cloned.Firewall.Whitelist[0] = "10.0.0.0/8"
	cloned.Firewall.ExtraForeverBan[0] = "203.0.113.5"
	cloned.Firewall.ProtectedPorts[0] = 8080
	cloned.Audit.Whitelist[0] = "changed.example.com"
	*cloned.Audit.PCDNBlock = true
	cloned.Audit.Throttles[0].RateKBps = 9999
	cloned.CustomRules.Block[0].Target = "changed.example.com"
	cloned.CustomRules.Outbounds[0].Outbounds[0] = "JP-1"
	*cloned.CustomRules.Outbounds[0].InterruptExistConnections = true
	cloned.CustomRules.Route[0]["outbound"] = "block"
	cloned.CustomRules.Route[0]["domain"].([]string)[0] = "mutated.example.com"
	cloned.CustomRules.DNS[0]["domain"].([]any)[0] = "mutated-dns.example.com"
	*cloned.TrafficRouting.Presets["ai"].Enabled = false

	if orig.Subs[0].Name != "sub-a" || orig.Subs[0].Rename[0].Replace != "b" {
		t.Fatal("orig.Subs mutated")
	}
	if !*orig.DNS.Enabled {
		t.Fatal("orig.DNS.Enabled mutated")
	}
	if !*orig.Tailscale.P2PAssist.PayloadFilter || orig.Tailscale.P2PAssist.Peers[0].AllowedLANTargets[0] != "192.168.1.10/32" {
		t.Fatal("orig.Tailscale.P2PAssist mutated")
	}
	if !orig.Server.WarpRouting.Presets["openai"] || orig.Server.WarpRouting.WarpDomains[0] != "openai.com" || orig.Server.WarpRouting.DirectCIDRs[0] != "203.0.113.0/24" {
		t.Fatal("orig.Server.WarpRouting mutated")
	}
	if !*orig.Watchdog.PreserveManualConfig || !*orig.Watchdog.Failover.Enabled || orig.Watchdog.Failover.Groups[0] != "Proxy" {
		t.Fatal("orig.Watchdog mutated")
	}
	if orig.Firewall.Whitelist[0] != "192.168.1.0/24" || orig.Firewall.ProtectedPorts[0] != 22 {
		t.Fatal("orig.Firewall mutated")
	}
	if orig.Audit.Whitelist[0] != "example.com" || *orig.Audit.PCDNBlock || orig.Audit.Throttles[0].RateKBps != 512 {
		t.Fatal("orig.Audit mutated")
	}
	if orig.CustomRules.Block[0].Target != "bad.example.com" ||
		orig.CustomRules.Outbounds[0].Outbounds[0] != "US-1" ||
		*orig.CustomRules.Outbounds[0].InterruptExistConnections ||
		orig.CustomRules.Route[0]["outbound"] != "direct" ||
		orig.CustomRules.Route[0]["domain"].([]string)[0] != "a.example.com" ||
		orig.CustomRules.DNS[0]["domain"].([]any)[0] != "b.example.com" {
		t.Fatal("orig.CustomRules mutated")
	}
	if !*orig.TrafficRouting.Presets["ai"].Enabled {
		t.Fatal("orig.TrafficRouting mutated")
	}
	if (*config.Config)(nil).Clone() != nil {
		t.Fatal("nil Clone must return nil")
	}
}

func TestStore_ReloadFingerprintAndMalformedFallback(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "singctl.yaml")
	writeYAML := func(up int, extra string) {
		body := "hy2:\n  up: " + string(rune('0'+up/10)) + string(rune('0'+up%10)) + "\n  down: 200\n" + extra
		if err := os.WriteFile(cfgPath, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeYAML(21, "")

	s := config.NewStore(cfgPath)
	if s.Path() != cfgPath {
		t.Fatalf("Path() = %q, want %q", s.Path(), cfgPath)
	}
	if got := s.Revision(); got != 1 {
		t.Fatalf("initial Revision() = %d, want 1", got)
	}
	first := s.Get()
	if first.Hy2.Up != 21 {
		t.Fatalf("initial Hy2.Up = %d, want 21", first.Hy2.Up)
	}

	// Unchanged file must skip YAML re-parse and keep exact pointer/revision.
	changed, same := s.ReloadIfChanged(false)
	if changed {
		t.Fatal("expected ReloadIfChanged(false) = false for unchanged file")
	}
	if same != first || s.Revision() != 1 {
		t.Fatalf("expected same snapshot pointer and revision 1")
	}

	// Modify file content + touch timestamp to change stat fingerprint.
	writeYAML(45, "# updated\n")
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(cfgPath, future, future); err != nil {
		t.Fatal(err)
	}

	changed, updated := s.ReloadIfChanged(false)
	if !changed {
		t.Fatal("expected ReloadIfChanged(false) = true after disk change")
	}
	if updated.Hy2.Up != 45 || s.Revision() != 2 {
		t.Fatalf("expected Hy2.Up=45 rev=2, got up=%d rev=%d", updated.Hy2.Up, s.Revision())
	}

	// Overwrite with malformed YAML: ReloadIfChanged must retain last known-good snapshot.
	if err := os.WriteFile(cfgPath, []byte("subs: [unclosed\n"), 0600); err != nil {
		t.Fatal(err)
	}
	future2 := future.Add(2 * time.Second)
	_ = os.Chtimes(cfgPath, future2, future2)

	changed, fallback := s.ReloadIfChanged(true)
	if changed {
		t.Fatal("expected ReloadIfChanged(true) = false on malformed YAML")
	}
	if fallback.Hy2.Up != 45 || s.Get().Hy2.Up != 45 || s.Revision() != 2 {
		t.Fatalf("expected last known-good snapshot (up=45 rev=2) preserved, got up=%d rev=%d", s.Get().Hy2.Up, s.Revision())
	}
	if _, err := s.LoadLatest(); err == nil {
		t.Fatal("expected LoadLatest() to surface malformed YAML parse error")
	}
}

func TestStore_UpdateAtomicAndRollbackOnError(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "singctl.yaml")
	if err := os.WriteFile(cfgPath, []byte("hy2:\n  up: 21\n  down: 200\n"), 0600); err != nil {
		t.Fatal(err)
	}

	s := config.NewStore(cfgPath)
	revBefore := s.Revision()

	if err := s.Update(func(c *config.Config) error {
		c.Hy2.Up = 88
		return nil
	}); err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	fi, err := os.Stat(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0600 {
		t.Fatalf("expected 0600 permission after Update, got %04o", perm)
	}
	diskCfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if diskCfg.Hy2.Up != 88 || s.Get().Hy2.Up != 88 || s.Revision() != revBefore+1 {
		t.Fatalf("unexpected Update result: disk=%d mem=%d rev=%d", diskCfg.Hy2.Up, s.Get().Hy2.Up, s.Revision())
	}

	sentinel := errors.New("validation failed")
	err = s.Update(func(c *config.Config) error {
		c.Hy2.Up = 999
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected sentinel error, got %v", err)
	}
	diskAfter, _ := config.Load(cfgPath)
	if diskAfter.Hy2.Up != 88 || s.Get().Hy2.Up != 88 || s.Revision() != revBefore+1 {
		t.Fatalf("expected no disk or memory mutation on mutator error")
	}
}

func TestStore_OptionsSetCloneAndInvalidate(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "singctl.yaml")
	var loadCalls atomic.Int32
	var saveCalls atomic.Int32

	s := config.NewStore(
		cfgPath,
		config.WithInitialConfig(&config.Config{Hy2: config.Hy2Config{Up: 33, Down: 300}}),
		config.WithLoader(func(path string) (*config.Config, error) {
			loadCalls.Add(1)
			return &config.Config{Hy2: config.Hy2Config{Up: 77, Down: 700}}, nil
		}),
		config.WithSaver(func(path string, cfg *config.Config) error {
			saveCalls.Add(1)
			return os.WriteFile(path, []byte("hy2:\n  up: 77\n  down: 700\n"), 0600)
		}),
	)

	if s.Revision() != 1 || s.Get().Hy2.Up != 33 {
		t.Fatalf("unexpected initial store state: rev=%d up=%d", s.Revision(), s.Get().Hy2.Up)
	}

	clone := s.GetClone()
	clone.Hy2.Up = 111
	if s.Get().Hy2.Up != 33 {
		t.Fatal("mutating GetClone() affected Store snapshot")
	}

	s.Set(&config.Config{Hy2: config.Hy2Config{Up: 55, Down: 500}})
	if s.Get().Hy2.Up != 55 || s.Revision() != 2 {
		t.Fatalf("unexpected state after Set: up=%d rev=%d", s.Get().Hy2.Up, s.Revision())
	}

	if err := s.Update(func(c *config.Config) error { c.Hy2.Up = 77; return nil }); err != nil {
		t.Fatalf("custom saver Update failed: %v", err)
	}
	if saveCalls.Load() != 1 {
		t.Fatalf("expected custom saver called once, got %d", saveCalls.Load())
	}

	// Touch file and invalidate fingerprint so LoadLatest hits custom loader.
	s.Invalidate()
	loaded, err := s.LoadLatest()
	if err != nil {
		t.Fatalf("LoadLatest after Invalidate failed: %v", err)
	}
	if loaded.Hy2.Up != 77 || loadCalls.Load() != 1 {
		t.Fatalf("expected custom loader hit once returning up=77, got up=%d calls=%d", loaded.Hy2.Up, loadCalls.Load())
	}
}

func TestStore_HighConcurrencyRace(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "singctl.yaml")
	if err := os.WriteFile(cfgPath, []byte("hy2:\n  up: 20\n  down: 200\n"), 0600); err != nil {
		t.Fatal(err)
	}

	s := config.NewStore(cfgPath)

	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 200 {
				cfg := s.Get()
				if cfg == nil {
					t.Error("Get() returned nil")
					return
				}
				_ = cfg.Hy2.Up
				_ = s.GetClone().Hy2.Down
				_ = s.Revision()
				_, _ = s.ReloadIfChanged(false)
				_, _ = s.LoadLatest()
			}
		}()
	}

	for w := range 4 {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := range 50 {
				if err := s.Update(func(c *config.Config) error {
					c.Hy2.Up = 30 + id*10 + i%5
					return nil
				}); err != nil {
					t.Errorf("concurrent Update failed: %v", err)
					return
				}
				if i%10 == 0 {
					c := s.GetClone()
					c.Hy2.Down = 250 + id
					s.Set(c)
				}
			}
		}(w)
	}

	wg.Wait()
	if s.Revision() == 0 || s.Get() == nil {
		t.Fatal("expected valid final store state after concurrent torture")
	}
}
