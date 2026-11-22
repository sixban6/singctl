// 文件职责：验证 AdGuard Home 基底 YAML 生成、AST 无损同步、私网 PTR 防环、Control API 与本地 DNS 探活边界。
package adguard_test

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
	"singctl/internal/adguard"
	"singctl/internal/config"
)

func TestValidateFilterURL_CaseInsensitiveSchemeAndMissingHostname(t *testing.T) {
	if _, err := adguard.ValidateFilterURL("HTTPS://example.com/filter.txt"); err != nil {
		t.Fatalf("expected uppercase HTTPS:// filter URL to be accepted, got: %v", err)
	}
	if _, err := adguard.ValidateFilterURL("http://:8080/filter.txt"); err == nil {
		t.Fatalf("expected URL with empty hostname 'http://:8080/filter.txt' to be rejected")
	}
	if _, err := adguard.ValidateFilterURL("ftp://example.com/filter.txt"); err == nil {
		t.Fatalf("expected ftp:// URL to be rejected")
	}
}

func TestBuildInitialConfigYAML_TableDrivenSchemaAndBoundaries(t *testing.T) {
	hash, err := config.HashPassword("TestPass123456")
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name         string
		params       adguard.ConfigParams
		wantErr      bool
		wantInterval string
		wantFileLog  bool
		wantPort     int
		wantDNSPort  int
		wantUser     string
		wantRules    []string
	}{
		{
			name:    "reject_empty_password",
			params:  adguard.ConfigParams{},
			wantErr: true,
		},
		{
			name:    "reject_plaintext_password",
			params:  adguard.ConfigParams{PasswordHash: "not-bcrypt"},
			wantErr: true,
		},
		{
			name: "openwrt_defaults_and_sub_whitelist_dedup",
			params: adguard.ConfigParams{
				LANIP:        "192.168.1.1",
				WebPort:      -1,
				DNSPort:      70000,
				Username:     "   ",
				PasswordHash: hash,
				IsOpenWrt:    true,
				SubURLs: []string{
					"https://sub1.example.com/api?token=abc",
					"https://SUB1.example.com/dup",
					"https://198.51.100.10/ip-only",
					"http://localhost:3001/local",
					"   ",
					"://broken-url",
				},
			},
			wantInterval: "24h",
			wantFileLog:  false,
			wantPort:     3000,
			wantDNSPort:  5353,
			wantUser:     "root",
			wantRules:    []string{"@@||sub1.example.com^$important"},
		},
		{
			name: "standard_linux_custom_ports_and_user",
			params: adguard.ConfigParams{
				LANIP:        "10.0.0.2",
				WebPort:      3080,
				DNSPort:      5354,
				Username:     "admin_user",
				PasswordHash: hash,
				IsOpenWrt:    false,
			},
			wantInterval: "72h",
			wantFileLog:  true,
			wantPort:     3080,
			wantDNSPort:  5354,
			wantUser:     "admin_user",
			wantRules:    nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := adguard.BuildInitialConfigYAML(tc.params)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			var parsed struct {
				SchemaVersion int `yaml:"schema_version"`
				HTTP          struct {
					Address string `yaml:"address"`
				} `yaml:"http"`
				Users []struct {
					Name     string `yaml:"name"`
					Password string `yaml:"password"`
				} `yaml:"users"`
				DNS struct {
					BindHosts          []string `yaml:"bind_hosts"`
					Port               int      `yaml:"port"`
					Ratelimit          int      `yaml:"ratelimit"`
					UsePrivatePTR      bool     `yaml:"use_private_ptr_resolvers"`
					UseHTTP3Upstreams  bool     `yaml:"use_http3_upstreams"`
					UpstreamMode       string   `yaml:"upstream_mode"`
					CacheOptimistic    bool     `yaml:"cache_optimistic"`
					EDNSClientSubnet   struct {
						Enabled bool `yaml:"enabled"`
					} `yaml:"edns_client_subnet"`
				} `yaml:"dns"`
				QueryLog struct {
					Interval       string   `yaml:"interval"`
					FileEnabled    bool     `yaml:"file_enabled"`
					IgnoredEnabled bool     `yaml:"ignored_enabled"`
					Ignored        []string `yaml:"ignored"`
				} `yaml:"querylog"`
				Statistics struct {
					IgnoredEnabled bool     `yaml:"ignored_enabled"`
					Ignored        []string `yaml:"ignored"`
				} `yaml:"statistics"`
				UserRules []string `yaml:"user_rules"`
			}
			if err := yaml.Unmarshal(out, &parsed); err != nil {
				t.Fatalf("unmarshal generated YAML failed: %v\n%s", err, string(out))
			}
			if parsed.SchemaVersion != 29 {
				t.Fatalf("schema_version = %d, want 29", parsed.SchemaVersion)
			}
			wantAddr := net.JoinHostPort(tc.params.LANIP, strconv.Itoa(tc.wantPort))
			if parsed.HTTP.Address != wantAddr {
				t.Fatalf("http.address = %q, want %q", parsed.HTTP.Address, wantAddr)
			}
			if len(parsed.Users) != 1 || parsed.Users[0].Name != tc.wantUser || parsed.Users[0].Password != hash {
				t.Fatalf("unexpected users: %+v", parsed.Users)
			}
			if !slices.Equal(parsed.DNS.BindHosts, []string{"127.0.0.1"}) || parsed.DNS.Port != tc.wantDNSPort {
				t.Fatalf("unexpected dns bind/port: %+v", parsed.DNS)
			}
			if parsed.DNS.Ratelimit != 0 || parsed.DNS.UsePrivatePTR || parsed.DNS.UseHTTP3Upstreams || !parsed.DNS.CacheOptimistic || !parsed.DNS.EDNSClientSubnet.Enabled {
				t.Fatalf("unexpected dns safety flags: %+v", parsed.DNS)
			}
			if parsed.QueryLog.Interval != tc.wantInterval || parsed.QueryLog.FileEnabled != tc.wantFileLog {
				t.Fatalf("unexpected querylog: %+v", parsed.QueryLog)
			}
			if !parsed.QueryLog.IgnoredEnabled || !slices.Contains(parsed.QueryLog.Ignored, "localhost") {
				t.Fatalf("expected localhost ignored in querylog: %+v", parsed.QueryLog)
			}
			if !parsed.Statistics.IgnoredEnabled || !slices.Contains(parsed.Statistics.Ignored, "localhost") {
				t.Fatalf("expected localhost ignored in statistics: %+v", parsed.Statistics)
			}
			if !slices.Equal(parsed.UserRules, tc.wantRules) {
				t.Fatalf("user_rules = %v, want %v", parsed.UserRules, tc.wantRules)
			}
		})
	}

	// Concurrent BuildInitialConfigYAML race check (ensures embedded template AST is never mutated across goroutines).
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			raw, bErr := adguard.BuildInitialConfigYAML(adguard.ConfigParams{
				LANIP:        "192.168.1.1",
				WebPort:      3000 + idx,
				DNSPort:      5353,
				Username:     "root",
				PasswordHash: hash,
				IsOpenWrt:    idx%2 == 0,
			})
			if bErr != nil || !strings.Contains(string(raw), strconv.Itoa(3000+idx)) {
				t.Errorf("concurrent BuildInitialConfigYAML failed: err=%v", bErr)
			}
		}(i)
	}
	wg.Wait()
}

func TestConfigGen_Blocklist_And_ControlAPI_EndToEnd(t *testing.T) {
	dir := t.TempDir()
	fakeBin := filepath.Join(dir, "AdGuardHome")
	if err := os.WriteFile(fakeBin, []byte("#!/bin/sh\necho 'AdGuard Home, version v0.107.55'\n"), 0755); err != nil {
		t.Fatal(err)
	}
	aghYAML := filepath.Join(dir, "AdGuardHome.yaml")
	singctlYAML := filepath.Join(dir, "singctl.yaml")

	hash, err := config.HashPassword("TestPass123456")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := adguard.BuildInitialConfigYAML(adguard.ConfigParams{PasswordHash: "plaintext"}); err == nil {
		t.Fatal("expected BuildInitialConfigYAML to reject non-bcrypt password")
	}
	initialBytes, err := adguard.BuildInitialConfigYAML(adguard.ConfigParams{
		LANIP:             "0.0.0.0",
		WebPort:           3000,
		DNSPort:           5353,
		Username:          "root",
		PasswordHash:      hash,
		IsOpenWrt:         true,
		DisablePrivatePTR: true,
		SubURLs:           []string{"https://sub.example.com/api/v1/subscribe?token=test"},
	})
	if err != nil {
		t.Fatalf("BuildInitialConfigYAML failed: %v", err)
	}
	if strings.Contains(string(initialBytes), "0.0.0.0:3000") {
		t.Fatalf("BuildInitialConfigYAML bound Web UI to 0.0.0.0:\n%s", string(initialBytes))
	}
	if !strings.Contains(string(initialBytes), "@@||sub.example.com^$important") {
		t.Fatalf("expected subscription domain auto-whitelisted in initial YAML")
	}
	if err := adguard.WriteConfigAtomically(aghYAML, initialBytes); err != nil {
		t.Fatalf("WriteConfigAtomically failed: %v", err)
	}

	cfg := &config.Config{
		Subs: []config.Subscription{{Name: "main", URL: "https://sub.example.com/s"}},
		DNS: config.ClientDNSConfig{
			Username: "root",
			Password: "TestPass123456",
		},
	}
	mgr := adguard.NewManager(cfg, singctlYAML)
	mgr.SetPathsForTest(fakeBin, aghYAML)

	ctx := t.Context()
	applied, mode, err := mgr.SyncBlockRules(ctx, []config.BlockRule{
		{Target: "tracker.example.com"},
		{Target: "198.51.100.7/32", SourceIP: "192.168.1.50"},
		{Target: "ruleset:ads"},
	})
	if err != nil || !applied || mode != "yaml_file" {
		t.Fatalf("offline SyncBlockRules = (%v, %q, %v), want (true, yaml_file, nil)", applied, mode, err)
	}
	if err := mgr.SetDomainWhitelist(ctx, "allow.example.com", true); err != nil {
		t.Fatalf("offline SetDomainWhitelist failed: %v", err)
	}

	var (
		mu              sync.Mutex
		userRules       = []string{"@@||sub.example.com^$important", "@@||allow.example.com^$important"}
		filters         = []map[string]any{{"id": 1, "enabled": true, "url": "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt", "name": "Base", "rules_count": 50000}}
		rewrites        = []adguard.RewriteEntry{{Domain: "router.lan", Answer: "192.168.1.1"}}
		protFallback404 = true
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || u != "root" || p != "TestPass123456" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		mu.Lock()
		defer mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/control/status":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"version":            "v0.107.55",
				"running":            true,
				"protection_enabled": true,
			})
		case "/control/stats":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"num_dns_queries":       1000,
				"num_blocked_filtering": 250,
				"avg_processing_time":   0.012,
				"top_blocked_domains":   []map[string]int64{{"ads.example.com": 80}},
				"top_queried_domains":   []map[string]int64{{"www.example.com": 300}},
			})
		case "/control/filtering/status":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"enabled":    true,
				"filters":    filters,
				"user_rules": userRules,
			})
		case "/control/filtering/set_rules":
			var body struct {
				Rules []string `json:"rules"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			userRules = body.Rules
			w.WriteHeader(http.StatusOK)
		case "/control/filtering/add_url":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			filters = append(filters, map[string]any{
				"id":          2,
				"enabled":     true,
				"url":         body["url"],
				"name":        body["name"],
				"rules_count": 1200,
			})
			w.WriteHeader(http.StatusOK)
		case "/control/filtering/set_url", "/control/filtering/remove_url", "/control/filtering/refresh", "/control/cache_clear", "/control/dns_config":
			w.WriteHeader(http.StatusOK)
		case "/control/protection":
			if protFallback404 {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusOK)
		case "/control/rewrite/list":
			_ = json.NewEncoder(w).Encode(rewrites)
		case "/control/rewrite/add":
			var entry adguard.RewriteEntry
			_ = json.NewDecoder(r.Body).Decode(&entry)
			rewrites = append(rewrites, entry)
			w.WriteHeader(http.StatusOK)
		case "/control/rewrite/delete":
			w.WriteHeader(http.StatusOK)
		case "/control/dns_info":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"upstream_dns":  []string{"https://223.5.5.5/dns-query"},
				"upstream_mode": "parallel",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	host, portStr, _ := net.SplitHostPort(srv.Listener.Addr().String())
	webPort, _ := strconv.Atoi(portStr)
	cfg.DNS.WebPort = webPort

	disablePTR := false
	changed, err := adguard.SyncExistingConfig(aghYAML, adguard.SyncOptions{
		LANIP:             host,
		WebPort:           webPort,
		DNSPort:           5353,
		DisablePrivatePTR: &disablePTR,
	})
	if err != nil || !changed {
		t.Fatalf("SyncExistingConfig = (%v, %v), want (true, nil)", changed, err)
	}

	applied, mode, err = mgr.SyncBlockRules(ctx, []config.BlockRule{{Target: "hotblock.example.com"}})
	if err != nil || !applied || mode != "hot_api" {
		t.Fatalf("hot SyncBlockRules = (%v, %q, %v), want (true, hot_api, nil)", applied, mode, err)
	}

	snap := mgr.Overview(ctx, true)
	if !snap.Installed || !snap.WebHealthy || snap.Stats.NumDNSQueries != 1000 || snap.Stats.BlockedPercent != 25.0 {
		t.Fatalf("unexpected Overview snapshot: %+v", snap)
	}

	if err := mgr.SetProtection(ctx, false, 15); err != nil {
		t.Fatalf("SetProtection fallback failed: %v", err)
	}
	mu.Lock()
	protFallback404 = false
	mu.Unlock()
	if err := mgr.SetProtection(ctx, true, 0); err != nil {
		t.Fatalf("SetProtection direct failed: %v", err)
	}

	if err := mgr.ClearCache(ctx); err != nil {
		t.Fatalf("ClearCache failed: %v", err)
	}
	if err := mgr.SetDomainWhitelist(ctx, "cdn.example.com", true); err != nil {
		t.Fatalf("hot SetDomainWhitelist add failed: %v", err)
	}
	if err := mgr.SetDomainWhitelist(ctx, "cdn.example.com", false); err != nil {
		t.Fatalf("hot SetDomainWhitelist remove failed: %v", err)
	}
	if err := mgr.SyncSubscriptionWhitelist(ctx, []string{"https://sub2.example.com/feed"}); err != nil {
		t.Fatalf("SyncSubscriptionWhitelist failed: %v", err)
	}
	if err := mgr.AddRewrite(ctx, "nas.lan", "192.168.1.20"); err != nil {
		t.Fatalf("AddRewrite failed: %v", err)
	}
	if err := mgr.AddRewrite(ctx, "bad domain!", "192.168.1.20"); err == nil {
		t.Fatal("expected AddRewrite to reject invalid domain")
	}
	if err := mgr.DeleteRewrite(ctx, "nas.lan", "192.168.1.20"); err != nil {
		t.Fatalf("DeleteRewrite failed: %v", err)
	}
	if err := mgr.SetFilterState(ctx, "https://anti-ad.net/easylist.txt", "", true); err != nil {
		t.Fatalf("SetFilterState add failed: %v", err)
	}
	if err := mgr.SetFilterState(ctx, "https://anti-ad.net/easylist.txt", "Anti-AD", false); err != nil {
		t.Fatalf("SetFilterState disable failed: %v", err)
	}
	if err := mgr.RefreshFilters(ctx); err != nil {
		t.Fatalf("RefreshFilters failed: %v", err)
	}
	if err := mgr.RemoveFilter(ctx, "https://anti-ad.net/easylist.txt"); err != nil {
		t.Fatalf("RemoveFilter failed: %v", err)
	}
}

func TestBuildInitialConfig_DisablesPrivatePTRAndSuppressesLocalhostNoise(t *testing.T) {
	hash, err := config.HashPassword("TestPass123456")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := adguard.BuildInitialConfigYAML(adguard.ConfigParams{
		LANIP:             "192.168.180.1",
		WebPort:           3000,
		DNSPort:           5353,
		Username:          "root",
		PasswordHash:      hash,
		IsOpenWrt:         true,
		DisablePrivatePTR: false,
	})
	if err != nil {
		t.Fatalf("BuildInitialConfigYAML failed: %v", err)
	}
	s := string(raw)
	if !strings.Contains(s, "use_private_ptr_resolvers: false") {
		t.Fatalf("expected use_private_ptr_resolvers: false even with DisablePrivatePTR=false, got:\n%s", s)
	}
	if strings.Count(s, "ignored_enabled: true") < 2 || strings.Count(s, "- localhost") < 2 {
		t.Fatalf("expected querylog and statistics ignored=[localhost] & ignored_enabled=true, got:\n%s", s)
	}
}

func TestNeedsHardeningSync_HealsLegacyPrivatePTRAndIgnored(t *testing.T) {
	dir := t.TempDir()
	aghYAML := filepath.Join(dir, "AdGuardHome.yaml")
	legacy := `http:
  address: 192.168.180.1:3000
dns:
  bind_hosts:
    - 127.0.0.1
  port: 5353
  use_private_ptr_resolvers: true
querylog:
  enabled: true
  ignored_enabled: false
  ignored:
    - custom.lan
statistics:
  enabled: true
  ignored_enabled: false
  ignored: []
schema_version: 29
`
	if err := os.WriteFile(aghYAML, []byte(legacy), 0600); err != nil {
		t.Fatal(err)
	}
	if !adguard.NeedsHardeningSync(aghYAML) {
		t.Fatal("expected NeedsHardeningSync=true on legacy use_private_ptr_resolvers=true config")
	}

	changed, err := adguard.SyncExistingConfig(aghYAML, adguard.SyncOptions{
		LANIP:   "192.168.180.1",
		WebPort: 3000,
		DNSPort: 5353,
	})
	if err != nil || !changed {
		t.Fatalf("SyncExistingConfig = (%v, %v), want (true, nil)", changed, err)
	}
	if adguard.NeedsHardeningSync(aghYAML) {
		t.Fatal("expected NeedsHardeningSync=false after SyncExistingConfig healed legacy YAML")
	}

	healedBytes, err := os.ReadFile(aghYAML)
	if err != nil {
		t.Fatal(err)
	}
	healed := string(healedBytes)
	if !strings.Contains(healed, "use_private_ptr_resolvers: false") {
		t.Fatalf("expected healed use_private_ptr_resolvers: false, got:\n%s", healed)
	}
	var parsedHealed struct {
		QueryLog struct {
			Ignored        []string `yaml:"ignored"`
			IgnoredEnabled bool     `yaml:"ignored_enabled"`
		} `yaml:"querylog"`
		Statistics struct {
			Ignored        []string `yaml:"ignored"`
			IgnoredEnabled bool     `yaml:"ignored_enabled"`
		} `yaml:"statistics"`
	}
	if err := yaml.Unmarshal(healedBytes, &parsedHealed); err != nil {
		t.Fatalf("unmarshal healed YAML: %v", err)
	}
	if !parsedHealed.QueryLog.IgnoredEnabled ||
		!slices.Contains(parsedHealed.QueryLog.Ignored, "custom.lan") ||
		!slices.Contains(parsedHealed.QueryLog.Ignored, "localhost") {
		t.Fatalf("expected querylog.ignored to preserve custom.lan and add localhost, got %+v", parsedHealed.QueryLog)
	}
	if !parsedHealed.Statistics.IgnoredEnabled ||
		!slices.Contains(parsedHealed.Statistics.Ignored, "localhost") {
		t.Fatalf("expected statistics.ignored to contain localhost with ignored_enabled=true, got %+v", parsedHealed.Statistics)
	}

	changedAgain, err := adguard.SyncExistingConfig(aghYAML, adguard.SyncOptions{
		LANIP:   "192.168.180.1",
		WebPort: 3000,
		DNSPort: 5353,
	})
	if err != nil || changedAgain {
		t.Fatalf("expected idempotent second SyncExistingConfig = (false, nil), got (%v, %v)", changedAgain, err)
	}
}

func TestProbeDNSWithRetry_ToleratesSingleTransientDrop(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	done := make(chan struct{})
	defer close(done)
	go func() {
		buf := make([]byte, 512)
		attempt := 0
		for {
			_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, addr, rErr := pc.ReadFrom(buf)
			if rErr != nil {
				select {
				case <-done:
					return
				default:
					continue
				}
			}
			attempt++
			if attempt == 1 || n < 12 {
				continue
			}
			resp := make([]byte, n)
			copy(resp, buf[:n])
			resp[2] |= 0x80
			_, _ = pc.WriteTo(resp, addr)
		}
	}()

	if err := adguard.ProbeDNSWithRetry(pc.LocalAddr().String(), 120*time.Millisecond, 2, 10*time.Millisecond); err != nil {
		t.Fatalf("expected ProbeDNSWithRetry to succeed on 2nd attempt after transient drop, got %v", err)
	}
}
