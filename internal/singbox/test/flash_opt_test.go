// 文件职责：验证 sing-box cache.db 迁入 /tmp 零闪存磨损、ujail 沙盒路径双兼容重写、旧闪存残留清理及孤立 .srs/.json 规则集自动 GC。
package singbox_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"singctl/internal/config"
	"singctl/internal/singbox"
	"singctl/internal/singbox/sboption"
	"singctl/internal/singbox/scripts"
)

func TestRelocateTmpCacheFile_PipelineAndSandboxCompatibility(t *testing.T) {
	const mib uint64 = 1024 * 1024

	if singbox.TmpCacheFilePath != "/tmp/sing-box-cache.db" {
		t.Fatalf("TmpCacheFilePath = %q, want /tmp/sing-box-cache.db", singbox.TmpCacheFilePath)
	}

	seedJSON := `{
		"log": {"level": "info"},
		"outbounds": [
			{"tag": "node-1", "type": "vless", "server": "198.51.100.1", "server_port": 443},
			{"tag": "Proxy", "type": "selector", "outbounds": ["node-1"]},
			{"tag": "#DC", "type": "direct"}
		],
		"dns": {
			"servers": [{"tag": "dns_local", "type": "udp", "server": "223.5.5.5"}],
			"rules": []
		},
		"route": {
			"default_mark": 1,
			"rules": [{"action": "sniff"}]
		},
		"experimental": {
			"clash_api": {"external_controller": "127.0.0.1:9090"},
			"cache_file": {"enabled": true, "path": "/etc/sing-box/cache.db", "store_dns": true}
		}
	}`

	parseCachePath := func(t *testing.T, raw string) string {
		t.Helper()
		doc, err := sboption.ParseDocument([]byte(raw))
		if err != nil {
			t.Fatalf("parse output: %v", err)
		}
		if doc.Experimental == nil || doc.Experimental.CacheFile == nil {
			return ""
		}
		return doc.Experimental.CacheFile.Path
	}

	t.Run("relocates_on_openwrt_low_memory_and_low_flash_preserving_single_tree", func(t *testing.T) {
		cases := []struct {
			name       string
			cfg        *config.Config
			ram        uint64
			isOpenWrt  bool
			isLowFlash bool
			platform   string
			wantPath   string
		}{
			{
				name:       "openwrt_big_ram_big_disk",
				cfg:        &config.Config{},
				ram:        2048 * mib,
				isOpenWrt:  true,
				isLowFlash: false,
				platform:   "linux",
				wantPath:   singbox.TmpCacheFilePath,
			},
			{
				name:       "non_openwrt_low_memory_512m",
				cfg:        &config.Config{},
				ram:        479 * mib,
				isOpenWrt:  false,
				isLowFlash: false,
				platform:   "linux",
				wantPath:   singbox.TmpCacheFilePath,
			},
			{
				name:       "non_openwrt_low_flash_128m",
				cfg:        &config.Config{},
				ram:        1024 * mib,
				isOpenWrt:  false,
				isLowFlash: true,
				platform:   "linux",
				wantPath:   singbox.TmpCacheFilePath,
			},
			{
				name:       "non_openwrt_high_ram_big_disk_keeps_etc_path",
				cfg:        &config.Config{},
				ram:        2048 * mib,
				isOpenWrt:  false,
				isLowFlash: false,
				platform:   "linux",
				wantPath:   "/etc/sing-box/cache.db",
			},
			{
				name:       "ios_adapter_never_gets_tmp_cache_path",
				cfg:        &config.Config{LowMemory: config.LowMemoryOn},
				ram:        256 * mib,
				isOpenWrt:  true,
				isLowFlash: true,
				platform:   singbox.PlatformIOS,
				wantPath:   "",
			},
			{
				name:       "darwin_never_rewrites_to_linux_tmp_cache_path",
				cfg:        &config.Config{LowMemory: config.LowMemoryOn},
				ram:        256 * mib,
				isOpenWrt:  true,
				isLowFlash: true,
				platform:   "darwin",
				wantPath:   "/etc/sing-box/cache.db",
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				g := singbox.NewOfflineConfigGenerator(tc.cfg)
				g.SetTotalRAMBytes(tc.ram)
				g.SetHostFlashProbes(
					func() bool { return tc.isOpenWrt },
					func() bool { return tc.isLowFlash },
				)
				doc := singbox.NewCompileDoc(seedJSON, tc.platform)
				if err := singbox.RunCompileStages(g, doc, singbox.DefaultCompileStages()); err != nil {
					t.Fatalf("RunCompileStages failed: %v", err)
				}
				if doc.UnmarshalCount() != 1 || doc.MarshalCount() != 0 {
					t.Fatalf("single-tree invariant broken: unmarshal=%d marshal=%d", doc.UnmarshalCount(), doc.MarshalCount())
				}
				parsed, err := doc.EnsureDoc()
				if err != nil {
					t.Fatal(err)
				}
				out, err := parsed.MarshalPretty()
				if err != nil {
					t.Fatal(err)
				}
				if got := parseCachePath(t, out); got != tc.wantPath {
					t.Fatalf("cache_file.path = %q, want %q\n%s", got, tc.wantPath, out)
				}
				if tc.platform == singbox.PlatformIOS {
					if err := singbox.CheckIOSCompatibility(out); err != nil {
						t.Fatalf("iOS compatibility check failed: %v", err)
					}
				}
			})
		}
	})

	t.Run("preserves_disabled_or_already_tmp_work_and_absent_cache_file", func(t *testing.T) {
		g := singbox.NewOfflineConfigGenerator(&config.Config{LowMemory: config.LowMemoryOn})
		g.SetHostFlashProbes(func() bool { return true }, func() bool { return true })

		// Already /tmp/sing-box-work/cache.db -> preserved
		workJSON := strings.ReplaceAll(seedJSON, "/etc/sing-box/cache.db", "/tmp/sing-box-work/cache.db")
		outWork, err := g.RunCompilePipeline(workJSON, "linux")
		if err != nil {
			t.Fatal(err)
		}
		if got := parseCachePath(t, outWork); got != "/tmp/sing-box-work/cache.db" {
			t.Fatalf("expected existing /tmp/sing-box-work/cache.db preserved, got %q", got)
		}

		// Empty path with enabled=true -> set to /tmp/sing-box-cache.db
		emptyPathJSON := strings.ReplaceAll(seedJSON, `"/etc/sing-box/cache.db"`, `""`)
		outEmpty, err := g.RunCompilePipeline(emptyPathJSON, "linux")
		if err != nil {
			t.Fatal(err)
		}
		if got := parseCachePath(t, outEmpty); got != singbox.TmpCacheFilePath {
			t.Fatalf("expected empty cache_file.path relocated to %s, got %q", singbox.TmpCacheFilePath, got)
		}

		// Disabled cache_file -> untouched
		disabledJSON := strings.ReplaceAll(seedJSON, `"enabled": true`, `"enabled": false`)
		outDisabled, err := g.RunCompilePipeline(disabledJSON, "linux")
		if err != nil {
			t.Fatal(err)
		}
		if got := parseCachePath(t, outDisabled); got != "/etc/sing-box/cache.db" {
			t.Fatalf("expected disabled cache_file untouched, got %q", got)
		}
	})

	t.Run("rewrite_sandbox_work_config_and_openwrt_scripts_support_both_paths", func(t *testing.T) {
		for _, orig := range []string{"/etc/sing-box/cache.db", "/tmp/sing-box-cache.db"} {
			in := `{"experimental":{"cache_file":{"enabled":true,"path":"` + orig + `"}}}`
			got := singbox.RewriteSandboxWorkConfig(in, "/etc/sing-box", "/tmp/sing-box-work")
			want := `"/tmp/sing-box-work/cache.db"`
			if !strings.Contains(got, want) {
				t.Fatalf("RewriteSandboxWorkConfig(%s) did not rewrite to %s, got:\n%s", orig, want, got)
			}
		}

		for _, backend := range []scripts.OpenWrtFirewallBackend{scripts.BackendNFTables, scripts.BackendIPTables} {
			script := scripts.GetOpenWrtStartScript(backend)
			if !strings.Contains(script, `"/tmp/sing-box-cache.db"`) || !strings.Contains(script, `"/etc/sing-box/cache.db"`) {
				t.Fatalf("OpenWrt start script (%s) must rewrite both /etc/sing-box/cache.db and /tmp/sing-box-cache.db", backend)
			}
			tmpScript := filepath.Join(t.TempDir(), "start.sh")
			_ = os.WriteFile(tmpScript, []byte(script), 0700)
			if out, err := exec.CommandContext(t.Context(), "/bin/sh", "-n", tmpScript).CombinedOutput(); err != nil {
				t.Fatalf("OpenWrt start script (%s) failed /bin/sh -n: %v\n%s", backend, err, string(out))
			}
		}
	})

	t.Run("cleanup_legacy_flash_cache_db_on_relocation_and_live_reload", func(t *testing.T) {
		dir := t.TempDir()
		cfgPath := filepath.Join(dir, "config.json")
		legacyCache := filepath.Join(dir, "cache.db")
		_ = os.WriteFile(legacyCache, []byte("old-flash-cache-bytes"), 0600)

		// Config still pointing to /etc/sing-box/cache.db -> must NOT delete cache.db
		etcJSON := `{"experimental":{"cache_file":{"enabled":true,"path":"/etc/sing-box/cache.db"}}}`
		if removed := singbox.CleanupLegacyFlashCacheDB(cfgPath, etcJSON); removed {
			t.Fatal("must NOT remove legacy cache.db when config does not use /tmp/ cache path")
		}
		if _, err := os.Stat(legacyCache); err != nil {
			t.Fatalf("expected legacy cache.db preserved, err=%v", err)
		}

		// Config migrated to /tmp/sing-box-cache.db -> deletes legacy cache.db
		tmpJSON := `{"experimental":{"cache_file":{"enabled":true,"path":"/tmp/sing-box-cache.db"}}}`
		if removed := singbox.CleanupLegacyFlashCacheDB(cfgPath, tmpJSON); !removed {
			t.Fatal("expected CleanupLegacyFlashCacheDB to remove legacy cache.db")
		}
		if _, err := os.Stat(legacyCache); !os.IsNotExist(err) {
			t.Fatalf("expected legacy cache.db removed, err=%v", err)
		}
		// Idempotent second call
		if removed := singbox.CleanupLegacyFlashCacheDB(cfgPath, tmpJSON); removed {
			t.Fatal("expected idempotent second call to return false")
		}

		// Live reload via ApplyLiveSingBoxConfig also cleans legacy cache.db
		origLookPath := singbox.LookPathFunc
		singbox.LookPathFunc = func(string) (string, error) { return "", os.ErrNotExist }
		t.Cleanup(func() { singbox.LookPathFunc = origLookPath })

		_ = os.WriteFile(cfgPath, []byte(etcJSON), 0600)
		_ = os.WriteFile(legacyCache, []byte("legacy-again"), 0600)
		if err := singbox.ApplyLiveSingBoxConfig(t.Context(), cfgPath, "", tmpJSON, "flashopt"); err != nil {
			t.Fatalf("ApplyLiveSingBoxConfig failed: %v", err)
		}
		if _, err := os.Stat(legacyCache); !os.IsNotExist(err) {
			t.Fatalf("expected ApplyLiveSingBoxConfig to clean legacy cache.db, err=%v", err)
		}
	})
}

func TestPruneOrphanRuleSetFiles_SafetyRedlinesAndLowMemoryGC(t *testing.T) {
	t.Run("removes_orphans_cleans_manifest_protects_active_and_non_ruleset_files", func(t *testing.T) {
		cacheDir := t.TempDir()
		ad1Bytes := append([]byte("SRS\x02"), []byte("ad1-data")...)
		ad2Bytes := append([]byte("SRS\x02"), make([]byte, 3500)...) // simulates ~3.5MB geosite-ad2.srs
		oldJSONBytes := []byte(`{"version":1,"rules":[]}`)
		noteBytes := []byte("keep me")

		_ = os.WriteFile(filepath.Join(cacheDir, "geosite-ad1.srs"), ad1Bytes, 0644)
		_ = os.WriteFile(filepath.Join(cacheDir, "geosite-ad2.srs"), ad2Bytes, 0644)
		_ = os.WriteFile(filepath.Join(cacheDir, "stale-source.json"), oldJSONBytes, 0644)
		_ = os.WriteFile(filepath.Join(cacheDir, "active-source.json"), oldJSONBytes, 0644)
		_ = os.WriteFile(filepath.Join(cacheDir, "README.txt"), noteBytes, 0644)
		_ = os.MkdirAll(filepath.Join(cacheDir, "subdir.srs"), 0755)

		manifest := map[string]map[string]any{
			"geosite-ad1":   {"url": "https://example.com/ad1.srs", "format": "binary"},
			"geosite-ad2":   {"url": "https://example.com/ad2.srs", "format": "binary"},
			"stale-source":  {"url": "https://example.com/stale.json", "format": "source"},
			"active-source": {"url": "https://example.com/active.json", "format": "source"},
		}
		mRaw, _ := json.MarshalIndent(manifest, "", "  ")
		_ = os.WriteFile(filepath.Join(cacheDir, "manifest.json"), mRaw, 0644)

		// Empty activeTags MUST NEVER wipe directory!
		for _, empty := range []map[string]struct{}{nil, {}, {"": {}}, {"   ": {}}} {
			r, f := singbox.PruneOrphanRuleSetFiles(cacheDir, empty)
			if r != 0 || f != 0 {
				t.Fatalf("empty activeTags %v must be a strict no-op, got (%d, %d)", empty, r, f)
			}
			if _, err := os.Stat(filepath.Join(cacheDir, "geosite-ad2.srs")); err != nil {
				t.Fatalf("geosite-ad2.srs was deleted on empty activeTags!")
			}
		}

		active := map[string]struct{}{
			"geosite-ad1":   {},
			"active-source": {},
		}
		removed, freed := singbox.PruneOrphanRuleSetFiles(cacheDir, active)
		wantFreed := int64(len(ad2Bytes) + len(oldJSONBytes))
		if removed != 2 || freed != wantFreed {
			t.Fatalf("PruneOrphanRuleSetFiles = (%d, %d), want (2, %d)", removed, freed, wantFreed)
		}

		// Orphans removed
		for _, gone := range []string{"geosite-ad2.srs", "stale-source.json"} {
			if _, err := os.Stat(filepath.Join(cacheDir, gone)); !os.IsNotExist(err) {
				t.Fatalf("expected orphan %s removed, err=%v", gone, err)
			}
		}
		// Active + manifest + non-ruleset + subdirs preserved
		for _, keep := range []string{"geosite-ad1.srs", "active-source.json", "manifest.json", "README.txt", "subdir.srs"} {
			if _, err := os.Stat(filepath.Join(cacheDir, keep)); err != nil {
				t.Fatalf("expected %s preserved, err=%v", keep, err)
			}
		}

		// Manifest pruned of orphan entries
		mAfterRaw, err := os.ReadFile(filepath.Join(cacheDir, "manifest.json"))
		if err != nil {
			t.Fatal(err)
		}
		var mAfter map[string]any
		if err := json.Unmarshal(mAfterRaw, &mAfter); err != nil {
			t.Fatal(err)
		}
		if _, hasAd2 := mAfter["geosite-ad2"]; hasAd2 {
			t.Fatalf("expected geosite-ad2 removed from manifest.json, got %v", mAfter)
		}
		if _, hasStale := mAfter["stale-source"]; hasStale {
			t.Fatalf("expected stale-source removed from manifest.json, got %v", mAfter)
		}
		if _, hasAd1 := mAfter["geosite-ad1"]; !hasAd1 {
			t.Fatalf("expected geosite-ad1 preserved in manifest.json, got %v", mAfter)
		}

		// Idempotent second call
		if r2, f2 := singbox.PruneOrphanRuleSetFiles(cacheDir, active); r2 != 0 || f2 != 0 {
			t.Fatalf("second PruneOrphanRuleSetFiles = (%d, %d), want (0, 0)", r2, f2)
		}
	})

	t.Run("low_memory_pipeline_strip_geosite_ad2_triggers_auto_gc_in_localize", func(t *testing.T) {
		const mib uint64 = 1024 * 1024
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write(append([]byte("SRS\x02"), []byte("payload-"+r.URL.Path)...))
		}))
		defer srv.Close()

		cacheDir := t.TempDir()
		// Pre-populate cached files including ~3.5MB-style geosite-ad2.srs from before low-memory mode
		_ = os.WriteFile(filepath.Join(cacheDir, "geosite-ad1.srs"), append([]byte("SRS\x02"), []byte("ad1")...), 0644)
		_ = os.WriteFile(filepath.Join(cacheDir, "geosite-ad2.srs"), append([]byte("SRS\x02"), make([]byte, 8192)...), 0644)
		_ = os.WriteFile(filepath.Join(cacheDir, "geosite-cn.srs"), append([]byte("SRS\x02"), []byte("cn")...), 0644)
		singbox.RecordRuleSetManifest(cacheDir, "geosite-ad1", srv.URL+"/ad1.srs", "binary")
		singbox.RecordRuleSetManifest(cacheDir, "geosite-ad2", srv.URL+"/ad2.srs", "binary")
		singbox.RecordRuleSetManifest(cacheDir, "geosite-cn", srv.URL+"/cn.srs", "binary")

		seedJSON := `{
			"outbounds": [
				{"tag": "node-1", "type": "vless", "server": "198.51.100.1", "server_port": 443},
				{"tag": "Proxy", "type": "selector", "outbounds": ["node-1"]},
				{"tag": "#DC", "type": "direct"}
			],
			"dns": {
				"servers": [{"tag": "dns_local", "type": "udp", "server": "223.5.5.5"}],
				"rules": [{"rule_set": ["geosite-ad1", "geosite-ad2"], "action": "reject"}]
			},
			"route": {
				"rules": [
					{"rule_set": ["geosite-ad1", "geosite-ad2"], "action": "reject"},
					{"rule_set": ["geosite-cn"], "outbound": "#DC"}
				],
				"rule_set": [
					{"tag": "geosite-ad1", "type": "remote", "format": "binary", "url": "` + srv.URL + `/ad1.srs"},
					{"tag": "geosite-ad2", "type": "remote", "format": "binary", "url": "` + srv.URL + `/ad2.srs"},
					{"tag": "geosite-cn", "type": "remote", "format": "binary", "url": "` + srv.URL + `/cn.srs"}
				]
			}
		}`

		// Low-memory compile strips geosite-ad2
		g := singbox.NewOfflineConfigGenerator(&config.Config{})
		g.SetTotalRAMBytes(479 * mib)
		compiled, err := g.RunCompilePipeline(seedJSON, "linux")
		if err != nil {
			t.Fatalf("RunCompilePipeline failed: %v", err)
		}
		if strings.Contains(compiled, "geosite-ad2") {
			t.Fatalf("expected geosite-ad2 stripped in low-memory mode")
		}

		// LocalizeRuleSets (OfflineFirst) automatically GCs orphan geosite-ad2.srs + manifest entry!
		localized, _, err := singbox.LocalizeRuleSets(compiled, singbox.LocalizeOptions{
			CacheDir:     cacheDir,
			Client:       &http.Client{Timeout: 5 * time.Second},
			OfflineFirst: true,
		})
		if err != nil {
			t.Fatalf("LocalizeRuleSets failed: %v", err)
		}
		if _, err := os.Stat(filepath.Join(cacheDir, "geosite-ad2.srs")); !os.IsNotExist(err) {
			t.Fatalf("expected orphan geosite-ad2.srs GC'd after LocalizeRuleSets, err=%v", err)
		}
		for _, keep := range []string{"geosite-ad1.srs", "geosite-cn.srs"} {
			if _, err := os.Stat(filepath.Join(cacheDir, keep)); err != nil {
				t.Fatalf("expected active %s preserved, err=%v", keep, err)
			}
		}

		// Also verify all-local config (len(tasks)==0) still GCs newly planted orphan .srs!
		_ = os.WriteFile(filepath.Join(cacheDir, "orphan-later.srs"), append([]byte("SRS\x02"), []byte("junk")...), 0644)
		if _, _, err := singbox.LocalizeRuleSets(localized, singbox.LocalizeOptions{
			CacheDir:     cacheDir,
			Client:       &http.Client{Timeout: 5 * time.Second},
			OfflineFirst: true,
		}); err != nil {
			t.Fatalf("second LocalizeRuleSets failed: %v", err)
		}
		if _, err := os.Stat(filepath.Join(cacheDir, "orphan-later.srs")); !os.IsNotExist(err) {
			t.Fatalf("expected orphan-later.srs GC'd even when all active rulesets are already local")
		}

		// Config with empty rule_set must NEVER wipe cacheDir!
		noRS := `{"route":{"rules":[],"rule_set":[]}}`
		if _, _, err := singbox.LocalizeRuleSets(noRS, singbox.LocalizeOptions{CacheDir: cacheDir}); err != nil {
			t.Fatalf("LocalizeRuleSets(empty rule_set) failed: %v", err)
		}
		if _, err := os.Stat(filepath.Join(cacheDir, "geosite-ad1.srs")); err != nil {
			t.Fatalf("empty rule_set config MUST NOT delete existing cached .srs files: %v", err)
		}
	})

	t.Run("concurrent_gc_and_pipeline_race_safe", func(t *testing.T) {
		var wg sync.WaitGroup
		for range 6 {
			wg.Go(func() {
				d := t.TempDir()
				_ = os.WriteFile(filepath.Join(d, "a.srs"), []byte("SRS\x02a"), 0644)
				_ = os.WriteFile(filepath.Join(d, "b.srs"), []byte("SRS\x02b"), 0644)
				r, _ := singbox.PruneOrphanRuleSetFiles(d, map[string]struct{}{"a": {}})
				if r != 1 {
					t.Errorf("expected 1 removed, got %d", r)
				}
			})
		}
		wg.Wait()
	})
}
