// 文件职责：验证 SmartDNS 第三方大体积去广告规则迁移至 /tmp 内存盘、历史闪存残留自动清理、重启 /tmp 清空零断网启动与后台补拉自愈。
package smartdns_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"singctl/internal/common/sysinfo"
	"singctl/internal/platform/servicemgr"
	"singctl/internal/smartdns"
)

func TestFilterCacheDirStrategy_OpenWrtLowFlashLowMemVsBigServer(t *testing.T) {
	const (
		mib uint64 = 1024 * 1024
		gib uint64 = 1024 * mib
	)

	if smartdns.DefaultFilterCacheDir != "/tmp/singctl-smartdns-filters" {
		t.Fatalf("DefaultFilterCacheDir = %q, want /tmp/singctl-smartdns-filters", smartdns.DefaultFilterCacheDir)
	}

	root := t.TempDir()
	rulesDir := filepath.Join(root, "rules.d")
	customCache := filepath.Join(root, "custom-tmp-filters")

	cases := []struct {
		name string
		opts smartdns.ManagerOptions
		want string
	}{
		{
			name: "explicit_filter_cache_dir_wins",
			opts: smartdns.ManagerOptions{
				RulesDir:       rulesDir,
				FilterCacheDir: customCache,
				IsOpenWrt:      func() bool { return false },
				IsLowFlashHost: func() bool { return false },
				ReadMemInfo:    func() (sysinfo.MemInfo, error) { return sysinfo.MemInfo{TotalBytes: 4 * gib, AvailableBytes: 3 * gib}, nil },
			},
			want: customCache,
		},
		{
			name: "openwrt_defaults_to_tmp_filter_cache",
			opts: smartdns.ManagerOptions{
				RulesDir:       rulesDir,
				IsOpenWrt:      func() bool { return true },
				IsLowFlashHost: func() bool { return false },
				ReadMemInfo:    func() (sysinfo.MemInfo, error) { return sysinfo.MemInfo{TotalBytes: 2 * gib, AvailableBytes: 1 * gib}, nil },
			},
			want: smartdns.DefaultFilterCacheDir,
		},
		{
			name: "low_flash_defaults_to_tmp_filter_cache",
			opts: smartdns.ManagerOptions{
				RulesDir:       rulesDir,
				IsOpenWrt:      func() bool { return false },
				IsLowFlashHost: func() bool { return true },
				ReadMemInfo:    func() (sysinfo.MemInfo, error) { return sysinfo.MemInfo{TotalBytes: 2 * gib, AvailableBytes: 1 * gib}, nil },
			},
			want: smartdns.DefaultFilterCacheDir,
		},
		{
			name: "low_memory_defaults_to_tmp_filter_cache",
			opts: smartdns.ManagerOptions{
				RulesDir:       rulesDir,
				IsOpenWrt:      func() bool { return false },
				IsLowFlashHost: func() bool { return false },
				ReadMemInfo:    func() (sysinfo.MemInfo, error) { return sysinfo.MemInfo{TotalBytes: 479 * mib, AvailableBytes: 205 * mib}, nil },
			},
			want: smartdns.DefaultFilterCacheDir,
		},
		{
			name: "config_is_low_memory_defaults_to_tmp_filter_cache",
			opts: smartdns.ManagerOptions{
				RulesDir:       rulesDir,
				IsOpenWrt:      func() bool { return false },
				IsLowFlashHost: func() bool { return false },
				ReadMemInfo:    func() (sysinfo.MemInfo, error) { return sysinfo.MemInfo{TotalBytes: 4 * gib, AvailableBytes: 3 * gib}, nil },
				Config:         smartdns.ConfigInput{IsLowMemory: true},
			},
			want: smartdns.DefaultFilterCacheDir,
		},
		{
			name: "big_disk_big_ram_non_openwrt_keeps_rules_dir",
			opts: smartdns.ManagerOptions{
				RulesDir:       rulesDir,
				IsOpenWrt:      func() bool { return false },
				IsLowFlashHost: func() bool { return false },
				ReadMemInfo:    func() (sysinfo.MemInfo, error) { return sysinfo.MemInfo{TotalBytes: 4 * gib, AvailableBytes: 3 * gib}, nil },
			},
			want: rulesDir,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mgr := smartdns.NewManager(tc.opts)
			if got := mgr.FilterCacheDir(); got != tc.want {
				t.Fatalf("FilterCacheDir() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestBuildConfigWithOptions_RequireExistingFilters_And_CleanupLegacyFlash(t *testing.T) {
	root := t.TempDir()
	rulesDir := filepath.Join(root, "etc", "smartdns-rules.d")
	filterDir := filepath.Join(root, "tmp", "filters")
	_ = os.MkdirAll(rulesDir, 0700)
	_ = os.MkdirAll(filterDir, 0700)

	// 1. Missing / empty / comment-only files must NOT emit conf-file when RequireExistingFilters=true
	_ = os.WriteFile(filepath.Join(filterDir, "adblock.conf"), nil, 0600)
	_ = os.WriteFile(filepath.Join(filterDir, "filter-empty.conf"), []byte("# comment only\n\n"), 0600)

	cfgMissing, err := smartdns.BuildConfigWithOptions(smartdns.ConfigInput{
		EnabledFilters: []string{"https://example.com/anti-ad.conf"},
	}, smartdns.BuildConfigOptions{
		RulesDir:               rulesDir,
		FilterCacheDir:         filterDir,
		AuditLogPath:           filepath.Join(root, "audit.log"),
		LogFilePath:            filepath.Join(root, "smartdns.log"),
		RequireExistingFilters: true,
	})
	if err != nil {
		t.Fatalf("BuildConfigWithOptions failed: %v", err)
	}
	if strings.Contains(cfgMissing, "adblock.conf") || strings.Contains(cfgMissing, "filter-empty.conf") {
		t.Fatalf("empty/comment-only filters must be omitted when RequireExistingFilters=true:\n%s", cfgMissing)
	}
	for _, baseRule := range []string{"whitelist.conf", "rewrites.conf", "audit_block.conf"} {
		if !strings.Contains(cfgMissing, "conf-file "+filepath.Join(rulesDir, baseRule)) {
			t.Fatalf("base user rule %s must stay in rulesDir:\n%s", baseRule, cfgMissing)
		}
	}

	// 2. Populated filter files in filterDir ARE emitted
	_ = os.WriteFile(filepath.Join(filterDir, "adblock.conf"), []byte("# rules\naddress /ad.example.com/#\n"), 0600)
	_ = os.WriteFile(filepath.Join(filterDir, "filter-extra.conf"), []byte("address /track.example.com/#\n"), 0600)

	cfgReady, err := smartdns.BuildConfigWithOptions(smartdns.ConfigInput{
		EnabledFilters: []string{"https://example.com/anti-ad.conf"},
	}, smartdns.BuildConfigOptions{
		RulesDir:               rulesDir,
		FilterCacheDir:         filterDir,
		AuditLogPath:           filepath.Join(root, "audit.log"),
		LogFilePath:            filepath.Join(root, "smartdns.log"),
		RequireExistingFilters: true,
	})
	if err != nil {
		t.Fatalf("BuildConfigWithOptions failed: %v", err)
	}
	if !strings.Contains(cfgReady, "conf-file "+filepath.Join(filterDir, "adblock.conf")) {
		t.Fatalf("expected conf-file for populated adblock.conf in filterDir:\n%s", cfgReady)
	}
	if !strings.Contains(cfgReady, "conf-file "+filepath.Join(filterDir, "filter-extra.conf")) {
		t.Fatalf("expected conf-file for populated filter-extra.conf in filterDir:\n%s", cfgReady)
	}

	// 3. Injection payload in FilterCacheDir rejected
	if _, err := smartdns.BuildConfigWithOptions(smartdns.ConfigInput{}, smartdns.BuildConfigOptions{
		RulesDir:       rulesDir,
		FilterCacheDir: "/tmp/evil\nbind 0.0.0.0:53",
	}); err == nil {
		t.Fatal("expected newline injection in FilterCacheDir rejected")
	}

	// 4. CleanupLegacyFlashFilters removes legacy adblock.conf + filter-*.conf while protecting user rules
	_ = os.WriteFile(filepath.Join(rulesDir, "whitelist.conf"), []byte("domain-rules /ok.example.com/ -address -\n"), 0600)
	_ = os.WriteFile(filepath.Join(rulesDir, "rewrites.conf"), []byte("address /nas.example.com/192.0.2.10\n"), 0600)
	_ = os.WriteFile(filepath.Join(rulesDir, "audit_block.conf"), []byte("address /bad.example.com/#\n"), 0600)
	legacyAdblock := strings.Repeat("address /ad.example.com/#\n", 100)
	legacyFilter := strings.Repeat("address /trk.example.com/#\n", 50)
	_ = os.WriteFile(filepath.Join(rulesDir, "adblock.conf"), []byte(legacyAdblock), 0600)
	_ = os.WriteFile(filepath.Join(rulesDir, "filter-anti-ad.conf"), []byte(legacyFilter), 0600)

	removed, freed := smartdns.CleanupLegacyFlashFilters(rulesDir)
	if removed != 2 || freed != int64(len(legacyAdblock)+len(legacyFilter)) {
		t.Fatalf("CleanupLegacyFlashFilters = (%d, %d), want (2, %d)", removed, freed, len(legacyAdblock)+len(legacyFilter))
	}
	// Idempotency
	if r2, f2 := smartdns.CleanupLegacyFlashFilters(rulesDir); r2 != 0 || f2 != 0 {
		t.Fatalf("second CleanupLegacyFlashFilters = (%d, %d), want (0, 0)", r2, f2)
	}
	for _, keep := range []string{"whitelist.conf", "rewrites.conf", "audit_block.conf"} {
		if _, err := os.Stat(filepath.Join(rulesDir, keep)); err != nil {
			t.Fatalf("user rule file %s must NEVER be deleted: %v", keep, err)
		}
	}
	for _, gone := range []string{"adblock.conf", "filter-anti-ad.conf"} {
		if _, err := os.Stat(filepath.Join(rulesDir, gone)); !os.IsNotExist(err) {
			t.Fatalf("legacy flash filter %s should have been deleted, err=%v", gone, err)
		}
	}
}

func TestManager_TmpFilterCache_RebootZeroDowntimeAndAsyncSelfHeal(t *testing.T) {
	const mib uint64 = 1024 * 1024

	var fetchHits atomic.Int32
	gate := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchHits.Add(1)
		if r.URL.Path == "/slow-filter.conf" {
			select {
			case <-gate:
			case <-r.Context().Done():
				return
			}
		}
		_, _ = w.Write([]byte("address /ad1.example.com/#\naddress /ad2.example.com/#\n"))
	}))
	defer srv.Close()

	root := t.TempDir()
	binPath := filepath.Join(root, "bin", "smartdns")
	cfgDir := filepath.Join(root, "etc")
	rulesDir := filepath.Join(cfgDir, "smartdns-rules.d")
	filterCacheDir := filepath.Join(root, "tmp-filters")
	_ = os.MkdirAll(filepath.Dir(binPath), 0755)
	_ = os.MkdirAll(rulesDir, 0700)
	_ = os.WriteFile(binPath, []byte("#!/bin/sh\necho 'smartdns Release48.5'\n"), 0755)

	// Plant legacy ~1.7MB-style flash files on /etc/singctl/smartdns-rules.d before migration
	_ = os.WriteFile(filepath.Join(rulesDir, "adblock.conf"), []byte("address /legacy.example.com/#\n"), 0600)
	_ = os.WriteFile(filepath.Join(rulesDir, "filter-legacy.conf"), []byte("address /legacy2.example.com/#\n"), 0600)

	mockSvc := servicemgr.NewMock()
	mgr := smartdns.NewManager(smartdns.ManagerOptions{
		BinaryPath:     binPath,
		ConfigDir:      cfgDir,
		RulesDir:       rulesDir,
		FilterCacheDir: filterCacheDir,
		AuditLogPath:   filepath.Join(root, "audit.log"),
		LogFilePath:    filepath.Join(root, "smartdns.log"),
		PIDFilePath:    filepath.Join(root, "smartdns.pid"),
		GOOS:           "linux",
		GOARCH:         "arm64",
		ServiceMgr:     mockSvc,
		HTTPClient:     srv.Client(),
		IsOpenWrt:      func() bool { return true },
		IsLowFlashHost: func() bool { return true },
		ReadMemInfo: func() (sysinfo.MemInfo, error) {
			return sysinfo.MemInfo{TotalBytes: 479 * mib, AvailableBytes: 205 * mib}, nil
		},
		ReadDiskSpace: func(string) (sysinfo.DiskSpace, error) {
			return sysinfo.DiskSpace{TotalBytes: 83 * mib, AvailBytes: 40 * mib}, nil
		},
		ProbeDNSFunc: func(string, time.Duration) error { return nil },
	})

	// 1. ApplyConfig stores adblock in filterCacheDir, cleans legacy flash filters, keeps user rules in rulesDir
	err := mgr.ApplyConfig(t.Context(), smartdns.ConfigInput{
		DNSPort:        5353,
		Whitelist:      []string{"keep.example.com"},
		Rewrites:       []smartdns.RewriteEntry{{Domain: "nas.example.com", Answer: "192.0.2.10"}},
		EnabledFilters: []string{srv.URL + "/fast-filter.conf"},
	})
	if err != nil {
		t.Fatalf("ApplyConfig failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(rulesDir, "adblock.conf")); !os.IsNotExist(err) {
		t.Fatalf("legacy flash adblock.conf must be cleaned when tmp filter cache enabled")
	}
	if _, err := os.Stat(filepath.Join(rulesDir, "filter-legacy.conf")); !os.IsNotExist(err) {
		t.Fatalf("legacy flash filter-legacy.conf must be cleaned when tmp filter cache enabled")
	}
	if raw, err := os.ReadFile(filepath.Join(filterCacheDir, "adblock.conf")); err != nil || !strings.Contains(string(raw), "address /ad1.example.com/#") {
		t.Fatalf("expected rules written to tmp filterCacheDir, err=%v raw=%q", err, string(raw))
	}
	confBytes, err := os.ReadFile(filepath.Join(cfgDir, "smartdns.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(confBytes), "conf-file "+filepath.Join(filterCacheDir, "adblock.conf")) {
		t.Fatalf("smartdns.conf should reference tmp filterCacheDir:\n%s", string(confBytes))
	}
	if strings.Contains(string(confBytes), filepath.Join(rulesDir, "adblock.conf")) {
		t.Fatalf("smartdns.conf must NOT reference flash rulesDir/adblock.conf:\n%s", string(confBytes))
	}

	preview, err := mgr.EffectiveConfigPreview()
	if err != nil || !strings.Contains(preview, "address /ad1.example.com/#") {
		t.Fatalf("EffectiveConfigPreview should show tmp filterCacheDir rules, err=%v\n%s", err, preview)
	}

	// 2. Simulate router reboot: /tmp filterCacheDir is WIPED while smartdns.conf stays on flash!
	// Configure slow filter URL so we prove Start() NEVER blocks waiting on network download.
	if err := os.RemoveAll(filterCacheDir); err != nil {
		t.Fatal(err)
	}
	mockSvc2 := servicemgr.NewMock()
	mgrReboot := smartdns.NewManager(smartdns.ManagerOptions{
		BinaryPath:     binPath,
		ConfigDir:      cfgDir,
		RulesDir:       rulesDir,
		FilterCacheDir: filterCacheDir,
		AuditLogPath:   filepath.Join(root, "audit.log"),
		LogFilePath:    filepath.Join(root, "smartdns.log"),
		PIDFilePath:    filepath.Join(root, "smartdns.pid"),
		GOOS:           "linux",
		GOARCH:         "arm64",
		ServiceMgr:     mockSvc2,
		HTTPClient:     srv.Client(),
		IsOpenWrt:      func() bool { return true },
		IsLowFlashHost: func() bool { return true },
		Config: smartdns.ConfigInput{
			DNSPort:        5353,
			Whitelist:      []string{"keep.example.com"},
			EnabledFilters: []string{srv.URL + "/slow-filter.conf"},
		},
		ProbeDNSFunc: func(string, time.Duration) error { return nil },
	})

	startDone := make(chan error, 1)
	go func() {
		startDone <- mgrReboot.Start()
	}()

	select {
	case err := <-startDone:
		if err != nil {
			t.Fatalf("Start after /tmp wipe failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		close(gate)
		t.Fatal("Start() blocked waiting for remote filter download instead of booting immediately")
	}

	// Immediately after Start(), smartdns.conf must NOT reference missing /tmp adblock.conf!
	bootConf, err := os.ReadFile(filepath.Join(cfgDir, "smartdns.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(bootConf), "adblock.conf") {
		t.Fatalf("smartdns.conf at boot must omit missing tmp adblock.conf so smartdns starts cleanly:\n%s", string(bootConf))
	}

	// Now unblock HTTP server and wait for async background self-heal + reload!
	close(gate)
	mgrReboot.WaitBackgroundSync()

	healedConf, err := os.ReadFile(filepath.Join(cfgDir, "smartdns.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(healedConf), "conf-file "+filepath.Join(filterCacheDir, "adblock.conf")) {
		t.Fatalf("expected smartdns.conf updated with tmp adblock.conf after async heal:\n%s", string(healedConf))
	}
	if _, err := os.Stat(filepath.Join(filterCacheDir, "adblock.conf")); err != nil {
		t.Fatalf("expected adblock.conf populated in tmp filterCacheDir after async heal: %v", err)
	}
	calls := mockSvc2.Calls()
	if !slices.Contains(calls, "start singctl-smartdns") || !slices.Contains(calls, "reload singctl-smartdns") {
		t.Fatalf("expected start followed by async reload, got calls=%v", calls)
	}

	// 3. Concurrent EnsureHealthy & Status race check
	var wg sync.WaitGroup
	for range 6 {
		wg.Go(func() {
			_ = mgrReboot.EnsureHealthy()
			_ = mgrReboot.Status()
		})
	}
	wg.Wait()
	mgrReboot.WaitBackgroundSync()
}

func TestOpenWrtInitScript_RebootTmpFilterGuardSyntax(t *testing.T) {
	procd := smartdns.BuildOpenWrtInitScript("/usr/bin/smartdns", "/etc/singctl/smartdns.conf", "/tmp/singctl-smartdns.pid")
	if !strings.Contains(procd, smartdns.DefaultFilterCacheDir) {
		t.Fatalf("procd init script should guard %s on cold reboot:\n%s", smartdns.DefaultFilterCacheDir, procd)
	}
	scriptPath := filepath.Join(t.TempDir(), "singctl-smartdns")
	if err := os.WriteFile(scriptPath, []byte(procd), 0700); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.CommandContext(t.Context(), "/bin/sh", "-n", scriptPath).CombinedOutput(); err != nil {
		t.Fatalf("procd script failed /bin/sh -n: %v\n%s", err, string(out))
	}
}
