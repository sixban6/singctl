// 文件职责：验证 AdGuard Home 安装期的超低内存防 OOM 死机护栏（MemTotal<=288MiB 或 MemAvailable<=256MiB 拦截与 ForceLowMemory 放行）。
package adguard_test

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"singctl/internal/adguard"
	"singctl/internal/common/sysinfo"
	"singctl/internal/config"
)

func TestInstall_LowMemoryGuardrailBoundaries(t *testing.T) {
	const (
		mib      uint64 = 1024 * 1024
		n60ProTo uint64 = 491040 * 1024 // ~479.5 MiB
		n60ProAv uint64 = 210260 * 1024 // ~205.3 MiB
	)

	t.Run("blocks_ultra_low_total_ram_via_readMemTotal_and_writes_nothing", func(t *testing.T) {
		for _, totalRAM := range []uint64{128 * mib, 224 * mib, 256 * mib, 288 * mib} {
			dir := t.TempDir()
			binPath := filepath.Join(dir, "AdGuardHome")
			aghYAML := filepath.Join(dir, "AdGuardHome.yaml")
			singctlYAML := filepath.Join(dir, "singctl.yaml")

			mgr := adguard.NewManager(&config.Config{}, singctlYAML)
			mgr.SetPathsForTest(binPath, aghYAML)
			mgr.SetReadMemTotalForTest(func() uint64 { return totalRAM })

			st, err := mgr.Install(adguard.InstallOptions{NonInteractive: true})
			if err == nil || st != nil {
				t.Fatalf("ram=%d: expected Install blocked by low-memory guard, got st=%+v err=%v", totalRAM, st, err)
			}
			msg := err.Error()
			for _, kw := range []string{"AdGuard Home", "OOM", "sing-box 纯 IP DoH + geosite-ad1"} {
				if !strings.Contains(msg, kw) {
					t.Fatalf("ram=%d: error message %q missing expected keyword %q", totalRAM, msg, kw)
				}
			}
			if _, statErr := os.Stat(aghYAML); !os.IsNotExist(statErr) {
				t.Fatalf("ram=%d: expected zero files written when blocked", totalRAM)
			}
		}
	})

	t.Run("blocks_low_available_ram_like_n60pro_via_readMemInfo", func(t *testing.T) {
		cases := []sysinfo.MemInfo{
			{TotalBytes: n60ProTo, AvailableBytes: n60ProAv},
			{TotalBytes: 512 * mib, AvailableBytes: 256 * mib},
		}
		for i, mem := range cases {
			dir := t.TempDir()
			mgr := adguard.NewManager(&config.Config{}, filepath.Join(dir, "singctl.yaml"))
			mgr.SetPathsForTest(filepath.Join(dir, "AdGuardHome"), filepath.Join(dir, "AdGuardHome.yaml"))
			mgr.SetReadMemInfoForTest(func() sysinfo.MemInfo { return mem })

			if _, err := mgr.Install(adguard.InstallOptions{NonInteractive: true}); err == nil {
				t.Fatalf("case[%d]: expected Install blocked for mem=%+v", i, mem)
			} else if !strings.Contains(err.Error(), "sing-box 纯 IP DoH + geosite-ad1") {
				t.Fatalf("case[%d]: unexpected error text: %v", i, err)
			}
		}
	})

	t.Run("allows_force_low_memory_override_or_sufficient_ram_hermetically", func(t *testing.T) {
		runPastGuard := func(t *testing.T, mem sysinfo.MemInfo, force bool) {
			t.Helper()
			dir := t.TempDir()
			fakeBin := filepath.Join(dir, "AdGuardHome")
			// Fake binary fails --check-config immediately so Install stops hermetically before touching host services
			if err := os.WriteFile(fakeBin, []byte("#!/bin/sh\necho 'synthetic check stop' >&2\nexit 1\n"), 0755); err != nil {
				t.Fatal(err)
			}
			aghYAML := filepath.Join(dir, "AdGuardHome.yaml")
			singctlYAML := filepath.Join(dir, "singctl.yaml")

			mgr := adguard.NewManager(&config.Config{}, singctlYAML)
			mgr.SetPathsForTest(fakeBin, aghYAML)
			mgr.SetReadMemInfoForTest(func() sysinfo.MemInfo { return mem })

			_, err := mgr.Install(adguard.InstallOptions{
				NonInteractive: true,
				ForceLowMemory: force,
			})
			if err == nil || !strings.Contains(err.Error(), "配置语法校验失败") {
				t.Fatalf("expected Install to pass memory guard and stop at synthetic --check-config, got: %v", err)
			}
		}

		// 1) 224 MiB with ForceLowMemory=true bypasses guard
		runPastGuard(t, sysinfo.MemInfo{TotalBytes: 224 * mib, AvailableBytes: 120 * mib}, true)
		// 2) 0 RAM (non-Linux / unknown) passes guard
		runPastGuard(t, sysinfo.MemInfo{TotalBytes: 0, AvailableBytes: 0}, false)
		// 3) 288 MiB + 1 byte total and 256 MiB + 1 byte available passes guard
		runPastGuard(t, sysinfo.MemInfo{TotalBytes: 288*mib + 1, AvailableBytes: 256*mib + 1}, false)
	})

	t.Run("concurrent_low_memory_guard_race_safe", func(t *testing.T) {
		dir := t.TempDir()
		mgr := adguard.NewManager(&config.Config{}, filepath.Join(dir, "singctl.yaml"))
		mgr.SetPathsForTest(filepath.Join(dir, "AdGuardHome"), filepath.Join(dir, "AdGuardHome.yaml"))
		mgr.SetReadMemTotalForTest(func() uint64 { return 224 * mib })

		var wg sync.WaitGroup
		for range 8 {
			wg.Go(func() {
				if _, err := mgr.Install(adguard.InstallOptions{NonInteractive: true}); err == nil {
					t.Errorf("expected concurrent Install to be blocked on 224 MiB")
				}
			})
		}
		wg.Wait()
	})
}
