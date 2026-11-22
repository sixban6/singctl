// 文件职责：验证 SmartDNS 管理器硬件护栏（RAM/UBIFS 闪存）、安装/卸载边界、ApplyConfig、EnsureHealthy 与配置预览。
package smartdns_test

import (
	"context"
	"errors"
	"os"
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

func TestManager_HardwareGuardBoundaries(t *testing.T) {
	const mib uint64 = 1024 * 1024

	t.Run("ram_guard_blocks_256m_and_288m_allows_n60pro_and_force_bypass", func(t *testing.T) {
		blockedCases := []sysinfo.MemInfo{
			{TotalBytes: 224 * mib, AvailableBytes: 120 * mib},
			{TotalBytes: 256 * mib, AvailableBytes: 128 * mib},
			{TotalBytes: 288 * mib, AvailableBytes: 160 * mib},
			{TotalBytes: 512 * mib, AvailableBytes: 95 * mib},
		}
		for i, mem := range blockedCases {
			root := t.TempDir()
			mgr := smartdns.NewManager(smartdns.ManagerOptions{
				BinaryPath: filepath.Join(root, "smartdns"),
				ConfigDir:  filepath.Join(root, "etc"),
				GOOS:       "linux",
				GOARCH:     "arm64",
				ServiceMgr: servicemgr.NewMock(),
				ReadMemInfo: func() (sysinfo.MemInfo, error) {
					return mem, nil
				},
				ReadDiskSpace: func(string) (sysinfo.DiskSpace, error) {
					return sysinfo.DiskSpace{AvailBytes: 20 * mib}, nil
				},
			})

			lowMemWarn, diskWarn := mgr.HardwareGuardWarning()
			if lowMemWarn == "" || diskWarn != "" {
				t.Errorf("case[%d] mem=%+v: got (lowMem=%q, disk=%q), want non-empty lowMem and empty disk", i, mem, lowMemWarn, diskWarn)
			}
			if !strings.Contains(lowMemWarn, "singbox") {
				t.Errorf("case[%d]: lowMemWarn %q should suggest singbox engine", i, lowMemWarn)
			}
			if _, err := mgr.Install(t.Context(), smartdns.InstallOptions{}); err == nil {
				t.Errorf("case[%d]: expected Install blocked by RAM guard", i)
			}
			st := mgr.Status()
			if st.HardwareEligible {
				t.Errorf("case[%d]: expected HardwareEligible=false", i)
			}
		}

		// n60pro profile (~479.5 MiB total, ~205 MiB avail, 19.8 MB flash) MUST pass!
		root := t.TempDir()
		binPath := filepath.Join(root, "smartdns")
		mgr := smartdns.NewManager(smartdns.ManagerOptions{
			BinaryPath:   binPath,
			ConfigDir:    filepath.Join(root, "etc"),
			AuditLogPath: filepath.Join(root, "audit.log"),
			LogFilePath:  filepath.Join(root, "smartdns.log"),
			PIDFilePath:  filepath.Join(root, "smartdns.pid"),
			GOOS:         "linux",
			GOARCH:       "arm64",
			ServiceMgr:   servicemgr.NewMock(),
			ReadMemInfo: func() (sysinfo.MemInfo, error) {
				return sysinfo.MemInfo{TotalBytes: 479 * mib, AvailableBytes: 205 * mib}, nil
			},
			ReadDiskSpace: func(string) (sysinfo.DiskSpace, error) {
				return sysinfo.DiskSpace{AvailBytes: 19*mib + 800*1024}, nil
			},
			DownloadFunc: func(_ context.Context, _, tmpDest string) error {
				return os.WriteFile(tmpDest, []byte("#!/bin/sh\necho 'smartdns Release48.5'\n"), 0755)
			},
			ProbeDNSFunc: func(string, time.Duration) error { return nil },
		})

		lowMemWarn, diskWarn := mgr.HardwareGuardWarning()
		if lowMemWarn != "" || diskWarn != "" {
			t.Fatalf("n60pro should be eligible, got lowMem=%q disk=%q", lowMemWarn, diskWarn)
		}
		if _, err := mgr.Install(t.Context(), smartdns.InstallOptions{}); err != nil {
			t.Fatalf("n60pro Install should succeed, got: %v", err)
		}

		// ForceLowMemory allows 256M device to install
		root2 := t.TempDir()
		mgrForce := smartdns.NewManager(smartdns.ManagerOptions{
			BinaryPath:   filepath.Join(root2, "smartdns"),
			ConfigDir:    filepath.Join(root2, "etc"),
			AuditLogPath: filepath.Join(root2, "audit.log"),
			LogFilePath:  filepath.Join(root2, "smartdns.log"),
			PIDFilePath:  filepath.Join(root2, "smartdns.pid"),
			GOOS:         "linux",
			GOARCH:       "arm64",
			ServiceMgr:   servicemgr.NewMock(),
			ReadMemInfo: func() (sysinfo.MemInfo, error) {
				return sysinfo.MemInfo{TotalBytes: 256 * mib, AvailableBytes: 80 * mib}, nil
			},
			ReadDiskSpace: func(string) (sysinfo.DiskSpace, error) {
				return sysinfo.DiskSpace{AvailBytes: 12 * mib}, nil
			},
			DownloadFunc: func(_ context.Context, _, tmpDest string) error {
				return os.WriteFile(tmpDest, []byte("fake"), 0755)
			},
			ExecVerifyFunc: func(context.Context, string) (string, error) {
				return "smartdns Release48.5", nil
			},
			ProbeDNSFunc: func(string, time.Duration) error { return nil },
		})
		if _, err := mgrForce.Install(t.Context(), smartdns.InstallOptions{ForceLowMemory: true}); err != nil {
			t.Fatalf("ForceLowMemory Install should pass, got: %v", err)
		}
	})

	t.Run("disk_guard_10mb_fresh_vs_6mb_upgrade", func(t *testing.T) {
		root := t.TempDir()
		binPath := filepath.Join(root, "smartdns")

		// Fresh install with 8 MB free -> blocked (< 10 MB)
		mgr := smartdns.NewManager(smartdns.ManagerOptions{
			BinaryPath: binPath,
			ConfigDir:  filepath.Join(root, "etc"),
			GOOS:       "linux",
			GOARCH:     "arm64",
			ServiceMgr: servicemgr.NewMock(),
			ReadMemInfo: func() (sysinfo.MemInfo, error) {
				return sysinfo.MemInfo{TotalBytes: 512 * mib, AvailableBytes: 200 * mib}, nil
			},
			ReadDiskSpace: func(string) (sysinfo.DiskSpace, error) {
				return sysinfo.DiskSpace{AvailBytes: 8 * mib}, nil
			},
		})
		if _, diskWarn := mgr.HardwareGuardWarning(); diskWarn == "" {
			t.Fatal("expected disk warning for 8 MB fresh install")
		}
		if _, err := mgr.Install(t.Context(), smartdns.InstallOptions{}); err == nil {
			t.Fatal("expected fresh install blocked at 8 MB")
		}

		// Existing binary present -> upgrade threshold drops to 6 MB, so 8 MB passes!
		if err := os.WriteFile(binPath, []byte("existing"), 0755); err != nil {
			t.Fatal(err)
		}
		if _, diskWarn := mgr.HardwareGuardWarning(); diskWarn != "" {
			t.Fatalf("expected upgrade at 8 MB to pass (>= 6 MB), got diskWarn=%q", diskWarn)
		}

		// Upgrade with 5 MB free -> blocked (< 6 MB)
		mgrLow := smartdns.NewManager(smartdns.ManagerOptions{
			BinaryPath: binPath,
			ConfigDir:  filepath.Join(root, "etc"),
			GOOS:       "linux",
			GOARCH:     "arm64",
			ServiceMgr: servicemgr.NewMock(),
			ReadMemInfo: func() (sysinfo.MemInfo, error) {
				return sysinfo.MemInfo{TotalBytes: 512 * mib, AvailableBytes: 200 * mib}, nil
			},
			ReadDiskSpace: func(string) (sysinfo.DiskSpace, error) {
				return sysinfo.DiskSpace{AvailBytes: 5 * mib}, nil
			},
		})
		if _, diskWarn := mgrLow.HardwareGuardWarning(); diskWarn == "" {
			t.Fatal("expected upgrade at 5 MB to trigger disk warning (< 6 MB)")
		}
	})
}

func TestManager_FullLifecycleApplyConfigEnsureHealthyPreviewAndUninstall(t *testing.T) {
	const mib uint64 = 1024 * 1024
	root := t.TempDir()
	binPath := filepath.Join(root, "bin", "smartdns")
	cfgDir := filepath.Join(root, "etc")
	sentinelFile := filepath.Join(cfgDir, "singctl.yaml")
	if err := os.MkdirAll(cfgDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sentinelFile, []byte("keep-me: true\n"), 0600); err != nil {
		t.Fatal(err)
	}

	mockSvc := servicemgr.NewMock()
	var probeHealthy atomic.Bool
	probeHealthy.Store(true)

	mgr := smartdns.NewManager(smartdns.ManagerOptions{
		BinaryPath:   binPath,
		ConfigDir:    cfgDir,
		AuditLogPath: filepath.Join(root, "audit.log"),
		LogFilePath:  filepath.Join(root, "smartdns.log"),
		PIDFilePath:  filepath.Join(root, "smartdns.pid"),
		GOOS:         "linux",
		GOARCH:       "amd64",
		ServiceMgr:   mockSvc,
		ReadMemInfo: func() (sysinfo.MemInfo, error) {
			return sysinfo.MemInfo{TotalBytes: 512 * mib, AvailableBytes: 256 * mib}, nil
		},
		ReadDiskSpace: func(string) (sysinfo.DiskSpace, error) {
			return sysinfo.DiskSpace{AvailBytes: 50 * mib}, nil
		},
		DownloadFunc: func(_ context.Context, assetName, tmpDest string) error {
			if assetName != "smartdns-x86_64" {
				return errors.New("wrong asset: " + assetName)
			}
			return os.WriteFile(tmpDest, []byte("binary"), 0755)
		},
		ExecVerifyFunc: func(context.Context, string) (string, error) {
			return "smartdns Release48.5", nil
		},
		ProbeDNSFunc: func(string, time.Duration) error {
			if probeHealthy.Load() {
				return nil
			}
			return errors.New("connection refused")
		},
	})

	// Preview works even before Install
	prePreview, err := mgr.EffectiveConfigPreview()
	if err != nil || !strings.Contains(prePreview, "bind 127.0.0.1:5353") {
		t.Fatalf("pre-install EffectiveConfigPreview = (%q, %v)", prePreview, err)
	}

	// Install
	st, err := mgr.Install(t.Context(), smartdns.InstallOptions{
		Config: smartdns.ConfigInput{
			DNSPort:   5353,
			Whitelist: []string{"safe.example.com"},
			Rewrites:  []smartdns.RewriteEntry{{Domain: "nas.example.com", Answer: "192.0.2.10"}},
		},
	})
	if err != nil {
		t.Fatalf("Install failed: %v", err)
	}
	if !st.Installed || !st.Running || !st.DNSHealthy || st.DNSAddr != "127.0.0.1:5353" {
		t.Fatalf("unexpected status: %+v", st)
	}

	// ApplyConfig updates config and reloads running service
	err = mgr.ApplyConfig(t.Context(), smartdns.ConfigInput{
		DNSPort:             5353,
		UpstreamMode:        "parallel",
		BlockAAAA:           true,
		Whitelist:           []string{"safe.example.com"},
		Rewrites:            []smartdns.RewriteEntry{{Domain: "nas.example.com", Answer: "192.0.2.20"}},
		AuditBlockedDomains: []string{"bad.example.com"},
	})
	if err != nil {
		t.Fatalf("ApplyConfig failed: %v", err)
	}
	if !slices.Contains(mockSvc.Calls(), "reload singctl-smartdns") {
		t.Errorf("expected ApplyConfig to reload active service, calls=%v", mockSvc.Calls())
	}

	// Preview shows persisted config & rule summary
	preview, err := mgr.EffectiveConfigPreview()
	if err != nil {
		t.Fatalf("EffectiveConfigPreview failed: %v", err)
	}
	for _, kw := range []string{"force-AAAA-SOA yes", "nas.example.com", "bad.example.com", "safe.example.com"} {
		if !strings.Contains(preview, kw) {
			t.Errorf("preview missing %q:\n%s", kw, preview)
		}
	}

	// EnsureHealthy triggers Restart when DNS probe fails
	probeHealthy.Store(false)
	if err := mgr.EnsureHealthy(); err != nil {
		t.Fatalf("EnsureHealthy failed: %v", err)
	}
	if !slices.Contains(mockSvc.Calls(), "restart singctl-smartdns") {
		t.Errorf("expected EnsureHealthy to restart unhealthy service, calls=%v", mockSvc.Calls())
	}

	// Concurrent Status() calls must be race-free
	var wg sync.WaitGroup
	for range 6 {
		wg.Go(func() {
			_ = mgr.Status()
		})
	}
	wg.Wait()

	// Uninstall removes binary, smartdns.conf, smartdns-rules.d, and unit, while PRESERVING /etc/singctl/singctl.yaml!
	if err := mgr.Uninstall(t.Context()); err != nil {
		t.Fatalf("Uninstall failed: %v", err)
	}
	if !slices.Contains(mockSvc.Calls(), "remove-unit singctl-smartdns") {
		t.Errorf("expected remove-unit call on Uninstall, calls=%v", mockSvc.Calls())
	}
	if _, err := os.Stat(binPath); !os.IsNotExist(err) {
		t.Errorf("expected binary removed after Uninstall")
	}
	if _, err := os.Stat(filepath.Join(cfgDir, "smartdns.conf")); !os.IsNotExist(err) {
		t.Errorf("expected smartdns.conf removed after Uninstall")
	}
	if _, err := os.Stat(filepath.Join(cfgDir, "smartdns-rules.d")); !os.IsNotExist(err) {
		t.Errorf("expected smartdns-rules.d removed after Uninstall")
	}
	if _, err := os.Stat(sentinelFile); err != nil {
		t.Fatalf("CRITICAL: Uninstall must NEVER delete sibling files like singctl.yaml in ConfigDir! err=%v", err)
	}
}

func TestManager_UnsupportedOSRejected(t *testing.T) {
	mgr := smartdns.NewManager(smartdns.ManagerOptions{
		BinaryPath: filepath.Join(t.TempDir(), "smartdns"),
		ConfigDir:  t.TempDir(),
		GOOS:       "darwin",
		GOARCH:     "arm64",
	})
	st := mgr.Status()
	if st.Supported {
		t.Fatal("expected Supported=false on darwin")
	}
	if _, err := mgr.Install(t.Context(), smartdns.InstallOptions{}); err == nil {
		t.Fatal("expected Install rejected on non-Linux OS")
	}
}
