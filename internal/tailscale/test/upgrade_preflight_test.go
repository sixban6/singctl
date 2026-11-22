// 文件职责：覆盖 Tailscale 升级预检（Flash/内存门禁、双通道发布回退、0600 状态持久化、DryRun 与并发竞态）测试。
package tailscale_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	releasepkg "singctl/internal/common/release"
	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/tailscale"
)

func TestPreflightUpgrade_FlashBlock_UpToDate_Force_Platform_And_InitSystems(t *testing.T) {
	primaryTagPath := "/repos/" + constant.GitHubRepo + "/releases/tags/tailscale-latest"
	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != primaryTagPath {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(releasepkg.Info{
			TagName: "tailscale-latest",
			Assets: []releasepkg.Asset{
				{
					Name:               "tailscale_1.104.7_arm64.tgz",
					BrowserDownloadURL: "https://example.com/tailscale_1.104.7_arm64.tgz",
					Size:               6 * 1024 * 1024,
					Digest:             "sha256:" + strings.Repeat("a", 64),
				},
				{
					Name:               "tailscale_1.104.7_amd64.tgz",
					BrowserDownloadURL: "https://example.com/tailscale_1.104.7_amd64.tgz",
					Size:               6500 * 1024,
					Digest:             "sha256:" + strings.Repeat("b", 64),
				},
			},
		})
	}))
	defer apiSrv.Close()

	ts := tailscale.New("", &config.TailscaleConfig{})
	ts.OpenWrtCheck = func() bool { return true }
	relClient := &releasepkg.Client{
		APIBase:     apiSrv.URL,
		HTTP:        apiSrv.Client(),
		DirectFirst: true,
	}

	preNonLinux, err := ts.PreflightUpgrade(t.Context(), tailscale.UpgradeOptions{
		LinuxCheck:    func() bool { return false },
		ReleaseClient: relClient,
	})
	if err != nil {
		t.Fatalf("PreflightUpgrade non-Linux unexpected error: %v", err)
	}
	if preNonLinux.Supported || preNonLinux.CanProceed || preNonLinux.CanForceProceed {
		t.Fatalf("expected Supported=false on non-Linux, got %+v", preNonLinux)
	}

	dir := t.TempDir()
	installDir := filepath.Join(dir, "sbin")
	_ = os.MkdirAll(installDir, 0755)
	initScript := filepath.Join(dir, "init-tailscale")
	_ = os.WriteFile(initScript, []byte("#!/bin/sh\nexit 0\n"), 0755)
	_ = os.WriteFile(filepath.Join(installDir, "tailscaled"), []byte(fmt.Sprintf(fakeCombinedBinaryScript, "1.104.7", "1.104.7")), 0755)
	_ = os.Symlink("tailscaled", filepath.Join(installDir, "tailscale"))

	paths := tailscale.UpgradePaths{
		InstallDir: installDir,
		InitScript: initScript,
		StateFile:  filepath.Join(dir, "state"),
		LogFile:    filepath.Join(dir, "log"),
		LockFile:   filepath.Join(dir, "lock"),
		SocketPath: filepath.Join(dir, "missing.sock"),
	}

	preLowFlash, err := ts.PreflightUpgrade(t.Context(), tailscale.UpgradeOptions{
		Paths:         paths,
		ArchOverride:  "arm64",
		LinuxCheck:    func() bool { return true },
		StatfsFn:      func(string) (uint64, error) { return 8 << 20, nil },
		MemInfoFn:     func() (uint64, uint64) { return 64 << 20, 0 },
		ReleaseClient: relClient,
	})
	if err != nil {
		t.Fatalf("PreflightUpgrade low flash error: %v", err)
	}
	if preLowFlash.CanProceed || preLowFlash.CanForceProceed || len(preLowFlash.BlockedReasons) == 0 {
		t.Fatalf("expected Flash block, got %+v", preLowFlash)
	}

	preUpToDate, err := ts.PreflightUpgrade(t.Context(), tailscale.UpgradeOptions{
		Paths:         paths,
		ArchOverride:  "arm64",
		LinuxCheck:    func() bool { return true },
		StatfsFn:      func(string) (uint64, error) { return 100 << 20, nil },
		MemInfoFn:     func() (uint64, uint64) { return 128 << 20, 0 },
		ReleaseClient: relClient,
	})
	if err != nil || !preUpToDate.UpToDate || preUpToDate.CanProceed || !preUpToDate.CanForceProceed {
		t.Fatalf("expected UpToDate=true CanProceed=false CanForceProceed=true, got %+v err=%v", preUpToDate, err)
	}

	_ = os.WriteFile(filepath.Join(installDir, "tailscaled"), []byte(fmt.Sprintf(fakeCombinedBinaryScript, "1.94.2", "1.94.2")), 0755)
	tsSystemd := tailscale.New("", &config.TailscaleConfig{})
	tsSystemd.OpenWrtCheck = func() bool { return false }
	preSystemd, err := tsSystemd.PreflightUpgrade(t.Context(), tailscale.UpgradeOptions{
		Paths:              paths,
		ArchOverride:       "amd64",
		LinuxCheck:         func() bool { return true },
		InitSystemOverride: "systemd",
		StatfsFn:           func(string) (uint64, error) { return 512 << 20, nil },
		MemInfoFn:          func() (uint64, uint64) { return 16 << 20, 0 },
		ReleaseClient:      relClient,
	})
	if err != nil || preSystemd.InitSystem != "systemd" || !preSystemd.CombinedMinimal || !preSystemd.CanProceed {
		t.Fatalf("unexpected systemd preflight: %+v err=%v", preSystemd, err)
	}
	if preSystemd.RequiredFreeBytes >= 40<<20 || len(preSystemd.Warnings) == 0 {
		t.Fatalf("unexpected systemd space/warnings: %+v", preSystemd)
	}
}

func TestUpgradeStateReadWrite_0600_And_SafeUpdateDryRun(t *testing.T) {
	dir := t.TempDir()
	paths := tailscale.UpgradePaths{
		StateFile: filepath.Join(dir, "upgrade.state"),
		LogFile:   filepath.Join(dir, "upgrade.log"),
	}

	idle, err := tailscale.ReadUpgradeState(paths)
	if err != nil || idle.Phase != tailscale.UpgradePhaseIdle {
		t.Fatalf("ReadUpgradeState missing = (%+v, %v)", idle, err)
	}

	st := &tailscale.UpgradeState{
		Phase:       tailscale.UpgradePhaseRolledBack,
		FromVersion: "1.94.2",
		ToVersion:   "1.104.8",
		Arch:        "arm64",
		Combined:    true,
		StartedAt:   time.Now().UTC().Format(time.RFC3339),
		Error:       "health gate timed out",
		RolledBack:  true,
	}
	if err := tailscale.WriteUpgradeState(paths, st); err != nil {
		t.Fatalf("WriteUpgradeState: %v", err)
	}

	info, err := os.Stat(paths.StateFile)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 permission on state file, got %v err=%v", info, err)
	}

	bigLog := strings.Repeat("old-log-line\n", 1000) + "FINAL_ROLLBACK_REASON\n"
	_ = os.WriteFile(paths.LogFile, []byte(bigLog), 0600)

	got, err := tailscale.ReadUpgradeState(paths)
	if err != nil || got.Phase != tailscale.UpgradePhaseRolledBack || len(got.LogTail) > 8192 || !strings.Contains(got.LogTail, "FINAL_ROLLBACK_REASON") {
		t.Fatalf("unexpected ReadUpgradeState: %+v err=%v", got, err)
	}

	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(releasepkg.Info{
			TagName: "latest",
			Assets: []releasepkg.Asset{{
				Name:               "tailscale_1.104.7_arm64.tgz",
				BrowserDownloadURL: "https://example.com/tailscale_1.104.7_arm64.tgz",
				Size:               6 * 1024 * 1024,
				Digest:             "sha256:" + strings.Repeat("c", 64),
			}},
		})
	}))
	defer apiSrv.Close()

	sbinDir := filepath.Join(dir, "sbin")
	_ = os.MkdirAll(sbinDir, 0755)
	_ = os.WriteFile(filepath.Join(sbinDir, "tailscaled"), []byte(fmt.Sprintf(fakeCombinedBinaryScript, "1.94.2", "1.94.2")), 0755)
	_ = os.Symlink("tailscaled", filepath.Join(sbinDir, "tailscale"))
	initScript := filepath.Join(dir, "init-tailscale")
	_ = os.WriteFile(initScript, []byte("#!/bin/sh\nexit 0\n"), 0755)

	ts := tailscale.New("", &config.TailscaleConfig{})
	ts.OpenWrtCheck = func() bool { return true }
	if err := ts.SafeUpdate(t.Context(), tailscale.UpgradeOptions{
		DryRun:       true,
		ArchOverride: "arm64",
		LinuxCheck:   func() bool { return true },
		StatfsFn:     func(string) (uint64, error) { return 100 << 20, nil },
		MemInfoFn:    func() (uint64, uint64) { return 64 << 20, 0 },
		Paths: tailscale.UpgradePaths{
			InstallDir: sbinDir,
			InitScript: initScript,
			StateFile:  filepath.Join(dir, "dry.state"),
			LogFile:    filepath.Join(dir, "dry.log"),
			LockFile:   filepath.Join(dir, "dry.lock"),
			SocketPath: filepath.Join(dir, "dry.sock"),
		},
		ReleaseClient: &releasepkg.Client{APIBase: apiSrv.URL, HTTP: apiSrv.Client(), DirectFirst: true},
	}); err != nil {
		t.Fatalf("SafeUpdate DryRun failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(sbinDir, tailscale.StagedTailscaledName)); !os.IsNotExist(err) {
		t.Fatal("DryRun must not stage .tailscaled.new")
	}
}

func TestFetchTailscaleRelease_PrimaryFallback_And_ConcurrentRace(t *testing.T) {
	amd64Sum := strings.Repeat("c", 64)
	legacySum := strings.Repeat("d", 64)
	primaryTagPath := "/repos/" + constant.GitHubRepo + "/releases/tags/tailscale-latest"
	primaryAssetPath := "/repos/" + constant.GitHubRepo + "/releases/assets/101"

	tests := []struct {
		name                string
		primaryStatus       int
		legacyStatus        int
		wantLegacyCalled    bool
		wantBlocked         bool
		wantCombined        bool
		wantDigest          string
		wantRequiredAtLeast int64
	}{
		{
			name:                "主通道命中并从本仓库checksums回填SHA256",
			primaryStatus:       http.StatusOK,
			legacyStatus:        http.StatusOK,
			wantLegacyCalled:    false,
			wantBlocked:         false,
			wantCombined:        true,
			wantDigest:          "sha256:" + amd64Sum,
			wantRequiredAtLeast: 16 << 20,
		},
		{
			name:                "主通道404时平滑回退旧仓库且40MiB标准amd64包识别为非精简版",
			primaryStatus:       http.StatusNotFound,
			legacyStatus:        http.StatusOK,
			wantLegacyCalled:    true,
			wantBlocked:         false,
			wantCombined:        false,
			wantDigest:          "sha256:" + legacySum,
			wantRequiredAtLeast: 100 << 20,
		},
		{
			name:             "主通道500服务器异常不盲目回退旧仓库",
			primaryStatus:    http.StatusInternalServerError,
			legacyStatus:     http.StatusOK,
			wantLegacyCalled: false,
			wantBlocked:      true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var legacyCalled bool
			var mu sync.Mutex

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case primaryTagPath:
					if tc.primaryStatus != http.StatusOK {
						http.Error(w, "primary status", tc.primaryStatus)
						return
					}
					_ = json.NewEncoder(w).Encode(releasepkg.Info{
						TagName: "tailscale-latest",
						Assets: []releasepkg.Asset{
							{Name: "tailscale_1.104.7_amd64.tgz", Size: 6500 * 1024},
							{ID: 101, Name: "checksums.txt"},
						},
					})
				case primaryAssetPath:
					_, _ = fmt.Fprintf(w, "%s  tailscale_1.104.7_amd64.tgz\n", amd64Sum)
				case "/repos/sixban6/auto_fetch_tailscale/releases/latest":
					mu.Lock()
					legacyCalled = true
					mu.Unlock()
					if tc.legacyStatus != http.StatusOK {
						http.Error(w, "legacy error", tc.legacyStatus)
						return
					}
					_ = json.NewEncoder(w).Encode(releasepkg.Info{
						TagName: "latest",
						Assets: []releasepkg.Asset{
							{Name: "tailscale_1.104.7_amd64.tgz", Size: 40 * 1024 * 1024},
							{ID: 202, Name: "checksums.txt"},
						},
					})
				case "/repos/sixban6/auto_fetch_tailscale/releases/assets/202":
					_, _ = fmt.Fprintf(w, "%s  tailscale_1.104.7_amd64.tgz\n", legacySum)
				default:
					http.NotFound(w, r)
				}
			}))
			defer srv.Close()

			dir := t.TempDir()
			sbinDir := filepath.Join(dir, "sbin")
			_ = os.MkdirAll(sbinDir, 0755)
			initScript := filepath.Join(dir, "init-tailscale")
			_ = os.WriteFile(initScript, []byte("#!/bin/sh\nexit 0\n"), 0755)
			_ = os.WriteFile(filepath.Join(sbinDir, "tailscaled"), []byte(fmt.Sprintf(fakeCombinedBinaryScript, "1.94.2", "1.94.2")), 0755)
			_ = os.Symlink("tailscaled", filepath.Join(sbinDir, "tailscale"))

			ts := tailscale.New("", &config.TailscaleConfig{})
			ts.OpenWrtCheck = func() bool { return false }
			client := &releasepkg.Client{APIBase: srv.URL, DLBase: srv.URL, HTTP: srv.Client(), DirectFirst: true}

			pre, err := ts.PreflightUpgrade(t.Context(), tailscale.UpgradeOptions{
				Paths: tailscale.UpgradePaths{
					InstallDir: sbinDir,
					InitScript: initScript,
					StateFile:  filepath.Join(dir, "state"),
					LogFile:    filepath.Join(dir, "log"),
					LockFile:   filepath.Join(dir, "lock"),
					SocketPath: filepath.Join(dir, "missing.sock"),
				},
				ArchOverride:       "amd64",
				LinuxCheck:         func() bool { return true },
				InitSystemOverride: "systemd",
				StatfsFn:           func(string) (uint64, error) { return 1 << 30, nil },
				MemInfoFn:          func() (uint64, uint64) { return 256 << 20, 0 },
				ReleaseClient:      client,
			})
			if err != nil {
				t.Fatalf("PreflightUpgrade error: %v", err)
			}
			mu.Lock()
			gotLegacy := legacyCalled
			mu.Unlock()
			if gotLegacy != tc.wantLegacyCalled {
				t.Fatalf("legacyCalled = %v, want %v", gotLegacy, tc.wantLegacyCalled)
			}
			if tc.wantBlocked {
				if len(pre.BlockedReasons) == 0 || pre.CanProceed {
					t.Fatalf("expected BlockedReasons non-empty, got %+v", pre)
				}
				return
			}
			asset := pre.SelectedAsset()
			if pre.CombinedMinimal != tc.wantCombined || !pre.HasOfficialDigest || asset == nil || asset.Digest != tc.wantDigest {
				t.Fatalf("unexpected preflight asset/combined: %+v asset=%+v", pre, asset)
			}
			if pre.RequiredFreeBytes < tc.wantRequiredAtLeast {
				t.Fatalf("RequiredFreeBytes = %d, want >= %d", pre.RequiredFreeBytes, tc.wantRequiredAtLeast)
			}
		})
	}

	t.Run("并发预检零数据竞争", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != primaryTagPath {
				http.NotFound(w, r)
				return
			}
			_ = json.NewEncoder(w).Encode(releasepkg.Info{
				TagName: "tailscale-latest",
				Assets: []releasepkg.Asset{
					{Name: "tailscale_1.104.7_amd64.tgz", Size: 6500 * 1024, Digest: "sha256:" + amd64Sum},
				},
			})
		}))
		defer srv.Close()

		dir := t.TempDir()
		sbinDir := filepath.Join(dir, "sbin")
		_ = os.MkdirAll(sbinDir, 0755)
		_ = os.WriteFile(filepath.Join(sbinDir, "tailscaled"), []byte(fmt.Sprintf(fakeCombinedBinaryScript, "1.94.2", "1.94.2")), 0755)
		_ = os.Symlink("tailscaled", filepath.Join(sbinDir, "tailscale"))

		ts := tailscale.New("", &config.TailscaleConfig{})
		ts.OpenWrtCheck = func() bool { return false }
		client := &releasepkg.Client{APIBase: srv.URL, DLBase: srv.URL, HTTP: srv.Client(), DirectFirst: true}

		var wg sync.WaitGroup
		for range 8 {
			wg.Go(func() {
				pre, err := ts.PreflightUpgrade(t.Context(), tailscale.UpgradeOptions{
					Paths: tailscale.UpgradePaths{
						InstallDir: sbinDir,
						StateFile:  filepath.Join(dir, "state"),
						LogFile:    filepath.Join(dir, "log"),
						LockFile:   filepath.Join(dir, "lock"),
						SocketPath: filepath.Join(dir, "missing.sock"),
					},
					ArchOverride:       "amd64",
					LinuxCheck:         func() bool { return true },
					InitSystemOverride: "systemd",
					StatfsFn:           func(string) (uint64, error) { return 1 << 30, nil },
					MemInfoFn:          func() (uint64, uint64) { return 256 << 20, 0 },
					ReleaseClient:      client,
				})
				if err != nil || !pre.CanProceed || !pre.CombinedMinimal {
					t.Errorf("concurrent PreflightUpgrade unexpected result: pre=%+v err=%v", pre, err)
				}
			})
		}
		wg.Wait()
	})
}
