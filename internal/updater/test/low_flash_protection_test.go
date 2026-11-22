// 文件职责：验证 updater 在小闪存与低内存宿主机自动优先选择 -lite 精简包、启用零 /tmp 流式升级，并严防服务端 VPS 误切 -lite。
package updater_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"singctl/internal/common/release"
	"singctl/internal/common/sysinfo"
	"singctl/internal/updater"
)

func TestUpdateSelf_LowFlashAndLowMemoryAutoLiteProtection(t *testing.T) {
	const (
		mib uint64 = 1024 * 1024
		gib uint64 = 1024 * mib
	)

	stdBin := "#!/bin/sh\necho singctl-standard\n"
	liteBin := "#!/bin/sh\necho singctl-lite\n"

	stdArchive, stdSHA := buildTestSingCtlTarGz(t, map[string]string{
		"singctl-linux-arm64/singctl": stdBin,
	})
	liteArchive, liteSHA := buildTestSingCtlTarGz(t, map[string]string{
		"singctl-linux-arm64-lite/singctl": liteBin,
	})
	stdAmd64Archive, stdAmd64SHA := buildTestSingCtlTarGz(t, map[string]string{
		"singctl-linux-amd64/singctl": stdBin,
	})
	liteAmd64Archive, liteAmd64SHA := buildTestSingCtlTarGz(t, map[string]string{
		"singctl-linux-amd64-lite/singctl": liteBin,
	})
	darwinArchive, darwinSHA := buildTestSingCtlTarGz(t, map[string]string{
		"singctl-darwin-arm64/singctl": stdBin,
	})

	startMockReleaseServer := func(t *testing.T, includeLite bool) (*httptest.Server, func() []string) {
		t.Helper()
		var mu sync.Mutex
		var downloads []string
		var srvURL string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/repos/test/singctl/releases/latest":
				assets := []release.Asset{
					{
						Name:               "singctl-linux-arm64.tar.gz",
						BrowserDownloadURL: srvURL + "/dl/singctl-linux-arm64.tar.gz",
						Size:               int64(len(stdArchive)),
						Digest:             "sha256:" + stdSHA,
					},
					{
						Name:               "singctl-linux-amd64.tar.gz",
						BrowserDownloadURL: srvURL + "/dl/singctl-linux-amd64.tar.gz",
						Size:               int64(len(stdAmd64Archive)),
						Digest:             "sha256:" + stdAmd64SHA,
					},
					{
						Name:               "singctl-darwin-arm64.tar.gz",
						BrowserDownloadURL: srvURL + "/dl/singctl-darwin-arm64.tar.gz",
						Size:               int64(len(darwinArchive)),
						Digest:             "sha256:" + darwinSHA,
					},
				}
				if includeLite {
					assets = append(assets,
						release.Asset{
							Name:               "singctl-linux-arm64-lite.tar.gz",
							BrowserDownloadURL: srvURL + "/dl/singctl-linux-arm64-lite.tar.gz",
							Size:               int64(len(liteArchive)),
							Digest:             "sha256:" + liteSHA,
						},
						release.Asset{
							Name:               "singctl-linux-amd64-lite.tar.gz",
							BrowserDownloadURL: srvURL + "/dl/singctl-linux-amd64-lite.tar.gz",
							Size:               int64(len(liteAmd64Archive)),
							Digest:             "sha256:" + liteAmd64SHA,
						},
					)
				}
				_ = json.NewEncoder(w).Encode(release.Info{
					TagName: "v1.14.210",
					Assets:  assets,
				})
			case "/dl/singctl-linux-arm64.tar.gz":
				mu.Lock()
				downloads = append(downloads, "singctl-linux-arm64.tar.gz")
				mu.Unlock()
				_, _ = w.Write(stdArchive)
			case "/dl/singctl-linux-arm64-lite.tar.gz":
				mu.Lock()
				downloads = append(downloads, "singctl-linux-arm64-lite.tar.gz")
				mu.Unlock()
				_, _ = w.Write(liteArchive)
			case "/dl/singctl-linux-amd64.tar.gz":
				mu.Lock()
				downloads = append(downloads, "singctl-linux-amd64.tar.gz")
				mu.Unlock()
				_, _ = w.Write(stdAmd64Archive)
			case "/dl/singctl-linux-amd64-lite.tar.gz":
				mu.Lock()
				downloads = append(downloads, "singctl-linux-amd64-lite.tar.gz")
				mu.Unlock()
				_, _ = w.Write(liteAmd64Archive)
			case "/dl/singctl-darwin-arm64.tar.gz":
				mu.Lock()
				downloads = append(downloads, "singctl-darwin-arm64.tar.gz")
				mu.Unlock()
				_, _ = w.Write(darwinArchive)
			default:
				http.NotFound(w, r)
			}
		}))
		srvURL = srv.URL
		t.Cleanup(srv.Close)
		return srv, func() []string {
			mu.Lock()
			defer mu.Unlock()
			out := make([]string, len(downloads))
			copy(out, downloads)
			return out
		}
	}

	t.Run("low_flash_128mb_router_even_with_1gb_ram_forces_lite_and_zero_tmp_stream", func(t *testing.T) {
		srv, getDownloads := startMockReleaseServer(t, true)
		tmpRoot := filepath.Join(t.TempDir(), "tmpfs")
		installDir := filepath.Join(t.TempDir(), "usr-bin")
		_ = os.MkdirAll(tmpRoot, 0755)
		_ = os.MkdirAll(installDir, 0755)
		exePath := filepath.Join(installDir, "singctl")
		_ = os.WriteFile(exePath, []byte("old-standard"), 0755)

		u := updater.NewWithDeps("", srv.URL, updater.Deps{
			APIBase:           srv.URL,
			DLBase:            srv.URL,
			HTTPClient:        srv.Client(),
			Repo:              "test/singctl",
			GOOS:              "linux",
			GOARCH:            "arm64",
			IsLite:            new(false),
			ReadTotalRAMBytes: func() uint64 { return 1 * gib },
			IsLowFlashHost:    func() bool { return true },
			StatTmpSpace: func(string) (sysinfo.DiskSpace, error) {
				return sysinfo.DiskSpace{TotalBytes: 512 * mib, AvailBytes: 400 * mib}, nil
			},
			ResolveExePath: func() (string, error) { return exePath, nil },
			TempDir:        tmpRoot,
		})

		if err := u.UpdateSelf("", "v1.14.100"); err != nil {
			t.Fatalf("UpdateSelf failed: %v", err)
		}
		if got := getDownloads(); len(got) != 1 || got[0] != "singctl-linux-arm64-lite.tar.gz" {
			t.Fatalf("expected low-flash router to download -lite asset, got %v", got)
		}
		if data, _ := os.ReadFile(exePath); string(data) != liteBin {
			t.Fatalf("expected lite binary installed, got %q", string(data))
		}
		if entries, _ := os.ReadDir(tmpRoot); len(entries) != 0 {
			t.Fatalf("expected zero-/tmp streaming on low-flash host (0 entries in tmp), got %v", entries)
		}
	})

	t.Run("low_memory_client_non_lite_binary_forces_lite", func(t *testing.T) {
		srv, getDownloads := startMockReleaseServer(t, true)
		installDir := filepath.Join(t.TempDir(), "usr-bin")
		_ = os.MkdirAll(installDir, 0755)
		exePath := filepath.Join(installDir, "singctl")
		_ = os.WriteFile(exePath, []byte("old-standard"), 0755)

		clientCfg := filepath.Join(t.TempDir(), "singctl.yaml")
		_ = os.WriteFile(clientCfg, []byte("subs:\n  - name: main\n    url: https://example.com/sub\n"), 0600)

		u := updater.NewWithDeps("", srv.URL, updater.Deps{
			APIBase:           srv.URL,
			DLBase:            srv.URL,
			HTTPClient:        srv.Client(),
			Repo:              "test/singctl",
			GOOS:              "linux",
			GOARCH:            "arm64",
			IsLite:            new(false),
			ReadTotalRAMBytes: func() uint64 { return 479 * mib },
			IsLowFlashHost:    func() bool { return false },
			ResolveExePath:    func() (string, error) { return exePath, nil },
		})

		if err := u.UpdateSelf(clientCfg, "v1.14.100"); err != nil {
			t.Fatalf("UpdateSelf failed: %v", err)
		}
		if got := getDownloads(); len(got) != 1 || got[0] != "singctl-linux-arm64-lite.tar.gz" {
			t.Fatalf("expected low-memory client to auto-pick -lite, got %v", got)
		}
	})

	t.Run("server_vps_with_512mb_ram_never_switches_to_lite", func(t *testing.T) {
		srv, getDownloads := startMockReleaseServer(t, true)
		installDir := filepath.Join(t.TempDir(), "usr-bin")
		_ = os.MkdirAll(installDir, 0755)
		exePath := filepath.Join(installDir, "singctl")
		_ = os.WriteFile(exePath, []byte("old-server"), 0755)

		serverCfg := filepath.Join(t.TempDir(), "singctl.yaml")
		_ = os.WriteFile(serverCfg, []byte("server:\n  node_domain: us1.example.com\n  hy2_port: 8443\n"), 0600)

		u := updater.NewWithDeps("", srv.URL, updater.Deps{
			APIBase:           srv.URL,
			DLBase:            srv.URL,
			HTTPClient:        srv.Client(),
			Repo:              "test/singctl",
			GOOS:              "linux",
			GOARCH:            "amd64",
			IsLite:            new(false),
			ReadTotalRAMBytes: func() uint64 { return 512 * mib },
			IsLowFlashHost:    func() bool { return false },
			ResolveExePath:    func() (string, error) { return exePath, nil },
		})

		if err := u.UpdateSelf(serverCfg, "v1.14.100"); err != nil {
			t.Fatalf("UpdateSelf on server VPS failed: %v", err)
		}
		if got := getDownloads(); len(got) != 1 || got[0] != "singctl-linux-amd64.tar.gz" {
			t.Fatalf("server VPS MUST keep standard package, got %v", got)
		}
		if data, _ := os.ReadFile(exePath); string(data) != stdBin {
			t.Fatalf("expected standard binary on server VPS, got %q", string(data))
		}
	})

	t.Run("ample_ram_and_flash_client_stays_standard_unless_already_lite", func(t *testing.T) {
		srv, getDownloads := startMockReleaseServer(t, true)
		installDir := filepath.Join(t.TempDir(), "usr-bin")
		_ = os.MkdirAll(installDir, 0755)
		exePath := filepath.Join(installDir, "singctl")
		_ = os.WriteFile(exePath, []byte("old-standard"), 0755)

		u := updater.NewWithDeps("", srv.URL, updater.Deps{
			APIBase:           srv.URL,
			DLBase:            srv.URL,
			HTTPClient:        srv.Client(),
			Repo:              "test/singctl",
			GOOS:              "linux",
			GOARCH:            "amd64",
			IsLite:            new(false),
			ReadTotalRAMBytes: func() uint64 { return 2 * gib },
			IsLowFlashHost:    func() bool { return false },
			StatTmpSpace: func(string) (sysinfo.DiskSpace, error) {
				return sysinfo.DiskSpace{TotalBytes: 2 * gib, AvailBytes: 1 * gib}, nil
			},
			ResolveExePath: func() (string, error) { return exePath, nil },
			TempDir:        t.TempDir(),
		})

		if err := u.UpdateSelf("", "v1.14.100"); err != nil {
			t.Fatalf("UpdateSelf failed: %v", err)
		}
		if got := getDownloads(); len(got) != 1 || got[0] != "singctl-linux-amd64.tar.gz" {
			t.Fatalf("expected standard package on big host, got %v", got)
		}
	})

	t.Run("low_flash_falls_back_to_standard_when_release_has_no_lite_asset", func(t *testing.T) {
		srv, getDownloads := startMockReleaseServer(t, false)
		installDir := filepath.Join(t.TempDir(), "usr-bin")
		_ = os.MkdirAll(installDir, 0755)
		exePath := filepath.Join(installDir, "singctl")
		_ = os.WriteFile(exePath, []byte("old"), 0755)

		u := updater.NewWithDeps("", srv.URL, updater.Deps{
			APIBase:           srv.URL,
			DLBase:            srv.URL,
			HTTPClient:        srv.Client(),
			Repo:              "test/singctl",
			GOOS:              "linux",
			GOARCH:            "arm64",
			IsLite:            new(false),
			ReadTotalRAMBytes: func() uint64 { return 1 * gib },
			IsLowFlashHost:    func() bool { return true },
			ResolveExePath:    func() (string, error) { return exePath, nil },
		})

		if err := u.UpdateSelf("", "v1.14.100"); err != nil {
			t.Fatalf("expected fallback to standard when -lite asset absent, got: %v", err)
		}
		if got := getDownloads(); len(got) != 1 || got[0] != "singctl-linux-arm64.tar.gz" {
			t.Fatalf("expected fallback download singctl-linux-arm64.tar.gz, got %v", got)
		}
	})

	t.Run("non_linux_host_ignores_low_flash_lite_switch", func(t *testing.T) {
		srv, getDownloads := startMockReleaseServer(t, true)
		installDir := filepath.Join(t.TempDir(), "usr-bin")
		_ = os.MkdirAll(installDir, 0755)
		exePath := filepath.Join(installDir, "singctl")
		_ = os.WriteFile(exePath, []byte("old-mac"), 0755)

		u := updater.NewWithDeps("", srv.URL, updater.Deps{
			APIBase:           srv.URL,
			DLBase:            srv.URL,
			HTTPClient:        srv.Client(),
			Repo:              "test/singctl",
			GOOS:              "darwin",
			GOARCH:            "arm64",
			IsLite:            new(false),
			ReadTotalRAMBytes: func() uint64 { return 256 * mib },
			IsLowFlashHost:    func() bool { return true },
			ResolveExePath:    func() (string, error) { return exePath, nil },
			TempDir:           t.TempDir(),
		})

		if err := u.UpdateSelf("", "v1.14.100"); err != nil {
			t.Fatalf("UpdateSelf(darwin) failed: %v", err)
		}
		if got := getDownloads(); len(got) != 1 || got[0] != "singctl-darwin-arm64.tar.gz" {
			t.Fatalf("expected darwin standard asset, got %v", got)
		}
	})
}
