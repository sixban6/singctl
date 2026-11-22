// 文件职责：验证 sing-box-lite 策略判定、资产版本解析、零 /tmp 闪存流式 SHA256 直写安装、404 平滑回退与 Update 幂等性。
package singbox_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	releasepkg "singctl/internal/common/release"
	"singctl/internal/common/sysinfo"
	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/singbox"
)

func buildSingBoxTarGz(t *testing.T, entryPath string, content string) ([]byte, string) {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	if err := tw.WriteHeader(&tar.Header{
		Name:     entryPath,
		Typeflag: tar.TypeReg,
		Mode:     0o755,
		Size:     int64(len(content)),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	// Extra trailing metadata file in archive to ensure streaming drains trailer bytes before SHA256 check.
	license := "GPL-3.0-or-later\n"
	if err := tw.WriteHeader(&tar.Header{
		Name:     "LICENSE",
		Typeflag: tar.TypeReg,
		Mode:     0o644,
		Size:     int64(len(license)),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(license)); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	raw := buf.Bytes()
	sum := sha256.Sum256(raw)
	return raw, hex.EncodeToString(sum[:])
}

func TestShouldUseSingBoxLite_TableDrivenBoundaries(t *testing.T) {
	const (
		mib            uint64 = 1024 * 1024
		n60ProOverlay  uint64 = 40*mib + 512*1024 // 40.5 MiB (/overlay on n60pro)
		thresholdExact uint64 = 120 * mib
	)

	cases := []struct {
		name         string
		goos         string
		goarch       string
		isLiteBinary bool
		lowMemory    bool
		availDisk    uint64
		envOverride  string
		want         bool
	}{
		// Normal auto-enable triggers on linux/amd64 & linux/arm64
		{
			name:         "n60pro_arm64_lite_lowmem_small_overlay",
			goos:         "linux",
			goarch:       "arm64",
			isLiteBinary: true,
			lowMemory:    true,
			availDisk:    n60ProOverlay,
			want:         true,
		},
		{
			name:         "linux_amd64_only_lite_binary_true",
			goos:         "linux",
			goarch:       "amd64",
			isLiteBinary: true,
			lowMemory:    false,
			availDisk:    20 * 1024 * mib,
			want:         true,
		},
		{
			name:         "linux_arm64_only_low_memory_true",
			goos:         "linux",
			goarch:       "arm64",
			isLiteBinary: false,
			lowMemory:    true,
			availDisk:    20 * 1024 * mib,
			want:         true,
		},
		{
			name:         "linux_amd64_small_disk_just_below_120mib",
			goos:         "linux",
			goarch:       "amd64",
			isLiteBinary: false,
			lowMemory:    false,
			availDisk:    thresholdExact - 1,
			want:         true,
		},
		{
			name:         "linux_arm64_small_disk_1_byte",
			goos:         "linux",
			goarch:       "arm64",
			isLiteBinary: false,
			lowMemory:    false,
			availDisk:    1,
			want:         true,
		},
		// Normal auto-disable on large-memory / ample-disk gateways (e.g. n4120 2GB RAM)
		{
			name:         "n4120_2gb_gateway_ample_disk_keeps_full_singbox",
			goos:         "linux",
			goarch:       "amd64",
			isLiteBinary: false,
			lowMemory:    false,
			availDisk:    thresholdExact,
			want:         false,
		},
		{
			name:         "zero_avail_disk_unknown_statfs_does_not_false_trigger",
			goos:         "linux",
			goarch:       "amd64",
			isLiteBinary: false,
			lowMemory:    false,
			availDisk:    0,
			want:         false,
		},
		{
			name:         "max_uint64_disk_full_binary_high_ram",
			goos:         "linux",
			goarch:       "arm64",
			isLiteBinary: false,
			lowMemory:    false,
			availDisk:    math.MaxUint64,
			want:         false,
		},
		// Explicit env overrides (SINGCTL_SINGBOX_LITE)
		{
			name:         "env_1_forces_lite_on_high_spec_linux_amd64",
			goos:         "linux",
			goarch:       "amd64",
			isLiteBinary: false,
			lowMemory:    false,
			availDisk:    50 * 1024 * mib,
			envOverride:  "1",
			want:         true,
		},
		{
			name:         "env_true_case_insensitive_forces_lite",
			goos:         "linux",
			goarch:       "arm64",
			isLiteBinary: false,
			lowMemory:    false,
			availDisk:    50 * 1024 * mib,
			envOverride:  "  TRUE ",
			want:         true,
		},
		{
			name:         "env_0_forces_off_even_on_n60pro",
			goos:         "linux",
			goarch:       "arm64",
			isLiteBinary: true,
			lowMemory:    true,
			availDisk:    n60ProOverlay,
			envOverride:  "0",
			want:         false,
		},
		{
			name:         "env_false_forces_off_even_on_small_flash",
			goos:         "linux",
			goarch:       "amd64",
			isLiteBinary: true,
			lowMemory:    true,
			availDisk:    10 * mib,
			envOverride:  " False ",
			want:         false,
		},
		{
			name:         "unknown_env_value_falls_back_to_auto_policy",
			goos:         "linux",
			goarch:       "arm64",
			isLiteBinary: false,
			lowMemory:    false,
			availDisk:    n60ProOverlay,
			envOverride:  "auto-unknown",
			want:         true,
		},
		// Unsupported OS / Arch boundaries
		{
			name:         "darwin_arm64_never_uses_linux_lite",
			goos:         "darwin",
			goarch:       "arm64",
			isLiteBinary: true,
			lowMemory:    true,
			availDisk:    10 * mib,
			envOverride:  "1",
			want:         false,
		},
		{
			name:         "windows_amd64_never_uses_linux_lite",
			goos:         "windows",
			goarch:       "amd64",
			isLiteBinary: true,
			lowMemory:    true,
			availDisk:    10 * mib,
			envOverride:  "true",
			want:         false,
		},
		{
			name:         "linux_386_unsupported_arch_returns_false",
			goos:         "linux",
			goarch:       "386",
			isLiteBinary: true,
			lowMemory:    true,
			availDisk:    10 * mib,
			envOverride:  "1",
			want:         false,
		},
		{
			name:         "linux_mipsle_unsupported_arch_returns_false",
			goos:         "linux",
			goarch:       "mipsle",
			isLiteBinary: true,
			lowMemory:    true,
			availDisk:    10 * mib,
			want:         false,
		},
		{
			name:   "empty_os_and_arch",
			goos:   "",
			goarch: "",
			want:   false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := singbox.ShouldUseSingBoxLite(tc.goos, tc.goarch, tc.isLiteBinary, tc.lowMemory, tc.availDisk, tc.envOverride)
			if got != tc.want {
				t.Fatalf("ShouldUseSingBoxLite(%q, %q, lite=%v, lowMem=%v, disk=%d, env=%q) = %v, want %v",
					tc.goos, tc.goarch, tc.isLiteBinary, tc.lowMemory, tc.availDisk, tc.envOverride, got, tc.want)
			}
		})
	}
}

func TestSelectAndParseSingBoxLiteAssetVersion(t *testing.T) {
	assets := []releasepkg.Asset{
		{Name: "checksums.txt"},
		{Name: "sing-box-1.14.4-linux-amd64.tar.gz"},
		{Name: "sing-box-1.14.4-linux-amd64-lite.tar.gz"},
		{Name: "sing-box-1.14.4-linux-arm64-lite.tar.gz"},
	}

	amd64Asset := singbox.SelectSingBoxLiteAsset(assets, "amd64")
	if amd64Asset == nil || amd64Asset.Name != "sing-box-1.14.4-linux-amd64-lite.tar.gz" {
		t.Fatalf("SelectSingBoxLiteAsset(amd64) = %+v", amd64Asset)
	}
	arm64Asset := singbox.SelectSingBoxLiteAsset(assets, "arm64")
	if arm64Asset == nil || arm64Asset.Name != "sing-box-1.14.4-linux-arm64-lite.tar.gz" {
		t.Fatalf("SelectSingBoxLiteAsset(arm64) = %+v", arm64Asset)
	}
	if bad := singbox.SelectSingBoxLiteAsset(assets, "riscv64"); bad != nil {
		t.Fatalf("expected nil for unsupported arch, got %+v", bad)
	}

	validVersions := map[string]string{
		"sing-box-1.14.4-linux-amd64-lite.tar.gz":      "1.14.4",
		"sing-box-1.15.0-rc.1-linux-arm64-lite.tar.gz": "1.15.0-rc.1",
		"sing-box-2.0-linux-arm64-lite.tar.gz":         "2.0",
	}
	for name, want := range validVersions {
		got, err := singbox.ParseSingBoxLiteAssetVersion(name)
		if err != nil || got != want {
			t.Fatalf("ParseSingBoxLiteAssetVersion(%q) = (%q, %v), want (%q, nil)", name, got, err, want)
		}
	}

	malformedNames := []string{
		"",
		"checksums.txt",
		"sing-box-1.14.4-linux-amd64.tar.gz",
		"sing-box--linux-amd64-lite.tar.gz",
		"sing-box-../1.14.4-linux-amd64-lite.tar.gz",
		"sing-box-1.14.4;rm -rf /-linux-arm64-lite.tar.gz",
	}
	for _, badName := range malformedNames {
		if got, err := singbox.ParseSingBoxLiteAssetVersion(badName); err == nil {
			t.Fatalf("expected error for malformed asset %q, got version %q", badName, got)
		}
	}
}

func TestSingBoxLite_ZeroTmpStreamingInstall_SymlinkReplace_And_MirrorTamperDefense(t *testing.T) {
	const mib uint64 = 1024 * 1024
	litePayload := "#!/bin/sh\necho 'sing-box version 1.14.4'\n"
	liteArchive, liteSHA := buildSingBoxTarGz(t, "sing-box-1.14.4-linux-arm64-lite/sing-box", litePayload)
	checksumsBody := fmt.Sprintf("%s  sing-box-1.14.4-linux-arm64-lite.tar.gz\n", liteSHA)

	var (
		srvURL            string
		mirrorCorrupt     atomic.Bool
		directCorrupt     atomic.Bool
		omitDigest        atomic.Bool
		omitChecksums     atomic.Bool
		mirrorHitMetadata atomic.Bool
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/mirror/") {
			if strings.Contains(r.URL.Path, "/repos/") || strings.HasSuffix(r.URL.Path, "checksums.txt") {
				mirrorHitMetadata.Store(true)
				http.Error(w, "mirror must NEVER serve metadata or checksums", http.StatusForbidden)
				return
			}
			if mirrorCorrupt.Load() {
				corrupted := append([]byte(nil), liteArchive...)
				corrupted[len(corrupted)-1] ^= 0xff
				_, _ = w.Write(corrupted)
				return
			}
			_, _ = w.Write(liteArchive)
			return
		}

		switch r.URL.Path {
		case "/repos/" + constant.GitHubRepo + "/releases/tags/" + constant.SingBoxLiteReleaseTag:
			digest := "sha256:" + liteSHA
			if omitDigest.Load() {
				digest = ""
			}
			assets := []releasepkg.Asset{{
				Name:               "sing-box-1.14.4-linux-arm64-lite.tar.gz",
				Size:               int64(len(liteArchive)),
				Digest:             digest,
				BrowserDownloadURL: srvURL + "/dl/sing-box-1.14.4-linux-arm64-lite.tar.gz",
			}}
			if !omitChecksums.Load() {
				assets = append(assets, releasepkg.Asset{
					Name:               "checksums.txt",
					Size:               int64(len(checksumsBody)),
					BrowserDownloadURL: srvURL + "/dl/checksums.txt",
				})
			}
			_ = json.NewEncoder(w).Encode(releasepkg.Info{
				TagName: constant.SingBoxLiteReleaseTag,
				Assets:  assets,
			})
		case "/dl/checksums.txt":
			_, _ = w.Write([]byte(checksumsBody))
		case "/dl/sing-box-1.14.4-linux-arm64-lite.tar.gz":
			if directCorrupt.Load() {
				corrupted := append([]byte(nil), liteArchive...)
				corrupted[len(corrupted)-1] ^= 0xff
				_, _ = w.Write(corrupted)
				return
			}
			_, _ = w.Write(liteArchive)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	srvURL = srv.URL

	rootDir := t.TempDir()
	fakeTmpDir := filepath.Join(rootDir, "tmp")
	overlayBinDir := filepath.Join(rootDir, "overlay", "usr", "bin")
	if err := os.MkdirAll(fakeTmpDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(overlayBinDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Pre-create a symlink /usr/bin/sing-box -> /tmp/old-ram-sing-box to prove atomic rename replaces
	// the symlink on /overlay without writing through into /tmp!
	ramBin := filepath.Join(fakeTmpDir, "old-ram-sing-box")
	if err := os.WriteFile(ramBin, []byte("ram-old"), 0755); err != nil {
		t.Fatal(err)
	}
	targetBin := filepath.Join(overlayBinDir, "sing-box")
	if err := os.Symlink(ramBin, targetBin); err != nil {
		t.Fatal(err)
	}

	isLite := true
	directFirst := false
	cfg := &config.Config{}
	cfg.GitHub.MirrorURL = srv.URL + "/mirror"

	makeSB := func() *singbox.SingBox {
		return singbox.NewWithDeps(cfg, singbox.InstallDeps{
			GOOS:              "linux",
			GOARCH:            "arm64",
			IsLiteBinary:      &isLite,
			ReadTotalRAMBytes: func() uint64 { return 491040 * 1024 },
			StatDiskSpace: func(string) (sysinfo.DiskSpace, error) {
				return sysinfo.DiskSpace{AvailBytes: 40*mib + 512*1024}, nil
			},
			Getenv:      func(string) string { return "" },
			TargetPath:  targetBin,
			TempDir:     fakeTmpDir,
			APIBase:     srv.URL,
			DLBase:      srv.URL,
			HTTPClient:  srv.Client(),
			DirectFirst: &directFirst,
		})
	}

	// Case 1: Mirror tampered + Digest omitted -> falls back to direct URL + verifies via checksums.txt!
	mirrorCorrupt.Store(true)
	omitDigest.Store(true)
	if err := makeSB().Install(); err != nil {
		t.Fatalf("Install with mirror fallback + checksums.txt failed: %v", err)
	}
	if mirrorHitMetadata.Load() {
		t.Fatal("security violation: metadata or checksums went through mirror")
	}

	// Verify targetBin is now a real regular file on /overlay (NOT a symlink), ramBin untouched, and zero new files in /tmp!
	fi, err := os.Lstat(targetBin)
	if err != nil {
		t.Fatalf("Lstat targetBin: %v", err)
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() {
		t.Fatalf("expected targetBin to be regular file after atomic replace, mode=%v", fi.Mode())
	}
	gotBody, err := os.ReadFile(targetBin)
	if err != nil || string(gotBody) != litePayload {
		t.Fatalf("installed payload = %q, want %q", string(gotBody), litePayload)
	}
	ramAfter, _ := os.ReadFile(ramBin)
	if string(ramAfter) != "ram-old" {
		t.Fatalf("atomic install wrote through symlink into /tmp! ramBin=%q", string(ramAfter))
	}
	tmpEntries, _ := os.ReadDir(fakeTmpDir)
	if len(tmpEntries) != 1 || tmpEntries[0].Name() != "old-ram-sing-box" {
		t.Fatalf("expected 0 new archive/temp files in /tmp, found %v", tmpEntries)
	}
	overlayEntries, _ := os.ReadDir(overlayBinDir)
	if len(overlayEntries) != 1 || overlayEntries[0].Name() != "sing-box" {
		t.Fatalf("expected zero leftover staging files in %s, found %v", overlayBinDir, overlayEntries)
	}

	// Case 2: Both mirror and direct tampered -> rejects installation and keeps existing binary intact!
	directCorrupt.Store(true)
	if err := makeSB().Install(); err == nil {
		t.Fatal("expected SHA256 verification failure when both mirror and direct are corrupted")
	}
	afterReject, _ := os.ReadFile(targetBin)
	if string(afterReject) != litePayload {
		t.Fatalf("corrupted stream overwrote existing healthy binary: %q", string(afterReject))
	}

	// Case 3: Neither Digest nor checksums.txt present -> refuses unverified sing-box-lite install!
	mirrorCorrupt.Store(false)
	directCorrupt.Store(false)
	omitDigest.Store(true)
	omitChecksums.Store(true)
	if err := makeSB().Install(); err == nil {
		t.Fatal("expected error when sing-box-lite release has neither official Digest nor checksums.txt")
	}
}

func TestSingBoxLite_404FallbackToUpstream_And_UpdateIdempotency(t *testing.T) {
	const mib uint64 = 1024 * 1024

	upstreamPayload := "upstream-full-1.14.5"
	upstreamArchive, upstreamSHA := buildSingBoxTarGz(t, "sing-box-1.14.5-linux-arm64/sing-box", upstreamPayload)

	lite1144Payload := "lite-1.14.4"
	lite1144Archive, lite1144SHA := buildSingBoxTarGz(t, "sing-box-1.14.4-linux-arm64-lite/sing-box", lite1144Payload)

	lite1145Payload := "lite-1.14.5"
	lite1145Archive, lite1145SHA := buildSingBoxTarGz(t, "sing-box-1.14.5-linux-arm64-lite/sing-box", lite1145Payload)

	var (
		srvURL           string
		liteChannelMode  atomic.Int32 // 0 = 404, 1 = v1.14.4, 2 = v1.14.5
		liteDownloadHits atomic.Int32
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/" + constant.GitHubRepo + "/releases/tags/" + constant.SingBoxLiteReleaseTag:
			switch liteChannelMode.Load() {
			case 0:
				http.NotFound(w, r)
			case 1:
				_ = json.NewEncoder(w).Encode(releasepkg.Info{
					TagName: constant.SingBoxLiteReleaseTag,
					Assets: []releasepkg.Asset{{
						Name:               "sing-box-1.14.4-linux-arm64-lite.tar.gz",
						Size:               int64(len(lite1144Archive)),
						Digest:             "sha256:" + lite1144SHA,
						BrowserDownloadURL: srvURL + "/dl/lite-1.14.4.tar.gz",
					}},
				})
			case 2:
				_ = json.NewEncoder(w).Encode(releasepkg.Info{
					TagName: constant.SingBoxLiteReleaseTag,
					Assets: []releasepkg.Asset{{
						Name:               "sing-box-1.14.5-linux-arm64-lite.tar.gz",
						Size:               int64(len(lite1145Archive)),
						Digest:             "sha256:" + lite1145SHA,
						BrowserDownloadURL: srvURL + "/dl/lite-1.14.5.tar.gz",
					}},
				})
			}
		case "/repos/SagerNet/sing-box/releases/latest":
			_ = json.NewEncoder(w).Encode(releasepkg.Info{
				TagName: "v1.14.5",
				Assets: []releasepkg.Asset{
					{Name: "sing-box-1.14.5-linux-arm64-glibc.tar.gz", Size: 999},
					{
						Name:               "sing-box-1.14.5-linux-arm64.tar.gz",
						Size:               int64(len(upstreamArchive)),
						Digest:             "sha256:" + upstreamSHA,
						BrowserDownloadURL: srvURL + "/dl/upstream-1.14.5.tar.gz",
					},
				},
			})
		case "/dl/upstream-1.14.5.tar.gz":
			_, _ = w.Write(upstreamArchive)
		case "/dl/lite-1.14.4.tar.gz":
			liteDownloadHits.Add(1)
			_, _ = w.Write(lite1144Archive)
		case "/dl/lite-1.14.5.tar.gz":
			liteDownloadHits.Add(1)
			_, _ = w.Write(lite1145Archive)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	srvURL = srv.URL

	root := t.TempDir()
	fakeTmp := filepath.Join(root, "tmp")
	_ = os.MkdirAll(fakeTmp, 0755)
	targetBin := filepath.Join(root, "usr", "bin", "sing-box")

	installedVer := "1.14.4"
	isLite := true
	directFirst := true

	sb := singbox.NewWithDeps(&config.Config{}, singbox.InstallDeps{
		GOOS:              "linux",
		GOARCH:            "arm64",
		IsLiteBinary:      &isLite,
		ReadTotalRAMBytes: func() uint64 { return 256 * mib },
		StatDiskSpace: func(string) (sysinfo.DiskSpace, error) {
			return sysinfo.DiskSpace{AvailBytes: 40 * mib}, nil
		},
		Getenv:           func(string) string { return "" },
		TargetPath:       targetBin,
		TempDir:          fakeTmp,
		CurrentVersionFn: func() (string, error) { return installedVer, nil },
		APIBase:          srv.URL,
		DLBase:           srv.URL,
		HTTPClient:       srv.Client(),
		DirectFirst:      &directFirst,
	})

	// 1. When singbox-lite-latest is 404 (not published yet), smoothly falls back to upstream SagerNet/sing-box!
	liteChannelMode.Store(0)
	if err := sb.Install(); err != nil {
		t.Fatalf("Install fallback on 404 failed: %v", err)
	}
	gotFallback, _ := os.ReadFile(targetBin)
	if string(gotFallback) != upstreamPayload {
		t.Fatalf("404 fallback installed %q, want %q", string(gotFallback), upstreamPayload)
	}

	// 2. When singbox-lite-latest is at 1.14.4 and installed version is 1.14.4 (even though upstream SagerNet is 1.14.5!),
	// sb.Update() compares against singbox-lite-latest (1.14.4) and skips download idempotently!
	liteChannelMode.Store(1)
	installedVer = "1.14.4"
	if err := sb.Update(); err != nil {
		t.Fatalf("Update when already at lite 1.14.4 failed: %v", err)
	}
	if hits := liteDownloadHits.Load(); hits != 0 {
		t.Fatalf("expected 0 downloads when installed=1.14.4 matches singbox-lite-latest=1.14.4, got %d", hits)
	}

	// 3. When singbox-lite-latest advances to 1.14.5, sb.Update() upgrades once, and a second Update() is a no-op!
	liteChannelMode.Store(2)
	if err := sb.Update(); err != nil {
		t.Fatalf("Update 1.14.4 -> 1.14.5 failed: %v", err)
	}
	gotUpgraded, _ := os.ReadFile(targetBin)
	if string(gotUpgraded) != lite1145Payload {
		t.Fatalf("upgraded payload = %q, want %q", string(gotUpgraded), lite1145Payload)
	}
	if hits := liteDownloadHits.Load(); hits != 1 {
		t.Fatalf("expected 1 lite download after upgrade, got %d", hits)
	}

	installedVer = "1.14.5"
	if err := sb.Update(); err != nil {
		t.Fatalf("idempotent second Update() failed: %v", err)
	}
	if hits := liteDownloadHits.Load(); hits != 1 {
		t.Fatalf("expected second Update() to skip download, hits=%d", hits)
	}

	// 4. Concurrent race check on pure policy & parser helpers
	var wg sync.WaitGroup
	for i := range 16 {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			_ = singbox.ShouldUseSingBoxLite("linux", "arm64", id%2 == 0, id%3 == 0, 40*mib, "")
			_, _ = singbox.ParseSingBoxLiteAssetVersion("sing-box-1.14.4-linux-arm64-lite.tar.gz")
			_ = singbox.SelectSingBoxLiteAsset([]releasepkg.Asset{{Name: "sing-box-1.14.4-linux-arm64-lite.tar.gz"}}, "arm64")
		}(i)
	}
	wg.Wait()
	_ = errors.New // keep import symmetry if needed
}
