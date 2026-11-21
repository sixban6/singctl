package tailscale

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
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

	"singctl/internal/config"
	releasepkg "singctl/internal/util/release"
)

const fakeCombinedBinaryScript = `#!/bin/sh
case "$(basename "$0")" in
  *tailscaled*)
    [ "$1" = "--version" ] || { echo "tailscaled requires --version, got $1" >&2; exit 1; }
    echo "%s"
    ;;
  *)
    [ "$1" = "version" ] || { echo "tailscale requires version, got $1" >&2; exit 1; }
    echo "%s"
    ;;
esac
`

type testTarEntry struct {
	Name     string
	Typeflag byte
	Body     []byte
	Linkname string
	Mode     int64
}

func buildTestTarGz(t *testing.T, entries []testTarEntry) (archive []byte, shaHex string) {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	for _, e := range entries {
		mode := e.Mode
		if mode == 0 {
			mode = 0755
		}
		hdr := &tar.Header{
			Name:     e.Name,
			Typeflag: e.Typeflag,
			Mode:     mode,
			Size:     int64(len(e.Body)),
			Linkname: e.Linkname,
		}
		if e.Typeflag == 0 {
			hdr.Typeflag = tar.TypeReg
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("write tar header %s: %v", e.Name, err)
		}
		if len(e.Body) > 0 && hdr.Typeflag == tar.TypeReg {
			if _, err := tw.Write(e.Body); err != nil {
				t.Fatalf("write tar body %s: %v", e.Name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar writer: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("close gzip writer: %v", err)
	}
	sum := sha256.Sum256(buf.Bytes())
	return buf.Bytes(), hex.EncodeToString(sum[:])
}

func TestStreamStageTailscaleArchive_CombinedSymlink_ZeroTmp(t *testing.T) {
	archive, sum := buildTestTarGz(t, []testTarEntry{
		{Name: "tailscale_1.104.7_arm64/", Typeflag: tar.TypeDir, Mode: 0755},
		{Name: "tailscale_1.104.7_arm64/tailscaled", Typeflag: tar.TypeReg, Body: []byte("combined-arm64-elf-payload")},
		{Name: "tailscale_1.104.7_arm64/tailscale", Typeflag: tar.TypeSymlink, Linkname: "tailscaled", Mode: 0777},
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(archive)
	}))
	defer srv.Close()

	isolatedTmp := t.TempDir()
	t.Setenv("TMPDIR", isolatedTmp)
	installDir := t.TempDir()

	client := &releasepkg.Client{
		HTTP:        srv.Client(),
		DirectFirst: true,
	}
	asset := releasepkg.Asset{
		Name:               "tailscale_1.104.7_arm64.tgz",
		BrowserDownloadURL: srv.URL + "/tailscale_1.104.7_arm64.tgz",
		Size:               int64(len(archive)),
		Digest:             "sha256:" + sum,
	}

	combined, shaOK, viaMirror, err := streamStageTailscaleArchive(t.Context(), client, asset, installDir)
	if err != nil {
		t.Fatalf("streamStageTailscaleArchive failed: %v", err)
	}
	if !combined || !shaOK || viaMirror {
		t.Fatalf("unexpected flags: combined=%v shaOK=%v viaMirror=%v", combined, shaOK, viaMirror)
	}

	gotTSD, err := os.ReadFile(filepath.Join(installDir, ".tailscaled.new"))
	if err != nil || string(gotTSD) != "combined-arm64-elf-payload" {
		t.Fatalf("unexpected .tailscaled.new content=%q err=%v", string(gotTSD), err)
	}
	if _, err := os.Stat(filepath.Join(installDir, ".tailscale.new")); !os.IsNotExist(err) {
		t.Fatalf("combined symlink layout must NOT write .tailscale.new, err=%v", err)
	}
	tmpEntries, err := os.ReadDir(isolatedTmp)
	if err != nil {
		t.Fatalf("read TMPDIR: %v", err)
	}
	if len(tmpEntries) != 0 {
		t.Fatalf("expected 0 files created in TMPDIR during streaming stage, got %d", len(tmpEntries))
	}
}

func TestStreamStageTailscaleArchive_DualBinary(t *testing.T) {
	archive, sum := buildTestTarGz(t, []testTarEntry{
		{Name: "tailscale_1.104.7_amd64/tailscaled", Typeflag: tar.TypeReg, Body: []byte("amd64-daemon-elf")},
		{Name: "tailscale_1.104.7_amd64/tailscale", Typeflag: tar.TypeReg, Body: []byte("amd64-cli-elf")},
		{Name: "tailscale_1.104.7_amd64/systemd/tailscaled.service", Typeflag: tar.TypeReg, Body: []byte("[Unit]")},
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(archive)
	}))
	defer srv.Close()

	installDir := t.TempDir()
	client := &releasepkg.Client{HTTP: srv.Client(), DirectFirst: true}
	asset := releasepkg.Asset{
		Name:               "tailscale_1.104.7_amd64.tgz",
		BrowserDownloadURL: srv.URL + "/tailscale_1.104.7_amd64.tgz",
		Size:               int64(len(archive)),
		Digest:             "sha256:" + sum,
	}

	combined, shaOK, _, err := streamStageTailscaleArchive(t.Context(), client, asset, installDir)
	if err != nil {
		t.Fatalf("streamStageTailscaleArchive (dual) failed: %v", err)
	}
	if combined {
		t.Fatalf("expected combined=false for dual-binary archive")
	}
	if !shaOK {
		t.Fatalf("expected shaOK=true")
	}
	gotTSD, err := os.ReadFile(filepath.Join(installDir, ".tailscaled.new"))
	if err != nil || string(gotTSD) != "amd64-daemon-elf" {
		t.Fatalf("unexpected .tailscaled.new: %q err=%v", string(gotTSD), err)
	}
	gotTS, err := os.ReadFile(filepath.Join(installDir, ".tailscale.new"))
	if err != nil || string(gotTS) != "amd64-cli-elf" {
		t.Fatalf("unexpected .tailscale.new: %q err=%v", string(gotTS), err)
	}
}

func TestStreamStageTailscaleArchive_SHA256Mismatch_RejectedAndFallback(t *testing.T) {
	goodArchive, goodSum := buildTestTarGz(t, []testTarEntry{
		{Name: "tailscale_1.104.7_arm64/tailscaled", Typeflag: tar.TypeReg, Body: []byte("clean-binary")},
		{Name: "tailscale_1.104.7_arm64/tailscale", Typeflag: tar.TypeSymlink, Linkname: "tailscaled"},
	})
	badArchive, _ := buildTestTarGz(t, []testTarEntry{
		{Name: "tailscale_1.104.7_arm64/tailscaled", Typeflag: tar.TypeReg, Body: []byte("evil-binary!")},
		{Name: "tailscale_1.104.7_arm64/tailscale", Typeflag: tar.TypeSymlink, Linkname: "tailscaled"},
	})

	// Test 1: Only tampered URL available -> must fail & leave 0 staged files.
	badSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(badArchive)
	}))
	defer badSrv.Close()

	installDir := t.TempDir()
	clientFail := &releasepkg.Client{HTTP: badSrv.Client(), DirectFirst: true}
	assetBad := releasepkg.Asset{
		Name:               "tailscale_1.104.7_arm64.tgz",
		BrowserDownloadURL: badSrv.URL + "/bad.tgz",
		Size:               int64(len(badArchive)),
		Digest:             "sha256:" + goodSum,
	}
	if _, _, _, err := streamStageTailscaleArchive(t.Context(), clientFail, assetBad, installDir); err == nil {
		t.Fatalf("expected sha256 mismatch error, got nil")
	}
	if _, err := os.Stat(filepath.Join(installDir, ".tailscaled.new")); !os.IsNotExist(err) {
		t.Fatalf("expected .tailscaled.new removed on sha256 mismatch")
	}

	// Test 2: Mirror serves tampered payload first, fallback direct URL serves clean payload -> must succeed via direct!
	mux := http.NewServeMux()
	mux.HandleFunc("/mirror/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(badArchive)
	})
	mux.HandleFunc("/direct/tailscale_1.104.7_arm64.tgz", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(goodArchive)
	})
	muxSrv := httptest.NewServer(mux)
	defer muxSrv.Close()

	clientMirrorFirst := &releasepkg.Client{
		HTTP:        muxSrv.Client(),
		Mirror:      muxSrv.URL + "/mirror",
		DirectFirst: false,
	}
	assetGood := releasepkg.Asset{
		Name:               "tailscale_1.104.7_arm64.tgz",
		BrowserDownloadURL: muxSrv.URL + "/direct/tailscale_1.104.7_arm64.tgz",
		Size:               int64(len(goodArchive)),
		Digest:             "sha256:" + goodSum,
	}
	combined, shaOK, viaMirror, err := streamStageTailscaleArchive(t.Context(), clientMirrorFirst, assetGood, installDir)
	if err != nil {
		t.Fatalf("expected fallback to clean direct channel after tampered mirror, got err: %v", err)
	}
	if !combined || !shaOK || viaMirror {
		t.Fatalf("unexpected fallback result: combined=%v shaOK=%v viaMirror=%v", combined, shaOK, viaMirror)
	}
	got, _ := os.ReadFile(filepath.Join(installDir, ".tailscaled.new"))
	if string(got) != "clean-binary" {
		t.Fatalf("expected clean-binary from fallback, got %q", string(got))
	}
}

func TestStreamStageTailscaleArchive_SizeMismatch_RejectedAndCleaned(t *testing.T) {
	archive, sum := buildTestTarGz(t, []testTarEntry{
		{Name: "tailscale_1.104.7_arm64/tailscaled", Typeflag: tar.TypeReg, Body: []byte("valid-payload")},
		{Name: "tailscale_1.104.7_arm64/tailscale", Typeflag: tar.TypeSymlink, Linkname: "tailscaled"},
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(archive)
	}))
	defer srv.Close()

	installDir := t.TempDir()
	client := &releasepkg.Client{HTTP: srv.Client(), DirectFirst: true}
	asset := releasepkg.Asset{
		Name:               "tailscale_1.104.7_arm64.tgz",
		BrowserDownloadURL: srv.URL + "/pkg.tgz",
		Size:               int64(len(archive) + 512),
		Digest:             "sha256:" + sum,
	}

	if _, _, _, err := streamStageTailscaleArchive(t.Context(), client, asset, installDir); err == nil || !strings.Contains(err.Error(), "size mismatch") {
		t.Fatalf("expected size mismatch error, got: %v", err)
	}
	if _, err := os.Stat(filepath.Join(installDir, ".tailscaled.new")); !os.IsNotExist(err) {
		t.Fatalf("expected .tailscaled.new removed on size mismatch")
	}
}

func TestPreflightUpgrade_FlashBlock_UpToDate_Force_Platform_And_InitSystems(t *testing.T) {
	// Mock GitHub Releases API server（主通道为本仓库 tailscale-latest，双架构均为精简合体包）
	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/sixban6/singctl/releases/tags/tailscale-latest" {
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

	ts := New("", &config.TailscaleConfig{})
	ts.OpenWrtCheck = func() bool { return true }
	relClient := &releasepkg.Client{
		APIBase:     apiSrv.URL,
		HTTP:        apiSrv.Client(),
		DirectFirst: true,
	}

	// 1. Non-Linux platform -> Supported=false
	preNonLinux, err := ts.PreflightUpgrade(t.Context(), UpgradeOptions{
		LinuxCheck:    func() bool { return false },
		ReleaseClient: relClient,
	})
	if err != nil {
		t.Fatalf("PreflightUpgrade non-Linux unexpected error: %v", err)
	}
	if preNonLinux.Supported || preNonLinux.CanProceed || preNonLinux.CanForceProceed {
		t.Fatalf("expected Supported=false on non-Linux, got %+v", preNonLinux)
	}

	// Setup fake installed binaries + init script
	dir := t.TempDir()
	installDir := filepath.Join(dir, "sbin")
	if err := os.MkdirAll(installDir, 0755); err != nil {
		t.Fatal(err)
	}
	initScript := filepath.Join(dir, "init-tailscale")
	if err := os.WriteFile(initScript, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(installDir, "tailscaled"), []byte(fmt.Sprintf(fakeCombinedBinaryScript, "1.104.7", "1.104.7")), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("tailscaled", filepath.Join(installDir, "tailscale")); err != nil {
		t.Fatal(err)
	}

	paths := UpgradePaths{
		InstallDir: installDir,
		InitScript: initScript,
		StateFile:  filepath.Join(dir, "state"),
		LogFile:    filepath.Join(dir, "log"),
		LockFile:   filepath.Join(dir, "lock"),
		SocketPath: filepath.Join(dir, "missing.sock"),
	}

	// 2. Low Flash free space -> Blocked! Neither normal nor force can proceed.
	preLowFlash, err := ts.PreflightUpgrade(t.Context(), UpgradeOptions{
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
	if !preLowFlash.CombinedMinimal || preLowFlash.InitSystem != "procd" {
		t.Fatalf("expected CombinedMinimal=true and procd, got %+v", preLowFlash)
	}

	// 3. Sufficient Flash & already up-to-date (1.104.7 == 1.104.7) -> CanProceed=false, CanForceProceed=true!
	preUpToDate, err := ts.PreflightUpgrade(t.Context(), UpgradeOptions{
		Paths:         paths,
		ArchOverride:  "arm64",
		LinuxCheck:    func() bool { return true },
		StatfsFn:      func(string) (uint64, error) { return 100 << 20, nil },
		MemInfoFn:     func() (uint64, uint64) { return 128 << 20, 0 },
		ReleaseClient: relClient,
	})
	if err != nil {
		t.Fatalf("PreflightUpgrade up-to-date error: %v", err)
	}
	if !preUpToDate.UpToDate || preUpToDate.CanProceed || !preUpToDate.CanForceProceed {
		t.Fatalf("expected UpToDate=true CanProceed=false CanForceProceed=true, got %+v", preUpToDate)
	}

	// 4. Older installed version + Linux systemd (amd64) -> CanProceed=true, InitSystem="systemd", CombinedMinimal=true, RequiredFreeBytes < 40 MiB
	if err := os.WriteFile(filepath.Join(installDir, "tailscaled"), []byte(fmt.Sprintf(fakeCombinedBinaryScript, "1.94.2", "1.94.2")), 0755); err != nil {
		t.Fatal(err)
	}
	tsSystemd := New("", &config.TailscaleConfig{})
	tsSystemd.OpenWrtCheck = func() bool { return false }
	preSystemd, err := tsSystemd.PreflightUpgrade(t.Context(), UpgradeOptions{
		Paths:              paths,
		ArchOverride:       "amd64",
		LinuxCheck:         func() bool { return true },
		InitSystemOverride: "systemd",
		StatfsFn:           func(string) (uint64, error) { return 512 << 20, nil },
		MemInfoFn:          func() (uint64, uint64) { return 16 << 20, 0 },
		ReleaseClient:      relClient,
	})
	if err != nil {
		t.Fatalf("PreflightUpgrade systemd error: %v", err)
	}
	if preSystemd.InitSystem != "systemd" || !preSystemd.CombinedMinimal || preSystemd.UpToDate || !preSystemd.CanProceed {
		t.Fatalf("unexpected systemd preflight (expected CombinedMinimal=true on unified amd64 build): %+v", preSystemd)
	}
	if preSystemd.RequiredFreeBytes >= 40<<20 {
		t.Fatalf("expected minimal amd64 RequiredFreeBytes < 40 MiB, got %d", preSystemd.RequiredFreeBytes)
	}
	if len(preSystemd.Warnings) == 0 {
		t.Fatalf("expected low memory soft warning when memAvail < 24 MiB, got 0 warnings")
	}
}

func TestUpgradeStateReadWrite_0600Permissions_AndLogTail(t *testing.T) {
	dir := t.TempDir()
	paths := UpgradePaths{
		StateFile: filepath.Join(dir, "upgrade.state"),
		LogFile:   filepath.Join(dir, "upgrade.log"),
	}

	// Missing state file returns clean idle state
	idle, err := ReadUpgradeState(paths)
	if err != nil {
		t.Fatalf("ReadUpgradeState missing: %v", err)
	}
	if idle.Phase != UpgradePhaseIdle {
		t.Fatalf("expected idle phase, got %q", idle.Phase)
	}

	st := &UpgradeState{
		Phase:       UpgradePhaseRolledBack,
		FromVersion: "1.94.2",
		ToVersion:   "1.104.8",
		Arch:        "arm64",
		Combined:    true,
		StartedAt:   time.Now().UTC().Format(time.RFC3339),
		Error:       "health gate timed out",
		RolledBack:  true,
	}
	if err := WriteUpgradeState(paths, st); err != nil {
		t.Fatalf("WriteUpgradeState: %v", err)
	}

	info, err := os.Stat(paths.StateFile)
	if err != nil {
		t.Fatalf("stat state: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 permission on state file, got %o", info.Mode().Perm())
	}

	// Write oversized log > 8KB and check truncation keeps tail
	bigLog := strings.Repeat("old-log-line\n", 1000) + "FINAL_ROLLBACK_REASON\n"
	if err := os.WriteFile(paths.LogFile, []byte(bigLog), 0600); err != nil {
		t.Fatal(err)
	}

	got, err := ReadUpgradeState(paths)
	if err != nil {
		t.Fatalf("ReadUpgradeState: %v", err)
	}
	if got.Phase != UpgradePhaseRolledBack || !got.RolledBack || got.ToVersion != "1.104.8" {
		t.Fatalf("unexpected decoded state: %+v", got)
	}
	if len(got.LogTail) > 8192 || !strings.Contains(got.LogTail, "FINAL_ROLLBACK_REASON") {
		t.Fatalf("expected LogTail truncated <= 8192 containing tail marker, len=%d", len(got.LogTail))
	}
}

func TestSafeUpdate_DryRun_DoesNotModifyBinaries(t *testing.T) {
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

	dir := t.TempDir()
	installDir := filepath.Join(dir, "sbin")
	_ = os.MkdirAll(installDir, 0755)
	_ = os.WriteFile(filepath.Join(installDir, "tailscaled"), []byte(fmt.Sprintf(fakeCombinedBinaryScript, "1.94.2", "1.94.2")), 0755)
	_ = os.Symlink("tailscaled", filepath.Join(installDir, "tailscale"))
	initScript := filepath.Join(dir, "init-tailscale")
	_ = os.WriteFile(initScript, []byte("#!/bin/sh\nexit 0\n"), 0755)

	ts := New("", &config.TailscaleConfig{})
	ts.OpenWrtCheck = func() bool { return true }
	err := ts.SafeUpdate(t.Context(), UpgradeOptions{
		DryRun:       true,
		ArchOverride: "arm64",
		LinuxCheck:   func() bool { return true },
		StatfsFn:     func(string) (uint64, error) { return 100 << 20, nil },
		MemInfoFn:    func() (uint64, uint64) { return 64 << 20, 0 },
		Paths: UpgradePaths{
			InstallDir: installDir,
			InitScript: initScript,
			StateFile:  filepath.Join(dir, "state"),
			LogFile:    filepath.Join(dir, "log"),
			LockFile:   filepath.Join(dir, "lock"),
			SocketPath: filepath.Join(dir, "sock"),
		},
		ReleaseClient: &releasepkg.Client{APIBase: apiSrv.URL, HTTP: apiSrv.Client(), DirectFirst: true},
	})
	if err != nil {
		t.Fatalf("SafeUpdate DryRun failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(installDir, ".tailscaled.new")); !os.IsNotExist(err) {
		t.Fatalf("DryRun must not stage .tailscaled.new")
	}
}

func TestVerifyStagedBinaries_And_SelectArchBoundaries(t *testing.T) {
	if !selectTailscaleAssetForArch("tailscale_1.104.7_arm64.tgz", "arm64") {
		t.Fatalf("expected arm64 asset match")
	}
	if selectTailscaleAssetForArch("tailscale_1.104.7_arm64.tgz", "arm") {
		t.Fatalf("arm must NOT match arm64 archive")
	}
	if !selectTailscaleAssetForArch("tailscale_1.104.7_arm.tgz", "arm") {
		t.Fatalf("expected exact arm asset match")
	}

	dir := t.TempDir()
	badTSD := filepath.Join(dir, stagedTailscaledName)
	badTS := filepath.Join(dir, stagedTailscaleName)
	if err := os.WriteFile(badTSD, []byte("NOT_A_VALID_ELF_BINARY"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(badTS, []byte("NOT_A_VALID_ELF_CLI"), 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyStagedBinaries(t.Context(), dir, false); err == nil {
		t.Fatalf("expected error on corrupted staged binary")
	}
	if _, err := os.Stat(badTSD); !os.IsNotExist(err) {
		t.Fatalf("expected staged .tailscaled.new cleaned up after failed verification")
	}
	if _, err := os.Stat(badTS); !os.IsNotExist(err) {
		t.Fatalf("expected staged .tailscale.new cleaned up after failed verification")
	}

	goodTSD := filepath.Join(dir, stagedTailscaledName)
	if err := os.WriteFile(goodTSD, []byte(fmt.Sprintf(fakeCombinedBinaryScript, "1.104.7", "1.104.7")), 0755); err != nil {
		t.Fatal(err)
	}
	ver, err := verifyStagedBinaries(t.Context(), dir, true)
	if err != nil {
		t.Fatalf("expected combined valid binary to pass: %v", err)
	}
	if ver != "1.104.7" {
		t.Fatalf("expected parsed version 1.104.7, got %q", ver)
	}
}

func TestFetchTailscaleRelease_PrimaryAndLegacyFallback(t *testing.T) {
	amd64Sum := strings.Repeat("c", 64)
	legacySum := strings.Repeat("d", 64)

	tests := []struct {
		name               string
		primaryStatus      int
		legacyStatus       int
		wantLegacyCalled   bool
		wantBlocked        bool
		wantCombined       bool
		wantDigest         string
		wantRequiredAtLeast int64
	}{
		{
			name:               "主通道命中并从本仓库checksums回填SHA256",
			primaryStatus:      http.StatusOK,
			legacyStatus:       http.StatusOK,
			wantLegacyCalled:   false,
			wantBlocked:        false,
			wantCombined:       true,
			wantDigest:         "sha256:" + amd64Sum,
			wantRequiredAtLeast: 16 << 20,
		},
		{
			name:               "主通道404时平滑回退旧仓库且40MiB标准amd64包识别为非精简版",
			primaryStatus:      http.StatusNotFound,
			legacyStatus:       http.StatusOK,
			wantLegacyCalled:   true,
			wantBlocked:        false,
			wantCombined:       false,
			wantDigest:         "sha256:" + legacySum,
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
				case "/repos/sixban6/singctl/releases/tags/tailscale-latest":
					if tc.primaryStatus != http.StatusOK {
						http.Error(w, "primary status", tc.primaryStatus)
						return
					}
					_ = json.NewEncoder(w).Encode(releasepkg.Info{
						TagName: "tailscale-latest",
						Assets: []releasepkg.Asset{
							{
								Name: "tailscale_1.104.7_amd64.tgz",
								Size: 6500 * 1024,
							},
							{
								ID:   101,
								Name: "checksums.txt",
							},
						},
					})
				case "/repos/sixban6/singctl/releases/assets/101":
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
							{
								Name: "tailscale_1.104.7_amd64.tgz",
								Size: 40 * 1024 * 1024,
							},
							{
								ID:   202,
								Name: "checksums.txt",
							},
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
			installDir := filepath.Join(dir, "sbin")
			if err := os.MkdirAll(installDir, 0755); err != nil {
				t.Fatal(err)
			}
			initScript := filepath.Join(dir, "init-tailscale")
			if err := os.WriteFile(initScript, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(installDir, "tailscaled"), []byte(fmt.Sprintf(fakeCombinedBinaryScript, "1.94.2", "1.94.2")), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("tailscaled", filepath.Join(installDir, "tailscale")); err != nil {
				t.Fatal(err)
			}

			ts := New("", &config.TailscaleConfig{})
			ts.OpenWrtCheck = func() bool { return false }
			client := &releasepkg.Client{
				APIBase:     srv.URL,
				DLBase:      srv.URL,
				HTTP:        srv.Client(),
				DirectFirst: true,
			}

			pre, err := ts.PreflightUpgrade(t.Context(), UpgradeOptions{
				Paths: UpgradePaths{
					InstallDir: installDir,
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
				t.Fatalf("PreflightUpgrade returned unexpected error: %v", err)
			}

			mu.Lock()
			gotLegacy := legacyCalled
			mu.Unlock()
			if gotLegacy != tc.wantLegacyCalled {
				t.Fatalf("legacyCalled = %v, want %v", gotLegacy, tc.wantLegacyCalled)
			}

			if tc.wantBlocked {
				if len(pre.BlockedReasons) == 0 || pre.CanProceed {
					t.Fatalf("expected BlockedReasons non-empty and CanProceed=false, got %+v", pre)
				}
				return
			}

			if pre.CombinedMinimal != tc.wantCombined {
				t.Fatalf("CombinedMinimal = %v, want %v", pre.CombinedMinimal, tc.wantCombined)
			}
			if !pre.HasOfficialDigest || pre.selectedAsset == nil || pre.selectedAsset.Digest != tc.wantDigest {
				t.Fatalf("expected checksum fallback digest %q, got asset=%+v", tc.wantDigest, pre.selectedAsset)
			}
			if pre.RequiredFreeBytes < tc.wantRequiredAtLeast {
				t.Fatalf("RequiredFreeBytes = %d, want >= %d", pre.RequiredFreeBytes, tc.wantRequiredAtLeast)
			}
		})
	}

	// 并发竞态验证：多 goroutine 并行执行 PreflightUpgrade 不应触发数据竞争
	t.Run("并发预检零数据竞争", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/repos/sixban6/singctl/releases/tags/tailscale-latest" {
				http.NotFound(w, r)
				return
			}
			_ = json.NewEncoder(w).Encode(releasepkg.Info{
				TagName: "tailscale-latest",
				Assets: []releasepkg.Asset{
					{
						Name:   "tailscale_1.104.7_amd64.tgz",
						Size:   6500 * 1024,
						Digest: "sha256:" + amd64Sum,
					},
				},
			})
		}))
		defer srv.Close()

		dir := t.TempDir()
		installDir := filepath.Join(dir, "sbin")
		_ = os.MkdirAll(installDir, 0755)
		_ = os.WriteFile(filepath.Join(installDir, "tailscaled"), []byte(fmt.Sprintf(fakeCombinedBinaryScript, "1.94.2", "1.94.2")), 0755)
		_ = os.Symlink("tailscaled", filepath.Join(installDir, "tailscale"))

		ts := New("", &config.TailscaleConfig{})
		ts.OpenWrtCheck = func() bool { return false }
		client := &releasepkg.Client{APIBase: srv.URL, DLBase: srv.URL, HTTP: srv.Client(), DirectFirst: true}

		var wg sync.WaitGroup
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				pre, err := ts.PreflightUpgrade(t.Context(), UpgradeOptions{
					Paths: UpgradePaths{
						InstallDir: installDir,
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
			}()
		}
		wg.Wait()
	})
}
