// 文件职责：覆盖 Tailscale 归档流式解包零临时空间暂存、SHA256 镜像防篡改回退与可执行预检测试。
package tailscale_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	releasepkg "singctl/internal/common/release"
	"singctl/internal/tailscale"
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

	client := &releasepkg.Client{HTTP: srv.Client(), DirectFirst: true}
	asset := releasepkg.Asset{
		Name:               "tailscale_1.104.7_arm64.tgz",
		BrowserDownloadURL: srv.URL + "/tailscale_1.104.7_arm64.tgz",
		Size:               int64(len(archive)),
		Digest:             "sha256:" + sum,
	}

	combined, shaOK, viaMirror, err := tailscale.StreamStageTailscaleArchive(t.Context(), client, asset, installDir)
	if err != nil {
		t.Fatalf("StreamStageTailscaleArchive failed: %v", err)
	}
	if !combined || !shaOK || viaMirror {
		t.Fatalf("unexpected flags: combined=%v shaOK=%v viaMirror=%v", combined, shaOK, viaMirror)
	}

	gotTSD, err := os.ReadFile(filepath.Join(installDir, tailscale.StagedTailscaledName))
	if err != nil || string(gotTSD) != "combined-arm64-elf-payload" {
		t.Fatalf("unexpected .tailscaled.new content=%q err=%v", string(gotTSD), err)
	}
	if _, err := os.Stat(filepath.Join(installDir, tailscale.StagedTailscaleName)); !os.IsNotExist(err) {
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

func TestStreamStageTailscaleArchive_DualBinary_TamperFallback_And_SizeMismatch(t *testing.T) {
	dualArchive, dualSum := buildTestTarGz(t, []testTarEntry{
		{Name: "tailscale_1.104.7_amd64/tailscaled", Typeflag: tar.TypeReg, Body: []byte("amd64-daemon-elf")},
		{Name: "tailscale_1.104.7_amd64/tailscale", Typeflag: tar.TypeReg, Body: []byte("amd64-cli-elf")},
		{Name: "tailscale_1.104.7_amd64/systemd/tailscaled.service", Typeflag: tar.TypeReg, Body: []byte("[Unit]")},
	})
	dualSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(dualArchive)
	}))
	defer dualSrv.Close()

	dualDir := t.TempDir()
	combined, shaOK, _, err := tailscale.StreamStageTailscaleArchive(
		t.Context(),
		&releasepkg.Client{HTTP: dualSrv.Client(), DirectFirst: true},
		releasepkg.Asset{
			Name:               "tailscale_1.104.7_amd64.tgz",
			BrowserDownloadURL: dualSrv.URL + "/tailscale_1.104.7_amd64.tgz",
			Size:               int64(len(dualArchive)),
			Digest:             "sha256:" + dualSum,
		},
		dualDir,
	)
	if err != nil || combined || !shaOK {
		t.Fatalf("dual binary stage failed: combined=%v shaOK=%v err=%v", combined, shaOK, err)
	}

	goodArchive, goodSum := buildTestTarGz(t, []testTarEntry{
		{Name: "tailscale_1.104.7_arm64/tailscaled", Typeflag: tar.TypeReg, Body: []byte("clean-binary")},
		{Name: "tailscale_1.104.7_arm64/tailscale", Typeflag: tar.TypeSymlink, Linkname: "tailscaled"},
	})
	badArchive, _ := buildTestTarGz(t, []testTarEntry{
		{Name: "tailscale_1.104.7_arm64/tailscaled", Typeflag: tar.TypeReg, Body: []byte("evil-binary!")},
		{Name: "tailscale_1.104.7_arm64/tailscale", Typeflag: tar.TypeSymlink, Linkname: "tailscaled"},
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/mirror/", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(badArchive) })
	mux.HandleFunc("/direct/pkg.tgz", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(goodArchive) })
	muxSrv := httptest.NewServer(mux)
	defer muxSrv.Close()

	fbDir := t.TempDir()
	combFB, shaFB, viaMir, err := tailscale.StreamStageTailscaleArchive(
		t.Context(),
		&releasepkg.Client{HTTP: muxSrv.Client(), Mirror: muxSrv.URL + "/mirror", DirectFirst: false},
		releasepkg.Asset{
			Name:               "tailscale_1.104.7_arm64.tgz",
			BrowserDownloadURL: muxSrv.URL + "/direct/pkg.tgz",
			Size:               int64(len(goodArchive)),
			Digest:             "sha256:" + goodSum,
		},
		fbDir,
	)
	if err != nil || !combFB || !shaFB || viaMir {
		t.Fatalf("expected clean fallback after tampered mirror: comb=%v sha=%v mir=%v err=%v", combFB, shaFB, viaMir, err)
	}

	sizeDir := t.TempDir()
	if _, _, _, err := tailscale.StreamStageTailscaleArchive(
		t.Context(),
		&releasepkg.Client{HTTP: muxSrv.Client(), DirectFirst: true},
		releasepkg.Asset{
			Name:               "tailscale_1.104.7_arm64.tgz",
			BrowserDownloadURL: muxSrv.URL + "/direct/pkg.tgz",
			Size:               int64(len(goodArchive) + 512),
			Digest:             "sha256:" + goodSum,
		},
		sizeDir,
	); err == nil || !strings.Contains(err.Error(), "size mismatch") {
		t.Fatalf("expected size mismatch error, got %v", err)
	}
}

func TestVerifyStagedBinaries_And_SelectArchBoundaries(t *testing.T) {
	if !tailscale.SelectTailscaleAssetForArch("tailscale_1.104.7_arm64.tgz", "arm64") ||
		tailscale.SelectTailscaleAssetForArch("tailscale_1.104.7_arm64.tgz", "arm") ||
		!tailscale.SelectTailscaleAssetForArch("tailscale_1.104.7_arm.tgz", "arm") {
		t.Fatal("unexpected SelectTailscaleAssetForArch boundary matching")
	}

	dir := t.TempDir()
	badTSD := filepath.Join(dir, tailscale.StagedTailscaledName)
	badTS := filepath.Join(dir, tailscale.StagedTailscaleName)
	_ = os.WriteFile(badTSD, []byte("NOT_A_VALID_ELF_BINARY"), 0755)
	_ = os.WriteFile(badTS, []byte("NOT_A_VALID_ELF_CLI"), 0755)
	if _, err := tailscale.VerifyStagedBinaries(t.Context(), dir, false); err == nil {
		t.Fatal("expected error on corrupted staged binary")
	}
	if _, err := os.Stat(badTSD); !os.IsNotExist(err) {
		t.Fatal("expected staged .tailscaled.new cleaned up after failed verification")
	}

	goodTSD := filepath.Join(dir, tailscale.StagedTailscaledName)
	_ = os.WriteFile(goodTSD, []byte(fmt.Sprintf(fakeCombinedBinaryScript, "1.104.7", "1.104.7")), 0755)
	ver, err := tailscale.VerifyStagedBinaries(t.Context(), dir, true)
	if err != nil || ver != "1.104.7" {
		t.Fatalf("VerifyStagedBinaries = (%q, %v), want (1.104.7, nil)", ver, err)
	}
}
