package release

import (
	"archive/tar"
	"archive/zip"
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
	"testing"
)

func makeTarGz(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	for name, content := range files {
		hdr := &tar.Header{Name: name, Mode: 0o755, Size: int64(len(content))}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func makeZip(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

type fixture struct {
	srv         *httptest.Server
	client      *Client
	archiveName string
	archiveHash string
	archiveSize int
	// directBroken=true 时直连下载路径返回 403
	directBroken bool
	// tamperMirror=true 时镜像返回被篡改的包
	tamperMirror bool
}

func (f *fixture) setMirror(m string) { f.client.Mirror = m }

// newFixture 起一个同时扮演 api.github.com / github.com / mirror 的测试服务器。
func newFixture(t *testing.T, tamperMirror, directBroken bool) *fixture {
	t.Helper()

	archiveBytes := makeTarGz(t, map[string]string{
		"pkg/singctl": "#!/bin/sh\necho fake-singctl\n",
	})
	archiveName := "singctl-test-os-arch.tar.gz"
	checksums := fmt.Sprintf("%s  %s\n%s  other-asset.zip\n",
		sha256Hex(archiveBytes), archiveName, sha256Hex([]byte("other")))

	fx := &fixture{
		archiveName:  archiveName,
		archiveHash:  sha256Hex(archiveBytes),
		archiveSize:  len(archiveBytes),
		directBroken: directBroken,
		tamperMirror: tamperMirror,
	}

	const archiveAssetID = 42
	const checksumAssetID = 43

	// srv 启动后才能知道绝对地址，闭包里引用这个变量
	var baseURL string

	mux := http.NewServeMux()

	// ---- api.github.com ----
	mux.HandleFunc("/repos/sixban6/singctl/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"tag_name": "v9.9.9",
			"assets": []map[string]any{
				{
					"name":                 archiveName,
					"id":                   archiveAssetID,
					"size":                 len(archiveBytes),
					"browser_download_url": baseURL + "/dl/" + archiveName,
				},
				{
					"name":                 "checksums.txt",
					"id":                   checksumAssetID,
					"size":                 len(checksums),
					"browser_download_url": baseURL + "/dl/checksums.txt",
				},
			},
		})
	})
	mux.HandleFunc("/repos/sixban6/singctl/releases/assets/", func(w http.ResponseWriter, r *http.Request) {
		// 模拟 GitHub 行为：仅 octet-stream Accept 返回真实内容
		if r.Header.Get("Accept") != "application/octet-stream" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if strings.HasSuffix(r.URL.Path, fmt.Sprint(checksumAssetID)) {
			_, _ = w.Write([]byte(checksums))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})

	// ---- github.com 直连下载 ----
	mux.HandleFunc("/dl/"+archiveName, func(w http.ResponseWriter, r *http.Request) {
		if directBroken {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_, _ = w.Write(archiveBytes)
	})
	mux.HandleFunc("/dl/checksums.txt", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(checksums))
	})

	// ---- 镜像（前缀代理 /mirror/<full-url>）----
	mux.HandleFunc("/mirror/", func(w http.ResponseWriter, r *http.Request) {
		if tamperMirror {
			// 被劫持的镜像：返回恶意内容（大小与官方元数据不一致）
			_, _ = w.Write([]byte("MALICIOUS PAYLOAD WITH DIFFERENT SIZE ................"))
			return
		}
		rest := strings.TrimPrefix(r.URL.Path, "/mirror/")
		if strings.HasSuffix(rest, archiveName) {
			_, _ = w.Write(archiveBytes)
			return
		}
		if strings.HasSuffix(rest, "checksums.txt") {
			_, _ = w.Write([]byte(checksums))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	baseURL = srv.URL

	fx.srv = srv
	fx.client = &Client{
		APIBase: srv.URL,
		DLBase:  srv.URL,
		HTTP:    srv.Client(),
	}
	return fx
}

func (f *fixture) findAsset(t *testing.T) *Asset {
	t.Helper()
	info, err := f.client.FetchLatest(t.Context(), "sixban6/singctl")
	if err != nil {
		t.Fatal(err)
	}
	if info.TagName != "v9.9.9" {
		t.Fatalf("unexpected tag: %s", info.TagName)
	}
	for i := range info.Assets {
		if info.Assets[i].Name == f.archiveName {
			a := info.Assets[i]
			return &a
		}
	}
	t.Fatal("archive asset not found")
	return nil
}

func TestParseChecksums(t *testing.T) {
	data := []byte("# comment\nabc123  file-a.tar.gz\n\nDEF456\t\tfile b.zip\n*fed789  file-c.tgz\n")
	sums := ParseChecksums(data)
	if got := sums["file-a.tar.gz"]; got != "abc123" {
		t.Errorf("file-a: got %q", got)
	}
	if got := sums["file b.zip"]; got != "def456" {
		t.Errorf("filename with space: got %q", got)
	}
	if got := sums["file-c.tgz"]; got != "fed789" {
		t.Errorf("binary-mode * prefix: got %q", got)
	}
	if len(sums) != 3 {
		t.Errorf("expected 3 entries, got %d", len(sums))
	}
}

func TestVerifySHA256(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	content := []byte("hello singctl")
	if err := os.WriteFile(p, content, 0644); err != nil {
		t.Fatal(err)
	}
	if err := VerifySHA256(p, sha256Hex(content)); err != nil {
		t.Errorf("valid hash should pass: %v", err)
	}
	if err := VerifySHA256(p, sha256Hex([]byte("tampered"))); err == nil {
		t.Error("mismatched hash should fail")
	}
}

func TestExtractTarGz(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "a.tar.gz")
	if err := os.WriteFile(archive, makeTarGz(t, map[string]string{
		"pkg/singctl": "bin",
		"pkg/README":  "doc",
	}), 0644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out")
	if err := Extract(archive, out); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"pkg/singctl": "bin", "pkg/README": "doc"} {
		got, err := os.ReadFile(filepath.Join(out, filepath.FromSlash(name)))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if string(got) != want {
			t.Errorf("%s: got %q want %q", name, got, want)
		}
	}
}

func TestExtractZip(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "a.zip")
	if err := os.WriteFile(archive, makeZip(t, map[string]string{"z/singctl.exe": "winbin"}), 0644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out")
	if err := Extract(archive, out); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(out, "z", "singctl.exe"))
	if err != nil || string(got) != "winbin" {
		t.Errorf("zip extract: %q %v", got, err)
	}
}

func TestExtractRejectsPathTraversal(t *testing.T) {
	dir := t.TempDir()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	_ = tw.WriteHeader(&tar.Header{Name: "../../evil", Mode: 0o644, Size: 5})
	_, _ = tw.Write([]byte("evil\n"))
	_ = tw.Close()
	archive := filepath.Join(dir, "evil.tar")
	if err := os.WriteFile(archive, buf.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}
	if err := Extract(archive, filepath.Join(dir, "out")); err == nil {
		t.Fatal("expected path traversal to be rejected")
	}
	if _, err := os.Stat(filepath.Join(dir, "evil")); !os.IsNotExist(err) {
		t.Fatal("file escaped destination dir")
	}
}

// 端到端：直连元数据 → 直连下载 → API 资产端点取 checksums → 校验通过
func TestEndToEndDirectDownloadAndVerify(t *testing.T) {
	fx := newFixture(t, false, false)
	asset := fx.findAsset(t)

	path, viaMirror, err := fx.client.Download(t.Context(), *asset, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if viaMirror {
		t.Error("expected direct download when no mirror configured")
	}
	if err := VerifySHA256(path, fx.archiveHash); err != nil {
		t.Fatalf("verify should pass: %v", err)
	}

	info, err := fx.client.FetchLatest(t.Context(), "sixban6/singctl")
	if err != nil {
		t.Fatal(err)
	}
	sums, err := fx.client.FetchChecksums(t.Context(), "sixban6/singctl", info.TagName, nil, info)
	if err != nil {
		t.Fatal(err)
	}
	if sums[fx.archiveName] != fx.archiveHash {
		t.Errorf("checksums map wrong: %v", sums)
	}
	if err := VerifySHA256(path, sums[fx.archiveName]); err != nil {
		t.Errorf("verify with fetched checksums should pass: %v", err)
	}
}

// 镜像投毒（篡改内容/大小）时：镜像优先策略应自动回退直连并拿到正确的包
func TestTamperedMirrorFallsBackToDirect(t *testing.T) {
	fx := newFixture(t, true, false)
	fx.setMirror(fx.srv.URL + "/mirror")
	fx.client.DirectFirst = false // 镜像优先
	asset := fx.findAsset(t)

	path, viaMirror, err := fx.client.Download(t.Context(), *asset, t.TempDir())
	if err != nil {
		t.Fatalf("expected fallback to direct: %v", err)
	}
	if viaMirror {
		t.Error("tampered mirror result must be rejected")
	}
	if err := VerifySHA256(path, fx.archiveHash); err != nil {
		t.Errorf("fallback content should verify: %v", err)
	}
}

// 镜像投毒且直连不可用时：必须报错，绝不能安装被篡改的包
func TestTamperedMirrorWithNoDirectMustFail(t *testing.T) {
	fx := newFixture(t, true, true)
	fx.setMirror(fx.srv.URL + "/mirror")
	fx.client.DirectFirst = false
	asset := fx.findAsset(t)

	if _, _, err := fx.client.Download(t.Context(), *asset, t.TempDir()); err == nil {
		t.Fatal("download must fail when mirror is tampered and direct is unreachable")
	}
}

// 镜像正常服务时：镜像优先策略走镜像且内容校验通过
func TestHonestMirrorSucceeds(t *testing.T) {
	fx := newFixture(t, false, false)
	fx.setMirror(fx.srv.URL + "/mirror")
	fx.client.DirectFirst = false
	asset := fx.findAsset(t)

	path, viaMirror, err := fx.client.Download(t.Context(), *asset, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if !viaMirror {
		t.Error("expected mirror to be used when preferred")
	}
	if err := VerifySHA256(path, fx.archiveHash); err != nil {
		t.Errorf("mirror content should verify: %v", err)
	}
}
