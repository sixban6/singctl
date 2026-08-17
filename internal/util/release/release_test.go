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
	// sameSizeTamper=true 时篡改包会被填充到与官方完全相同的字节数
	// （此时大小校验必然放行，只有 sha256 能识破）
	sameSizeTamper bool
}

func (f *fixture) setMirror(m string) { f.client.Mirror = m }

// newFixture 起一个同时扮演 api.github.com / github.com / mirror 的测试服务器。
func newFixture(t *testing.T, tamperMirror, directBroken bool) *fixture {
	return newFixtureFull(t, tamperMirror, directBroken, false)
}

func newFixtureFull(t *testing.T, tamperMirror, directBroken, sameSizeTamper bool) *fixture {
	t.Helper()

	archiveBytes := makeTarGz(t, map[string]string{
		"pkg/singctl": "#!/bin/sh\necho fake-singctl\n",
	})
	archiveName := "singctl-test-os-arch.tar.gz"
	checksums := fmt.Sprintf("%s  %s\n%s  other-asset.zip\n",
		sha256Hex(archiveBytes), archiveName, sha256Hex([]byte("other")))

	fx := &fixture{
		archiveName:    archiveName,
		archiveHash:    sha256Hex(archiveBytes),
		archiveSize:    len(archiveBytes),
		directBroken:   directBroken,
		tamperMirror:   tamperMirror,
		sameSizeTamper: sameSizeTamper,
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
					"digest":               "sha256:" + sha256Hex(archiveBytes),
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
	malicious := []byte("MALICIOUS PAYLOAD ................")
	if sameSizeTamper {
		// 等长投毒：字节数与官方包完全一致，只有 sha256 能识破
		for len(malicious) < len(archiveBytes) {
			malicious = append(malicious, '.')
		}
		malicious = malicious[:len(archiveBytes)]
	}
	mux.HandleFunc("/mirror/", func(w http.ResponseWriter, r *http.Request) {
		if tamperMirror {
			_, _ = w.Write(malicious)
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

	res, err := fx.client.Download(t.Context(), *asset, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if res.ViaMirror {
		t.Error("expected direct download when no mirror configured")
	}
	if !res.SHA256Verified || !res.SizeChecked {
		t.Errorf("expected digest+size verification, got sha=%v size=%v", res.SHA256Verified, res.SizeChecked)
	}
	if err := VerifySHA256(res.Path, fx.archiveHash); err != nil {
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
	if err := VerifySHA256(res.Path, sums[fx.archiveName]); err != nil {
		t.Errorf("verify with fetched checksums should pass: %v", err)
	}
}

// 镜像投毒（篡改内容/大小）时：镜像优先策略应自动回退直连并拿到正确的包
func TestTamperedMirrorFallsBackToDirect(t *testing.T) {
	fx := newFixture(t, true, false)
	fx.setMirror(fx.srv.URL + "/mirror")
	fx.client.DirectFirst = false // 镜像优先
	asset := fx.findAsset(t)

	res, err := fx.client.Download(t.Context(), *asset, t.TempDir())
	if err != nil {
		t.Fatalf("expected fallback to direct: %v", err)
	}
	if res.ViaMirror {
		t.Error("tampered mirror result must be rejected")
	}
	if err := VerifySHA256(res.Path, fx.archiveHash); err != nil {
		t.Errorf("fallback content should verify: %v", err)
	}
}

// 镜像投毒且直连不可用时：必须报错，绝不能安装被篡改的包
func TestTamperedMirrorWithNoDirectMustFail(t *testing.T) {
	fx := newFixture(t, true, true)
	fx.setMirror(fx.srv.URL + "/mirror")
	fx.client.DirectFirst = false
	asset := fx.findAsset(t)

	if _, err := fx.client.Download(t.Context(), *asset, t.TempDir()); err == nil {
		t.Fatal("download must fail when mirror is tampered and direct is unreachable")
	}
}

// 镜像正常服务时：镜像优先策略走镜像且内容校验通过
func TestHonestMirrorSucceeds(t *testing.T) {
	fx := newFixture(t, false, false)
	fx.setMirror(fx.srv.URL + "/mirror")
	fx.client.DirectFirst = false
	asset := fx.findAsset(t)

	res, err := fx.client.Download(t.Context(), *asset, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if !res.ViaMirror {
		t.Error("expected mirror to be used when preferred")
	}
	if !res.SHA256Verified {
		t.Error("expected digest verification via honest mirror")
	}
	if err := VerifySHA256(res.Path, fx.archiveHash); err != nil {
		t.Errorf("mirror content should verify: %v", err)
	}
}

// 关键场景：镜像返回与官方包字节数完全相同的恶意内容。
// 大小校验必然放行，只有官方 digest 的 sha256 比对能识破。
func TestTamperedMirrorSameSizeCaughtByDigest(t *testing.T) {
	fx := newFixtureFull(t, true, false, true)
	fx.setMirror(fx.srv.URL + "/mirror")
	fx.client.DirectFirst = false // 镜像优先
	asset := fx.findAsset(t)

	res, err := fx.client.Download(t.Context(), *asset, t.TempDir())
	if err != nil {
		t.Fatalf("expected fallback to direct: %v", err)
	}
	if res.ViaMirror || !res.SHA256Verified {
		t.Errorf("same-size tampered mirror must be rejected by sha256, got viaMirror=%v shaVerified=%v", res.ViaMirror, res.SHA256Verified)
	}
	if err := VerifySHA256(res.Path, fx.archiveHash); err != nil {
		t.Errorf("fallback content should verify: %v", err)
	}
}

// digest 缺失（老版本 API/资产）时退化为仅大小校验，内容仍应正确
func TestNoDigestFallsBackToSizeOnly(t *testing.T) {
	fx := newFixture(t, false, false)
	fx.setMirror(fx.srv.URL + "/mirror")
	fx.client.DirectFirst = false
	asset := fx.findAsset(t)
	asset.Digest = "" // 模拟无 digest

	res, err := fx.client.Download(t.Context(), *asset, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if res.SHA256Verified {
		t.Error("digest cleared, sha256 verification should not be claimed")
	}
	if !res.SizeChecked || !res.ViaMirror {
		t.Errorf("expected size-only check via mirror, got size=%v mirror=%v", res.SizeChecked, res.ViaMirror)
	}
	if err := VerifySHA256(res.Path, fx.archiveHash); err != nil {
		t.Errorf("content should still be correct: %v", err)
	}
}

// 用户显式 SkipSHA256 时允许跳过校验（自担风险）
func TestSkipSHA256AcceptsTampered(t *testing.T) {
	fx := newFixture(t, true, true) // 镜像投毒 + 直连不可用
	fx.setMirror(fx.srv.URL + "/mirror")
	fx.client.DirectFirst = false
	fx.client.SkipSHA256 = true
	asset := fx.findAsset(t)
	// 投毒镜像内容大小与官方不同，跳过 sha256 后大小校验仍会拒绝，
	// 这里把大小也一并视为不可信（模拟旧版无 size 元数据），验证逃生口行为
	asset.Size = 0

	res, err := fx.client.Download(t.Context(), *asset, t.TempDir())
	if err != nil {
		t.Fatalf("skip-verification download should succeed: %v", err)
	}
	if res.SHA256Verified {
		t.Error("SkipSHA256 must not claim verification")
	}
}
