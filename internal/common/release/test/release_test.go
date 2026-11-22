// 文件职责：验证 release 信任锚直连元数据、镜像防投毒 SHA256 强校验、防 Zip-Slip 解压与小内存流式二进制提取 ExtractBinaryStream。
package release_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"singctl/internal/common/release"
)

func makeTarGzArchive(t *testing.T, entries map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	for name, content := range entries {
		if err := tw.WriteHeader(&tar.Header{
			Name:     name,
			Typeflag: tar.TypeReg,
			Mode:     0o755,
			Size:     int64(len(content)),
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	_ = tw.Close()
	_ = gw.Close()
	return buf.Bytes()
}

func TestTrustAnchorMetadataNeverUsesMirror_And_FindAssetURL(t *testing.T) {
	mirrorHitAPI := false
	archiveBytes := makeTarGzArchive(t, map[string]string{"bin/demo": "hello-binary"})
	sum := sha256.Sum256(archiveBytes)
	digest := "sha256:" + hex.EncodeToString(sum[:])

	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/mirror/") {
			if strings.Contains(r.URL.Path, "/repos/") {
				mirrorHitAPI = true
				http.Error(w, "mirror must NEVER receive metadata API calls", http.StatusForbidden)
				return
			}
			_, _ = w.Write(archiveBytes)
			return
		}
		switch r.URL.Path {
		case "/repos/example/demo/releases/latest":
			_ = json.NewEncoder(w).Encode(release.Info{
				TagName: "v1.4.2",
				Assets: []release.Asset{{
					Name:               "demo-linux-amd64.tar.gz",
					Size:               int64(len(archiveBytes)),
					Digest:             digest,
					BrowserDownloadURL: srvURL + "/dl/demo-linux-amd64.tar.gz",
				}},
			})
		case "/repos/example/demo/releases":
			_ = json.NewEncoder(w).Encode([]release.Info{
				{TagName: "v1.5.0-rc.1", Assets: []release.Asset{{Name: "SFM-1.5.0-Apple.pkg", BrowserDownloadURL: "https://example.com/SFM.pkg"}}},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	srvURL = srv.URL

	c := release.NewClient(srv.URL + "/mirror")
	c.APIBase = srv.URL
	c.DLBase = srv.URL
	c.HTTP = srv.Client()
	c.DirectFirst = false // Force mirror for binary downloads, while metadata MUST still go direct!

	tag, err := c.FetchLatestTag(t.Context(), "example/demo")
	if err != nil || tag != "1.4.2" {
		t.Fatalf("FetchLatestTag = (%q, %v), want (1.4.2, nil)", tag, err)
	}
	if mirrorHitAPI {
		t.Fatal("security violation: metadata API call went through mirror")
	}

	guiURL, err := c.FindAssetURL(t.Context(), "example/demo", func(name string) bool {
		return strings.HasPrefix(name, "SFM-")
	})
	if err != nil || guiURL != "https://example.com/SFM.pkg" {
		t.Fatalf("FindAssetURL = (%q, %v)", guiURL, err)
	}

	info, err := c.FetchLatest(t.Context(), "example/demo")
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Download(t.Context(), info.Assets[0], t.TempDir())
	if err != nil || !res.ViaMirror || !res.SHA256Verified {
		t.Fatalf("Download via mirror = (%+v, %v)", res, err)
	}
}

func TestExtractBinaryStream_SecurityBoundsAndZipSlip(t *testing.T) {
	dir := t.TempDir()
	rawArchive := makeTarGzArchive(t, map[string]string{
		"README.md":            "docs",
		"nested/dir/wireproxy": "binary-payload-12345",
	})

	// 1. Happy path stream extraction
	destBin := filepath.Join(dir, "bin", "wireproxy")
	if err := release.ExtractBinaryStream(bytes.NewReader(rawArchive), "wireproxy", destBin, 1024*1024); err != nil {
		t.Fatalf("ExtractBinaryStream failed: %v", err)
	}
	got, err := os.ReadFile(destBin)
	if err != nil || string(got) != "binary-payload-12345" {
		t.Fatalf("extracted content = (%q, %v)", string(got), err)
	}

	// 2. Oversize bomb rejected by maxBytes cap without corrupting existing binary
	if err := release.ExtractBinaryStream(bytes.NewReader(rawArchive), "wireproxy", destBin, 8); err == nil {
		t.Fatal("expected maxBytes limit error on oversize binary entry")
	}
	gotAfterReject, _ := os.ReadFile(destBin)
	if string(gotAfterReject) != "binary-payload-12345" {
		t.Fatalf("failed oversize extraction corrupted existing binary: %q", string(gotAfterReject))
	}

	// 3. Zip-Slip traversal entry rejected
	evilArchive := makeTarGzArchive(t, map[string]string{
		"../../outside/wireproxy": "evil",
	})
	if err := release.ExtractBinaryStream(bytes.NewReader(evilArchive), "wireproxy", filepath.Join(dir, "out", "wireproxy"), 1024); err == nil {
		t.Fatal("expected Zip-Slip path traversal entry to be rejected")
	}

	// 4. ExtractBinary from archive file on disk + DownloadAndExtractBinary
	arcFile := filepath.Join(dir, "pkg.tar.gz")
	_ = os.WriteFile(arcFile, rawArchive, 0600)
	destFromFile := filepath.Join(dir, "fromfile", "wireproxy")
	if err := release.ExtractBinary(arcFile, "wireproxy", destFromFile); err != nil {
		t.Fatalf("ExtractBinary failed: %v", err)
	}

	dlSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(rawArchive)
	}))
	defer dlSrv.Close()
	destFromHTTP := filepath.Join(dir, "fromhttp", "wireproxy")
	if err := release.DownloadAndExtractBinary(t.Context(), dlSrv.Client(), dlSrv.URL+"/pkg.tar.gz", "", "wireproxy", destFromHTTP); err != nil {
		t.Fatalf("DownloadAndExtractBinary failed: %v", err)
	}
}

func TestFetchTag_TrustAnchorNotFoundAndInputValidation(t *testing.T) {
	mirrorHitAPI := false
	apiHits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiHits++
		if strings.HasPrefix(r.URL.Path, "/mirror/") {
			mirrorHitAPI = true
			http.Error(w, "mirror must NEVER receive FetchTag metadata calls", http.StatusForbidden)
			return
		}
		switch r.URL.Path {
		case "/repos/example/demo/releases/tags/singbox-lite-latest":
			_ = json.NewEncoder(w).Encode(release.Info{
				TagName: "singbox-lite-latest",
				Assets: []release.Asset{
					{Name: "sing-box-1.14.4-linux-arm64-lite.tar.gz", Size: 1024},
					{Name: "checksums.txt", Size: 128},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	c := release.NewClient(srv.URL + "/mirror")
	c.APIBase = srv.URL
	c.DLBase = srv.URL
	c.HTTP = srv.Client()
	c.DirectFirst = false

	// 1. Happy path: fetches fixed prerelease tag directly without touching mirror
	info, err := c.FetchTag(t.Context(), "example/demo", "singbox-lite-latest")
	if err != nil {
		t.Fatalf("FetchTag valid prerelease tag failed: %v", err)
	}
	if mirrorHitAPI {
		t.Fatal("security violation: FetchTag went through mirror")
	}
	if info.TagName != "singbox-lite-latest" || len(info.Assets) != 2 {
		t.Fatalf("unexpected FetchTag Info: %+v", info)
	}

	// 2. HTTP 404 maps cleanly to release.IsNotFound
	_, err = c.FetchTag(t.Context(), "example/demo", "non-existent-tag")
	if err == nil || !release.IsNotFound(err) {
		t.Fatalf("FetchTag 404 err = %v, want release.IsNotFound=true", err)
	}

	// 3. Invalid / empty / path-traversal / query-injection inputs rejected BEFORE any network call
	hitsBeforeBad := apiHits
	badInputs := []struct {
		name string
		repo string
		tag  string
	}{
		{name: "empty_repo", repo: "", tag: "singbox-lite-latest"},
		{name: "empty_tag", repo: "example/demo", tag: "   "},
		{name: "repo_missing_slash", repo: "exampleOnly", tag: "v1.0.0"},
		{name: "repo_traversal", repo: "example/../evil", tag: "v1.0.0"},
		{name: "tag_path_traversal", repo: "example/demo", tag: "../../latest"},
		{name: "tag_slash_injection", repo: "example/demo", tag: "foo/bar"},
		{name: "tag_query_injection", repo: "example/demo", tag: "v1.0.0?per_page=100"},
		{name: "tag_fragment_injection", repo: "example/demo", tag: "v1.0.0#frag"},
	}
	for _, tc := range badInputs {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := c.FetchTag(t.Context(), tc.repo, tc.tag); err == nil {
				t.Fatalf("expected error for repo=%q tag=%q, got nil", tc.repo, tc.tag)
			}
		})
	}
	if apiHits != hitsBeforeBad {
		t.Fatalf("malformed FetchTag inputs triggered %d HTTP requests, want 0", apiHits-hitsBeforeBad)
	}
}
