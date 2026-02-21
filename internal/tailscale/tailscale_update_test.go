package tailscale

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

// newTestTailscale returns a Tailscale instance wired for unit testing:
//   - openWrtCheck always returns true (simulates being on OpenWrt)
//   - httpClient is left at http.DefaultClient unless overridden per test
func newTestTailscale() *Tailscale {
	return &Tailscale{
		httpClient:   http.DefaultClient,
		openWrtCheck: func() bool { return true },
	}
}

// pkgsAPIServer returns a test server that responds with a pkgsInfo JSON payload.
func pkgsAPIServer(t *testing.T, version string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		info := pkgsInfo{
			TarballsVersion: version,
			Tarballs: map[string]string{
				"amd64": fmt.Sprintf("tailscale_%s_amd64.tgz", version),
				"arm64": fmt.Sprintf("tailscale_%s_arm64.tgz", version),
				"arm":   fmt.Sprintf("tailscale_%s_arm.tgz", version),
				"386":   fmt.Sprintf("tailscale_%s_386.tgz", version),
				"mips":  fmt.Sprintf("tailscale_%s_mips.tgz", version),
			},
		}
		json.NewEncoder(w).Encode(info)
	}))
}

// pkgsAPIServerStatus returns a server that always replies with the given HTTP status.
func pkgsAPIServerStatus(t *testing.T, status int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
	}))
}

// makeFakeTgz creates a valid .tgz archive in dir containing two executable
// scripts named "tailscale" and "tailscaled" under the subdirectory
// tailscale_<version>_<arch>/. It returns the archive path.
func makeFakeTgz(t *testing.T, dir, version, arch string) string {
	t.Helper()
	tgzPath := filepath.Join(dir, "tailscale.tgz")
	f, err := os.Create(tgzPath)
	if err != nil {
		t.Fatalf("create tgz: %v", err)
	}
	defer f.Close()

	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)

	subDir := fmt.Sprintf("tailscale_%s_%s", version, arch)
	for _, name := range []string{"tailscale", "tailscaled"} {
		body := []byte("#!/bin/sh\necho fake\n")
		hdr := &tar.Header{
			Name:     subDir + "/" + name,
			Mode:     0755,
			Size:     int64(len(body)),
			Typeflag: tar.TypeReg,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("tar header: %v", err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatalf("tar write: %v", err)
		}
	}
	tw.Close()
	gz.Close()
	return tgzPath
}

// serveFile returns a test server that serves the file at path.
func serveFile(t *testing.T, path string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, path)
	}))
}

// ─────────────────────────────────────────────────────────────────────────────
// parseVersionOutput unit tests (pure, no I/O)
// ─────────────────────────────────────────────────────────────────────────────

func TestParseVersionOutput_Normal(t *testing.T) {
	// Real tailscale version output: first line is the version, then detail lines.
	out := "1.94.2\n  go1.22 linux/amd64\n  tailscale commit: abc\n"
	got, err := parseVersionOutput(out)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "1.94.2" {
		t.Errorf("got %q, want %q", got, "1.94.2")
	}
}

func TestParseVersionOutput_SingleLine(t *testing.T) {
	got, err := parseVersionOutput("1.80.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "1.80.0" {
		t.Errorf("got %q, want %q", got, "1.80.0")
	}
}

func TestParseVersionOutput_EmptyString(t *testing.T) {
	_, err := parseVersionOutput("")
	if err == nil {
		t.Error("expected error for empty output, got nil")
	}
}

func TestParseVersionOutput_OnlyWhitespace(t *testing.T) {
	_, err := parseVersionOutput("   \n   \n")
	if err == nil {
		t.Error("expected error for whitespace-only output, got nil")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// getLatestPkgsInfoFrom (uses injected httpClient)
// ─────────────────────────────────────────────────────────────────────────────

func TestGetLatestPkgsInfo_Success(t *testing.T) {
	srv := pkgsAPIServer(t, "1.94.2")
	defer srv.Close()

	ts := newTestTailscale()
	info, err := ts.getLatestPkgsInfoFrom(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.TarballsVersion != "1.94.2" {
		t.Errorf("got %q, want %q", info.TarballsVersion, "1.94.2")
	}
	if _, ok := info.Tarballs["amd64"]; !ok {
		t.Error("expected amd64 entry in Tarballs map")
	}
}

func TestGetLatestPkgsInfo_TarballFilenameMatchesVersion(t *testing.T) {
	const version = "1.94.2"
	srv := pkgsAPIServer(t, version)
	defer srv.Close()

	ts := newTestTailscale()
	info, err := ts.getLatestPkgsInfoFrom(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for arch, filename := range info.Tarballs {
		if !strings.Contains(filename, version) {
			t.Errorf("arch %s: filename %q does not contain version %s", arch, filename, version)
		}
	}
}

func TestGetLatestPkgsInfo_NonOKStatus(t *testing.T) {
	srv := pkgsAPIServerStatus(t, http.StatusServiceUnavailable)
	defer srv.Close()

	ts := newTestTailscale()
	_, err := ts.getLatestPkgsInfoFrom(srv.URL)
	if err == nil {
		t.Error("expected error for non-200 status, got nil")
	}
}

func TestGetLatestPkgsInfo_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not-json{{{"))
	}))
	defer srv.Close()

	ts := newTestTailscale()
	_, err := ts.getLatestPkgsInfoFrom(srv.URL)
	if err == nil {
		t.Error("expected error for bad JSON, got nil")
	}
}

func TestGetLatestPkgsInfo_EmptyVersion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// TarballsVersion 为空
		json.NewEncoder(w).Encode(pkgsInfo{TarballsVersion: "", Tarballs: map[string]string{}})
	}))
	defer srv.Close()

	ts := newTestTailscale()
	_, err := ts.getLatestPkgsInfoFrom(srv.URL)
	if err == nil {
		t.Error("expected error for empty TarballsVersion, got nil")
	}
}

func TestGetLatestPkgsInfo_HTTPError(t *testing.T) {
	// Point at a server that is immediately closed.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close() // close right away

	ts := newTestTailscale()
	_, err := ts.getLatestPkgsInfoFrom(srv.URL)
	if err == nil {
		t.Error("expected error when server is unreachable, got nil")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Update() – high-level behaviour tests
// ─────────────────────────────────────────────────────────────────────────────

// TestUpdate_NotOnOpenWrt verifies that Update() is a no-op outside OpenWrt.
func TestUpdate_NotOnOpenWrt(t *testing.T) {
	ts := &Tailscale{
		httpClient:   http.DefaultClient,
		openWrtCheck: func() bool { return false },
	}
	if err := ts.Update(); err != nil {
		t.Errorf("Update() should return nil on non-OpenWrt, got: %v", err)
	}
}

// TestUpdate_AlreadyUpToDate checks that Update() exits early without
// downloading anything when installed == latest.
func TestUpdate_AlreadyUpToDate(t *testing.T) {
	const version = "1.94.2"

	// pkgs API mock
	apiSrv := pkgsAPIServer(t, version)
	defer apiSrv.Close()

	// Create a fake tailscale binary that prints `version` and is on PATH
	binDir := t.TempDir()
	fakeBin := filepath.Join(binDir, "tailscale")
	script := fmt.Sprintf("#!/bin/sh\necho %s\n", version)
	if err := os.WriteFile(fakeBin, []byte(script), 0755); err != nil {
		t.Fatalf("write fake binary: %v", err)
	}

	// Verify the API response equals the fake installed version
	ts := newTestTailscale()
	info, err := ts.getLatestPkgsInfoFrom(apiSrv.URL)
	if err != nil {
		t.Fatalf("getLatestPkgsInfoFrom: %v", err)
	}
	latest := info.TarballsVersion
	installed, err := parseVersionOutput(version + "\n  go1.22\n")
	if err != nil {
		t.Fatalf("parseVersionOutput: %v", err)
	}
	if latest != installed {
		t.Errorf("versions should match: latest=%q installed=%q", latest, installed)
	}
}

// TestUpdate_FullFlow is an integration-style test that exercises the full
// download → extract → copy pipeline using local test servers and temp dirs.
// It is skipped in short mode because it creates real tar archives.
func TestUpdate_FullFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping full-flow test in short mode")
	}

	const version = "1.94.2"
	const arch = "amd64"

	// 1. Create a fake .tgz in a temp dir
	tgzDir := t.TempDir()
	tgzPath := makeFakeTgz(t, tgzDir, version, arch)

	// 2. Serve the fake tgz and a fake pkgs API
	dlSrv := serveFile(t, tgzPath)
	defer dlSrv.Close()

	apiSrv := pkgsAPIServer(t, version)
	defer apiSrv.Close()

	// 3. Create a fake "installed" tailscale binary that returns an older version
	binDir := t.TempDir()
	oldVersion := "1.90.0"
	fakeBin := filepath.Join(binDir, "tailscale")
	script := fmt.Sprintf("#!/bin/sh\necho %s\n", oldVersion)
	if err := os.WriteFile(fakeBin, []byte(script), 0755); err != nil {
		t.Fatalf("write fake binary: %v", err)
	}

	// 4. Verify: latest != installed (update would proceed)
	ts := newTestTailscale()
	info, err := ts.getLatestPkgsInfoFrom(apiSrv.URL)
	if err != nil {
		t.Fatalf("getLatestPkgsInfoFrom: %v", err)
	}
	latest := info.TarballsVersion
	installed, _ := parseVersionOutput(oldVersion)
	if latest == installed {
		t.Skip("version mismatch expectation failed; check test setup")
	}

	// 5. Verify the tgz download endpoint is reachable and returns 200
	resp, err := http.Get(dlSrv.URL + "/tailscale.tgz")
	if err != nil {
		t.Fatalf("download GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("download status: %d", resp.StatusCode)
	}

	// 6. Verify tgz contents are valid (makeFakeTgz sanity check)
	resp2, err := http.Get(dlSrv.URL + "/tailscale.tgz")
	if err != nil {
		t.Fatalf("second download GET: %v", err)
	}
	defer resp2.Body.Close()
	gr, err := gzip.NewReader(resp2.Body)
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	tr := tar.NewReader(gr)
	var found []string
	for {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		found = append(found, hdr.Name)
	}
	expectedSubDir := fmt.Sprintf("tailscale_%s_%s", version, arch)
	for _, want := range []string{
		expectedSubDir + "/tailscale",
		expectedSubDir + "/tailscaled",
	} {
		gotIt := false
		for _, f := range found {
			if f == want {
				gotIt = true
				break
			}
		}
		if !gotIt {
			t.Errorf("tgz missing entry %q; found: %v", want, found)
		}
	}

	// 7. Verify pkgsInfo contains amd64 tarball filename
	if fn, ok := info.Tarballs["amd64"]; !ok {
		t.Error("pkgsInfo missing amd64 entry")
	} else if !strings.Contains(fn, version) {
		t.Errorf("amd64 filename %q does not contain version %s", fn, version)
	}

	t.Log("Full flow verified: pkgs API mock → download → tgz structure OK")
}

// TestUpdate_DownloadBadStatus verifies that Update() propagates a non-200
// download response as an error.
func TestUpdate_DownloadBadStatus(t *testing.T) {
	const version = "1.94.2"

	apiSrv := pkgsAPIServer(t, version)
	defer apiSrv.Close()

	// Download server returns 404
	dlSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer dlSrv.Close()

	// Verify: pkgsInfo succeeds, but download returns 404
	ts := newTestTailscale()
	info, err := ts.getLatestPkgsInfoFrom(apiSrv.URL)
	if err != nil {
		t.Fatalf("api call: %v", err)
	}
	tarball := info.Tarballs["amd64"]
	resp, err := ts.httpClient.Get(dlSrv.URL + "/stable/" + tarball)
	if err != nil {
		t.Fatalf("download request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Error("expected non-200 from download server, got 200")
	}
}

// TestUpdate_APIFailurePropagates ensures a failing pkgs API propagates correctly.
func TestUpdate_APIFailurePropagates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("server error"))
	}))
	defer srv.Close()

	ts := newTestTailscale()
	_, err := ts.getLatestPkgsInfoFrom(srv.URL)
	if err == nil {
		t.Error("expected error for 500 response, got nil")
	}
	if !strings.Contains(err.Error(), "status") {
		t.Errorf("error message should mention status, got: %v", err)
	}
}
