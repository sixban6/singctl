// 文件职责：验证 SmartDNS 静态二进制资产选择、流式安装自检、失败清理与版本缓存。
package smartdns_test

import (
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

	"singctl/internal/common/sysinfo"
	"singctl/internal/platform/servicemgr"
	"singctl/internal/smartdns"
)

func TestSelectAssetName(t *testing.T) {
	cases := []struct {
		goos    string
		goarch  string
		want    string
		wantErr bool
	}{
		{"linux", "arm64", "smartdns-aarch64", false},
		{"linux", "amd64", "smartdns-x86_64", false},
		{"linux", "arm", "smartdns-arm", false},
		{"linux", "386", "smartdns-x86", false},
		{"linux", "mips", "smartdns-mips", false},
		{"linux", "mipsle", "smartdns-mipsel", false},
		{"linux", "riscv64", "", true},
		{"linux", "", "", true},
		{"darwin", "arm64", "", true},
		{"darwin", "amd64", "", true},
		{"windows", "amd64", "", true},
		{"", "arm64", "", true},
	}

	for _, tc := range cases {
		got, err := smartdns.SelectAssetName(tc.goos, tc.goarch)
		if tc.wantErr {
			if err == nil {
				t.Errorf("SelectAssetName(%q, %q) expected error, got %q", tc.goos, tc.goarch, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("SelectAssetName(%q, %q) unexpected error: %v", tc.goos, tc.goarch, err)
		}
		if got != tc.want {
			t.Errorf("SelectAssetName(%q, %q) = %q, want %q", tc.goos, tc.goarch, got, tc.want)
		}
	}
}

func TestParseVersionOutput(t *testing.T) {
	cases := []struct {
		raw  string
		want string
	}{
		{"", ""},
		{"   \n\t ", ""},
		{"smartdns 1.2026.01.01-1200\n", "smartdns 1.2026.01.01-1200"},
		{"\n  smartdns Release48.5  \nextra line\n", "smartdns Release48.5"},
	}
	for _, tc := range cases {
		if got := smartdns.ParseVersionOutput(tc.raw); got != tc.want {
			t.Errorf("ParseVersionOutput(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}
}

func TestCachedBinaryVersion_CacheHitAndInvalidation(t *testing.T) {
	dir := t.TempDir()
	binPath := filepath.Join(dir, "smartdns")
	counterFile := filepath.Join(dir, "invocations.txt")

	writeFakeBin := func(ver string) {
		t.Helper()
		script := fmt.Sprintf("#!/bin/sh\necho x >> %q\necho %q\n", counterFile, ver)
		if err := os.WriteFile(binPath, []byte(script), 0755); err != nil {
			t.Fatal(err)
		}
	}

	// Missing binary returns empty string
	if v := smartdns.CachedBinaryVersion(binPath); v != "" {
		t.Fatalf("expected empty version for missing binary, got %q", v)
	}
	// Directory returns empty string
	if v := smartdns.CachedBinaryVersion(dir); v != "" {
		t.Fatalf("expected empty version for directory, got %q", v)
	}

	writeFakeBin("smartdns Release48.5")

	// First call executes binary
	if got := smartdns.CachedBinaryVersion(binPath); got != "smartdns Release48.5" {
		t.Fatalf("first CachedBinaryVersion = %q, want %q", got, "smartdns Release48.5")
	}

	// Concurrent repeated calls hit cache (no extra fork)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			if got := smartdns.CachedBinaryVersion(binPath); got != "smartdns Release48.5" {
				t.Errorf("concurrent CachedBinaryVersion = %q", got)
			}
		})
	}
	wg.Wait()

	rawCount, err := os.ReadFile(counterFile)
	if err != nil {
		t.Fatal(err)
	}
	if lines := len(strings.Split(strings.TrimSpace(string(rawCount)), "\n")); lines != 1 {
		t.Fatalf("expected binary executed once due to cache, got %d invocations", lines)
	}

	// Upgrade binary (new size & mtime) invalidates cache immediately
	writeFakeBin("smartdns Release49.0-extended")
	future := time.Now().Add(2 * time.Second)
	_ = os.Chtimes(binPath, future, future)

	if got := smartdns.CachedBinaryVersion(binPath); got != "smartdns Release49.0-extended" {
		t.Fatalf("after upgrade CachedBinaryVersion = %q, want %q", got, "smartdns Release49.0-extended")
	}
}

func TestInstall_StreamingReleaseDownloadAndSelfCheck(t *testing.T) {
	payload := []byte("#!/bin/sh\necho 'smartdns Release48.5'\n")
	sum := sha256.Sum256(payload)
	digest := "sha256:" + hex.EncodeToString(sum[:])

	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/pymumu/smartdns/releases/latest":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"tag_name": "Release48.5",
				"assets": []map[string]any{
					{
						"name":                 "smartdns-aarch64",
						"browser_download_url": srv.URL + "/download/smartdns-aarch64",
						"size":                 len(payload),
						"digest":               digest,
					},
				},
			})
		case "/download/smartdns-aarch64":
			_, _ = w.Write(payload)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	t.Run("success_streams_to_target_dir_verifies_and_renames_atomically", func(t *testing.T) {
		root := t.TempDir()
		binPath := filepath.Join(root, "bin", "smartdns")
		cfgDir := filepath.Join(root, "etc")
		mockSvc := servicemgr.NewMock()

		mgr := smartdns.NewManager(smartdns.ManagerOptions{
			BinaryPath:     binPath,
			ConfigDir:      cfgDir,
			AuditLogPath:   filepath.Join(root, "audit.log"),
			LogFilePath:    filepath.Join(root, "smartdns.log"),
			PIDFilePath:    filepath.Join(root, "smartdns.pid"),
			ReleaseAPIBase: srv.URL,
			HTTPClient:     srv.Client(),
			GOOS:           "linux",
			GOARCH:         "arm64",
			ServiceMgr:     mockSvc,
			ReadMemInfo: func() (sysinfo.MemInfo, error) {
				return sysinfo.MemInfo{TotalBytes: 512 * 1024 * 1024, AvailableBytes: 205 * 1024 * 1024}, nil
			},
			ReadDiskSpace: func(string) (sysinfo.DiskSpace, error) {
				return sysinfo.DiskSpace{AvailBytes: 20 * 1024 * 1024}, nil
			},
			ProbeDNSFunc: func(string, time.Duration) error { return nil },
		})

		st, err := mgr.Install(t.Context(), smartdns.InstallOptions{})
		if err != nil {
			t.Fatalf("Install failed: %v", err)
		}
		if !st.Installed || !st.Running || !st.DNSHealthy || !st.Supported || !st.HardwareEligible {
			t.Fatalf("unexpected status after Install: %+v", st)
		}
		if st.Version != "smartdns Release48.5" {
			t.Fatalf("version = %q, want %q", st.Version, "smartdns Release48.5")
		}
		// Ensure staging .tmp file is gone after atomic rename
		if _, err := os.Stat(binPath + ".tmp"); !os.IsNotExist(err) {
			t.Fatalf("expected %s.tmp cleaned up after atomic rename", binPath)
		}
		// Binary must be executable
		info, err := os.Stat(binPath)
		if err != nil || info.Mode().Perm()&0111 == 0 {
			t.Fatalf("expected executable binary at %s, info=%v err=%v", binPath, info, err)
		}
	})

	t.Run("failed_binary_self_check_removes_tmp_and_preserves_clean_state", func(t *testing.T) {
		root := t.TempDir()
		binPath := filepath.Join(root, "bin", "smartdns")
		badPayload := []byte("#!/bin/sh\necho 'missing shared lib' >&2\nexit 127\n")
		badSum := sha256.Sum256(badPayload)
		badDigest := "sha256:" + hex.EncodeToString(badSum[:])

		var badSrv *httptest.Server
		badSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/repos/pymumu/smartdns/releases/latest" {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"tag_name": "Release48.5",
					"assets": []map[string]any{
						{
							"name":                 "smartdns-aarch64",
							"browser_download_url": badSrv.URL + "/download/smartdns-aarch64",
							"size":                 len(badPayload),
							"digest":               badDigest,
						},
					},
				})
				return
			}
			_, _ = w.Write(badPayload)
		}))
		defer badSrv.Close()

		mgr := smartdns.NewManager(smartdns.ManagerOptions{
			BinaryPath:     binPath,
			ConfigDir:      filepath.Join(root, "etc"),
			AuditLogPath:   filepath.Join(root, "audit.log"),
			LogFilePath:    filepath.Join(root, "smartdns.log"),
			PIDFilePath:    filepath.Join(root, "smartdns.pid"),
			ReleaseAPIBase: badSrv.URL,
			HTTPClient:     badSrv.Client(),
			GOOS:           "linux",
			GOARCH:         "arm64",
			ServiceMgr:     servicemgr.NewMock(),
			ReadMemInfo: func() (sysinfo.MemInfo, error) {
				return sysinfo.MemInfo{TotalBytes: 512 * 1024 * 1024, AvailableBytes: 205 * 1024 * 1024}, nil
			},
			ReadDiskSpace: func(string) (sysinfo.DiskSpace, error) {
				return sysinfo.DiskSpace{AvailBytes: 20 * 1024 * 1024}, nil
			},
			ProbeDNSFunc: func(string, time.Duration) error { return nil },
		})

		if _, err := mgr.Install(t.Context(), smartdns.InstallOptions{}); err == nil {
			t.Fatal("expected Install to fail when -v self-check fails")
		}
		if _, err := os.Stat(binPath + ".tmp"); !os.IsNotExist(err) {
			t.Fatalf("expected failed %s.tmp removed automatically", binPath)
		}
		if _, err := os.Stat(binPath); !os.IsNotExist(err) {
			t.Fatalf("expected %s not installed after failed self-check", binPath)
		}
	})
}
