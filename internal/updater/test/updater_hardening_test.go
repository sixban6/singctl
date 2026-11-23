// 文件职责：验证 updater 路径清洗、Lite 资产选择及低内存/低 /tmp 空间下的零 /tmp 流式直写 SHA256 升级与失败回滚保护。
package updater_test

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
	"sync/atomic"
	"testing"

	"singctl/internal/common/release"
	"singctl/internal/common/sysinfo"
	"singctl/internal/updater"
)

func buildTestSingCtlTarGz(t *testing.T, entries map[string]string) ([]byte, string) {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range entries {
		hdr := &tar.Header{
			Name:     name,
			Mode:     0755,
			Size:     int64(len(body)),
			Typeflag: tar.TypeReg,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("write tar header %s: %v", name, err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatalf("write tar body %s: %v", name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	raw := buf.Bytes()
	sum := sha256.Sum256(raw)
	return raw, hex.EncodeToString(sum[:])
}

func TestSanitizeExecutablePath_And_AssetMatching(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"/usr/bin/singctl (deleted)", "/usr/bin/singctl"},
		{"/usr/local/bin/singctl.backup", "/usr/local/bin/singctl"},
		{"/usr/local/bin/singctl.backup.backup (deleted)", "/usr/local/bin/singctl"},
		{"  /usr/bin/singctl  ", "/usr/bin/singctl"},
	}
	for _, tc := range cases {
		if got := updater.SanitizeExecutablePath(tc.in); got != tc.want {
			t.Errorf("SanitizeExecutablePath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}

	if _, err := updater.ResolveExecutablePath(); err != nil {
		t.Fatalf("ResolveExecutablePath failed: %v", err)
	}

	assets := []release.Asset{
		{Name: "checksums.txt"},
		{Name: "singctl-linux-amd64.deb"},
		{Name: "singctl-linux-amd64-lite.tar.gz"},
		{Name: "singctl-linux-x86_64.tar.gz"},
	}
	std := updater.SelectSingCtlAsset(assets, "linux", "amd64", false)
	if std == nil || std.Name != "singctl-linux-x86_64.tar.gz" {
		t.Fatalf("expected standard x86_64 tar.gz asset (excluding checksums, .deb, and -lite), got %+v", std)
	}
	lite := updater.SelectSingCtlAsset(assets, "linux", "amd64", true)
	if lite == nil || lite.Name != "singctl-linux-amd64-lite.tar.gz" {
		t.Fatalf("expected -lite.tar.gz asset when isLite=true, got %+v", lite)
	}
	onlyNonArchive := []release.Asset{
		{Name: "checksums.txt"},
		{Name: "singctl-linux-amd64.deb"},
	}
	if got := updater.SelectSingCtlAsset(onlyNonArchive, "linux", "amd64", false); got != nil {
		t.Fatalf("expected checksums.txt and .deb to be excluded, got %+v", got)
	}
}

func TestUpdateSelf_LowMemoryZeroTmpStreaming_DigestAndChecksumsAndRollback(t *testing.T) {
	const mib = 1024 * 1024
	const newBinContent = "#!/bin/sh\necho singctl-v1.14.200-lite\n"

	archiveBytes, archiveSHA := buildTestSingCtlTarGz(t, map[string]string{
		"singctl-linux-arm64-lite/singctl":              newBinContent,
		"singctl-linux-arm64-lite/configs/singctl.yaml": "# trailing config after binary to test full stream hashing\n",
	})
	badMirrorArchive, _ := buildTestSingCtlTarGz(t, map[string]string{
		"singctl-linux-arm64-lite/singctl": "TAMPERED_MALICIOUS_PAYLOAD",
	})

	isLite := true

	t.Run("low_memory_224MB_streams_with_official_digest_and_zero_tmp_writes", func(t *testing.T) {
		tmpRoot := filepath.Join(t.TempDir(), "mock-tmpfs")
		if err := os.MkdirAll(tmpRoot, 0755); err != nil {
			t.Fatal(err)
		}
		installDir := filepath.Join(t.TempDir(), "usr-bin")
		if err := os.MkdirAll(installDir, 0755); err != nil {
			t.Fatal(err)
		}
		exePath := filepath.Join(installDir, "singctl")
		if err := os.WriteFile(exePath, []byte("old-v1.14.100"), 0755); err != nil {
			t.Fatal(err)
		}

		var srvURL string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/repos/test/singctl/releases/latest":
				_ = json.NewEncoder(w).Encode(release.Info{
					TagName: "v1.14.200",
					Assets: []release.Asset{
						{
							Name:               "singctl-linux-arm64-lite.tar.gz",
							BrowserDownloadURL: srvURL + "/dl/singctl-linux-arm64-lite.tar.gz",
							Size:               int64(len(archiveBytes)),
							Digest:             "sha256:" + archiveSHA,
						},
					},
				})
			case "/dl/singctl-linux-arm64-lite.tar.gz":
				_, _ = w.Write(archiveBytes)
			default:
				http.NotFound(w, r)
			}
		}))
		defer srv.Close()
		srvURL = srv.URL

		u := updater.NewWithDeps("", srv.URL, updater.Deps{
			APIBase:           srv.URL,
			DLBase:            srv.URL,
			HTTPClient:        srv.Client(),
			Repo:              "test/singctl",
			GOOS:              "linux",
			GOARCH:            "arm64",
			IsLite:            &isLite,
			ReadTotalRAMBytes: func() uint64 { return 224 * mib },
			ResolveExePath:    func() (string, error) { return exePath, nil },
			TempDir:           tmpRoot,
		})

		if err := u.UpdateSelf("", "v1.14.100"); err != nil {
			t.Fatalf("UpdateSelf streaming failed: %v", err)
		}

		gotExe, err := os.ReadFile(exePath)
		if err != nil || string(gotExe) != newBinContent {
			t.Fatalf("expected updated binary content, got (%q, %v)", string(gotExe), err)
		}
		tmpEntries, err := os.ReadDir(tmpRoot)
		if err != nil || len(tmpEntries) != 0 {
			t.Fatalf("expected ZERO files/dirs created in /tmp (%s), got %v", tmpRoot, tmpEntries)
		}
		binEntries, err := os.ReadDir(installDir)
		if err != nil || len(binEntries) != 1 {
			t.Fatalf("expected no leftover temporary staged files in installDir, got %v", binEntries)
		}

		// Idempotency: already up to date returns nil immediately
		if err := u.UpdateSelf("", "v1.14.200"); err != nil {
			t.Fatalf("expected up-to-date UpdateSelf to return nil, got %v", err)
		}
	})

	t.Run("low_tmp_space_triggers_streaming_with_checksums_txt_and_mirror_tamper_fallback", func(t *testing.T) {
		tmpRoot := filepath.Join(t.TempDir(), "tiny-tmpfs")
		_ = os.MkdirAll(tmpRoot, 0755)
		installDir := filepath.Join(t.TempDir(), "usr-bin")
		_ = os.MkdirAll(installDir, 0755)
		exePath := filepath.Join(installDir, "singctl")
		_ = os.WriteFile(exePath, []byte("old-binary"), 0755)

		var mirrorHits atomic.Int32
		mirrorSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mirrorHits.Add(1)
			// Mirror serves tampered archive! Must be rejected and cleaned up, then fallback to direct!
			_, _ = w.Write(badMirrorArchive)
		}))
		defer mirrorSrv.Close()

		var directURL string
		directSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/repos/test/singctl/releases/latest":
				_ = json.NewEncoder(w).Encode(release.Info{
					TagName: "v1.14.200",
					Assets: []release.Asset{
						{
							Name:               "singctl-linux-arm64-lite.tar.gz",
							BrowserDownloadURL: directURL + "/dl/singctl-linux-arm64-lite.tar.gz",
							// Intentionally omit Digest to exercise FetchChecksums fallback!
						},
						{
							Name:               "checksums.txt",
							BrowserDownloadURL: directURL + "/dl/checksums.txt",
						},
					},
				})
			case "/dl/checksums.txt":
				fmt.Fprintf(w, "%s  singctl-linux-arm64-lite.tar.gz\n", archiveSHA)
			case "/dl/singctl-linux-arm64-lite.tar.gz":
				_, _ = w.Write(archiveBytes)
			default:
				http.NotFound(w, r)
			}
		}))
		defer directSrv.Close()
		directURL = directSrv.URL

		u := updater.NewWithDeps(mirrorSrv.URL, directSrv.URL, updater.Deps{
			APIBase:           directSrv.URL,
			DLBase:            directSrv.URL,
			HTTPClient:        directSrv.Client(),
			Repo:              "test/singctl",
			GOOS:              "linux",
			GOARCH:            "arm64",
			IsLite:            &isLite,
			ReadTotalRAMBytes: func() uint64 { return 2048 * mib }, // High RAM, but tiny /tmp!
			StatTmpSpace: func(string) (sysinfo.DiskSpace, error) {
				return sysinfo.DiskSpace{TotalBytes: 32 * mib, AvailBytes: 12 * mib}, nil
			},
			ResolveExePath: func() (string, error) { return exePath, nil },
			TempDir:        tmpRoot,
		})

		if err := u.UpdateSelf("", "v1.14.100"); err != nil {
			t.Fatalf("expected mirror tamper fallback to direct stream to succeed, got: %v", err)
		}
		if mirrorHits.Load() == 0 {
			t.Fatal("expected mirror to be attempted first before falling back")
		}
		gotExe, _ := os.ReadFile(exePath)
		if string(gotExe) != newBinContent {
			t.Fatalf("unexpected final binary content: %q", string(gotExe))
		}
		if entries, _ := os.ReadDir(installDir); len(entries) != 1 {
			t.Fatalf("expected clean installDir without temp leftovers, got %v", entries)
		}
	})

	t.Run("all_sources_tampered_aborts_cleanly_and_preserves_original_binary", func(t *testing.T) {
		installDir := filepath.Join(t.TempDir(), "usr-bin")
		_ = os.MkdirAll(installDir, 0755)
		exePath := filepath.Join(installDir, "singctl")
		const origPayload = "trusted-existing-binary"
		_ = os.WriteFile(exePath, []byte(origPayload), 0755)

		var srvURL string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/repos/test/singctl/releases/latest":
				_ = json.NewEncoder(w).Encode(release.Info{
					TagName: "v1.14.200",
					Assets: []release.Asset{
						{
							Name:               "singctl-linux-arm64-lite.tar.gz",
							BrowserDownloadURL: srvURL + "/dl/singctl-linux-arm64-lite.tar.gz",
							Digest:             "sha256:" + strings.Repeat("a", 64),
						},
					},
				})
			case "/dl/singctl-linux-arm64-lite.tar.gz":
				_, _ = w.Write(badMirrorArchive)
			default:
				http.NotFound(w, r)
			}
		}))
		defer srv.Close()
		srvURL = srv.URL

		u := updater.NewWithDeps("", srv.URL, updater.Deps{
			APIBase:           srv.URL,
			DLBase:            srv.URL,
			HTTPClient:        srv.Client(),
			Repo:              "test/singctl",
			GOOS:              "linux",
			GOARCH:            "arm64",
			IsLite:            &isLite,
			ReadTotalRAMBytes: func() uint64 { return 256 * mib },
			ResolveExePath:    func() (string, error) { return exePath, nil },
		})

		err := u.UpdateSelf("", "v1.14.100")
		if err == nil {
			t.Fatal("expected tampered SHA256 stream to fail")
		}
		gotExe, _ := os.ReadFile(exePath)
		if string(gotExe) != origPayload {
			t.Fatalf("tampered stream must NEVER overwrite live binary, got %q", string(gotExe))
		}
		if entries, _ := os.ReadDir(installDir); len(entries) != 1 {
			t.Fatalf("expected temporary extracted file to be deleted on checksum failure, got %v", entries)
		}
	})

	t.Run("streaming_update_migrates_config_preserving_notify_for_client_and_server", func(t *testing.T) {
		for _, tc := range []struct {
			name        string
			initialYAML string
			wantContain []string
			wantAbsent  []string
		}{
			{
				name: "client_preserves_telegram_notify",
				initialYAML: `subs:
  - name: main
    url: https://sub.example.com/client?token=test
notify:
  enabled: true
  channels:
    telegram:
      enabled: true
      bot_token: "123456:stream_test_token"
      chat_id: "-100999"
`,
				wantContain: []string{"123456:stream_test_token", "-100999"},
				wantAbsent:  []string{"\nserver:\n"},
			},
			{
				name: "server_preserves_server_and_telegram_notify",
				initialYAML: `server:
  node_domain: "node.example.com"
  cf_dns_key: "cf-test-token"
notify:
  enabled: true
  channels:
    telegram:
      enabled: true
      bot_token: "654321:server_stream_token"
      chat_id: "888888"
`,
				wantContain: []string{"node.example.com", "654321:server_stream_token", "888888"},
				wantAbsent:  []string{"\nsubs:\n"},
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				workDir := t.TempDir()
				installDir := filepath.Join(workDir, "bin")
				_ = os.MkdirAll(installDir, 0755)
				exePath := filepath.Join(installDir, "singctl")
				_ = os.WriteFile(exePath, []byte("old-binary"), 0755)

				cfgPath := filepath.Join(workDir, "singctl.yaml")
				if err := os.WriteFile(cfgPath, []byte(tc.initialYAML), 0600); err != nil {
					t.Fatal(err)
				}

				// Mock new binary that exits non-zero on internal-migrate so in-process fallback is also exercised cleanly.
				fallbackBin := "#!/bin/sh\nexit 1\n"
				pkgBytes, pkgSHA := buildTestSingCtlTarGz(t, map[string]string{
					"singctl-linux-arm64-lite/singctl": fallbackBin,
				})

				var srvURL string
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					switch r.URL.Path {
					case "/repos/test/singctl/releases/latest":
						_ = json.NewEncoder(w).Encode(release.Info{
							TagName: "v1.14.201",
							Assets: []release.Asset{
								{
									Name:               "singctl-linux-arm64-lite.tar.gz",
									BrowserDownloadURL: srvURL + "/dl/singctl-linux-arm64-lite.tar.gz",
									Size:               int64(len(pkgBytes)),
									Digest:             "sha256:" + pkgSHA,
								},
							},
						})
					case "/dl/singctl-linux-arm64-lite.tar.gz":
						_, _ = w.Write(pkgBytes)
					default:
						http.NotFound(w, r)
					}
				}))
				defer srv.Close()
				srvURL = srv.URL

				u := updater.NewWithDeps("", srv.URL, updater.Deps{
					APIBase:           srv.URL,
					DLBase:            srv.URL,
					HTTPClient:        srv.Client(),
					Repo:              "test/singctl",
					GOOS:              "linux",
					GOARCH:            "arm64",
					IsLite:            &isLite,
					ReadTotalRAMBytes: func() uint64 { return 256 * mib },
					ResolveExePath:    func() (string, error) { return exePath, nil },
				})

				if err := u.UpdateSelf(cfgPath, "v1.14.100"); err != nil {
					t.Fatalf("UpdateSelf streaming with config failed: %v", err)
				}
				afterBytes, err := os.ReadFile(cfgPath)
				if err != nil {
					t.Fatal(err)
				}
				after := string(afterBytes)
				for _, want := range tc.wantContain {
					if !strings.Contains(after, want) {
						t.Fatalf("expected migrated config to contain %q, got:\n%s", want, after)
					}
				}
				for _, forbid := range tc.wantAbsent {
					if strings.Contains(after, forbid) {
						t.Fatalf("expected migrated config NOT to contain %q, got:\n%s", forbid, after)
					}
				}
			})
		}
	})
}
