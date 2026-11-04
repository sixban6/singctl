package singbox

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"singctl/internal/config"
)

func TestGenerator_MultiSubscription_PartialFailure(t *testing.T) {
	// Server 1: returns HTML error (0 nodes)
	tsHTML := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<!DOCTYPE html><html><body>Login Error</body></html>"))
	}))
	defer tsHTML.Close()

	// Server 2: Closed server (connection refused)
	tsClosed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	closedURL := tsClosed.URL
	tsClosed.Close()

	// Server 3: returns valid base64 subscription node
	tsValid := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		// hysteria2://dummy-user:dummy-pass@mock-node.example.com:443?sni=mock-node.example.com#sec_mock_hy2
		w.Write([]byte("aHlzdGVyaWEyOi8vZHVtbXktdXNlcjpkdW1teS1wYXNzQG1vY2stbm9kZS5leGFtcGxlLmNvbTo0NDM/c25pPW1vY2stbm9kZS5leGFtcGxlLmNvbSNzZWNfbW9ja19oeTI="))
	}))
	defer tsValid.Close()

	cfg := &config.Config{
		Subs: []config.Subscription{
			{Name: "sub_html", URL: tsHTML.URL},
			{Name: "sub_closed", URL: closedURL},
			{Name: "sub_valid", URL: tsValid.URL},
		},
	}

	generator := NewConfigGenerator(cfg)
	generator.SetCacheDir(t.TempDir())
	res, err := generator.GenerateForPlatform("linux")
	if err != nil {
		t.Fatalf("expected generation to succeed by skipping failed subs, got error: %v", err)
	}

	if !strings.Contains(res, "sub_valid") && !strings.Contains(res, "mock-node.example.com") {
		t.Fatalf("generated config should contain nodes from valid sub, got: %s", res)
	}
}

func TestGenerator_MultiSubscription_AllFail(t *testing.T) {
	tsHTML1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<!DOCTYPE html><html><body>Error 1</body></html>"))
	}))
	defer tsHTML1.Close()

	tsHTML2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<!DOCTYPE html><html><body>Error 2</body></html>"))
	}))
	defer tsHTML2.Close()

	cfg := &config.Config{
		Subs: []config.Subscription{
			{Name: "bad_sub1", URL: tsHTML1.URL},
			{Name: "bad_sub2", URL: tsHTML2.URL},
		},
	}

	generator := NewConfigGenerator(cfg)
	generator.SetCacheDir(t.TempDir())
	_, err := generator.GenerateForPlatform("linux")
	if err == nil {
		t.Fatal("expected error when all subscriptions fail, got nil")
	}

	errMsg := err.Error()
	if !strings.Contains(errMsg, "bad_sub1") || !strings.Contains(errMsg, "bad_sub2") {
		t.Fatalf("error message should identify each failed subscription name, got: %s", errMsg)
	}
}

func TestGenerator_SingleSubscription_Failure(t *testing.T) {
	tsHTML := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<!DOCTYPE html><html><body>Error</body></html>"))
	}))
	defer tsHTML.Close()

	cfg := &config.Config{
		Subs: []config.Subscription{
			{Name: "single_bad", URL: tsHTML.URL},
		},
	}

	generator := NewConfigGenerator(cfg)
	generator.SetCacheDir(t.TempDir())
	_, err := generator.GenerateForPlatform("linux")
	if err == nil {
		t.Fatal("expected error when single subscription fails, got nil")
	}

	if !strings.Contains(err.Error(), "single_bad") {
		t.Fatalf("error message should identify subscription name, got: %v", err)
	}
}

func TestGenerator_ZeroSubscriptions(t *testing.T) {
	cfg := &config.Config{
		Subs: []config.Subscription{},
	}

	generator := NewConfigGenerator(cfg)
	generator.SetCacheDir(t.TempDir())
	_, err := generator.GenerateForPlatform("linux")
	if err == nil {
		t.Fatal("expected error when subs is empty, got nil")
	}
}

func encodeURISub(lines ...string) string {
	return base64.StdEncoding.EncodeToString([]byte(strings.Join(lines, "\n")))
}

func TestGenerator_SingleAndMultiNodeRules(t *testing.T) {
	payload := encodeURISub(
		"hysteria2://dummy-pass@us1.example.com:443?sni=us1.example.com#US-Node Premium",
		"hysteria2://dummy-pass@jp1.example.com:443?sni=jp1.example.com#JP-Node Premium",
		"hysteria2://dummy-pass@192.0.2.10:443?sni=info.example.com#剩余流量 10GB",
	)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(payload))
	}))
	defer ts.Close()

	t.Run("single subscription include exclude rename", func(t *testing.T) {
		cfg := &config.Config{
			Subs: []config.Subscription{
				{
					Name:    "main",
					URL:     ts.URL,
					Include: "US|JP",
					Exclude: "剩余|到期",
					Rename: []config.RenameRule{
						{Match: ` Premium$`, Replace: ""},
						{Match: `^US-`, Replace: "美国-"},
					},
				},
			},
		}
		gen := NewConfigGenerator(cfg)
		gen.SetCacheDir(t.TempDir())
		out, err := gen.GenerateForPlatform("darwin")
		if err != nil {
			t.Fatalf("GenerateForPlatform failed: %v", err)
		}
		if !strings.Contains(out, "美国-Node") || !strings.Contains(out, "JP-Node") {
			t.Fatalf("expected renamed/kept tags in output, got:\n%s", out)
		}
		if strings.Contains(out, "Premium") || strings.Contains(out, "剩余流量") {
			t.Fatalf("expected excluded/renamed tags to be absent, got:\n%s", out)
		}
	})

	t.Run("multi subscription rules and all filtered out error", func(t *testing.T) {
		cfg := &config.Config{
			Subs: []config.Subscription{
				{
					Name:    "filtered_all",
					URL:     ts.URL,
					Include: "NON_EXISTENT_REGION",
				},
				{
					Name:    "kept_sub",
					URL:     ts.URL,
					Include: "^JP-",
					Rename:  []config.RenameRule{{Match: ` Premium$`, Replace: ""}},
				},
			},
		}
		gen := NewConfigGenerator(cfg)
		gen.SetCacheDir(t.TempDir())
		out, err := gen.GenerateForPlatform("darwin")
		if err != nil {
			t.Fatalf("expected partial success when one sub is filtered out, got: %v", err)
		}
		if !strings.Contains(out, "[kept_sub] JP-Node") {
			t.Fatalf("expected [kept_sub] JP-Node in output, got:\n%s", out)
		}
		if strings.Contains(out, "[filtered_all]") || strings.Contains(out, "us1.example.com") {
			t.Fatalf("unexpected filtered nodes in output:\n%s", out)
		}

		allFilteredCfg := &config.Config{
			Subs: []config.Subscription{
				{Name: "sub1", URL: ts.URL, Include: "NO_MATCH_1"},
				{Name: "sub2", URL: ts.URL, Include: "NO_MATCH_2"},
			},
		}
		genFail := NewConfigGenerator(allFilteredCfg)
		genFail.SetCacheDir(t.TempDir())
		_, err = genFail.GenerateForPlatform("darwin")
		if err == nil || !strings.Contains(err.Error(), "sub1") || !strings.Contains(err.Error(), "sub2") {
			t.Fatalf("expected detailed error listing filtered-out subs, got: %v", err)
		}
	})
}

func TestGenerator_SubscriptionCacheFallback(t *testing.T) {
	payload := encodeURISub(
		"hysteria2://dummy-pass@hk1.example.com:443?sni=hk1.example.com#HK-Primary",
	)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Subscription-Userinfo", "upload=1073741824; download=8589934592; total=10737418240; expire=1893456000")
		_, _ = w.Write([]byte(payload))
	}))
	subURL := ts.URL

	cacheDir := t.TempDir()
	cfg := &config.Config{
		Subs: []config.Subscription{
			{Name: "cached_main", URL: subURL},
		},
	}

	gen := NewConfigGenerator(cfg)
	gen.SetCacheDir(cacheDir)

	firstOut, err := gen.GenerateForPlatform("darwin")
	if err != nil {
		ts.Close()
		t.Fatalf("initial GenerateForPlatform failed: %v", err)
	}
	if !strings.Contains(firstOut, "hk1.example.com") {
		ts.Close()
		t.Fatalf("initial output missing hk1.example.com")
	}

	entries, err := os.ReadDir(cacheDir)
	if err != nil || len(entries) == 0 {
		ts.Close()
		t.Fatalf("expected subscription cache file in %s, entries=%d err=%v", cacheDir, len(entries), err)
	}
	fi, err := entries[0].Info()
	if err != nil {
		ts.Close()
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0600 {
		ts.Close()
		t.Fatalf("expected cache file mode 0600, got %o", perm)
	}

	// Shut down upstream server completely; second generation must succeed via cached copy.
	ts.Close()
	secondOut, err := gen.GenerateForPlatform("darwin")
	if err != nil {
		t.Fatalf("expected fallback to cached subscription after upstream outage, got error: %v", err)
	}
	if !strings.Contains(secondOut, "hk1.example.com") {
		t.Fatalf("cached fallback output missing hk1.example.com")
	}
}

func TestGenerator_PlatformExternalControllerAndSingBoxCheck(t *testing.T) {
	payload := encodeURISub(
		"hysteria2://dummy-pass@sg1.example.com:443?sni=sg1.example.com#SG-Node",
	)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(payload))
	}))
	defer ts.Close()

	cfg := &config.Config{
		Subs: []config.Subscription{
			{Name: "main", URL: ts.URL, RemoveEmoji: true},
		},
	}
	gen := NewConfigGenerator(cfg)
	gen.SetCacheDir(t.TempDir())

	sbBin, hasSingBox := exec.LookPath("sing-box")

	cases := []struct {
		platform       string
		wantController string
	}{
		{platform: PlatformIOS, wantController: "127.0.0.1:9095"},
		{platform: "darwin", wantController: "127.0.0.1:9090"},
		{platform: "windows", wantController: "127.0.0.1:9090"},
	}

	for _, tc := range cases {
		t.Run(tc.platform, func(t *testing.T) {
			out, err := gen.GenerateForPlatform(tc.platform)
			if err != nil {
				t.Fatalf("GenerateForPlatform(%s) failed: %v", tc.platform, err)
			}

			var parsed struct {
				Experimental struct {
					ClashAPI struct {
						ExternalController string `json:"external_controller"`
					} `json:"clash_api"`
				} `json:"experimental"`
			}
			if err := json.Unmarshal([]byte(out), &parsed); err != nil {
				t.Fatalf("unmarshal generated JSON: %v", err)
			}
			if parsed.Experimental.ClashAPI.ExternalController != tc.wantController {
				t.Fatalf("%s external_controller = %q, want %q",
					tc.platform, parsed.Experimental.ClashAPI.ExternalController, tc.wantController)
			}

			if tc.platform == PlatformIOS {
				if err := CheckIOSCompatibility(out); err != nil {
					t.Fatalf("CheckIOSCompatibility failed: %v", err)
				}
			}

			if hasSingBox == nil && sbBin != "" {
				cfgFile := filepath.Join(t.TempDir(), "config.json")
				if err := os.WriteFile(cfgFile, []byte(out), 0600); err != nil {
					t.Fatal(err)
				}
				cmd := exec.CommandContext(t.Context(), sbBin, "check", "-c", cfgFile)
				if checkOut, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("sing-box check failed for platform %s: %v\n%s", tc.platform, err, string(checkOut))
				}
			}
		})
	}
}
