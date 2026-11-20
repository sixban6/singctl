package webui

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"singctl/internal/tailscale"
)

func TestTailscaleUpgradeAPI_PreflightViaTailscaleAndLAN(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "singctl.yaml")
	if err := os.WriteFile(cfgPath, []byte("subs: []\n"), 0600); err != nil {
		t.Fatal(err)
	}

	srv := New(Options{
		ConfigPath: cfgPath,
		Version:    "v1.14.146-test",
		TailscaleUpgradeForTest: &TailscaleUpgradeTestHooks{
			Preflight: func(ctx context.Context) (*tailscale.UpgradePreflight, error) {
				return &tailscale.UpgradePreflight{
					Supported:             true,
					Arch:                  "arm64",
					IsOpenWrt:             true,
					InitSystem:            "procd",
					CurrentVersion:        "1.94.2",
					LatestVersion:         "1.104.7",
					CombinedMinimal:       true,
					HasOfficialDigest:     true,
					FlashFreeBytes:        64 << 20,
					MemAvailableBytes:     72 << 20,
					EstimatedInstallBytes: 16 << 20,
					RequiredFreeBytes:     20 << 20,
					TailscaleRunning:      true,
					BackendState:          "Running",
					CanProceed:            true,
					CanForceProceed:       true,
				}, nil
			},
			ReadState: func() (*tailscale.UpgradeState, error) {
				return &tailscale.UpgradeState{Phase: tailscale.UpgradePhaseIdle}, nil
			},
		},
	})

	cases := []struct {
		name         string
		remoteAddr   string
		wantTSAccess bool
	}{
		{name: "TailscaleIPv4", remoteAddr: "100.64.200.15:54321", wantTSAccess: true},
		{name: "TailscaleIPv6", remoteAddr: "[fd7a:115c:a1e0::1]:54321", wantTSAccess: true},
		{name: "LANIPv4", remoteAddr: "192.168.1.5:54321", wantTSAccess: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/tailscale/upgrade/preflight", nil)
			req.RemoteAddr = tc.remoteAddr
			rec := httptest.NewRecorder()
			srv.Mux.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("GET preflight status=%d body=%s", rec.Code, rec.Body.String())
			}
			var got tailscale.UpgradePreflight
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatalf("decode preflight: %v", err)
			}
			if got.ViaTailscale != tc.wantTSAccess {
				t.Fatalf("remoteAddr=%q: got viaTailscale=%v, want %v", tc.remoteAddr, got.ViaTailscale, tc.wantTSAccess)
			}
			if !got.CanProceed || !got.CombinedMinimal || got.LatestVersion != "1.104.7" {
				t.Fatalf("unexpected preflight payload: %+v", got)
			}
		})
	}
}

func TestTailscaleUpgradeAPI_StatusIdleAndRolledBack(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "singctl.yaml")
	if err := os.WriteFile(cfgPath, []byte("subs: []\n"), 0600); err != nil {
		t.Fatal(err)
	}
	paths := tailscale.UpgradePaths{
		StateFile: filepath.Join(dir, "upgrade.state"),
		LogFile:   filepath.Join(dir, "upgrade.log"),
	}

	srv := New(Options{
		ConfigPath: cfgPath,
		TailscaleUpgradeForTest: &TailscaleUpgradeTestHooks{
			Paths: paths,
			StatusFn: func(string) map[string]any {
				return map[string]any{"installed": true, "running": true, "state": "Running", "version": "1.94.2"}
			},
		},
	})

	// 1. Missing state file -> idle
	req1 := httptest.NewRequest(http.MethodGet, "/api/tailscale/upgrade/status", nil)
	rec1 := httptest.NewRecorder()
	srv.Mux.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusOK {
		t.Fatalf("status idle HTTP=%d body=%s", rec1.Code, rec1.Body.String())
	}
	var resp1 struct {
		State     tailscale.UpgradeState `json:"state"`
		Tailscale map[string]any         `json:"tailscale"`
	}
	if err := json.Unmarshal(rec1.Body.Bytes(), &resp1); err != nil {
		t.Fatal(err)
	}
	if resp1.State.Phase != tailscale.UpgradePhaseIdle {
		t.Fatalf("expected idle phase, got %q", resp1.State.Phase)
	}

	// 2. Rolled back state + log tail
	if err := os.WriteFile(paths.LogFile, []byte("[ROLLBACK] restored 1.94.2\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := tailscale.WriteUpgradeState(paths, &tailscale.UpgradeState{
		Phase:       tailscale.UpgradePhaseRolledBack,
		FromVersion: "1.94.2",
		ToVersion:   "1.104.8",
		RolledBack:  true,
		Error:       "health timeout",
	}); err != nil {
		t.Fatal(err)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/api/tailscale/upgrade/status", nil)
	rec2 := httptest.NewRecorder()
	srv.Mux.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("status rolled_back HTTP=%d body=%s", rec2.Code, rec2.Body.String())
	}
	var resp2 struct {
		State     tailscale.UpgradeState `json:"state"`
		Tailscale map[string]any         `json:"tailscale"`
	}
	if err := json.Unmarshal(rec2.Body.Bytes(), &resp2); err != nil {
		t.Fatal(err)
	}
	if resp2.State.Phase != tailscale.UpgradePhaseRolledBack || !resp2.State.RolledBack || !strings.Contains(resp2.State.LogTail, "restored 1.94.2") {
		t.Fatalf("unexpected rolled_back response: %+v", resp2.State)
	}
}

func TestRunner_TsUpdateArgsAndSwapHandoffMarker(t *testing.T) {
	if got := TsUpdateArgs(nil); !slices.Equal(got, []string{"ts", "update", "--no-wait"}) {
		t.Fatalf("TsUpdateArgs(nil) = %v", got)
	}
	if got := TsUpdateArgs(map[string]any{"force": true}); !slices.Equal(got, []string{"ts", "update", "--no-wait", "--force"}) {
		t.Fatalf("TsUpdateArgs(force=true) = %v", got)
	}

	rec := httptest.NewRecorder()
	nw := NewNDJSONWriter(rec)
	_, _ = nw.Write([]byte("2026/11/20 [INFO] " + tailscale.TailscaleSwapHandoffMarker + " pid=42 log=/tmp/x.log\n"))
	_, _ = nw.Write([]byte("2026/11/20 [SUCCESS] 已安全移交后台切换进程\n"))
	if !nw.sawTailscaleSwapHandoff {
		t.Fatalf("expected sawTailscaleSwapHandoff=true")
	}
	if strings.Contains(rec.Body.String(), tailscale.TailscaleSwapHandoffMarker) {
		t.Fatalf("expected internal marker suppressed from user NDJSON output, got %s", rec.Body.String())
	}
}
