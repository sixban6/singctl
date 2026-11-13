package webui

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"singctl/internal/config"
)

func TestBuildWatchdogConfigDTO_MatchesModernSingBoxGroups(t *testing.T) {
	dto := buildWatchdogConfigDTO(&config.Config{})

	if dto.Failover.PatrolInterval != 300 {
		t.Fatalf("expected default patrol_interval=300 (5m), got %d", dto.Failover.PatrolInterval)
	}
	if !dto.Failover.IsDefaultGroups {
		t.Fatal("expected zero-value config to report IsDefaultGroups=true")
	}
	for _, legacy := range []string{"Game", "Game-TCP", "Game-UDP"} {
		if slices.Contains(dto.Failover.Groups, legacy) {
			t.Fatalf("legacy removed group %q must not appear in default failover groups: %v", legacy, dto.Failover.Groups)
		}
		if slices.Contains(dto.Failover.DefaultGroups, legacy) {
			t.Fatalf("legacy removed group %q must not appear in default_groups: %v", legacy, dto.Failover.DefaultGroups)
		}
	}
	for _, expected := range []string{"#VPS", "Proxy", "AI", "#Nodes"} {
		if !slices.Contains(dto.Failover.Groups, expected) {
			t.Fatalf("expected core sing-box group %q in default failover groups, got %v", expected, dto.Failover.Groups)
		}
	}
}

func TestHandleWatchdogConfigPut_PersistsAndReloadsFailoverParams(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "singctl.yaml")
	if err := os.WriteFile(cfgPath, []byte("mode: router\nwatchdog:\n  interval: 180\n"), 0600); err != nil {
		t.Fatal(err)
	}

	srv := New(Options{
		ConfigPath: cfgPath,
		Listen:     "127.0.0.1:0",
		Password:   "test-pass-123",
		Version:    "v1.14.105",
	})
	token := srv.SessionToken()

	putBody, _ := json.Marshal(map[string]any{
		"failover": map[string]any{
			"enabled":               true,
			"groups":                []string{"#VPS", "Proxy"},
			"has_groups":            true,
			"patrol_interval":       15,
			"probe_timeout_ms":      2000,
			"confirm_retries":       2,
			"auto_failback":         true,
			"failback_cooldown":     120,
			"max_failback_delay_ms": 450,
		},
	})
	req := httptest.NewRequest(http.MethodPut, "/api/watchdog/config", bytes.NewReader(putBody))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.Mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected PUT /api/watchdog/config 200, got %d: %s", rec.Code, rec.Body.String())
	}

	loaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Watchdog.Failover.PatrolInterval != 15 {
		t.Fatalf("expected patrol_interval=15 persisted, got %d", loaded.Watchdog.Failover.PatrolInterval)
	}
	if loaded.Watchdog.Failover.ProbeTimeoutMs != 2000 {
		t.Fatalf("expected probe_timeout_ms=2000 persisted, got %d", loaded.Watchdog.Failover.ProbeTimeoutMs)
	}
	if loaded.Watchdog.Failover.ConfirmRetries != 2 {
		t.Fatalf("expected confirm_retries=2 persisted, got %d", loaded.Watchdog.Failover.ConfirmRetries)
	}
	if !slices.Equal(loaded.Watchdog.Failover.Groups, []string{"#VPS", "Proxy"}) {
		t.Fatalf("expected groups [#VPS Proxy], got %v", loaded.Watchdog.Failover.Groups)
	}

	// Verify subsequent GET /api/watchdog returns the persisted values.
	getReq := httptest.NewRequest(http.MethodGet, "/api/watchdog", nil)
	getReq.Header.Set("Authorization", "Bearer "+token)
	getRec := httptest.NewRecorder()
	srv.Mux.ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("expected GET /api/watchdog 200, got %d", getRec.Code)
	}
	var report struct {
		Config struct {
			Failover struct {
				PatrolInterval int      `json:"patrol_interval"`
				ProbeTimeoutMs int      `json:"probe_timeout_ms"`
				ConfirmRetries int      `json:"confirm_retries"`
				Groups         []string `json:"groups"`
			} `json:"failover"`
		} `json:"config"`
	}
	if err := json.Unmarshal(getRec.Body.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.Config.Failover.PatrolInterval != 15 || report.Config.Failover.ProbeTimeoutMs != 2000 || report.Config.Failover.ConfirmRetries != 2 {
		t.Fatalf("GET /api/watchdog returned mismatched values: %+v", report.Config.Failover)
	}
}
