// 文件职责：覆盖 webui 配置修改事务回滚（updateConfigTx）、Options 显式依赖注入、实例级 actionBusy 隔离与脱敏测试。
package webui_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"singctl/internal/config"
	"singctl/internal/webui"
)

func TestOptionsDI_IOSGenerator_StoreSnapshot_And_Redaction(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "singctl.yaml")
	initialYAML := "subs:\n  - name: main\n    url: https://sub.example.com/api/v1/client/subscribe?token=supersecret123\nhy2:\n  up: 30\n  down: 300\n"
	if err := os.WriteFile(cfgPath, []byte(initialYAML), 0600); err != nil {
		t.Fatal(err)
	}

	srv := webui.New(webui.Options{
		ConfigPath:              cfgPath,
		SkipAdGuardProbeForTest: true,
		IOSGenerator: func(cfg *config.Config) (string, error) {
			return "", errors.New("upstream failed: https://sub.example.com/api/v1/client/subscribe?token=supersecret123")
		},
	})

	if srv.ConfigStore() == nil {
		t.Fatal("expected ConfigStore() initialized on Server")
	}
	snap1, err := srv.LoadConfigSnapshot()
	if err != nil || snap1.Hy2.Up != 30 {
		t.Fatalf("LoadConfigSnapshot = (%+v, %v)", snap1, err)
	}

	// Verify /api/gen/ios uses injected Options.IOSGenerator AND redacts subscription URL query token in error output
	reqIOS := httptest.NewRequest(http.MethodGet, "/api/gen/ios", nil)
	recIOS := httptest.NewRecorder()
	srv.Mux.ServeHTTP(recIOS, reqIOS)
	if recIOS.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on IOSGenerator error, got %d", recIOS.Code)
	}
	if strings.Contains(recIOS.Body.String(), "supersecret123") {
		t.Fatalf("expected subscription token redacted in error response, got %s", recIOS.Body.String())
	}
}

func TestUpdateConfigTx_RollsBackOnLiveApplyFailure(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "singctl.yaml")
	sbPath := filepath.Join(dir, "config.json")
	origYAML := "subs: []\nhy2:\n  up: 50\n  down: 500\n"
	if err := os.WriteFile(cfgPath, []byte(origYAML), 0600); err != nil {
		t.Fatal(err)
	}
	// Invalid sing-box JSON triggers live-apply failure in PUT /api/traffic-routing, which must roll back singctl.yaml!
	if err := os.WriteFile(sbPath, []byte("{not-valid-json"), 0600); err != nil {
		t.Fatal(err)
	}

	srv := webui.New(webui.Options{
		ConfigPath:              cfgPath,
		SingBoxConfigPath:       sbPath,
		SkipAdGuardProbeForTest: true,
	})

	req := httptest.NewRequest(http.MethodPut, "/api/traffic-routing", bytes.NewBufferString(`{"reset":true}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.Mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on corrupted live config.json, got %d: %s", rec.Code, rec.Body.String())
	}

	diskAfter, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(diskAfter) != origYAML {
		t.Fatalf("expected updateConfigTx to roll back exact singctl.yaml bytes:\ngot:  %q\nwant: %q", string(diskAfter), origYAML)
	}
}

func TestServer_InstanceScopedActionBusyLock(t *testing.T) {
	dir := t.TempDir()
	slowExe := filepath.Join(dir, "fake-singctl")
	script := "#!/bin/sh\nsleep 0.25\necho 'done'\n"
	if err := os.WriteFile(slowExe, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}

	srvA := webui.New(webui.Options{
		ConfigPath:     filepath.Join(dir, "a.yaml"),
		ExecutablePath: slowExe,
	})
	srvB := webui.New(webui.Options{
		ConfigPath:     filepath.Join(dir, "b.yaml"),
		ExecutablePath: slowExe,
	})

	// Concurrent actions on DIFFERENT Server instances must BOTH succeed (200), proving busyFlag is instance-scoped!
	var wg sync.WaitGroup
	codes := make([]int, 2)
	for idx, s := range []*webui.Server{srvA, srvB} {
		wg.Add(1)
		go func(i int, srv *webui.Server) {
			defer wg.Done()
			payload, _ := json.Marshal(map[string]any{"name": "sb-stop"})
			req := httptest.NewRequest(http.MethodPost, "/api/action", bytes.NewReader(payload))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			srv.Mux.ServeHTTP(rec, req)
			codes[i] = rec.Code
		}(idx, s)
	}
	wg.Wait()
	if codes[0] != http.StatusOK || codes[1] != http.StatusOK {
		t.Fatalf("expected both isolated Server instances to execute actions concurrently (200, 200), got %v", codes)
	}
}
