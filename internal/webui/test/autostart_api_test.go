// 文件职责：验证客户端 WebUI 开机自启动与掉电恢复开关 API（GET/PUT /api/system/autostart）、0600 原子持久化、鉴权与 /api/status 摘要暴露。
package webui_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"singctl/internal/config"
	"singctl/internal/daemon"
	"singctl/internal/platform/servicemgr"
	"singctl/internal/webui"
)

func TestAutoStartAPI_GetTogglePersistAndRace(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "singctl.yaml")
	if err := config.Save(cfgPath, &config.Config{}); err != nil {
		t.Fatal(err)
	}

	mockMgr := servicemgr.NewMock()
	srv := webui.New(webui.Options{
		ConfigPath:          cfgPath,
		ExecutablePath:      "/usr/bin/singctl",
		AutoStartServiceMgr: mockMgr,
	})

	doReq := func(method, path string, body any) *httptest.ResponseRecorder {
		var buf bytes.Buffer
		if body != nil {
			_ = json.NewEncoder(&buf).Encode(body)
		}
		req := httptest.NewRequest(method, path, &buf)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		srv.Mux.ServeHTTP(rec, req)
		return rec
	}

	// 1. Initial GET returns configEnabled=true by default
	rec := doReq(http.MethodGet, "/api/system/autostart", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/system/autostart status=%d body=%s", rec.Code, rec.Body.String())
	}
	var st daemon.AutoStartStatus
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatalf("decode GET /api/system/autostart failed: %v", err)
	}
	if !st.Supported || !st.ConfigEnabled || st.ServiceName != daemon.AutoStartServiceName {
		t.Fatalf("unexpected initial autoStart status: %+v", st)
	}

	// 2. PUT {"enabled": true} installs + enables unit and persists auto_start: true
	rec = doReq(http.MethodPut, "/api/system/autostart", map[string]any{"enabled": true})
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT enable failed: code=%d body=%s", rec.Code, rec.Body.String())
	}
	var putResp struct {
		OK      bool                   `json:"ok"`
		Message string                 `json:"message"`
		Status  daemon.AutoStartStatus `json:"status"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &putResp); err != nil {
		t.Fatalf("decode PUT enable response failed: %v", err)
	}
	if !putResp.OK || !putResp.Status.Enabled || !putResp.Status.ServiceEnabled || !putResp.Status.ServiceInstalled {
		t.Fatalf("expected enabled status after PUT true, got %+v", putResp)
	}

	// 3. PUT {"enabled": false} removes unit, persists auto_start: false with 0600, and updates Store snapshot
	rec = doReq(http.MethodPut, "/api/system/autostart", map[string]any{"enabled": false})
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT disable failed: code=%d body=%s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &putResp); err != nil {
		t.Fatalf("decode PUT disable response failed: %v", err)
	}
	if !putResp.OK || putResp.Status.Enabled || putResp.Status.ConfigEnabled || putResp.Status.ServiceEnabled {
		t.Fatalf("expected disabled status after PUT false, got %+v", putResp)
	}

	fi, err := os.Stat(cfgPath)
	if err != nil || fi.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 permissions on singctl.yaml, got %v (err=%v)", fi.Mode().Perm(), err)
	}
	loaded, err := config.Load(cfgPath)
	if err != nil || loaded.Watchdog.IsAutoStartEnabled() {
		t.Fatalf("expected disk config Watchdog.IsAutoStartEnabled()==false, err=%v val=%v", err, loaded.Watchdog.IsAutoStartEnabled())
	}
	if srv.ConfigStore().Get().Watchdog.IsAutoStartEnabled() {
		t.Fatalf("expected in-memory ConfigStore snapshot updated to false immediately")
	}

	// 4. Re-enable and verify GET /api/status exposes autoStart summary
	rec = doReq(http.MethodPut, "/api/system/autostart", map[string]any{"enabled": true})
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT re-enable failed: code=%d body=%s", rec.Code, rec.Body.String())
	}
	rec = doReq(http.MethodGet, "/api/status", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/status failed: code=%d body=%s", rec.Code, rec.Body.String())
	}
	var statusPayload struct {
		AutoStart *daemon.AutoStartStatus `json:"autoStart"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &statusPayload); err != nil || statusPayload.AutoStart == nil {
		t.Fatalf("expected autoStart in /api/status, err=%v body=%s", err, rec.Body.String())
	}
	if !statusPayload.AutoStart.Enabled {
		t.Fatalf("expected autoStart.Enabled==true in /api/status, got %+v", statusPayload.AutoStart)
	}

	// 5. Validation guards: empty object and malformed JSON return 400
	if badRec := doReq(http.MethodPut, "/api/system/autostart", map[string]any{}); badRec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing enabled field, got %d", badRec.Code)
	}
	rawReq := httptest.NewRequest(http.MethodPut, "/api/system/autostart", bytes.NewBufferString("{bad"))
	rawReq.Header.Set("Content-Type", "application/json")
	rawRec := httptest.NewRecorder()
	srv.Mux.ServeHTTP(rawRec, rawReq)
	if rawRec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for malformed JSON, got %d", rawRec.Code)
	}

	// 6. Auth guard when password is set
	authSrv := webui.New(webui.Options{
		ConfigPath:          cfgPath,
		Password:            "secret-pass",
		ExecutablePath:      "/usr/bin/singctl",
		AutoStartServiceMgr: servicemgr.NewMock(),
	})
	unauthReq := httptest.NewRequest(http.MethodGet, "/api/system/autostart", nil)
	unauthRec := httptest.NewRecorder()
	authSrv.Mux.ServeHTTP(unauthRec, unauthReq)
	if unauthRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unauthenticated GET /api/system/autostart, got %d", unauthRec.Code)
	}

	// 7. Concurrent GET + PUT race check
	var wg sync.WaitGroup
	for i := range 6 {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			if idx%2 == 0 {
				r := doReq(http.MethodGet, "/api/system/autostart", nil)
				if r.Code != http.StatusOK {
					t.Errorf("concurrent GET returned %d", r.Code)
				}
			} else {
				r := doReq(http.MethodPut, "/api/system/autostart", map[string]any{"enabled": idx == 1})
				if r.Code != http.StatusOK {
					t.Errorf("concurrent PUT returned %d", r.Code)
				}
			}
		}(i)
	}
	wg.Wait()
}
