// 文件职责：验证客户端 WebUI 核心组件自动更新开关 API（GET/PUT /api/system/auto-update）的默认全关契约、局部持久化、参数校验、鉴权与并发安全。
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
	"singctl/internal/webui"
)

type autoUpdateComponentResp struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Enabled        bool   `json:"enabled"`
	Installed      bool   `json:"installed"`
	CurrentVersion string `json:"currentVersion"`
	Status         string `json:"status"`
}

type autoUpdateStatusResp struct {
	SingCtl       bool                      `json:"singctl"`
	SingBox       bool                      `json:"singbox"`
	AdGuardHome   bool                      `json:"adguardHome"`
	Tailscale     bool                      `json:"tailscale"`
	IntervalHours int                       `json:"intervalHours"`
	DaemonRunning bool                      `json:"daemonRunning"`
	Components    []autoUpdateComponentResp `json:"components"`
}

func TestAutoUpdateAPI_DefaultOffTogglePersistAndValidation(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "singctl.yaml")
	if err := config.Save(cfgPath, &config.Config{}); err != nil {
		t.Fatal(err)
	}

	srv := webui.New(webui.Options{
		ConfigPath:              cfgPath,
		Version:                 "v1.14.206",
		SkipAdGuardProbeForTest: true,
	})

	doReq := func(method, path string, rawBody []byte) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, bytes.NewReader(rawBody))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		srv.Mux.ServeHTTP(rec, req)
		return rec
	}

	// 1. Initial GET returns all 4 toggles OFF and default 24h interval
	rec := doReq(http.MethodGet, "/api/system/auto-update", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/system/auto-update status=%d body=%s", rec.Code, rec.Body.String())
	}
	var st autoUpdateStatusResp
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatalf("decode GET response: %v", err)
	}
	if st.SingCtl || st.SingBox || st.AdGuardHome || st.Tailscale {
		t.Fatalf("expected all 4 auto-update toggles default OFF, got %+v", st)
	}
	if st.IntervalHours != 24 {
		t.Fatalf("expected default intervalHours=24, got %d", st.IntervalHours)
	}
	if len(st.Components) != 4 {
		t.Fatalf("expected 4 components in response, got %d: %+v", len(st.Components), st.Components)
	}

	// 2. PUT partial toggle {"singbox": true} persists 0600 and preserves other 3 as false
	rec = doReq(http.MethodPut, "/api/system/auto-update", []byte(`{"singbox":true}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT singbox=true failed: status=%d body=%s", rec.Code, rec.Body.String())
	}
	var putResp struct {
		OK      bool                 `json:"ok"`
		Message string               `json:"message"`
		Status  autoUpdateStatusResp `json:"status"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &putResp); err != nil {
		t.Fatalf("decode PUT response: %v", err)
	}
	if !putResp.OK || !putResp.Status.SingBox || putResp.Status.SingCtl || putResp.Status.AdGuardHome || putResp.Status.Tailscale {
		t.Fatalf("unexpected PUT singbox=true status: %+v", putResp.Status)
	}

	fi, err := os.Stat(cfgPath)
	if err != nil || fi.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 permissions on %s, got err=%v mode=%o", cfgPath, err, fi.Mode().Perm())
	}

	// 3. PUT second partial update preserves singbox=true and enables singctl + adguardHome + tailscale + 12h
	rec = doReq(http.MethodPut, "/api/system/auto-update", []byte(`{"singctl":true,"adguardHome":true,"tailscale":true,"intervalHours":12}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT multi failed: status=%d body=%s", rec.Code, rec.Body.String())
	}
	loaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("load saved config: %v", err)
	}
	au := loaded.Watchdog.AutoUpdate
	if !au.SingCtl || !au.SingBox || !au.AdGuardHome || !au.Tailscale || au.IntervalHours != 12 {
		t.Fatalf("unexpected persisted AutoUpdate: %+v", au)
	}
	if !srv.ConfigStore().Get().Watchdog.AutoUpdate.SingCtl {
		t.Fatal("expected ConfigStore snapshot updated immediately")
	}

	// 4. Invalid payloads rejected with 400 Bad Request
	badPayloads := []string{
		`{invalid`,
		`{}`,
		`{"intervalHours": -1}`,
		`{"intervalHours": 3}`,
		`{"intervalHours": 169}`,
	}
	for _, raw := range badPayloads {
		badRec := doReq(http.MethodPut, "/api/system/auto-update", []byte(raw))
		if badRec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for payload %s, got %d body=%s", raw, badRec.Code, badRec.Body.String())
		}
	}

	// 5. Turn all 4 off & reset interval -> cleans disk state
	rec = doReq(http.MethodPut, "/api/system/auto-update", []byte(`{"singctl":false,"singbox":false,"adguardHome":false,"tailscale":false,"intervalHours":0}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT all-off failed: status=%d body=%s", rec.Code, rec.Body.String())
	}
	loadedOff, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("load cleared config: %v", err)
	}
	if loadedOff.Watchdog.AutoUpdate.AnyEnabled() || !loadedOff.Watchdog.AutoUpdate.IsEmpty() {
		t.Fatalf("expected all-off cleared AutoUpdate, got %+v", loadedOff.Watchdog.AutoUpdate)
	}
}

func TestAutoUpdateAPI_AuthGuardAndConcurrentRace(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "singctl.yaml")
	if err := config.Save(cfgPath, &config.Config{}); err != nil {
		t.Fatal(err)
	}

	srv := webui.New(webui.Options{
		ConfigPath:              cfgPath,
		Password:                "test-secret-password",
		Version:                 "v1.14.206",
		SkipAdGuardProbeForTest: true,
	})

	// Unauthenticated requests blocked with 401
	for _, method := range []string{http.MethodGet, http.MethodPut} {
		req := httptest.NewRequest(method, "/api/system/auto-update", bytes.NewReader([]byte(`{"singbox":true}`)))
		rec := httptest.NewRecorder()
		srv.Mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s without auth: expected 401, got %d", method, rec.Code)
		}
	}

	// Concurrent authenticated GET/PUT storm under -race
	token := srv.SessionToken()
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			var req *http.Request
			if idx%2 == 0 {
				req = httptest.NewRequest(http.MethodGet, "/api/system/auto-update", nil)
			} else {
				body := `{"singbox":true}`
				if idx%4 == 1 {
					body = `{"singbox":false}`
				}
				req = httptest.NewRequest(http.MethodPut, "/api/system/auto-update", bytes.NewReader([]byte(body)))
				req.Header.Set("Content-Type", "application/json")
			}
			req.Header.Set("Authorization", "Bearer "+token)
			rec := httptest.NewRecorder()
			srv.Mux.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Errorf("concurrent req %d unexpected status %d: %s", idx, rec.Code, rec.Body.String())
			}
		}(i)
	}
	wg.Wait()
}
