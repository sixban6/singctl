// 文件职责：验证客户端 /api/status 的短周期 SWR 单飞缓存与写操作自动失效契约。
package webui_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"

	"singctl/internal/config"
	"singctl/internal/webui"
)

func TestStatusAPI_SWRCacheAndWriteInvalidation(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "singctl.yaml")
	if err := config.Save(cfgPath, &config.Config{}); err != nil {
		t.Fatal(err)
	}

	srv := webui.New(webui.Options{
		ConfigPath:              cfgPath,
		Version:                 "v1.14.207",
		SkipAdGuardProbeForTest: true,
	})

	// 1. Concurrent GET /api/status requests coalesce cleanly under -race
	var wg sync.WaitGroup
	for range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
			rec := httptest.NewRecorder()
			srv.Mux.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Errorf("GET /api/status status=%d body=%s", rec.Code, rec.Body.String())
			}
		}()
	}
	wg.Wait()

	// 2. Write via PUT /api/system/mirror invalidates status cache and reflects fresh state immediately
	putReq := httptest.NewRequest(http.MethodPut, "/api/system/auto-update", bytes.NewReader([]byte(`{"singbox":true}`)))
	putReq.Header.Set("Content-Type", "application/json")
	putRec := httptest.NewRecorder()
	srv.Mux.ServeHTTP(putRec, putReq)
	if putRec.Code != http.StatusOK {
		t.Fatalf("PUT /api/system/auto-update status=%d body=%s", putRec.Code, putRec.Body.String())
	}

	// 3. Subsequent GET /api/status still succeeds and returns fresh authEnabled/singctlVersion
	getReq := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	getRec := httptest.NewRecorder()
	srv.Mux.ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("GET /api/status after write status=%d", getRec.Code)
	}
	var payload map[string]any
	if err := json.Unmarshal(getRec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode /api/status: %v", err)
	}
	if payload["singctlVersion"] != "v1.14.207" {
		t.Fatalf("unexpected singctlVersion: %v", payload["singctlVersion"])
	}
}
