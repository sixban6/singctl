package webui_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"singctl/internal/audit"
	"singctl/internal/config"
	"singctl/internal/webui"
)

func TestAuditAPI_ShortSingleFlightCacheAndWriteInvalidation(t *testing.T) {
	var clashHits atomic.Int32
	clashSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		clashHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"connections":[{"id":"c1","upload":100,"download":200,"start":"2026-11-27T12:00:00Z","chains":["DIRECT"],"rule":"final","metadata":{"network":"tcp","sourceIP":"192.168.89.137","destinationIP":"203.0.113.10","destinationPort":"443","host":"api.example.com"}}]}`))
	}))
	defer clashSrv.Close()

	tmp := t.TempDir()
	cfgPath := filepath.Join(tmp, "singctl.yaml")
	if err := os.WriteFile(cfgPath, []byte("subs: []\n"), 0600); err != nil {
		t.Fatal(err)
	}
	collector := audit.NewCollector(&config.Config{})
	collector.SetEndpointsForTest([]string{clashSrv.URL}, "", filepath.Join(tmp, "audit-state.json"))
	collector.SetLeaseFilesForTest(nil, filepath.Join(tmp, "no-arp"), filepath.Join(tmp, "no-hosts"))

	srv := webui.New(webui.Options{
		ConfigPath:     cfgPath,
		AuditCollector: collector,
	})

	// Two rapid default WebUI audit GETs within TTL should coalesce into 1 collector hit!
	for range 2 {
		rec := httptest.NewRecorder()
		srv.Mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/audit?sort=active&dir=desc", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /api/audit status=%d body=%s", rec.Code, rec.Body.String())
		}
		var rep audit.Report
		if err := json.Unmarshal(rec.Body.Bytes(), &rep); err != nil {
			t.Fatalf("decode report: %v", err)
		}
		if len(rep.Flows) != 1 {
			t.Fatalf("expected 1 flow, got %d", len(rep.Flows))
		}
	}
	if hits := clashHits.Load(); hits != 1 {
		t.Fatalf("expected short auditCache to serve 2nd rapid GET from cache (1 clash hit), got %d hits", hits)
	}

	// Write mutation (whitelist add) MUST immediately invalidate auditCache!
	reqW := httptest.NewRequest(http.MethodPost, "/api/audit/whitelist", bytes.NewBufferString(`{"action":"add","target":"api.example.com"}`))
	reqW.Header.Set("Content-Type", "application/json")
	recW := httptest.NewRecorder()
	srv.Mux.ServeHTTP(recW, reqW)
	if recW.Code != http.StatusOK {
		t.Fatalf("POST /api/audit/whitelist status=%d body=%s", recW.Code, recW.Body.String())
	}

	recAfter := httptest.NewRecorder()
	srv.Mux.ServeHTTP(recAfter, httptest.NewRequest(http.MethodGet, "/api/audit?sort=active&dir=desc", nil))
	if recAfter.Code != http.StatusOK {
		t.Fatalf("GET /api/audit after whitelist status=%d", recAfter.Code)
	}
	if hits := clashHits.Load(); hits < 2 {
		t.Fatalf("expected whitelist mutation to invalidate auditCache and trigger fresh collect (>=2 hits), got %d", hits)
	}
}
