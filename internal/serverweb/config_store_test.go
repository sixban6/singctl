// 文件职责：验证服务端 Web 面板热路径接口统一复用 config.Store 不可变快照、坏文件回退与写操作无原地污染。
package serverweb

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"singctl/internal/config"
)

func TestServerWeb_ConfigStoreHotPathSnapshotAndMutationIsolation(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "singctl.yaml")
	sbCfgPath := filepath.Join(tmpDir, "sing-box.json")
	if err := os.WriteFile(sbCfgPath, []byte(`{"inbounds":[],"outbounds":[{"type":"direct","tag":"DIRECT"}],"route":{"rules":[]}}`), 0600); err != nil {
		t.Fatal(err)
	}
	initialYAML := `
server:
  node_domain: "node.example.com"
  substore_domain: "sub.example.com"
  sni: "www.example.com"
  warp_routing:
    mode: "split"
    warp_domains:
      - "chat.example.com"
  web_admin:
    path: "/sr/initpath"
    username: "opsadmin"
    password: "Password123"
    password_pending_ack: true
`
	if err := os.WriteFile(cfgPath, []byte(initialYAML), 0600); err != nil {
		t.Fatal(err)
	}

	var loadCalls atomic.Int32
	store := config.NewStore(cfgPath, config.WithLoader(func(p string) (*config.Config, error) {
		loadCalls.Add(1)
		return config.Load(p)
	}))
	if got := loadCalls.Load(); got != 1 {
		t.Fatalf("expected 1 initial store load, got %d", got)
	}

	srv := New(Options{
		ConfigPath:        cfgPath,
		ConfigStore:       store,
		SingBoxConfigPath: sbCfgPath,
		SubStoreDir:       filepath.Join(tmpDir, "sub-store"),
		FleetFilePath:     filepath.Join(tmpDir, "fleet.yaml"),
		BanFilePath:       filepath.Join(tmpDir, "bans.json"),
		AuditFilePath:     filepath.Join(tmpDir, "audit.json"),
		Username:          "opsadmin",
		Password:          "Password123",
	})
	defer srv.limiter.Close()
	srv.sniff.EnableSystemProbe = false
	srv.warpDaemonProbe = func(bool) WarpDaemonStatus {
		return WarpDaemonStatus{Installed: true, Running: true, TunnelHealthy: true, SocksPort: 40000, WarpIP: "198.51.100.10"}
	}

	doAuthed := func(method, target, body string) *httptest.ResponseRecorder {
		var req *http.Request
		if body != "" {
			req = httptest.NewRequest(method, target, strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
		} else {
			req = httptest.NewRequest(method, target, nil)
		}
		req.SetBasicAuth("opsadmin", "Password123")
		req.RemoteAddr = "127.0.0.1:43210"
		rec := httptest.NewRecorder()
		srv.Mux.ServeHTTP(rec, req)
		return rec
	}

	// 1. Unchanged file on disk: hot-path endpoints must hit config.Store snapshot without reparsing YAML
	baselineLoads := loadCalls.Load()
	for _, ep := range []string{
		"/api/server/subscriptions",
		"/api/server/nodes",
		"/api/server/certs",
		"/api/server/warp/routing",
	} {
		rec := doAuthed(http.MethodGet, ep, "")
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s failed: %d %s", ep, rec.Code, rec.Body.String())
		}
	}
	if got := loadCalls.Load(); got != baselineLoads {
		t.Fatalf("expected 0 extra YAML disk loads across unchanged hot-path GETs, went from %d to %d", baselineLoads, got)
	}

	// 2. Mutation isolation: holding a snapshot before POST /api/server/credentials/ack must not mutate old snapshot in-place
	snapBefore := store.Get()
	if !snapBefore.Server.WebAdmin.PasswordPendingAck {
		t.Fatal("expected initial snapshot PasswordPendingAck=true")
	}
	revBefore := store.Revision()

	ackRec := doAuthed(http.MethodPost, "/api/server/credentials/ack", `{}`)
	if ackRec.Code != http.StatusOK {
		t.Fatalf("POST /api/server/credentials/ack failed: %d %s", ackRec.Code, ackRec.Body.String())
	}
	if !snapBefore.Server.WebAdmin.PasswordPendingAck {
		t.Fatal("shared config snapshot was mutated in-place by handleAckCredentials")
	}
	snapAfter := store.Get()
	if snapAfter.Server.WebAdmin.PasswordPendingAck {
		t.Fatal("expected updated store snapshot to have PasswordPendingAck=false")
	}
	if store.Revision() <= revBefore {
		t.Fatalf("expected store revision to advance after saveConfig, stayed at %d", store.Revision())
	}
	if st, err := os.Stat(cfgPath); err != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 permissions on saved singctl.yaml, err=%v", err)
	}

	// 3. Torn/corrupted YAML on disk: tolerant read endpoints must preserve last-known-good store snapshot
	if err := os.WriteFile(cfgPath, []byte("server:\n  node_domain: [broken"), 0600); err != nil {
		t.Fatal(err)
	}
	store.Invalidate()
	warpRec := doAuthed(http.MethodGet, "/api/server/warp/routing", "")
	if warpRec.Code != http.StatusOK || !strings.Contains(warpRec.Body.String(), "chat.example.com") {
		t.Fatalf("expected /api/server/warp/routing to preserve last-known-good warp_domains via store fallback, got %d: %s", warpRec.Code, warpRec.Body.String())
	}
	subAfterCorrupt := doAuthed(http.MethodGet, "/api/server/subscriptions", "")
	if subAfterCorrupt.Code != http.StatusOK || !strings.Contains(subAfterCorrupt.Body.String(), "sub.example.com") {
		t.Fatalf("expected /api/server/subscriptions to survive corrupted YAML via store fallback, got %d: %s", subAfterCorrupt.Code, subAfterCorrupt.Body.String())
	}
	certsRec := doAuthed(http.MethodGet, "/api/server/certs", "")
	if certsRec.Code != http.StatusOK {
		t.Fatalf("expected /api/server/certs to survive corrupted YAML via store fallback, got %d: %s", certsRec.Code, certsRec.Body.String())
	}

	// 4. Restore valid YAML and run concurrent reads + credential ack under -race
	if err := os.WriteFile(cfgPath, []byte(initialYAML), 0600); err != nil {
		t.Fatal(err)
	}
	store.Invalidate()
	var wg sync.WaitGroup
	for range 6 {
		wg.Go(func() {
			for range 5 {
				_ = doAuthed(http.MethodGet, "/api/server/warp/routing", "")
				_ = doAuthed(http.MethodGet, "/api/server/subscriptions", "")
			}
		})
	}
	wg.Wait()
}
