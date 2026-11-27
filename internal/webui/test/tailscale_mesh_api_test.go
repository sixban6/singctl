// 文件职责：覆盖 WebUI 统一 Tailscale 拓扑聚合 (/api/tailscale/mesh)、一键保存热下发回滚与在线口令设置 (/api/auth/password) 测试。
package webui_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"singctl/internal/config"
	"singctl/internal/tailscale"
	"singctl/internal/webui"
)

func TestTailscaleMeshAPI_GetSaveRollbackAndPassword(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "singctl.yaml")
	if err := os.WriteFile(cfgPath, []byte(`subs:
  - name: "main"
    url: "https://example.com/sub"
gateway:
  mode: "main"
tailscale:
  auth_key: "tskey-auth-test-0001-abcdef"
  subnets: "192.168.31.0/24"
  use_build: false
`), 0600); err != nil {
		t.Fatalf("write singctl.yaml: %v", err)
	}

	now := time.Date(2026, 11, 27, 0, 0, 0, 0, time.UTC)
	var failFW4 bool
	var mu sync.Mutex
	var meshSyncCalls []string
	var modeSyncCalls []string

	apiStub := &stubTSLocalAPI{
		statusFn: func(call int) (*tailscale.StatusSnapshot, error) {
			return &tailscale.StatusSnapshot{
				BackendState: "Running",
				Self:         tailscale.PeerStatus{ID: "nSelf", HostName: "ImmortalWrt", ShortName: "n4120", TailscaleIPs: []string{"100.108.214.2"}},
				Peers: []tailscale.PeerStatus{
					{
						ID:            "nHome1",
						HostName:      "OpenWrt",
						DNSName:       "ax3000t.example.ts.net.",
						ShortName:     "ax3000t",
						TailscaleIPs:  []string{"100.96.182.83"},
						PrimaryRoutes: []string{"192.168.55.0/24"},
						Online:        true,
						Active:        true,
						CurAddr:       "198.51.100.20:41641",
					},
					{
						ID:           "nPhone1",
						HostName:     "iphone",
						DNSName:      "iphone.example.ts.net.",
						ShortName:    "iphone",
						TailscaleIPs: []string{"100.96.182.100"},
						Online:       true,
					},
				},
			}, nil
		},
		netMap: &tailscale.NetMapSnapshot{
			SelfEndpoints: []string{"203.0.113.1:41641"},
			PeerEndpoints: map[string][]string{
				"nHome1": {"198.51.100.20:41641"},
			},
		},
	}

	fw4Mgr := &tailscale.FW4Manager{
		BaseDir: t.TempDir(),
		Runner: func(ctx context.Context, stdin string, name string, args ...string) ([]byte, error) {
			if name == "nft" && len(args) >= 2 && args[0] == "-c" {
				return nil, nil
			}
			if name == "fw4" && len(args) > 0 && args[0] == "check" {
				if failFW4 {
					return []byte("fw4 check failed"), errors.New("exit 1")
				}
				return nil, nil
			}
			if name == "nft" && len(args) >= 4 && args[0] == "-a" && args[1] == "list" && failFW4 {
				return nil, errors.New("nft missing")
			}
			if name == "nft" && len(args) >= 4 && args[0] == "-j" && args[1] == "list" && args[2] == "set" {
				return []byte(`{"nftables":[]}`), nil
			}
			return nil, nil
		},
	}

	ctrl := &tailscale.P2PAssistController{
		LocalAPI:    apiStub,
		FW4:         fw4Mgr,
		Now:         func() time.Time { return now },
		Sleep:       func(ctx context.Context, d time.Duration) error { return nil },
		HostSelfIPs: func() []netip.Addr { return []netip.Addr{netip.MustParseAddr("203.0.113.1")} },
	}

	srv := webui.New(webui.Options{
		ConfigPath: cfgPath,
		Version:    "v1.14.204-test",
		TailscaleP2PForTest: &webui.TailscaleP2PTestHooks{
			Controller:     ctrl,
			FW4Available:   true,
			UjailAvailable: false,
			Now:            func() time.Time { return now },
			DefaultLANCIDR: "192.168.31.0/24",
			RouteOutput: strings.Join([]string{
				"192.168.27.0/24 via 192.168.31.151 dev br-lan",
				"192.168.28.0/24 via 192.168.31.151 dev br-lan",
				"192.168.31.0/24 dev br-lan scope link src 192.168.31.1",
			}, "\n"),
			NeighText: "192.168.31.88 dev br-lan lladdr 02:00:00:00:01:88 REACHABLE\n192.168.31.151 dev br-lan lladdr 02:00:00:00:01:51 REACHABLE\n",
			MeshSync: func(ctx context.Context, subnetsCSV string, acceptRoutes bool) error {
				mu.Lock()
				defer mu.Unlock()
				meshSyncCalls = append(meshSyncCalls, subnetsCSV+"|"+func() string {
					if acceptRoutes {
						return "accept=true"
					}
					return "accept=false"
				}())
				return nil
			},
			MeshSyncWithMode: func(ctx context.Context, mode, subnetsCSV string, acceptRoutes, exitNode bool) error {
				mu.Lock()
				defer mu.Unlock()
				modeSyncCalls = append(modeSyncCalls, mode+"|"+subnetsCSV+"|exit="+func() string {
					if exitNode {
						return "true"
					}
					return "false"
				}())
				return nil
			},
		},
	})

	// 1. GET /api/tailscale/mesh returns localNetworks (primary + downstream) + classified peers.
	reqGet := httptest.NewRequest(http.MethodGet, "/api/tailscale/mesh", nil)
	recGet := httptest.NewRecorder()
	srv.Mux.ServeHTTP(recGet, reqGet)
	if recGet.Code != http.StatusOK {
		t.Fatalf("GET /api/tailscale/mesh status=%d body=%s", recGet.Code, recGet.Body.String())
	}
	var meshGet struct {
		GatewayRole           string `json:"gatewayRole"`
		WebPasswordConfigured bool   `json:"webPasswordConfigured"`
		LocalNetworks         []struct {
			CIDR       string `json:"cidr"`
			Kind       string `json:"kind"`
			ViaGateway string `json:"viaGateway"`
			Selected   bool   `json:"selected"`
		} `json:"localNetworks"`
		GatewayPeers    []tailscale.P2PPeerView `json:"gatewayPeers"`
		PersonalDevices []tailscale.P2PPeerView `json:"personalDevices"`
	}
	if err := json.Unmarshal(recGet.Body.Bytes(), &meshGet); err != nil {
		t.Fatalf("decode mesh GET: %v", err)
	}
	if meshGet.GatewayRole != "main" || meshGet.WebPasswordConfigured {
		t.Fatalf("unexpected gatewayRole/webPasswordConfigured: %+v", meshGet)
	}
	if len(meshGet.LocalNetworks) < 3 {
		t.Fatalf("expected >=3 discovered localNetworks (31, 27, 28), got %+v", meshGet.LocalNetworks)
	}
	if len(meshGet.GatewayPeers) != 1 || meshGet.GatewayPeers[0].ID != "nHome1" {
		t.Fatalf("expected 1 gateway peer nHome1, got %+v", meshGet.GatewayPeers)
	}
	if len(meshGet.PersonalDevices) != 1 || meshGet.PersonalDevices[0].ID != "nPhone1" {
		t.Fatalf("expected 1 personal device nPhone1, got %+v", meshGet.PersonalDevices)
	}

	// 2. PUT /api/tailscale/mesh rejects malicious CIDR input.
	reqBad := httptest.NewRequest(http.MethodPut, "/api/tailscale/mesh", bytes.NewBufferString(`{"subnets":["192.168.31.0/24;rm -rf /"]}`))
	reqBad.Header.Set("Content-Type", "application/json")
	recBad := httptest.NewRecorder()
	srv.Mux.ServeHTTP(recBad, reqBad)
	if recBad.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on bad CIDR, got %d: %s", recBad.Code, recBad.Body.String())
	}

	// 3. PUT /api/tailscale/mesh saves multi-subnets + bidirectional peer, invokes MeshSync and reconciles fw4.
	savePayload := `{
		"subnets": ["192.168.31.0/24", "192.168.27.0/24", "192.168.28.0/24"],
		"peers": [{"id": "nHome1", "name": "ax3000t", "tailscale_ip": "100.96.182.83", "access_mode": "bidirectional", "jit_enabled": true}]
	}`
	reqPut := httptest.NewRequest(http.MethodPut, "/api/tailscale/mesh", bytes.NewBufferString(savePayload))
	reqPut.Header.Set("Content-Type", "application/json")
	recPut := httptest.NewRecorder()
	srv.Mux.ServeHTTP(recPut, reqPut)
	if recPut.Code != http.StatusOK {
		t.Fatalf("PUT /api/tailscale/mesh failed status=%d body=%s", recPut.Code, recPut.Body.String())
	}
	loadedCfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if loadedCfg.Tailscale.Subnets != "192.168.31.0/24,192.168.27.0/24,192.168.28.0/24" {
		t.Fatalf("unexpected persisted subnets: %q", loadedCfg.Tailscale.Subnets)
	}
	if len(loadedCfg.Tailscale.P2PAssist.Peers) != 1 || loadedCfg.Tailscale.P2PAssist.Peers[0].AccessMode != config.TailscaleAccessBidirectional {
		t.Fatalf("unexpected persisted p2p peers: %+v", loadedCfg.Tailscale.P2PAssist.Peers)
	}
	mu.Lock()
	syncSnapshot := append([]string(nil), meshSyncCalls...)
	mu.Unlock()
	if len(syncSnapshot) != 1 || syncSnapshot[0] != "192.168.31.0/24,192.168.27.0/24,192.168.28.0/24|accept=true" {
		t.Fatalf("unexpected MeshSync calls: %v", syncSnapshot)
	}

	// 4. PUT /api/tailscale/mesh rolls back singctl.yaml if FW4 fails.
	failFW4 = true
	reqFail := httptest.NewRequest(http.MethodPut, "/api/tailscale/mesh", bytes.NewBufferString(`{"subnets":["192.168.31.0/24"],"peers":[]}`))
	reqFail.Header.Set("Content-Type", "application/json")
	recFail := httptest.NewRecorder()
	srv.Mux.ServeHTTP(recFail, reqFail)
	if recFail.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on fw4 apply error, got %d: %s", recFail.Code, recFail.Body.String())
	}
	failFW4 = false
	afterRb, _ := config.Load(cfgPath)
	if afterRb.Tailscale.Subnets != "192.168.31.0/24,192.168.27.0/24,192.168.28.0/24" {
		t.Fatalf("expected rollback of singctl.yaml subnets, got %q", afterRb.Tailscale.Subnets)
	}

	// 5. PUT /api/auth/password validates length, persists 0600 web.password, issues 30d cookie, and enforces auth immediately.
	reqShort := httptest.NewRequest(http.MethodPut, "/api/auth/password", bytes.NewBufferString(`{"password":"123"}`))
	reqShort.Header.Set("Content-Type", "application/json")
	recShort := httptest.NewRecorder()
	srv.Mux.ServeHTTP(recShort, reqShort)
	if recShort.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on short password, got %d: %s", recShort.Code, recShort.Body.String())
	}

	reqSetPw := httptest.NewRequest(http.MethodPut, "/api/auth/password", bytes.NewBufferString(`{"password":"HomeGuard!2026"}`))
	reqSetPw.Header.Set("Content-Type", "application/json")
	recSetPw := httptest.NewRecorder()
	srv.Mux.ServeHTTP(recSetPw, reqSetPw)
	if recSetPw.Code != http.StatusOK {
		t.Fatalf("PUT /api/auth/password failed status=%d body=%s", recSetPw.Code, recSetPw.Body.String())
	}
	var pwResp struct {
		OK           bool   `json:"ok"`
		AuthRequired bool   `json:"authRequired"`
		Token        string `json:"token"`
	}
	if err := json.Unmarshal(recSetPw.Body.Bytes(), &pwResp); err != nil || !pwResp.OK || !pwResp.AuthRequired || pwResp.Token == "" {
		t.Fatalf("unexpected PUT /api/auth/password response: %+v err=%v", pwResp, err)
	}
	pwFile := filepath.Join(dir, webui.WebPasswordFileName)
	st, statErr := os.Stat(pwFile)
	if statErr != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 web.password file, stat=%v err=%v", st, statErr)
	}
	if gotCookie := recSetPw.Result().Cookies(); len(gotCookie) == 0 || gotCookie[0].Name != webui.SessionCookieName {
		t.Fatalf("expected 30d %s cookie to be issued, got %+v", webui.SessionCookieName, gotCookie)
	}

	// Unauthenticated request to protected endpoint must now return 401.
	reqUnauth := httptest.NewRequest(http.MethodGet, "/api/tailscale/mesh", nil)
	recUnauth := httptest.NewRecorder()
	srv.Mux.ServeHTTP(recUnauth, reqUnauth)
	if recUnauth.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 after enabling WebUI password, got %d", recUnauth.Code)
	}

	// Authenticated via returned Bearer token succeeds and shows webPasswordConfigured=true.
	reqAuthed := httptest.NewRequest(http.MethodGet, "/api/tailscale/mesh", nil)
	reqAuthed.Header.Set("Authorization", "Bearer "+pwResp.Token)
	recAuthed := httptest.NewRecorder()
	srv.Mux.ServeHTTP(recAuthed, reqAuthed)
	if recAuthed.Code != http.StatusOK {
		t.Fatalf("expected 200 with bearer token, got %d", recAuthed.Code)
	}
	if !strings.Contains(recAuthed.Body.String(), `"webPasswordConfigured":true`) {
		t.Fatalf("expected webPasswordConfigured=true in mesh GET, got: %s", recAuthed.Body.String())
	}

	// Changing password with wrong currentPassword fails 403.
	reqWrongCur := httptest.NewRequest(http.MethodPut, "/api/auth/password", bytes.NewBufferString(`{"currentPassword":"wrong","password":"AnotherPassword!1"}`))
	reqWrongCur.Header.Set("Authorization", "Bearer "+pwResp.Token)
	reqWrongCur.Header.Set("Content-Type", "application/json")
	recWrongCur := httptest.NewRecorder()
	srv.Mux.ServeHTTP(recWrongCur, reqWrongCur)
	if recWrongCur.Code != http.StatusForbidden {
		t.Fatalf("expected 403 on wrong currentPassword, got %d: %s", recWrongCur.Code, recWrongCur.Body.String())
	}

	// 6. GET /api/tailscale/mesh includes discovered local devices in 192.168.31.0/24 (192.168.31.88 & 192.168.31.151).
	reqMeshDevs := httptest.NewRequest(http.MethodGet, "/api/tailscale/mesh", nil)
	reqMeshDevs.Header.Set("Authorization", "Bearer "+pwResp.Token)
	recMeshDevs := httptest.NewRecorder()
	srv.Mux.ServeHTTP(recMeshDevs, reqMeshDevs)
	if recMeshDevs.Code != http.StatusOK || !strings.Contains(recMeshDevs.Body.String(), `"192.168.31.88"`) || !strings.Contains(recMeshDevs.Body.String(), `"isDownstream":true`) {
		t.Fatalf("expected discovered devices 31.88 & 31.151(isDownstream) in mesh GET, got: %s", recMeshDevs.Body.String())
	}

	// 7. Mode & LocalRules support (invalid role -> 400; gateway+allowlist -> persists LocalRules; exit -> clears live advertised LAN while keeping exit=true).
	reqBadMode := httptest.NewRequest(http.MethodPut, "/api/tailscale/mesh", bytes.NewBufferString(`{"mode":"bogus_role","subnets":["192.168.31.0/24"]}`))
	reqBadMode.Header.Set("Authorization", "Bearer "+pwResp.Token)
	reqBadMode.Header.Set("Content-Type", "application/json")
	recBadMode := httptest.NewRecorder()
	srv.Mux.ServeHTTP(recBadMode, reqBadMode)
	if recBadMode.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on invalid mode, got %d", recBadMode.Code)
	}

	allowBody := `{"mode":"gateway","subnets":["192.168.31.0/24"],"local_rules":[{"cidr":"192.168.31.0/24","scope":"allowlist","devices":["192.168.31.88"]}],"peers":[{"id":"nHome1","name":"ax3000t","access_mode":"bidirectional","jit_enabled":true}]}`
	reqAllow := httptest.NewRequest(http.MethodPut, "/api/tailscale/mesh", bytes.NewBufferString(allowBody))
	reqAllow.Header.Set("Authorization", "Bearer "+pwResp.Token)
	reqAllow.Header.Set("Content-Type", "application/json")
	recAllow := httptest.NewRecorder()
	srv.Mux.ServeHTTP(recAllow, reqAllow)
	if recAllow.Code != http.StatusOK {
		t.Fatalf("PUT allowlist failed: %d %s", recAllow.Code, recAllow.Body.String())
	}
	allowCfg, _ := config.Load(cfgPath)
	if allowCfg.Tailscale.P2PAssist.RoleMode != "gateway" || len(allowCfg.Tailscale.P2PAssist.LocalRules) != 1 || allowCfg.Tailscale.P2PAssist.LocalRules[0].Scope != config.TailscaleScopeAllowlist {
		t.Fatalf("expected persisted RoleMode=gateway & LocalRules allowlist, got %+v", allowCfg.Tailscale.P2PAssist)
	}

	reqExit := httptest.NewRequest(http.MethodPut, "/api/tailscale/mesh", bytes.NewBufferString(`{"mode":"exit","subnets":[],"peers":[]}`))
	reqExit.Header.Set("Authorization", "Bearer "+pwResp.Token)
	reqExit.Header.Set("Content-Type", "application/json")
	recExit := httptest.NewRecorder()
	srv.Mux.ServeHTTP(recExit, reqExit)
	if recExit.Code != http.StatusOK {
		t.Fatalf("PUT mode=exit failed: %d %s", recExit.Code, recExit.Body.String())
	}
	mu.Lock()
	modeCalls := append([]string(nil), modeSyncCalls...)
	mu.Unlock()
	if len(modeCalls) < 2 || modeCalls[len(modeCalls)-2] != "gateway|192.168.31.0/24|exit=true" || modeCalls[len(modeCalls)-1] != "exit||exit=true" {
		t.Fatalf("unexpected MeshSyncWithMode calls: %v", modeCalls)
	}
}
