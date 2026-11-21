package webui

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
)

type stubTSLocalAPI struct {
	mu          sync.Mutex
	statusFn    func(call int) (*tailscale.StatusSnapshot, error)
	netMap      *tailscale.NetMapSnapshot
	statusCalls int
}

func (s *stubTSLocalAPI) Status(ctx context.Context) (*tailscale.StatusSnapshot, error) {
	s.mu.Lock()
	s.statusCalls++
	call := s.statusCalls
	s.mu.Unlock()
	return s.statusFn(call)
}

func (s *stubTSLocalAPI) NetMap(ctx context.Context) (*tailscale.NetMapSnapshot, error) {
	return s.netMap, nil
}

func (s *stubTSLocalAPI) PingDisco(ctx context.Context, peerTSIP string) (*tailscale.PingResult, error) {
	return &tailscale.PingResult{IP: peerTSIP, DERPRegionCode: "sfo", LatencySeconds: 0.025}, nil
}

func TestTailscaleP2PAPI_GetPutValidationRollbackPokeAndConfigPreservation(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "singctl.yaml")
	if err := os.WriteFile(cfgPath, []byte(`subs:
  - name: "main"
    url: "https://example.com/sub"
tailscale:
  auth_key: ""
  subnets: "192.168.180.0/24"
  use_build: false
`), 0600); err != nil {
		t.Fatalf("write singctl.yaml: %v", err)
	}

	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	var failFW4 bool
	var pokeUpgraded bool

	apiStub := &stubTSLocalAPI{
		statusFn: func(call int) (*tailscale.StatusSnapshot, error) {
			cur := ""
			relay := "sfo"
			if pokeUpgraded {
				cur = "198.51.100.10:41641"
				relay = ""
			}
			return &tailscale.StatusSnapshot{
				BackendState: "Running",
				Self:         tailscale.PeerStatus{ID: "nSelf", HostName: "ImmortalWrt", ShortName: "n4120"},
				Peers: []tailscale.PeerStatus{
					{
						ID:            "nRemote1",
						HostName:      "ImmortalWrt",
						DNSName:       "router-remote.example.ts.net.",
						ShortName:     "router-remote",
						TailscaleIPs:  []string{"100.64.200.2"},
						PrimaryRoutes: []string{"192.168.55.0/24"},
						Online:        true,
						Active:        false,
						CurAddr:       cur,
						Relay:         relay,
					},
					{
						ID:           "nAdminLaptop",
						HostName:     "admin-laptop",
						DNSName:      "laptop.example.ts.net.",
						ShortName:    "laptop",
						TailscaleIPs: []string{"100.64.200.99"},
						Online:       false,
					},
				},
			}, nil
		},
		netMap: &tailscale.NetMapSnapshot{
			SelfEndpoints: []string{"203.0.113.1:41641"},
			PeerEndpoints: map[string][]string{
				"nRemote1": {"192.168.55.1:41641", "198.51.100.10:41641"},
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
					return []byte("fw4 broken"), errors.New("exit 1")
				}
				return nil, nil
			}
			if name == "nft" && len(args) >= 4 && args[0] == "-a" && args[1] == "list" && failFW4 {
				return nil, errors.New("nft unavailable")
			}
			if name == "nft" && len(args) >= 2 && args[0] == "add" && args[1] == "element" {
				pokeUpgraded = true
				return nil, nil
			}
			if name == "nft" && len(args) >= 4 && args[0] == "-j" && args[1] == "list" && args[2] == "set" {
				return []byte(`{"nftables":[]}`), nil
			}
			return nil, nil
		},
	}

	ctrl := &tailscale.P2PAssistController{
		LocalAPI:       apiStub,
		FW4:            fw4Mgr,
		Now:            func() time.Time { return now },
		Sleep:          func(ctx context.Context, d time.Duration) error { return nil },
		DefaultLANCIDR: func() string { return "192.168.180.0/24" },
		HostSelfIPs:    func() []netip.Addr { return []netip.Addr{netip.MustParseAddr("203.0.113.1")} },
	}

	srv := New(Options{
		ConfigPath: cfgPath,
		Version:    "v1.14.145-test",
		TailscaleP2PForTest: &TailscaleP2PTestHooks{
			Controller:     ctrl,
			FW4Available:   true,
			UjailAvailable: true,
			Now:            func() time.Time { return now },
			DefaultLANCIDR: "192.168.180.0/24",
		},
	})

	// 1. GET /api/tailscale/p2p discovers peers and defaults to disabled / 0 open pinholes
	reqGet := httptest.NewRequest(http.MethodGet, "/api/tailscale/p2p", nil)
	recGet := httptest.NewRecorder()
	srv.Mux.ServeHTTP(recGet, reqGet)
	if recGet.Code != http.StatusOK {
		t.Fatalf("GET /api/tailscale/p2p status=%d body=%s", recGet.Code, recGet.Body.String())
	}
	var getResp struct {
		Supported    bool `json:"supported"`
		FW4Available bool `json:"fw4Available"`
		OpenPinholes int  `json:"openPinholes"`
		Peers        []struct {
			ID                   string `json:"id"`
			ShortName            string `json:"shortName"`
			CandidatePublicCount int    `json:"candidatePublicCount"`
			EffectiveAccessMode  string `json:"effectiveAccessMode"`
		} `json:"peers"`
	}
	if err := json.Unmarshal(recGet.Body.Bytes(), &getResp); err != nil {
		t.Fatalf("decode GET: %v", err)
	}
	if !getResp.Supported || !getResp.FW4Available || getResp.OpenPinholes != 0 || len(getResp.Peers) != 2 {
		t.Fatalf("unexpected GET response: %+v", getResp)
	}
	if getResp.Peers[0].CandidatePublicCount != 1 {
		t.Fatalf("expected 1 filtered public candidate IP for remote router, got %+v", getResp.Peers[0])
	}

	// 2. PUT /api/tailscale/p2p rejects invalid target injection & invalid access mode
	badTarget := `{"enabled":true,"peers":[{"id":"nRemote1","name":"router-remote","jit_enabled":true,"access_mode":"bidirectional","allowed_lan_targets":["192.168.180.10; drop"]}]}`
	reqBad := httptest.NewRequest(http.MethodPut, "/api/tailscale/p2p", bytes.NewBufferString(badTarget))
	reqBad.Header.Set("Content-Type", "application/json")
	recBad := httptest.NewRecorder()
	srv.Mux.ServeHTTP(recBad, reqBad)
	if recBad.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on injection allowed_lan_targets, got %d: %s", recBad.Code, recBad.Body.String())
	}

	// 3. Valid PUT saves config (0600) and applies rules
	validUntil := now.Add(7 * 24 * time.Hour).Format(time.RFC3339)
	validBody := `{"enabled":true,"jit_window_sec":5,"cooldown_sec":300,"payload_filter":true,"peers":[{"id":"nRemote1","name":"router-remote","tailscale_ip":"100.64.200.2","jit_enabled":true,"access_mode":"bidirectional_timed","bidirectional_until":"` + validUntil + `","allowed_lan_targets":["192.168.180.10:8445"]}]}`
	reqPut := httptest.NewRequest(http.MethodPut, "/api/tailscale/p2p", bytes.NewBufferString(validBody))
	reqPut.Header.Set("Content-Type", "application/json")
	recPut := httptest.NewRecorder()
	srv.Mux.ServeHTTP(recPut, reqPut)
	if recPut.Code != http.StatusOK {
		t.Fatalf("PUT /api/tailscale/p2p failed status=%d body=%s", recPut.Code, recPut.Body.String())
	}

	loaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("reload config: %v", err)
	}
	if !loaded.Tailscale.P2PAssist.Enabled || len(loaded.Tailscale.P2PAssist.Peers) != 1 {
		t.Fatalf("expected persisted p2p_assist, got %+v", loaded.Tailscale.P2PAssist)
	}

	// 4. PUT /api/tailscale/p2p rolls back singctl.yaml when FW4 apply fails
	failFW4 = true
	reqFail := httptest.NewRequest(http.MethodPut, "/api/tailscale/p2p", bytes.NewBufferString(`{"enabled":true,"jit_window_sec":8,"peers":[]}`))
	reqFail.Header.Set("Content-Type", "application/json")
	recFail := httptest.NewRecorder()
	srv.Mux.ServeHTTP(recFail, reqFail)
	if recFail.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 rollback error, got %d: %s", recFail.Code, recFail.Body.String())
	}
	failFW4 = false
	afterRollback, _ := config.Load(cfgPath)
	if len(afterRollback.Tailscale.P2PAssist.Peers) != 1 || afterRollback.Tailscale.P2PAssist.JITWindowSec != 5 {
		t.Fatalf("expected singctl.yaml rolled back after apply error, got %+v", afterRollback.Tailscale.P2PAssist)
	}

	// 5. POST /api/tailscale/p2p/poke executes JIT window and reports direct upgrade
	reqPoke := httptest.NewRequest(http.MethodPost, "/api/tailscale/p2p/poke", bytes.NewBufferString(`{"id":"nRemote1"}`))
	reqPoke.Header.Set("Content-Type", "application/json")
	recPoke := httptest.NewRecorder()
	srv.Mux.ServeHTTP(recPoke, reqPoke)
	if recPoke.Code != http.StatusOK {
		t.Fatalf("POST /api/tailscale/p2p/poke failed status=%d body=%s", recPoke.Code, recPoke.Body.String())
	}
	if !strings.Contains(recPoke.Body.String(), `"direct":true`) {
		t.Fatalf("expected direct=true in poke response, got: %s", recPoke.Body.String())
	}

	// 6. PUT /api/config preserves existing tailscale.p2p_assist config intact
	cfgPutBody := `{"subs":[{"name":"main","url":"https://example.com/sub2","skip_tls_verify":false,"remove_emoji":true}],"github":{"mirror_url":"https://gh-proxy.com"},"hy2":{"up":20,"down":200},"tailscale":{"auth_key":"","use_build":false,"subnets":"192.168.180.0/24"},"server":{"sb_domain":"","cf_dns_key":"","sni":"swdist.apple.com"}}`
	reqCfgPut := httptest.NewRequest(http.MethodPut, "/api/config", bytes.NewBufferString(cfgPutBody))
	reqCfgPut.Header.Set("Content-Type", "application/json")
	recCfgPut := httptest.NewRecorder()
	srv.Mux.ServeHTTP(recCfgPut, reqCfgPut)
	if recCfgPut.Code != http.StatusOK {
		t.Fatalf("PUT /api/config status=%d body=%s", recCfgPut.Code, recCfgPut.Body.String())
	}
	finalCfg, _ := config.Load(cfgPath)
	if !finalCfg.Tailscale.P2PAssist.Enabled || len(finalCfg.Tailscale.P2PAssist.Peers) != 1 {
		t.Fatalf("expected PUT /api/config to preserve tailscale.p2p_assist, got %+v", finalCfg.Tailscale.P2PAssist)
	}

	// 7. Required security toggles (enabled & payload_filter) stay enforced while sandbox_ujail can be disabled
	enforcedBody := `{"enabled":false,"payload_filter":false,"sandbox_ujail":false,"jit_window_sec":5,"cooldown_sec":300,"peers":[]}`
	reqEnf := httptest.NewRequest(http.MethodPut, "/api/tailscale/p2p", bytes.NewBufferString(enforcedBody))
	reqEnf.Header.Set("Content-Type", "application/json")
	recEnf := httptest.NewRecorder()
	srv.Mux.ServeHTTP(recEnf, reqEnf)
	if recEnf.Code != http.StatusOK {
		t.Fatalf("PUT /api/tailscale/p2p status=%d body=%s", recEnf.Code, recEnf.Body.String())
	}
	enfCfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("reload config after security enforcement: %v", err)
	}
	if !enfCfg.Tailscale.P2PAssist.Enabled || !enfCfg.Tailscale.P2PAssist.EffectivePayloadFilter() || enfCfg.Tailscale.P2PAssist.SandboxUjail {
		t.Fatalf("expected enabled=true, payload_filter=true enforced and sandbox_ujail=false honored, got %+v", enfCfg.Tailscale.P2PAssist)
	}
}
