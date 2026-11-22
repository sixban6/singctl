// 文件职责：覆盖 Tailscale 领域状态解析、LocalAPI RouteAll、P2P 配置校验与状态报告合并构建的单元测试。
package tailscale_test

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"singctl/internal/config"
	"singctl/internal/tailscale"
)

func TestIsTailscaleAddr_And_Request(t *testing.T) {
	for _, tsIP := range []string{"100.64.0.1", "100.100.100.100", "[fd7a:115c:a1e0::1%utun0]"} {
		if !tailscale.IsTailscaleAddr(tsIP) {
			t.Fatalf("expected IsTailscaleAddr(%q) = true", tsIP)
		}
	}
	for _, nonTS := range []string{"", "not-ip", "127.0.0.1", "192.168.1.50", "198.51.100.1"} {
		if tailscale.IsTailscaleAddr(nonTS) {
			t.Fatalf("expected IsTailscaleAddr(%q) = false", nonTS)
		}
	}

	reqDirect := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	reqDirect.RemoteAddr = "100.64.10.5:51234"
	if !tailscale.IsTailscaleRequest(reqDirect) {
		t.Fatal("expected direct tailscale RemoteAddr to return true")
	}

	reqLoopProxy := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	reqLoopProxy.RemoteAddr = "127.0.0.1:40000"
	reqLoopProxy.Header.Set("X-Forwarded-For", "100.64.20.9, 127.0.0.1")
	if !tailscale.IsTailscaleRequest(reqLoopProxy) {
		t.Fatal("expected loopback reverse-proxied tailscale XFF to return true")
	}

	// Spoofed XFF from LAN client must NOT be trusted
	reqSpoof := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	reqSpoof.RemoteAddr = "192.168.1.50:40000"
	reqSpoof.Header.Set("X-Forwarded-For", "100.64.20.9")
	if tailscale.IsTailscaleRequest(reqSpoof) {
		t.Fatal("expected LAN spoofed XFF to return false")
	}
}

func TestRouteAllPrefs_QueryBackendStatus_And_InspectHostStatus(t *testing.T) {
	sockDir, err := os.MkdirTemp("/tmp", "ts-prefs-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	sockPath := filepath.Join(sockDir, "ts.sock")

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/localapi/v0/prefs" {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"RouteAll":true}`))
				return
			}
			http.NotFound(w, r)
		}),
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	localAPI := &tailscale.UnixLocalAPIClient{SocketPath: sockPath}
	routeAll, err := localAPI.RouteAllPrefs(t.Context())
	if err != nil || !routeAll {
		t.Fatalf("RouteAllPrefs = (%v, %v), want (true, nil)", routeAll, err)
	}

	binDir := t.TempDir()
	fakeTS := filepath.Join(binDir, "tailscale")
	script := `#!/bin/sh
if [ "$1" = "version" ]; then
  echo "1.104.8"
  exit 0
fi
if [ "$1" = "status" ] && [ "$2" = "--json" ]; then
  cat <<'EOF'
{"BackendState":"Running","Self":{"AdvertisedRoutes":["192.168.10.0/24","0.0.0.0/0","::/0"],"ExitNodeOption":true}}
EOF
  exit 0
fi
exit 1
`
	if err := os.WriteFile(fakeTS, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}

	st := tailscale.InspectHostStatus(t.Context(), tailscale.HostStatusOptions{
		BinPath:           fakeTS,
		LocalAPI:          localAPI,
		AuthKeyConfigured: true,
	})
	if st["installed"] != true || st["running"] != true || st["state"] != "Running" ||
		st["mode"] != "gateway" || st["acceptRoutes"] != true || st["subnets"] != "192.168.10.0/24" ||
		st["version"] != "1.104.8" || st["authKeySet"] != true {
		t.Fatalf("unexpected InspectHostStatus: %+v", st)
	}
}

func TestNormalizeAndValidateP2PAssistConfig_And_BuildP2PReport(t *testing.T) {
	validFuture := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC).Format(time.RFC3339)
	norm, err := tailscale.NormalizeAndValidateP2PAssistConfig(config.TailscaleP2PAssistConfig{
		JITWindowSec: 99,
		CooldownSec:  5,
		Peers: []config.TailscaleP2PPeerConfig{
			{},
			{ID: "p1", Name: "remote-a", TailscaleIP: "100.64.200.2", JITEnabled: true, AccessMode: config.TailscaleAccessBidirectionalTimed, BidirectionalUntil: validFuture, AllowedLANTargets: []string{"192.168.1.10:8445"}},
			{ID: "p1", Name: "duplicate-ignored"},
		},
	})
	if err != nil {
		t.Fatalf("NormalizeAndValidateP2PAssistConfig unexpected error: %v", err)
	}
	if !norm.Enabled || norm.JITWindowSec != 10 || norm.CooldownSec != 30 || len(norm.Peers) != 1 {
		t.Fatalf("unexpected normalized config: %+v", norm)
	}

	badCases := []config.TailscaleP2PAssistConfig{
		{Peers: []config.TailscaleP2PPeerConfig{{Name: "bad-ip", TailscaleIP: "not-an-ip"}}},
		{Peers: []config.TailscaleP2PPeerConfig{{Name: "bad-mode", AccessMode: "root_shell"}}},
		{Peers: []config.TailscaleP2PPeerConfig{{Name: "missing-until", AccessMode: config.TailscaleAccessBidirectionalTimed}}},
		{Peers: []config.TailscaleP2PPeerConfig{{Name: "bad-until", AccessMode: config.TailscaleAccessBidirectionalTimed, BidirectionalUntil: "tomorrow"}}},
		{Peers: []config.TailscaleP2PPeerConfig{{Name: "bad-lan", AllowedLANTargets: []string{"192.168.1.1; accept"}}}},
	}
	for i, bad := range badCases {
		if _, err := tailscale.NormalizeAndValidateP2PAssistConfig(bad); err == nil {
			t.Fatalf("case %d: expected validation error, got nil", i)
		}
	}

	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	ctrl := &tailscale.P2PAssistController{
		LocalAPI: &fakeLocalAPIForReport{},
		FW4: &tailscale.FW4Manager{
			BaseDir: t.TempDir(),
			Runner: func(context.Context, string, string, ...string) ([]byte, error) {
				return []byte(`{"nftables":[]}`), nil
			},
		},
		HostSelfIPs: func() []netip.Addr { return []netip.Addr{netip.MustParseAddr("203.0.113.1")} },
	}
	cfg := &config.Config{
		Tailscale: config.TailscaleConfig{
			P2PAssist: config.TailscaleP2PAssistConfig{
				Enabled: true,
				Peers: []config.TailscaleP2PPeerConfig{
					{ID: "pLive", Name: "router-live", JITEnabled: true, AccessMode: config.TailscaleAccessOutboundOnly},
					{ID: "pOfflineCfg", Name: "router-absent", TailscaleIP: "100.64.200.9", JITEnabled: true, AccessMode: config.TailscaleAccessBidirectional},
				},
			},
		},
	}
	dmSnap := &tailscale.P2PRuntimeSnapshot{
		ApplyMode: tailscale.ApplyModeFW4Reload,
		PeerStates: map[string]tailscale.P2PPeerRuntimeState{
			"pLive": {Key: "pLive", PinholeOpen: true, LastResult: "direct"},
		},
	}

	rawReport := tailscale.BuildP2PReport(t.Context(), tailscale.P2PReportOptions{
		Config:         cfg,
		Controller:     ctrl,
		DaemonRuntime:  dmSnap,
		DaemonRunning:  true,
		Supported:      true,
		IsOpenWrt:      true,
		FW4Available:   true,
		UjailAvailable: true,
		DefaultLANCIDR: "192.168.1.0/24",
		Now:            now,
	})
	encoded, err := json.Marshal(rawReport)
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Supported        bool                    `json:"supported"`
		TailscaleRunning bool                    `json:"tailscaleRunning"`
		Peers            []tailscale.P2PPeerView `json:"peers"`
	}
	if err := json.Unmarshal(encoded, &parsed); err != nil {
		t.Fatal(err)
	}
	if !parsed.Supported || !parsed.TailscaleRunning || len(parsed.Peers) != 2 {
		t.Fatalf("unexpected BuildP2PReport: %+v", parsed)
	}
	if !parsed.Peers[0].PinholeActive || parsed.Peers[0].CandidatePublicCount != 1 || parsed.Peers[1].ID != "pOfflineCfg" {
		t.Fatalf("unexpected peer views: %+v", parsed.Peers)
	}
}

type fakeLocalAPIForReport struct{}

func (f *fakeLocalAPIForReport) Status(context.Context) (*tailscale.StatusSnapshot, error) {
	return &tailscale.StatusSnapshot{
		BackendState: "Running",
		Self:         tailscale.PeerStatus{ID: "nSelf"},
		Peers: []tailscale.PeerStatus{
			{ID: "pLive", ShortName: "router-live", TailscaleIPs: []string{"100.64.200.2"}, Online: true, Active: true, Addrs: []string{"198.51.100.55:41641"}},
		},
	}, nil
}

func (f *fakeLocalAPIForReport) NetMap(context.Context) (*tailscale.NetMapSnapshot, error) {
	return &tailscale.NetMapSnapshot{PeerEndpoints: map[string][]string{}}, nil
}

func (f *fakeLocalAPIForReport) PingDisco(context.Context, string) (*tailscale.PingResult, error) {
	return &tailscale.PingResult{}, nil
}
