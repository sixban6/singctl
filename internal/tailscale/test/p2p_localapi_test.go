// 文件职责：覆盖 tailscaled Unix Socket LocalAPI 客户端连接复用、公网候选端点过滤与重名设备匹配测试。
package tailscale_test

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"singctl/internal/config"
	"singctl/internal/tailscale"
)

func TestUnixLocalAPIClient_StatusAndPingOverUnixSocket(t *testing.T) {
	ctx := t.Context()
	sockDir, err := os.MkdirTemp("/tmp", "ts-*")
	if err != nil {
		t.Fatalf("mkdir temp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	sockPath := filepath.Join(sockDir, "ts.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	defer ln.Close()

	var gotPingQuery string
	mux := http.NewServeMux()
	mux.HandleFunc("GET /localapi/v0/status", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"BackendState": "Running",
			"Self": map[string]any{
				"ID":           "nSelf111",
				"HostName":     "ImmortalWrt",
				"DNSName":      "n4120.example.ts.net.",
				"TailscaleIPs": []string{"100.64.200.1", "fd7a:115c:a1e0::1"},
				"Addrs":        []string{"203.0.113.1:41641"},
			},
			"Peer": map[string]any{
				"key-remote": map[string]any{
					"ID":            "nRemote222",
					"HostName":      "ImmortalWrt",
					"DNSName":       "router-remote.example.ts.net.",
					"TailscaleIPs":  []string{"100.64.200.2"},
					"PrimaryRoutes": []string{"192.168.55.0/24"},
					"Online":        true,
					"Active":        true,
					"CurAddr":       "",
					"Relay":         "sfo",
					"RxBytes":       1200,
					"TxBytes":       3400,
				},
			},
		})
	})
	mux.HandleFunc("POST /localapi/v0/ping", func(w http.ResponseWriter, r *http.Request) {
		gotPingQuery = r.URL.RawQuery
		_ = json.NewEncoder(w).Encode(map[string]any{
			"IP":             "100.64.200.2",
			"DERPRegionCode": "sfo",
			"LatencySeconds": 0.042,
		})
	})

	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	client := &tailscale.UnixLocalAPIClient{
		SocketPath: sockPath,
		NetMapRunner: func(ctx context.Context, bin string) ([]byte, error) {
			return []byte(`{
				"SelfNode": {"StableID": "nSelf111", "Endpoints": ["203.0.113.1:41641", "192.168.1.1:41641"]},
				"Peers": [
					{"StableID": "nRemote222", "Endpoints": ["192.168.55.1:41641", "198.51.100.10:41641", "[2001:db8::10]:41641"]}
				]
			}`), nil
		},
	}

	st, err := client.Status(ctx)
	if err != nil {
		t.Fatalf("Status failed: %v", err)
	}
	if st.BackendState != "Running" || st.Self.ID != "nSelf111" || len(st.Peers) != 1 {
		t.Fatalf("unexpected status snapshot: %+v", st)
	}
	p := st.Peers[0]
	if p.ShortName != "router-remote" || p.Relay != "sfo" || !p.Online || !p.Active {
		t.Fatalf("unexpected peer[0]: %+v", p)
	}

	nm, err := client.NetMap(ctx)
	if err != nil {
		t.Fatalf("NetMap failed: %v", err)
	}
	if len(nm.SelfEndpoints) != 2 || len(nm.PeerEndpoints["nRemote222"]) != 3 {
		t.Fatalf("unexpected netmap: %+v", nm)
	}

	pingRes, err := client.PingDisco(ctx, "100.64.200.2")
	if err != nil {
		t.Fatalf("PingDisco failed: %v", err)
	}
	if !strings.Contains(gotPingQuery, "type=disco") || !strings.Contains(gotPingQuery, "ip=100.64.200.2") {
		t.Fatalf("unexpected ping query: %q", gotPingQuery)
	}
	if pingRes.DERPRegionCode != "sfo" {
		t.Fatalf("unexpected ping result: %+v", pingRes)
	}
}

func TestFilterPublicCandidateIPs_StrictValidation(t *testing.T) {
	selfIPs := []netip.Addr{
		netip.MustParseAddr("203.0.113.1"),
		netip.MustParseAddr("2001:db8::1"),
	}
	endpoints := []string{
		"not-an-endpoint",
		"127.0.0.1:41641",
		"[::1]:41641",
		"0.0.0.0:41641",
		"10.0.0.5:41641",
		"172.16.0.5:41641",
		"192.168.1.5:41641",
		"100.64.200.2:41641",
		"100.100.100.100:41641",
		"169.254.1.1:41641",
		"[fe80::1]:41641",
		"[fd7a:115c:a1e0::2]:41641",
		"224.0.0.1:41641",
		"[ff02::1]:41641",
		"192.0.0.1:41641",
		"[64:ff9b::198.51.100.1]:41641",
		"203.0.113.1:41641",
		"[2001:db8::1]:41641",
		"198.51.100.10:41641",
		"198.51.100.10:51234",
		"[::ffff:198.51.100.11]:41641",
		"198.51.100.12:41641",
		"198.51.100.13:41641",
		"198.51.100.14:41641",
		"[2001:db8::10]:41641",
		"[2001:db8::11]:41641",
		"[2001:db8::12]:41641",
		"[2001:db8::13]:41641",
		"[2001:db8::14]:41641",
	}

	v4, v6 := tailscale.FilterPublicCandidateIPs(endpoints, selfIPs)
	wantV4 := []netip.Addr{
		netip.MustParseAddr("198.51.100.10"),
		netip.MustParseAddr("198.51.100.11"),
		netip.MustParseAddr("198.51.100.12"),
		netip.MustParseAddr("198.51.100.13"),
	}
	wantV6 := []netip.Addr{
		netip.MustParseAddr("2001:db8::10"),
		netip.MustParseAddr("2001:db8::11"),
		netip.MustParseAddr("2001:db8::12"),
		netip.MustParseAddr("2001:db8::13"),
	}
	if !reflect.DeepEqual(v4, wantV4) {
		t.Fatalf("v4 mismatch:\n got: %v\nwant: %v", v4, wantV4)
	}
	if !reflect.DeepEqual(v6, wantV6) {
		t.Fatalf("v6 mismatch:\n got: %v\nwant: %v", v6, wantV6)
	}
}

func TestMatchConfiguredPeer_DisambiguatesDuplicateHostNames(t *testing.T) {
	peers := []tailscale.PeerStatus{
		{
			ID:           "nSelf111",
			HostName:     "ImmortalWrt",
			ShortName:    "n4120",
			DNSName:      "n4120.example.ts.net.",
			TailscaleIPs: []string{"100.64.200.1"},
		},
		{
			ID:           "nRemoteA",
			HostName:     "ImmortalWrt",
			ShortName:    "ax3000t-remote",
			DNSName:      "ax3000t-remote.example.ts.net.",
			TailscaleIPs: []string{"100.64.200.2"},
		},
		{
			ID:           "nRemoteB",
			HostName:     "ImmortalWrt",
			ShortName:    "r2s-backup",
			DNSName:      "r2s-backup.example.ts.net.",
			TailscaleIPs: []string{"100.64.200.3"},
		},
	}

	m, ok := tailscale.MatchConfiguredPeer(config.TailscaleP2PPeerConfig{ID: "nRemoteB", Name: "ImmortalWrt"}, peers, "nSelf111")
	if !ok || m.ID != "nRemoteB" {
		t.Fatalf("expected ID match nRemoteB, got ok=%v peer=%+v", ok, m)
	}

	m, ok = tailscale.MatchConfiguredPeer(config.TailscaleP2PPeerConfig{TailscaleIP: "100.64.200.2"}, peers, "nSelf111")
	if !ok || m.ID != "nRemoteA" {
		t.Fatalf("expected IP match nRemoteA, got ok=%v peer=%+v", ok, m)
	}

	m, ok = tailscale.MatchConfiguredPeer(config.TailscaleP2PPeerConfig{Name: "AX3000T-REMOTE"}, peers, "nSelf111")
	if !ok || m.ID != "nRemoteA" {
		t.Fatalf("expected ShortName match nRemoteA, got ok=%v peer=%+v", ok, m)
	}

	if m, ok := tailscale.MatchConfiguredPeer(config.TailscaleP2PPeerConfig{ID: "nSelf111", Name: "n4120"}, peers, "nSelf111"); ok || m != nil {
		t.Fatalf("expected Self ID to never match, got %+v", m)
	}
}

func TestP2PAssistController_ReusesDefaultLocalAPIClient(t *testing.T) {
	ctrl := &tailscale.P2PAssistController{}
	first := ctrl.EffectiveLocalAPI()
	second := ctrl.EffectiveLocalAPI()
	if first != tailscale.DefaultLocalAPIClient() || second != tailscale.DefaultLocalAPIClient() {
		t.Fatalf("expected P2PAssistController.EffectiveLocalAPI() to return singleton DefaultLocalAPIClient()")
	}
}

func TestUnixLocalAPIClient_ReusesUnixConnectionAcrossCalls(t *testing.T) {
	sockDir, err := os.MkdirTemp("/tmp", "ts-sock-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	sockPath := filepath.Join(sockDir, "tailscaled.sock")

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	var newConns atomic.Int32
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/localapi/v0/status" {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"BackendState":"Running","Self":{"ID":"self1","HostName":"router","DNSName":"router.tail.ts.net.","TailscaleIPs":["100.64.0.1"],"Online":true},"Peer":{}}`))
		}),
		ConnState: func(_ net.Conn, st http.ConnState) {
			if st == http.StateNew {
				newConns.Add(1)
			}
		},
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	client := &tailscale.UnixLocalAPIClient{SocketPath: sockPath}
	tr, ok := client.HTTPClient().Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport, got %T", client.HTTPClient().Transport)
	}
	if tr.IdleConnTimeout <= 0 || tr.MaxIdleConns <= 0 {
		t.Fatalf("expected positive IdleConnTimeout & MaxIdleConns, got IdleConnTimeout=%v MaxIdleConns=%d", tr.IdleConnTimeout, tr.MaxIdleConns)
	}

	const calls = 20
	for i := range calls {
		snap, err := client.Status(t.Context())
		if err != nil {
			t.Fatalf("call %d Status failed: %v", i, err)
		}
		if snap.BackendState != "Running" {
			t.Fatalf("call %d unexpected BackendState=%q", i, snap.BackendState)
		}
	}

	if got := newConns.Load(); got > 2 {
		t.Fatalf("expected Unix socket keep-alive reuse (<= 2 connections across %d calls), got %d", calls, got)
	}
}
