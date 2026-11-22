// 文件职责：覆盖 dohprobe 领域检测器的两阶段流量差分、双栈同机关联、Anycast 防误报、ClashAPI 接入与并发竞态测试。
package dohprobe_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"singctl/internal/netdiag"
	"singctl/internal/netdiag/dohprobe"
	"singctl/internal/singbox/clashapi"
)

func TestNormalizeHelpers_And_ResolveClientIP(t *testing.T) {
	if got := dohprobe.NormalizeIPString("[fd00:1::50%eth0]"); got != "fd00:1::50" {
		t.Fatalf("NormalizeIPString = %q, want fd00:1::50", got)
	}
	if dohprobe.NormalizeIPString("invalid-ip") != "" {
		t.Fatal("expected empty string for invalid IP")
	}
	if !dohprobe.IsPrivateLANAddr("192.168.1.50") || !dohprobe.IsPrivateLANAddr("fd00:1::50") {
		t.Fatal("expected private LAN addresses to be recognized")
	}
	for _, nonLAN := range []string{"", "127.0.0.1", "::1", "100.64.0.10", "fd7a:115c:a1e0::1", "198.51.100.20"} {
		if dohprobe.IsPrivateLANAddr(nonLAN) {
			t.Fatalf("expected %q to NOT be private LAN", nonLAN)
		}
	}
	if dohprobe.NormalizeDNSOrgFamily("Google Public DNS", "203.0.113.8") != "google" ||
		dohprobe.NormalizeDNSOrgFamily("", "1.1.1.1") != "cloudflare" ||
		dohprobe.NormalizeDNSOrgFamily("Alibaba Cloud", "223.5.5.5") != "alibaba" {
		t.Fatal("unexpected DNS org family normalization")
	}

	p := dohprobe.NewProber(dohprobe.Deps{})
	req := httptest.NewRequest(http.MethodPost, "/api/dns/browser-doh", nil)
	req.RemoteAddr = "127.0.0.1:54321"
	req.Header.Set("X-Forwarded-For", "192.168.1.88, 127.0.0.1")
	if got := p.ResolveClientIP(req); got != "192.168.1.88" {
		t.Fatalf("ResolveClientIP(loopback XFF) = %q, want 192.168.1.88", got)
	}

	// Non-loopback remote addr must NOT spoof X-Forwarded-For
	reqDirect := httptest.NewRequest(http.MethodPost, "/api/dns/browser-doh", nil)
	reqDirect.RemoteAddr = "192.168.1.77:51000"
	reqDirect.Header.Set("X-Forwarded-For", "192.168.1.1")
	if got := p.ResolveClientIP(reqDirect); got != "192.168.1.77" {
		t.Fatalf("ResolveClientIP(LAN spoofed XFF) = %q, want 192.168.1.77", got)
	}
}

func TestProber_SkipGuards_And_Unavailable(t *testing.T) {
	p := dohprobe.NewProber(dohprobe.Deps{
		ClashConnections: func(context.Context) ([]dohprobe.ClashConn, error) {
			return nil, errors.New("clash offline")
		},
		GatewayEDNSProber: func(context.Context) (*netdiag.DNSResolverProfile, error) {
			return nil, errors.New("edns offline")
		},
	})
	ctx := t.Context()

	tsResp := p.Check(ctx, "100.64.0.10", true, dohprobe.CheckRequest{})
	if tsResp.Status != "skipped_remote" || !tsResp.ViaTailscale || tsResp.IsLANClient {
		t.Fatalf("expected skipped_remote via tailscale, got %+v", tsResp)
	}

	loopResp := p.Check(ctx, "127.0.0.1", false, dohprobe.CheckRequest{})
	if loopResp.Status != "skipped_remote" || loopResp.ViaTailscale || loopResp.IsLANClient {
		t.Fatalf("expected skipped_remote for loopback, got %+v", loopResp)
	}

	unavail := p.Check(ctx, "192.168.1.50", false, dohprobe.CheckRequest{})
	if unavail.Status != "unavailable" || unavail.Confidence != "none" {
		t.Fatalf("expected unavailable when clash & edns both fail, got %+v", unavail)
	}
}

func TestProber_CleanSameOrg_DirectDetect_And_DualStackSibling(t *testing.T) {
	ctx := t.Context()

	// 1. Same Google org family without public DoH connection => clean
	pClean := dohprobe.NewProber(dohprobe.Deps{
		ClashConnections: func(context.Context) ([]dohprobe.ClashConn, error) {
			return []dohprobe.ClashConn{
				{SourceIP: "192.168.1.50", DestIP: "198.51.100.20", DestPort: "443", Host: "api.example.com", Network: "tcp", Rule: "Match"},
			}, nil
		},
		GatewayEDNSProber: func(context.Context) (*netdiag.DNSResolverProfile, error) {
			return &netdiag.DNSResolverProfile{IP: "198.51.100.1", CountryCode: "US", ISP: "Google LLC"}, nil
		},
	})
	r1 := pClean.Check(ctx, "192.168.1.50", false, dohprobe.CheckRequest{
		BrowserSamples:        []dohprobe.EDNSSample{{DNSIP: "203.0.113.8", CountryCode: "US", ISP: "Google Public DNS"}},
		BrowserProbeAttempted: 2,
	})
	if r1.Status != "clean" {
		t.Fatalf("expected clean for same Google org family, got %+v", r1)
	}

	// 2. Sibling IPv6 via MAC lookup + device isolation + REJECT rule signal
	pSibling := dohprobe.NewProber(dohprobe.Deps{
		PeerIPsForMAC: func(_ context.Context, clientIP string) []string {
			if clientIP == "192.168.1.50" {
				return []string{"fd00:1::50"}
			}
			return nil
		},
		ClashConnections: func(context.Context) ([]dohprobe.ClashConn, error) {
			return []dohprobe.ClashConn{
				{SourceIP: "192.168.1.99", DestIP: "8.8.8.8", DestPort: "443", Host: "dns.google", Network: "tcp"},
				{SourceIP: "fd00:1::50", DestIP: "1.1.1.1", DestPort: "443", Network: "tcp", Rule: "REJECT"},
			}, nil
		},
		GatewayEDNSProber: func(context.Context) (*netdiag.DNSResolverProfile, error) {
			return &netdiag.DNSResolverProfile{IP: "198.51.100.2", CountryCode: "SG", ISP: "Cloudflare, Inc."}, nil
		},
	})
	r2 := pSibling.Check(ctx, "192.168.1.50", false, dohprobe.CheckRequest{BrowserProbeAttempted: 2})
	if r2.Status != "detected" || r2.Confidence != "high" || r2.DetectedProvider != "Cloudflare DoH" {
		t.Fatalf("expected Cloudflare DoH via sibling IPv6, got %+v", r2)
	}
	if len(r2.MatchedEndpoints) != 1 || r2.MatchedEndpoints[0].SourceIP != "fd00:1::50" {
		t.Fatalf("expected isolated sibling endpoint, got %+v", r2.MatchedEndpoints)
	}
	// Device 192.168.1.55 has no DoH connections -> must be clean
	rIsolated := pSibling.Check(ctx, "192.168.1.55", false, dohprobe.CheckRequest{BrowserProbeAttempted: 2})
	if rIsolated.Status != "clean" {
		t.Fatalf("expected clean for isolated device, got %+v", rIsolated)
	}
}

func TestProber_StrictConflict_CNLeak_And_CustomMismatch(t *testing.T) {
	ctx := t.Context()
	p := dohprobe.NewProber(dohprobe.Deps{
		ClashConnections: func(context.Context) ([]dohprobe.ClashConn, error) { return nil, nil },
		GatewayEDNSProber: func(context.Context) (*netdiag.DNSResolverProfile, error) {
			return &netdiag.DNSResolverProfile{IP: "198.51.100.1", CountryCode: "JP", ISP: "Google LLC"}, nil
		},
	})

	conflict := p.Check(ctx, "192.168.1.50", false, dohprobe.CheckRequest{
		BrowserProbeAttempted: 2,
		BrowserProbeFailed:    2,
	})
	if conflict.Status != "detected" || conflict.Confidence != "medium" {
		t.Fatalf("expected strict conflict detected, got %+v", conflict)
	}

	cnLeak := p.Check(ctx, "192.168.1.50", false, dohprobe.CheckRequest{
		BrowserSamples:        []dohprobe.EDNSSample{{DNSIP: "203.0.113.114", CountryCode: "CN", ISP: "AliDNS"}},
		BrowserProbeAttempted: 2,
	})
	if cnLeak.Status != "suspected" || cnLeak.DetectedProvider != "AliDNS" {
		t.Fatalf("expected CN leak suspected, got %+v", cnLeak)
	}

	mismatch := p.Check(ctx, "192.168.1.50", false, dohprobe.CheckRequest{
		BrowserSamples:        []dohprobe.EDNSSample{{DNSIP: "203.0.113.9", CountryCode: "CH", ISP: "Quad9"}},
		BrowserProbeAttempted: 2,
	})
	if mismatch.Status != "suspected" || mismatch.Confidence != "medium" {
		t.Fatalf("expected org mismatch suspected, got %+v", mismatch)
	}
}

func TestProber_TwoPhaseDelta_ClashClientWiring_And_ConcurrentRace(t *testing.T) {
	var mu sync.Mutex
	upBytes := int64(2000)
	downBytes := int64(3000)

	clashSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/version":
			_, _ = w.Write([]byte(`{"version":"1.14.0"}`))
		case "/connections":
			mu.Lock()
			u, d := upBytes, downBytes
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{
				"connections": []map[string]any{
					{
						"id":       "keepalive-1",
						"upload":   u,
						"download": d,
						"rule":     "RuleSet",
						"metadata": map[string]any{
							"network":         "tcp",
							"sourceIP":        "192.168.1.50",
							"destinationIP":   "8.8.4.4",
							"destinationPort": "443",
							"host":            "dns.google",
						},
					},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer clashSrv.Close()

	cli := clashapi.NewClient(clashapi.Options{Endpoints: []string{clashSrv.URL}})
	p := dohprobe.NewProber(dohprobe.Deps{
		SingBoxRunning: func() bool { return true },
		ClashClient:    cli,
		PeerIPsForMAC:  func(context.Context, string) []string { return nil },
		GatewayEDNSProber: func(context.Context) (*netdiag.DNSResolverProfile, error) {
			return &netdiag.DNSResolverProfile{IP: "198.51.100.1", CountryCode: "US", ISP: "Google LLC"}, nil
		},
	})
	ctx := t.Context()

	// 1. Idle keep-alive (tiny 24-byte PING growth) -> ignored cleanly
	begin1 := p.Check(ctx, "192.168.1.50", false, dohprobe.CheckRequest{Phase: "begin"})
	if begin1.Status != "pending" || begin1.ProbeID == "" {
		t.Fatalf("expected pending begin, got %+v", begin1)
	}
	mu.Lock()
	upBytes += 12
	downBytes += 12
	mu.Unlock()
	fin1 := p.Check(ctx, "192.168.1.50", false, dohprobe.CheckRequest{
		Phase:                 "finish",
		ProbeID:               begin1.ProbeID,
		BrowserSamples:        []dohprobe.EDNSSample{{DNSIP: "203.0.113.8", CountryCode: "US", ISP: "Google LLC"}},
		BrowserProbeAttempted: 3,
	})
	if fin1.Status != "clean" || fin1.IdleLeftoverCount != 1 {
		t.Fatalf("expected clean + idleLeftoverCount=1, got %+v", fin1)
	}

	// 2. Active DoH query traffic growth -> detected
	begin2 := p.Check(ctx, "192.168.1.50", false, dohprobe.CheckRequest{Phase: "begin"})
	mu.Lock()
	upBytes += 480
	downBytes += 720
	mu.Unlock()
	fin2 := p.Check(ctx, "192.168.1.50", false, dohprobe.CheckRequest{
		Phase:                 "finish",
		ProbeID:               begin2.ProbeID,
		BrowserSamples:        []dohprobe.EDNSSample{{DNSIP: "203.0.113.8", CountryCode: "US", ISP: "Google LLC"}},
		BrowserProbeAttempted: 3,
	})
	if fin2.Status != "detected" || fin2.DetectedProvider != "Google Public DoH" {
		t.Fatalf("expected detected on active socket growth, got %+v", fin2)
	}

	// 3. Concurrent begin/finish race stress across multiple LAN clients
	var wg sync.WaitGroup
	for i := range 8 {
		clientAddr := "192.168.1." + string(rune('2'+i)) + "0"
		wg.Go(func() {
			b := p.Check(ctx, clientAddr, false, dohprobe.CheckRequest{Phase: "begin"})
			_ = p.Check(ctx, clientAddr, false, dohprobe.CheckRequest{Phase: "finish", ProbeID: b.ProbeID})
		})
	}
	wg.Wait()
}
