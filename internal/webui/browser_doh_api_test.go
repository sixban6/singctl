package webui

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"singctl/internal/netdiag"
)

func postBrowserDoH(t *testing.T, srv *Server, payload string) browserDoHCheckResponse {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/dns/browser-doh", bytes.NewBufferString(payload))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.Mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/dns/browser-doh returned HTTP %d: %s", rec.Code, rec.Body.String())
	}
	var resp browserDoHCheckResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal browser-doh response: %v", err)
	}
	return resp
}

func TestBrowserDoHCheck_TailscaleClientSkipped(t *testing.T) {
	srv := New(Options{
		ConfigPath: "/nonexistent/singctl.yaml",
		BrowserDoHForTest: &BrowserDoHTestHooks{
			ClientIP: "100.64.0.10",
		},
	})
	resp := postBrowserDoH(t, srv, `{}`)
	if resp.Status != "skipped_remote" || !resp.ViaTailscale || resp.IsLANClient {
		t.Fatalf("expected skipped_remote for tailscale client, got %+v", resp)
	}
}

func TestBrowserDoHCheck_CleanSameOrgAnycastNoFalsePositive(t *testing.T) {
	srv := New(Options{
		ConfigPath: "/nonexistent/singctl.yaml",
		BrowserDoHForTest: &BrowserDoHTestHooks{
			ClientIP: "192.168.1.50",
			ClashConnections: func(context.Context) ([]BrowserDoHClashConn, error) {
				return []BrowserDoHClashConn{
					{
						SourceIP: "192.168.1.50",
						DestIP:   "198.51.100.20",
						DestPort: "443",
						Host:     "api.example.com",
						Network:  "tcp",
						Rule:     "Match",
						Chains:   []string{"#VPS"},
					},
				}, nil
			},
			GatewayEDNSProber: func(context.Context) (*netdiag.DNSResolverProfile, error) {
				return &netdiag.DNSResolverProfile{
					IP:          "198.51.100.1",
					Country:     "United States",
					CountryCode: "US",
					ISP:         "Google LLC",
				}, nil
			},
		},
	})

	resp := postBrowserDoH(t, srv, `{
		"browserSamples": [
			{"dnsIp": "203.0.113.8", "country": "United States", "countryCode": "US", "isp": "Google Public DNS"}
		],
		"browserProbeAttempted": 2,
		"browserProbeFailed": 0
	}`)
	if resp.Status != "clean" {
		t.Fatalf("expected clean when browser and gateway share Google anycast family, got %+v", resp)
	}
}

func TestBrowserDoHCheck_ClashDetectsSameProviderDoH(t *testing.T) {
	srv := New(Options{
		ConfigPath: "/nonexistent/singctl.yaml",
		BrowserDoHForTest: &BrowserDoHTestHooks{
			ClientIP: "192.168.1.50",
			ClashConnections: func(context.Context) ([]BrowserDoHClashConn, error) {
				return []BrowserDoHClashConn{
					{
						SourceIP: "192.168.1.50",
						DestIP:   "8.8.8.8",
						DestPort: "443",
						Host:     "dns.google",
						Network:  "tcp",
						Rule:     "RuleSet",
					},
				}, nil
			},
			GatewayEDNSProber: func(context.Context) (*netdiag.DNSResolverProfile, error) {
				return &netdiag.DNSResolverProfile{
					IP:          "198.51.100.1",
					Country:     "United States",
					CountryCode: "US",
					ISP:         "Google LLC",
				}, nil
			},
		},
	})

	resp := postBrowserDoH(t, srv, `{
		"browserSamples": [
			{"dnsIp": "203.0.113.8", "country": "United States", "countryCode": "US", "isp": "Google LLC"}
		],
		"browserProbeAttempted": 2,
		"browserProbeFailed": 0
	}`)
	if resp.Status != "detected" || resp.Confidence != "high" {
		t.Fatalf("expected high-confidence detected for dns.google direct connection, got %+v", resp)
	}
	if resp.DetectedProvider != "Google Public DoH" || len(resp.MatchedEndpoints) != 1 {
		t.Fatalf("unexpected detected provider/endpoints: %+v", resp)
	}
}

func TestBrowserDoHCheck_DualStackSiblingIPv6AndDeviceIsolation(t *testing.T) {
	srv := New(Options{
		ConfigPath: "/nonexistent/singctl.yaml",
		BrowserDoHForTest: &BrowserDoHTestHooks{
			ClientIP: "192.168.1.50",
			PeerIPsForMAC: func(string) []string {
				return []string{"fd00:1::50"}
			},
			ClashConnections: func(context.Context) ([]BrowserDoHClashConn, error) {
				return []BrowserDoHClashConn{
					// Different LAN device connecting to Cloudflare DoH: must NOT alert client 192.168.1.50
					{
						SourceIP: "192.168.1.99",
						DestIP:   "1.1.1.1",
						DestPort: "443",
						Host:     "cloudflare-dns.com",
						Network:  "tcp",
					},
					// Same device over IPv6 connecting directly to raw 1.1.1.1:443 (empty Host)
					{
						SourceIP: "fd00:1::50",
						DestIP:   "1.1.1.1",
						DestPort: "443",
						Network:  "tcp",
					},
				}, nil
			},
			GatewayEDNSProber: func(context.Context) (*netdiag.DNSResolverProfile, error) {
				return &netdiag.DNSResolverProfile{IP: "198.51.100.2", CountryCode: "SG", ISP: "Cloudflare, Inc."}, nil
			},
		},
	})

	resp := postBrowserDoH(t, srv, `{"browserProbeAttempted":2,"browserProbeFailed":0}`)
	if resp.Status != "detected" || resp.DetectedProvider != "Cloudflare DoH" {
		t.Fatalf("expected Cloudflare DoH detection via MAC sibling IPv6, got %+v", resp)
	}
	if len(resp.MatchedEndpoints) != 1 || resp.MatchedEndpoints[0].SourceIP != "fd00:1::50" {
		t.Fatalf("expected only sibling IPv6 match, got %+v", resp.MatchedEndpoints)
	}

	// Verify isolation when only 192.168.1.99 uses DoH and 192.168.1.50 does not.
	srvIsolated := New(Options{
		ConfigPath: "/nonexistent/singctl.yaml",
		BrowserDoHForTest: &BrowserDoHTestHooks{
			ClientIP: "192.168.1.50",
			ClashConnections: func(context.Context) ([]BrowserDoHClashConn, error) {
				return []BrowserDoHClashConn{
					{
						SourceIP: "192.168.1.99",
						DestIP:   "1.1.1.1",
						DestPort: "443",
						Host:     "cloudflare-dns.com",
					},
				}, nil
			},
			GatewayEDNSProber: func(context.Context) (*netdiag.DNSResolverProfile, error) {
				return &netdiag.DNSResolverProfile{IP: "198.51.100.2", CountryCode: "SG", ISP: "Cloudflare, Inc."}, nil
			},
		},
	})
	isolatedResp := postBrowserDoH(t, srvIsolated, `{"browserProbeAttempted":2,"browserProbeFailed":0}`)
	if isolatedResp.Status != "clean" {
		t.Fatalf("expected clean when only another LAN device uses DoH, got %+v", isolatedResp)
	}
}

func TestBrowserDoHCheck_StrictConflictAndCustomResolverSuspected(t *testing.T) {
	srvConflict := New(Options{
		ConfigPath: "/nonexistent/singctl.yaml",
		BrowserDoHForTest: &BrowserDoHTestHooks{
			ClientIP: "192.168.1.50",
			ClashConnections: func(context.Context) ([]BrowserDoHClashConn, error) {
				return nil, nil
			},
			GatewayEDNSProber: func(context.Context) (*netdiag.DNSResolverProfile, error) {
				return &netdiag.DNSResolverProfile{IP: "198.51.100.1", CountryCode: "JP", ISP: "Cloudflare, Inc."}, nil
			},
		},
	})
	conflictResp := postBrowserDoH(t, srvConflict, `{
		"browserSamples": [],
		"browserProbeAttempted": 2,
		"browserProbeFailed": 2
	}`)
	if conflictResp.Status != "detected" || conflictResp.Confidence != "medium" {
		t.Fatalf("expected detected on strict DoH conflict, got %+v", conflictResp)
	}

	srvMismatch := New(Options{
		ConfigPath: "/nonexistent/singctl.yaml",
		BrowserDoHForTest: &BrowserDoHTestHooks{
			ClientIP: "192.168.1.50",
			ClashConnections: func(context.Context) ([]BrowserDoHClashConn, error) {
				return nil, nil
			},
			GatewayEDNSProber: func(context.Context) (*netdiag.DNSResolverProfile, error) {
				return &netdiag.DNSResolverProfile{IP: "198.51.100.1", CountryCode: "US", ISP: "Google LLC"}, nil
			},
		},
	})
	mismatchResp := postBrowserDoH(t, srvMismatch, `{
		"browserSamples": [
			{"dnsIp": "203.0.113.9", "country": "Switzerland", "countryCode": "CH", "isp": "Quad9"}
		],
		"browserProbeAttempted": 2,
		"browserProbeFailed": 0
	}`)
	if mismatchResp.Status != "suspected" || mismatchResp.Confidence != "medium" {
		t.Fatalf("expected suspected on custom resolver mismatch, got %+v", mismatchResp)
	}
}

func TestBrowserDoHCheck_TwoPhaseIgnoresStaleIdleKeepAlive(t *testing.T) {
	conns := []BrowserDoHClashConn{
		{
			ID:       "conn-stale-1",
			Upload:   2652,
			Download: 3296,
			SourceIP: "192.168.1.50",
			DestIP:   "8.8.4.4",
			DestPort: "443",
			Host:     "dns.google",
			Network:  "tcp",
		},
		{
			ID:       "conn-stale-2",
			Upload:   4992,
			Download: 10171,
			SourceIP: "192.168.1.50",
			DestIP:   "8.8.4.4",
			DestPort: "443",
			Host:     "dns.google",
			Network:  "tcp",
		},
	}

	srv := New(Options{
		ConfigPath: "/nonexistent/singctl.yaml",
		BrowserDoHForTest: &BrowserDoHTestHooks{
			ClientIP: "192.168.1.50",
			ClashConnections: func(context.Context) ([]BrowserDoHClashConn, error) {
				return conns, nil
			},
			GatewayEDNSProber: func(context.Context) (*netdiag.DNSResolverProfile, error) {
				return &netdiag.DNSResolverProfile{IP: "198.51.100.1", CountryCode: "US", ISP: "Google LLC"}, nil
			},
		},
	})

	// 1. Exact 0-byte growth across both sockets
	beginResp := postBrowserDoH(t, srv, `{"phase":"begin"}`)
	if beginResp.Status != "pending" || beginResp.ProbeID == "" {
		t.Fatalf("expected pending begin response with probeId, got %+v", beginResp)
	}

	finishResp := postBrowserDoH(t, srv, `{
		"phase": "finish",
		"probeId": "`+beginResp.ProbeID+`",
		"browserSamples": [{"dnsIp": "203.0.113.8", "countryCode": "US", "isp": "Google LLC"}],
		"browserProbeAttempted": 3,
		"browserProbeFailed": 0
	}`)
	if finishResp.Status != "clean" || finishResp.IdleLeftoverCount != 2 {
		t.Fatalf("expected clean + idleLeftoverCount=2 for zero-delta keepalive sockets, got %+v", finishResp)
	}

	// 2. Tiny 24-byte HTTP/2 PING keepalive frame growth still ignored cleanly
	begin2 := postBrowserDoH(t, srv, `{"phase":"begin"}`)
	conns[0].Upload += 12
	conns[0].Download += 12
	finish2 := postBrowserDoH(t, srv, `{
		"phase": "finish",
		"probeId": "`+begin2.ProbeID+`",
		"browserSamples": [{"dnsIp": "203.0.113.8", "countryCode": "US", "isp": "Google LLC"}],
		"browserProbeAttempted": 3,
		"browserProbeFailed": 0
	}`)
	if finish2.Status != "clean" || finish2.IdleLeftoverCount != 2 {
		t.Fatalf("expected clean + idleLeftoverCount=2 for tiny keepalive PING delta, got %+v", finish2)
	}
}

func TestBrowserDoHCheck_TwoPhaseDetectsActiveKeepAliveGrowthAndNewConn(t *testing.T) {
	// Sub-case A: Existing keep-alive dns.google socket has significant active traffic during probe
	connsA := []BrowserDoHClashConn{
		{
			ID:       "conn-active-1",
			Upload:   2652,
			Download: 3296,
			SourceIP: "192.168.1.50",
			DestIP:   "8.8.4.4",
			DestPort: "443",
			Host:     "dns.google",
			Network:  "tcp",
		},
	}
	srvA := New(Options{
		ConfigPath: "/nonexistent/singctl.yaml",
		BrowserDoHForTest: &BrowserDoHTestHooks{
			ClientIP: "192.168.1.50",
			ClashConnections: func(context.Context) ([]BrowserDoHClashConn, error) {
				return connsA, nil
			},
			GatewayEDNSProber: func(context.Context) (*netdiag.DNSResolverProfile, error) {
				return &netdiag.DNSResolverProfile{IP: "198.51.100.1", CountryCode: "US", ISP: "Google LLC"}, nil
			},
		},
	})

	beginA := postBrowserDoH(t, srvA, `{"phase":"begin"}`)
	connsA[0].Upload += 548
	connsA[0].Download += 804
	finishA := postBrowserDoH(t, srvA, `{
		"phase": "finish",
		"probeId": "`+beginA.ProbeID+`",
		"browserSamples": [{"dnsIp": "203.0.113.8", "countryCode": "US", "isp": "Google LLC"}],
		"browserProbeAttempted": 3,
		"browserProbeFailed": 0
	}`)
	if finishA.Status != "detected" || finishA.Confidence != "high" || finishA.DetectedProvider != "Google Public DoH" {
		t.Fatalf("expected Google Public DoH detection on active keep-alive traffic growth, got %+v", finishA)
	}

	// Sub-case B: Brand-new cloudflare-dns.com socket opens between begin and finish
	connsB := []BrowserDoHClashConn{}
	srvB := New(Options{
		ConfigPath: "/nonexistent/singctl.yaml",
		BrowserDoHForTest: &BrowserDoHTestHooks{
			ClientIP: "192.168.1.50",
			ClashConnections: func(context.Context) ([]BrowserDoHClashConn, error) {
				return connsB, nil
			},
			GatewayEDNSProber: func(context.Context) (*netdiag.DNSResolverProfile, error) {
				return &netdiag.DNSResolverProfile{IP: "198.51.100.1", CountryCode: "US", ISP: "Google LLC"}, nil
			},
		},
	})
	beginB := postBrowserDoH(t, srvB, `{"phase":"begin"}`)
	connsB = append(connsB, BrowserDoHClashConn{
		ID:       "conn-new-cf",
		Upload:   320,
		Download: 410,
		SourceIP: "192.168.1.50",
		DestIP:   "1.1.1.1",
		DestPort: "443",
		Host:     "cloudflare-dns.com",
		Network:  "tcp",
	})
	finishB := postBrowserDoH(t, srvB, `{
		"phase": "finish",
		"probeId": "`+beginB.ProbeID+`",
		"browserProbeAttempted": 3,
		"browserProbeFailed": 0
	}`)
	if finishB.Status != "detected" || finishB.Confidence != "high" || finishB.DetectedProvider != "Cloudflare DoH" {
		t.Fatalf("expected Cloudflare DoH detection on newly opened socket, got %+v", finishB)
	}
}
