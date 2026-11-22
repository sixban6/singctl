// 文件职责：覆盖 clashapi 统一客户端的端点解析、策略切换、并发测速、SSRF 防护、流式流量摘要、DNS 探活与并发竞态测试。
package clashapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"singctl/internal/singbox/clashapi"
)

func TestNormalizeBaseURL_And_ValidateProbeURL(t *testing.T) {
	normCases := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"   ", ""},
		{"127.0.0.1:9099", "http://127.0.0.1:9099"},
		{":9090", "http://127.0.0.1:9090"},
		{"0.0.0.0:9090", "http://127.0.0.1:9090"},
		{"[::]:9090", "http://127.0.0.1:9090"},
		{"http://127.0.0.1:9090/", "http://127.0.0.1:9090"},
	}
	for _, tc := range normCases {
		if got := clashapi.NormalizeBaseURL(tc.in); got != tc.want {
			t.Fatalf("NormalizeBaseURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}

	if err := clashapi.ValidateProbeURL(clashapi.DefaultDelayProbeURL); err != nil {
		t.Fatalf("expected valid default probe URL, got %v", err)
	}
	badURLs := []string{
		"",
		"not-a-url",
		"ftp://example.com/204",
		"file:///etc/passwd",
		"https://user:pass@example.com/204",
		"http://localhost:8090/api/status",
		"http://sub.localhost/test",
		"http://router.local/probe",
		"http://127.0.0.1:8080/health",
		"http://[::1]:8080/",
		"http://10.0.0.1/status",
		"http://192.168.1.1/",
		"http://169.254.169.254/latest/meta-data/",
		"http://100.64.0.1/",
		"http://0.0.0.0/",
		"http://198.18.0.1/",
	}
	for _, u := range badURLs {
		if err := clashapi.ValidateProbeURL(u); err == nil {
			t.Fatalf("expected SSRF rejection for %q, got nil", u)
		}
	}
}

func TestResolveOutboundChain_CycleAndGroupHelpers(t *testing.T) {
	if !clashapi.IsProxyGroupType("selector") || !clashapi.IsProxyGroupType("URLTest") || clashapi.IsProxyGroupType("vless") {
		t.Fatal("unexpected IsProxyGroupType classification")
	}
	if clashapi.CanonicalGroupType("urltest") != "URLTest" || clashapi.CanonicalGroupType("selector") != "Selector" {
		t.Fatal("unexpected CanonicalGroupType")
	}

	proxies := map[string]clashapi.ProxyItem{
		"Proxy": {Type: "Selector", Now: "#Auto"},
		"#Auto": {Type: "URLTest", Now: "HK-01", History: []clashapi.HistoryEntry{{Delay: 55}}},
		"HK-01": {Type: "VLESS", History: []clashapi.HistoryEntry{{Delay: 42}}},
		"LoopA": {Type: "Selector", Now: "LoopB"},
		"LoopB": {Type: "Selector", Now: "LoopA"},
	}
	chain, leaf, delay := clashapi.ResolveOutboundChain(proxies, "Proxy")
	if !slices.Equal(chain, []string{"Proxy", "#Auto", "HK-01"}) || leaf != "HK-01" || delay != 42 {
		t.Fatalf("unexpected chain=(%v, %q, %d)", chain, leaf, delay)
	}
	// Cycle protection must terminate cleanly without infinite loop
	loopChain, loopLeaf, _ := clashapi.ResolveOutboundChain(proxies, "LoopA")
	if len(loopChain) != 2 || loopLeaf == "" {
		t.Fatalf("expected bounded cycle resolution, got chain=%v leaf=%q", loopChain, loopLeaf)
	}
}

func TestClient_EndToEndOperationsAndAuth(t *testing.T) {
	const secret = "clash-secret-xyz"
	var (
		mu          sync.Mutex
		curMode     = "rule"
		curProxyNow = "#Auto"
		deletedIDs  []string
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+secret {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		mu.Lock()
		modeSnap := curMode
		nowSnap := curProxyNow
		mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/version":
			_, _ = w.Write([]byte(`{"version":"1.14.0"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/configs":
			_ = json.NewEncoder(w).Encode(map[string]any{"mode": modeSnap})
		case r.Method == http.MethodPatch && r.URL.Path == "/configs":
			var body struct {
				Mode string `json:"mode"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			mu.Lock()
			curMode = body.Mode
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == "/proxies":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"proxies": map[string]any{
					"Proxy": map[string]any{"type": "Selector", "now": nowSnap, "all": []string{"#Auto", "SG-01"}},
					"SG-01": map[string]any{"type": "VLESS", "udp": true},
					"JP-02": map[string]any{"type": "Hysteria2", "udp": true},
				},
			})
		case r.Method == http.MethodPut && r.URL.Path == "/proxies/Proxy":
			var body struct {
				Name string `json:"name"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			mu.Lock()
			curProxyNow = body.Name
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/proxies/") && strings.HasSuffix(r.URL.Path, "/delay"):
			raw := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/proxies/"), "/delay")
			node, _ := url.PathUnescape(raw)
			if node == "SG-01" {
				_, _ = w.Write([]byte(`{"delay":38}`))
				return
			}
			http.Error(w, `{"message":"timeout"}`, http.StatusGatewayTimeout)
		case r.Method == http.MethodGet && r.URL.Path == "/connections":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"uploadTotal":   1024,
				"downloadTotal": 4096,
				"memory":        16777216,
				"connections": []map[string]any{
					{
						"id":       "c-1",
						"upload":   512,
						"download": 2048,
						"chains":   []string{"SG-01", "Proxy"},
						"rule":     "final",
						"metadata": map[string]any{
							"network":         "tcp",
							"type":            "mixed",
							"sourceIP":        "192.168.1.50",
							"destinationIP":   "198.51.100.10",
							"destinationPort": "443",
							"host":            "api.example.com",
							"sniffHost":       "api.example.com",
						},
					},
				},
			})
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/connections/"):
			id := strings.TrimPrefix(r.URL.Path, "/connections/")
			mu.Lock()
			deletedIDs = append(deletedIDs, id)
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == "/traffic":
			_, _ = w.Write([]byte("{\"up\":111,\"down\":222}\n{\"up\":333,\"down\":444}\n"))
		case r.Method == http.MethodGet && r.URL.Path == "/memory":
			_, _ = w.Write([]byte("{\"inuse\":8388608}\n"))
		case r.Method == http.MethodGet && r.URL.Path == "/dns/query":
			qName := r.URL.Query().Get("name")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"Status": 0,
				"Answer": []map[string]any{
					{"Name": qName, "Type": 1, "TTL": 60, "data": "198.51.100.88"},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	sbPath := filepath.Join(dir, "config.json")
	ctrlAddr := strings.TrimPrefix(srv.URL, "http://")
	rawCfg := fmt.Sprintf(`{"experimental":{"clash_api":{"external_controller":%q,"secret":%q}}}`, ctrlAddr, secret)
	if err := os.WriteFile(sbPath, []byte(rawCfg), 0600); err != nil {
		t.Fatal(err)
	}

	cli := clashapi.NewClient(clashapi.Options{ConfigPath: sbPath})
	ctx := t.Context()

	base, sec, err := cli.ResolveEndpoint(ctx)
	if err != nil || base != srv.URL || sec != secret {
		t.Fatalf("ResolveEndpoint = (%q, %q, %v), want (%q, %q, nil)", base, sec, err, srv.URL, secret)
	}

	// Proxies + Mode + Switch + PatchMode
	proxies, err := cli.ProxiesAt(ctx, base, sec)
	if err != nil || proxies["Proxy"].Now != "#Auto" {
		t.Fatalf("ProxiesAt failed: %v %+v", err, proxies)
	}
	if baseAcross, mapAcross, err := cli.ResolveProxiesAcross(ctx, []string{"http://127.0.0.1:1", base}, sec); err != nil || baseAcross != base || len(mapAcross) != 3 {
		t.Fatalf("ResolveProxiesAcross failed: base=%q len=%d err=%v", baseAcross, len(mapAcross), err)
	}
	if err := cli.SwitchSelectorAt(ctx, base, sec, "Proxy", "SG-01"); err != nil {
		t.Fatalf("SwitchSelectorAt failed: %v", err)
	}
	if err := cli.PatchModeAt(ctx, base, sec, "global"); err != nil {
		t.Fatalf("PatchModeAt failed: %v", err)
	}
	if mode, err := cli.ModeAt(ctx, base, sec); err != nil || mode != "global" {
		t.Fatalf("ModeAt = (%q, %v), want (global, nil)", mode, err)
	}

	// ProbeDelay + ProbeDelaysBatch
	d, err := cli.ProbeDelayAt(ctx, base, sec, "SG-01", clashapi.DefaultDelayProbeURL, 1500)
	if err != nil || d != 38 {
		t.Fatalf("ProbeDelayAt(SG-01) = (%d, %v), want (38, nil)", d, err)
	}
	batch := cli.ProbeDelaysBatchAt(ctx, base, sec, []string{"SG-01", "JP-02"}, clashapi.DefaultDelayProbeURL, 1500, 4)
	if batch["SG-01"] != 38 || batch["JP-02"] != 0 {
		t.Fatalf("unexpected ProbeDelaysBatchAt: %+v", batch)
	}

	// Connections + Summary + CloseConnection
	snap, err := cli.ConnectionsAt(ctx, base, sec)
	if err != nil || len(snap.Connections) != 1 || snap.Connections[0].Metadata.Host != "api.example.com" {
		t.Fatalf("ConnectionsAt failed: %v %+v", err, snap)
	}
	upTot, dnTot, cnt, ok := cli.ConnectionsSummaryAt(ctx, base, sec)
	if !ok || upTot != 1024 || dnTot != 4096 || cnt != 1 {
		t.Fatalf("ConnectionsSummaryAt = (%d, %d, %d, %v)", upTot, dnTot, cnt, ok)
	}
	if err := cli.CloseConnectionAt(ctx, base, sec, "c-1"); err != nil || !slices.Equal(deletedIDs, []string{"c-1"}) {
		t.Fatalf("CloseConnectionAt failed: err=%v deleted=%v", err, deletedIDs)
	}

	// Stream objects + StreamTrafficAt
	var mem struct {
		Inuse int64 `json:"inuse"`
	}
	if !cli.ReadFirstStreamObjectAt(ctx, base, sec, "/memory", &mem) || mem.Inuse != 8388608 {
		t.Fatalf("ReadFirstStreamObjectAt(/memory) failed: %+v", mem)
	}
	var ticks [][2]int64
	streamCtx, cancelStream := context.WithTimeout(ctx, 2*time.Second)
	defer cancelStream()
	_ = cli.StreamTrafficAt(streamCtx, base, sec, func(up, down int64) {
		ticks = append(ticks, [2]int64{up, down})
	})
	if len(ticks) != 2 || ticks[0] != [2]int64{111, 222} || ticks[1] != [2]int64{333, 444} {
		t.Fatalf("unexpected StreamTrafficAt ticks: %+v", ticks)
	}

	// QueryDNSAcross (auth check + valid A record)
	badOK, _, _ := cli.QueryDNSAcross(ctx, []string{base}, "wrong-secret", []string{"example.com"})
	if badOK {
		t.Fatal("expected QueryDNSAcross with wrong secret to fail")
	}
	dnsOK, latMs, detail := cli.QueryDNSAcross(ctx, []string{base}, sec, []string{"example.com"})
	if !dnsOK || latMs <= 0 || !strings.Contains(detail, "198.51.100.88") {
		t.Fatalf("QueryDNSAcross = (%v, %d, %q)", dnsOK, latMs, detail)
	}
}

func buildSyntheticConnectionsJSON(n int) []byte {
	var buf bytes.Buffer
	buf.Grow(n * 260)
	buf.WriteString(`{"downloadTotal":9876543210,"uploadTotal":123456789,"memory":45678912,"connections":[`)
	for i := range n {
		if i > 0 {
			buf.WriteByte(',')
		}
		fmt.Fprintf(&buf,
			`{"id":"conn-%d","upload":%d,"download":%d,"chains":["Proxy"],"rule":"final","metadata":{"network":"tcp","sourceIP":"192.168.1.%d","destinationIP":"203.0.113.%d","destinationPort":"443","host":"cdn%d.example.com"}}`,
			i, i*128, i*2048, (i%200)+1, (i%200)+1, i%10,
		)
	}
	buf.WriteString(`]}`)
	return buf.Bytes()
}

func TestDecodeConnectionsSummary_BoundariesAndConcurrentRace(t *testing.T) {
	payload := buildSyntheticConnectionsJSON(300)
	up, down, cnt, ok := clashapi.DecodeConnectionsSummary(bytes.NewReader(payload))
	if !ok || up != 123456789 || down != 9876543210 || cnt != 300 {
		t.Fatalf("got (%d, %d, %d, %v)", up, down, cnt, ok)
	}

	for _, validEdge := range []string{
		`{"uploadTotal":10,"downloadTotal":20,"connections":[]}`,
		`{"uploadTotal":10,"downloadTotal":20,"connections":null}`,
		`{"connections":[{"id":"a","extra":{"nested":[1,true,null]}}],"unknown":[1,2],"uploadTotal":5,"downloadTotal":9}`,
	} {
		if _, _, _, ok := clashapi.DecodeConnectionsSummary(strings.NewReader(validEdge)); !ok {
			t.Fatalf("expected valid summary decode for %s", validEdge)
		}
	}

	for _, bad := range []string{
		``,
		`not-json`,
		`[]`,
		`{"uploadTotal":"bad","connections":[]}`,
		`{"connections":{}}`,
		`{"uploadTotal":1,"connections":[{}`,
		`{"uploadTotal":1,"connections":[]} trailing`,
	} {
		if _, _, _, ok := clashapi.DecodeConnectionsSummary(strings.NewReader(bad)); ok {
			t.Fatalf("expected malformed input %q to return ok=false", bad)
		}
	}

	var connCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		connCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(payload)
	}))
	defer srv.Close()

	cli := clashapi.NewClient(clashapi.Options{})
	var wg sync.WaitGroup
	for range 12 {
		wg.Go(func() {
			for range 10 {
				u, d, c, ok := cli.ConnectionsSummaryAt(t.Context(), srv.URL, "")
				if !ok || u != 123456789 || d != 9876543210 || c != 300 {
					t.Errorf("unexpected concurrent summary (%d, %d, %d, %v)", u, d, c, ok)
					return
				}
			}
		})
	}
	wg.Wait()
	if connCount.Load() != 120 {
		t.Fatalf("expected 120 requests served, got %d", connCount.Load())
	}
}

func BenchmarkDecodeConnectionsSummary_800(b *testing.B) {
	payload := buildSyntheticConnectionsJSON(800)
	var r bytes.Reader
	b.ReportAllocs()
	for b.Loop() {
		r.Reset(payload)
		_, _, cnt, ok := clashapi.DecodeConnectionsSummary(&r)
		if !ok || cnt != 800 {
			b.Fatalf("got (%d, %v)", cnt, ok)
		}
	}
}
