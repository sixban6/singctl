package subhub

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"singctl/internal/singbox"

	"gopkg.in/yaml.v3"
)

const (
	sampleHy2URI   = "hysteria2://testpass123@edge.example.com:443/?sni=edge.example.com&alpn=h3&insecure=0#Tokyo-Hy2"
	sampleVLESSURI = "vless://11111111-2222-3333-4444-555555555555@198.51.100.20:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk=AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfE&sid=a1b2c3d4&type=tcp#Tokyo-VLESS"
	sampleSSURI    = "ss://YWVzLTI1Ni1nY206c2VjcmV0cGFzcw@198.51.100.30:8388#SG-SS"
)

func seedLegacySubStoreJSON(t *testing.T, dir string) string {
	t.Helper()
	filePath := filepath.Join(dir, "sub-store.json")
	legacyDoc := map[string]any{
		"schemaVersion": "2.0",
		"customSetting": map[string]any{"theme": "dark"},
		"subs": []any{
			map[string]any{
				"name":         "auto_generated_hy2",
				"displayName":  "Hysteria2 Auto",
				"display-name": "Hysteria2 Auto",
				"source":       "local",
				"content":      sampleHy2URI,
			},
			map[string]any{
				"name":         "auto_generated_vless",
				"displayName":  "VLESS Reality Auto",
				"display-name": "VLESS Reality Auto",
				"source":       "local",
				"content":      sampleVLESSURI,
			},
		},
		"collections": []any{
			map[string]any{
				"name":          "all",
				"displayName":   "all",
				"subscriptions": []any{"auto_generated_hy2", "auto_generated_vless"},
			},
		},
	}
	raw, err := json.MarshalIndent(legacyDoc, "", "  ")
	if err != nil {
		t.Fatalf("marshal legacy json: %v", err)
	}
	if err := os.WriteFile(filePath, raw, 0600); err != nil {
		t.Fatalf("write legacy json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "key"), []byte("a1b2c3d4e5f60718293a4b5c6d"), 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return filePath
}

func TestStoreLegacyCompatibilityAndCRUD(t *testing.T) {
	dir := t.TempDir()
	filePath := seedLegacySubStoreJSON(t, dir)
	st := NewStore(dir, filePath)

	key, err := st.GetKey()
	if err != nil || key != "a1b2c3d4e5f60718293a4b5c6d" {
		t.Fatalf("expected seeded key, got %q (err=%v)", key, err)
	}

	sources, err := st.ListSources()
	if err != nil {
		t.Fatalf("ListSources failed: %v", err)
	}
	if len(sources) != 2 {
		t.Fatalf("expected 2 seeded sources, got %d", len(sources))
	}
	if !sources[0].AutoManaged || sources[0].NodeCount != 1 {
		t.Fatalf("unexpected source[0]: %+v", sources[0])
	}

	// Add custom local source
	added, err := st.UpsertSource(t.Context(), SourceUpsertInput{
		DisplayName: "My Backup Nodes",
		Source:      "local",
		Content:     sampleSSURI,
		Remark:      "Singapore standby",
	})
	if err != nil {
		t.Fatalf("UpsertSource local failed: %v", err)
	}
	if added.Name != "my-backup-nodes" || added.NodeCount != 1 {
		t.Fatalf("unexpected added source: %+v", added)
	}

	// Verify SSRF blocking when AllowLoopbackRemote == false
	if _, err := st.UpsertSource(t.Context(), SourceUpsertInput{
		Name:   "ssrf-loopback",
		Source: "remote",
		URL:    "http://127.0.0.1:8080/sub",
	}); err == nil {
		t.Fatal("expected SSRF block for 127.0.0.1 when AllowLoopbackRemote=false")
	}
	if _, err := st.UpsertSource(t.Context(), SourceUpsertInput{
		Name:   "ssrf-cgnat",
		Source: "remote",
		URL:    "http://100.64.0.1/sub",
	}); err == nil {
		t.Fatal("expected SSRF block for CGNAT 100.64.0.1 when AllowLoopbackRemote=false")
	}

	// Enable loopback remote for local httptest server verification
	remoteSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		encoded := base64.StdEncoding.EncodeToString([]byte("trojan://trojanpass@203.0.113.55:443?sni=cdn.example.org#HK-Trojan"))
		_, _ = w.Write([]byte(encoded))
	}))
	defer remoteSrv.Close()

	st.AllowLoopbackRemote = true
	remoteItem, err := st.UpsertSource(t.Context(), SourceUpsertInput{
		Name:        "airport_hk",
		DisplayName: "HK Remote Sub",
		Source:      "remote",
		URL:         remoteSrv.URL + "/api/v1/client/subscribe?token=xyz",
	})
	if err != nil {
		t.Fatalf("UpsertSource remote failed: %v", err)
	}
	if remoteItem.NodeCount != 1 {
		t.Fatalf("expected 1 node from remote sub, got %d", remoteItem.NodeCount)
	}

	// Resolve aggregated "all" collection -> should contain 4 distinct nodes
	bundle, err := st.ResolveCollection(t.Context(), "all")
	if err != nil {
		t.Fatalf("ResolveCollection failed: %v", err)
	}
	if len(bundle.Nodes) != 4 {
		t.Fatalf("expected 4 aggregated nodes, got %d", len(bundle.Nodes))
	}

	// Auto-managed source cannot be deleted, but can be disabled
	if err := st.DeleteSource("auto_generated_hy2"); err == nil {
		t.Fatal("expected error deleting auto-managed source")
	}
	if _, err := st.UpsertSource(t.Context(), SourceUpsertInput{
		Name:    "auto_generated_hy2",
		Enabled: new(false),
	}); err != nil {
		t.Fatalf("disable auto_generated_hy2 failed: %v", err)
	}
	bundleAfterDisable, err := st.ResolveCollection(t.Context(), "all")
	if err != nil {
		t.Fatalf("ResolveCollection after disable failed: %v", err)
	}
	if len(bundleAfterDisable.Nodes) != 3 {
		t.Fatalf("expected 3 nodes after disabling hy2, got %d", len(bundleAfterDisable.Nodes))
	}

	// Delete custom source
	if err := st.DeleteSource("my-backup-nodes"); err != nil {
		t.Fatalf("DeleteSource custom failed: %v", err)
	}

	// Verify extra top-level keys in sub-store.json were preserved intact
	rawAfter, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("read sub-store.json: %v", err)
	}
	var docAfter map[string]any
	if err := json.Unmarshal(rawAfter, &docAfter); err != nil {
		t.Fatalf("unmarshal sub-store.json: %v", err)
	}
	if docAfter["schemaVersion"] != "2.0" {
		t.Fatalf("expected schemaVersion preserved, got %v", docAfter["schemaVersion"])
	}

	// RotateKey
	newKey, err := st.RotateKey()
	if err != nil || len(newKey) != 26 || newKey == key {
		t.Fatalf("RotateKey failed: newKey=%q err=%v", newKey, err)
	}
}

func TestDetectTargetAndRenderAllFormats(t *testing.T) {
	if got := DetectTarget("", "", "SFI/1.14.0 (iPhone; iOS 18.2)"); got != TargetSingBox {
		t.Fatalf("expected SingBox for SFI UA, got %s", got)
	}
	if got := DetectTarget("", "", "Clash.Meta/v1.18.9"); got != TargetClashMeta {
		t.Fatalf("expected ClashMeta for Clash.Meta UA, got %s", got)
	}
	if got := DetectTarget("", "", "Shadowrocket/2090"); got != TargetBase64 {
		t.Fatalf("expected Base64 for Shadowrocket UA, got %s", got)
	}
	if got := DetectTarget("Surge", "", "Mozilla/5.0"); got != TargetSurge {
		t.Fatalf("expected Surge from target query, got %s", got)
	}
	if got := DetectTarget("Loon", "", "Mozilla/5.0"); got != TargetLoon {
		t.Fatalf("expected Loon from target query, got %s", got)
	}
	if got := DetectTarget("", "1", "Clash.Meta/v1.18"); got != TargetPlain {
		t.Fatalf("expected Plain when raw=1, got %s", got)
	}

	dir := t.TempDir()
	filePath := seedLegacySubStoreJSON(t, dir)
	st := NewStore(dir, filePath)
	bundle, err := st.ResolveCollection(t.Context(), "all")
	if err != nil {
		t.Fatalf("ResolveCollection: %v", err)
	}

	// 1. Base64
	resB64, err := RenderBundle(t.Context(), bundle, RenderOptions{Target: TargetBase64})
	if err != nil {
		t.Fatalf("Render Base64: %v", err)
	}
	decoded, err := base64.StdEncoding.DecodeString(string(resB64.Body))
	if err != nil || !strings.Contains(string(decoded), "hysteria2://") || !strings.Contains(string(decoded), "vless://") {
		t.Fatalf("unexpected Base64 output: err=%v decoded=%q", err, string(decoded))
	}

	// 2. ClashMeta YAML
	resClash, err := RenderBundle(t.Context(), bundle, RenderOptions{
		Target:   TargetClashMeta,
		UpMbps:   100,
		DownMbps: 300,
	})
	if err != nil {
		t.Fatalf("Render ClashMeta: %v", err)
	}
	var clashDoc struct {
		Proxies     []map[string]any `yaml:"proxies"`
		ProxyGroups []map[string]any `yaml:"proxy-groups"`
	}
	if err := yaml.Unmarshal(resClash.Body, &clashDoc); err != nil {
		t.Fatalf("invalid ClashMeta YAML: %v\n%s", err, string(resClash.Body))
	}
	if len(clashDoc.Proxies) != 2 || len(clashDoc.ProxyGroups) == 0 {
		t.Fatalf("unexpected ClashMeta structure: proxies=%d groups=%d", len(clashDoc.Proxies), len(clashDoc.ProxyGroups))
	}

	// 3. SingBox JSON (sandbox-safe remote rule_sets for iOS SFI / Android SFA)
	resSB, err := RenderBundle(t.Context(), bundle, RenderOptions{Target: TargetSingBox})
	if err != nil {
		t.Fatalf("Render SingBox: %v", err)
	}
	if err := singbox.CheckIOSCompatibility(string(resSB.Body)); err != nil {
		t.Fatalf("SingBox output failed CheckIOSCompatibility: %v", err)
	}

	// 4. Surge
	resSurge, err := RenderBundle(t.Context(), bundle, RenderOptions{
		Target:     TargetSurge,
		RequestURL: "https://sub.example.com/secret/download/collection/all?target=Surge",
	})
	if err != nil {
		t.Fatalf("Render Surge: %v", err)
	}
	if !strings.HasPrefix(string(resSurge.Body), "#!MANAGED-CONFIG ") || !strings.Contains(string(resSurge.Body), "= hysteria2") {
		t.Fatalf("unexpected Surge output:\n%s", string(resSurge.Body))
	}

	// 5. Loon
	resLoon, err := RenderBundle(t.Context(), bundle, RenderOptions{Target: TargetLoon})
	if err != nil {
		t.Fatalf("Render Loon: %v", err)
	}
	if !strings.Contains(string(resLoon.Body), "= VLESS") || !strings.Contains(string(resLoon.Body), "public-key=") {
		t.Fatalf("unexpected Loon output:\n%s", string(resLoon.Body))
	}
}

func TestServerHTTPHandlersAndSecurity(t *testing.T) {
	dir := t.TempDir()
	filePath := seedLegacySubStoreJSON(t, dir)
	srv := NewServer(Options{
		DataDir:  dir,
		FilePath: filePath,
		Version:  "v1.14.31",
	})
	h := srv.Handler()

	// 1. Direct loopback GET / -> 200 with version meta tag
	reqRoot := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:3001/", nil)
	reqRoot.RemoteAddr = "127.0.0.1:54321"
	recRoot := httptest.NewRecorder()
	h.ServeHTTP(recRoot, reqRoot)
	if recRoot.Code != http.StatusOK || !strings.Contains(recRoot.Body.String(), `content="v1.14.31"`) {
		t.Fatalf("expected loopback / 200 with version meta, got code=%d body=%q", recRoot.Code, recRoot.Body.String())
	}

	// 2. Proxied external GET / -> 404 (no Sub-Store fingerprint exposed)
	reqProxied := httptest.NewRequest(http.MethodGet, "https://sub.example.com/", nil)
	reqProxied.RemoteAddr = "127.0.0.1:54322"
	reqProxied.Header.Set("X-Forwarded-For", "203.0.113.99")
	recProxied := httptest.NewRecorder()
	h.ServeHTTP(recProxied, reqProxied)
	if recProxied.Code != http.StatusNotFound {
		t.Fatalf("expected proxied / to return 404, got %d", recProxied.Code)
	}

	// 3. Invalid secret key -> 404
	reqBadKey := httptest.NewRequest(http.MethodGet, "https://sub.example.com/wrongkey/download/collection/all", nil)
	recBadKey := httptest.NewRecorder()
	h.ServeHTTP(recBadKey, reqBadKey)
	if recBadKey.Code != http.StatusNotFound {
		t.Fatalf("expected wrong key to return 404, got %d", recBadKey.Code)
	}

	// 4. Valid legacy URL with ClashMeta target -> 200 YAML
	reqValid := httptest.NewRequest(http.MethodGet, "https://sub.example.com/a1b2c3d4e5f60718293a4b5c6d/download/collection/all?target=ClashMeta", nil)
	reqValid.Header.Set("User-Agent", "Clash.Meta/v1.18.8")
	reqValid.Header.Set("X-Real-IP", "198.51.100.7")
	reqValid.Header.Set("X-Geo-Country", "JP")
	recValid := httptest.NewRecorder()
	h.ServeHTTP(recValid, reqValid)
	if recValid.Code != http.StatusOK {
		t.Fatalf("expected valid download 200, got %d: %s", recValid.Code, recValid.Body.String())
	}
	if !strings.Contains(recValid.Body.String(), "proxies:") || !strings.Contains(recValid.Body.String(), "reality-opts:") {
		t.Fatalf("expected ClashMeta YAML with reality-opts, got:\n%s", recValid.Body.String())
	}
	if cc := recValid.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Fatalf("expected private no-store Cache-Control, got %q", cc)
	}

	// 5. Subscription access audit log records both valid pulls and denied probes
	logs, err := srv.Store().ListAccessLogs()
	if err != nil || len(logs) != 2 {
		t.Fatalf("expected 2 access audit logs (ok + denied), got %d err=%v", len(logs), err)
	}
	if logs[0].Status != "ok" || logs[0].ClientApp != "Clash.Meta" || logs[0].CountryCode != "JP" || logs[0].IP != "198.51.100.7" {
		t.Fatalf("unexpected latest access log: %+v", logs[0])
	}
	if logs[1].Status != "denied" {
		t.Fatalf("expected second log to be denied probe, got %+v", logs[1])
	}
}

func TestAdaptiveUAWaterfallAndAntiWAF(t *testing.T) {
	var hitCount atomic.Int32
	wafSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitCount.Add(1)
		ua := strings.ToLower(r.Header.Get("User-Agent"))
		switch {
		case strings.Contains(ua, "mozilla/") || strings.Contains(ua, "singctl-subhub"):
			w.WriteHeader(http.StatusTeapot) // 418 Photon-Edge WAF block
			_, _ = w.Write([]byte("<html>blocked bot</html>"))
		case strings.Contains(ua, "v2rayng"):
			w.WriteHeader(http.StatusForbidden) // 403 block
		case strings.Contains(ua, "shadowrocket"):
			// 200 OK HTML WAF JS challenge — must NOT poison cache!
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<!DOCTYPE html><html><body>Checking your browser before accessing...</body></html>"))
		case strings.Contains(ua, "clash.meta"):
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`proxies:
  - name: JP-AnyTLS-01
    type: anytls
    server: jp1.example.com
    port: 443
    password: secret-anytls-pass
    sni: jp1.example.com
    skip-cert-verify: false
  - name: SG-SS2022-01
    type: ss
    server: 198.51.100.41
    port: 8388
    cipher: 2022-blake3-aes-128-gcm
    password: AbCd/Ef+GhIjKlMnOpQrSw==
`))
		default:
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	defer wafSrv.Close()

	dir := t.TempDir()
	st := NewStore(dir, filepath.Join(dir, "sub-store.json"))
	st.AllowLoopbackRemote = true

	item, err := st.UpsertSource(t.Context(), SourceUpsertInput{
		Name:        "cry_test",
		DisplayName: "Cry Anti-Bot Sub",
		Source:      "remote",
		URL:         wafSrv.URL + "/api/v1/subscribe?token=testtoken",
	})
	if err != nil {
		t.Fatalf("UpsertSource adaptive waterfall failed: %v", err)
	}
	if item.NodeCount != 2 {
		t.Fatalf("expected 2 parsed nodes from Clash YAML fallback, got %d", item.NodeCount)
	}
	if item.EffectiveUA != UAClashMeta {
		t.Fatalf("expected winning EffectiveUA=%q, got %q", UAClashMeta, item.EffectiveUA)
	}
	if got := hitCount.Load(); got != 3 {
		t.Fatalf("expected 3 waterfall attempts (v2rayNG->Shadowrocket->ClashMeta), got %d", got)
	}

	// Second explicit refresh should remember EffectiveUA and succeed on the very first request
	hitCount.Store(0)
	refreshed, err := st.RefreshSources(t.Context(), "cry_test")
	if err != nil {
		t.Fatalf("RefreshSources failed: %v", err)
	}
	if got := hitCount.Load(); got != 1 {
		t.Fatalf("expected cached winning UA to succeed in 1 request, got %d", got)
	}
	if len(refreshed) != 1 || refreshed[0].NodeCount != 2 {
		t.Fatalf("unexpected refreshed items: %+v", refreshed)
	}
}

func TestSingBoxJSONParserAndAnyTLSRoundTrip(t *testing.T) {
	sbPayload := `{
  "outbounds": [
    {"type": "selector", "tag": "Proxy", "outbounds": ["HK-AnyTLS", "US-SS2022", "JP-Reality"]},
    {"type": "urltest", "tag": "Auto", "outbounds": ["HK-AnyTLS", "US-SS2022"]},
    {
      "type": "anytls",
      "tag": "HK-AnyTLS",
      "server": "hk1.example.com",
      "server_port": 443,
      "password": "anytls-test-password",
      "idle_session_check_interval": "30s",
      "tls": {
        "enabled": true,
        "server_name": "hk1.example.com",
        "insecure": false,
        "alpn": ["h2", "http/1.1"]
      }
    },
    {
      "type": "shadowsocks",
      "tag": "US-SS2022",
      "server": "203.0.113.77",
      "server_port": 8388,
      "method": "2022-blake3-aes-128-gcm",
      "password": "KeyWith/Slash+AndPlus=="
    },
    {
      "type": "vless",
      "tag": "JP-Reality",
      "server": "198.51.100.99",
      "server_port": 443,
      "uuid": "11111111-2222-3333-4444-555555555555",
      "flow": "xtls-rprx-vision",
      "tls": {
        "enabled": true,
        "server_name": "www.microsoft.com",
        "utls": {"enabled": true, "fingerprint": "chrome"},
        "reality": {
          "enabled": true,
          "public_key": "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfE",
          "short_id": "a1b2c3d4"
        }
      }
    },
    {"type": "direct", "tag": "direct"},
    {"type": "dns", "tag": "dns-out"}
  ]
}`

	nodes, uris := ParseRawSubscriptionPayload(t.Context(), []byte(sbPayload))
	if len(nodes) != 3 || len(uris) != 3 {
		t.Fatalf("expected 3 proxy nodes and 3 synthesized URIs, got nodes=%d uris=%d", len(nodes), len(uris))
	}

	bundle := &ResolvedBundle{
		Name:  "all",
		Nodes: nodes,
		URIs:  uris,
	}

	// Verify SingBox v1.14 rendering preserves anytls and SS-2022 password with '/' intact
	resSB, err := RenderBundle(t.Context(), bundle, RenderOptions{Target: TargetSingBox})
	if err != nil {
		t.Fatalf("RenderBundle SingBox failed: %v", err)
	}
	sbOut := string(resSB.Body)
	if !strings.Contains(sbOut, `"type": "anytls"`) || !strings.Contains(sbOut, `"KeyWith/Slash+AndPlus=="`) {
		t.Fatalf("expected SingBox output to preserve anytls and exact SS-2022 key, got:\n%s", sbOut)
	}

	// Verify Clash.Meta rendering includes anytls
	resClash, err := RenderBundle(t.Context(), bundle, RenderOptions{Target: TargetClashMeta})
	if err != nil {
		t.Fatalf("RenderBundle ClashMeta failed: %v", err)
	}
	if !strings.Contains(string(resClash.Body), "type: anytls") {
		t.Fatalf("expected ClashMeta output to contain anytls proxy, got:\n%s", string(resClash.Body))
	}

	// Verify legacy SS Base64 + URL-safe SIP002 SS + raw UTF-8 Chinese/Emoji fragments normalize cleanly
	legacyCred := base64.StdEncoding.EncodeToString([]byte("2022-blake3-aes-128-gcm:Sec/Key+123==@192.0.2.88:8388"))
	sipURLSafe := base64.RawURLEncoding.EncodeToString([]byte("2022-blake3-aes-256-gcm:Another/Key+With/Slashes=="))
	mixedRaw := strings.Join([]string{
		"ss://" + legacyCred + "#🇯🇵 东京节点 01",
		"ss://" + sipURLSafe + "@192.0.2.89:8389#🇭🇰 香港专线 02",
	}, "\n")
	ssNodes, ssURIs := ParseRawSubscriptionPayload(t.Context(), []byte(mixedRaw))
	if len(ssNodes) != 2 || len(ssURIs) != 2 {
		t.Fatalf("expected 2 normalized SS nodes, got nodes=%d uris=%d", len(ssNodes), len(ssURIs))
	}
	if ssNodes[0].Password != "Sec/Key+123==" || ssNodes[0].Tag != "🇯🇵 东京节点 01" {
		t.Fatalf("unexpected legacy SS node[0]: %+v", ssNodes[0])
	}
	if ssNodes[1].Password != "Another/Key+With/Slashes==" || ssNodes[1].Tag != "🇭🇰 香港专线 02" {
		t.Fatalf("unexpected SIP002 URL-safe SS node[1]: %+v", ssNodes[1])
	}
}

func TestSOCKS5WarpFallbackInAutoMode(t *testing.T) {
	// Target upstream server reachable via our mock WARP SOCKS5 proxy
	upstreamGoodSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		payload := base64.StdEncoding.EncodeToString([]byte("anytls://warp-pass@us1.example.com:443/?sni=us1.example.com&insecure=0#US-AnyTLS"))
		_, _ = w.Write([]byte(payload))
	}))
	defer upstreamGoodSrv.Close()

	// Direct server simulates Cloudflare/WAF blocking datacenter direct IP with 403
	directBlockedSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer directBlockedSrv.Close()

	goodAddr := strings.TrimPrefix(upstreamGoodSrv.URL, "http://")

	// Minimal RFC 1928 SOCKS5 server forwarding all CONNECT streams to upstreamGoodSrv
	socksLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen mock socks5: %v", err)
	}
	defer socksLn.Close()

	go func() {
		for {
			conn, err := socksLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				var greet [3]byte
				if _, err := io.ReadFull(c, greet[:]); err != nil {
					return
				}
				_, _ = c.Write([]byte{0x05, 0x00})

				var hdr [4]byte
				if _, err := io.ReadFull(c, hdr[:]); err != nil {
					return
				}
				switch hdr[3] {
				case 0x01:
					var skip [6]byte
					_, _ = io.ReadFull(c, skip[:])
				case 0x03:
					var dlen [1]byte
					_, _ = io.ReadFull(c, dlen[:])
					skip := make([]byte, int(dlen[0])+2)
					_, _ = io.ReadFull(c, skip)
				case 0x04:
					var skip [18]byte
					_, _ = io.ReadFull(c, skip[:])
				}
				_, _ = c.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 80})

				upConn, err := net.Dial("tcp", goodAddr)
				if err != nil {
					return
				}
				defer upConn.Close()
				go func() { _, _ = io.Copy(upConn, c) }()
				_, _ = io.Copy(c, upConn)
			}(conn)
		}
	}()

	dir := t.TempDir()
	st := NewStore(dir, filepath.Join(dir, "sub-store.json"))
	st.AllowLoopbackRemote = true
	st.WarpProxyAddr = socksLn.Addr().String()

	item, err := st.UpsertSource(t.Context(), SourceUpsertInput{
		Name:        "warp_rescued",
		DisplayName: "WARP Rescued Sub",
		Source:      "remote",
		URL:         directBlockedSrv.URL + "/sub",
		ProxyMode:   "auto",
	})
	if err != nil {
		t.Fatalf("expected auto proxyMode to fall back from direct 403 to WARP SOCKS5, got err: %v", err)
	}
	if item.UsedProxy != "warp" || item.NodeCount != 1 {
		t.Fatalf("expected UsedProxy=warp and NodeCount=1, got %+v", item)
	}
}
