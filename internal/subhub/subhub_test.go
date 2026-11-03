package subhub

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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
