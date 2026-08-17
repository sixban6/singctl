package test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"singctl/internal/singbox"
	ruleset_snapshot "singctl/internal/singbox/ruleset_snapshot"
)

// ───────────────────────── 测试工具 ─────────────────────────

// validSRS 构造带合法魔数的 .srs 内容
func validSRS(payload string) []byte {
	return append([]byte("RULE"), []byte(payload)...)
}

// serveRuleSet 启动一个固定返回指定内容/状态的测试服务器
func serveRuleSet(t *testing.T, status int, body []byte) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// countingServer 启动记录请求路径的测试服务器
func countingServer(t *testing.T, hits *sync.Map) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := hits.LoadOrStore(r.URL.Path, 0)
		hits.Store(r.URL.Path, n.(int)+1)
		_, _ = w.Write(validSRS("content:" + r.URL.Path))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// buildConfig 构造包含若干 rule_set 条目的配置 JSON
func buildConfig(t *testing.T, entries ...map[string]any) string {
	t.Helper()
	arr := make([]any, 0, len(entries))
	for _, e := range entries {
		arr = append(arr, e)
	}
	cfg := map[string]any{
		"route": map[string]any{
			"rule_set": arr,
		},
	}
	out, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	return string(out)
}

func parseRuleSets(t *testing.T, cfgJSON string) []map[string]any {
	t.Helper()
	var cfg map[string]any
	if err := json.Unmarshal([]byte(cfgJSON), &cfg); err != nil {
		t.Fatalf("unmarshal config: %v", err)
	}
	route := cfg["route"].(map[string]any)
	raw := route["rule_set"].([]any)
	out := make([]map[string]any, 0, len(raw))
	for _, r := range raw {
		out = append(out, r.(map[string]any))
	}
	return out
}

func testOpts(t *testing.T, cacheDir string) singbox.LocalizeOptions {
	t.Helper()
	return singbox.LocalizeOptions{
		CacheDir: cacheDir,
		Client:   &http.Client{Timeout: 5 * time.Second},
		Workers:  2,
	}
}

func remoteEntry(tag, url string) map[string]any {
	return map[string]any{
		"tag":             tag,
		"type":            "remote",
		"format":          "binary",
		"url":             url,
		"download_detour": "direct", // 远程专属字段，本地化后应被删除
	}
}

// ───────────────────────── LocalizeRuleSets ─────────────────────────

func TestLocalizeRuleSets_DownloadSuccess(t *testing.T) {
	srv := serveRuleSet(t, http.StatusOK, validSRS("rules-v1"))
	cacheDir := t.TempDir()

	in := buildConfig(t,
		remoteEntry("geoip-cn", srv.URL+"/geoip-cn.srs"),
		remoteEntry("geosite-cn", srv.URL+"/geosite-cn.srs"),
	)

	out, stats, err := singbox.LocalizeRuleSets(in, testOpts(t, cacheDir))
	if err != nil {
		t.Fatalf("LocalizeRuleSets: %v", err)
	}
	if stats.Remote != 2 || stats.Localized != 2 {
		t.Fatalf("stats = %+v, want Remote=2 Localized=2", stats)
	}

	entries := parseRuleSets(t, out)
	for _, e := range entries {
		if e["type"] != "local" {
			t.Errorf("entry %v: type = %v, want local", e["tag"], e["type"])
		}
		path, _ := e["path"].(string)
		if path == "" {
			t.Errorf("entry %v: missing path", e["tag"])
			continue
		}
		if !strings.HasPrefix(path, cacheDir) {
			t.Errorf("entry %v: path %q not under cache dir", e["tag"], path)
		}
		if _, err := os.Stat(path); err != nil {
			t.Errorf("cache file %s missing: %v", path, err)
		}
		// 远程专属字段应被清除
		if _, has := e["url"]; has {
			t.Errorf("entry %v: url should be removed", e["tag"])
		}
		if _, has := e["download_detour"]; has {
			t.Errorf("entry %v: download_detour should be removed", e["tag"])
		}
	}

	// manifest 应记录原始 URL 与原始条目
	data, err := os.ReadFile(filepath.Join(cacheDir, "manifest.json"))
	if err != nil {
		t.Fatalf("manifest missing: %v", err)
	}
	var manifest map[string]struct {
		URL      string         `json:"url"`
		Original map[string]any `json:"original"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("manifest unmarshal: %v", err)
	}
	if len(manifest) != 2 {
		t.Fatalf("manifest entries = %d, want 2", len(manifest))
	}
	for _, tag := range []string{"geoip-cn", "geosite-cn"} {
		m, ok := manifest[tag]
		if !ok || m.URL != srv.URL+"/"+tag+".srs" {
			t.Fatalf("manifest[%s] = %+v", tag, m)
		}
		// Original 必须是改写前的 remote 条目（深拷贝，未被 localizeEntry 污染）
		if m.Original["type"] != "remote" || m.Original["url"] != srv.URL+"/"+tag+".srs" {
			t.Errorf("manifest[%s].Original = %v, want remote entry", tag, m.Original)
		}
	}
}

func TestLocalizeRuleSets_FallbackToExistingCache(t *testing.T) {
	srv := serveRuleSet(t, http.StatusInternalServerError, nil)
	cacheDir := t.TempDir()

	// 预置一份旧的有效缓存
	old := filepath.Join(cacheDir, "geoip-cn.srs")
	if err := os.WriteFile(old, validSRS("old-rules"), 0644); err != nil {
		t.Fatal(err)
	}

	in := buildConfig(t, remoteEntry("geoip-cn", srv.URL+"/geoip-cn.srs"))
	out, stats, err := singbox.LocalizeRuleSets(in, testOpts(t, cacheDir))
	if err != nil {
		t.Fatalf("LocalizeRuleSets: %v", err)
	}
	if stats.Fallback != 1 {
		t.Fatalf("stats = %+v, want Fallback=1", stats)
	}

	entries := parseRuleSets(t, out)
	if entries[0]["type"] != "local" {
		t.Errorf("entry should be local after fallback, got %v", entries[0])
	}
	// 内容应保持旧缓存不被破坏
	got, _ := os.ReadFile(entries[0]["path"].(string))
	if string(got) != "RULEold-rules" {
		t.Errorf("cache content changed: %q", got)
	}
}

func TestLocalizeRuleSets_KeepRemoteWhenNoCache(t *testing.T) {
	srv := serveRuleSet(t, http.StatusNotFound, nil)

	// tag 不在内置快照中，才会走“保留远程引用”路径
	in := buildConfig(t, remoteEntry("my-custom-rs", srv.URL+"/custom.srs"))
	out, stats, err := singbox.LocalizeRuleSets(in, testOpts(t, t.TempDir()))
	if err != nil {
		t.Fatalf("LocalizeRuleSets: %v", err)
	}
	if stats.Kept != 1 {
		t.Fatalf("stats = %+v, want Kept=1", stats)
	}
	entries := parseRuleSets(t, out)
	if entries[0]["type"] != "remote" || entries[0]["url"] != srv.URL+"/custom.srs" {
		t.Errorf("entry should stay remote, got %v", entries[0])
	}
}

func TestLocalizeRuleSets_MirrorFallback(t *testing.T) {
	// 直连服务器返回 404，镜像服务器提供内容
	bad := serveRuleSet(t, http.StatusNotFound, nil)
	good := serveRuleSet(t, http.StatusOK, validSRS("via-mirror"))
	cacheDir := t.TempDir()

	// URL 路径中包含 github.com 以触发镜像候选生成
	githubURL := bad.URL + "/https://github.com/SagerNet/sing-geoip/rule/geoip.srs"

	opts := singbox.LocalizeOptions{
		MirrorURL: good.URL,
		CacheDir:  cacheDir,
		Client:    &http.Client{Timeout: 5 * time.Second},
		Workers:   2,
	}
	out, stats, err := singbox.LocalizeRuleSets(buildConfig(t, remoteEntry("geoip", githubURL)), opts)
	if err != nil {
		t.Fatalf("LocalizeRuleSets: %v", err)
	}
	if stats.Localized != 1 {
		t.Fatalf("stats = %+v, want Localized=1 (via mirror)", stats)
	}
	entries := parseRuleSets(t, out)
	got, _ := os.ReadFile(entries[0]["path"].(string))
	if string(got) != "RULEvia-mirror" {
		t.Errorf("mirror content not used: %q", got)
	}
}

func TestLocalizeRuleSets_SourceFormat(t *testing.T) {
	sourceJSON := []byte(`{"version":1,"rules":[{"domain":["example.com"]}]}`)
	srv := serveRuleSet(t, http.StatusOK, sourceJSON)

	entry := remoteEntry("src-rules", srv.URL+"/rules.json")
	entry["format"] = "source"

	out, stats, err := singbox.LocalizeRuleSets(buildConfig(t, entry), testOpts(t, t.TempDir()))
	if err != nil {
		t.Fatalf("LocalizeRuleSets: %v", err)
	}
	if stats.Localized != 1 {
		t.Fatalf("stats = %+v, want Localized=1", stats)
	}
	entries := parseRuleSets(t, out)
	path := entries[0]["path"].(string)
	if filepath.Ext(path) != ".json" {
		t.Errorf("source format should use .json ext, got %s", path)
	}

	// 服务器返回 HTML 错误页时必须拒绝缓存（内容校验）
	htmlSrv := serveRuleSet(t, http.StatusOK, []byte("<html>404 not found</html>"))
	entry2 := remoteEntry("src-bad", htmlSrv.URL+"/rules.json")
	entry2["format"] = "source"
	out2, stats2, err := singbox.LocalizeRuleSets(buildConfig(t, entry2), testOpts(t, t.TempDir()))
	if err != nil {
		t.Fatalf("LocalizeRuleSets: %v", err)
	}
	if stats2.Localized != 0 || stats2.Kept != 1 {
		t.Fatalf("HTML content must not be cached, stats = %+v", stats2)
	}
	if e := parseRuleSets(t, out2)[0]; e["type"] != "remote" {
		t.Errorf("entry should remain remote, got %v", e)
	}
}

func TestLocalizeRuleSets_InvalidJSON(t *testing.T) {
	out, _, err := singbox.LocalizeRuleSets("{not json", testOpts(t, t.TempDir()))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
	if out != "{not json" {
		t.Errorf("input should be returned unchanged, got %s", out)
	}
}

func TestLocalizeRuleSets_NoRuleSet(t *testing.T) {
	in := `{"log":{"level":"info"}}`
	out, stats, err := singbox.LocalizeRuleSets(in, testOpts(t, t.TempDir()))
	if err != nil || stats.Remote != 0 {
		t.Fatalf("err=%v stats=%+v", err, stats)
	}
	if out != in {
		t.Errorf("config without route should be unchanged, got %s", out)
	}
}

// ───────────────────────── 熔断 ─────────────────────────

func TestLocalizeRuleSets_NetworkBreaker(t *testing.T) {
	srv := serveRuleSet(t, http.StatusServiceUnavailable, nil)

	entries := make([]map[string]any, 0, 12)
	for i := 0; i < 12; i++ {
		entries = append(entries, remoteEntry(fmt.Sprintf("rs-%02d", i), fmt.Sprintf("%s/rs%02d.srs", srv.URL, i)))
	}
	opts := testOpts(t, t.TempDir())
	opts.Workers = 2

	_, stats, err := singbox.LocalizeRuleSets(buildConfig(t, entries...), opts)
	if err != nil {
		t.Fatalf("LocalizeRuleSets: %v", err)
	}
	if !stats.Aborted {
		t.Fatalf("expected breaker to abort, stats = %+v", stats)
	}
	if stats.Localized != 0 {
		t.Errorf("no download should succeed, stats = %+v", stats)
	}
	// 全部失败且无缓存 → 全部保留 remote
	if stats.Kept != 12 {
		t.Errorf("stats = %+v, want Kept=12", stats)
	}
}

// ───────────────────────── 配置文件级操作 ─────────────────────────

func writeConfigFile(t *testing.T, cfgJSON string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(cfgJSON), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLocalizeConfigFile(t *testing.T) {
	srv := serveRuleSet(t, http.StatusOK, validSRS("v1"))
	path := writeConfigFile(t, buildConfig(t, remoteEntry("geoip", srv.URL+"/geoip.srs")))

	changed, stats, err := singbox.LocalizeConfigFile(path, testOpts(t, t.TempDir()))
	if err != nil {
		t.Fatalf("LocalizeConfigFile: %v", err)
	}
	if !changed || stats.Localized != 1 {
		t.Fatalf("changed=%v stats=%+v", changed, stats)
	}

	// 第二次执行：全部已是 local，无需改写
	changed2, stats2, err := singbox.LocalizeConfigFile(path, testOpts(t, t.TempDir()))
	if err != nil {
		t.Fatalf("LocalizeConfigFile: %v", err)
	}
	if changed2 {
		t.Errorf("second run should not rewrite config")
	}
	if stats2.Remote != 0 {
		t.Errorf("stats2 = %+v, want Remote=0", stats2)
	}

	// 文件权限保持
	fi, _ := os.Stat(path)
	if fi.Mode().Perm() != 0600 {
		t.Errorf("config perm changed: %v", fi.Mode().Perm())
	}
}

func TestRefreshConfigCache_NoDoubleDownload(t *testing.T) {
	var hits sync.Map
	srv := countingServer(t, &hits)
	cacheDir := t.TempDir()

	// 第一步：全部本地化（2 次下载）
	path := writeConfigFile(t, buildConfig(t,
		remoteEntry("rs-a", srv.URL+"/a.srs"),
		remoteEntry("rs-b", srv.URL+"/b.srs"),
	))
	if _, _, err := singbox.LocalizeConfigFile(path, testOpts(t, cacheDir)); err != nil {
		t.Fatalf("first localize: %v", err)
	}

	// 第二步：构造 mixed 配置 —— rs-a 保持 local（引用第一步缓存），rs-b 还原为 remote
	entries := parseRuleSets(t, mustRead(t, path))
	localA := entries[0] // 已是 local
	remoteB := remoteEntry("rs-b", srv.URL+"/b.srs")
	mixedPath := writeConfigFile(t, buildConfig(t, localA, remoteB))

	changed, stats, err := singbox.RefreshConfigCache(mixedPath, testOpts(t, cacheDir))
	if err != nil {
		t.Fatalf("RefreshConfigCache: %v", err)
	}
	// rs-b 新本地化 + rs-a 刷新已有
	if stats.Localized != 1 || stats.Refreshed != 1 {
		t.Fatalf("stats = %+v, want Localized=1 Refreshed=1", stats)
	}
	if !changed {
		t.Errorf("mixed config should be rewritten (rs-b localized)")
	}

	// 每个规则集在刷新阶段只应被下载一次：a=2 次（首+刷）、b=2 次（首+新本地化）
	for _, p := range []string{"/a.srs", "/b.srs"} {
		n, _ := hits.Load(p)
		if n.(int) != 2 {
			t.Errorf("%s downloaded %d times, want 2 (no double download)", p, n.(int))
		}
	}
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestRevertAndClearCache(t *testing.T) {
	srv := serveRuleSet(t, http.StatusOK, validSRS("v1"))
	cacheDir := t.TempDir()

	path := writeConfigFile(t, buildConfig(t, remoteEntry("geoip", srv.URL+"/geoip.srs")))
	if _, _, err := singbox.LocalizeConfigFile(path, testOpts(t, cacheDir)); err != nil {
		t.Fatalf("localize: %v", err)
	}

	reverted, err := singbox.RevertAndClearCache(path, singbox.LocalizeOptions{CacheDir: cacheDir})
	if err != nil {
		t.Fatalf("RevertAndClearCache: %v", err)
	}
	if reverted != 1 {
		t.Fatalf("reverted = %d, want 1", reverted)
	}

	// 配置应还原为 remote 原始条目（含 url 等字段）
	entries := parseRuleSets(t, mustRead(t, path))
	if entries[0]["type"] != "remote" || entries[0]["url"] != srv.URL+"/geoip.srs" {
		t.Errorf("entry not reverted: %v", entries[0])
	}
	if _, has := entries[0]["path"]; has {
		t.Errorf("local path field should be removed after revert: %v", entries[0])
	}

	// 缓存目录应被清空
	if _, err := os.Stat(cacheDir); !os.IsNotExist(err) {
		t.Errorf("cache dir should be removed, err=%v", err)
	}
}

// ───────────────────────── CacheStatus ─────────────────────────

// ───────────────── 内置快照兑底 ─────────────────

func TestSnapshotFallbackByTag(t *testing.T) {
	// 服务器不可用（返回 503），tag 命中内置快照 → 从快照兑底
	srv := serveRuleSet(t, http.StatusServiceUnavailable, nil)
	cacheDir := t.TempDir()

	in := buildConfig(t, remoteEntry("geoip-cn", srv.URL+"/geoip-cn.srs"))
	out, stats, err := singbox.LocalizeRuleSets(in, testOpts(t, cacheDir))
	if err != nil {
		t.Fatalf("LocalizeRuleSets: %v", err)
	}
	if stats.Snapshot != 1 || stats.Kept != 0 {
		t.Fatalf("stats = %+v, want Snapshot=1 Kept=0", stats)
	}
	entries := parseRuleSets(t, out)
	e := entries[0]
	if e["type"] != "local" {
		t.Fatalf("entry should be localized from snapshot, got %v", e)
	}
	// 缓存文件应存在且内容合法（sha256 已在解压时校验）
	data, err := os.ReadFile(e["path"].(string))
	if err != nil {
		t.Fatalf("read snapshot-backed cache: %v", err)
	}
	if !bytes.HasPrefix(data, []byte("SRS")) && !bytes.HasPrefix(data, []byte("RULE")) {
		t.Fatalf("snapshot content invalid: %q", data[:8])
	}
	// 后续再次运行：下载仍失败，但本地已有快照建立的缓存 → Fallback
	_, stats2, err := singbox.LocalizeRuleSets(in, testOpts(t, cacheDir))
	if err != nil {
		t.Fatalf("second run: %v", err)
	}
	if stats2.Fallback != 1 {
		t.Fatalf("stats2 = %+v, want Fallback=1", stats2)
	}
}

func TestSnapshotFallbackByURL(t *testing.T) {
	// tag 不匹配，但 URL（含镜像前缀）与快照规范 URL 等价 → 兑底
	// 用已关闭的本地服务器作镜像前缀，避免测试依赖真实网络
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	dead.Close()
	url := dead.URL + "/https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geoip/private.srs"

	in := buildConfig(t, remoteEntry("my-renamed-private", url))
	out, stats, err := singbox.LocalizeRuleSets(in, testOpts(t, t.TempDir()))
	if err != nil {
		t.Fatalf("LocalizeRuleSets: %v", err)
	}
	if stats.Snapshot != 1 {
		t.Fatalf("stats = %+v, want Snapshot=1 (matched by URL)", stats)
	}
	entries := parseRuleSets(t, out)
	if entries[0]["type"] != "local" {
		t.Errorf("entry should be localized from snapshot, got %v", entries[0])
	}
}

func TestSnapshotIntegrity(t *testing.T) {
	snap := ruleset_snapshot.Load()
	if snap.Count() == 0 {
		t.Fatal("embedded snapshot is empty")
	}
	if snap.GeneratedAt() == "" {
		t.Fatal("snapshot manifest missing generated_at")
	}
	// 逐条解压校验（sha256/size 由 Extract 内部校验）
	for _, tag := range snap.Tags() {
		data, err := snap.Extract(tag)
		if err != nil {
			t.Errorf("extract %s: %v", tag, err)
			continue
		}
		if !bytes.HasPrefix(data, []byte("SRS")) && !bytes.HasPrefix(data, []byte("RULE")) {
			t.Errorf("extract %s: invalid magic %q", tag, data[:4])
		}
	}
	// 不存在的 tag
	if _, err := snap.Extract("no-such-tag"); err == nil {
		t.Error("expected error for unknown tag")
	}
}

func TestCacheStatus(t *testing.T) {
	srv := serveRuleSet(t, http.StatusOK, validSRS("v1"))
	cacheDir := t.TempDir()

	if _, _, err := singbox.LocalizeRuleSets(
		buildConfig(t, remoteEntry("geoip", srv.URL+"/geoip.srs")),
		testOpts(t, cacheDir)); err != nil {
		t.Fatalf("localize: %v", err)
	}

	entries := singbox.CacheStatus(singbox.LocalizeOptions{CacheDir: cacheDir})
	// manifest 中的 geoip + 内置快照的全部条目
	snap := ruleset_snapshot.Load()
	if len(entries) != 1+snap.Count() {
		t.Fatalf("entries = %d, want %d (1 manifest + %d snapshot-only)", len(entries), 1+snap.Count(), snap.Count())
	}
	var geoip *singbox.RuleSetCacheEntry
	for i := range entries {
		if entries[i].Tag == "geoip" {
			geoip = &entries[i]
		}
	}
	if geoip == nil || !geoip.FileOK || geoip.URL != srv.URL+"/geoip.srs" {
		t.Fatalf("geoip entry = %+v", geoip)
	}
	// 快照条目应标记 InSnapshot
	snapOnly := 0
	for _, e := range entries {
		if e.InSnapshot {
			snapOnly++
		}
	}
	if snapOnly != snap.Count() {
		t.Errorf("InSnapshot entries = %d, want %d", snapOnly, snap.Count())
	}
}
