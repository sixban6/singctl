// 文件职责：负责规则集并发下载与镜像竞速、内容格式校验、manifest 持久化及配置原子写回原语。
package singbox

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"singctl/internal/common/fsx"
	log "singctl/internal/logger"
	rssnapshot "singctl/internal/singbox/ruleset_snapshot"
	"strings"
	"sync"
	"time"
)

// ───────────────────────────── 内部实现 ─────────────────────────────

type fetchOutcome struct {
	ok      bool
	cached  bool
	aborted bool
	err     error
}

// ruleSetTask 单个规则集下载任务；entry 仅在需要改写配置的场景使用（刷新场景可为 nil）。
type ruleSetTask struct {
	idx             int
	tag             string
	url             string
	format          string
	entry           map[string]any
	wasMissingLocal bool
}

func (t ruleSetTask) fields() (int, string, string, string) {
	return t.idx, t.tag, t.url, t.format
}

// isCacheFresh 判断本地规则集缓存是否在有效期内且内容合法。
func isCacheFresh(path, format string, manifest ruleSetManifest, tag string, ttl time.Duration) bool {
	if ttl <= 0 || !cachedFileValid(path, format) {
		return false
	}
	meta, hasMeta := manifest[tag]
	if !hasMeta || meta.UpdatedAt == "" {
		return false
	}
	updatedAt, err := time.Parse(time.RFC3339, meta.UpdatedAt)
	if err != nil {
		return false
	}
	if time.Since(updatedAt) < ttl {
		return true
	}
	// 兜底：若上次运行被中断（如 Ctrl+C），文件已落盘但 manifest 尚未覆写，
	// 此时文件修改时间明显晚于 manifest 记录时间且仍在 TTL 内，可视为有效新缓存
	if fi, err := os.Stat(path); err == nil {
		if fi.ModTime().After(updatedAt.Add(time.Minute)) && time.Since(fi.ModTime()) < ttl {
			meta.UpdatedAt = fi.ModTime().UTC().Format(time.RFC3339)
			manifest[tag] = meta
			return true
		}
	}
	return false
}

// fetchRuleSets 并行下载任务，带以下加速与容错机制：
//  1. 命中未过期本地缓存（CacheTTL）时直接复用，不发起网络请求；
//  2. 首选候选（如镜像源）连续失败达到阈值时，立即取消在途镜像请求并切换为直连优先；
//  3. 整体连续失败达到阈值时触发熔断，立即取消所有在途请求并回退本地缓存。
func fetchRuleSets(tasks []ruleSetTask, opts LocalizeOptions, manifest ruleSetManifest) (map[int]fetchOutcome, bool) {
	results := make(map[int]fetchOutcome, len(tasks))

	var pending []ruleSetTask
	for _, t := range tasks {
		idx, tag, _, format := t.fields()
		path := cacheFilePath(opts.CacheDir, tag, format)
		if isCacheFresh(path, format, manifest, tag, opts.CacheTTL) {
			results[idx] = fetchOutcome{ok: true, cached: true}
			continue
		}
		pending = append(pending, t)
	}
	if len(pending) == 0 {
		return results, false
	}

	if !opts.Silent {
		log.Info("正在同步规则集缓存 (需更新 %d/%d 个)...", len(pending), len(tasks))
	}

	abortCtx, cancelAbort := context.WithCancel(context.Background())
	defer cancelAbort()

	primaryCtx, cancelPrimary := context.WithCancel(abortCtx)
	defer cancelPrimary()

	var (
		mu                sync.Mutex
		failStreak        int
		aborted           bool
		primaryFailStreak int
		primaryBroken     bool
		fallbackWorking   bool
		manMu             sync.Mutex
	)

	shouldAbort := func() bool {
		mu.Lock()
		defer mu.Unlock()
		return aborted
	}
	noteResult := func(ok bool) {
		mu.Lock()
		defer mu.Unlock()
		if ok {
			failStreak = 0
			return
		}
		failStreak++
		if failStreak >= breakerThreshold {
			if !aborted {
				aborted = true
				cancelAbort()
				if !opts.Silent {
					log.Warn("⚠️ 网络不可用（GitHub/镜像均无法访问），跳过剩余规则集下载，将回退本地缓存")
				}
			}
		}
	}

	getCandidateState := func() (broken, fbWorking bool) {
		mu.Lock()
		defer mu.Unlock()
		return primaryBroken, fallbackWorking
	}
	notePrimaryResult := func(ok bool) {
		mu.Lock()
		defer mu.Unlock()
		if ok {
			primaryFailStreak = 0
			return
		}
		if aborted {
			return
		}
		primaryFailStreak++
		if !primaryBroken && primaryFailStreak >= primaryFailThreshold {
			primaryBroken = true
			cancelPrimary()
			if !opts.Silent {
				log.Warn("⚠️ 镜像源响应异常，已自动切换为直连优先下载")
			}
		}
	}
	noteFallbackSuccess := func() {
		mu.Lock()
		fallbackWorking = true
		mu.Unlock()
	}

	sem := make(chan struct{}, opts.Workers)
	var wg sync.WaitGroup
	for _, t := range pending {
		wg.Add(1)
		go func(t ruleSetTask) {
			defer wg.Done()
			idx, tag, url, format := t.fields()
			path := cacheFilePath(opts.CacheDir, tag, format)

			if shouldAbort() {
				mu.Lock()
				results[idx] = fetchOutcome{ok: false, aborted: true, err: fmt.Errorf("network aborted")}
				mu.Unlock()
				return
			}
			sem <- struct{}{}
			defer func() { <-sem }()

			// 获取信号量后再次检查熔断状态，防止排队等待期间已触发熔断但协程仍继续发起超时请求
			if shouldAbort() {
				mu.Lock()
				results[idx] = fetchOutcome{ok: false, aborted: true, err: fmt.Errorf("network aborted")}
				mu.Unlock()
				return
			}

			data, err := downloadRuleSet(
				abortCtx,
				primaryCtx,
				url,
				format,
				opts,
				shouldAbort,
				getCandidateState,
				notePrimaryResult,
				noteFallbackSuccess,
			)
			if shouldAbort() && err != nil {
				mu.Lock()
				results[idx] = fetchOutcome{ok: false, aborted: true, err: err}
				mu.Unlock()
				return
			}
			noteResult(err == nil)
			if err != nil {
				mu.Lock()
				results[idx] = fetchOutcome{ok: false, aborted: false, err: err}
				mu.Unlock()
				return
			}
			if err := atomicWriteFile(path, data, 0644); err != nil {
				mu.Lock()
				results[idx] = fetchOutcome{ok: false, err: err}
				mu.Unlock()
				return
			}
			manMu.Lock()
			meta := manifest[tag]
			meta.UpdatedAt = time.Now().Format(time.RFC3339)
			manifest[tag] = meta
			_ = saveManifest(opts.CacheDir, manifest)
			manMu.Unlock()
			mu.Lock()
			results[idx] = fetchOutcome{ok: true}
			mu.Unlock()
		}(t)
	}
	wg.Wait()

	// 汇报熔断状态
	mu.Lock()
	wasAborted := aborted
	mu.Unlock()
	if wasAborted && !opts.Silent {
		log.Warn("⚠️ 规则集下载被熔断跳过，重启将继续使用本地缓存（如存在）")
	}
	return results, wasAborted
}

// downloadRuleSet 依次尝试候选 URL（支持镜像源故障自动降级与在途取消），并校验内容合法性。
func downloadRuleSet(
	abortCtx context.Context,
	primaryCtx context.Context,
	rawURL, format string,
	opts LocalizeOptions,
	shouldAbort func() bool,
	getCandidateState func() (broken, fbWorking bool),
	notePrimaryResult func(ok bool),
	noteFallbackSuccess func(),
) ([]byte, error) {
	client := opts.Client
	cands := fetchCandidates(rawURL, opts.MirrorURL)
	hasFallback := len(cands) > 1

	type candItem struct {
		url       string
		isPrimary bool
	}
	items := make([]candItem, 0, len(cands))
	if hasFallback && getCandidateState != nil {
		broken, fbWorking := getCandidateState()
		if broken {
			// 首选源已判定异常：优先尝试备用（直连）源；若备用源已验证可用则直接跳过异常首选源
			for _, u := range cands[1:] {
				items = append(items, candItem{url: u, isPrimary: false})
			}
			if !fbWorking {
				items = append(items, candItem{url: cands[0], isPrimary: true})
			}
		}
	}
	if len(items) == 0 {
		for i, u := range cands {
			items = append(items, candItem{url: u, isPrimary: hasFallback && i == 0})
		}
	}

	var lastErr error
	for _, item := range items {
		if shouldAbort != nil && shouldAbort() {
			return nil, fmt.Errorf("network aborted")
		}
		reqCtx := abortCtx
		if item.isPrimary && primaryCtx != nil {
			reqCtx = primaryCtx
		}
		if reqCtx == nil {
			reqCtx = context.Background()
		}

		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, item.url, nil)
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("User-Agent", "singctl-rule-set-cache")
		resp, err := client.Do(req)
		if err != nil {
			if shouldAbort != nil && shouldAbort() {
				return nil, fmt.Errorf("network aborted")
			}
			if item.isPrimary && notePrimaryResult != nil {
				notePrimaryResult(false)
			}
			lastErr = fmt.Errorf("%s: %w", redactURL(item.url), err)
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxRuleSetSize+1))
		resp.Body.Close()
		if err != nil {
			if shouldAbort != nil && shouldAbort() {
				return nil, fmt.Errorf("network aborted")
			}
			if item.isPrimary && notePrimaryResult != nil {
				notePrimaryResult(false)
			}
			lastErr = fmt.Errorf("%s: read body: %w", redactURL(item.url), err)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			if item.isPrimary && notePrimaryResult != nil {
				notePrimaryResult(false)
			}
			lastErr = fmt.Errorf("%s: HTTP %d", redactURL(item.url), resp.StatusCode)
			continue
		}
		if err := validateRuleSet(body, format); err != nil {
			if item.isPrimary && notePrimaryResult != nil {
				notePrimaryResult(false)
			}
			lastErr = fmt.Errorf("%s: %w", redactURL(item.url), err)
			continue
		}
		if item.isPrimary && notePrimaryResult != nil {
			notePrimaryResult(true)
		} else if hasFallback && !item.isPrimary && noteFallbackSuccess != nil {
			noteFallbackSuccess()
		}
		return body, nil
	}
	return nil, lastErr
}

// fetchCandidates 生成候选下载地址：原样 → 剥离镜像直连（或叠加镜像）。
func fetchCandidates(rawURL, mirror string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(u string) {
		if u != "" && !seen[u] {
			seen[u] = true
			out = append(out, u)
		}
	}
	add(rawURL)

	trimmed := strings.TrimSuffix(mirror, "/")
	if trimmed != "" && strings.HasPrefix(rawURL, trimmed+"/") {
		// 镜像前缀 URL → 追加直连候选
		add(strings.TrimPrefix(rawURL, trimmed+"/"))
	} else if trimmed != "" && isGitHubURL(rawURL) {
		// 直连 GitHub URL → 追加镜像候选
		add(trimmed + "/" + rawURL)
	}
	return out
}

func isGitHubURL(u string) bool {
	return strings.Contains(u, "github.com") ||
		strings.Contains(u, "githubusercontent.com") ||
		strings.Contains(u, "github.io") ||
		strings.Contains(u, "githubassets.com")
}

// validateRuleSet 校验下载内容确实是规则集，防止把镜像返回的 HTML 错误页缓存下来。
func validateRuleSet(data []byte, format string) error {
	if len(data) == 0 {
		return fmt.Errorf("empty content")
	}
	switch format {
	case "source":
		if !json.Valid(data) {
			return fmt.Errorf("invalid source-format rule set (not JSON)")
		}
	default: // binary (.srs)
		if !bytes.HasPrefix(data, []byte(srsMagic)) && !bytes.HasPrefix(data, []byte(legacySRSMagic)) {
			return fmt.Errorf("invalid binary rule set (missing %q/%q magic)", srsMagic, legacySRSMagic)
		}
	}
	return nil
}

// copyRuleSetEntry 复制规则集条目（值为标量，浅拷贝即可）。
func copyRuleSetEntry(src map[string]any) map[string]any {
	dst := make(map[string]any, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

// localizeEntry 将 remote 条目改写为 local（保留 tag/format，删除 url 等远程字段）。
func localizeEntry(entry map[string]any, path string) {
	for k := range entry {
		if k != "tag" && k != "format" {
			delete(entry, k)
		}
	}
	entry["type"] = "local"
	entry["path"] = path
}

// sanitizeKeptRemoteEntry 清理保留为 remote 的规则集条目：
//   - 若配置已启用 v1.14+ route.default_http_client，直接移除弃用的 download_detour；
//   - 否则剥离指向空 direct / DirectConn 出站的 download_detour，防止 sing-box 1.14+ 报 empty direct 致命错误。
func sanitizeKeptRemoteEntry(entry map[string]any, hasDefaultHTTPClient bool) {
	if hasDefaultHTTPClient {
		delete(entry, "download_detour")
		return
	}
	if detour, _ := entry["download_detour"].(string); strings.EqualFold(detour, "direct") || strings.EqualFold(detour, "DirectConn") || strings.EqualFold(detour, "#DC") {
		delete(entry, "download_detour")
	}
}

func sanitizeRootHTTPClients(cfg map[string]any) bool {
	rawHC, ok := cfg["http_clients"].([]any)
	if !ok || len(rawHC) == 0 {
		return false
	}
	changed := false
	for _, item := range rawHC {
		hc, ok := item.(map[string]any)
		if !ok || hc == nil {
			continue
		}
		if detour, _ := hc["detour"].(string); isEmptyDirectRawOutboundTag(cfg["outbounds"], strings.TrimSpace(detour)) {
			delete(hc, "detour")
			changed = true
		}
	}
	return changed
}

func isEmptyDirectRawOutboundTag(rawOutbounds any, targetTag string) bool {
	if targetTag == "" {
		return true
	}
	arr, ok := rawOutbounds.([]any)
	if !ok {
		return false
	}
	for _, item := range arr {
		ob, ok := item.(map[string]any)
		if !ok {
			continue
		}
		tag, _ := ob["tag"].(string)
		if strings.TrimSpace(tag) != targetTag {
			continue
		}
		typ, _ := ob["type"].(string)
		if !strings.EqualFold(strings.TrimSpace(typ), "direct") {
			return false
		}
		for k := range ob {
			if k != "type" && k != "tag" {
				return false
			}
		}
		return true
	}
	return false
}

// revertMissingLocalToRemote 当 type=local 的规则集磁盘文件缺失且重下失败时，
// 将其回退为合法的 type=remote 条目（不含空 direct detour），防止 sing-box 启动因找不到本地文件而崩溃。
func revertMissingLocalToRemote(entry map[string]any, url, format string) {
	delete(entry, "path")
	delete(entry, "download_detour")
	entry["type"] = "remote"
	entry["url"] = url
	if format != "" {
		entry["format"] = format
	}
}

// RecordRuleSetManifest 供外部模块（如审计黑名单导入规则集）登记规则集 URL 到 manifest.json，
// 以便后续本地 .srs 文件缺失或执行 cache update 时能够自动重下恢复。
func RecordRuleSetManifest(cacheDir, tag, url, format string) {
	if tag == "" || url == "" {
		return
	}
	if cacheDir == "" {
		cacheDir = RuleSetCacheDir()
	}
	if format == "" {
		format = "binary"
	}
	_ = os.MkdirAll(cacheDir, 0755)
	manifest := loadManifest(cacheDir)
	meta := manifest[tag]
	meta.URL = url
	meta.Format = format
	meta.UpdatedAt = time.Now().Format(time.RFC3339)
	if meta.Original == nil {
		meta.Original = map[string]any{
			"tag":    tag,
			"type":   "remote",
			"format": format,
			"url":    url,
		}
	}
	manifest[tag] = meta
	_ = saveManifest(cacheDir, manifest)
}

// replaceMapEntry 用原始条目内容完整覆盖现有 map（原地替换，保持引用）。
func replaceMapEntry(dst, src map[string]any) {
	for k := range dst {
		delete(dst, k)
	}
	for k, v := range src {
		dst[k] = v
	}
}

// cacheFilePath 依据 tag 与 format 生成缓存文件路径。
func cacheFilePath(cacheDir, tag, format string) string {
	ext := ".srs"
	if format == "source" {
		ext = ".json"
	}
	safe := sanitizeTag(tag)
	return filepath.Join(cacheDir, safe+ext)
}

// sanitizeTag 规则集 tag → 安全文件名。
func sanitizeTag(tag string) string {
	var b strings.Builder
	for _, r := range tag {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	if b.Len() == 0 {
		return "ruleset"
	}
	return b.String()
}

// cachedFileValid 本地缓存文件是否存在且内容合法。
func tryRestoreRuleSetFromSnapshot(snap *rssnapshot.Snapshot, tag, url, format, destPath string) bool {
	if snap == nil {
		return false
	}
	snapTag, _, snapFormat, ok := snap.Lookup(tag, url)
	if !ok || snapFormat != format {
		return false
	}
	if err := snap.ExtractToFile(snapTag, destPath, 0644); err != nil {
		return false
	}
	if !cachedFileValid(destPath, snapFormat) {
		_ = os.Remove(destPath)
		return false
	}
	return true
}

func cachedFileValid(path, format string) bool {
	fi, err := os.Stat(path)
	if err != nil || fi.Size() == 0 {
		return false
	}
	// binary 格式做魔数复核，source 格式已由下载时校验过，存在即可用
	if format != "source" {
		f, err := os.Open(path)
		if err != nil {
			return false
		}
		defer f.Close()
		magicLen := len(legacySRSMagic) // 取两种魔数的最大长度（RULE=4 > SRS=3）
		magic := make([]byte, magicLen)
		if _, err := io.ReadFull(f, magic); err != nil {
			return false
		}
		return bytes.HasPrefix(magic, []byte(srsMagic)) || bytes.HasPrefix(magic, []byte(legacySRSMagic))
	}
	return true
}

// ───────────────────────── manifest 与文件工具 ─────────────────────────

func manifestPath(cacheDir string) string {
	return filepath.Join(cacheDir, manifestFileName)
}

func loadManifest(cacheDir string) ruleSetManifest {
	m := ruleSetManifest{}
	data, err := os.ReadFile(manifestPath(cacheDir))
	if err != nil {
		return m
	}
	_ = json.Unmarshal(data, &m)
	return m
}

func saveManifest(cacheDir string, m ruleSetManifest) error {
	if len(m) == 0 {
		return nil
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(manifestPath(cacheDir), data, 0644)
}

func atomicWriteFile(path string, data []byte, mode os.FileMode) error {
	return fsx.WriteAtomic(path, data, mode)
}

func configFileMode(path string) os.FileMode {
	if fi, err := os.Stat(path); err == nil && fi.Mode().IsRegular() {
		return fi.Mode().Perm()
	}
	return 0600
}

// mutateConfigFile 通用"读 → 变换 → 原子写回"流程。
func mutateConfigFile(configPath string, opts LocalizeOptions,
	transform func(string, LocalizeOptions) (string, RuleSetStats, error)) (bool, RuleSetStats, error) {

	data, err := os.ReadFile(configPath)
	if err != nil {
		return false, RuleSetStats{}, fmt.Errorf("read config file: %w", err)
	}
	out, stats, err := transform(string(data), opts)
	if err != nil {
		return false, stats, err
	}
	if out == string(data) || !stats.HasLocalChange() {
		return false, stats, nil
	}
	if err := atomicWriteFile(configPath, []byte(out), configFileMode(configPath)); err != nil {
		return false, stats, fmt.Errorf("write config file: %w", err)
	}
	return true, stats, nil
}

// redactURL 日志中隐藏镜像前缀后的完整 URL，避免过长。
func redactURL(u string) string {
	if i := strings.Index(u, "://"); i >= 0 {
		rest := u[i+3:]
		if j := strings.Index(rest, "/"); j >= 0 {
			return u[:i+3+j] + "/…"
		}
	}
	return u
}
