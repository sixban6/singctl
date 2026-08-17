package singbox

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"singctl/internal/constant"
	log "singctl/internal/logger"
)

// ─────────────────────────────────────────────────────────────────────────────
// 规则集本地缓存 (Rule-Set Local Cache)
//
// 生成的 sing-box 配置中 route.rule_set 绝大多数为 type: remote，URL 指向
// GitHub (raw.githubusercontent.com 等)。sing-box 启动阶段必须完成远程规则集
// 下载，一旦 GitHub 不可用，服务将无法启动。
//
// 本方案：
//  1. 配置生成/迁移时，将所有 remote 规则集提前下载到本地缓存目录；
//  2. 下载成功后把条目改写为 type: local + 本地绝对路径，
//     sing-box 启动完全不依赖网络；
//  3. 下载失败时自动回退到本地已有缓存（规则集变动低频，旧版本可接受）；
//  4. 失败且无缓存时保持 remote 原样，行为与之前一致；
//  5. manifest.json 记录 tag → 原始 remote 条目，支持手动刷新与还原；
//  6. 网络整体不可用时快速熔断，避免拖慢 start/restart。
// ─────────────────────────────────────────────────────────────────────────────

const (
	defaultFetchTimeout = 20 * time.Second
	defaultWorkers      = 6
	maxRuleSetSize      = 64 << 20 // 64MB 防御性上限
	srsMagic            = "RULE"   // sing-box .srs 二进制格式魔数
	manifestFileName    = "manifest.json"
	// 连续失败达到该阈值且无任何成功时熔断（判定 GitHub 与镜像均不可用）
	breakerThreshold = 4
)

// LocalizeOptions 本地化选项
type LocalizeOptions struct {
	MirrorURL string       // GitHub 镜像前缀，如 https://gh-proxy.com
	CacheDir  string       // 缓存目录
	Client    *http.Client // HTTP 客户端（测试可注入）
	Workers   int          // 并发下载数
}

func (o LocalizeOptions) withDefaults() LocalizeOptions {
	if o.CacheDir == "" {
		o.CacheDir = RuleSetCacheDir()
	}
	if o.Client == nil {
		o.Client = &http.Client{Timeout: defaultFetchTimeout}
	}
	if o.Workers <= 0 {
		o.Workers = defaultWorkers
	}
	return o
}

// RuleSetStats 本地化结果统计
type RuleSetStats struct {
	Remote    int  // 配置中发现的 remote 规则集数量
	Localized int  // 新下载成功并改写为本地引用
	Fallback  int  // 下载失败但成功回退本地旧缓存
	Kept      int  // 下载失败且无缓存，保持 remote 原样
	Refreshed int  // cache update 时刷新的已本地化条目
	Aborted   bool // 网络熔断，剩余下载被跳过
}

func (s RuleSetStats) HasLocalChange() bool {
	return s.Localized > 0 || s.Fallback > 0
}

// ruleSetManifest 缓存清单：tag → 原始条目信息，用于刷新与还原
type ruleSetManifest map[string]ruleSetMeta

type ruleSetMeta struct {
	URL       string         `json:"url"`
	Format    string         `json:"format,omitempty"`
	UpdatedAt string         `json:"updated_at,omitempty"`
	Original  map[string]any `json:"original,omitempty"` // 原始 remote 条目，用于还原
}

// RuleSetCacheDir 规则集缓存目录（位于 sing-box 配置目录下）
func RuleSetCacheDir() string {
	return filepath.Join(constant.SingBoxConfigDir, "rule_sets")
}

// ───────────────────────────── 对外接口 ─────────────────────────────

// LocalizeRuleSets 将 JSON 配置中 route.rule_set 的 remote 规则集缓存到本地
// 并改写为 type: local。网络失败时回退本地缓存；无缓存则保持原样。
// 仅在输入 JSON 非法时返回 error（此时调用方应继续使用原始配置）。
func LocalizeRuleSets(jsonStr string, opts LocalizeOptions) (string, RuleSetStats, error) {
	opts = opts.withDefaults()
	stats := RuleSetStats{}

	var cfg map[string]any
	if err := json.Unmarshal([]byte(jsonStr), &cfg); err != nil {
		return jsonStr, stats, fmt.Errorf("ruleset localize: invalid JSON: %w", err)
	}

	route, _ := cfg["route"].(map[string]any)
	if route == nil {
		return jsonStr, stats, nil
	}
	arr, _ := route["rule_set"].([]any)

	// 1. 收集 remote 任务
	var tasks []ruleSetTask
	for i, raw := range arr {
		entry, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		typ, _ := entry["type"].(string)
		url, _ := entry["url"].(string)
		tag, _ := entry["tag"].(string)
		if typ != "remote" || url == "" || tag == "" {
			continue
		}
		format, _ := entry["format"].(string)
		if format == "" {
			format = "binary"
		}
		stats.Remote++
		tasks = append(tasks, ruleSetTask{idx: i, tag: tag, url: url, format: format, entry: entry})
	}
	if len(tasks) == 0 {
		return jsonStr, stats, nil
	}

	if err := os.MkdirAll(opts.CacheDir, 0755); err != nil {
		return jsonStr, stats, fmt.Errorf("ruleset localize: create cache dir failed: %w", err)
	}

	manifest := loadManifest(opts.CacheDir)

	// 2. 并行下载
	results, aborted := fetchRuleSets(tasks, opts, manifest)
	stats.Aborted = aborted

	// 3. 依据结果改写条目
	for _, t := range tasks {
		path := cacheFilePath(opts.CacheDir, t.tag, t.format)
		// 无论成败都记录 manifest，供 sb cache update/clear 使用
		meta := manifest[t.tag]
		meta.URL = t.url
		meta.Format = t.format
		if meta.Original == nil {
			// 必须深拷贝：t.entry 后续会被 localizeEntry 原地改写，
			// 直接存引用会把改写后的 local 条目写入 manifest，导致无法还原
			meta.Original = copyRuleSetEntry(t.entry)
		}
		manifest[t.tag] = meta

		if results[t.idx].ok {
			stats.Localized++
			localizeEntry(t.entry, path)
			continue
		}
		// 下载失败 → 回退本地缓存
		if cachedFileValid(path, t.format) {
			stats.Fallback++
			localizeEntry(t.entry, path)
			log.Warn("⚠️ 规则集 %q 下载失败(%v)，已回退本地缓存: %s", t.tag, results[t.idx].err, path)
			continue
		}
		stats.Kept++
		log.Warn("⚠️ 规则集 %q 下载失败且无本地缓存(%v)，保留远程引用", t.tag, results[t.idx].err)
	}

	if err := saveManifest(opts.CacheDir, manifest); err != nil {
		log.Warn("ruleset manifest save failed: %v", err)
	}

	out, err := json.Marshal(cfg)
	if err != nil {
		return jsonStr, stats, fmt.Errorf("ruleset localize: re-marshal failed: %w", err)
	}
	return string(out), stats, nil
}

// LocalizeConfigFile 就地本地化现有配置文件（仅当其中含 remote 规则集时改写）。
// 用于存量配置迁移：singctl sb start / restart 时自动把旧配置切换为本地缓存。
func LocalizeConfigFile(configPath string, opts LocalizeOptions) (bool, RuleSetStats, error) {
	return mutateConfigFile(configPath, opts, func(data string, o LocalizeOptions) (string, RuleSetStats, error) {
		return LocalizeRuleSets(data, o)
	})
}

// RefreshConfigCache 刷新规则集缓存：
//   - remote 条目：下载并本地化（同 LocalizeConfigFile）
//   - local 条目：按 manifest 记录的 URL 重新下载刷新缓存文件
//
// 注意：阶段一只处理原始配置中为 remote 的条目，阶段二只刷新原始配置中
// 已是 local 的条目，避免对同一规则集重复下载。
func RefreshConfigCache(configPath string, opts LocalizeOptions) (bool, RuleSetStats, error) {
	return mutateConfigFile(configPath, opts, func(data string, o LocalizeOptions) (string, RuleSetStats, error) {
		o = o.withDefaults()

		// 记录原始配置中各条目的 type，用于区分两个阶段的处理对象
		origTypes := ruleSetTypes(data)

		// 第一阶段：remote → local
		out, stats, err := LocalizeRuleSets(data, o)
		if err != nil {
			return data, stats, err
		}

		// 第二阶段：刷新原始配置中已是 local 的条目
		var cfg map[string]any
		if err := json.Unmarshal([]byte(out), &cfg); err != nil {
			return out, stats, nil
		}
		route, _ := cfg["route"].(map[string]any)
		if route == nil {
			return out, stats, nil
		}
		arr, _ := route["rule_set"].([]any)

		manifest := loadManifest(o.CacheDir)
		var tasks []ruleSetTask
		for _, raw := range arr {
			entry, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			typ, _ := entry["type"].(string)
			tag, _ := entry["tag"].(string)
			// 仅刷新原始配置中已是 local 的条目（remote 的刚在阶段一下载过）
			if typ != "local" || tag == "" || origTypes[tag] != "local" {
				continue
			}
			meta, ok := manifest[tag]
			if !ok || meta.URL == "" {
				continue
			}
			format, _ := entry["format"].(string)
			if format == "" {
				format = "binary"
			}
			tasks = append(tasks, ruleSetTask{idx: len(tasks), tag: tag, url: meta.URL, format: format})
		}
		if len(tasks) > 0 {
			if err := os.MkdirAll(o.CacheDir, 0755); err != nil {
				return out, stats, nil
			}
			results, _ := fetchRuleSets(tasks, o, manifest)
			for _, t := range tasks {
				if results[t.idx].ok {
					stats.Refreshed++
				} else {
					log.Warn("⚠️ 规则集 %q 刷新失败(%v)，继续使用现有缓存", t.tag, results[t.idx].err)
				}
			}
		}
		return out, stats, nil
	})
}

// ruleSetTypes 解析配置中各规则集条目的 tag → type 映射。
func ruleSetTypes(jsonStr string) map[string]string {
	types := map[string]string{}
	var cfg map[string]any
	if err := json.Unmarshal([]byte(jsonStr), &cfg); err != nil {
		return types
	}
	route, _ := cfg["route"].(map[string]any)
	if route == nil {
		return types
	}
	arr, _ := route["rule_set"].([]any)
	for _, raw := range arr {
		entry, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		tag, _ := entry["tag"].(string)
		typ, _ := entry["type"].(string)
		if tag != "" {
			types[tag] = typ
		}
	}
	return types
}

// RuleSetCacheEntry 单条规则集缓存的状态信息。
type RuleSetCacheEntry struct {
	Tag       string
	URL       string
	Format    string
	UpdatedAt string
	File      string
	FileOK    bool // 缓存文件存在且内容合法
}

// CacheStatus 读取缓存清单，返回各规则集的缓存状态（按 tag 排序）。
func CacheStatus(opts LocalizeOptions) []RuleSetCacheEntry {
	opts = opts.withDefaults()
	manifest := loadManifest(opts.CacheDir)
	entries := make([]RuleSetCacheEntry, 0, len(manifest))
	for tag, meta := range manifest {
		format := meta.Format
		if format == "" {
			format = "binary"
		}
		path := cacheFilePath(opts.CacheDir, tag, format)
		entries = append(entries, RuleSetCacheEntry{
			Tag:       tag,
			URL:       meta.URL,
			Format:    format,
			UpdatedAt: meta.UpdatedAt,
			File:      path,
			FileOK:    cachedFileValid(path, format),
		})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Tag < entries[j].Tag })
	return entries
}

// RevertAndClearCache 将配置中的 local 规则集还原为 remote（依据 manifest），
// 并清空缓存目录。用于 singctl sb cache clear。
func RevertAndClearCache(configPath string, opts LocalizeOptions) (int, error) {
	opts = opts.withDefaults()

	data, err := os.ReadFile(configPath)
	if err != nil {
		return 0, fmt.Errorf("read config file: %w", err)
	}

	var cfg map[string]any
	if err := json.Unmarshal([]byte(data), &cfg); err != nil {
		return 0, fmt.Errorf("parse config file: %w", err)
	}
	route, _ := cfg["route"].(map[string]any)
	if route == nil {
		return 0, nil
	}
	arr, _ := route["rule_set"].([]any)
	if len(arr) == 0 {
		return 0, nil
	}

	manifest := loadManifest(opts.CacheDir)
	reverted := 0
	for _, raw := range arr {
		entry, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		typ, _ := entry["type"].(string)
		tag, _ := entry["tag"].(string)
		if typ != "local" || tag == "" {
			continue
		}
		meta, ok := manifest[tag]
		if !ok || meta.Original == nil {
			continue
		}
		// 用 manifest 中的原始 remote 条目完整替换
		replaceMapEntry(entry, meta.Original)
		reverted++
	}
	if reverted > 0 {
		out, err := json.Marshal(cfg)
		if err != nil {
			return reverted, fmt.Errorf("re-marshal config: %w", err)
		}
		if err := atomicWriteFile(configPath, out, configFileMode(configPath)); err != nil {
			return reverted, fmt.Errorf("write config file: %w", err)
		}
	}

	if err := os.RemoveAll(opts.CacheDir); err != nil {
		return reverted, fmt.Errorf("remove cache dir: %w", err)
	}
	return reverted, nil
}

// ───────────────────────────── 内部实现 ─────────────────────────────

type fetchOutcome struct {
	ok  bool
	err error
}

// ruleSetTask 单个规则集下载任务；entry 仅在需要改写配置的场景使用（刷新场景可为 nil）。
type ruleSetTask struct {
	idx    int
	tag    string
	url    string
	format string
	entry  map[string]any
}

func (t ruleSetTask) fields() (int, string, string, string) {
	return t.idx, t.tag, t.url, t.format
}

// fetchRuleSets 并行下载任务，带网络熔断（连续失败且无任何成功时跳过剩余下载）。
func fetchRuleSets(tasks []ruleSetTask, opts LocalizeOptions, manifest ruleSetManifest) (map[int]fetchOutcome, bool) {
	results := make(map[int]fetchOutcome, len(tasks))

	var (
		mu         sync.Mutex
		okCount    int
		failStreak int
		aborted    bool
		manMu      sync.Mutex
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
			okCount++
			failStreak = 0
			return
		}
		failStreak++
		if okCount == 0 && failStreak >= breakerThreshold {
			if !aborted {
				aborted = true
				log.Warn("⚠️ 网络不可用（GitHub/镜像均无法访问），跳过剩余规则集下载，将回退本地缓存")
			}
		}
	}

	sem := make(chan struct{}, opts.Workers)
	var wg sync.WaitGroup
	for _, t := range tasks {
		wg.Add(1)
		go func(t ruleSetTask) {
			defer wg.Done()
			idx, tag, url, format := t.fields()
			if shouldAbort() {
				mu.Lock()
				results[idx] = fetchOutcome{ok: false, err: fmt.Errorf("network aborted")}
				mu.Unlock()
				return
			}
			sem <- struct{}{}
			defer func() { <-sem }()

			data, err := downloadRuleSet(url, format, opts)
			noteResult(err == nil)
			if err != nil {
				mu.Lock()
				results[idx] = fetchOutcome{ok: false, err: err}
				mu.Unlock()
				return
			}
			path := cacheFilePath(opts.CacheDir, tag, format)
			if err := atomicWriteFile(path, data, 0644); err != nil {
				mu.Lock()
				results[idx] = fetchOutcome{ok: false, err: err}
				mu.Unlock()
				return
			}
			manMu.Lock()
			if meta, ok := manifest[tag]; ok {
				meta.UpdatedAt = time.Now().Format(time.RFC3339)
				manifest[tag] = meta
			}
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
	if wasAborted {
		log.Warn("⚠️ 规则集下载被熔断跳过，重启将继续使用本地缓存（如存在）")
	}
	return results, wasAborted
}

// downloadRuleSet 依次尝试原始 URL / 直连 / 镜像，校验内容合法性。
func downloadRuleSet(rawURL, format string, opts LocalizeOptions) ([]byte, error) {
	client := opts.Client
	var lastErr error
	for _, cand := range fetchCandidates(rawURL, opts.MirrorURL) {
		req, err := http.NewRequest(http.MethodGet, cand, nil)
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("User-Agent", "singctl-rule-set-cache")
		resp, err := client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("%s: %w", redactURL(cand), err)
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxRuleSetSize+1))
		resp.Body.Close()
		if err != nil {
			lastErr = fmt.Errorf("%s: read body: %w", redactURL(cand), err)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("%s: HTTP %d", redactURL(cand), resp.StatusCode)
			continue
		}
		if err := validateRuleSet(body, format); err != nil {
			lastErr = fmt.Errorf("%s: %w", redactURL(cand), err)
			continue
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
		if !bytes.HasPrefix(data, []byte(srsMagic)) {
			return fmt.Errorf("invalid binary rule set (missing %q magic)", srsMagic)
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
		magic := make([]byte, len(srsMagic))
		if _, err := io.ReadFull(f, magic); err != nil {
			return false
		}
		return bytes.HasPrefix(magic, []byte(srsMagic))
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
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
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
