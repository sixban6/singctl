// 文件职责：提供 sing-box 规则集本地缓存目录管理、声明式离线本地化与缓存刷新/回退对外契约。
package singbox

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"singctl/internal/common/sysinfo"
	"singctl/internal/constant"
	log "singctl/internal/logger"
	rssnapshot "singctl/internal/singbox/ruleset_snapshot"
	"sort"
	"strings"
	"time"
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
	defaultFetchTimeout    = 8 * time.Second
	defaultWorkers         = 6
	maxRuleSetSize         = 64 << 20 // 64MB 防御性上限
	DefaultRuleSetCacheTTL = 24 * time.Hour
	// sing-box 二进制规则集魔数：
	//   旧格式 (sing-box < 1.12): "RULE" + version(1)
	//   新格式 (sing-box >= 1.12): "SRS" + version(2)
	legacySRSMagic   = "RULE"
	srsMagic         = "SRS"
	manifestFileName = "manifest.json"
	// 连续失败达到该阈值时熔断（判定 GitHub 与镜像均不可用）
	breakerThreshold = 4
	// 首选候选（如镜像源）连续失败达到该阈值时自动降级为直连优先
	primaryFailThreshold = 2
)

// LocalizeOptions 本地化选项
type LocalizeOptions struct {
	MirrorURL    string        // GitHub 镜像前缀，如 https://gh-proxy.com
	CacheDir     string        // 缓存目录
	Client       *http.Client  // HTTP 客户端（测试可注入）
	Workers      int           // 并发下载数
	CacheTTL     time.Duration // 本地缓存有效期（>0 时命中未过期缓存直接跳过网络下载）
	OfflineFirst bool          // 离线优先（sb gen / sb start 使用）：直接复用本地缓存或解压内置快照，不阻塞等待网络下载
	Silent       bool          // 静默模式（后台守护进程自动更新使用）：不向终端输出常规进度与单条警告
}

func (o LocalizeOptions) withDefaults() LocalizeOptions {
	if o.CacheDir == "" {
		o.CacheDir = RuleSetCacheDir()
	}
	if o.Client == nil {
		o.Client = &http.Client{
			Timeout: defaultFetchTimeout,
			Transport: &http.Transport{
				DialContext: (&net.Dialer{
					Timeout: 4 * time.Second,
				}).DialContext,
				TLSHandshakeTimeout:   4 * time.Second,
				ResponseHeaderTimeout: 5 * time.Second,
			},
		}
	}
	if o.Workers <= 0 {
		o.Workers = defaultWorkers
	}
	return o
}

// RuleSetStats 本地化结果统计
type RuleSetStats struct {
	Remote    int  // 配置中发现的 remote 规则集数量
	Localized int  // 新下载成功（或命中未过期缓存）并改写为本地引用
	Cached    int  // 其中直接复用 TTL 内未过期本地缓存的数量
	Fallback  int  // 下载失败但成功回退本地旧缓存
	Snapshot  int  // 下载失败且无缓存，从程序内置快照兑底
	Kept      int  // 下载失败且无任何兑底，保持 remote 原样
	Refreshed int  // cache update 时刷新的已本地化条目
	Aborted   bool // 网络熔断，剩余下载被跳过
}

func (s RuleSetStats) HasLocalChange() bool {
	return s.Localized > 0 || s.Fallback > 0 || s.Snapshot > 0 || s.Kept > 0
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
	sanitizedHC := sanitizeRootHTTPClients(cfg)
	hasDefaultHC := false
	if dhc, _ := route["default_http_client"].(string); strings.TrimSpace(dhc) != "" {
		hasDefaultHC = true
	}
	arr, _ := route["rule_set"].([]any)

	manifest := loadManifest(opts.CacheDir)
	snap := rssnapshot.Load()

	// 1. 收集 remote 任务、记录全部活跃规则集 tag，并自检已是 type: local 但磁盘文件缺失/损坏的规则集条目
	var tasks []ruleSetTask
	activeTags := make(map[string]struct{}, len(arr))
	cleanCacheDir := filepath.Clean(opts.CacheDir)
	repairedLocalOnDisk := false
	for i, raw := range arr {
		entry, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		typ, _ := entry["type"].(string)
		url, _ := entry["url"].(string)
		tag, _ := entry["tag"].(string)
		if tag == "" {
			continue
		}
		activeTags[tag] = struct{}{}
		format, _ := entry["format"].(string)
		if format == "" {
			format = "binary"
		}

		if typ == "local" {
			path, _ := entry["path"].(string)
			if path == "" {
				path = cacheFilePath(opts.CacheDir, tag, format)
			} else if filepath.Clean(filepath.Dir(path)) == cleanCacheDir {
				if base := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path)); base != "" {
					activeTags[base] = struct{}{}
				}
			}
			if cachedFileValid(path, format) {
				continue
			}
			// 磁盘文件缺失或损坏：1) 优先从内置离线快照毫秒级流式恢复
			meta := manifest[tag]
			if tryRestoreRuleSetFromSnapshot(snap, tag, meta.URL, format, path) {
				stats.Snapshot++
				repairedLocalOnDisk = true
				entry["path"] = path
				if !opts.Silent {
					log.Info("📦 检测到本地规则集文件缺失 (%s)，已从内置离线快照自动恢复: %s", tag, path)
				}
				continue
			}
			// 2) 若不在内置快照中，根据 manifest 记录的原始 URL 自动加入重新下载队列
			dlURL := meta.URL
			if dlURL == "" && meta.Original != nil {
				dlURL, _ = meta.Original["url"].(string)
			}
			if dlURL != "" {
				if !opts.Silent {
					log.Warn("⚠️ 检测到本地规则集文件缺失 (%s)，正在尝试从远程重新下载恢复...", tag)
				}
				tasks = append(tasks, ruleSetTask{
					idx:             i,
					tag:             tag,
					url:             dlURL,
					format:          format,
					entry:           entry,
					wasMissingLocal: true,
				})
			}
			continue
		}

		if typ != "remote" || url == "" {
			continue
		}
		stats.Remote++
		tasks = append(tasks, ruleSetTask{idx: i, tag: tag, url: url, format: format, entry: entry})
	}
	if len(tasks) == 0 {
		pruneOrphanRuleSetsLogged(opts, activeTags)
		if repairedLocalOnDisk || sanitizedHC {
			out, err := json.Marshal(cfg)
			if err == nil {
				return string(out), stats, nil
			}
		}
		return jsonStr, stats, nil
	}

	if err := os.MkdirAll(opts.CacheDir, 0755); err != nil {
		return jsonStr, stats, fmt.Errorf("ruleset localize: create cache dir failed: %w", err)
	}

	for _, t := range tasks {
		// 无论成败都预先记录 manifest 元信息，供下载期间增量落盘及 sb cache update/clear 使用
		meta := manifest[t.tag]
		meta.URL = t.url
		meta.Format = t.format
		if meta.Original == nil && !t.wasMissingLocal {
			// 必须深拷贝：t.entry 后续会被 localizeEntry 原地改写，
			// 直接存引用会把改写后的 local 条目写入 manifest，导致无法还原
			meta.Original = copyRuleSetEntry(t.entry)
		}
		manifest[t.tag] = meta
	}

	// OfflineFirst 模式（用于 sb gen / sb start）：
	// 优先直接复用本地已有 .srs 缓存或解压程序内置快照，完全不发起网络请求，做到毫秒级生成；
	// 仅当存在既无本地缓存、又不在内置快照中的自定义远程规则集时，才对该条目发起网络拉取。
	if opts.OfflineFirst {
		var netTasks []ruleSetTask
		for _, t := range tasks {
			path := cacheFilePath(opts.CacheDir, t.tag, t.format)
			if cachedFileValid(path, t.format) {
				stats.Localized++
				stats.Cached++
				localizeEntry(t.entry, path)
				continue
			}
			if tryRestoreRuleSetFromSnapshot(snap, t.tag, t.url, t.format, path) {
				stats.Snapshot++
				localizeEntry(t.entry, path)
				continue
			}
			netTasks = append(netTasks, t)
		}

		if len(netTasks) > 0 {
			results, aborted := fetchRuleSets(netTasks, opts, manifest)
			stats.Aborted = aborted
			for _, t := range netTasks {
				path := cacheFilePath(opts.CacheDir, t.tag, t.format)
				if results[t.idx].ok {
					stats.Localized++
					localizeEntry(t.entry, path)
					continue
				}
				stats.Kept++
				if t.wasMissingLocal {
					revertMissingLocalToRemote(t.entry, t.url, t.format)
				} else {
					sanitizeKeptRemoteEntry(t.entry, hasDefaultHC)
				}
				if !opts.Silent && !results[t.idx].aborted {
					log.Warn("⚠️ 自定义规则集 %q 下载失败且无内置快照(%v)，保留远程引用", t.tag, results[t.idx].err)
				}
			}
		}

		if err := saveManifest(opts.CacheDir, manifest); err != nil && !opts.Silent {
			log.Warn("ruleset manifest save failed: %v", err)
		}
		pruneOrphanRuleSetsLogged(opts, activeTags)
		out, err := json.Marshal(cfg)
		if err != nil {
			return jsonStr, stats, fmt.Errorf("ruleset localize: re-marshal failed: %w", err)
		}
		return string(out), stats, nil
	}

	// 2. 并行下载
	results, aborted := fetchRuleSets(tasks, opts, manifest)
	stats.Aborted = aborted

	// 3. 依据结果改写条目（在线下载 → 本地旧缓存 → 内置快照 三级兑底）
	for _, t := range tasks {
		path := cacheFilePath(opts.CacheDir, t.tag, t.format)

		if results[t.idx].ok {
			stats.Localized++
			if results[t.idx].cached {
				stats.Cached++
			}
			localizeEntry(t.entry, path)
			continue
		}
		// 下载失败 → 回退本地缓存
		if cachedFileValid(path, t.format) {
			stats.Fallback++
			localizeEntry(t.entry, path)
			if !opts.Silent && !results[t.idx].aborted {
				log.Warn("⚠️ 规则集 %q 下载失败(%v)，已回退本地缓存: %s", t.tag, results[t.idx].err, path)
			}
			continue
		}
		// 无本地缓存 → 程序内置快照兑底（流式解压校验直写，避免整块堆内存分配）
		if tryRestoreRuleSetFromSnapshot(snap, t.tag, t.url, t.format, path) {
			stats.Snapshot++
			localizeEntry(t.entry, path)
			if !opts.Silent && !results[t.idx].aborted {
				log.Warn("📦 规则集 %q 下载失败且无缓存，已使用程序内置快照兑底: %s", t.tag, path)
			}
			continue
		}
		stats.Kept++
		if t.wasMissingLocal {
			revertMissingLocalToRemote(t.entry, t.url, t.format)
		} else {
			sanitizeKeptRemoteEntry(t.entry, hasDefaultHC)
		}
		if !opts.Silent && !results[t.idx].aborted {
			log.Warn("⚠️ 规则集 %q 下载失败且无任何兑底(%v)，保留远程引用", t.tag, results[t.idx].err)
		}
	}

	if err := saveManifest(opts.CacheDir, manifest); err != nil && !opts.Silent {
		log.Warn("ruleset manifest save failed: %v", err)
	}
	pruneOrphanRuleSetsLogged(opts, activeTags)

	out, err := json.Marshal(cfg)
	if err != nil {
		return jsonStr, stats, fmt.Errorf("ruleset localize: re-marshal failed: %w", err)
	}
	return string(out), stats, nil
}

func pruneOrphanRuleSetsLogged(opts LocalizeOptions, activeTags map[string]struct{}) {
	if len(activeTags) == 0 {
		return
	}
	removed, freed := PruneOrphanRuleSetFiles(opts.CacheDir, activeTags)
	if removed > 0 && !opts.Silent {
		log.Info("🧹 已自动回收 %d 个孤立规则集缓存文件（释放 %s）", removed, sysinfo.FormatBytes(freed))
	}
}

// PruneOrphanRuleSetFiles 安全清理规则集缓存目录中不再被当前配置引用的孤立 .srs / .json 文件，
// 并同步清理 manifest.json 中对应的失效条目。
// 防误删红线：仅删除扩展名为 .srs 或 .json 且非 manifest.json 的普通文件；当 activeTags 为空时严禁清空目录。
func PruneOrphanRuleSetFiles(cacheDir string, activeTags map[string]struct{}) (removed int, freedBytes int64) {
	cleanDir := strings.TrimSpace(cacheDir)
	if cleanDir == "" || len(activeTags) == 0 {
		return 0, 0
	}

	activeBases := make(map[string]struct{}, len(activeTags)*2)
	for rawTag := range activeTags {
		tag := strings.TrimSpace(rawTag)
		if tag == "" {
			continue
		}
		activeBases[tag] = struct{}{}
		activeBases[sanitizeTag(tag)] = struct{}{}
	}
	if len(activeBases) == 0 {
		return 0, 0
	}

	entries, err := os.ReadDir(cleanDir)
	if err != nil {
		return 0, 0
	}

	for _, entry := range entries {
		if entry.IsDir() || !entry.Type().IsRegular() {
			continue
		}
		name := entry.Name()
		if strings.EqualFold(name, manifestFileName) {
			continue
		}
		ext := filepath.Ext(name)
		lowerExt := strings.ToLower(ext)
		if lowerExt != ".srs" && lowerExt != ".json" {
			continue
		}
		base := strings.TrimSuffix(name, ext)
		if _, keep := activeBases[base]; keep {
			continue
		}
		info, _ := entry.Info()
		if err := os.Remove(filepath.Join(cleanDir, name)); err == nil {
			removed++
			if info != nil {
				freedBytes += info.Size()
			}
		}
	}

	manifest := loadManifest(cleanDir)
	if len(manifest) > 0 {
		manifestChanged := false
		for tag := range manifest {
			_, keepRaw := activeBases[tag]
			_, keepSanitized := activeBases[sanitizeTag(tag)]
			if !keepRaw && !keepSanitized {
				delete(manifest, tag)
				manifestChanged = true
			}
		}
		if manifestChanged {
			if len(manifest) == 0 {
				_ = os.Remove(manifestPath(cleanDir))
			} else {
				_ = saveManifest(cleanDir, manifest)
			}
		}
	}

	return removed, freedBytes
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
			results, aborted := fetchRuleSets(tasks, o, manifest)
			stats.Aborted = stats.Aborted || aborted
			for _, t := range tasks {
				if results[t.idx].ok {
					if results[t.idx].cached {
						stats.Cached++
					} else {
						stats.Refreshed++
					}
				} else if !o.Silent && !results[t.idx].aborted {
					log.Warn("⚠️ 规则集 %q 刷新失败(%v)，继续使用现有缓存", t.tag, results[t.idx].err)
				}
			}
			_ = saveManifest(o.CacheDir, manifest)
		}
		return out, stats, nil
	})
}

// NeedsCacheRefresh 检查配置文件中的规则集是否存在需要联网更新的条目
// （例如仍为 remote、本地文件缺失、仅由内置快照初装尚未联网更新、或已超过 CacheTTL）。
func NeedsCacheRefresh(configPath string, opts LocalizeOptions) bool {
	opts = opts.withDefaults()
	ttl := opts.CacheTTL
	if ttl <= 0 {
		ttl = DefaultRuleSetCacheTTL
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return false
	}
	var cfg map[string]any
	if err := json.Unmarshal(data, &cfg); err != nil {
		return false
	}
	route, _ := cfg["route"].(map[string]any)
	if route == nil {
		return false
	}
	arr, _ := route["rule_set"].([]any)
	if len(arr) == 0 {
		return false
	}

	manifest := loadManifest(opts.CacheDir)
	for _, raw := range arr {
		entry, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		typ, _ := entry["type"].(string)
		tag, _ := entry["tag"].(string)
		if tag == "" {
			continue
		}
		if typ == "remote" {
			return true
		}
		if typ != "local" {
			continue
		}
		meta, hasMeta := manifest[tag]
		if !hasMeta || meta.URL == "" {
			continue
		}
		format, _ := entry["format"].(string)
		if format == "" {
			format = "binary"
		}
		path := cacheFilePath(opts.CacheDir, tag, format)
		if !isCacheFresh(path, format, manifest, tag, ttl) {
			return true
		}
	}
	return false
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
	Tag        string
	URL        string
	Format     string
	UpdatedAt  string
	File       string
	FileOK     bool // 缓存文件存在且内容合法
	InSnapshot bool // 程序内置快照中包含此规则集（可随时兑底）
}

// CacheStatus 读取缓存清单，返回各规则集的缓存状态（按 tag 排序）。
// 同时并入内置快照中存在但尚未建立缓存的条目，便于了解兑底覆盖面。
func CacheStatus(opts LocalizeOptions) []RuleSetCacheEntry {
	opts = opts.withDefaults()
	manifest := loadManifest(opts.CacheDir)
	snap := rssnapshot.Load()
	entries := make([]RuleSetCacheEntry, 0, len(manifest)+snap.Count())
	seen := map[string]bool{}
	for tag, meta := range manifest {
		format := meta.Format
		if format == "" {
			format = "binary"
		}
		path := cacheFilePath(opts.CacheDir, tag, format)
		_, _, _, inSnap := snap.Lookup(tag, "")
		entries = append(entries, RuleSetCacheEntry{
			Tag:        tag,
			URL:        meta.URL,
			Format:     format,
			UpdatedAt:  meta.UpdatedAt,
			File:       path,
			FileOK:     cachedFileValid(path, format),
			InSnapshot: inSnap,
		})
		seen[tag] = true
	}
	// 快照中存在但尚未建立本地缓存的条目（例如从未成功下载过）
	for _, tag := range snap.Tags() {
		if seen[tag] {
			continue
		}
		if mTag, mURL, mFormat, ok := snap.Lookup(tag, ""); ok {
			entries = append(entries, RuleSetCacheEntry{
				Tag:        mTag,
				URL:        mURL,
				Format:     mFormat,
				File:       "(仅内置快照)",
				InSnapshot: true,
			})
		}
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
