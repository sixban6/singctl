// 文件职责：负责 SubHub 本地/远程订阅源目录（sub-store.json）的 mtime 内存缓存读取、CRUD 变更、集合聚合解析与订阅路径密钥（key）管理。
//
// 架构设计原则：
//   - 高内聚拆 file：网络自适应抓取与 SSRF 校验下沉至 remote_fetcher.go，多格式节点解析与链路归一化下沉至 payload_decoder.go，
//     本文件聚焦持久化仓储状态、并发锁保护与集合合并去重。
package subhub

import (
	"cmp"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"singctl/internal/constant"

	"github.com/sixban6/singgen/pkg/model"
)

const (
	DefaultCollectionName = "all"
	maxRemoteSubBytes     = 8 * 1024 * 1024 // 8 MiB

	UAV2rayNG      = "v2rayNG/1.8.19"
	UAShadowrocket = "Shadowrocket/2078 CFNetwork/1496.0.7 Darwin/23.5.0"
	UAClashMeta    = "clash.meta/v1.18.0"
	UASingBox      = "SFA/1.11.0 (sing-box 1.11.0)"
)

var slugSanitizeRe = regexp.MustCompile(`[^a-zA-Z0-9_-]+`)

// SourceItem describes a single subscription source managed by SubHub.
type SourceItem struct {
	Name          string `json:"name"`
	DisplayName   string `json:"displayName"`
	Source        string `json:"source"` // "local" or "remote"
	URL           string `json:"url"`
	Content       string `json:"content"`
	Remark        string `json:"remark"`
	Enabled       bool   `json:"enabled"`
	AutoManaged   bool   `json:"autoManaged"`
	NodeCount     int    `json:"nodeCount"`
	UserAgent     string `json:"userAgent,omitzero"`     // "auto", "v2rayng", "shadowrocket", "clashmeta", "singbox", or custom UA
	ProxyMode     string `json:"proxyMode,omitzero"`     // "auto", "direct", "warp"
	EffectiveUA   string `json:"effectiveUa,omitzero"`   // last winning User-Agent string
	UsedProxy     string `json:"usedProxy,omitzero"`     // "direct" or "warp"
	LastFetchedAt string `json:"lastFetchedAt,omitzero"` // RFC3339 timestamp
	LastError     string `json:"lastError,omitzero"`     // last fetch failure message, if any
}

// SourceUpsertInput is the payload for creating or updating a subscription source.
type SourceUpsertInput struct {
	Name             string `json:"name"`
	DisplayName      string `json:"displayName"`
	Source           string `json:"source"` // "local" or "remote"
	URL              string `json:"url"`
	Content          string `json:"content"`
	Remark           string `json:"remark"`
	UserAgent        string `json:"userAgent,omitzero"`
	ProxyMode        string `json:"proxyMode,omitzero"`
	Enabled          *bool  `json:"enabled,omitzero"`
	AllowAutoManaged bool   `json:"-"`
}

// ResolvedBundle contains deduplicated proxy URIs and parsed nodes ready for target rendering.
type ResolvedBundle struct {
	Name  string
	URIs  []string
	Nodes []model.Node
}

type remoteCacheEntry struct {
	URL         string    `json:"url"`
	Body        string    `json:"body"`
	FetchedAt   time.Time `json:"fetchedAt"`
	EffectiveUA string    `json:"effectiveUa,omitzero"`
	UsedProxy   string    `json:"usedProxy,omitzero"`
	LastError   string    `json:"lastError,omitzero"`
}

// Store manages subscription persistence, mtime caching, and remote subscription fetching.
type Store struct {
	DataDir             string
	FilePath            string
	AllowLoopbackRemote bool
	WarpProxyAddr       string
	HTTPTimeout         time.Duration
	CacheTTL            time.Duration

	mu               sync.RWMutex
	cachedMtime      time.Time
	cachedSize       int64
	cachedDoc        map[string]any
	remoteCacheMtime time.Time
	remoteCache      map[string]remoteCacheEntry
	lastAttempt      map[string]time.Time
}

// NewStore creates a Store backed by dir and filePath (defaulting to constant.SubStoreDir/SubStoreFile).
func NewStore(dir, filePath string) *Store {
	d := cmp.Or(strings.TrimSpace(dir), constant.SubStoreDir)
	f := cmp.Or(strings.TrimSpace(filePath), constant.SubStoreFile)
	if dir != "" && filePath == "" {
		f = filepath.Join(d, "sub-store.json")
	}
	s := &Store{
		DataDir:       d,
		FilePath:      f,
		WarpProxyAddr: DefaultWarpProxyAddr,
		HTTPTimeout:   12 * time.Second,
		CacheTTL:      10 * time.Minute,
		remoteCache:   make(map[string]remoteCacheEntry),
		lastAttempt:   make(map[string]time.Time),
	}
	s.loadRemoteCacheFromDisk()
	return s
}

func (s *Store) keyFilePath() string {
	return filepath.Join(s.DataDir, "key")
}

func (s *Store) remoteCachePath() string {
	return filepath.Join(s.DataDir, ".remote_cache.json")
}

// GetKey returns the persisted subscription path secret key, if present.
func (s *Store) GetKey() (string, error) {
	data, err := os.ReadFile(s.keyFilePath())
	if err != nil {
		return "", err
	}
	key := strings.TrimSpace(string(data))
	if key == "" {
		return "", errors.New("subscription key file is empty")
	}
	return key, nil
}

// EnsureKey returns the existing key or generates and saves a new 26-hex random key (0600).
func (s *Store) EnsureKey() (string, error) {
	if key, err := s.GetKey(); err == nil && key != "" {
		return key, nil
	}
	return s.RotateKey()
}

// RotateKey generates and atomically writes a fresh 26-hex subscription secret key.
func (s *Store) RotateKey() (string, error) {
	if err := os.MkdirAll(s.DataDir, 0700); err != nil {
		return "", fmt.Errorf("create subhub data dir: %w", err)
	}
	buf := make([]byte, 13)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate random key: %w", err)
	}
	key := hex.EncodeToString(buf)
	tmp := s.keyFilePath() + ".tmp"
	if err := os.WriteFile(tmp, []byte(key), 0600); err != nil {
		return "", fmt.Errorf("write key file: %w", err)
	}
	_ = os.Chmod(tmp, 0600)
	if err := os.Rename(tmp, s.keyFilePath()); err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("commit key file: %w", err)
	}
	_ = os.Chmod(s.keyFilePath(), 0600)
	return key, nil
}

func isAutoManagedName(name string) bool {
	return name == "auto_generated_hy2" || name == "auto_generated_vless"
}

func (s *Store) readDocLocked() (map[string]any, error) {
	st, err := os.Stat(s.FilePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return map[string]any{
				"subs":        []any{},
				"collections": []any{},
			}, nil
		}
		return nil, err
	}

	if s.cachedDoc != nil && st.ModTime().Equal(s.cachedMtime) && st.Size() == s.cachedSize {
		return cloneDoc(s.cachedDoc), nil
	}

	raw, err := os.ReadFile(s.FilePath)
	if err != nil {
		return nil, err
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		doc := map[string]any{"subs": []any{}, "collections": []any{}}
		s.cachedDoc = doc
		s.cachedMtime = st.ModTime()
		s.cachedSize = st.Size()
		return cloneDoc(doc), nil
	}

	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parse %s: %w", s.FilePath, err)
	}
	if doc == nil {
		doc = make(map[string]any)
	}
	s.cachedDoc = doc
	s.cachedMtime = st.ModTime()
	s.cachedSize = st.Size()
	return cloneDoc(doc), nil
}

func cloneDoc(doc map[string]any) map[string]any {
	b, err := json.Marshal(doc)
	if err != nil {
		return maps.Clone(doc)
	}
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	if out == nil {
		out = make(map[string]any)
	}
	return out
}

func (s *Store) writeDocLocked(doc map[string]any) error {
	if err := os.MkdirAll(filepath.Dir(s.FilePath), 0700); err != nil {
		return fmt.Errorf("create dir for %s: %w", s.FilePath, err)
	}
	mode := os.FileMode(0600)
	if st, err := os.Stat(s.FilePath); err == nil {
		mode = st.Mode().Perm()
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal %s: %w", s.FilePath, err)
	}
	tmp := s.FilePath + ".tmp"
	if err := os.WriteFile(tmp, out, mode); err != nil {
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, s.FilePath); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename %s: %w", s.FilePath, err)
	}
	if st, err := os.Stat(s.FilePath); err == nil {
		s.cachedDoc = cloneDoc(doc)
		s.cachedMtime = st.ModTime()
		s.cachedSize = st.Size()
	}
	return nil
}

func subEnabled(sub map[string]any) bool {
	v, exists := sub["enabled"]
	if !exists {
		return true
	}
	b, ok := v.(bool)
	if !ok {
		return true
	}
	return b
}

func mapToSourceItem(sub map[string]any, cache remoteCacheEntry) SourceItem {
	name, _ := sub["name"].(string)
	displayName, _ := sub["displayName"].(string)
	if displayName == "" {
		displayName, _ = sub["display-name"].(string)
	}
	displayName = cmp.Or(displayName, name)

	srcType, _ := sub["source"].(string)
	rawURL, _ := sub["url"].(string)
	content, _ := sub["content"].(string)
	remark, _ := sub["remark"].(string)

	if srcType == "" {
		if strings.TrimSpace(rawURL) != "" {
			srcType = "remote"
		} else {
			srcType = "local"
		}
	}

	item := SourceItem{
		Name:        name,
		DisplayName: displayName,
		Source:      srcType,
		URL:         rawURL,
		Content:     content,
		Remark:      remark,
		Enabled:     subEnabled(sub),
		AutoManaged: isAutoManagedName(name),
	}

	if srcType == "remote" {
		uaStrategy, proxyMode := subFetchOptions(sub)
		item.UserAgent = uaStrategy
		item.ProxyMode = proxyMode
		item.EffectiveUA = cache.EffectiveUA
		item.UsedProxy = cache.UsedProxy
		item.LastError = cache.LastError
		if !cache.FetchedAt.IsZero() {
			item.LastFetchedAt = cache.FetchedAt.UTC().Format(time.RFC3339)
		}
		if cache.Body != "" {
			nodes, uris := ParseRawSubscriptionPayload(context.Background(), []byte(cache.Body))
			item.NodeCount = max(len(nodes), len(uris))
		}
	} else if strings.TrimSpace(content) != "" {
		nodes, uris := ParseRawSubscriptionPayload(context.Background(), []byte(content))
		item.NodeCount = max(len(nodes), len(uris))
	}

	return item
}

// ListSources returns all subscription sources configured in sub-store.json.
func (s *Store) ListSources() ([]SourceItem, error) {
	s.mu.Lock()
	doc, err := s.readDocLocked()
	var cacheSnapshot map[string]remoteCacheEntry
	if err == nil {
		s.reloadRemoteCacheLocked()
		cacheSnapshot = maps.Clone(s.remoteCache)
	}
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}

	rawSubs, _ := doc["subs"].([]any)
	items := make([]SourceItem, 0, len(rawSubs))
	for _, entry := range rawSubs {
		sub, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		u, _ := sub["url"].(string)
		items = append(items, mapToSourceItem(sub, cacheSnapshot[strings.TrimSpace(u)]))
	}
	return items, nil
}

// UpsertSource creates or updates a subscription source and registers it in the "all" collection.
func (s *Store) UpsertSource(ctx context.Context, in SourceUpsertInput) (*SourceItem, error) {
	displayName := strings.TrimSpace(in.DisplayName)
	name := strings.TrimSpace(in.Name)
	if name == "" && displayName != "" {
		slug := strings.Trim(slugSanitizeRe.ReplaceAllString(strings.ToLower(displayName), "-"), "-")
		if slug == "" {
			slug = fmt.Sprintf("sub-%d", time.Now().Unix())
		}
		name = slug
	}
	if name == "" {
		return nil, errors.New("订阅名称不能为空")
	}
	if isAutoManagedName(name) && !in.AllowAutoManaged {
		if strings.TrimSpace(in.Source) == "remote" {
			return nil, errors.New("系统自动同步节点源不支持改为远程 URL 类型")
		}
	}

	srcType := strings.ToLower(strings.TrimSpace(in.Source))
	if srcType == "" {
		if strings.TrimSpace(in.URL) != "" {
			srcType = "remote"
		} else {
			srcType = "local"
		}
	}
	if srcType != "local" && srcType != "remote" {
		return nil, fmt.Errorf("不支持的订阅源类型: %s (仅支持 local 或 remote)", srcType)
	}

	rawURL := strings.TrimSpace(in.URL)
	content := strings.TrimSpace(in.Content)
	enabled := true
	if in.Enabled != nil {
		enabled = *in.Enabled
	}

	prevUA, prevPM := s.existingSubFetchOptions(name)
	uaStrategy := cmp.Or(strings.TrimSpace(in.UserAgent), prevUA, "auto")
	proxyMode := normalizeProxyMode(cmp.Or(strings.TrimSpace(in.ProxyMode), prevPM, "auto"))

	if srcType == "remote" {
		if err := s.validateRemoteURL(rawURL); err != nil {
			return nil, err
		}
		if enabled {
			body, err := s.fetchRemoteAdaptive(ctx, rawURL, uaStrategy, proxyMode, true)
			if err != nil {
				return nil, fmt.Errorf("拉取远程订阅验证失败: %w", err)
			}
			nodes, uris := ParseRawSubscriptionPayload(ctx, []byte(body))
			if len(nodes) == 0 && len(uris) == 0 {
				return nil, errors.New("远程订阅内容未解析出任何有效代理节点")
			}
		}
	} else {
		if content == "" && (!isAutoManagedName(name) || in.Enabled == nil) {
			return nil, errors.New("本地节点内容不能为空（请输入 vless://、hysteria2:// 等节点链接）")
		}
		if content != "" {
			nodes, uris := ParseRawSubscriptionPayload(ctx, []byte(content))
			if len(nodes) == 0 && len(uris) == 0 {
				return nil, errors.New("未识别到有效的代理节点链接（支持 vless/hysteria2/trojan/vmess/ss/tuic/anytls、Base64、Clash YAML 或 Sing-box JSON）")
			}
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	doc, err := s.readDocLocked()
	if err != nil {
		return nil, err
	}

	rawSubs, _ := doc["subs"].([]any)
	var updatedSub map[string]any
	idx := slices.IndexFunc(rawSubs, func(entry any) bool {
		m, ok := entry.(map[string]any)
		if !ok {
			return false
		}
		n, _ := m["name"].(string)
		return n == name
	})

	if idx >= 0 {
		existing := rawSubs[idx].(map[string]any)
		if displayName != "" {
			existing["displayName"] = displayName
			existing["display-name"] = displayName
		}
		existing["source"] = srcType
		if srcType == "remote" {
			existing["url"] = rawURL
			existing["content"] = ""
			existing["userAgent"] = uaStrategy
			existing["proxyMode"] = proxyMode
			if strings.EqualFold(uaStrategy, "auto") {
				delete(existing, "ua")
			}
		} else {
			existing["url"] = ""
			if content != "" || !isAutoManagedName(name) {
				existing["content"] = content
			}
		}
		if in.Remark != "" || !isAutoManagedName(name) {
			existing["remark"] = strings.TrimSpace(in.Remark)
		}
		existing["enabled"] = enabled
		rawSubs[idx] = existing
		updatedSub = existing
	} else {
		if displayName == "" {
			displayName = name
		}
		updatedSub = map[string]any{
			"name":         name,
			"displayName":  displayName,
			"display-name": displayName,
			"source":       srcType,
			"url":          rawURL,
			"content":      content,
			"remark":       strings.TrimSpace(in.Remark),
			"enabled":      enabled,
		}
		if srcType == "remote" {
			updatedSub["userAgent"] = uaStrategy
			updatedSub["proxyMode"] = proxyMode
		}
		rawSubs = append(rawSubs, updatedSub)
	}
	doc["subs"] = rawSubs
	ensureInAllCollection(doc, name)

	if err := s.writeDocLocked(doc); err != nil {
		return nil, err
	}

	var cacheEntry remoteCacheEntry
	if rawURL != "" {
		cacheEntry = s.remoteCache[rawURL]
	}
	item := mapToSourceItem(updatedSub, cacheEntry)
	return &item, nil
}

// DeleteSource deletes a subscription source by name and cleans references in collections.
func (s *Store) DeleteSource(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return errors.New("订阅名称不能为空")
	}
	if isAutoManagedName(name) {
		return errors.New("本机自动同步源不可直接删除，如需停用可将其设为禁用")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	doc, err := s.readDocLocked()
	if err != nil {
		return err
	}

	rawSubs, _ := doc["subs"].([]any)
	filtered := make([]any, 0, len(rawSubs))
	removed := false
	for _, entry := range rawSubs {
		m, ok := entry.(map[string]any)
		if !ok {
			filtered = append(filtered, entry)
			continue
		}
		if n, _ := m["name"].(string); n == name {
			removed = true
			continue
		}
		filtered = append(filtered, m)
	}
	if !removed {
		return fmt.Errorf("未找到名为 %q 的订阅源", name)
	}
	doc["subs"] = filtered

	if rawCols, ok := doc["collections"].([]any); ok {
		for _, c := range rawCols {
			col, ok := c.(map[string]any)
			if !ok {
				continue
			}
			if subList, ok := col["subscriptions"].([]any); ok {
				cleaned := make([]any, 0, len(subList))
				for _, sn := range subList {
					if sStr, ok := sn.(string); ok && sStr == name {
						continue
					}
					cleaned = append(cleaned, sn)
				}
				col["subscriptions"] = cleaned
			}
		}
		doc["collections"] = rawCols
	}

	return s.writeDocLocked(doc)
}

func ensureInAllCollection(doc map[string]any, subName string) {
	rawCols, _ := doc["collections"].([]any)
	foundAll := false
	for _, c := range rawCols {
		col, ok := c.(map[string]any)
		if !ok {
			continue
		}
		if n, _ := col["name"].(string); n == DefaultCollectionName {
			foundAll = true
			subList, _ := col["subscriptions"].([]any)
			exists := slices.ContainsFunc(subList, func(v any) bool {
				s, ok := v.(string)
				return ok && s == subName
			})
			if !exists {
				subList = append(subList, subName)
				col["subscriptions"] = subList
			}
		}
	}
	if !foundAll {
		rawCols = append(rawCols, map[string]any{
			"name":          DefaultCollectionName,
			"displayName":   DefaultCollectionName,
			"subscriptions": []any{subName},
		})
	}
	doc["collections"] = rawCols
}

// ResolveCollection aggregates and parses all enabled subscriptions in the named collection.
func (s *Store) ResolveCollection(ctx context.Context, collectionName string) (*ResolvedBundle, error) {
	collectionName = cmp.Or(strings.TrimSpace(collectionName), DefaultCollectionName)

	s.mu.Lock()
	doc, err := s.readDocLocked()
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}

	rawSubs, _ := doc["subs"].([]any)
	subByName := make(map[string]map[string]any, len(rawSubs))
	var orderedNames []string
	for _, entry := range rawSubs {
		m, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		if n, _ := m["name"].(string); n != "" {
			subByName[n] = m
			orderedNames = append(orderedNames, n)
		}
	}

	var targetSubNames []string
	rawCols, _ := doc["collections"].([]any)
	foundCol := false
	for _, entry := range rawCols {
		col, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		n, _ := col["name"].(string)
		if strings.EqualFold(n, collectionName) {
			foundCol = true
			if list, ok := col["subscriptions"].([]any); ok {
				for _, v := range list {
					if sn, ok := v.(string); ok && sn != "" {
						targetSubNames = append(targetSubNames, sn)
					}
				}
			} else if list, ok := col["subs"].([]any); ok {
				for _, v := range list {
					if sn, ok := v.(string); ok && sn != "" {
						targetSubNames = append(targetSubNames, sn)
					}
				}
			}
			break
		}
	}

	if !foundCol {
		if strings.EqualFold(collectionName, DefaultCollectionName) {
			targetSubNames = orderedNames
		} else {
			return nil, fmt.Errorf("collection %q not found", collectionName)
		}
	}

	return s.resolveSubList(ctx, collectionName, targetSubNames, subByName)
}

// ResolveSubscription resolves a single named subscription source.
func (s *Store) ResolveSubscription(ctx context.Context, subName string) (*ResolvedBundle, error) {
	s.mu.Lock()
	doc, err := s.readDocLocked()
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}

	rawSubs, _ := doc["subs"].([]any)
	subByName := make(map[string]map[string]any, len(rawSubs))
	for _, entry := range rawSubs {
		if m, ok := entry.(map[string]any); ok {
			if n, _ := m["name"].(string); n != "" {
				subByName[n] = m
			}
		}
	}
	if _, ok := subByName[subName]; !ok {
		return nil, fmt.Errorf("subscription %q not found", subName)
	}
	return s.resolveSubList(ctx, subName, []string{subName}, subByName)
}

func (s *Store) resolveSubList(ctx context.Context, bundleName string, names []string, subByName map[string]map[string]any) (*ResolvedBundle, error) {
	var allURIs []string
	var allNodes []model.Node
	seenURIs := make(map[string]bool)
	seenNodeFP := make(map[string]bool)
	usedTags := make(map[string]int)

	for _, name := range names {
		sub, ok := subByName[name]
		if !ok || !subEnabled(sub) {
			continue
		}

		srcType, _ := sub["source"].(string)
		rawURL, _ := sub["url"].(string)
		content, _ := sub["content"].(string)

		var payload string
		if srcType == "remote" || (srcType == "" && strings.TrimSpace(rawURL) != "") {
			uaStrategy, proxyMode := subFetchOptions(sub)
			body, err := s.fetchRemoteAdaptive(ctx, strings.TrimSpace(rawURL), uaStrategy, proxyMode, false)
			if err != nil {
				continue
			}
			payload = body
		} else {
			payload = content
		}

		if strings.TrimSpace(payload) == "" {
			continue
		}

		nodes, uris := ParseRawSubscriptionPayload(ctx, []byte(payload))
		for _, u := range uris {
			if !seenURIs[u] {
				seenURIs[u] = true
				allURIs = append(allURIs, u)
			}
		}
		for _, node := range nodes {
			fp := nodeFingerprint(node)
			if seenNodeFP[fp] {
				continue
			}
			seenNodeFP[fp] = true

			baseTag := cmp.Or(strings.TrimSpace(node.Tag), fmt.Sprintf("%s-%s-%d", node.Type, node.Addr, node.Port))
			if count := usedTags[baseTag]; count > 0 {
				node.Tag = fmt.Sprintf("%s_%d", baseTag, count)
			} else {
				node.Tag = baseTag
			}
			usedTags[baseTag]++
			allNodes = append(allNodes, node)

			if synth := NodeToURI(node); synth != "" && len(uris) == 0 && !seenURIs[synth] {
				seenURIs[synth] = true
				allURIs = append(allURIs, synth)
			}
		}
	}

	return &ResolvedBundle{
		Name:  bundleName,
		URIs:  allURIs,
		Nodes: allNodes,
	}, nil
}

func nodeFingerprint(n model.Node) string {
	cp := n
	cp.ID = ""
	cp.Tag = ""
	b, _ := json.Marshal(cp)
	return string(b)
}
