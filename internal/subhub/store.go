// 文件职责：负责 SubHub 本地/远程订阅源目录（sub-store.json）的 mtime 内存缓存读取、CRUD 变更、集合聚合解析与订阅路径密钥（key）管理。
//
// 架构设计原则：
//   - 高内聚拆文件：强类型文档模型与节点合并下沉至 store_doc.go，网络自适应抓取与 SSRF 校验下沉至 remote_fetcher.go，
//     多格式节点解析与链路归一化下沉至 payload_decoder.go，本文件聚焦持久化仓储状态、并发锁保护与集合合并去重。
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
	MaxRemoteSubBytes     = 8 * 1024 * 1024 // 8 MiB
	maxRemoteSubBytes     = MaxRemoteSubBytes

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

// SyncServerNodesInput describes the auto-generated local server nodes to synchronize into sub-store.json.
type SyncServerNodesInput struct {
	NodeDomain string
	Hy2URI     string
	Hy2Tag     string
	VlessURI   string
	VrTag      string
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
	cachedDoc        *subStoreDoc
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

func (s *Store) readDocLocked() (*subStoreDoc, error) {
	st, err := os.Stat(s.FilePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return newEmptySubStoreDoc(), nil
		}
		return nil, err
	}

	if s.cachedDoc != nil && st.ModTime().Equal(s.cachedMtime) && st.Size() == s.cachedSize {
		return s.cachedDoc.Clone(), nil
	}

	raw, err := os.ReadFile(s.FilePath)
	if err != nil {
		return nil, err
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		doc := newEmptySubStoreDoc()
		s.cachedDoc = doc
		s.cachedMtime = st.ModTime()
		s.cachedSize = st.Size()
		return doc.Clone(), nil
	}

	var doc subStoreDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parse %s: %w", s.FilePath, err)
	}
	s.cachedDoc = &doc
	s.cachedMtime = st.ModTime()
	s.cachedSize = st.Size()
	return doc.Clone(), nil
}

func (s *Store) writeDocLocked(doc *subStoreDoc) error {
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
	_ = os.Chmod(tmp, mode)
	if err := os.Rename(tmp, s.FilePath); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename %s: %w", s.FilePath, err)
	}
	if st, err := os.Stat(s.FilePath); err == nil {
		s.cachedDoc = doc.Clone()
		s.cachedMtime = st.ModTime()
		s.cachedSize = st.Size()
	}
	return nil
}

// SyncAutoServerNodes synchronizes auto_generated_hy2 and auto_generated_vless into sub-store.json
// using strongly-typed document persistence (preserving nodes from other VPSs, cleaning deprecated entries,
// and eliminating cross-package map[string]any dual-writes).
func (s *Store) SyncAutoServerNodes(in SyncServerNodesInput) error {
	if strings.TrimSpace(s.FilePath) == "" {
		return errors.New("sub-store file path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(s.FilePath), 0700); err != nil {
		return fmt.Errorf("create sub-store directory: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if existingBytes, err := os.ReadFile(s.FilePath); err == nil && len(existingBytes) > 0 {
		bakPath := s.FilePath + ".bak"
		if bErr := os.WriteFile(bakPath, existingBytes, 0600); bErr == nil {
			_ = os.Chmod(bakPath, 0600)
		}
	}

	doc, err := s.readDocLocked()
	if err != nil {
		// Recover cleanly from corrupted legacy files during server deploy
		doc = newEmptySubStoreDoc()
	}

	upsertAutoSub := func(targetName, displayName, uri, remark, tag, scheme string) {
		idx := slices.IndexFunc(doc.Subs, func(r subRecord) bool { return r.Name == targetName })
		if idx >= 0 {
			doc.Subs[idx].Content = MergeServerNodeContent(doc.Subs[idx].Content, uri, in.NodeDomain, tag, scheme)
			doc.Subs[idx].DisplayName = displayName
			doc.Subs[idx].Source = cmp.Or(doc.Subs[idx].Source, "local")
			return
		}
		doc.Subs = append(doc.Subs, subRecord{
			Name:        targetName,
			DisplayName: displayName,
			Source:      "local",
			Content:     strings.TrimSpace(uri),
			Remark:      remark,
		})
	}

	upsertAutoSub("auto_generated_hy2", "Hysteria2 Auto", in.Hy2URI, "Auto-generated Hysteria 2 Subscription", in.Hy2Tag, "hysteria2")
	upsertAutoSub("auto_generated_vless", "VLESS Reality Auto", in.VlessURI, "Auto-generated VLESS+Reality Subscription", in.VrTag, "vless")

	cleanedSubs := make([]subRecord, 0, len(doc.Subs))
	seenSubNames := make(map[string]bool, len(doc.Subs))
	for _, sub := range doc.Subs {
		if sub.Name == "auto_generated_tuic" || sub.Name == "auto_generated_anytls" {
			continue
		}
		if sub.Name != "" {
			if seenSubNames[sub.Name] {
				continue
			}
			seenSubNames[sub.Name] = true
		}
		cleanedSubs = append(cleanedSubs, sub)
	}
	doc.Subs = cleanedSubs

	doc.Collections = ReconcileAllCollection(doc.Collections, []string{"auto_generated_hy2", "auto_generated_vless"})
	for i := range doc.Collections {
		kept := make([]string, 0, len(doc.Collections[i].Subscriptions))
		for _, sn := range doc.Collections[i].Subscriptions {
			if seenSubNames[sn] && !slices.Contains(kept, sn) {
				kept = append(kept, sn)
			}
		}
		doc.Collections[i].Subscriptions = kept
	}

	return s.writeDocLocked(doc)
}

func recordToSourceItem(sub subRecord, cache remoteCacheEntry) SourceItem {
	srcType := sub.effectiveSourceType()
	item := SourceItem{
		Name:        sub.Name,
		DisplayName: cmp.Or(sub.DisplayName, sub.Name),
		Source:      srcType,
		URL:         sub.URL,
		Content:     sub.Content,
		Remark:      sub.Remark,
		Enabled:     sub.isEnabled(),
		AutoManaged: isAutoManagedName(sub.Name),
	}

	if srcType == "remote" {
		uaStrategy, proxyMode := sub.fetchOptions()
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
	} else if strings.TrimSpace(sub.Content) != "" {
		nodes, uris := ParseRawSubscriptionPayload(context.Background(), []byte(sub.Content))
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

	items := make([]SourceItem, 0, len(doc.Subs))
	for _, sub := range doc.Subs {
		items = append(items, recordToSourceItem(sub, cacheSnapshot[strings.TrimSpace(sub.URL)]))
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
	if isAutoManagedName(name) && !in.AllowAutoManaged && strings.TrimSpace(in.Source) == "remote" {
		return nil, errors.New("系统自动同步节点源不支持改为远程 URL 类型")
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

	var updatedSub subRecord
	idx := slices.IndexFunc(doc.Subs, func(r subRecord) bool { return r.Name == name })
	if idx >= 0 {
		existing := doc.Subs[idx]
		if displayName != "" {
			existing.DisplayName = displayName
		}
		existing.Source = srcType
		if srcType == "remote" {
			existing.URL = rawURL
			existing.Content = ""
			existing.UserAgent = uaStrategy
			existing.ProxyMode = proxyMode
			if strings.EqualFold(uaStrategy, "auto") {
				existing.LegacyUA = ""
			}
		} else {
			existing.URL = ""
			if content != "" || !isAutoManagedName(name) {
				existing.Content = content
			}
		}
		if in.Remark != "" || !isAutoManagedName(name) {
			existing.Remark = strings.TrimSpace(in.Remark)
		}
		existing.Enabled = new(enabled)
		doc.Subs[idx] = existing
		updatedSub = existing
	} else {
		updatedSub = subRecord{
			Name:        name,
			DisplayName: cmp.Or(displayName, name),
			Source:      srcType,
			URL:         rawURL,
			Content:     content,
			Remark:      strings.TrimSpace(in.Remark),
			Enabled:     new(enabled),
		}
		if srcType == "remote" {
			updatedSub.UserAgent = uaStrategy
			updatedSub.ProxyMode = proxyMode
		}
		doc.Subs = append(doc.Subs, updatedSub)
	}
	ensureInAllCollection(doc, name)

	if err := s.writeDocLocked(doc); err != nil {
		return nil, err
	}

	var cacheEntry remoteCacheEntry
	if rawURL != "" {
		cacheEntry = s.remoteCache[rawURL]
	}
	item := recordToSourceItem(updatedSub, cacheEntry)
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

	beforeLen := len(doc.Subs)
	doc.Subs = slices.DeleteFunc(doc.Subs, func(r subRecord) bool { return r.Name == name })
	if len(doc.Subs) == beforeLen {
		return fmt.Errorf("未找到名为 %q 的订阅源", name)
	}

	for i := range doc.Collections {
		doc.Collections[i].Subscriptions = slices.DeleteFunc(doc.Collections[i].Subscriptions, func(sn string) bool {
			return sn == name
		})
	}
	return s.writeDocLocked(doc)
}

func ensureInAllCollection(doc *subStoreDoc, subName string) {
	for i := range doc.Collections {
		if doc.Collections[i].Name == DefaultCollectionName {
			if !slices.Contains(doc.Collections[i].Subscriptions, subName) {
				doc.Collections[i].Subscriptions = append(doc.Collections[i].Subscriptions, subName)
			}
			return
		}
	}
	doc.Collections = append(doc.Collections, collectionRecord{
		Name:          DefaultCollectionName,
		DisplayName:   DefaultCollectionName,
		Subscriptions: []string{subName},
	})
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

	subByName := make(map[string]subRecord, len(doc.Subs))
	orderedNames := make([]string, 0, len(doc.Subs))
	for _, sub := range doc.Subs {
		if sub.Name != "" {
			subByName[sub.Name] = sub
			orderedNames = append(orderedNames, sub.Name)
		}
	}

	var targetSubNames []string
	foundCol := false
	for _, col := range doc.Collections {
		if strings.EqualFold(col.Name, collectionName) {
			foundCol = true
			for _, sn := range col.Subscriptions {
				if sn != "" {
					targetSubNames = append(targetSubNames, sn)
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

	subByName := make(map[string]subRecord, len(doc.Subs))
	for _, sub := range doc.Subs {
		if sub.Name != "" {
			subByName[sub.Name] = sub
		}
	}
	if _, ok := subByName[subName]; !ok {
		return nil, fmt.Errorf("subscription %q not found", subName)
	}
	return s.resolveSubList(ctx, subName, []string{subName}, subByName)
}

func (s *Store) resolveSubList(ctx context.Context, bundleName string, names []string, subByName map[string]subRecord) (*ResolvedBundle, error) {
	var allURIs []string
	var allNodes []model.Node
	seenURIs := make(map[string]bool)
	seenNodeFP := make(map[string]bool)
	usedTags := make(map[string]int)

	for _, name := range names {
		sub, ok := subByName[name]
		if !ok || !sub.isEnabled() {
			continue
		}

		var payload string
		if sub.effectiveSourceType() == "remote" {
			uaStrategy, proxyMode := sub.fetchOptions()
			body, err := s.fetchRemoteAdaptive(ctx, strings.TrimSpace(sub.URL), uaStrategy, proxyMode, false)
			if err != nil {
				continue
			}
			payload = body
		} else {
			payload = sub.Content
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
