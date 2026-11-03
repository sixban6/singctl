package subhub

import (
	"cmp"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"singctl/internal/constant"

	"github.com/sixban6/singgen/pkg/model"
	"github.com/sixban6/singgen/pkg/singgen"
	"gopkg.in/yaml.v3"
)

const (
	DefaultCollectionName = "all"
	maxRemoteSubBytes     = 8 * 1024 * 1024 // 8 MiB
)

var slugSanitizeRe = regexp.MustCompile(`[^a-zA-Z0-9_-]+`)

// SourceItem describes a single subscription source managed by SubHub.
type SourceItem struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	Source      string `json:"source"` // "local" or "remote"
	URL         string `json:"url"`
	Content     string `json:"content"`
	Remark      string `json:"remark"`
	Enabled     bool   `json:"enabled"`
	AutoManaged bool   `json:"autoManaged"`
	NodeCount   int    `json:"nodeCount"`
}

// SourceUpsertInput is the payload for creating or updating a subscription source.
type SourceUpsertInput struct {
	Name             string `json:"name"`
	DisplayName      string `json:"displayName"`
	Source           string `json:"source"` // "local" or "remote"
	URL              string `json:"url"`
	Content          string `json:"content"`
	Remark           string `json:"remark"`
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
	URL       string    `json:"url"`
	Body      string    `json:"body"`
	FetchedAt time.Time `json:"fetchedAt"`
}

// Store manages subscription persistence, mtime caching, and remote subscription fetching.
type Store struct {
	DataDir             string
	FilePath            string
	AllowLoopbackRemote bool
	HTTPTimeout         time.Duration
	CacheTTL            time.Duration

	mu          sync.RWMutex
	cachedMtime time.Time
	cachedSize  int64
	cachedDoc   map[string]any
	remoteCache map[string]remoteCacheEntry
}

// NewStore creates a Store backed by dir and filePath (defaulting to constant.SubStoreDir/SubStoreFile).
func NewStore(dir, filePath string) *Store {
	d := cmp.Or(strings.TrimSpace(dir), constant.SubStoreDir)
	f := cmp.Or(strings.TrimSpace(filePath), constant.SubStoreFile)
	if dir != "" && filePath == "" {
		f = filepath.Join(d, "sub-store.json")
	}
	s := &Store{
		DataDir:     d,
		FilePath:    f,
		HTTPTimeout: 12 * time.Second,
		CacheTTL:    10 * time.Minute,
		remoteCache: make(map[string]remoteCacheEntry),
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
	if err := os.MkdirAll(s.DataDir, 0755); err != nil {
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
	if err := os.Rename(tmp, s.keyFilePath()); err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("commit key file: %w", err)
	}
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
	if err := os.MkdirAll(filepath.Dir(s.FilePath), 0755); err != nil {
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

func mapToSourceItem(sub map[string]any, cachedBody string) SourceItem {
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

	var count int
	if srcType == "remote" {
		if cachedBody != "" {
			nodes, uris := ParseRawSubscriptionPayload(context.Background(), []byte(cachedBody))
			count = max(len(nodes), len(uris))
		}
	} else if strings.TrimSpace(content) != "" {
		nodes, uris := ParseRawSubscriptionPayload(context.Background(), []byte(content))
		count = max(len(nodes), len(uris))
	}

	return SourceItem{
		Name:        name,
		DisplayName: displayName,
		Source:      srcType,
		URL:         rawURL,
		Content:     content,
		Remark:      remark,
		Enabled:     subEnabled(sub),
		AutoManaged: isAutoManagedName(name),
		NodeCount:   count,
	}
}

// ListSources returns all subscription sources configured in sub-store.json.
func (s *Store) ListSources() ([]SourceItem, error) {
	s.mu.Lock()
	doc, err := s.readDocLocked()
	var remoteBodies map[string]string
	if err == nil {
		remoteBodies = make(map[string]string, len(s.remoteCache))
		for k, v := range s.remoteCache {
			remoteBodies[k] = v.Body
		}
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
		items = append(items, mapToSourceItem(sub, remoteBodies[strings.TrimSpace(u)]))
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
		// Allow toggling enabled or updating remark on auto-managed sources, but not overwriting protocol URIs arbitrarily unless content is provided intentionally
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

	var prefetchedBody string
	if srcType == "remote" {
		if err := s.validateRemoteURL(rawURL); err != nil {
			return nil, err
		}
		if enabled {
			body, err := s.fetchRemoteBody(ctx, rawURL, true)
			if err != nil {
				return nil, fmt.Errorf("拉取远程订阅验证失败: %w", err)
			}
			nodes, uris := ParseRawSubscriptionPayload(ctx, []byte(body))
			if len(nodes) == 0 && len(uris) == 0 {
				return nil, errors.New("远程订阅内容未解析出任何有效代理节点")
			}
			prefetchedBody = body
		}
	} else {
		if content == "" && (!isAutoManagedName(name) || in.Enabled == nil) {
			return nil, errors.New("本地节点内容不能为空（请输入 vless://、hysteria2:// 等节点链接）")
		}
		if content != "" {
			nodes, uris := ParseRawSubscriptionPayload(ctx, []byte(content))
			if len(nodes) == 0 && len(uris) == 0 {
				return nil, errors.New("未识别到有效的代理节点链接（支持 vless/hysteria2/trojan/vmess/ss/tuic/anytls、Base64 或 Clash YAML）")
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
		rawSubs = append(rawSubs, updatedSub)
	}
	doc["subs"] = rawSubs
	ensureInAllCollection(doc, name)

	if err := s.writeDocLocked(doc); err != nil {
		return nil, err
	}

	if prefetchedBody == "" && rawURL != "" {
		prefetchedBody = s.remoteCache[rawURL].Body
	}
	item := mapToSourceItem(updatedSub, prefetchedBody)
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
			body, err := s.fetchRemoteBody(ctx, strings.TrimSpace(rawURL), false)
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

func (s *Store) validateRemoteURL(rawURL string) error {
	if rawURL == "" {
		return errors.New("远程订阅 URL 不能为空")
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("无效的订阅 URL: %w", err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return errors.New("远程订阅仅支持 http:// 或 https:// 协议")
	}
	host := strings.TrimSpace(u.Hostname())
	if host == "" {
		return errors.New("远程订阅 URL 缺少主机名")
	}
	if !s.AllowLoopbackRemote {
		if strings.EqualFold(host, "localhost") {
			return errors.New("安全策略禁止拉取本机回环地址 (localhost)")
		}
		if addr, err := netip.ParseAddr(host); err == nil && isBlockedRemoteAddr(addr) {
			return fmt.Errorf("安全策略禁止拉取私网或回环地址 (%s)", host)
		}
	}
	return nil
}

func isBlockedRemoteAddr(addr netip.Addr) bool {
	addr = addr.Unmap()
	if addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsMulticast() || addr.IsUnspecified() {
		return true
	}
	// Block CGNAT / Tailscale 100.64.0.0/10
	if cgnat, err := netip.ParsePrefix("100.64.0.0/10"); err == nil && cgnat.Contains(addr) {
		return true
	}
	return false
}

func (s *Store) newSafeHTTPClient() *http.Client {
	timeout := cmp.Or(s.HTTPTimeout, 12*time.Second)
	dialer := &net.Dialer{
		Timeout:   8 * time.Second,
		KeepAlive: 15 * time.Second,
	}
	if !s.AllowLoopbackRemote {
		dialer.Control = func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			addr, err := netip.ParseAddr(host)
			if err != nil {
				return err
			}
			if isBlockedRemoteAddr(addr) {
				return fmt.Errorf("blocked SSRF connection to non-public IP %s", addr)
			}
			return nil
		}
	}

	transport := &http.Transport{
		DialContext:           dialer.DialContext,
		TLSHandshakeTimeout:   8 * time.Second,
		ResponseHeaderTimeout: timeout,
		MaxIdleConns:          10,
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			return s.validateRemoteURL(req.URL.String())
		},
	}
}

func (s *Store) fetchRemoteBody(ctx context.Context, rawURL string, forceRefresh bool) (string, error) {
	if err := s.validateRemoteURL(rawURL); err != nil {
		return "", err
	}

	ttl := cmp.Or(s.CacheTTL, 10*time.Minute)
	s.mu.RLock()
	cached, hasCached := s.remoteCache[rawURL]
	s.mu.RUnlock()

	if !forceRefresh && hasCached && cached.Body != "" && time.Since(cached.FetchedAt) < ttl {
		return cached.Body, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		if hasCached && cached.Body != "" {
			return cached.Body, nil
		}
		return "", err
	}
	req.Header.Set("User-Agent", "singctl-subhub/1.0 (Clash.Meta; Mihomo; sing-box)")
	req.Header.Set("Accept", "*/*")

	resp, err := s.newSafeHTTPClient().Do(req)
	if err != nil {
		if hasCached && cached.Body != "" {
			return cached.Body, nil
		}
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if hasCached && cached.Body != "" {
			return cached.Body, nil
		}
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	rawBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxRemoteSubBytes))
	if err != nil {
		if hasCached && cached.Body != "" {
			return cached.Body, nil
		}
		return "", err
	}

	body := strings.TrimSpace(string(rawBytes))
	if body == "" {
		if hasCached && cached.Body != "" {
			return cached.Body, nil
		}
		return "", errors.New("empty response body")
	}

	s.mu.Lock()
	s.remoteCache[rawURL] = remoteCacheEntry{
		URL:       rawURL,
		Body:      body,
		FetchedAt: time.Now(),
	}
	s.saveRemoteCacheLocked()
	s.mu.Unlock()

	return body, nil
}

func (s *Store) loadRemoteCacheFromDisk() {
	raw, err := os.ReadFile(s.remoteCachePath())
	if err != nil || len(raw) == 0 {
		return
	}
	var entries map[string]remoteCacheEntry
	if err := json.Unmarshal(raw, &entries); err == nil && entries != nil {
		s.remoteCache = entries
	}
}

func (s *Store) saveRemoteCacheLocked() {
	if s.DataDir == "" {
		return
	}
	_ = os.MkdirAll(s.DataDir, 0755)
	if b, err := json.Marshal(s.remoteCache); err == nil {
		_ = os.WriteFile(s.remoteCachePath(), b, 0600)
	}
}

var supportedURISchemes = []string{
	"vless://",
	"vmess://",
	"trojan://",
	"hysteria2://",
	"hy2://",
	"ss://",
	"tuic://",
	"anytls://",
}

func hasSupportedScheme(line string) bool {
	lower := strings.ToLower(strings.TrimSpace(line))
	for _, p := range supportedURISchemes {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	return false
}

func decodeBase64Flexible(s string) (string, bool) {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" || strings.Contains(trimmed, "://") || strings.Contains(trimmed, "proxies:") {
		return "", false
	}
	compact := strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, trimmed)

	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	for _, enc := range encodings {
		if b, err := enc.DecodeString(compact); err == nil && len(b) > 0 {
			decoded := string(b)
			if strings.Contains(decoded, "://") || strings.Contains(decoded, "proxies:") {
				return decoded, true
			}
		}
	}
	return "", false
}

// ParseRawSubscriptionPayload parses raw URI lists, Base64 URI blobs, or Clash YAML into nodes and canonical URIs.
func ParseRawSubscriptionPayload(ctx context.Context, raw []byte) ([]model.Node, []string) {
	text := strings.TrimSpace(string(raw))
	if text == "" {
		return nil, nil
	}
	if decoded, ok := decodeBase64Flexible(text); ok {
		text = strings.TrimSpace(decoded)
	}

	var uris []string
	for line := range strings.SplitSeq(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		l := strings.TrimSpace(line)
		if l == "" || strings.HasPrefix(l, "#") || strings.HasPrefix(l, "//") {
			continue
		}
		if hasSupportedScheme(l) {
			uris = append(uris, l)
		}
	}

	parser := singgen.NewContextParser(singgen.GenerateOptions{})
	if len(uris) > 0 {
		cleanInput := strings.Join(uris, "\n")
		nodes, err := parser.Parse(ctx, []byte(cleanInput))
		if err == nil && len(nodes) > 0 {
			return nodes, uris
		}
		// Fallback line-by-line so one malformed line never drops healthy nodes
		var lineNodes []model.Node
		for _, u := range uris {
			if n, lErr := parser.Parse(ctx, []byte(u)); lErr == nil && len(n) > 0 {
				lineNodes = append(lineNodes, n...)
			}
		}
		return lineNodes, uris
	}

	// Fallback: Clash / Mihomo YAML ("proxies:")
	if strings.Contains(text, "proxies:") {
		nodes := parseClashYAMLProxies(text)
		if len(nodes) > 0 {
			synthURIs := make([]string, 0, len(nodes))
			for _, n := range nodes {
				if u := NodeToURI(n); u != "" {
					synthURIs = append(synthURIs, u)
				}
			}
			return nodes, synthURIs
		}
	}

	return nil, nil
}

func parseClashYAMLProxies(yamlText string) []model.Node {
	var doc struct {
		Proxies []map[string]any `yaml:"proxies"`
	}
	if err := yaml.Unmarshal([]byte(yamlText), &doc); err != nil || len(doc.Proxies) == 0 {
		return nil
	}

	var nodes []model.Node
	for _, p := range doc.Proxies {
		typ := strings.ToLower(asString(p["type"]))
		name := asString(p["name"])
		server := asString(p["server"])
		port := asUint16(p["port"])
		if server == "" || port == 0 {
			continue
		}

		n := model.Node{
			Tag:   name,
			Addr:  server,
			Port:  port,
			Extra: make(map[string]any),
		}
		n.Security.SkipVerify = asBool(p["skip-cert-verify"])
		n.Security.ServerName = cmp.Or(asString(p["servername"]), asString(p["sni"]))
		if alpn, ok := p["alpn"].([]any); ok {
			for _, a := range alpn {
				if s := asString(a); s != "" {
					n.Security.ALPN = append(n.Security.ALPN, s)
				}
			}
		}
		if netType := asString(p["network"]); netType != "" {
			n.Transport.Net = netType
		}
		if wsOpts, ok := p["ws-opts"].(map[string]any); ok {
			n.Transport.Path = asString(wsOpts["path"])
			if hdrs, ok := wsOpts["headers"].(map[string]any); ok {
				n.Transport.Host = asString(hdrs["Host"])
			}
		}

		switch typ {
		case "vless":
			n.Type = "vless"
			n.UUID = asString(p["uuid"])
			n.Security.TLS = asBool(p["tls"])
			if flow := asString(p["flow"]); flow != "" {
				n.Extra["flow"] = flow
			}
			if fp := asString(p["client-fingerprint"]); fp != "" {
				n.Extra["fingerprint"] = fp
			}
			if ro, ok := p["reality-opts"].(map[string]any); ok {
				n.Security.TLS = true
				n.Extra["security"] = "reality"
				n.Extra["public_key"] = asString(ro["public-key"])
				n.Extra["short_id"] = asString(ro["short-id"])
			}
		case "hysteria2":
			n.Type = "hysteria2"
			n.Password = asString(p["password"])
			n.Security.TLS = true
			if obfs := asString(p["obfs"]); obfs != "" {
				n.Extra["obfs"] = map[string]string{
					"type":     obfs,
					"password": asString(p["obfs-password"]),
				}
			}
		case "trojan":
			n.Type = "trojan"
			n.Password = asString(p["password"])
			n.Security.TLS = true
		case "ss":
			n.Type = "shadowsocks"
			n.Password = asString(p["password"])
			n.Extra["method"] = asString(p["cipher"])
		case "vmess":
			n.Type = "vmess"
			n.UUID = asString(p["uuid"])
			n.Security.TLS = asBool(p["tls"])
		case "tuic":
			n.Type = "tuic"
			n.UUID = asString(p["uuid"])
			n.Password = asString(p["password"])
			n.Security.TLS = true
		case "anytls":
			n.Type = "anytls"
			n.Password = asString(p["password"])
			n.Security.TLS = true
		default:
			continue
		}
		nodes = append(nodes, n)
	}
	return nodes
}

func asString(v any) string {
	switch x := v.(type) {
	case string:
		return strings.TrimSpace(x)
	case int:
		return strconv.Itoa(x)
	case int64:
		return strconv.FormatInt(x, 10)
	case float64:
		return strconv.Itoa(int(x))
	default:
		return ""
	}
}

func asUint16(v any) uint16 {
	switch x := v.(type) {
	case int:
		if x > 0 && x <= 65535 {
			return uint16(x)
		}
	case int64:
		if x > 0 && x <= 65535 {
			return uint16(x)
		}
	case float64:
		if x > 0 && x <= 65535 {
			return uint16(x)
		}
	case string:
		if p, err := strconv.Atoi(strings.TrimSpace(x)); err == nil && p > 0 && p <= 65535 {
			return uint16(p)
		}
	}
	return 0
}

func asBool(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return strings.EqualFold(x, "true") || x == "1"
	default:
		return false
	}
}
