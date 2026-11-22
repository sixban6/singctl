// 文件职责：定义 SubHub 持久化文档（subStoreDoc / subRecord / collectionRecord）的强类型保真编解码、零序列化深拷贝与本机自动节点同步。
package subhub

import (
	"bytes"
	"cmp"
	"encoding/json"
	"net/url"
	"slices"
	"strings"
)

// subStoreDoc 表示 /etc/sub-store/sub-store.json 的强类型根模型，未知顶层字段保存在 Extra 中。
type subStoreDoc struct {
	Subs        []subRecord                `json:"subs"`
	Collections []collectionRecord         `json:"collections"`
	Extra       map[string]json.RawMessage `json:"-"`
}

var knownSubStoreDocKeys = map[string]bool{"subs": true, "collections": true}

func newEmptySubStoreDoc() *subStoreDoc {
	return &subStoreDoc{
		Subs:        []subRecord{},
		Collections: []collectionRecord{},
	}
}

func (d *subStoreDoc) UnmarshalJSON(data []byte) error {
	var typed struct {
		Subs        []subRecord        `json:"subs"`
		Collections []collectionRecord `json:"collections"`
	}
	if err := json.Unmarshal(data, &typed); err != nil {
		return err
	}
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(data, &rawMap); err != nil {
		return err
	}
	for k := range knownSubStoreDocKeys {
		delete(rawMap, k)
	}
	d.Subs = typed.Subs
	if d.Subs == nil {
		d.Subs = []subRecord{}
	}
	d.Collections = typed.Collections
	if d.Collections == nil {
		d.Collections = []collectionRecord{}
	}
	if len(rawMap) > 0 {
		d.Extra = rawMap
	} else {
		d.Extra = nil
	}
	return nil
}

func (d subStoreDoc) MarshalJSON() ([]byte, error) {
	subs := d.Subs
	if subs == nil {
		subs = []subRecord{}
	}
	cols := d.Collections
	if cols == nil {
		cols = []collectionRecord{}
	}
	baseBytes, err := json.Marshal(struct {
		Subs        []subRecord        `json:"subs"`
		Collections []collectionRecord `json:"collections"`
	}{
		Subs:        subs,
		Collections: cols,
	})
	if err != nil {
		return nil, err
	}
	if len(d.Extra) == 0 {
		return baseBytes, nil
	}
	var merged map[string]json.RawMessage
	if err := json.Unmarshal(baseBytes, &merged); err != nil {
		return nil, err
	}
	for k, v := range d.Extra {
		if !knownSubStoreDocKeys[k] && len(v) > 0 {
			merged[k] = v
		}
	}
	return json.Marshal(merged)
}

// Clone 零序列化深拷贝整个 subStoreDoc。
func (d *subStoreDoc) Clone() *subStoreDoc {
	if d == nil {
		return newEmptySubStoreDoc()
	}
	out := &subStoreDoc{
		Subs:        make([]subRecord, len(d.Subs)),
		Collections: make([]collectionRecord, len(d.Collections)),
		Extra:       cloneRawMessages(d.Extra),
	}
	for i := range d.Subs {
		out.Subs[i] = d.Subs[i].Clone()
	}
	for i := range d.Collections {
		out.Collections[i] = d.Collections[i].Clone()
	}
	return out
}

// subRecord 描述单条本地或远程订阅源记录，单点输出标准 displayName 并自动吸收历史遗留的 display-name。
type subRecord struct {
	Name        string                     `json:"name"`
	DisplayName string                     `json:"displayName,omitempty"`
	Source      string                     `json:"source,omitempty"`
	URL         string                     `json:"url"`
	Content     string                     `json:"content"`
	Remark      string                     `json:"remark,omitempty"`
	Enabled     *bool                      `json:"enabled,omitempty"`
	UserAgent   string                     `json:"userAgent,omitempty"`
	LegacyUA    string                     `json:"ua,omitempty"`
	ProxyMode   string                     `json:"proxyMode,omitempty"`
	Extra       map[string]json.RawMessage `json:"-"`
}

var knownSubRecordKeys = map[string]bool{
	"name": true, "displayName": true, "display-name": true,
	"source": true, "url": true, "content": true, "remark": true,
	"enabled": true, "userAgent": true, "ua": true, "proxyMode": true,
}

func (r *subRecord) UnmarshalJSON(data []byte) error {
	var aux struct {
		Name              string `json:"name"`
		DisplayName       string `json:"displayName"`
		LegacyDisplayName string `json:"display-name"`
		Source            string `json:"source"`
		URL               string `json:"url"`
		Content           string `json:"content"`
		Remark            string `json:"remark"`
		Enabled           *bool  `json:"enabled"`
		UserAgent         string `json:"userAgent"`
		LegacyUA          string `json:"ua"`
		ProxyMode         string `json:"proxyMode"`
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(data, &rawMap); err != nil {
		return err
	}
	for k := range knownSubRecordKeys {
		delete(rawMap, k)
	}
	*r = subRecord{
		Name:        aux.Name,
		DisplayName: cmp.Or(aux.DisplayName, aux.LegacyDisplayName),
		Source:      aux.Source,
		URL:         aux.URL,
		Content:     aux.Content,
		Remark:      aux.Remark,
		Enabled:     aux.Enabled,
		UserAgent:   aux.UserAgent,
		LegacyUA:    aux.LegacyUA,
		ProxyMode:   aux.ProxyMode,
	}
	if len(rawMap) > 0 {
		r.Extra = rawMap
	}
	return nil
}

func (r subRecord) MarshalJSON() ([]byte, error) {
	type plain subRecord
	baseBytes, err := json.Marshal(plain(r))
	if err != nil {
		return nil, err
	}
	if len(r.Extra) == 0 {
		return baseBytes, nil
	}
	var merged map[string]json.RawMessage
	if err := json.Unmarshal(baseBytes, &merged); err != nil {
		return nil, err
	}
	for k, v := range r.Extra {
		if !knownSubRecordKeys[k] && len(v) > 0 {
			merged[k] = v
		}
	}
	return json.Marshal(merged)
}

func (r subRecord) Clone() subRecord {
	cp := r
	if r.Enabled != nil {
		cp.Enabled = new(*r.Enabled)
	}
	cp.Extra = cloneRawMessages(r.Extra)
	return cp
}

func (r subRecord) isEnabled() bool {
	return r.Enabled == nil || *r.Enabled
}

func (r subRecord) effectiveSourceType() string {
	if r.Source != "" {
		return r.Source
	}
	if strings.TrimSpace(r.URL) != "" {
		return "remote"
	}
	return "local"
}

func (r subRecord) fetchOptions() (uaStrategy, proxyMode string) {
	ua := strings.TrimSpace(r.UserAgent)
	if ua == "" && strings.TrimSpace(r.LegacyUA) != "" {
		if !strings.Contains(strings.ToLower(r.LegacyUA), "mozilla/") {
			ua = strings.TrimSpace(r.LegacyUA)
		}
	}
	return cmp.Or(ua, "auto"), normalizeProxyMode(r.ProxyMode)
}

// collectionRecord 描述聚合订阅集合（如 "all"）。
type collectionRecord struct {
	Name          string                     `json:"name"`
	DisplayName   string                     `json:"displayName,omitempty"`
	Subscriptions []string                   `json:"subscriptions"`
	Extra         map[string]json.RawMessage `json:"-"`
}

var knownCollectionKeys = map[string]bool{
	"name": true, "displayName": true, "subscriptions": true, "subs": true,
}

func (c *collectionRecord) UnmarshalJSON(data []byte) error {
	var aux struct {
		Name          string   `json:"name"`
		DisplayName   string   `json:"displayName"`
		Subscriptions []string `json:"subscriptions"`
		LegacySubs    []string `json:"subs"`
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(data, &rawMap); err != nil {
		return err
	}
	for k := range knownCollectionKeys {
		delete(rawMap, k)
	}
	subs := aux.Subscriptions
	if len(subs) == 0 && len(aux.LegacySubs) > 0 {
		subs = aux.LegacySubs
	}
	if subs == nil {
		subs = []string{}
	}
	*c = collectionRecord{
		Name:          aux.Name,
		DisplayName:   aux.DisplayName,
		Subscriptions: subs,
	}
	if len(rawMap) > 0 {
		c.Extra = rawMap
	}
	return nil
}

func (c collectionRecord) MarshalJSON() ([]byte, error) {
	cp := c
	if cp.Subscriptions == nil {
		cp.Subscriptions = []string{}
	}
	type plain collectionRecord
	baseBytes, err := json.Marshal(plain(cp))
	if err != nil {
		return nil, err
	}
	if len(c.Extra) == 0 {
		return baseBytes, nil
	}
	var merged map[string]json.RawMessage
	if err := json.Unmarshal(baseBytes, &merged); err != nil {
		return nil, err
	}
	for k, v := range c.Extra {
		if !knownCollectionKeys[k] && len(v) > 0 {
			merged[k] = v
		}
	}
	return json.Marshal(merged)
}

func (c collectionRecord) Clone() collectionRecord {
	cp := c
	cp.Subscriptions = slices.Clone(c.Subscriptions)
	cp.Extra = cloneRawMessages(c.Extra)
	return cp
}

func cloneRawMessages(src map[string]json.RawMessage) map[string]json.RawMessage {
	if len(src) == 0 {
		return nil
	}
	dst := make(map[string]json.RawMessage, len(src))
	for k, v := range src {
		dst[k] = bytes.Clone(v)
	}
	return dst
}

// MergeServerNodeContent 将当前 VPS 的新节点链接幂等合并至多行本地订阅内容中：
// 替换同属当前 VPS（按域名 / SNI+Tag / Tag 匹配）的旧链接，完整保留其他集群节点并严格去重。
func MergeServerNodeContent(existingContent, newURI, nodeDomain, targetTag, expectedScheme string) string {
	newURI = strings.TrimSpace(newURI)
	if newURI == "" {
		return existingContent
	}

	var resultLines []string
	replaced := false
	for rawLine := range strings.SplitSeq(strings.ReplaceAll(existingContent, "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}
		if line == newURI || isURIForServer(line, nodeDomain, targetTag, expectedScheme) {
			if !replaced {
				resultLines = append(resultLines, newURI)
				replaced = true
			}
		} else {
			resultLines = append(resultLines, line)
		}
	}
	if !replaced {
		resultLines = append(resultLines, newURI)
	}

	finalLines := make([]string, 0, len(resultLines))
	seen := make(map[string]bool, len(resultLines))
	for _, l := range resultLines {
		if !seen[l] {
			seen[l] = true
			finalLines = append(finalLines, l)
		}
	}
	return strings.Join(finalLines, "\n")
}

func isURIForServer(nodeURI, rawDomain, targetTag, expectedScheme string) bool {
	nodeURI = strings.TrimSpace(nodeURI)
	currentDomain := strings.ToLower(strings.TrimSpace(rawDomain))
	if nodeURI == "" || currentDomain == "" {
		return false
	}

	if u, err := url.Parse(nodeURI); err == nil {
		if u.Scheme != "" && expectedScheme != "" && !strings.EqualFold(u.Scheme, expectedScheme) {
			return false
		}
		if uHost := strings.ToLower(u.Hostname()); uHost != "" {
			if uHost == currentDomain {
				return true
			}
			if strings.ToLower(u.Query().Get("sni")) == currentDomain && targetTag != "" && u.Fragment == targetTag {
				return true
			}
		}
		if targetTag != "" && u.Fragment == targetTag {
			return true
		}
	}

	lower := strings.ToLower(nodeURI)
	if expectedScheme != "" && !strings.HasPrefix(lower, strings.ToLower(expectedScheme)+"://") {
		return false
	}
	if strings.Contains(lower, "@"+currentDomain+":") ||
		strings.Contains(lower, "@"+currentDomain+"/") ||
		strings.Contains(lower, "@"+currentDomain+"?") {
		return true
	}
	return targetTag != "" && (strings.HasSuffix(nodeURI, "#"+targetTag) || strings.Contains(nodeURI, "#"+targetTag+"?"))
}

// ReconcileAllCollection 清理遗留的 "Auto" 集合，并将指定订阅源名称幂等合入 "all" 集合。
func ReconcileAllCollection(cols []collectionRecord, subNames []string) []collectionRecord {
	cleaned := make([]collectionRecord, 0, len(cols)+1)
	foundAll := false
	for _, col := range cols {
		if col.Name == "Auto" {
			continue
		}
		cp := col.Clone()
		if cp.Name == DefaultCollectionName {
			foundAll = true
			for _, sn := range subNames {
				if sn != "" && !slices.Contains(cp.Subscriptions, sn) {
					cp.Subscriptions = append(cp.Subscriptions, sn)
				}
			}
		}
		cleaned = append(cleaned, cp)
	}
	if !foundAll {
		cleaned = append(cleaned, collectionRecord{
			Name:          DefaultCollectionName,
			DisplayName:   DefaultCollectionName,
			Subscriptions: slices.Clone(subNames),
		})
	}
	return cleaned
}
