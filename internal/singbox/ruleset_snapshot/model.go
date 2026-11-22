// 文件职责：定义内置规则集快照的清单模型、标签检索与镜像前缀剥离纯函数。
package ruleset_snapshot

import (
	"slices"
	"strings"
)

type snapshotEntry struct {
	URL    string `json:"url"`
	Format string `json:"format"`
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type snapshotManifest struct {
	GeneratedAt string                   `json:"generated_at"`
	Count       int                      `json:"count"`
	Entries     map[string]snapshotEntry `json:"entries"`
}

// Snapshot 已加载的内置快照。
type Snapshot struct {
	manifest snapshotManifest
}

// Count 快照中的规则集数量。
func (s *Snapshot) Count() int { return len(s.manifest.Entries) }

// GeneratedAt 快照生成时间（RFC3339，可能为空）。
func (s *Snapshot) GeneratedAt() string { return s.manifest.GeneratedAt }

// EntrySize 返回指定规则集 tag 在快照清单中的解压后字节数。
func (s *Snapshot) EntrySize(tag string) (int64, bool) {
	e, ok := s.manifest.Entries[tag]
	if !ok {
		return 0, false
	}
	return e.Size, true
}

// Tags 返回快照包含的所有 tag（字典序）。
func (s *Snapshot) Tags() []string {
	tags := make([]string, 0, len(s.manifest.Entries))
	for tag := range s.manifest.Entries {
		tags = append(tags, tag)
	}
	slices.Sort(tags)
	return tags
}

// Lookup 按 tag 或 URL 查找快照条目，返回清单中实际命中的 tag（供 Extract
// 使用）、规范直连 URL 与格式。URL 匹配时会忽略镜像前缀。
func (s *Snapshot) Lookup(tag, url string) (matchedTag, canonicalURL, format string, ok bool) {
	if e, exists := s.manifest.Entries[tag]; exists {
		return tag, e.URL, e.Format, true
	}
	if url == "" {
		return "", "", "", false
	}
	bare := stripMirrorPrefix(url)
	for key, e := range s.manifest.Entries {
		if e.URL == url || e.URL == bare {
			return key, e.URL, e.Format, true
		}
	}
	return "", "", "", false
}

// stripMirrorPrefix 剥离常见的 "https://mirror/https://github.com/..." 形式
// 镜像前缀，得到规范直连 URL。
func stripMirrorPrefix(u string) string {
	if i := strings.LastIndex(u, "https://"); i > 0 {
		return u[i:]
	}
	return u
}
