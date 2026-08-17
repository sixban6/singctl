// Package ruleset_snapshot 提供编译期内置的规则集兜底快照。
//
// 快照由 cmd/snapshotgen 生成并提交到 assets/ 目录，通过 go:embed 打包进
// singctl 二进制。当"在线下载失败且本地缓存不存在"时，规则集从快照解出
// 并落盘为本地缓存文件，保证即使 GitHub 与镜像同时不可用、且从未建立过
// 缓存（例如新装机器），sing-box 依然可以启动。
//
// 快照会随规则集上游更新而过期，仅作为最终兜底：规则集变动低频，
// 稍旧的版本远优于无法启动。
package ruleset_snapshot

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

//go:embed assets
var assetsFS embed.FS

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

var loaded *Snapshot

// Load 解析内置快照清单（进程内缓存，重复调用开销可忽略）。
func Load() *Snapshot {
	if loaded != nil {
		return loaded
	}
	s := &Snapshot{}
	if data, err := assetsFS.ReadFile("assets/manifest.json"); err == nil {
		if err := json.Unmarshal(data, &s.manifest); err != nil {
			s.manifest = snapshotManifest{}
		}
	}
	loaded = s
	return s
}

// Count 快照中的规则集数量。
func (s *Snapshot) Count() int { return len(s.manifest.Entries) }

// GeneratedAt 快照生成时间（RFC3339，可能为空）。
func (s *Snapshot) GeneratedAt() string { return s.manifest.GeneratedAt }

// Tags 返回快照包含的所有 tag（字典序）。
func (s *Snapshot) Tags() []string {
	tags := make([]string, 0, len(s.manifest.Entries))
	for tag := range s.manifest.Entries {
		tags = append(tags, tag)
	}
	// sort
	for i := 1; i < len(tags); i++ {
		for j := i; j > 0 && tags[j] < tags[j-1]; j-- {
			tags[j], tags[j-1] = tags[j-1], tags[j]
		}
	}
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

// Extract 解出指定 tag 的规则集内容（gunzip + sha256 完整性校验）。
func (s *Snapshot) Extract(tag string) ([]byte, error) {
	e, ok := s.manifest.Entries[tag]
	if !ok {
		return nil, fmt.Errorf("snapshot has no ruleset %q", tag)
	}
	data, err := assetsFS.ReadFile("assets/" + e.File)
	if err != nil {
		return nil, fmt.Errorf("read embedded asset: %w", err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("gunzip %s: %w", e.File, err)
	}
	raw, err := io.ReadAll(zr)
	if err != nil {
		return nil, fmt.Errorf("gunzip %s: %w", e.File, err)
	}
	if e.SHA256 != "" {
		sum := sha256.Sum256(raw)
		if hex.EncodeToString(sum[:]) != e.SHA256 {
			return nil, fmt.Errorf("snapshot %s: sha256 mismatch", e.File)
		}
	}
	if e.Size > 0 && int64(len(raw)) != e.Size {
		return nil, fmt.Errorf("snapshot %s: size mismatch (want %d, got %d)", e.File, e.Size, len(raw))
	}
	return raw, nil
}

// stripMirrorPrefix 剥离常见的 "https://mirror/https://github.com/..." 形式
// 镜像前缀，得到规范直连 URL。取最后一个 "https://" 的位置：镜像 URL
// 形如 <mirror>/<原始URL>，原始 URL 几乎总是 https:// 开头；普通 URL 只
// 含一个 "https://"，行为不变。
func stripMirrorPrefix(u string) string {
	if i := strings.LastIndex(u, "https://"); i > 0 {
		return u[i:]
	}
	return u
}
