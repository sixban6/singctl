//go:build !lite

// Package ruleset_snapshot 提供编译期内置的规则集兜底快照。
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
)

//go:embed assets
var assetsFS embed.FS

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
