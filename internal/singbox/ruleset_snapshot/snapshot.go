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
	"os"
	"path/filepath"
	"sync"
)

//go:embed assets
var assetsFS embed.FS

// IsLite 标识当前二进制是否为不含内嵌规则集快照的轻量构建。
const IsLite = false

// 32KB 流式拷贝缓冲区对象池：避免释放几十个大体积内置规则集时反复分配临时切片或整块 readAll 堆膨胀。
var extractCopyBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 32<<10)
		return &b
	},
}

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
	defer zr.Close()
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

// ExtractToFile 将指定 tag 的规则集流式解压校验并原子落盘，避免整块规则集驻留堆内存。
// 性能优化原理：直接打开 embed.FS 只读流并经 gzip.Reader + io.TeeReader 边写入临时文件边计算 SHA256，
// 配合 sync.Pool 复用 32KB 拷贝缓冲区，将 `sb gen` 恢复 40+ 个内置规则集时的瞬时峰值内存压低到几十 KB。
func (s *Snapshot) ExtractToFile(tag, destPath string, perm os.FileMode) error {
	e, ok := s.manifest.Entries[tag]
	if !ok {
		return fmt.Errorf("snapshot has no ruleset %q", tag)
	}
	f, err := assetsFS.Open("assets/" + e.File)
	if err != nil {
		return fmt.Errorf("read embedded asset: %w", err)
	}
	defer f.Close()

	zr, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("gunzip %s: %w", e.File, err)
	}
	defer zr.Close()

	dir := filepath.Dir(destPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	tmpFile, err := os.CreateTemp(dir, ".ruleset-snap-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp %s: %w", dir, err)
	}
	tmpPath := tmpFile.Name()
	cleanupTmp := true
	defer func() {
		_ = tmpFile.Close()
		if cleanupTmp {
			_ = os.Remove(tmpPath)
		}
	}()

	hasher := sha256.New()
	reader := io.TeeReader(zr, hasher)
	bufPtr := extractCopyBufPool.Get().(*[]byte)
	written, copyErr := io.CopyBuffer(tmpFile, reader, *bufPtr)
	extractCopyBufPool.Put(bufPtr)
	if copyErr != nil {
		return fmt.Errorf("stream extract %s: %w", e.File, copyErr)
	}

	if e.Size > 0 && written != e.Size {
		return fmt.Errorf("snapshot %s: size mismatch (want %d, got %d)", e.File, e.Size, written)
	}
	if e.SHA256 != "" && hex.EncodeToString(hasher.Sum(nil)) != e.SHA256 {
		return fmt.Errorf("snapshot %s: sha256 mismatch", e.File)
	}
	if err := tmpFile.Chmod(perm); err != nil {
		return fmt.Errorf("chmod %s: %w", tmpPath, err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("close %s: %w", tmpPath, err)
	}
	if err := os.Rename(tmpPath, destPath); err != nil {
		return fmt.Errorf("rename %s: %w", destPath, err)
	}
	cleanupTmp = false
	return nil
}
