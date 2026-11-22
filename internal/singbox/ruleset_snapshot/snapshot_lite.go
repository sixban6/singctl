//go:build lite

// 文件职责：在轻量精简构建（lite）下剔除 1.6MB 内嵌规则集快照资产，返回空清单以自然回退远端按需拉取与本地缓存。
package ruleset_snapshot

import (
	"fmt"
	"os"
	"sync"
)

// IsLite 标识当前二进制为剔除大体积离线规则集快照的轻量构建。
const IsLite = true

var loadLiteOnce = sync.OnceValue(func() *Snapshot {
	return &Snapshot{}
})

// Load 返回空的内置快照清单，促使规则集引擎按需拉取远端规则集并使用本地磁盘缓存。
func Load() *Snapshot {
	return loadLiteOnce()
}

// Extract 在 lite 构建下始终返回未命中错误。
func (s *Snapshot) Extract(tag string) ([]byte, error) {
	return nil, fmt.Errorf("snapshot has no ruleset %q (lite build)", tag)
}

// ExtractToFile 在 lite 构建下始终返回未命中错误。
func (s *Snapshot) ExtractToFile(tag, _ string, _ os.FileMode) error {
	return fmt.Errorf("snapshot has no ruleset %q (lite build)", tag)
}
