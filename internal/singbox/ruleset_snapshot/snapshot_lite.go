//go:build lite

// Package ruleset_snapshot 的轻量版（lite）实现，不包含内嵌快照 assets，以最小化二进制体积。
package ruleset_snapshot

import (
	"fmt"
)

// Load 返回空的快照清单（轻量版无内嵌快照）。
func Load() *Snapshot {
	if loaded != nil {
		return loaded
	}
	loaded = &Snapshot{
		manifest: snapshotManifest{
			Entries: make(map[string]snapshotEntry),
		},
	}
	return loaded
}

// Extract 在轻量版中直接返回不可用错误。
func (s *Snapshot) Extract(tag string) ([]byte, error) {
	return nil, fmt.Errorf("embedded ruleset snapshot is disabled in lite build")
}
