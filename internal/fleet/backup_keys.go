// 文件职责：提供 Fleet 灾备恢复时的私钥文件名防目录穿越净化与节点 key_path 跨目录对齐辅助。
package fleet

import (
	"errors"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// SanitizeKeyFilename 校验并净化备份包中的舰队密钥文件名，严禁路径分隔符与目录穿越。
func SanitizeKeyFilename(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || trimmed == "." || trimmed == ".." || strings.Contains(trimmed, "..") || strings.ContainsAny(trimmed, `/\`) {
		return "", errors.New("invalid fleet key filename")
	}
	base := filepath.Base(trimmed)
	if base != trimmed || base == "" || base == "." || base == ".." {
		return "", errors.New("invalid fleet key filename")
	}
	return base, nil
}

// RewriteRestoredKeyPaths 若灾备恢复目标主机的 KeysDir 变更，将受管 fleet_keys 路径自动对齐至当前 KeysDir。
func RewriteRestoredKeyPaths(rawFleetYAML, targetKeysDir string, bundledKeys map[string][]byte) string {
	if targetKeysDir == "" || len(bundledKeys) == 0 {
		return rawFleetYAML
	}
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(rawFleetYAML), &doc); err != nil {
		return rawFleetYAML
	}
	nodesRaw, ok := doc["nodes"].([]any)
	if !ok {
		return rawFleetYAML
	}
	changed := false
	for _, item := range nodesRaw {
		nodeMap, ok := item.(map[string]any)
		if !ok {
			continue
		}
		kp, _ := nodeMap["key_path"].(string)
		if kp == "" {
			continue
		}
		base := filepath.Base(kp)
		if _, exists := bundledKeys[base]; exists {
			newPath := filepath.Join(targetKeysDir, base)
			if newPath != kp {
				nodeMap["key_path"] = newPath
				changed = true
			}
		}
	}
	if !changed {
		return rawFleetYAML
	}
	out, err := yaml.Marshal(doc)
	if err != nil {
		return rawFleetYAML
	}
	return string(out)
}
