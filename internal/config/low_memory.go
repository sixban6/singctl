// 文件职责：定义客户端自适应低内存模式（low_memory: auto/on/off）配置类型、宽容解析及阈值判定方法。
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"singctl/internal/common/sysinfo"

	"gopkg.in/yaml.v3"
)

const (
	LowMemoryAuto = "auto"
	LowMemoryOn   = "on"
	LowMemoryOff  = "off"

	// DefaultLowMemoryThresholdBytes 默认客户端低内存模式自动激活总物理内存上限（复用 sysinfo.LowMemoryThresholdBytes = 512 MiB）。
	DefaultLowMemoryThresholdBytes uint64 = sysinfo.LowMemoryThresholdBytes
)

// LowMemoryMode 表示客户端低内存开关配置（支持 auto / on / off 及布尔 true / false 宽容解析）。
type LowMemoryMode string

// NormalizeLowMemoryMode 归一化并校验 low_memory 配置字符串。
// 空字符串或 "auto" 返回 ("auto", true)；"on"/"true"/"1"/"yes"/"enabled" 返回 ("on", true)；
// "off"/"false"/"0"/"no"/"disabled" 返回 ("off", true)；其余非法字符串返回 ("", false)。
func NormalizeLowMemoryMode(raw string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", LowMemoryAuto:
		return LowMemoryAuto, true
	case LowMemoryOn, "true", "1", "yes", "enabled":
		return LowMemoryOn, true
	case LowMemoryOff, "false", "0", "no", "disabled":
		return LowMemoryOff, true
	default:
		return "", false
	}
}

// UnmarshalYAML 支持 YAML 布尔值（true/false）与字符串（"auto"/"on"/"off"）宽容解析，拒绝复杂结构或非法字符串。
func (m *LowMemoryMode) UnmarshalYAML(node *yaml.Node) error {
	if node == nil {
		*m = ""
		return nil
	}
	if node.Kind != yaml.ScalarNode {
		return fmt.Errorf("invalid low_memory mode: expected scalar string or bool")
	}
	if node.Tag == "!!null" {
		*m = ""
		return nil
	}
	if node.Tag == "!!bool" {
		var b bool
		if err := node.Decode(&b); err != nil {
			return err
		}
		if b {
			*m = LowMemoryOn
		} else {
			*m = LowMemoryOff
		}
		return nil
	}
	raw := strings.TrimSpace(node.Value)
	if raw == "" {
		*m = ""
		return nil
	}
	norm, ok := NormalizeLowMemoryMode(raw)
	if !ok {
		return fmt.Errorf("invalid low_memory mode %q (expected auto/on/off or true/false)", raw)
	}
	*m = LowMemoryMode(norm)
	return nil
}

// UnmarshalJSON 支持 JSON 布尔值（true/false）、null 与字符串（"auto"/"on"/"off"）宽容解析。
func (m *LowMemoryMode) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		*m = ""
		return nil
	}
	if bytes.Equal(trimmed, []byte("true")) {
		*m = LowMemoryOn
		return nil
	}
	if bytes.Equal(trimmed, []byte("false")) {
		*m = LowMemoryOff
		return nil
	}
	var raw string
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return fmt.Errorf("invalid low_memory JSON value: %w", err)
	}
	if strings.TrimSpace(raw) == "" {
		*m = ""
		return nil
	}
	norm, ok := NormalizeLowMemoryMode(raw)
	if !ok {
		return fmt.Errorf("invalid low_memory mode %q (expected auto/on/off or true/false)", raw)
	}
	*m = LowMemoryMode(norm)
	return nil
}

// EffectiveLowMemory 根据显式配置与宿主机总物理内存字节数判定当前是否启用低内存模式：
//   - "on" / true：强制开启；
//   - "off" / false：强制关闭；
//   - "" / "auto"（默认）：当 0 < totalRAMBytes <= 512 MiB 时自动开启。
func (c *Config) EffectiveLowMemory(totalRAMBytes uint64) bool {
	if c != nil {
		if norm, ok := NormalizeLowMemoryMode(string(c.LowMemory)); ok {
			switch norm {
			case LowMemoryOn:
				return true
			case LowMemoryOff:
				return false
			}
		}
	}
	return sysinfo.IsLowMemoryRAM(totalRAMBytes)
}
