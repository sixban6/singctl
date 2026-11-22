// 文件职责：实现 sboption 各层配置结构体的 Extra 未知字段无损捕获、合并序列化与零反射深拷贝辅助函数。
package sboption

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// CloneRawMap 深拷贝未知扩展字段字典，确保多协程/多阶段修改互不污染底层字节切片。
func CloneRawMap(src map[string]json.RawMessage) map[string]json.RawMessage {
	if len(src) == 0 {
		return nil
	}
	dst := make(map[string]json.RawMessage, len(src))
	for k, v := range src {
		dst[k] = bytes.Clone(v)
	}
	return dst
}

func unmarshalEnvelope(data []byte, typedTarget any, knownKeys map[string]bool, extra *map[string]json.RawMessage) error {
	if err := json.Unmarshal(data, typedTarget); err != nil {
		return err
	}
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(data, &rawMap); err != nil {
		return err
	}
	for k := range knownKeys {
		delete(rawMap, k)
	}
	if len(rawMap) > 0 {
		*extra = rawMap
	} else {
		*extra = nil
	}
	return nil
}

func marshalEnvelope(typedVal any, knownKeys map[string]bool, extra map[string]json.RawMessage) ([]byte, error) {
	baseBytes, err := json.Marshal(typedVal)
	if err != nil {
		return nil, err
	}
	if len(extra) == 0 {
		return baseBytes, nil
	}
	var merged map[string]json.RawMessage
	if err := json.Unmarshal(baseBytes, &merged); err != nil {
		return nil, err
	}
	if merged == nil {
		merged = make(map[string]json.RawMessage, len(extra))
	}
	for k, v := range extra {
		if knownKeys[k] || len(v) == 0 {
			continue
		}
		merged[k] = v
	}
	return json.Marshal(merged)
}

// CanonicalJSON 生成任意配置片段（结构体或 map[string]any）的规范化紧凑 JSON 签名（按键名排序），
// 用于规则等价性比对、黑名单幂等去重与出站内容指纹计算。
func CanonicalJSON(v any) (string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	var norm any
	if err := json.Unmarshal(raw, &norm); err != nil {
		return "", err
	}
	out, err := json.Marshal(norm)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// PrettyBytes 将紧凑或已缩进的 JSON 字节流格式化为标准 2 空格缩进可读文本。
func PrettyBytes(raw []byte) (string, error) {
	var buf bytes.Buffer
	if err := json.Indent(&buf, raw, "", "  "); err != nil {
		return "", fmt.Errorf("pretty: invalid JSON: %w", err)
	}
	return buf.String(), nil
}
