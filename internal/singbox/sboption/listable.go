// 文件职责：实现兼容 JSON 单值与数组双态无损编解码的泛型切片 Listable[T]。
package sboption

import (
	"bytes"
	"encoding/json"
	"slices"
)

// Listable 兼容 sing-box 配置中允许单标量（如 "geosite-cn"、853）与数组（如 ["geosite-cn"]、[443, 853]）
// 双态书写的字段，并在未修改形态时按原单值/数组形态无损序列化回写。
type Listable[T any] struct {
	Items  []T
	Scalar bool
}

// ListOf 构造按 JSON 数组形态序列化的 Listable。
func ListOf[T any](items ...T) Listable[T] {
	if len(items) == 0 {
		return Listable[T]{}
	}
	return Listable[T]{Items: slices.Clone(items), Scalar: false}
}

// ScalarOf 构造按 JSON 单标量形态序列化的单元素 Listable。
func ScalarOf[T any](v T) Listable[T] {
	return Listable[T]{Items: []T{v}, Scalar: true}
}

// IsZero 供 encoding/json 的 omitzero 标签判断是否省略空字段。
func (l Listable[T]) IsZero() bool {
	return len(l.Items) == 0
}

// IsEmpty 返回列表是否为空。
func (l Listable[T]) IsEmpty() bool {
	return len(l.Items) == 0
}

// Len 返回元素数量。
func (l Listable[T]) Len() int {
	return len(l.Items)
}

// Slice 返回底层切片视图。
func (l Listable[T]) Slice() []T {
	return l.Items
}

// Clone 深拷贝切片与形态标记。
func (l Listable[T]) Clone() Listable[T] {
	if len(l.Items) == 0 {
		return Listable[T]{}
	}
	return Listable[T]{
		Items:  slices.Clone(l.Items),
		Scalar: l.Scalar,
	}
}

// UnmarshalJSON 解析单值或数组 JSON。
func (l *Listable[T]) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		*l = Listable[T]{}
		return nil
	}
	if trimmed[0] == '[' {
		var arr []T
		if err := json.Unmarshal(trimmed, &arr); err != nil {
			return err
		}
		l.Items = arr
		l.Scalar = false
		return nil
	}
	var single T
	if err := json.Unmarshal(trimmed, &single); err != nil {
		return err
	}
	l.Items = []T{single}
	l.Scalar = true
	return nil
}

// MarshalJSON 按原单值或数组形态输出 JSON。
func (l Listable[T]) MarshalJSON() ([]byte, error) {
	if len(l.Items) == 0 {
		return []byte("null"), nil
	}
	if l.Scalar && len(l.Items) == 1 {
		return json.Marshal(l.Items[0])
	}
	return json.Marshal(l.Items)
}
