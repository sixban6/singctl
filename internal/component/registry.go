package component

import (
	"fmt"
	"strings"
	"sync"
)

// Registry 维护已注册组件的有序列表与大小写不敏感索引（支持主键 ID 与别名查找）。
type Registry struct {
	mu      sync.RWMutex
	ordered []Component
	byKey   map[string]Component
}

// NewRegistry 创建一个空组件注册表实例。
func NewRegistry() *Registry {
	return &Registry{
		byKey: make(map[string]Component),
	}
}

func normalizeKey(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// Register 注册单个组件及其别名；空 ID 或主键/别名冲突时返回错误。
func (r *Registry) Register(c Component) error {
	if c == nil {
		return fmt.Errorf("component must not be nil")
	}
	id := normalizeKey(c.ID())
	if id == "" {
		return fmt.Errorf("component ID must not be empty")
	}

	keys := make([]string, 0, 1+len(c.Aliases()))
	keys = append(keys, id)
	for _, a := range c.Aliases() {
		na := normalizeKey(a)
		if na != "" {
			keys = append(keys, na)
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	for _, k := range keys {
		if existing, exists := r.byKey[k]; exists {
			return fmt.Errorf("component key %q already registered by %q", k, existing.ID())
		}
	}
	for _, k := range keys {
		r.byKey[k] = c
	}
	r.ordered = append(r.ordered, c)
	return nil
}

// MustRegister 注册组件并在发生编程期配置冲突时 panic，适用于包级内置注册表初始化。
func (r *Registry) MustRegister(c Component) {
	if err := r.Register(c); err != nil {
		panic(err)
	}
}

// Resolve 按主键或别名解析已注册组件（大小写不敏感、自动去除前后空白）。
func (r *Registry) Resolve(name string) (Component, error) {
	key := normalizeKey(name)
	if key == "" {
		return nil, fmt.Errorf("component name must not be empty")
	}

	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.byKey[key]
	if !ok {
		return nil, fmt.Errorf("unknown component %q", name)
	}
	return c, nil
}

// All 按注册先后顺序返回所有组件的只读切片副本。
func (r *Registry) All() []Component {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Component, len(r.ordered))
	copy(out, r.ordered)
	return out
}
