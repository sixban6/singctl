package config

import (
	"cmp"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// StoreOption 定义 config.Store 的可选构造参数。
type StoreOption func(*storeConfig)

type storeConfig struct {
	initial *Config
	hasInit bool
	loadFn  func(path string) (*Config, error)
	saveFn  func(path string, cfg *Config) error
}

// WithInitialConfig 预先注入初始配置快照，避免启动时重复解析磁盘文件。
func WithInitialConfig(cfg *Config) StoreOption {
	return func(sc *storeConfig) {
		if cfg != nil {
			sc.initial = cfg
			sc.hasInit = true
		}
	}
}

// WithLoader 自定义配置加载器（未设置时回退 config.Load）。
func WithLoader(fn func(path string) (*Config, error)) StoreOption {
	return func(sc *storeConfig) {
		sc.loadFn = fn
	}
}

// WithSaver 自定义配置保存器（未设置时回退 config.Save）。
func WithSaver(fn func(path string, cfg *Config) error) StoreOption {
	return func(sc *storeConfig) {
		sc.saveFn = fn
	}
}

// Store 维护只读不可变 *Config 原子快照、磁盘文件指纹变更检测与原子持久化更新。
// 热路径读操作（Get / Revision）完全无锁；写操作与按需磁盘重载受互斥锁串行保护。
type Store struct {
	mu      sync.Mutex
	snap    atomic.Pointer[Config]
	rev     atomic.Uint64
	path    string
	modTime time.Time
	size    int64
	hasStat bool
	lastErr error
	loadFn  func(path string) (*Config, error)
	saveFn  func(path string, cfg *Config) error
}

// NewStore 创建配置快照仓库；若未提供 WithInitialConfig 且 path 可读，将自动完成首次加载。
func NewStore(path string, opts ...StoreOption) *Store {
	sc := storeConfig{
		loadFn: Load,
		saveFn: Save,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(&sc)
		}
	}
	if sc.loadFn == nil {
		sc.loadFn = Load
	}
	if sc.saveFn == nil {
		sc.saveFn = Save
	}

	s := &Store{
		path:   path,
		loadFn: sc.loadFn,
		saveFn: sc.saveFn,
	}
	s.snap.Store(&Config{})

	if sc.hasInit && sc.initial != nil {
		s.Set(sc.initial)
		return s
	}

	if strings.TrimSpace(path) != "" {
		if loaded, err := s.loadFn(path); err == nil && loaded != nil {
			s.commitLoadedLocked(loaded)
		} else if err != nil {
			s.lastErr = err
		}
	}
	return s
}

// Path 返回关联的配置文件路径。
func (s *Store) Path() string {
	if s == nil {
		return ""
	}
	return s.path
}

// Revision 返回当前快照单调递增版本号（0 表示尚未成功加载或设置配置）。
func (s *Store) Revision() uint64 {
	if s == nil {
		return 0
	}
	return s.rev.Load()
}

// Get 无锁返回当前只读不可变配置快照（调用方禁止原地修改返回值）。
func (s *Store) Get() *Config {
	if s == nil {
		return &Config{}
	}
	if cfg := s.snap.Load(); cfg != nil {
		return cfg
	}
	return &Config{}
}

// GetClone 返回当前配置快照的深拷贝副本，适合只修改部分字段后写回。
func (s *Store) GetClone() *Config {
	return s.Get().Clone()
}

// ReloadIfChanged 根据文件 mtime+size 指纹按需重载配置（force=true 强制重载）。
// 当磁盘配置损坏导致加载失败时，自动保留上一份已知有效的配置快照并返回 (false, cur)。
func (s *Store) ReloadIfChanged(force bool) (bool, *Config) {
	if s == nil {
		return false, &Config{}
	}
	curRev := s.rev.Load()
	fresh, err := s.loadLatestInternal(force)
	if err != nil || fresh == nil {
		return false, s.Get()
	}
	return s.rev.Load() != curRev, fresh
}

// LoadLatest 按需刷新并返回最新配置及加载错误。
func (s *Store) LoadLatest() (*Config, error) {
	if s == nil {
		return nil, fmt.Errorf("nil config store")
	}
	return s.loadLatestInternal(false)
}

func (s *Store) loadLatestInternal(force bool) (*Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if strings.TrimSpace(s.path) == "" {
		if s.rev.Load() > 0 {
			return s.Get(), nil
		}
		return nil, fmt.Errorf("empty config path")
	}

	fi, statErr := os.Stat(s.path)
	if statErr != nil {
		s.lastErr = fmt.Errorf("read config file: %w", statErr)
		return nil, s.lastErr
	}

	if !force && s.hasStat && s.rev.Load() > 0 && s.lastErr == nil &&
		fi.ModTime().Equal(s.modTime) && fi.Size() == s.size {
		return s.Get(), nil
	}

	fresh, err := s.loadFn(s.path)
	if err != nil {
		s.lastErr = err
		return nil, err
	}
	if fresh == nil {
		s.lastErr = fmt.Errorf("loaded nil config")
		return nil, s.lastErr
	}

	cloned := fresh.Clone()
	cloned.sourcePath = cmp.Or(cloned.sourcePath, s.path)
	s.snap.Store(cloned)
	s.rev.Add(1)
	s.modTime = fi.ModTime()
	s.size = fi.Size()
	s.hasStat = true
	s.lastErr = nil
	return cloned, nil
}

func (s *Store) commitLoadedLocked(cfg *Config) {
	cloned := cfg.Clone()
	cloned.sourcePath = cmp.Or(cloned.sourcePath, s.path)
	s.snap.Store(cloned)
	s.rev.Add(1)
	s.refreshStatLocked()
	s.lastErr = nil
}

func (s *Store) refreshStatLocked() {
	if strings.TrimSpace(s.path) == "" {
		s.modTime = time.Time{}
		s.size = 0
		s.hasStat = false
		return
	}
	if fi, err := os.Stat(s.path); err == nil {
		s.modTime = fi.ModTime()
		s.size = fi.Size()
		s.hasStat = true
		return
	}
	s.modTime = time.Time{}
	s.size = 0
	s.hasStat = false
}

// Set 直接替换当前内存快照（深拷贝后发布）并刷新磁盘指纹缓存。
func (s *Store) Set(cfg *Config) {
	if s == nil || cfg == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.commitLoadedLocked(cfg)
}

// Invalidate 清除缓存指纹，使下次 LoadLatest 或 ReloadIfChanged 强制从磁盘重读。
func (s *Store) Invalidate() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.modTime = time.Time{}
	s.size = 0
	s.hasStat = false
	s.lastErr = nil
}

// Update 在互斥锁保护下克隆当前配置、执行变更回调、原子写盘后发布新快照。
func (s *Store) Update(fn func(*Config) error) error {
	if s == nil {
		return fmt.Errorf("nil config store")
	}
	if fn == nil {
		return fmt.Errorf("nil update mutator")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if strings.TrimSpace(s.path) != "" {
		if fi, statErr := os.Stat(s.path); statErr == nil {
			if !s.hasStat || s.lastErr != nil || !fi.ModTime().Equal(s.modTime) || fi.Size() != s.size {
				if fresh, err := s.loadFn(s.path); err == nil && fresh != nil {
					s.snap.Store(fresh.Clone())
					s.modTime = fi.ModTime()
					s.size = fi.Size()
					s.hasStat = true
					s.lastErr = nil
				}
			}
		}
	}

	next := s.Get().Clone()
	if err := fn(next); err != nil {
		return err
	}
	next.sourcePath = cmp.Or(next.sourcePath, s.path)

	if strings.TrimSpace(s.path) != "" {
		if err := s.saveFn(s.path, next); err != nil {
			return err
		}
	}

	s.snap.Store(next)
	s.rev.Add(1)
	s.refreshStatLocked()
	s.lastErr = nil
	return nil
}
