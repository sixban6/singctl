package servicemgr

import (
	"context"
	"sync"
)

// MockManager 为并发安全的纯内存服务管理器替身，供上层单测验证启停与单元安装序列。
type MockManager struct {
	mu     sync.Mutex
	active map[string]bool
	calls  []string
}

// NewMock 创建纯内存 Mock 服务管理器。
func NewMock() *MockManager {
	return &MockManager{
		active: make(map[string]bool),
	}
}

func (m *MockManager) record(op, name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, op+" "+name)
}

func (m *MockManager) setActive(name string, v bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.active[name] = v
}

// Calls 返回当前已记录的所有操作序列快照。
func (m *MockManager) Calls() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, len(m.calls))
	copy(out, m.calls)
	return out
}

func (m *MockManager) Kind() InitKind { return InitSystemd }

func (m *MockManager) Start(_ context.Context, name string) error {
	if err := ValidateUnitName(name); err != nil {
		return err
	}
	m.record("start", name)
	m.setActive(name, true)
	return nil
}

func (m *MockManager) Stop(_ context.Context, name string) error {
	if err := ValidateUnitName(name); err != nil {
		return err
	}
	m.record("stop", name)
	m.setActive(name, false)
	return nil
}

func (m *MockManager) Restart(_ context.Context, name string) error {
	if err := ValidateUnitName(name); err != nil {
		return err
	}
	m.record("restart", name)
	m.setActive(name, true)
	return nil
}

func (m *MockManager) Reload(_ context.Context, name string) error {
	if err := ValidateUnitName(name); err != nil {
		return err
	}
	m.record("reload", name)
	return nil
}

func (m *MockManager) ReloadOrRestart(ctx context.Context, name string) error {
	return m.Reload(ctx, name)
}

func (m *MockManager) Enable(_ context.Context, name string) error {
	if err := ValidateUnitName(name); err != nil {
		return err
	}
	m.record("enable", name)
	return nil
}

func (m *MockManager) Disable(_ context.Context, name string) error {
	if err := ValidateUnitName(name); err != nil {
		return err
	}
	m.record("disable", name)
	return nil
}

func (m *MockManager) DaemonReload(context.Context) error {
	m.record("daemon-reload", "")
	return nil
}

func (m *MockManager) IsActive(_ context.Context, name string) bool {
	if ValidateUnitName(name) != nil {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.active[name]
}

func (m *MockManager) InstallUnit(_ context.Context, spec UnitSpec) error {
	if err := ValidateUnitName(spec.Name); err != nil {
		return err
	}
	if err := ValidateEnvMap(spec.Env); err != nil {
		return err
	}
	m.record("install-unit", spec.Name)
	m.setActive(spec.Name, true)
	return nil
}

func (m *MockManager) RemoveUnit(_ context.Context, spec UnitSpec) error {
	if err := ValidateUnitName(spec.Name); err != nil {
		return err
	}
	m.record("remove-unit", spec.Name)
	m.setActive(spec.Name, false)
	return nil
}
