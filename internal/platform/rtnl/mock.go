// 文件职责：提供并发安全的纯内存 rtnl.Client 测试替身，供零宿主机污染单元测试与回归验证使用。
package rtnl

import (
	"net/netip"
	"slices"
	"sync"
)

// MockClient 是并发安全的 rtnl.Client 测试替身。
type MockClient struct {
	mu              sync.Mutex
	Addresses       []InterfaceAddr
	Neighbors       map[int][]NeighborEntry
	DefaultRoutes   map[int]DefaultRoute
	LocalTables     map[[2]int]bool
	ReconcileErr    error
	CleanupErr      error
	ReplaceErr      error
	ThrowErr        error
	ListNeighborErr error

	reconciledSpecs       []TProxyRouteSpec
	cleanedTables         [][]int
	replacedDefaultRoutes []DefaultRoute
	replacedUnicastRoutes []UnicastRouteSpec
	deletedUnicastRoutes  []UnicastRouteSpec
	ensuredThrows         []netip.Prefix
}

// NewMockClient 创建初始化完成的 MockClient。
func NewMockClient() *MockClient {
	return &MockClient{
		Neighbors:     make(map[int][]NeighborEntry),
		DefaultRoutes: make(map[int]DefaultRoute),
		LocalTables:   make(map[[2]int]bool),
	}
}

func (m *MockClient) ListAddresses() ([]InterfaceAddr, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.Addresses), nil
}

func (m *MockClient) ListNeighbors(family int) ([]NeighborEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ListNeighborErr != nil {
		return nil, m.ListNeighborErr
	}
	return slices.Clone(m.Neighbors[family]), nil
}

func (m *MockClient) GetDefaultRoute(family int) (DefaultRoute, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.DefaultRoutes[family]
	return r, ok, nil
}

func (m *MockClient) ReplaceDefaultRoute(family int, gw netip.Addr, ifName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ReplaceErr != nil {
		return m.ReplaceErr
	}
	r := DefaultRoute{Family: family, Gateway: gw, IfName: ifName}
	m.DefaultRoutes[family] = r
	m.replacedDefaultRoutes = append(m.replacedDefaultRoutes, r)
	return nil
}

func (m *MockClient) ReplaceUnicastRoute(spec UnicastRouteSpec) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ReplaceErr != nil {
		return m.ReplaceErr
	}
	m.replacedUnicastRoutes = append(m.replacedUnicastRoutes, spec)
	return nil
}

func (m *MockClient) DeleteUnicastRoute(spec UnicastRouteSpec) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.CleanupErr != nil {
		return m.CleanupErr
	}
	m.deletedUnicastRoutes = append(m.deletedUnicastRoutes, spec)
	return nil
}

// ReplacedUnicastRoutes 返回记录的 ReplaceUnicastRoute 调用规格副本。
func (m *MockClient) ReplacedUnicastRoutes() []UnicastRouteSpec {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.replacedUnicastRoutes)
}

// DeletedUnicastRoutes 返回记录的 DeleteUnicastRoute 调用规格副本。
func (m *MockClient) DeletedUnicastRoutes() []UnicastRouteSpec {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.deletedUnicastRoutes)
}

func (m *MockClient) HasRouteTableLocal(family int, table int) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.LocalTables[[2]int{family, table}], nil
}

func (m *MockClient) EnsureThrowRoutes(family int, table int, prefixes []netip.Prefix) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ThrowErr != nil {
		return m.ThrowErr
	}
	_ = family
	_ = table
	m.ensuredThrows = append(m.ensuredThrows, prefixes...)
	return nil
}

func (m *MockClient) ReconcileTProxyRoutes(spec TProxyRouteSpec) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ReconcileErr != nil {
		return m.ReconcileErr
	}
	m.reconciledSpecs = append(m.reconciledSpecs, spec)
	return nil
}

func (m *MockClient) CleanupTProxyRoutes(tables ...int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.CleanupErr != nil {
		return m.CleanupErr
	}
	m.cleanedTables = append(m.cleanedTables, slices.Clone(tables))
	return nil
}

// ReconciledSpecs 返回记录的 ReconcileTProxyRoutes 调用参数副本。
func (m *MockClient) ReconciledSpecs() []TProxyRouteSpec {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.reconciledSpecs)
}

// CleanedTables 返回记录的 CleanupTProxyRoutes 调用参数副本。
func (m *MockClient) CleanedTables() [][]int {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([][]int, len(m.cleanedTables))
	for i, c := range m.cleanedTables {
		out[i] = slices.Clone(c)
	}
	return out
}

// EnsuredThrows 返回记录的 EnsureThrowRoutes 前缀副本。
func (m *MockClient) EnsuredThrows() []netip.Prefix {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.ensuredThrows)
}
