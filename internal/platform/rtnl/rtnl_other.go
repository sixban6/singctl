// 文件职责：提供非 Linux 平台（macOS/Windows）无副作用 rtnl.Client 编译桩实现。
//go:build !linux

package rtnl

import "net/netip"

type stubClient struct{}

func newDefaultClient() Client {
	return &stubClient{}
}

func (s *stubClient) ListAddresses() ([]InterfaceAddr, error) {
	return nil, ErrUnsupportedPlatform
}

func (s *stubClient) ListNeighbors(int) ([]NeighborEntry, error) {
	return nil, ErrUnsupportedPlatform
}

func (s *stubClient) GetDefaultRoute(int) (DefaultRoute, bool, error) {
	return DefaultRoute{}, false, ErrUnsupportedPlatform
}

func (s *stubClient) ReplaceDefaultRoute(int, netip.Addr, string) error {
	return ErrUnsupportedPlatform
}

func (s *stubClient) ReplaceUnicastRoute(UnicastRouteSpec) error {
	return ErrUnsupportedPlatform
}

func (s *stubClient) DeleteUnicastRoute(UnicastRouteSpec) error {
	return ErrUnsupportedPlatform
}

func (s *stubClient) HasRouteTableLocal(int, int) (bool, error) {
	return false, ErrUnsupportedPlatform
}

func (s *stubClient) EnsureThrowRoutes(int, int, []netip.Prefix) error {
	return ErrUnsupportedPlatform
}

func (s *stubClient) ReconcileTProxyRoutes(TProxyRouteSpec) error {
	return ErrUnsupportedPlatform
}

func (s *stubClient) CleanupTProxyRoutes(...int) error {
	return ErrUnsupportedPlatform
}
