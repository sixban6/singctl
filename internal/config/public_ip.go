// 文件职责：保留配置层公网 IP 获取与测试桩兼容签名，底层探测与缓存委托 common/netx。
package config

import "singctl/internal/common/netx"

// DiscoverPublicIP probes IP echo services via common/netx to determine the server public IP.
func DiscoverPublicIP() string {
	return netx.DiscoverPublicIP()
}

// SetDiscoveredPublicIPForTest allows mocking the discovered IP during tests.
func SetDiscoveredPublicIPForTest(ip string) {
	netx.SetDiscoveredPublicIPForTest(ip)
}

// ResetDiscoveredPublicIPForTest resets the cached IP for tests.
func ResetDiscoveredPublicIPForTest() {
	netx.ResetDiscoveredPublicIPForTest()
}
