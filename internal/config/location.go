// 文件职责：保留配置层地域标签探测与缩写映射兼容签名，底层网络与映射逻辑委托 common/netx。
package config

import "singctl/internal/common/netx"

// SetDiscoveredLocationTagForTest allows mocking the discovered location tag during tests.
func SetDiscoveredLocationTagForTest(tag string) {
	netx.SetDiscoveredLocationTagForTest(tag)
}

// ResetDiscoveredLocationTagForTest resets the cached location tag for tests.
func ResetDiscoveredLocationTagForTest() {
	netx.ResetDiscoveredLocationTagForTest()
}

// DiscoverLocationTag probes GeoIP providers via common/netx to determine the location tag.
func DiscoverLocationTag(ip string) string {
	return netx.DiscoverLocationTag(ip)
}

// CityCountryToTag converts city and country code to a standard clean abbreviation.
func CityCountryToTag(city, countryCode string) string {
	return netx.CityCountryToTag(city, countryCode)
}

func cachedLocationTag() string {
	return netx.CachedLocationTag()
}

func sanitizeTag(tag string) string {
	return netx.SanitizeTag(tag)
}
