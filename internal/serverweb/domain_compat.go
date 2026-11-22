// 文件职责：声明 serverweb 控制面对外保持兼容的领域类型别名与空指针安全构造函数，底层能力归位各领域子包。
package serverweb

import (
	"singctl/internal/deploy"
	"singctl/internal/netdiag/ipgeo"
	"singctl/internal/sniff"
	"singctl/internal/subhub"
)

type (
	IPGeoInfo       = ipgeo.Info
	GeoCacheEntry   = ipgeo.CacheEntry
	IPGeoResolver   = ipgeo.Resolver
	SniffIPStat     = sniff.IPStat
	SniffSubnetStat = sniff.SubnetStat
	SniffCountryStat = sniff.CountryStat
	SniffSummary    = sniff.Summary
	SniffTracker    = sniff.Tracker
	AttemptSnapshot = sniff.LimiterAttempt

	CertHealth                = deploy.CertHealth
	WarpDaemonStatus          = deploy.WarpDaemonStatus
	WarpNodeSummary           = deploy.WarpNodeSummary
	WarpRoutingStatusResponse = deploy.WarpRoutingStatusResponse
	WarpWatchdogDeps          = deploy.WarpWatchdogDeps
	SubscriptionRiskSummary   = subhub.SubscriptionRiskSummary
)

// SniffTimeLayout 为嗅探快照标准时间布局常量。
const SniffTimeLayout = sniff.TimeLayout

// NewIPGeoResolver 创建实例级 IP 地理位置解析器（委托 internal/netdiag/ipgeo）。
func NewIPGeoResolver(filePath ...string) *IPGeoResolver {
	return ipgeo.NewResolver(filePath...)
}

// CountryCodeToFlag 将 ISO-3166 两位国家码转换为国旗 Emoji。
func CountryCodeToFlag(code string) string {
	return ipgeo.CountryCodeToFlag(code)
}

// FormatGeoLabel 拼接紧凑可读的中文地理位置描述。
func FormatGeoLabel(country, region, city string) string {
	return ipgeo.FormatGeoLabel(country, region, city)
}

// NewSniffTracker 创建嗅探雷达追踪器（安全处理具体类型 nil 指针转接口）。
func NewSniffTracker(geo *IPGeoResolver, limiter *IPLimiter, filePath ...string) *SniffTracker {
	var bl sniff.BanLimiter
	if limiter != nil {
		bl = limiter
	}
	return sniff.NewTracker(geo, bl, filePath...)
}
