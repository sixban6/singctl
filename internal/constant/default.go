package constant

const (
	// GitHubRepo 与 GitHubRepoURL 定义本项目的官方 GitHub 仓库标识与主页地址，
	// 供自更新、健康体检、安全自愈及统一组件发布通道共享复用。
	GitHubRepo    = "sixban6/singctl"
	GitHubRepoURL = "https://github.com/" + GitHubRepo

	// SingBoxTargetMajor 定义本仓库当前适配验证通过的 sing-box 主次版本号（与仓库根目录 .upstream-version 严格同步）。
	SingBoxTargetMajor = "1.14"

	// SingBoxTargetTemplateVersion 为配置编译流水线与 iOS 适配默认使用的目标版本标签（如 "v1.14"）。
	SingBoxTargetTemplateVersion = "v" + SingBoxTargetMajor

	// SingBoxLiteReleaseTag 为本仓库独立托管的裁剪版 sing-box 滚动 Prerelease 标签（--latest=false）。
	SingBoxLiteReleaseTag = "singbox-lite-latest"

	// CaddyReleaseTag 为本仓库独立托管的定制版 Caddy (Cloudflare DNS + Layer4) 滚动 Prerelease 标签（--latest=false）。
	CaddyReleaseTag = "caddy-latest"

	// RuleSetsReleaseTag 为本仓库独立托管的自定义 sing-box 规则集 (.srs) 滚动 Prerelease 标签（--latest=false）。
	RuleSetsReleaseTag = "rulesets-latest"

	// RuleSetReleaseBaseURL 为自定义规则集滚动发布通道的权威下载前缀。
	RuleSetReleaseBaseURL = GitHubRepoURL + "/releases/download/" + RuleSetsReleaseTag

	AppName          = "SFM"
	ExitNode         = "exit-node"
	MainRouter       = "router"
	AcceptRoutes     = "accept-routes"
	TailscaleMode    = "mode"
	TailscaleSubnets = "subnets"

	// 客户端双引擎防劫持本地 DNS 标识常量（单一权威归属）。
	DNSEngineAuto     = "auto"
	DNSEngineAdGuard  = "adguard"
	DNSEngineSmartDNS = "smartdns"

	// SmartDNS 权威路径与服务常量（单一权威归属）。
	SmartDNSInstallPath  = "/usr/bin/smartdns"
	SmartDNSConfigDir    = "/etc/singctl"
	SmartDNSConfigFile   = "/etc/singctl/smartdns.conf"
	SmartDNSRulesDir     = "/etc/singctl/smartdns-rules.d"
	SmartDNSAuditLogPath = "/tmp/singctl-smartdns-audit.log"
	SmartDNSServiceName  = "singctl-smartdns"

	// Safe Commit 远端安全回滚保险丝权威路径与超时边界常量（单一权威归属）。
	SafeCommitDir              = "/tmp/singctl-safecommit"
	SafeCommitStateFile        = SafeCommitDir + "/state.json"
	SafeCommitLastRollbackFile = SafeCommitDir + "/last_rollback.json"
	SafeCommitWatchLogFile     = SafeCommitDir + "/watch.log"
	SafeCommitDefaultTTLSec    = 180
	SafeCommitMinTTLSec        = 60
	SafeCommitMaxTTLSec        = 600

	// VLANProxyBypassFile 为透明代理按 VLAN 子网直连绕行清单的权威落盘路径（0600，每行一条 IPv4 CIDR）。
	VLANProxyBypassFile = "/etc/singctl/vlan-proxy-bypass.list"

	// VLANDNSBypassFile 为自定义子网 DNS 免本机 dns_redirect / 透明代理劫持清单的权威落盘路径（0600）。
	VLANDNSBypassFile = "/etc/singctl/vlan-dns-bypass.list"

	// VLANSideRoutesFile 为主机与 VLAN 子网交由旁路由策略路由分流的权威落盘路径（0600）。
	VLANSideRoutesFile = "/etc/singctl/vlan-side-routes.list"
)

// DefaultAdBlockSafeDomains 定义内置极小去广告防误杀安全域名基线（微信搜一搜表情原图 CDN、闪萌、SOOGIF、微信 HTTPDNS）。
// 单一权威归属：供 sing-box 编译与热同步、AdGuard Home 与 SmartDNS 共同复用；用户显式拉黑项由上层自动剔除。
var DefaultAdBlockSafeDomains = []string{
	"wxaintpcos.wxqcloud.qq.com.cn", // 微信搜一搜/AI 表情原图 COS CDN
	"dl.weshineapp.com",             // 闪萌表情包下载源
	"pass1.soogif.com",              // SOOGIF 动图表情源
	"pass2.soogif.com",              // SOOGIF 动图表情源
	"dns.weixin.qq.com",             // 微信内置 HTTPDNS 调度
	"dns.weixin.qq.com.cn",          // 微信内置 HTTPDNS 调度 (.cn)
	"aedns.weixin.qq.com",           // 微信边缘 DNS 调度
}
