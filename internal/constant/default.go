package constant

const (
	// GitHubRepo 与 GitHubRepoURL 定义本项目的官方 GitHub 仓库标识与主页地址，
	// 供自更新、健康体检、安全自愈及统一组件发布通道共享复用。
	GitHubRepo    = "sixban6/singctl"
	GitHubRepoURL = "https://github.com/" + GitHubRepo

	// SingBoxLiteReleaseTag 为本仓库独立托管的裁剪版 sing-box 滚动 Prerelease 标签（--latest=false）。
	SingBoxLiteReleaseTag = "singbox-lite-latest"

	// CaddyReleaseTag 为本仓库独立托管的定制版 Caddy (Cloudflare DNS + Layer4) 滚动 Prerelease 标签（--latest=false）。
	CaddyReleaseTag = "caddy-latest"

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
)
