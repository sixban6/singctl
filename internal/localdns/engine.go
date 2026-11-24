// 文件职责：定义双引擎防劫持 DNS（SmartDNS / AdGuard Home）统一能力契约、引擎接口、凭据可选小接口与显式依赖注入配置。
package localdns

import (
	"context"
	"net"
	"net/http"
	"time"

	"singctl/internal/adguard"
	"singctl/internal/common/sysinfo"
	"singctl/internal/config"
	"singctl/internal/platform/servicemgr"
	"singctl/internal/smartdns"
)

// Capabilities 描述活跃防劫持 DNS 引擎支持的功能能力矩阵（驱动前端动态渲染）。
type Capabilities struct {
	HasNativeWebPanel  bool `json:"hasNativeWebPanel"`
	HasConfigPreview   bool `json:"hasConfigPreview"`
	HasQueryStats      bool `json:"hasQueryStats"`
	HasFilterLists     bool `json:"hasFilterLists"`
	HasCustomFilterURL bool `json:"hasCustomFilterURL"`
	HasPauseProtection bool `json:"hasPauseProtection"`
	HasBlockAAAA       bool `json:"hasBlockAAAA"`
	CanClearCache      bool `json:"canClearCache"`
	CanUninstall       bool `json:"canUninstall"`
}

// EngineMeta 描述单个 DNS 引擎的展示元数据与资源占用提示。
type EngineMeta struct {
	ID       string
	Name     string
	Tagline  string
	DiskHint string
	RAMHint  string
}

// EngineOption 描述引擎下拉切换器单个引擎选项的完整状态与硬件准入评估结果。
type EngineOption struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Tagline       string `json:"tagline"`
	Installed     bool   `json:"installed"`
	Active        bool   `json:"active"`
	Recommended   bool   `json:"recommended"`
	Eligible      bool   `json:"eligible"`
	BlockedReason string `json:"blockedReason,omitempty"`
	DiskHint      string `json:"diskHint"`
	RAMHint       string `json:"ramHint"`
	Version       string `json:"version,omitempty"`
}

// ConfigPreview 描述抽屉展示的实时生效配置代码片段与运行诊断摘要。
type ConfigPreview struct {
	Engine         string `json:"engine"`
	Title          string `json:"title"`
	Path           string `json:"path"`
	Content        string `json:"content"`
	RuntimeSummary string `json:"runtimeSummary"`
}

// CredentialsInfo 描述具备原生管理面板的 DNS 引擎访问凭据。
type CredentialsInfo struct {
	WebURL   string `json:"webUrl"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// EngineStatus 汇总单个 DNS 引擎的轻量安装、进程与探活状态。
type EngineStatus struct {
	Supported  bool
	Installed  bool
	Running    bool
	DNSHealthy bool
	WebHealthy bool
	Version    string
	DNSAddr    string
	WebAddr    string
	WebURL     string
}

// InstallOptions 控制外部 DNS 引擎安装与硬件护栏覆写选项。
type InstallOptions struct {
	Username       string
	NonInteractive bool
	ForceDownload  bool
	ForceLowMemory bool
	SkipWaitReady  bool
}

// UpstreamUpdateResult 汇总加密上游更新后的生效列表、调度模式与自动归一化提示。
type UpstreamUpdateResult struct {
	Upstreams         []adguard.UpstreamServerInfo `json:"upstreams"`
	UpstreamMode      string                       `json:"upstreamMode"`
	UpstreamModeLabel string                       `json:"upstreamModeLabel"`
	Notes             []string                     `json:"notes,omitempty"`
}

// OverviewSnapshot 100% 兼容原有 adguard.OverviewSnapshot JSON 字段，并扩展双引擎状态、纯 DoH 兜底标记与能力字段。
type OverviewSnapshot struct {
	adguard.OverviewSnapshot
	ConfiguredEngine  string         `json:"configuredEngine"`
	ActiveEngine      string         `json:"activeEngine"`
	ActiveEngineLabel string         `json:"activeEngineLabel"`
	RecommendedEngine string         `json:"recommendedEngine"`
	RecommendedReason string         `json:"recommendedReason"`
	DnsmasqLinked     bool           `json:"dnsmasqLinked"`
	WorkMode          string         `json:"workMode"`
	FallbackDoHActive bool           `json:"fallbackDoHActive"`
	BlockAAAA         bool           `json:"blockAAAA"`
	StatsSource       string         `json:"statsSource"`
	StatsSourceLabel  string         `json:"statsSourceLabel"`
	Capabilities      Capabilities   `json:"capabilities"`
	Engines           []EngineOption `json:"engines"`
}

// Engine 定义双引擎防劫持本地 DNS（smartdns / adguard）的统一领域契约。
type Engine interface {
	ID() string
	Meta() EngineMeta
	Capabilities() Capabilities
	IsInstalled() bool
	Status(ctx context.Context) EngineStatus
	Overview(ctx context.Context, singboxLinked bool) *OverviewSnapshot
	ConfigPreview(ctx context.Context) (*ConfigPreview, error)

	Install(ctx context.Context, opts InstallOptions) error
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	Disable(ctx context.Context) error
	Restart(ctx context.Context) error
	Uninstall(ctx context.Context, purge bool) error
	EnsureHealthy(ctx context.Context) error

	SetProtection(ctx context.Context, enabled bool, durationMinutes int) error
	ClearCache(ctx context.Context) error
	ProbeUpstreams(ctx context.Context, domain string) *adguard.ProbeReport
	SetUpstreams(ctx context.Context, upstreams []string, mode string, resetDefault bool) (*UpstreamUpdateResult, error)
	SetWhitelist(ctx context.Context, domain string, allow bool) error
	AddRewrite(ctx context.Context, domain, answer string) error
	DeleteRewrite(ctx context.Context, domain, answer string) error
	SetFilterState(ctx context.Context, filterURL, name string, enabled bool) error
	RemoveFilter(ctx context.Context, filterURL string) error
	RefreshFilters(ctx context.Context) error
	SyncBlockRules(ctx context.Context, blocks []config.BlockRule) (applied bool, mode string, err error)
	SyncCommonConfig(ctx context.Context) error
}

// CredentialManager 正交可选小接口：仅带原生 Web 面板的引擎（如 AdGuard Home）实现。
type CredentialManager interface {
	Credentials(ctx context.Context) (*CredentialsInfo, error)
	ResetCredentials(ctx context.Context, newUsername string) (*CredentialsInfo, error)
}

// EngineDeps 显式注入双引擎运行期所需的路径、持久化、探测与测试替身（零值自动回退生产默认）。
type EngineDeps struct {
	ConfigPath            string
	SaveConfig            func(cfg *config.Config) error
	SingBoxConfigPath     string
	SingBoxWorkConfigPath string
	AdGuardBinPath        string
	AdGuardConfigPath     string
	SmartDNSBinPath       string
	SmartDNSConfigDir     string
	SmartDNSConfigFile    string
	SmartDNSRulesDir      string
	SmartDNSAuditLogPath  string
	SmartDNSLogFilePath   string
	SmartDNSPIDFilePath   string
	SmartDNSServiceName   string
	ServiceMgr            servicemgr.Manager
	HTTPClient            *http.Client
	ReadMemInfo           func() (sysinfo.MemInfo, error)
	ReadDiskSpace         func(path string) (sysinfo.DiskSpace, error)
	GOOS                  string
	GOARCH                string
	IsOpenWrt             func() bool
	SkipProbeForTest      bool

	ProbeUpstreamListFunc   func(ctx context.Context, upstreams []string, domain string, timeout time.Duration) []adguard.UpstreamProbeItem
	LookupIPFunc            func(ctx context.Context, host string) ([]net.IP, error)
	BypassFirewallFunc      func(ips []string)
	ProbeDNSFunc            func(addr string, timeout time.Duration) error
	ProbeResolutionFunc     func(addr, domain string, timeout time.Duration) ([]string, time.Duration, error)
	CheckPortAvailableFunc  func(port int) bool
	PortReleasePollInterval time.Duration
	SyncSingBoxDNSLocalFunc func(ctx context.Context, sbCfgPath, workPath string, useExternal bool, dnsPort int) (bool, error)
	IsSingBoxRunningFunc    func() bool
	NowFunc                 func() time.Time

	SmartDNSStats     *StatsRing
	SmartDNSTailer    *smartdns.AuditLogTailer
	SmartDNSManager   *smartdns.Manager
	AdGuardManager    *adguard.Manager
	SmartDNSExtraOpt  *smartdns.ManagerOptions
	DnsmasqBridgeDeps *DnsmasqBridgeDeps
}
