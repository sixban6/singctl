// 文件职责：定义 SmartDNS 引擎常量、配置输入、状态快照、硬件护栏与核心生命周期管理器。
package smartdns

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"singctl/internal/common/sysinfo"
	"singctl/internal/logger"
	"singctl/internal/platform/servicemgr"
)

const (
	DefaultBinaryPath     = "/usr/bin/smartdns"
	DefaultConfigDir      = "/etc/singctl"
	DefaultConfigFile     = "/etc/singctl/smartdns.conf"
	DefaultRulesDir       = "/etc/singctl/smartdns-rules.d"
	DefaultFilterCacheDir = "/tmp/singctl-smartdns-filters"
	DefaultAuditLogPath   = "/tmp/singctl-smartdns-audit.log"
	DefaultLogFilePath  = "/tmp/singctl-smartdns.log"
	DefaultPIDFilePath  = "/tmp/singctl-smartdns.pid"
	DefaultServiceName  = "singctl-smartdns"
	DefaultDNSPort      = 5353
	SmartDNSRepo        = "pymumu/smartdns"

	// 硬件护栏阈值（匹配 OpenWrt UBIFS 与小内存路由器边界；SmartDNS 实测常驻 RSS ~6.3 MB）
	MinInstallDiskMB      = 10
	MinUpgradeDiskMB      = 6
	MinTotalRAMBytes      = 112 * 1024 * 1024 // >= 112 MiB（放行 256MB 标称路由器如 AX3000T，仅保护 64M/128M 极低内存路由）
	MinAvailRAMBytes      = 32 * 1024 * 1024  // >= 32 MiB（相对 ~6.3 MiB 实测 RSS 保留 >5 倍安全余量）
	UltraLowTotalRAMBytes = 288 * 1024 * 1024 // <= 288 MiB（256MB 级路由器自动启用超轻量运行配置）
)

// RewriteEntry 描述一条局域网自定义域名解析重写或屏蔽规则。
type RewriteEntry struct {
	Domain string `json:"domain" yaml:"domain"`
	Answer string `json:"answer" yaml:"answer"`
}

// ConfigInput 定义 SmartDNS 配置与托管规则生成所需的纯数据输入（零依赖上层 config 包）。
type ConfigInput struct {
	DNSPort             int            `json:"dnsPort,omitzero"`
	Upstreams           []string       `json:"upstreams,omitzero"`
	UpstreamMode        string         `json:"upstreamMode,omitzero"`
	Whitelist           []string       `json:"whitelist,omitzero"`
	Rewrites            []RewriteEntry `json:"rewrites,omitzero"`
	AuditBlockedDomains []string       `json:"auditBlockedDomains,omitzero"`
	EnabledFilters      []string       `json:"enabledFilters,omitzero"`
	BlockAAAA           bool           `json:"blockAAAA,omitzero"`
	ProtectionPaused    bool           `json:"protectionPaused,omitzero"`
	MirrorURL           string         `json:"mirrorUrl,omitzero"`
	IsLowMemory         bool           `json:"isLowMemory,omitzero"`
	IsUltraLowMemory    bool           `json:"isUltraLowMemory,omitzero"`
}

// Options 为 ConfigInput 的兼容别名。
type Options = ConfigInput

// InstallOptions 控制 SmartDNS 安装、升级与低内存护栏行为。
type InstallOptions struct {
	Config         ConfigInput
	ForceDownload  bool
	ForceLowMemory bool
	SkipWaitReady  bool
}

// StatusInfo 汇总本地 SmartDNS 引擎的运行、探测与硬件准入状态。
type StatusInfo struct {
	Supported        bool   `json:"supported"`
	Installed        bool   `json:"installed"`
	Running          bool   `json:"running"`
	DNSHealthy       bool   `json:"dnsHealthy"`
	Version          string `json:"version"`
	BinaryPath       string `json:"binaryPath"`
	ConfigFile       string `json:"configFile"`
	DNSAddr          string `json:"dnsAddr"`
	LowMemoryWarning string `json:"lowMemoryWarning,omitzero"`
	DiskWarning      string `json:"diskWarning,omitzero"`
	HardwareEligible bool   `json:"hardwareEligible"`
}

// ManagerOptions 定义 SmartDNS 管理器的路径、配置与可注入 I/O 协作者（零值字段自动回退生产默认实现）。
type ManagerOptions struct {
	BinaryPath     string
	ConfigDir      string
	ConfigFile     string
	RulesDir       string
	FilterCacheDir string
	AuditLogPath   string
	LogFilePath    string
	PIDFilePath    string
	ServiceName    string
	SystemdDir     string
	ProcdDir       string
	ReleaseAPIBase string
	Config         ConfigInput

	GOOS   string
	GOARCH string

	ServiceMgr     servicemgr.Manager
	ReadMemInfo    func() (sysinfo.MemInfo, error)
	ReadDiskSpace  func(path string) (sysinfo.DiskSpace, error)
	IsOpenWrt      func() bool
	IsLowFlashHost func() bool
	HTTPClient     *http.Client
	DownloadFunc   func(ctx context.Context, assetName, tmpDestPath string) error
	ExecVerifyFunc func(ctx context.Context, binPath string) (string, error)
	ProbeDNSFunc   func(addr string, timeout time.Duration) error
}

// Manager 管理本地 SmartDNS 引擎的完整生命周期、规则落盘与配置预览。
type Manager struct {
	mu             sync.RWMutex
	binPath        string
	configDir      string
	configFile     string
	rulesDir       string
	filterCacheDir string
	auditLogPath   string
	logFilePath    string
	pidFilePath    string
	serviceName    string
	systemdDir     string
	procdDir       string
	releaseAPIBase string
	cfg            ConfigInput
	goos           string
	goarch         string

	serviceMgr     servicemgr.Manager
	readMemInfo    func() (sysinfo.MemInfo, error)
	readDiskSpace  func(path string) (sysinfo.DiskSpace, error)
	isOpenWrtFn    func() bool
	isLowFlashFn   func() bool
	httpClient     *http.Client
	downloadFunc   func(ctx context.Context, assetName, tmpDestPath string) error
	execVerifyFunc func(ctx context.Context, binPath string) (string, error)
	probeDNSFunc   func(addr string, timeout time.Duration) error

	bgCtx          context.Context
	bgCancel       context.CancelFunc
	bgSyncInFlight atomic.Bool
	bgWG           sync.WaitGroup
}

// NewManager 创建 SmartDNS 生命周期管理器（零值字段自动回退生产默认实现）。
func NewManager(opts ManagerOptions) *Manager {
	binPath := cmp.Or(strings.TrimSpace(opts.BinaryPath), DefaultBinaryPath)
	configFile := strings.TrimSpace(opts.ConfigFile)
	configDir := strings.TrimSpace(opts.ConfigDir)
	if configDir == "" && configFile != "" {
		configDir = filepath.Dir(configFile)
	}
	configDir = cmp.Or(configDir, DefaultConfigDir)
	if configFile == "" {
		configFile = filepath.Join(configDir, "smartdns.conf")
	}

	rulesDir := strings.TrimSpace(opts.RulesDir)
	if rulesDir == "" {
		if strings.TrimSpace(opts.ConfigDir) != "" || strings.TrimSpace(opts.ConfigFile) != "" {
			rulesDir = filepath.Join(configDir, "smartdns-rules.d")
		} else {
			rulesDir = DefaultRulesDir
		}
	}
	bgCtx, bgCancel := context.WithCancel(context.Background())

	return &Manager{
		binPath:        binPath,
		configDir:      configDir,
		configFile:     configFile,
		rulesDir:       rulesDir,
		filterCacheDir: strings.TrimSpace(opts.FilterCacheDir),
		auditLogPath:   cmp.Or(strings.TrimSpace(opts.AuditLogPath), DefaultAuditLogPath),
		logFilePath:    cmp.Or(strings.TrimSpace(opts.LogFilePath), DefaultLogFilePath),
		pidFilePath:    cmp.Or(strings.TrimSpace(opts.PIDFilePath), DefaultPIDFilePath),
		serviceName:    cmp.Or(strings.TrimSpace(opts.ServiceName), DefaultServiceName),
		systemdDir:     strings.TrimSpace(opts.SystemdDir),
		procdDir:       strings.TrimSpace(opts.ProcdDir),
		releaseAPIBase: strings.TrimSpace(opts.ReleaseAPIBase),
		cfg:            cloneConfigInput(opts.Config),
		goos:           cmp.Or(strings.TrimSpace(opts.GOOS), runtime.GOOS),
		goarch:         cmp.Or(strings.TrimSpace(opts.GOARCH), runtime.GOARCH),
		serviceMgr:     opts.ServiceMgr,
		readMemInfo:    opts.ReadMemInfo,
		readDiskSpace:  opts.ReadDiskSpace,
		isOpenWrtFn:    opts.IsOpenWrt,
		isLowFlashFn:   opts.IsLowFlashHost,
		httpClient:     opts.HTTPClient,
		downloadFunc:   opts.DownloadFunc,
		execVerifyFunc: opts.ExecVerifyFunc,
		probeDNSFunc:   opts.ProbeDNSFunc,
		bgCtx:          bgCtx,
		bgCancel:       bgCancel,
	}
}

func cloneConfigInput(in ConfigInput) ConfigInput {
	out := in
	out.Upstreams = slices.Clone(in.Upstreams)
	out.Whitelist = slices.Clone(in.Whitelist)
	out.Rewrites = slices.Clone(in.Rewrites)
	out.AuditBlockedDomains = slices.Clone(in.AuditBlockedDomains)
	out.EnabledFilters = slices.Clone(in.EnabledFilters)
	return out
}

func mergeConfigInput(base, override ConfigInput) ConfigInput {
	out := cloneConfigInput(override)
	if out.DNSPort == 0 {
		out.DNSPort = base.DNSPort
	}
	if len(out.Upstreams) == 0 && len(base.Upstreams) > 0 {
		out.Upstreams = slices.Clone(base.Upstreams)
	}
	if strings.TrimSpace(out.UpstreamMode) == "" {
		out.UpstreamMode = base.UpstreamMode
	}
	if strings.TrimSpace(out.MirrorURL) == "" {
		out.MirrorURL = base.MirrorURL
	}
	if len(out.Whitelist) == 0 && len(base.Whitelist) > 0 {
		out.Whitelist = slices.Clone(base.Whitelist)
	}
	if len(out.Rewrites) == 0 && len(base.Rewrites) > 0 {
		out.Rewrites = slices.Clone(base.Rewrites)
	}
	if len(out.AuditBlockedDomains) == 0 && len(base.AuditBlockedDomains) > 0 {
		out.AuditBlockedDomains = slices.Clone(base.AuditBlockedDomains)
	}
	if len(out.EnabledFilters) == 0 && len(base.EnabledFilters) > 0 {
		out.EnabledFilters = slices.Clone(base.EnabledFilters)
	}
	if !out.BlockAAAA && base.BlockAAAA {
		out.BlockAAAA = base.BlockAAAA
	}
	if !out.ProtectionPaused && base.ProtectionPaused {
		out.ProtectionPaused = base.ProtectionPaused
	}
	if !out.IsLowMemory && base.IsLowMemory {
		out.IsLowMemory = base.IsLowMemory
	}
	if !out.IsUltraLowMemory && base.IsUltraLowMemory {
		out.IsUltraLowMemory = base.IsUltraLowMemory
	}
	return out
}

func (m *Manager) snapshotConfig() ConfigInput {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return cloneConfigInput(m.cfg)
}

func (m *Manager) setConfig(in ConfigInput) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cfg = cloneConfigInput(in)
}

func (m *Manager) dnsPort() int {
	cfg := m.snapshotConfig()
	if cfg.DNSPort > 0 && cfg.DNSPort <= 65535 && cfg.DNSPort != 53 {
		return cfg.DNSPort
	}
	return DefaultDNSPort
}

func (m *Manager) dnsAddr() string {
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(m.dnsPort()))
}

func (m *Manager) isBinaryPresent() bool {
	if m.binPath == "" {
		return false
	}
	info, err := os.Stat(m.binPath)
	return err == nil && !info.IsDir()
}

func (m *Manager) currentMemInfo() sysinfo.MemInfo {
	fn := m.readMemInfo
	if fn == nil {
		fn = sysinfo.ReadMemInfo
	}
	info, err := fn()
	if err != nil {
		return sysinfo.MemInfo{}
	}
	return info
}

func (m *Manager) checkLowMemoryGuard(forceLowMemory bool) error {
	if forceLowMemory {
		return nil
	}
	mem := m.currentMemInfo()
	const mib = 1024 * 1024
	if mem.TotalBytes > 0 && mem.TotalBytes < MinTotalRAMBytes {
		return fmt.Errorf(
			"检测到极低内存设备（物理总内存约 %d MB < 112 MB），已拦截安装 SmartDNS 防 OOM（如确认内存充裕可通过 ForceLowMemory 强制覆盖）",
			mem.TotalBytes/mib,
		)
	}
	if mem.AvailableBytes > 0 && mem.AvailableBytes < MinAvailRAMBytes {
		return fmt.Errorf(
			"检测到设备当前可用内存不足（总内存约 %d MB，可用内存约 %d MB < 32 MB），已拦截安装 SmartDNS 防 OOM（如确认可运行可通过 ForceLowMemory 强制覆盖）",
			mem.TotalBytes/mib,
			mem.AvailableBytes/mib,
		)
	}
	return nil
}

func (m *Manager) checkDiskSpace(alreadyInstalled bool) error {
	needMB := uint64(MinInstallDiskMB)
	if alreadyInstalled {
		needMB = uint64(MinUpgradeDiskMB)
	}
	diskFn := m.readDiskSpace
	if diskFn == nil {
		diskFn = sysinfo.Statfs
	}
	checked := make(map[string]struct{}, 2)
	for _, p := range []string{m.binPath, m.configDir} {
		if p == "" {
			continue
		}
		if _, dup := checked[p]; dup {
			continue
		}
		checked[p] = struct{}{}

		ds, err := diskFn(p)
		if err != nil {
			if errors.Is(err, errors.ErrUnsupported) {
				continue
			}
			continue
		}
		availMB := ds.AvailBytes / (1024 * 1024)
		if availMB < needMB {
			return fmt.Errorf(
				"磁盘可用空间不足（%s 所在分区剩余 %d MB，安装/升级 SmartDNS 至少需要 %d MB），已安全中止以保护软路由闪存",
				p, availMB, needMB,
			)
		}
	}
	return nil
}

// HardwareGuardWarning 检查当前宿主机内存与闪存空间是否满足 SmartDNS 准入阈值（未命中则返回空串）。
func (m *Manager) HardwareGuardWarning() (lowMemWarn, diskWarn string) {
	if err := m.checkLowMemoryGuard(false); err != nil {
		lowMemWarn = err.Error()
	}
	if err := m.checkDiskSpace(m.isBinaryPresent()); err != nil {
		diskWarn = err.Error()
	}
	return lowMemWarn, diskWarn
}

// Install 执行硬件护栏校验、流式安装二进制、规则落盘、主配置生成与托管服务拉起。
func (m *Manager) Install(ctx context.Context, opts InstallOptions) (*StatusInfo, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if m.goos != "linux" {
		return nil, fmt.Errorf("SmartDNS 客户端托管仅支持 Linux / OpenWrt 环境 (当前: %s)", m.goos)
	}
	if _, err := SelectAssetName(m.goos, m.goarch); err != nil {
		return nil, err
	}
	if err := m.checkLowMemoryGuard(opts.ForceLowMemory); err != nil {
		return nil, err
	}
	alreadyHasBinary := m.isBinaryPresent()
	if err := m.checkDiskSpace(alreadyHasBinary); err != nil {
		return nil, err
	}

	mergedCfg := mergeConfigInput(m.snapshotConfig(), opts.Config)
	// 先校验配置语法与输入合法性，确保存在注入或非法端口时在下载前即快速失败。
	if _, err := BuildConfigWithOptions(mergedCfg, BuildConfigOptions{
		RulesDir:       m.rulesDir,
		FilterCacheDir: m.effectiveFilterCacheDir(mergedCfg),
		AuditLogPath:   m.auditLogPath,
		LogFilePath:    m.logFilePath,
	}); err != nil {
		return nil, err
	}

	m.setConfig(mergedCfg)

	if !alreadyHasBinary || opts.ForceDownload {
		if err := m.downloadAndInstallBinary(ctx); err != nil {
			return nil, err
		}
	} else {
		logger.Info("检测到已安装 SmartDNS (%s)，跳过重复下载", m.binPath)
	}

	if err := m.writeConfigAndRules(ctx, mergedCfg); err != nil {
		return nil, err
	}
	if err := m.installAndStartService(ctx); err != nil {
		return nil, err
	}
	if !opts.SkipWaitReady {
		if err := m.waitDNSReady(ctx, 10*time.Second); err != nil {
			return nil, err
		}
	}

	st := m.Status()
	return &st, nil
}

// ApplyConfig 校验并原子落盘托管规则与 smartdns.conf，并在服务运行中时平滑重载生效。
func (m *Manager) ApplyConfig(ctx context.Context, input ConfigInput) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := m.writeConfigAndRules(ctx, input); err != nil {
		return err
	}
	m.setConfig(input)
	if m.isBinaryPresent() && m.isServiceActive() {
		return m.Reload()
	}
	return nil
}

func (m *Manager) writeConfigAndRules(ctx context.Context, input ConfigInput) error {
	filterDir := m.effectiveFilterCacheDir(input)
	if _, err := BuildConfigWithOptions(input, BuildConfigOptions{
		RulesDir:       m.rulesDir,
		FilterCacheDir: filterDir,
		AuditLogPath:   m.auditLogPath,
		LogFilePath:    m.logFilePath,
	}); err != nil {
		return err
	}
	if err := WriteManagedRules(m.rulesDir, RuleSetInput{
		Whitelist:           input.Whitelist,
		Rewrites:            input.Rewrites,
		AuditBlockedDomains: input.AuditBlockedDomains,
	}); err != nil {
		return err
	}
	if err := m.ensureManagedBasePlaceholders(filterDir); err != nil {
		return err
	}
	usingSeparateTmpCache := filepath.Clean(filterDir) != filepath.Clean(m.rulesDir)
	if usingSeparateTmpCache {
		if removed, freed := CleanupLegacyFlashFilters(m.rulesDir); removed > 0 {
			logger.Info("🧹 已清理 SmartDNS 历史闪存去广告缓存 %d 个文件（释放 %s）", removed, sysinfo.FormatBytes(freed))
		}
	}
	if len(input.EnabledFilters) > 0 || input.ProtectionPaused {
		if _, err := syncAdblockFiltersWithClient(ctx, m.httpClient, filterDir, input.EnabledFilters, input.ProtectionPaused); err != nil {
			return err
		}
	} else if usingSeparateTmpCache {
		_ = os.Remove(filepath.Join(filterDir, "adblock.conf"))
	}
	confText, err := BuildConfigWithOptions(input, BuildConfigOptions{
		RulesDir:               m.rulesDir,
		FilterCacheDir:         filterDir,
		AuditLogPath:           m.auditLogPath,
		LogFilePath:            m.logFilePath,
		RequireExistingFilters: true,
	})
	if err != nil {
		return err
	}
	return WriteConfig(m.configFile, confText)
}

// Uninstall 停止并移除托管服务单元、SmartDNS 二进制与 SmartDNS 专属配置/规则文件（绝不删除共享配置父目录）。
func (m *Manager) Uninstall(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if m.bgCancel != nil {
		m.bgCancel()
	}
	m.bgWG.Wait()

	mgr := m.activeServiceMgr()
	_ = mgr.Stop(ctx, m.serviceName)
	rmUnitErr := mgr.RemoveUnit(ctx, m.unitSpec())

	for _, f := range []string{
		m.binPath,
		m.binPath + ".tmp",
		m.configFile,
		m.auditLogPath,
		m.logFilePath,
		m.pidFilePath,
	} {
		if strings.TrimSpace(f) != "" {
			_ = os.Remove(f)
		}
	}
	if strings.TrimSpace(m.rulesDir) != "" && m.rulesDir != "/" && m.rulesDir != m.configDir {
		_ = os.RemoveAll(m.rulesDir)
	}
	if strings.TrimSpace(m.filterCacheDir) != "" && m.filterCacheDir != "/" && m.filterCacheDir != m.configDir {
		_ = os.RemoveAll(m.filterCacheDir)
	} else if m.rulesDir == DefaultRulesDir {
		_ = os.RemoveAll(DefaultFilterCacheDir)
	}
	return rmUnitErr
}

// EnsureHealthy 供看门狗巡检调用：本地 DNS 端口探活连续失败时自动重启恢复，并自愈重启后缺失的内存盘去广告规则。
func (m *Manager) EnsureHealthy() error {
	if !m.isBinaryPresent() {
		return nil
	}
	dnsAddr := m.dnsAddr()
	if err := m.probeDNSWithRetry(dnsAddr, 1500*time.Millisecond, 2, 300*time.Millisecond); err == nil {
		m.triggerBackgroundFilterSync(m.snapshotConfig())
		return nil
	}
	logger.Warn("[Watchdog] SmartDNS (%s) 未响应，正在自动重启恢复...", dnsAddr)
	if err := m.Restart(); err != nil {
		return err
	}
	m.triggerBackgroundFilterSync(m.snapshotConfig())
	return nil
}

// Status 采集 SmartDNS 安装、版本、健康与硬件护栏状态快照。
func (m *Manager) Status() StatusInfo {
	lowMemWarn, diskWarn := m.HardwareGuardWarning()
	st := StatusInfo{
		Supported:        m.goos == "linux",
		Installed:        m.isBinaryPresent(),
		BinaryPath:       m.binPath,
		ConfigFile:       m.configFile,
		DNSAddr:          m.dnsAddr(),
		LowMemoryWarning: lowMemWarn,
		DiskWarning:      diskWarn,
		HardwareEligible: lowMemWarn == "" && diskWarn == "",
	}

	if st.Installed {
		var (
			wg            sync.WaitGroup
			ver           string
			dnsHealthy    bool
			serviceActive bool
		)
		wg.Go(func() {
			ver = m.detectInstalledVersion()
		})
		wg.Go(func() {
			dnsHealthy = m.probeDNSWithRetry(st.DNSAddr, 800*time.Millisecond, 2, 150*time.Millisecond) == nil
		})
		wg.Go(func() {
			serviceActive = m.isServiceActive()
		})
		wg.Wait()

		st.Version = ver
		st.DNSHealthy = dnsHealthy
		st.Running = dnsHealthy || serviceActive
	}
	return st
}

// EffectiveConfigPreview 返回主配置文件及受管规则目录汇总文本，供前端配置抽屉展示。
func (m *Manager) EffectiveConfigPreview() (string, error) {
	var b strings.Builder

	if raw, err := os.ReadFile(m.configFile); err == nil {
		b.WriteString("# === 主配置: ")
		b.WriteString(m.configFile)
		b.WriteString(" ===\n")
		b.Write(raw)
		if len(raw) > 0 && raw[len(raw)-1] != '\n' {
			b.WriteByte('\n')
		}
	} else if os.IsNotExist(err) {
		cfgSnap := m.snapshotConfig()
		preview, buildErr := BuildConfigWithOptions(cfgSnap, BuildConfigOptions{
			RulesDir:       m.rulesDir,
			FilterCacheDir: m.effectiveFilterCacheDir(cfgSnap),
			AuditLogPath:   m.auditLogPath,
			LogFilePath:    m.logFilePath,
		})
		if buildErr != nil {
			return "", buildErr
		}
		b.WriteString("# === 预览模式（尚未落盘）: ")
		b.WriteString(m.configFile)
		b.WriteString(" ===\n")
		b.WriteString(preview)
	} else {
		return "", fmt.Errorf("read smartdns config: %w", err)
	}

	appendRuleFileSummary(&b, m.rulesDir, "whitelist.conf", 100)
	appendRuleFileSummary(&b, m.rulesDir, "rewrites.conf", 100)
	appendRuleFileSummary(&b, m.rulesDir, "audit_block.conf", 100)
	filterDir := m.effectiveFilterCacheDir(m.snapshotConfig())
	if _, err := os.Stat(filepath.Join(filterDir, "adblock.conf")); err == nil {
		appendRuleFileSummary(&b, filterDir, "adblock.conf", 10)
	} else {
		appendRuleFileSummary(&b, m.rulesDir, "adblock.conf", 10)
	}

	return b.String(), nil
}

func appendRuleFileSummary(b *strings.Builder, rulesDir, name string, maxLines int) {
	p := filepath.Join(rulesDir, name)
	raw, err := os.ReadFile(p)
	if err != nil {
		return
	}
	b.WriteString("\n# === 托管规则: ")
	b.WriteString(name)
	b.WriteString(" ===\n")

	totalRules := 0
	shown := 0
	for line := range strings.SplitSeq(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		totalRules++
		if shown < maxLines {
			b.WriteString(trimmed)
			b.WriteByte('\n')
			shown++
		}
	}
	if totalRules == 0 {
		b.WriteString("# (空)\n")
	} else if totalRules > shown {
		fmt.Fprintf(b, "# ... 其余 %d 条已折叠（共 %d 条）\n", totalRules-shown, totalRules)
	}
}
