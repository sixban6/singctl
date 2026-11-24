// 文件职责：负责 AdGuard Home 发布包选择、下载校验、初始化配置编排、凭据重置与状态诊断。
package adguard

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"singctl/internal/common/fsx"
	"singctl/internal/common/netx"
	releasepkg "singctl/internal/common/release"
	"singctl/internal/common/sysinfo"
	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/logger"
)

func availableDiskMB(targetPath string) (uint64, error) {
	ds, err := sysinfo.Statfs(targetPath)
	if err != nil {
		if errors.Is(err, errors.ErrUnsupported) {
			return 10240, nil
		}
		return 0, err
	}
	return ds.AvailBytes / (1024 * 1024), nil
}

const (
	adGuardRepo                = "AdguardTeam/AdGuardHome"
	minFreshInstallDiskMB      = 80
	minUpgradeInstallDiskMB    = 45
	ultraLowTotalRAMGuardBytes = sysinfo.UltraLowMemoryThresholdBytes     // 288 MiB 物理总内存红线
	lowAvailableRAMGuardBytes  = sysinfo.LowMemoryAvailableThresholdBytes // 256 MiB 可用内存红线（如 512MB MT7986 路由实余 ~205MB）
)

var (
	validUsernameRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,32}$`)

	installedCheckMu       sync.RWMutex
	installedCheckOverride func() bool
)

// SetInstalledCheckForTest 仅供单元测试注入 AdGuardHome 安装状态探测桩。
func SetInstalledCheckForTest(fn func() bool) {
	installedCheckMu.Lock()
	defer installedCheckMu.Unlock()
	installedCheckOverride = fn
}

// HasInstalledCheckOverrideForTest 返回当前是否处于单元测试安装桩模式。
func HasInstalledCheckOverrideForTest() bool {
	installedCheckMu.RLock()
	defer installedCheckMu.RUnlock()
	return installedCheckOverride != nil
}

// IsSupportedPlatform 返回当前操作系统是否支持客户端本地 AdGuard Home 托管。
func IsSupportedPlatform() bool {
	return runtime.GOOS == "linux" || runtime.GOOS == "darwin"
}

// IsInstalled 检测当前系统是否已安装 AdGuardHome 可执行文件。
func IsInstalled() bool {
	installedCheckMu.RLock()
	fn := installedCheckOverride
	installedCheckMu.RUnlock()
	if fn != nil {
		return fn()
	}
	if constant.AdGuardInstallPath == "" {
		return false
	}
	info, err := os.Stat(constant.AdGuardInstallPath)
	return err == nil && !info.IsDir()
}

// StatusInfo 汇总本地 AdGuard Home 的运行与配置状态。
type StatusInfo struct {
	Installed  bool
	Running    bool
	DNSHealthy bool
	WebHealthy bool
	BinaryPath string
	ConfigFile string
	Version    string
	DNSAddr    string
	WebAddr    string
	WebURL     string
	Username   string
	Password   string
}

// InstallOptions 控制安装与初始化行为。
type InstallOptions struct {
	ConfigPath     string
	Username       string // 显式指定用户名；为空时交互式询问（回车默认 root）
	NonInteractive bool   // 非交互模式：不等待终端输入，直接使用已有用户名或默认 root
	ForceDownload  bool   // 强制重新下载二进制
	ForceLowMemory bool   // 强制忽略超低内存防呆护栏继续安装
	Input          io.Reader
}

// Manager 管理客户端本地 AdGuard Home 的安装、配置生成与服务生命周期。
type Manager struct {
	cfg           *config.Config
	configPath    string
	binPath       string
	aghConfigDir  string
	aghConfigFile string
	aghWorkDir    string
	systemdUnit   string
	initdScript         string
	readMemTotal        func() uint64
	readMemInfo         func() sysinfo.MemInfo
	probeUpstreamListFn func(ctx context.Context, upstreams []string, domain string, timeout time.Duration) []UpstreamProbeItem
	lookupIPFn          func(ctx context.Context, host string) ([]net.IP, error)
	bypassFirewallFn    func(ips []string)
}

// NewManager 创建默认路径的 AdGuard Home 管理器。
func NewManager(cfg *config.Config, singctlConfigPath string) *Manager {
	if cfg == nil {
		cfg = &config.Config{}
	}
	return &Manager{
		cfg:           cfg,
		configPath:    singctlConfigPath,
		binPath:       constant.AdGuardInstallPath,
		aghConfigDir:  constant.AdGuardConfigDir,
		aghConfigFile: constant.AdGuardConfigFile,
		aghWorkDir:    constant.AdGuardWorkDir,
		systemdUnit:   constant.AdGuardSystemdService,
		initdScript:   constant.AdGuardInitdScript,
	}
}

// SetPathsForTest 仅供单元测试覆盖 AdGuardHome 二进制与配置文件路径。
func (m *Manager) SetPathsForTest(binPath, aghConfigFile string) {
	if binPath != "" {
		m.binPath = binPath
	}
	if aghConfigFile != "" {
		m.aghConfigFile = aghConfigFile
		m.aghConfigDir = filepath.Dir(aghConfigFile)
		m.aghWorkDir = m.aghConfigDir
	}
}

// SetReadMemTotalForTest 仅供单元测试注入宿主机总物理内存字节数探测函数。
func (m *Manager) SetReadMemTotalForTest(fn func() uint64) {
	m.readMemTotal = fn
}

// SetReadMemInfoForTest 仅供单元测试注入宿主机完整内存信息（MemTotal + MemAvailable）探测函数。
func (m *Manager) SetReadMemInfoForTest(fn func() sysinfo.MemInfo) {
	m.readMemInfo = fn
}

// SetUpstreamHooksForTest 仅供单元测试显式注入上游探测、域名解析与防火墙放行钩子（零全局状态）。
func (m *Manager) SetUpstreamHooksForTest(
	probeFn func(ctx context.Context, upstreams []string, domain string, timeout time.Duration) []UpstreamProbeItem,
	lookupFn func(ctx context.Context, host string) ([]net.IP, error),
	bypassFn func(ips []string),
) {
	m.probeUpstreamListFn = probeFn
	m.lookupIPFn = lookupFn
	m.bypassFirewallFn = bypassFn
}

// SelectAssetName 根据目标 OS 与 CPU 架构返回官方 Release 压缩包文件名。
func SelectAssetName(goos, goarch string) (string, error) {
	switch goos {
	case "linux":
		switch goarch {
		case "amd64":
			return "AdGuardHome_linux_amd64.tar.gz", nil
		case "arm64":
			return "AdGuardHome_linux_arm64.tar.gz", nil
		case "arm":
			return "AdGuardHome_linux_armv7.tar.gz", nil
		case "386":
			return "AdGuardHome_linux_386.tar.gz", nil
		default:
			return "", fmt.Errorf("unsupported Linux architecture for AdGuard Home: %s", goarch)
		}
	case "darwin":
		switch goarch {
		case "amd64":
			return "AdGuardHome_darwin_amd64.zip", nil
		case "arm64":
			return "AdGuardHome_darwin_arm64.zip", nil
		default:
			return "", fmt.Errorf("unsupported macOS architecture for AdGuard Home: %s", goarch)
		}
	default:
		return "", fmt.Errorf("AdGuard Home client integration is supported on Linux/OpenWrt (current OS: %s)", goos)
	}
}

// PromptAdminUsername 提示用户输入管理员用户名；直接回车或无法读取终端时返回默认 "root"。
func PromptAdminUsername(r io.Reader) string {
	var reader *bufio.Reader
	if r != nil {
		reader = bufio.NewReader(r)
	} else if f, err := os.Open("/dev/tty"); err == nil {
		defer f.Close()
		reader = bufio.NewReader(f)
	} else {
		return "root"
	}

	fmt.Print("请输入 AdGuard Home 管理员账号 [直接回车默认: root]: ")
	line, err := reader.ReadString('\n')
	if err != nil && len(line) == 0 {
		fmt.Println()
		return "root"
	}
	candidate := strings.TrimSpace(line)
	if candidate == "" {
		return "root"
	}
	if !validUsernameRe.MatchString(candidate) {
		logger.Warn("用户名仅支持字母、数字及 _.- (1-32位)，已自动使用默认账号: root")
		return "root"
	}
	return candidate
}

// Install 执行一键安装、免向导初始化配置、随机密码生成与服务自启。
func (m *Manager) Install(opts InstallOptions) (*StatusInfo, error) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		return nil, fmt.Errorf("singctl dns 仅支持 Linux / OpenWrt 客户端环境 (当前: %s)", runtime.GOOS)
	}

	if err := m.checkLowMemoryGuard(opts.ForceLowMemory); err != nil {
		return nil, err
	}

	alreadyHasBinary := m.isBinaryPresent()
	if err := m.checkDiskSpace(alreadyHasBinary); err != nil {
		return nil, err
	}

	chosenUser := strings.TrimSpace(opts.Username)
	firstInit := strings.TrimSpace(m.cfg.DNS.Password) == ""
	if chosenUser == "" && firstInit && !opts.NonInteractive {
		chosenUser = PromptAdminUsername(opts.Input)
	}

	m.cfg.DNS.SetEnabled(true)
	credChanged := m.cfg.DNS.EnsureCredentials(chosenUser)

	lanIP := sanitizeWebBindIP(netx.GetPrimaryLANIPv4())
	dnsAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(m.cfg.DNS.GetDNSPort()))
	if ProbeDNS(dnsAddr, 600*time.Millisecond) != nil {
		availPort := SelectAvailableWebPort(lanIP, m.cfg.DNS.GetWebPort())
		if availPort != m.cfg.DNS.GetWebPort() {
			logger.Warn("端口 %d 已被其它服务占用，AdGuard Home Web 面板自动切换至端口 %d", m.cfg.DNS.GetWebPort(), availPort)
			m.cfg.DNS.WebPort = availPort
			credChanged = true
		}
	}

	if credChanged && m.configPath != "" {
		if err := config.Save(m.configPath, m.cfg); err != nil {
			logger.Warn("保存 DNS 凭据到 %s 失败: %v", m.configPath, err)
		}
	}

	if !alreadyHasBinary || opts.ForceDownload {
		if err := m.downloadAndInstallBinary(context.Background()); err != nil {
			return nil, err
		}
	} else {
		logger.Info("检测到已安装 AdGuard Home (%s)，跳过重复下载", m.binPath)
	}

	if err := m.ensureConfigFile(lanIP, firstInit || chosenUser != ""); err != nil {
		return nil, err
	}
	if err := m.validateConfigWithBinary(); err != nil {
		return nil, err
	}
	if err := m.installAndStartService(); err != nil {
		return nil, err
	}
	if err := m.waitDNSReady(10 * time.Second); err != nil {
		return nil, err
	}
	_ = os.Chmod(m.aghConfigDir, 0700)
	_ = os.Chmod(m.aghConfigFile, 0600)

	st := m.Status()
	m.PrintAccessSummary(st)
	return st, nil
}

func (m *Manager) currentMemInfo() sysinfo.MemInfo {
	if m.readMemInfo != nil {
		return m.readMemInfo()
	}
	if m.readMemTotal != nil {
		return sysinfo.MemInfo{TotalBytes: m.readMemTotal()}
	}
	info, err := sysinfo.ReadMemInfo()
	if err != nil {
		return sysinfo.MemInfo{}
	}
	return info
}

// LowMemoryGuardWarning 返回当前宿主环境是否命中 AdGuard Home 低内存防 OOM 拦截提示（未命中返回空字符串）。
func (m *Manager) LowMemoryGuardWarning() string {
	if err := m.checkLowMemoryGuard(false); err != nil {
		return err.Error()
	}
	return ""
}

func (m *Manager) checkLowMemoryGuard(forceLowMemory bool) error {
	if forceLowMemory {
		return nil
	}
	mem := m.currentMemInfo()
	const mib = 1024 * 1024
	if sysinfo.IsUltraLowMemoryRAM(mem.TotalBytes) {
		return fmt.Errorf(
			"检测到超低内存设备（物理总内存约 %d MB <= 288 MB），已拦截安装 AdGuard Home 以避免引发 OOM 死机；224M/256M 小内存路由器建议直接使用内置零额外内存的 sing-box 纯 IP DoH + geosite-ad1 去广告方案",
			mem.TotalBytes/mib,
		)
	}
	if mem.AvailableBytes > 0 && mem.AvailableBytes <= lowAvailableRAMGuardBytes {
		return fmt.Errorf(
			"检测到设备当前可用内存不足（总内存约 %d MB，可用内存约 %d MB <= 256 MB），已拦截安装 AdGuard Home 以避免引发 OOM 死机；224M/256M 小内存路由器建议直接使用内置零额外内存的 sing-box 纯 IP DoH + geosite-ad1 去广告方案",
			mem.TotalBytes/mib,
			mem.AvailableBytes/mib,
		)
	}
	return nil
}

func (m *Manager) isBinaryPresent() bool {
	if m.binPath == "" {
		return false
	}
	info, err := os.Stat(m.binPath)
	return err == nil && !info.IsDir()
}

func (m *Manager) checkDiskSpace(alreadyInstalled bool) error {
	needMB := uint64(minFreshInstallDiskMB)
	if alreadyInstalled {
		needMB = uint64(minUpgradeInstallDiskMB)
	}
	for _, path := range []string{m.binPath, m.aghConfigDir} {
		if path == "" {
			continue
		}
		avail, err := availableDiskMB(path)
		if err != nil {
			continue
		}
		if avail < needMB {
			return fmt.Errorf("磁盘可用空间不足 (%s 所在分区剩余 %d MB，安装 AdGuard Home 至少需要 %d MB)，已安全中止以保护软路由闪存", path, avail, needMB)
		}
	}
	return nil
}

func (m *Manager) downloadAndInstallBinary(ctx context.Context) error {
	assetName, err := SelectAssetName(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return err
	}

	tempDir, err := os.MkdirTemp("", "adguard-install-*")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tempDir)

	logger.Info("正在获取 AdGuard Home 最新稳定版发布信息 (%s)...", assetName)
	client := releasepkg.NewClient(m.cfg.GitHub.MirrorURL)
	client.DirectFirst = netx.CheckGoogleConnectivity()

	info, err := client.FetchLatest(ctx, adGuardRepo)
	if err != nil {
		return fmt.Errorf("无法直连 GitHub API 获取 AdGuard Home 发布元数据: %w", err)
	}

	var targetAsset *releasepkg.Asset
	for i := range info.Assets {
		if info.Assets[i].Name == assetName {
			targetAsset = &info.Assets[i]
			break
		}
	}
	if targetAsset == nil {
		return fmt.Errorf("AdGuard Home %s 未提供当前架构安装包: %s", info.TagName, assetName)
	}

	logger.Info("正在下载 AdGuard Home %s (%s)...", info.TagName, targetAsset.Name)
	res, err := client.Download(ctx, *targetAsset, tempDir)
	if err != nil {
		return fmt.Errorf("下载 AdGuard Home 失败: %w", err)
	}
	if res.SHA256Verified {
		logger.Success("sha256 校验通过，与官方发布摘要一致 (%s)", targetAsset.Name)
	}

	extractDir := filepath.Join(tempDir, "extracted")
	if err := releasepkg.Extract(res.Path, extractDir); err != nil {
		return fmt.Errorf("解压 AdGuard Home 失败: %w", err)
	}

	newExe, err := fsx.FindExecutable(extractDir, "AdGuardHome")
	if err != nil {
		return fmt.Errorf("解压包中未找到 AdGuardHome 可执行文件: %w", err)
	}

	if isProcessRunning() {
		_ = m.Stop()
	}
	if err := fsx.InstallOrReplace(newExe, m.binPath); err != nil {
		return fmt.Errorf("安装二进制到 %s 失败: %w", m.binPath, err)
	}
	logger.Success("AdGuard Home 核心已安装至 %s", m.binPath)
	return nil
}

func (m *Manager) ensureConfigFile(lanIP string, updateAuth bool) error {
	passHash, err := config.HashPassword(m.cfg.DNS.GetPassword())
	if err != nil {
		return fmt.Errorf("加密管理员密码失败: %w", err)
	}

	if _, statErr := os.Stat(m.aghConfigFile); statErr == nil {
		logger.Info("检测到已有配置文件 %s，执行无损同步（保留既有自定义规则与过滤器）...", m.aghConfigFile)
		_, syncErr := SyncExistingConfig(m.aghConfigFile, SyncOptions{
			LANIP:             lanIP,
			WebPort:           m.cfg.DNS.GetWebPort(),
			DNSPort:           m.cfg.DNS.GetDNSPort(),
			Username:          m.cfg.DNS.GetUsername(),
			PasswordHash:      passHash,
			UpdateAuth:        updateAuth,
			DisablePrivatePTR: new(true),
		})
		if syncErr == nil {
			return nil
		}
		logger.Warn("现有 AdGuardHome.yaml 解析失败 (%v)，将备份并重新生成标准配置", syncErr)
		_ = os.Rename(m.aghConfigFile, m.aghConfigFile+".bak")
	}

	var subURLs []string
	for _, s := range m.cfg.Subs {
		if strings.TrimSpace(s.URL) != "" {
			subURLs = append(subURLs, s.URL)
		}
	}

	yamlData, err := BuildInitialConfigYAML(ConfigParams{
		LANIP:             lanIP,
		WebPort:           m.cfg.DNS.GetWebPort(),
		DNSPort:           m.cfg.DNS.GetDNSPort(),
		Username:          m.cfg.DNS.GetUsername(),
		PasswordHash:      passHash,
		IsOpenWrt:         sysinfo.IsOpenWrt(),
		DisablePrivatePTR: true,
		SubURLs:           subURLs,
		WhitelistDomains:  m.effectiveSafeWhitelistDomains(),
	})
	if err != nil {
		return err
	}

	if err := WriteConfigAtomically(m.aghConfigFile, yamlData); err != nil {
		return fmt.Errorf("写入 %s 失败: %w", m.aghConfigFile, err)
	}
	logger.Success("已生成免引导安全配置文件: %s (权限 0600)", m.aghConfigFile)
	return nil
}

func (m *Manager) validateConfigWithBinary() error {
	if !m.isBinaryPresent() {
		return errors.New("AdGuardHome 二进制不存在")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, m.binPath, "--check-config", "-c", m.aghConfigFile, "-w", m.aghWorkDir)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("AdGuardHome 配置语法校验失败: %w\n%s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// SyncGatewayMode 在主路由/旁路由模式切换时同步 AdGuardHome.yaml 基础运行参数（始终禁用私网 PTR 防回环），
// 若配置发生变更且 AdGuard Home 当前正在运行，则自动平滑重启使其立即生效。
func (m *Manager) SyncGatewayMode(lanIP string) error {
	if _, err := os.Stat(m.aghConfigFile); err != nil {
		return nil
	}
	if strings.TrimSpace(lanIP) == "" {
		lanIP = netx.GetPrimaryLANIPv4()
	}
	changed, err := SyncExistingConfig(m.aghConfigFile, SyncOptions{
		LANIP:             sanitizeWebBindIP(lanIP),
		WebPort:           m.cfg.DNS.GetWebPort(),
		DNSPort:           m.cfg.DNS.GetDNSPort(),
		DisablePrivatePTR: new(true),
	})
	if err != nil {
		return err
	}
	if changed && m.isBinaryPresent() && isProcessRunning() {
		return m.Restart()
	}
	return nil
}

// ResetCredentials 重置 AdGuard Home 管理员账号与随机密码（或指定新账号）。
func (m *Manager) ResetCredentials(newUsername string) (string, string, error) {
	if strings.TrimSpace(newUsername) != "" && !validUsernameRe.MatchString(strings.TrimSpace(newUsername)) {
		return "", "", fmt.Errorf("用户名仅支持字母、数字及 _.- (1-32位)")
	}
	if strings.TrimSpace(newUsername) != "" {
		m.cfg.DNS.Username = strings.TrimSpace(newUsername)
	} else if strings.TrimSpace(m.cfg.DNS.Username) == "" {
		m.cfg.DNS.Username = "root"
	}
	m.cfg.DNS.Password = config.GenerateSecurePassword(16)

	if m.configPath != "" {
		if err := config.Save(m.configPath, m.cfg); err != nil {
			return "", "", fmt.Errorf("保存新密码到 %s 失败: %w", m.configPath, err)
		}
	}

	if _, err := os.Stat(m.aghConfigFile); err == nil {
		lanIP := sanitizeWebBindIP(netx.GetPrimaryLANIPv4())
		if err := m.ensureConfigFile(lanIP, true); err != nil {
			return "", "", err
		}
		if isProcessRunning() {
			if err := m.Restart(); err != nil {
				return "", "", err
			}
		}
	}

	return m.cfg.DNS.GetUsername(), m.cfg.DNS.GetPassword(), nil
}

// EnsureHealthy 供看门狗守护进程调用：自动自愈旧版私网 PTR 回环配置，并在 DNS 端口连续两次失联时自动拉起恢复。
func (m *Manager) EnsureHealthy() error {
	if !m.cfg.DNS.IsEnabled() || !m.isBinaryPresent() {
		return nil
	}
	if NeedsHardeningSync(m.aghConfigFile) {
		lanIP := sanitizeWebBindIP(netx.GetPrimaryLANIPv4())
		if changed, err := SyncExistingConfig(m.aghConfigFile, SyncOptions{
			LANIP:             lanIP,
			WebPort:           m.cfg.DNS.GetWebPort(),
			DNSPort:           m.cfg.DNS.GetDNSPort(),
			DisablePrivatePTR: new(true),
		}); err == nil && changed {
			logger.Warn("[Watchdog] 检测到 AdGuard Home 存在旧版私网 PTR 回环或噪声配置，正在自动加固并平滑重启...")
			return m.Restart()
		}
	}
	dnsAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(m.cfg.DNS.GetDNSPort()))
	if err := ProbeDNSWithRetry(dnsAddr, 1500*time.Millisecond, 2, 1*time.Second); err == nil {
		return nil
	}
	logger.Warn("[Watchdog] AdGuard Home (%s) 未响应，正在自动拉起恢复...", dnsAddr)
	return m.Start()
}

// Status 获取当前 AdGuard Home 完整状态快照。
func (m *Manager) Status() *StatusInfo {
	dnsAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(m.cfg.DNS.GetDNSPort()))
	webAddr := ReadCurrentHTTPAddress(m.aghConfigFile)
	if webAddr == "" {
		lanIP := sanitizeWebBindIP(netx.GetPrimaryLANIPv4())
		webAddr = net.JoinHostPort(lanIP, strconv.Itoa(m.cfg.DNS.GetWebPort()))
	}

	st := &StatusInfo{
		Installed:  m.isBinaryPresent(),
		BinaryPath: m.binPath,
		ConfigFile: m.aghConfigFile,
		DNSAddr:    dnsAddr,
		WebAddr:    webAddr,
		WebURL:     "http://" + webAddr,
		Username:   m.cfg.DNS.GetUsername(),
		Password:   m.cfg.DNS.GetPassword(),
	}

	if st.Installed {
		var wg sync.WaitGroup
		wg.Add(3)
		go func() {
			defer wg.Done()
			st.Version = CachedBinaryVersion(m.binPath)
		}()
		go func() {
			defer wg.Done()
			st.DNSHealthy = ProbeDNSWithRetry(dnsAddr, 800*time.Millisecond, 2, 150*time.Millisecond) == nil
		}()
		go func() {
			defer wg.Done()
			st.WebHealthy = ProbeTCPPort(webAddr, 350*time.Millisecond)
		}()
		wg.Wait()
		st.Running = st.DNSHealthy || st.WebHealthy || isProcessRunning()
	}

	return st
}

// PrintAccessSummary 打印 AdGuard Home 面板地址与登录凭据。
func (m *Manager) PrintAccessSummary(st *StatusInfo) {
	if st == nil {
		return
	}
	logger.Info("───────────────────────────────────────────────────────────")
	logger.Success("🛡️  AdGuard Home 本地防劫持 DNS 已就绪")
	logger.Info("   • DNS 监听地址 : %s (仅供本机 sing-box dns_local 安全调用)", st.DNSAddr)
	logger.Info("   • Web 管理面板 : %s (仅限局域网访问)", st.WebURL)
	logger.Info("   • 管理员账号   : %s", st.Username)
	if st.Password != "" {
		logger.Info("   • 管理员密码   : %s", st.Password)
	} else {
		logger.Info("   • 管理员密码   : (已加密保存于 %s，可通过 singctl dns reset-password 重置)", st.ConfigFile)
	}
	logger.Info("───────────────────────────────────────────────────────────")
}
