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

	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/logger"
	"singctl/internal/util/file"
	"singctl/internal/util/netinfo"
	releasepkg "singctl/internal/util/release"
)

const (
	adGuardRepo             = "AdguardTeam/AdGuardHome"
	minFreshInstallDiskMB   = 80
	minUpgradeInstallDiskMB = 45
)

var validUsernameRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,32}$`)

var (
	installedCheckMu       sync.RWMutex
	installedCheckOverride func() bool
)

// SetInstalledCheckForTest 仅供单元测试注入 AdGuardHome 安装状态探测桩。
func SetInstalledCheckForTest(fn func() bool) {
	installedCheckMu.Lock()
	defer installedCheckMu.Unlock()
	installedCheckOverride = fn
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
	Installed   bool
	Running     bool
	DNSHealthy  bool
	WebHealthy  bool
	BinaryPath  string
	ConfigFile  string
	Version     string
	DNSAddr     string
	WebAddr     string
	WebURL      string
	Username    string
	Password    string
}

// InstallOptions 控制安装与初始化行为。
type InstallOptions struct {
	ConfigPath     string
	Username       string // 显式指定用户名；为空时交互式询问（回车默认 root）
	NonInteractive bool   // 非交互模式：不等待终端输入，直接使用已有用户名或默认 root
	ForceDownload  bool   // 强制重新下载二进制
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
	initdScript   string
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
	var ttyFile *os.File

	if r != nil {
		reader = bufio.NewReader(r)
	} else if f, err := os.Open("/dev/tty"); err == nil {
		ttyFile = f
		defer ttyFile.Close()
		reader = bufio.NewReader(ttyFile)
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

	alreadyHasBinary := m.isBinaryPresent()
	if err := m.checkDiskSpace(alreadyHasBinary); err != nil {
		return nil, err
	}

	// 1. 确定管理员用户名（首次安装且未预设密码时允许交互输入，回车默认 root）与自动生成强随机密码
	chosenUser := strings.TrimSpace(opts.Username)
	firstInit := strings.TrimSpace(m.cfg.DNS.Password) == ""
	if chosenUser == "" && firstInit && !opts.NonInteractive {
		chosenUser = PromptAdminUsername(opts.Input)
	}

	m.cfg.DNS.SetEnabled(true)
	credChanged := m.cfg.DNS.EnsureCredentials(chosenUser)

	// 2. 获取本机局域网私网 IP（严禁 0.0.0.0），并检测 Web 面板端口可用性
	lanIP := sanitizeWebBindIP(netinfo.GetPrimaryLANIPv4())
	dnsAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(m.cfg.DNS.GetDNSPort()))
	aghAlreadyRunning := ProbeDNS(dnsAddr, 600*time.Millisecond) == nil
	if !aghAlreadyRunning {
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

	// 3. 下载或复用二进制（下载动作在任何重启之前完成，保证软路由网关不断网）
	if !alreadyHasBinary || opts.ForceDownload {
		if err := m.downloadAndInstallBinary(context.Background()); err != nil {
			return nil, err
		}
	} else {
		logger.Info("检测到已安装 AdGuard Home (%s)，跳过重复下载", m.binPath)
	}

	// 4. 生成或同步 AdGuardHome.yaml（直接写入完整配置 + bcrypt 密码，彻底跳过 0.0.0.0:3000 首次引导向导）
	if err := m.ensureConfigFile(lanIP, firstInit || chosenUser != ""); err != nil {
		return nil, err
	}

	// 5. 使用官方二进制预检配置文件合法性
	if err := m.validateConfigWithBinary(); err != nil {
		return nil, err
	}

	// 6. 注册系统开机自启服务并启动
	if err := m.installAndStartService(); err != nil {
		return nil, err
	}

	// 7. 等待本地 DNS 端口就绪并收敛配置文件权限为 0600
	if err := m.waitDNSReady(10 * time.Second); err != nil {
		return nil, err
	}
	_ = os.Chmod(m.aghConfigDir, 0700)
	_ = os.Chmod(m.aghConfigFile, 0600)

	st := m.Status()
	m.PrintAccessSummary(st)
	return st, nil
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
	client.DirectFirst = netinfo.CheckGoogleConnectivity()

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

	newExe, err := file.FindExecutable(extractDir, "AdGuardHome")
	if err != nil {
		return fmt.Errorf("解压包中未找到 AdGuardHome 可执行文件: %w", err)
	}

	// 若正在运行则先优雅停止，避免旧二进制占用导致替换失败
	if isProcessRunning() {
		_ = m.Stop()
	}

	if err := file.InstallOrReplace(newExe, m.binPath); err != nil {
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
			LANIP:        lanIP,
			WebPort:      m.cfg.DNS.GetWebPort(),
			DNSPort:      m.cfg.DNS.GetDNSPort(),
			Username:     m.cfg.DNS.GetUsername(),
			PasswordHash: passHash,
			UpdateAuth:   updateAuth,
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
		LANIP:        lanIP,
		WebPort:      m.cfg.DNS.GetWebPort(),
		DNSPort:      m.cfg.DNS.GetDNSPort(),
		Username:     m.cfg.DNS.GetUsername(),
		PasswordHash: passHash,
		IsOpenWrt:    netinfo.IsOpenWrt(),
		SubURLs:      subURLs,
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

func (m *Manager) installAndStartService() error {
	if err := os.MkdirAll(m.aghWorkDir, 0700); err != nil {
		return err
	}

	if hasOpenWrtProcd() && m.initdScript != "" {
		sanitizeOpenWrtDnsmasqTTL()
		scriptContent := BuildOpenWrtInitScript(m.binPath, m.aghConfigFile, m.aghWorkDir)
		if err := os.WriteFile(m.initdScript, []byte(scriptContent), 0755); err != nil {
			return fmt.Errorf("写入 OpenWrt 服务脚本 %s 失败: %w", m.initdScript, err)
		}
		_ = exec.Command(m.initdScript, "enable").Run()
		if out, err := exec.Command(m.initdScript, "restart").CombinedOutput(); err != nil {
			if out2, err2 := exec.Command(m.initdScript, "start").CombinedOutput(); err2 != nil {
				return fmt.Errorf("启动 OpenWrt AdGuardHome 服务失败: %v (%s / %s)", err2, strings.TrimSpace(string(out)), strings.TrimSpace(string(out2)))
			}
		}
		return nil
	}

	if hasSystemd() && m.systemdUnit != "" {
		unitContent := BuildSystemdUnit(m.binPath, m.aghConfigFile, m.aghWorkDir)
		if err := os.WriteFile(m.systemdUnit, []byte(unitContent), 0644); err != nil {
			return fmt.Errorf("写入 systemd 服务文件 %s 失败: %w", m.systemdUnit, err)
		}
		_ = exec.Command("systemctl", "daemon-reload").Run()
		_ = exec.Command("systemctl", "enable", "AdGuardHome").Run()
		if out, err := exec.Command("systemctl", "restart", "AdGuardHome").CombinedOutput(); err != nil {
			return fmt.Errorf("启动 systemd AdGuardHome 服务失败: %w\n%s", err, strings.TrimSpace(string(out)))
		}
		return nil
	}

	// 无 systemd/procd 环境（如容器或开发机）直接后台守护启动
	_ = m.Stop()
	return startBackgroundDirect(m.binPath, m.aghConfigFile, m.aghWorkDir)
}

// sanitizeOpenWrtDnsmasqTTL 清理 OpenWrt/ImmortalWrt 固件自带 dnsmasq 中可能存在的强制 min_cache_ttl / mini_ttl，
// 防止 1 秒 TTL 的动态节点域名被 dnsmasq 强行篡改缓存 3600 秒。
func sanitizeOpenWrtDnsmasqTTL() {
	if _, err := exec.LookPath("uci"); err != nil {
		return
	}
	changed := false
	for _, key := range []string{"min_cache_ttl", "mini_ttl", "minttl", "use_stale_cache"} {
		target := "dhcp.@dnsmasq[0]." + key
		if out, err := exec.Command("uci", "-q", "get", target).Output(); err == nil && len(strings.TrimSpace(string(out))) > 0 {
			if exec.Command("uci", "-q", "delete", target).Run() == nil {
				changed = true
			}
		}
	}
	if changed {
		_ = exec.Command("uci", "commit", "dhcp").Run()
		_ = exec.Command("/etc/init.d/dnsmasq", "reload").Run()
	}
}

func (m *Manager) waitDNSReady(maxWait time.Duration) error {
	dnsAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(m.cfg.DNS.GetDNSPort()))
	deadline := time.Now().Add(maxWait)
	var lastErr error
	for time.Now().Before(deadline) {
		if err := ProbeDNS(dnsAddr, 800*time.Millisecond); err == nil {
			return nil
		} else {
			lastErr = err
		}
		time.Sleep(400 * time.Millisecond)
	}
	return fmt.Errorf("等待 AdGuard Home DNS 端口 (%s) 就绪超时: %v", dnsAddr, lastErr)
}

// Start 启动已安装的 AdGuard Home（若局域网 IP 发生变化会自动同步 Web 监听地址）。
func (m *Manager) Start() error {
	if !m.isBinaryPresent() {
		return fmt.Errorf("AdGuard Home 尚未安装 (%s)，请先运行: singctl dns install", m.binPath)
	}
	if _, err := os.Stat(m.aghConfigFile); os.IsNotExist(err) {
		m.cfg.DNS.EnsureCredentials("")
		if m.configPath != "" {
			_ = config.Save(m.configPath, m.cfg)
		}
		if err := m.ensureConfigFile(sanitizeWebBindIP(netinfo.GetPrimaryLANIPv4()), true); err != nil {
			return err
		}
	} else {
		// 自动修正局域网 IP 漂移（例如 DHCP 旁路由更换了网段 IP）
		lanIP := sanitizeWebBindIP(netinfo.GetPrimaryLANIPv4())
		_, _ = SyncExistingConfig(m.aghConfigFile, SyncOptions{
			LANIP:   lanIP,
			WebPort: m.cfg.DNS.GetWebPort(),
			DNSPort: m.cfg.DNS.GetDNSPort(),
		})
	}

	if err := m.installAndStartService(); err != nil {
		return err
	}
	if err := m.waitDNSReady(10 * time.Second); err != nil {
		return err
	}
	_ = os.Chmod(m.aghConfigFile, 0600)
	return nil
}

// Stop 停止正在运行的 AdGuard Home 服务。
func (m *Manager) Stop() error {
	if hasOpenWrtProcd() && m.initdScript != "" {
		if _, err := os.Stat(m.initdScript); err == nil {
			_ = exec.Command(m.initdScript, "stop").Run()
		}
	}
	if hasSystemd() {
		_ = exec.Command("systemctl", "stop", "AdGuardHome").Run()
	}
	if isProcessRunning() {
		_ = exec.Command("pkill", "-f", "AdGuardHome").Run()
		_ = exec.Command("killall", "AdGuardHome").Run()
		for range 10 {
			if !isProcessRunning() {
				break
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
	return nil
}

// Restart 重启 AdGuard Home。
func (m *Manager) Restart() error {
	_ = m.Stop()
	return m.Start()
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
		lanIP := sanitizeWebBindIP(netinfo.GetPrimaryLANIPv4())
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

// Uninstall 停止并卸载 AdGuard Home 服务与二进制（可选保留或清理配置目录）。
func (m *Manager) Uninstall(purgeConfig bool) error {
	_ = m.Stop()

	if hasOpenWrtProcd() && m.initdScript != "" {
		_ = exec.Command(m.initdScript, "disable").Run()
		_ = os.Remove(m.initdScript)
	}
	if hasSystemd() && m.systemdUnit != "" {
		_ = exec.Command("systemctl", "disable", "AdGuardHome").Run()
		_ = os.Remove(m.systemdUnit)
		_ = exec.Command("systemctl", "daemon-reload").Run()
	}
	if m.binPath != "" {
		_ = os.Remove(m.binPath)
	}
	if purgeConfig && m.aghConfigDir != "" {
		_ = os.RemoveAll(m.aghConfigDir)
	}

	m.cfg.DNS.SetEnabled(false)
	if m.configPath != "" {
		_ = config.Save(m.configPath, m.cfg)
	}
	return nil
}

// EnsureHealthy 供看门狗守护进程调用：若已安装且启用但 DNS 端口失联，自动拉起恢复。
func (m *Manager) EnsureHealthy() error {
	if !m.cfg.DNS.IsEnabled() || !m.isBinaryPresent() {
		return nil
	}
	dnsAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(m.cfg.DNS.GetDNSPort()))
	if err := ProbeDNS(dnsAddr, 1500*time.Millisecond); err == nil {
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
		lanIP := sanitizeWebBindIP(netinfo.GetPrimaryLANIPv4())
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
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		out, err := exec.CommandContext(ctx, m.binPath, "--version").Output()
		cancel()
		if err == nil {
			st.Version = strings.TrimSpace(string(out))
		}
		st.DNSHealthy = ProbeDNS(dnsAddr, 1200*time.Millisecond) == nil
		st.WebHealthy = ProbeTCPPort(webAddr, 1000*time.Millisecond)
		st.Running = st.DNSHealthy || isProcessRunning()
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
