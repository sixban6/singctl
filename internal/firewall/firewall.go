// 文件职责：提供防火墙配置归一化、SSH 防锁死端口探测、nftables 规则编译与跨平台启停持久化。
package firewall

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"

	"singctl/internal/common/fsx"
	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/logger"
	"singctl/internal/platform/servicemgr"
)

const (
	// DefaultConfigPath 是 `singctl fw enable` 未传配置文件路径时尝试读取的默认配置位置。
	DefaultConfigPath = "/etc/singctl/singctl.yaml"
)

// PortCatalogEntry 描述常见受保护端口及其语义标签，供 WebUI 可视化展示与选择。
type PortCatalogEntry struct {
	Port  int    `json:"port"`
	Label string `json:"label"`
}

var defaultBaseProtectedPorts = []int{
	20, 21, 22, 23, // FTP, SSH (auto-excluded if sshd/dropbear uses 22), Telnet
	25, 110, 465, 587, 993, 995, // Mail protocols
	1433, 1434, // MSSQL
	1521, // Oracle
	3306, // MySQL
	3389, // RDP
	6379, // Redis
}

var defaultWhitelistV4 = []string{
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"100.64.0.0/10",
}

var defaultForeverBlocklistV4 = []string{
	"167.94.138.0/24",
	"167.94.145.0/24",
	"167.94.146.0/24",
	"198.235.24.0/24",
	"205.210.31.0/24",
	"64.62.197.0/24",
	"64.62.156.0/24",
	"80.82.77.0/24",
	"89.248.0.0/16",
	"193.163.125.0/24",
	"185.224.128.0/24",
	"154.213.184.0/24",
	"79.124.58.0/24",
	"79.124.60.0/24",
	"95.214.27.0/24",
	"94.156.66.0/24",
	"94.156.71.0/24",
	"90.151.171.0/24",
	"78.128.114.0/24",
	"122.14.229.0/24",
}

var defaultPortCatalog = []PortCatalogEntry{
	{Port: 20, Label: "FTP 数据"},
	{Port: 21, Label: "FTP"},
	{Port: 22, Label: "SSH"},
	{Port: 23, Label: "Telnet"},
	{Port: 25, Label: "SMTP"},
	{Port: 110, Label: "POP3"},
	{Port: 143, Label: "IMAP"},
	{Port: 465, Label: "SMTPS"},
	{Port: 587, Label: "Mail Submission"},
	{Port: 993, Label: "IMAPS"},
	{Port: 995, Label: "POP3S"},
	{Port: 1080, Label: "SOCKS 代理"},
	{Port: 1433, Label: "MSSQL"},
	{Port: 1434, Label: "MSSQL Browser"},
	{Port: 1521, Label: "Oracle DB"},
	{Port: 3306, Label: "MySQL"},
	{Port: 3389, Label: "RDP 远程桌面"},
	{Port: 5432, Label: "PostgreSQL"},
	{Port: 6379, Label: "Redis"},
	{Port: 27017, Label: "MongoDB"},
}

// criticalServiceExemptPorts 禁止作为诱捕端口（避免网关自身 HTTP/HTTPS/DNS/WebUI/TProxy/Tailscale 被公网探测连带锁定）。
var criticalServiceExemptPorts = []int{53, 80, 443, 3000, 5353, 7895, 8090, 41641}

// DefaultProtectedPorts 返回默认高危诱捕端口列表副本。
func DefaultProtectedPorts() []int {
	return slices.Clone(defaultBaseProtectedPorts)
}

// DefaultWhitelistV4 返回内置防自锁私网/Tailscale 白名单副本。
func DefaultWhitelistV4() []string {
	return slices.Clone(defaultWhitelistV4)
}

// DefaultForeverBlocklistV4 返回内置公网扫描黑名单网段列表副本。
func DefaultForeverBlocklistV4() []string {
	return slices.Clone(defaultForeverBlocklistV4)
}

// PortCatalog 返回常见端口与用途字典副本，供 WebUI 展示标签。
func PortCatalog() []PortCatalogEntry {
	return slices.Clone(defaultPortCatalog)
}

// BuildOptions 控制 `nftables inet security` 规则表的生成参数。
type BuildOptions struct {
	SSHConnection        string
	CallerIP             string
	ActiveSSHPorts       []int
	Mode                 string // "standard" | "minimal"
	BanTimeoutDays       int    // 1..30 (default 7)
	PingLimitPerSec      int    // 1..100 (default 10)
	CustomWhitelist      []string
	ExtraForeverBan      []string
	CustomProtectedPorts []int
}

// OptionsFromConfig 从 SingCtl 配置与当前访问源合成安全的 BuildOptions（自动探测并豁免激活的 SSH 端口）。
func OptionsFromConfig(cfg *config.Config, callerIP string) BuildOptions {
	opts := BuildOptions{
		SSHConnection:   os.Getenv("SSH_CONNECTION"),
		CallerIP:        strings.TrimSpace(callerIP),
		ActiveSSHPorts:  DetectSSHPorts(),
		Mode:            "standard",
		BanTimeoutDays:  7,
		PingLimitPerSec: 10,
	}
	if cfg != nil {
		opts.Mode = cfg.Firewall.EffectiveMode()
		opts.BanTimeoutDays = cfg.Firewall.EffectiveBanTimeoutDays()
		opts.PingLimitPerSec = cfg.Firewall.EffectivePingLimitPerSec()
		opts.CustomWhitelist = slices.Clone(cfg.Firewall.Whitelist)
		opts.ExtraForeverBan = slices.Clone(cfg.Firewall.ExtraForeverBan)
		opts.CustomProtectedPorts = slices.Clone(cfg.Firewall.ProtectedPorts)
	}
	return opts
}

// DetectSSHPorts inspects OpenSSH, OpenWrt Dropbear, and SSH_CONNECTION to avoid locking out active SSH ports.
func DetectSSHPorts() []int {
	files := []string{"/etc/ssh/sshd_config"}
	if extra, err := filepath.Glob("/etc/ssh/sshd_config.d/*.conf"); err == nil {
		files = append(files, extra...)
	}
	return DetectSSHPortsFrom(os.Getenv("SSH_CONNECTION"), files, "/etc/config/dropbear")
}

// DetectSSHPortsFrom 从指定的 SSH_CONNECTION 环境变量、OpenSSH 配置列表与 Dropbear 配置路径解析活跃 SSH 端口。
func DetectSSHPortsFrom(sshConn string, sshdFiles []string, dropbearFile string) []int {
	var ports []int
	ports = appendUniquePort(ports, parseSSHConnServerPort(sshConn))

	foundExplicit := false
	for _, f := range sshdFiles {
		raw, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, p := range parseSSHDPortDirectives(string(raw)) {
			ports = appendUniquePort(ports, p)
			foundExplicit = true
		}
	}

	if strings.TrimSpace(dropbearFile) != "" {
		if raw, err := os.ReadFile(dropbearFile); err == nil {
			for _, p := range parseDropbearPortDirectives(string(raw)) {
				ports = appendUniquePort(ports, p)
				foundExplicit = true
			}
		}
	}

	if !foundExplicit && len(ports) == 0 {
		ports = appendUniquePort(ports, 22)
	}
	return ports
}

func appendUniquePort(ports []int, p int) []int {
	if p <= 0 || p > 65535 || slices.Contains(ports, p) {
		return ports
	}
	return append(ports, p)
}

func parseSSHConnServerPort(sshConn string) int {
	fields := strings.Fields(sshConn)
	if len(fields) != 4 {
		return 0
	}
	p, err := strconv.Atoi(fields[3])
	if err != nil {
		return 0
	}
	return p
}

func parseSSHDPortDirectives(content string) []int {
	var out []int
	for line := range strings.SplitSeq(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		parts := strings.Fields(trimmed)
		if len(parts) < 2 || !strings.EqualFold(parts[0], "Port") {
			continue
		}
		if p, err := strconv.Atoi(parts[1]); err == nil {
			out = append(out, p)
		}
	}
	return out
}

func parseDropbearPortDirectives(content string) []int {
	var out []int
	for line := range strings.SplitSeq(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		parts := strings.Fields(trimmed)
		if len(parts) < 3 || !strings.EqualFold(parts[0], "option") || !strings.EqualFold(parts[1], "Port") {
			continue
		}
		if p, err := strconv.Atoi(strings.Trim(parts[2], `"'`)); err == nil {
			out = append(out, p)
		}
	}
	return out
}

// BuildSecurityNFT generates a sanitized nftables security ruleset with default options.
func BuildSecurityNFT(sshConnection string, activeSSHPorts []int) string {
	return BuildSecurityNFTWithOptions(BuildOptions{
		SSHConnection:  sshConnection,
		ActiveSSHPorts: activeSSHPorts,
		Mode:           "standard",
	})
}

// BuildSecurityNFTWithOptions 根据结构化防火墙选项生成防自锁、支持双模式的 nftables `inet security` 规则脚本。
func BuildSecurityNFTWithOptions(opts BuildOptions) string {
	isMinimal := strings.EqualFold(strings.TrimSpace(opts.Mode), "minimal")
	timeoutDays := clampDefaultInt(opts.BanTimeoutDays, 7, 1, 30)
	pingLimit := clampDefaultInt(opts.PingLimitPerSec, 10, 1, 100)

	whitelistV4, whitelistV6 := collectNormalizedWhitelists(opts)
	foreverV4 := collectForeverBlocklistV4(opts.ExtraForeverBan)
	protectedPorts := collectProtectedPorts(opts)

	return renderSecurityNFT(nftSecurityTemplateData{
		ForeverV4:       foreverV4,
		BanTimeoutDays:  timeoutDays,
		WhitelistV4:     whitelistV4,
		WhitelistV6:     whitelistV6,
		ProtectedPorts:  protectedPorts,
		PingLimitPerSec: pingLimit,
		EnableHoneypot:  !isMinimal && len(protectedPorts) > 0,
	})
}

func clampDefaultInt(val, def, lo, hi int) int {
	if val <= 0 {
		val = def
	}
	return min(hi, max(lo, val))
}

func collectNormalizedWhitelists(opts BuildOptions) ([]string, []string) {
	v4 := slices.Clone(defaultWhitelistV4)
	var v6 []string

	if fields := strings.Fields(strings.TrimSpace(opts.SSHConnection)); len(fields) >= 1 {
		v4, v6 = appendWhitelistEntry(fields[0], false, v4, v6)
	}
	if opts.CallerIP != "" {
		v4, v6 = appendWhitelistEntry(opts.CallerIP, false, v4, v6)
	}
	for _, w := range opts.CustomWhitelist {
		v4, v6 = appendWhitelistEntry(w, true, v4, v6)
	}
	return v4, v6
}

func appendWhitelistEntry(raw string, allowPrivate bool, v4, v6 []string) ([]string, []string) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return v4, v6
	}
	if p, err := netip.ParsePrefix(trimmed); err == nil {
		p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()).Masked()
		s := p.String()
		if p.IsSingleIP() {
			s = p.Addr().String()
		}
		if p.Addr().Is4() {
			return appendUniqueString(v4, s), v6
		}
		return v4, appendUniqueString(v6, s)
	}
	addr, err := netip.ParseAddr(trimmed)
	if err != nil {
		return v4, v6
	}
	addr = addr.Unmap()
	if !allowPrivate && (addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast()) {
		return v4, v6
	}
	if addr.Is4() {
		return appendUniqueString(v4, addr.String()), v6
	}
	return v4, appendUniqueString(v6, addr.String())
}

func appendUniqueString(list []string, val string) []string {
	if slices.Contains(list, val) {
		return list
	}
	return append(list, val)
}

func collectForeverBlocklistV4(extra []string) []string {
	foreverV4 := slices.Clone(defaultForeverBlocklistV4)
	for _, raw := range extra {
		if norm, isV6, err := validateForeverBanCIDR(raw); err == nil && !isV6 {
			foreverV4 = appendUniqueString(foreverV4, norm)
		}
	}
	return foreverV4
}

func collectProtectedPorts(opts BuildOptions) []int {
	basePorts := defaultBaseProtectedPorts
	hasCustom := len(opts.CustomProtectedPorts) > 0
	if hasCustom {
		basePorts = opts.CustomProtectedPorts
	}
	var ports []int
	for _, p := range basePorts {
		if p <= 0 || p > 65535 || slices.Contains(ports, p) {
			continue
		}
		if slices.Contains(opts.ActiveSSHPorts, p) || slices.Contains(criticalServiceExemptPorts, p) {
			continue
		}
		ports = append(ports, p)
	}
	if hasCustom {
		sort.Ints(ports)
	}
	return ports
}

func validateForeverBanCIDR(raw string) (string, bool, error) {
	return ValidateBanTarget(raw, "forever", "", nil)
}

// Enable writes sec_block.nft to /etc/sing-box/ and loads it using nft, honoring saved firewall config if present.
func Enable() error {
	var cfg *config.Config
	if loaded, err := config.Load(DefaultConfigPath); err == nil {
		cfg = loaded
	}
	return EnableWithOptions(OptionsFromConfig(cfg, ""), true)
}

// EnableWithOptions 使用指定选项写盘、校验并热加载 `nftables inet security` 表；当 preserveDynamic=true 时迁移保留现有动态黑牢。
func EnableWithOptions(opts BuildOptions, preserveDynamic bool) error {
	if err := ensureLinuxRootNFT(); err != nil {
		return err
	}
	if err := os.MkdirAll(constant.SingBoxConfigDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory %s: %v", constant.SingBoxConfigDir, err)
	}
	if len(opts.ActiveSSHPorts) == 0 {
		opts.ActiveSSHPorts = DetectSSHPorts()
	}
	if opts.SSHConnection == "" {
		opts.SSHConnection = os.Getenv("SSH_CONNECTION")
	}

	dynamicV4, dynamicV6 := snapshotLiveDynamicBans(preserveDynamic)
	scriptPath := constant.SingBoxNftablesFile
	if err := fsx.WriteAtomic0600(scriptPath, []byte(BuildSecurityNFTWithOptions(opts))); err != nil {
		return fmt.Errorf("failed to write %s: %v", scriptPath, err)
	}

	preloadNFTablesModule()
	if out, err := exec.Command("nft", "-c", "-f", scriptPath).CombinedOutput(); err != nil {
		return fmt.Errorf("nftables syntax check failed: %v\nOutput: %s", err, string(out))
	}
	_ = exec.Command("nft", "delete", "table", "inet", "security").Run()

	logger.Info("Loading nftables rules from %s...", scriptPath)
	if out, err := exec.Command("nft", "-f", scriptPath).CombinedOutput(); err != nil {
		return fmt.Errorf("failed to load nftables rules: %v\nOutput: %s", err, string(out))
	}
	if preserveDynamic && (len(dynamicV4) > 0 || len(dynamicV6) > 0) {
		if restoreErr := restoreDynamicBans(dynamicV4, dynamicV6); restoreErr != nil {
			logger.Warn("Dynamic ban snapshot restore partial/failed: %v", restoreErr)
		}
	}
	persistAutostartService()
	logger.Success("Security block rules applied successfully")
	return nil
}

func ensureLinuxRootNFT() error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("firewall commands are only supported on Linux")
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("this command requires root privileges (run with sudo)")
	}
	if _, err := exec.LookPath("nft"); err != nil {
		return fmt.Errorf("nft command not found, please install nftables")
	}
	return nil
}

func snapshotLiveDynamicBans(preserve bool) ([]BanItem, []BanItem) {
	if !preserve {
		return nil, nil
	}
	snap, err := readLiveSecurityTable()
	if err != nil || snap == nil {
		return nil, nil
	}
	return slices.Clone(snap.DynamicV4), slices.Clone(snap.DynamicV6)
}

func persistAutostartService() {
	var err error
	if servicemgr.IsOpenWrt() {
		logger.Info("Detected OpenWrt system, setting up init.d service...")
		err = setupOpenWrtInit()
	} else {
		logger.Info("Setting up systemd service...")
		err = setupSystemdService()
	}
	if err != nil {
		logger.Warn("Rules applied, but failed to setup auto-start service: %v", err)
		return
	}
	logger.Success("Auto-start persistence configured successfully")
}

func restoreDynamicBans(v4, v6 []BanItem) error {
	if err := restoreDynamicBanSet("blocklist_ip4", v4); err != nil {
		return err
	}
	return restoreDynamicBanSet("blocklist_ip6", v6)
}

func restoreDynamicBanSet(setName string, items []BanItem) error {
	const chunkSize = 400
	for i := 0; i < len(items); i += chunkSize {
		end := min(len(items), i+chunkSize)
		var elems []string
		for _, it := range items[i:end] {
			if net.ParseIP(it.Target) == nil {
				continue
			}
			elems = append(elems, fmt.Sprintf("%s timeout %ds", it.Target, max(int64(60), it.ExpiresSec)))
		}
		if len(elems) == 0 {
			continue
		}
		script := fmt.Sprintf("add element inet security %s { %s }\n", setName, strings.Join(elems, ", "))
		cmd := exec.Command("nft", "-f", "-")
		cmd.Stdin = bytes.NewBufferString(script)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("%s restore error: %v (%s)", setName, err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

// Disable removes security rules and auto-start persistence.
func Disable() error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("firewall commands are only supported on Linux")
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("this command requires root privileges (run with sudo)")
	}
	if servicemgr.IsOpenWrt() {
		teardownOpenWrtInit()
	} else {
		teardownSystemdService()
	}
	_ = exec.Command("nft", "delete", "table", "inet", "security").Run()
	_ = os.Remove(constant.SingBoxNftablesFile)
	logger.Success("Security block rules disabled and removed")
	return nil
}

func preloadNFTablesModule() {
	for _, bin := range []string{"modprobe", "/sbin/modprobe", "/usr/sbin/modprobe"} {
		if _, err := exec.LookPath(bin); err == nil {
			_ = exec.Command(bin, "nf_tables").Run()
			return
		}
	}
}

func setupSystemdService() error {
	ctx := context.Background()
	content := BuildFirewallSystemdUnit(constant.SingBoxNftablesFile)
	if err := os.WriteFile(constant.FirewallSystemdService, []byte(content), 0644); err != nil {
		return err
	}
	mgr := servicemgr.NewSystemd(nil)
	_ = mgr.DaemonReload(ctx)
	if err := mgr.Enable(ctx, "singctl-firewall.service"); err != nil {
		return err
	}
	return mgr.Start(ctx, "singctl-firewall.service")
}

func teardownSystemdService() {
	_ = servicemgr.NewSystemd(nil).RemoveUnit(context.Background(), servicemgr.UnitSpec{
		Name:        "singctl-firewall.service",
		SystemdPath: constant.FirewallSystemdService,
	})
}

func setupOpenWrtInit() error {
	scriptPath := constant.FirewallInitdScript
	content := renderOpenWrtInitScript(constant.SingBoxNftablesFile)
	if err := os.WriteFile(scriptPath, []byte(content), 0755); err != nil {
		return err
	}
	return servicemgr.NewProcd(nil, filepath.Dir(scriptPath)).Enable(context.Background(), filepath.Base(scriptPath))
}

func teardownOpenWrtInit() {
	scriptPath := constant.FirewallInitdScript
	if _, err := os.Stat(scriptPath); err == nil {
		_ = servicemgr.NewProcd(nil, filepath.Dir(scriptPath)).RemoveUnit(context.Background(), servicemgr.UnitSpec{
			Name:      filepath.Base(scriptPath),
			ProcdPath: scriptPath,
		})
	}
}

func fileExists(path string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}
