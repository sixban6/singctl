package firewall

import (
	"bytes"
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

	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/logger"
	"singctl/internal/util/file"
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
	return detectSSHPortsFrom(os.Getenv("SSH_CONNECTION"), files, "/etc/config/dropbear")
}

func detectSSHPortsFrom(sshConn string, sshdFiles []string, dropbearFile string) []int {
	var ports []int
	addPort := func(p int) {
		if p > 0 && p <= 65535 && !slices.Contains(ports, p) {
			ports = append(ports, p)
		}
	}

	// 1. Inspect current SSH_CONNECTION ("<client_ip> <client_port> <server_ip> <server_port>")
	fields := strings.Fields(sshConn)
	if len(fields) == 4 {
		if p, err := strconv.Atoi(fields[3]); err == nil {
			addPort(p)
		}
	}

	// 2. Inspect OpenSSH configs (/etc/ssh/sshd_config and /etc/ssh/sshd_config.d/*.conf)
	foundExplicitPort := false
	for _, f := range sshdFiles {
		raw, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for line := range strings.SplitSeq(string(raw), "\n") {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}
			parts := strings.Fields(trimmed)
			if len(parts) >= 2 && strings.EqualFold(parts[0], "Port") {
				if p, err := strconv.Atoi(parts[1]); err == nil {
					addPort(p)
					foundExplicitPort = true
				}
			}
		}
	}

	// 3. Inspect OpenWrt /etc/config/dropbear (`option Port '2222'`)
	if strings.TrimSpace(dropbearFile) != "" {
		if raw, err := os.ReadFile(dropbearFile); err == nil {
			for line := range strings.SplitSeq(string(raw), "\n") {
				trimmed := strings.TrimSpace(line)
				if trimmed == "" || strings.HasPrefix(trimmed, "#") {
					continue
				}
				parts := strings.Fields(trimmed)
				if len(parts) >= 3 && strings.EqualFold(parts[0], "option") && strings.EqualFold(parts[1], "Port") {
					val := strings.Trim(parts[2], `"'`)
					if p, err := strconv.Atoi(val); err == nil {
						addPort(p)
						foundExplicitPort = true
					}
				}
			}
		}
	}

	// Default OpenSSH/Dropbear port is 22 when no explicit Port directive is configured
	if !foundExplicitPort && len(ports) == 0 {
		addPort(22)
	}
	return ports
}

// BuildSecurityNFT generates a sanitized nftables security ruleset with default options.
// It whitelists RFC1918 + CGNAT/Tailscale ranges and the current SSH client IP (if any),
// and excludes active SSH daemon ports from protected_ports to prevent self-lockout.
func BuildSecurityNFT(sshConnection string, activeSSHPorts []int) string {
	return BuildSecurityNFTWithOptions(BuildOptions{
		SSHConnection:  sshConnection,
		ActiveSSHPorts: activeSSHPorts,
		Mode:           "standard",
	})
}

// BuildSecurityNFTWithOptions 根据结构化防火墙选项生成防自锁、支持双模式的 nftables `inet security` 规则脚本。
func BuildSecurityNFTWithOptions(opts BuildOptions) string {
	mode := "standard"
	if strings.EqualFold(strings.TrimSpace(opts.Mode), "minimal") {
		mode = "minimal"
	}
	timeoutDays := opts.BanTimeoutDays
	if timeoutDays <= 0 {
		timeoutDays = 7
	}
	timeoutDays = min(30, max(1, timeoutDays))

	pingLimit := opts.PingLimitPerSec
	if pingLimit <= 0 {
		pingLimit = 10
	}
	pingLimit = min(100, max(1, pingLimit))

	whitelistV4 := slices.Clone(defaultWhitelistV4)
	var whitelistV6 []string

	appendPublicOrCustomWhitelist := func(raw string, allowPrivate bool) {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			return
		}
		if p, err := netip.ParsePrefix(trimmed); err == nil {
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()).Masked()
			s := p.String()
			if p.IsSingleIP() {
				s = p.Addr().String()
			}
			if p.Addr().Is4() {
				if !slices.Contains(whitelistV4, s) {
					whitelistV4 = append(whitelistV4, s)
				}
			} else if !slices.Contains(whitelistV6, s) {
				whitelistV6 = append(whitelistV6, s)
			}
			return
		}
		if addr, err := netip.ParseAddr(trimmed); err == nil {
			addr = addr.Unmap()
			if !allowPrivate && (addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast()) {
				return
			}
			s := addr.String()
			if addr.Is4() {
				if !slices.Contains(whitelistV4, s) {
					whitelistV4 = append(whitelistV4, s)
				}
			} else if !slices.Contains(whitelistV6, s) {
				whitelistV6 = append(whitelistV6, s)
			}
		}
	}

	if fields := strings.Fields(strings.TrimSpace(opts.SSHConnection)); len(fields) >= 1 {
		appendPublicOrCustomWhitelist(fields[0], false)
	}
	if opts.CallerIP != "" {
		appendPublicOrCustomWhitelist(opts.CallerIP, false)
	}
	for _, w := range opts.CustomWhitelist {
		appendPublicOrCustomWhitelist(w, true)
	}

	foreverV4 := slices.Clone(defaultForeverBlocklistV4)
	for _, extra := range opts.ExtraForeverBan {
		if norm, isV6, err := validateForeverBanCIDR(extra); err == nil && !isV6 && !slices.Contains(foreverV4, norm) {
			foreverV4 = append(foreverV4, norm)
		}
	}

	var foreverBlock strings.Builder
	for i, cidr := range foreverV4 {
		if i > 0 {
			foreverBlock.WriteString(",\n          ")
		}
		foreverBlock.WriteString(cidr)
	}

	var v6ElemsLine string
	if len(whitelistV6) > 0 {
		v6ElemsLine = fmt.Sprintf("\n        elements = { %s }", strings.Join(whitelistV6, ", "))
	}

	basePorts := defaultBaseProtectedPorts
	if len(opts.CustomProtectedPorts) > 0 {
		basePorts = opts.CustomProtectedPorts
	}
	var protected []string
	var seenPorts []int
	for _, p := range basePorts {
		if p <= 0 || p > 65535 || slices.Contains(seenPorts, p) {
			continue
		}
		if slices.Contains(opts.ActiveSSHPorts, p) || slices.Contains(criticalServiceExemptPorts, p) {
			continue
		}
		seenPorts = append(seenPorts, p)
		protected = append(protected, strconv.Itoa(p))
	}
	sort.Slice(seenPorts, func(i, j int) bool { return seenPorts[i] < seenPorts[j] })
	if len(opts.CustomProtectedPorts) > 0 {
		protected = protected[:0]
		for _, p := range seenPorts {
			protected = append(protected, strconv.Itoa(p))
		}
	}

	protectedSetSection := ""
	honeypotRulesSection := ""
	if mode != "minimal" && len(protected) > 0 {
		protectedSetSection = fmt.Sprintf(`
    set protected_ports {
        type inet_service
        flags interval
        elements = {
            %s
        }
    }
`, strings.Join(protected, ",\n            "))
		honeypotRulesSection = `

        # 记录并处理 IPv4 受保护端口的连接尝试 (TCP & UDP)
        meta l4proto tcp tcp dport @protected_ports \
            log prefix "[NFT] Blocked IPv4 TCP: " \
            add @blocklist_ip4 { ip saddr limit rate 5/minute } \
            counter drop
        meta l4proto udp udp dport @protected_ports \
            log prefix "[NFT] Blocked IPv4 UDP: " \
            add @blocklist_ip4 { ip saddr limit rate 5/minute } \
            counter drop

        # 记录并处理 IPv6 受保护端口的连接尝试 (TCP & UDP)
        meta l4proto tcp tcp dport @protected_ports \
            log prefix "[NFT] Blocked IPv6 TCP: " \
            add @blocklist_ip6 { ip6 saddr limit rate 5/minute } \
            counter drop
        meta l4proto udp udp dport @protected_ports \
            log prefix "[NFT] Blocked IPv6 UDP: " \
            add @blocklist_ip6 { ip6 saddr limit rate 5/minute } \
            counter drop`
	}

	return fmt.Sprintf(`#!/usr/sbin/nft -f

table inet security {

    set blocklist_ip4_forever {
        type ipv4_addr
        flags interval
        auto-merge
        size 65535
        elements = {
          %s
        }
    }

    set blocklist_ip4 {
        type ipv4_addr
        flags dynamic,timeout
        size 65535
        timeout %dd
    }

    set blocklist_ip6 {
        type ipv6_addr
        flags dynamic,timeout
        size 65535
        timeout %dd
    }

    set whitelist_ip {
        type ipv4_addr
        flags interval
        auto-merge
        elements = { %s }
    }

    set whitelist_ip6 {
        type ipv6_addr
        flags interval
        auto-merge%s
    }
%s
    chain input {
        type filter hook input priority 0; policy accept;

        # 优先处理已建立的连接，提高性能
        ct state established,related counter accept

        # 允许回环接口和常见虚拟网络接口的流量
        iifname "lo" counter accept
        iifname "tailscale0" counter accept
        iifname "wg*" counter accept
        iifname "tun*" counter accept
        iifname "docker0" counter accept

        # 限制 ICMP (Ping) 频率
        ip protocol icmp icmp type echo-request limit rate %d/second counter accept
        ip6 nexthdr icmpv6 icmpv6 type echo-request limit rate %d/second counter accept

        # 允许来自白名单 IP 的所有连接
        ip saddr @whitelist_ip counter accept
        ip6 saddr @whitelist_ip6 counter accept

        ip saddr @blocklist_ip4_forever log prefix "[NFT] Ban Forever IPv4 (listed): " counter drop

        # 记录并丢弃来自 IPv4 黑名单的连接
        ip saddr @blocklist_ip4 \
            log prefix "[NFT] Blocked IPv4 (listed): " \
            counter drop

        # 记录并丢弃来自 IPv6 黑名单的连接
        ip6 saddr @blocklist_ip6 \
            log prefix "[NFT] Blocked IPv6 (listed): " \
            counter drop%s
    }

}
`, foreverBlock.String(), timeoutDays, timeoutDays, strings.Join(whitelistV4, ", "), v6ElemsLine, protectedSetSection, pingLimit, pingLimit, honeypotRulesSection)
}

func validateForeverBanCIDR(raw string) (string, bool, error) {
	norm, isV6, err := ValidateBanTarget(raw, "forever", "", nil)
	return norm, isV6, err
}

// BuildMinimalBlocklistNFT 生成零端口拦截的最小安全黑名单表（仅包含私网/Tailscale 白名单、已建立连接放行与黑名单集合丢包）。
// 供从未执行过 `singctl fw enable` 的主机在触发「一键拉黑」时按需初始化，彻底杜绝任何 SSH 端口误封锁死风险。
func BuildMinimalBlocklistNFT() string {
	return `table inet security {
    set blocklist_ip4_forever {
        type ipv4_addr
        flags interval
        auto-merge
        size 65535
    }
    set blocklist_ip4 {
        type ipv4_addr
        flags dynamic,timeout
        size 65535
        timeout 7d
    }
    set blocklist_ip6 {
        type ipv6_addr
        flags dynamic,timeout
        size 65535
        timeout 7d
    }
    set whitelist_ip {
        type ipv4_addr
        flags interval
        auto-merge
        elements = { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10 }
    }
    set whitelist_ip6 {
        type ipv6_addr
        flags interval
        auto-merge
    }
    chain input {
        type filter hook input priority 0; policy accept;
        ct state established,related counter accept
        iifname "lo" counter accept
        iifname "tailscale0" counter accept
        iifname "wg*" counter accept
        iifname "tun*" counter accept
        ip saddr @whitelist_ip counter accept
        ip6 saddr @whitelist_ip6 counter accept
        ip saddr @blocklist_ip4_forever log prefix "[NFT] Ban Forever IPv4 (listed): " counter drop
        ip saddr @blocklist_ip4 log prefix "[NFT] Blocked IPv4 (listed): " counter drop
        ip6 saddr @blocklist_ip6 log prefix "[NFT] Blocked IPv6 (listed): " counter drop
    }
}
`
}

// BuildFirewallSystemdUnit 生成带 nf_tables 内核模块预加载与开机 Netlink 重试机制的 systemd 单元。
// 解决部分 KVM/Debian VPS 开机早期 nf_tables 模块尚未注册 Netlink 时 `nft -f` 报
// "Unable to initialize Netlink socket: Protocol not supported" 退出导致丢表的问题。
func BuildFirewallSystemdUnit(scriptPath string) string {
	return fmt.Sprintf(`[Unit]
Description=Singctl Security NFTables Rules
# 确保在网络、内核模块加载及主流防火墙就绪后加载，避免早期 Netlink 未初始化或规则被冲刷
After=network.target systemd-modules-load.service nftables.service firewalld.service ufw.service

[Service]
Type=oneshot
ExecStartPre=-/bin/sh -c 'modprobe nf_tables 2>/dev/null || /sbin/modprobe nf_tables 2>/dev/null || true'
ExecStart=/bin/sh -c 'i=0; while [ "$i" -lt 5 ]; do /usr/sbin/nft -f "%s" && exit 0; modprobe nf_tables 2>/dev/null || /sbin/modprobe nf_tables 2>/dev/null || true; sleep 1; i=$((i + 1)); done; exec /usr/sbin/nft -f "%s"'
ExecStop=-/usr/sbin/nft delete table inet security
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
`, scriptPath, scriptPath)
}

const openwrtInitScript = `#!/bin/sh /etc/rc.common

START=99
STOP=10

start() {
	echo "Loading singctl security firewall rules..."
	modprobe nf_tables 2>/dev/null || true
	/usr/sbin/nft -f %s
}

stop() {
	echo "Removing singctl security firewall rules..."
	/usr/sbin/nft delete table inet security 2>/dev/null || true
}
`

// isOpenWrt 检查是否为 OpenWrt 系统
func isOpenWrt() bool {
	if _, err := os.Stat("/etc/openwrt_release"); err == nil {
		return true
	}
	if _, err := os.Stat("/etc/openwrt_version"); err == nil {
		return true
	}
	return false
}

// Enable writes sec_block.nft to /etc/sing-box/ and loads it using nft, honoring saved firewall config if present.
// It preserves currently jailed dynamic attacker elements across reloads and configures auto-start persistence.
func Enable() error {
	var cfg *config.Config
	if loaded, err := config.Load(DefaultConfigPath); err == nil {
		cfg = loaded
	}
	return EnableWithOptions(OptionsFromConfig(cfg, ""), true)
}

// EnableWithOptions 使用指定选项写盘、校验并热加载 `nftables inet security` 表；当 preserveDynamic=true 时迁移保留现有动态黑牢。
func EnableWithOptions(opts BuildOptions, preserveDynamic bool) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("firewall commands are only supported on Linux")
	}

	if os.Geteuid() != 0 {
		return fmt.Errorf("this command requires root privileges (run with sudo)")
	}

	if _, err := exec.LookPath("nft"); err != nil {
		return fmt.Errorf("nft command not found, please install nftables")
	}

	configDir := constant.SingBoxConfigDir
	scriptPath := constant.SingBoxNftablesFile

	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory %s: %v", configDir, err)
	}

	if len(opts.ActiveSSHPorts) == 0 {
		opts.ActiveSSHPorts = DetectSSHPorts()
	}
	if opts.SSHConnection == "" {
		opts.SSHConnection = os.Getenv("SSH_CONNECTION")
	}

	var dynamicV4, dynamicV6 []BanItem
	if preserveDynamic {
		if snap, err := readLiveSecurityTable(); err == nil && snap != nil {
			for _, item := range snap.DynamicV4 {
				dynamicV4 = append(dynamicV4, item)
			}
			for _, item := range snap.DynamicV6 {
				dynamicV6 = append(dynamicV6, item)
			}
		}
	}

	nftRules := BuildSecurityNFTWithOptions(opts)
	if err := file.WriteAtomic0600(scriptPath, []byte(nftRules)); err != nil {
		return fmt.Errorf("failed to write %s: %v", scriptPath, err)
	}

	preloadNFTablesModule()

	// 1. 预校验语法并清理旧表，确保重复执行幂等且绝不追加重复规则
	if out, err := exec.Command("nft", "-c", "-f", scriptPath).CombinedOutput(); err != nil {
		return fmt.Errorf("nftables syntax check failed: %v\nOutput: %s", err, string(out))
	}
	_ = exec.Command("nft", "delete", "table", "inet", "security").Run()

	// 2. 本次执行，立即生效
	logger.Info("Loading nftables rules from %s...", scriptPath)
	cmd := exec.Command("nft", "-f", scriptPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to load nftables rules: %v\nOutput: %s", err, string(output))
	}

	// 3. 热迁移回填原有的动态封禁黑名单（不清空已有扫描器 TTL）
	if preserveDynamic && (len(dynamicV4) > 0 || len(dynamicV6) > 0) {
		if restoreErr := restoreDynamicBans(dynamicV4, dynamicV6); restoreErr != nil {
			logger.Warn("Dynamic ban snapshot restore partial/failed: %v", restoreErr)
		}
	}

	// 4. 部署跨平台开机自启
	var persistErr error
	if isOpenWrt() {
		logger.Info("Detected OpenWrt system, setting up init.d service...")
		persistErr = setupOpenWrtInit()
	} else {
		logger.Info("Setting up systemd service...")
		persistErr = setupSystemdService()
	}

	if persistErr != nil {
		logger.Warn("Rules applied, but failed to setup auto-start service: %v", persistErr)
	} else {
		logger.Success("Auto-start persistence configured successfully")
	}

	logger.Success("Security block rules applied successfully")
	return nil
}

func restoreDynamicBans(v4, v6 []BanItem) error {
	restoreSet := func(setName string, items []BanItem) error {
		const chunkSize = 400
		for i := 0; i < len(items); i += chunkSize {
			end := min(len(items), i+chunkSize)
			var elems []string
			for _, it := range items[i:end] {
				if net.ParseIP(it.Target) == nil {
					continue
				}
				ttl := max(int64(60), it.ExpiresSec)
				elems = append(elems, fmt.Sprintf("%s timeout %ds", it.Target, ttl))
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
	if err := restoreSet("blocklist_ip4", v4); err != nil {
		return err
	}
	return restoreSet("blocklist_ip6", v6)
}

// Disable removes security rules and auto-start persistence.
func Disable() error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("firewall commands are only supported on Linux")
	}

	if os.Geteuid() != 0 {
		return fmt.Errorf("this command requires root privileges (run with sudo)")
	}

	// 1. 清理自启服务
	if isOpenWrt() {
		teardownOpenWrtInit()
	} else {
		teardownSystemdService()
	}

	// 2. 从内存中销毁定制化表
	_ = exec.Command("nft", "delete", "table", "inet", "security").Run()

	// 3. 移除规则文件
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

// ----------------- Systemd (Debian / Ubuntu) -----------------
func setupSystemdService() error {
	servicePath := constant.FirewallSystemdService
	content := BuildFirewallSystemdUnit(constant.SingBoxNftablesFile)
	if err := os.WriteFile(servicePath, []byte(content), 0644); err != nil {
		return err
	}
	_ = exec.Command("systemctl", "daemon-reload").Run()
	if err := exec.Command("systemctl", "enable", "--now", "singctl-firewall.service").Run(); err != nil {
		return err
	}
	return nil
}

func teardownSystemdService() {
	_ = exec.Command("systemctl", "disable", "--now", "singctl-firewall.service").Run()
	_ = os.Remove(constant.FirewallSystemdService)
	_ = exec.Command("systemctl", "daemon-reload").Run()
}

// ----------------- init.d (OpenWrt) -----------------
func setupOpenWrtInit() error {
	scriptPath := constant.FirewallInitdScript
	content := fmt.Sprintf(openwrtInitScript, constant.SingBoxNftablesFile)
	if err := os.WriteFile(scriptPath, []byte(content), 0755); err != nil {
		return err
	}
	// 执行 /etc/init.d/singctl-firewall enable (相当于创建 /etc/rc.d/S99singctl-firewall)
	if err := exec.Command(scriptPath, "enable").Run(); err != nil {
		return err
	}
	return nil
}

func teardownOpenWrtInit() {
	scriptPath := constant.FirewallInitdScript
	if _, err := os.Stat(scriptPath); err == nil {
		_ = exec.Command(scriptPath, "disable").Run()
		_ = os.Remove(scriptPath)
	}
}

func fileExists(path string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}
