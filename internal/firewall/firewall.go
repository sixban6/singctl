package firewall

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"

	"singctl/internal/constant"
	"singctl/internal/logger"
)

var defaultBaseProtectedPorts = []int{
	20, 21, 22, 23, // FTP, SSH (auto-excluded if sshd uses 22), Telnet
	25, 110, 465, 587, 993, 995, // Mail protocols
	1080,       // Open SOCKS proxy
	1433, 1434, // MSSQL
	1521, // Oracle
	3306, // MySQL
	3389, // RDP
	6379, // Redis
}

// DetectSSHPorts inspects sshd configuration and SSH_CONNECTION to avoid locking out active SSH ports.
func DetectSSHPorts() []int {
	var ports []int
	addPort := func(p int) {
		if p > 0 && p <= 65535 && !slices.Contains(ports, p) {
			ports = append(ports, p)
		}
	}

	// 1. Inspect current SSH_CONNECTION ("<client_ip> <client_port> <server_ip> <server_port>")
	fields := strings.Fields(os.Getenv("SSH_CONNECTION"))
	if len(fields) == 4 {
		if p, err := strconv.Atoi(fields[3]); err == nil {
			addPort(p)
		}
	}

	// 2. Inspect /etc/ssh/sshd_config and /etc/ssh/sshd_config.d/*.conf
	files := []string{"/etc/ssh/sshd_config"}
	if extra, err := filepath.Glob("/etc/ssh/sshd_config.d/*.conf"); err == nil {
		files = append(files, extra...)
	}
	foundExplicitPort := false
	for _, f := range files {
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

	// Default OpenSSH port is 22 when no explicit Port directive is configured
	if !foundExplicitPort && len(ports) == 0 {
		addPort(22)
	}
	return ports
}

// BuildSecurityNFT generates a sanitized nftables security ruleset.
// It whitelists RFC1918 + CGNAT/Tailscale ranges and the current SSH client IP (if any),
// and excludes active SSH daemon ports from protected_ports to prevent self-lockout.
func BuildSecurityNFT(sshConnection string, activeSSHPorts []int) string {
	whitelistV4 := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"100.64.0.0/10",
	}
	var whitelistV6 []string

	fields := strings.Fields(strings.TrimSpace(sshConnection))
	if len(fields) >= 1 {
		if ip := net.ParseIP(fields[0]); ip != nil && !ip.IsLoopback() && !ip.IsPrivate() {
			if v4 := ip.To4(); v4 != nil {
				s := v4.String()
				if !slices.Contains(whitelistV4, s) {
					whitelistV4 = append(whitelistV4, s)
				}
			} else {
				s := ip.String()
				if !slices.Contains(whitelistV6, s) {
					whitelistV6 = append(whitelistV6, s)
				}
			}
		}
	}

	var protected []string
	for _, p := range defaultBaseProtectedPorts {
		if slices.Contains(activeSSHPorts, p) {
			continue
		}
		protected = append(protected, strconv.Itoa(p))
	}

	v6WhitelistSet := ""
	v6WhitelistRule := ""
	if len(whitelistV6) > 0 {
		v6WhitelistSet = fmt.Sprintf(`
    set whitelist_ip6 {
        type ipv6_addr
        flags interval
        auto-merge
        elements = { %s }
    }
`, strings.Join(whitelistV6, ", "))
		v6WhitelistRule = "\n        ip6 saddr @whitelist_ip6 counter accept"
	}

	return fmt.Sprintf(`#!/usr/sbin/nft -f

table inet security {

    set blocklist_ip4_forever {
        type ipv4_addr
        flags interval
        auto-merge
        size 65535
        elements = {
          167.94.138.0/24,
          167.94.145.0/24,
          167.94.146.0/24,
          198.235.24.0/24,
          205.210.31.0/24,
          64.62.197.0/24,
          64.62.156.0/24,
          80.82.77.0/24,
          89.248.0.0/16,
          193.163.125.0/24,
          185.224.128.0/24,
          154.213.184.0/24,
          79.124.58.0/24,
          79.124.60.0/24,
          95.214.27.0/24,
          94.156.66.0/24,
          94.156.71.0/24,
          90.151.171.0/24,
          78.128.114.0/24,
          122.14.229.0/24
        }
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
        elements = { %s }
    }
%s
    set protected_ports {
        type inet_service
        flags interval
        elements = {
            %s
        }
    }

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
        ip protocol icmp icmp type echo-request limit rate 10/second counter accept
        ip6 nexthdr icmpv6 icmpv6 type echo-request limit rate 10/second counter accept

        # 允许来自白名单 IP 的所有连接
        ip saddr @whitelist_ip counter accept%s

        ip saddr @blocklist_ip4_forever log prefix "[NFT] Ban Forever IPv4 (listed): " counter drop

        # 记录并丢弃来自 IPv4 黑名单的连接
        ip saddr @blocklist_ip4 \
            log prefix "[NFT] Blocked IPv4 (listed): " \
            counter drop

        # 记录并丢弃来自 IPv6 黑名单的连接
        ip6 saddr @blocklist_ip6 \
            log prefix "[NFT] Blocked IPv6 (listed): " \
            counter drop

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
            counter drop
    }

}
`, strings.Join(whitelistV4, ", "), v6WhitelistSet, strings.Join(protected, ",\n            "), v6WhitelistRule)
}

const systemdService = `[Unit]
Description=Singctl Security NFTables Rules
# 确保在主流防火墙完成后加载，避免被冲刷
After=network.target nftables.service firewalld.service ufw.service

[Service]
Type=oneshot
ExecStart=/usr/sbin/nft -f %s
ExecStop=/usr/sbin/nft delete table inet security
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
`

const openwrtInitScript = `#!/bin/sh /etc/rc.common

START=99
STOP=10

start() {
	echo "Loading singctl security firewall rules..."
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

// Enable writes sec_block.nft to /etc/sing-box/ and loads it using nft.
// It also sets up an auto-start service to persist the firewall rules across reboots.
func Enable() error {
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

	nftRules := BuildSecurityNFT(os.Getenv("SSH_CONNECTION"), DetectSSHPorts())
	if err := os.WriteFile(scriptPath, []byte(nftRules), 0600); err != nil {
		return fmt.Errorf("failed to write %s: %v", scriptPath, err)
	}

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

	// 3. 部署跨平台开机自启
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

// ----------------- Systemd (Debian / Ubuntu) -----------------
func setupSystemdService() error {
	servicePath := constant.FirewallSystemdService
	content := fmt.Sprintf(systemdService, constant.SingBoxNftablesFile)
	if err := os.WriteFile(servicePath, []byte(content), 0644); err != nil {
		return err
	}
	_ = exec.Command("systemctl", "daemon-reload").Run()
	if err := exec.Command("systemctl", "enable", "singctl-firewall.service").Run(); err != nil {
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
