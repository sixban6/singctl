package firewall

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"singctl/internal/logger"
)

const secBlockNFT = `#!/usr/sbin/nft -f

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
        elements = { 192.168.31.0/24, 112.26.33.106, 10.8.8.8/30, 100.64.0.0/10}
    }

    set protected_ports {
        type inet_service
        flags interval
        elements = {
            20-23,   # FTP, SSH, Telnet
            25,      # SMTP
            80,      # HTTP
            110,     # POP3
            123,     # NTP
            443,     # HTTPS
            465,     # SMTPS
            587,     # SMTP (submission)
            993,     # IMAPS
            995,     # POP3S
            1433-1434, # Microsoft SQL Server
            1521,    # Oracle
            2222,    # Alternative SSH
            3306,    # MySQL
            3389,    # RDP
            6379,    # Redis
            8080,    # Alternative HTTP
            8443,    # Alternative HTTPS
            1080,    # SOCKS proxy
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
        ip saddr @whitelist_ip counter accept

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
            add @blocklist_ip4 { ip saddr limit rate 3/minute } \
            counter drop
        meta l4proto udp udp dport @protected_ports \
            log prefix "[NFT] Blocked IPv4 UDP: " \
            add @blocklist_ip4 { ip saddr limit rate 3/minute } \
            counter drop

        # 记录并处理 IPv6 受保护端口的连接尝试 (TCP & UDP)
        meta l4proto tcp tcp dport @protected_ports \
            log prefix "[NFT] Blocked IPv6 TCP: " \
            add @blocklist_ip6 { ip6 saddr limit rate 3/minute } \
            counter drop
        meta l4proto udp udp dport @protected_ports \
            log prefix "[NFT] Blocked IPv6 UDP: " \
            add @blocklist_ip6 { ip6 saddr limit rate 3/minute } \
            counter drop
    }

}
`

const systemdService = `[Unit]
Description=Singctl Security NFTables Rules
# 确保在主流防火墙完成后加载，避免被冲刷
After=network.target nftables.service firewalld.service ufw.service

[Service]
Type=oneshot
ExecStart=/usr/sbin/nft -f /etc/sing-box/sec_block.nft
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
	/usr/sbin/nft -f /etc/sing-box/sec_block.nft
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

// Enable write sec_block.nft to /etc/sing-box/ and loads it using nft.
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

	configDir := "/etc/sing-box"
	scriptPath := filepath.Join(configDir, "sec_block.nft")

	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory %s: %v", configDir, err)
	}

	if err := os.WriteFile(scriptPath, []byte(secBlockNFT), 0644); err != nil {
		return fmt.Errorf("failed to write %s: %v", scriptPath, err)
	}

	// 1. 本次执行，立即生效
	logger.Info("Loading nftables rules from %s...", scriptPath)
	cmd := exec.Command("nft", "-f", scriptPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to load nftables rules: %v\nOutput: %s", err, string(output))
	}

	// 2. 部署跨平台开机自启
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
	_ = os.Remove("/etc/sing-box/sec_block.nft")

	logger.Success("Security block rules disabled and removed")
	return nil
}

// ----------------- Systemd (Debian / Ubuntu) -----------------
func setupSystemdService() error {
	servicePath := "/etc/systemd/system/singctl-firewall.service"
	if err := os.WriteFile(servicePath, []byte(systemdService), 0644); err != nil {
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
	_ = os.Remove("/etc/systemd/system/singctl-firewall.service")
	_ = exec.Command("systemctl", "daemon-reload").Run()
}

// ----------------- init.d (OpenWrt) -----------------
func setupOpenWrtInit() error {
	scriptPath := "/etc/init.d/singctl-firewall"
	if err := os.WriteFile(scriptPath, []byte(openwrtInitScript), 0755); err != nil {
		return err
	}
	// 执行 /etc/init.d/singctl-firewall enable (相当于创建 /etc/rc.d/S99singctl-firewall)
	if err := exec.Command(scriptPath, "enable").Run(); err != nil {
		return err
	}
	return nil
}

func teardownOpenWrtInit() {
	scriptPath := "/etc/init.d/singctl-firewall"
	if _, err := os.Stat(scriptPath); err == nil {
		_ = exec.Command(scriptPath, "disable").Run()
		_ = os.Remove(scriptPath)
	}
}
