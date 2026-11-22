// 文件职责：管理 Tailscale 宿主内核 TUN 检测、UDP GRO 网卡加速、OpenWrt UCI 防火墙及 procd/systemd 服务脚本生成。
package tailscale

import (
	"cmp"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"

	"singctl/internal/constant"
	"singctl/internal/logger"
)

func configureOpenWrtTailscaleFirewall() {
	logger.Info("Configuring firewall and network for OpenWrt...")

	CleanupTailscaleFirewall()

	exec.Command("uci", "set", "network.tailscale=interface").Run()
	exec.Command("uci", "set", "network.tailscale.device=tailscale0").Run()
	exec.Command("uci", "set", "network.tailscale.proto=unmanaged").Run()

	exec.Command("uci", "set", "firewall.tailscale_zone=zone").Run()
	exec.Command("uci", "set", "firewall.tailscale_zone.name=tailscale").Run()
	exec.Command("uci", "set", "firewall.tailscale_zone.network=tailscale").Run()
	exec.Command("uci", "set", "firewall.tailscale_zone.input=ACCEPT").Run()
	exec.Command("uci", "set", "firewall.tailscale_zone.output=ACCEPT").Run()
	exec.Command("uci", "set", "firewall.tailscale_zone.forward=ACCEPT").Run()
	exec.Command("uci", "set", "firewall.tailscale_zone.masq=1").Run()

	exec.Command("uci", "set", "firewall.ts_fwd_to_lan=forwarding").Run()
	exec.Command("uci", "set", "firewall.ts_fwd_to_lan.src=tailscale").Run()
	exec.Command("uci", "set", "firewall.ts_fwd_to_lan.dest=lan").Run()

	exec.Command("uci", "set", "firewall.ts_fwd_from_lan=forwarding").Run()
	exec.Command("uci", "set", "firewall.ts_fwd_from_lan.src=lan").Run()
	exec.Command("uci", "set", "firewall.ts_fwd_from_lan.dest=tailscale").Run()

	exec.Command("uci", "set", "firewall.ts_fwd_to_wan=forwarding").Run()
	exec.Command("uci", "set", "firewall.ts_fwd_to_wan.src=tailscale").Run()
	exec.Command("uci", "set", "firewall.ts_fwd_to_wan.dest=wan").Run()

	exec.Command("uci", "commit", "network").Run()
	exec.Command("uci", "commit", "firewall").Run()
	exec.Command("/etc/init.d/network", "reload").Run()
	exec.Command("/etc/init.d/firewall", "reload").Run()
}

// CleanupTailscaleFirewall 删除历史上用 "uci add" 产生的匿名重复 zone/forwarding 条目。
func CleanupTailscaleFirewall() {
	RemoveAnonymousUCISections("firewall", "zone", "name", "tailscale")
	RemoveAnonymousUCISections("firewall", "forwarding", "src", "tailscale")
	RemoveAnonymousUCISections("firewall", "forwarding", "dest", "tailscale")
}

// RemoveAnonymousUCISections 找出 config 中类型为 sectionType、且 key==value 的所有匿名 section 并倒序删除。
func RemoveAnonymousUCISections(config, sectionType, key, value string) {
	out, err := exec.Command("uci", "show", config).Output()
	if err != nil {
		return
	}

	targetPrefix := config + ".@" + sectionType + "["
	matchSuffix := "." + key + "='" + value + "'"

	indexSet := map[int]struct{}{}
	for line := range strings.SplitSeq(string(out), "\n") {
		if !strings.HasPrefix(line, targetPrefix) {
			continue
		}
		if !strings.HasSuffix(strings.TrimRight(line, "\r"), matchSuffix) {
			continue
		}
		rest := strings.TrimPrefix(line, targetPrefix)
		closeBracket := strings.Index(rest, "]")
		if closeBracket < 0 {
			continue
		}
		var idx int
		if _, err := fmt.Sscanf(rest[:closeBracket], "%d", &idx); err == nil {
			indexSet[idx] = struct{}{}
		}
	}

	indices := make([]int, 0, len(indexSet))
	for idx := range indexSet {
		indices = append(indices, idx)
	}
	slices.SortFunc(indices, func(a, b int) int {
		return cmp.Compare(b, a)
	})

	for _, idx := range indices {
		section := fmt.Sprintf("%s.@%s[%d]", config, sectionType, idx)
		exec.Command("uci", "delete", section).Run()
		logger.Info("Removed duplicate anonymous section: %s", section)
	}
	if len(indices) > 0 {
		exec.Command("uci", "commit", config).Run()
	}
}

func defaultRouteNetdev() (string, error) {
	out, err := exec.Command("ip", "-o", "route", "get", "8.8.8.8").Output()
	if err != nil {
		return "", fmt.Errorf("failed to get default route: %w", err)
	}
	fields := strings.Fields(string(out))
	for i, field := range fields {
		if field == "dev" && i+1 < len(fields) {
			return fields[i+1], nil
		}
	}
	return "", fmt.Errorf("could not determine network interface")
}

// OptimizeUDPGRO configures UDP GRO settings for better Tailscale performance.
func OptimizeUDPGRO() error {
	if _, err := exec.LookPath("ethtool"); err != nil {
		return fmt.Errorf("ethtool not found (install with: apk add ethtool or opkg install ethtool)")
	}
	netdev, err := defaultRouteNetdev()
	if err != nil {
		return err
	}
	logger.Info("Configuring UDP GRO on interface: %s", netdev)
	if err := exec.Command("ethtool", "-K", netdev, "rx-udp-gro-forwarding", "on", "rx-gro-list", "off").Run(); err != nil {
		return fmt.Errorf("ethtool command failed: %w", err)
	}
	logger.Success("UDP GRO optimization applied")
	return nil
}

// RestoreUDPGRO restores UDP GRO settings to default values.
func RestoreUDPGRO() error {
	if _, err := exec.LookPath("ethtool"); err != nil {
		return fmt.Errorf("ethtool not found")
	}
	netdev, err := defaultRouteNetdev()
	if err != nil {
		return err
	}
	logger.Info("Restoring UDP GRO on interface: %s", netdev)
	if err := exec.Command("ethtool", "-K", netdev, "rx-udp-gro-forwarding", "off", "rx-gro-list", "on").Run(); err != nil {
		return fmt.Errorf("ethtool command failed: %w", err)
	}
	logger.Success("UDP GRO settings restored to default")
	return nil
}

func CheckTunModule() bool {
	if err := exec.Command("modprobe", "tun").Run(); err == nil {
		return true
	}
	out, err := exec.Command("lsmod").Output()
	if err == nil {
		for line := range strings.SplitSeq(string(out), "\n") {
			parts := strings.Fields(line)
			if len(parts) > 0 && parts[0] == "tun" {
				return true
			}
		}
	}
	return false
}

func CreateInitScript(hasTun bool) error {
	scriptPath := constant.TailscaleInitdScript

	content := `#!/bin/sh /etc/rc.common
USE_PROCD=1
START=99
STOP=10

start_service() {
`
	if hasTun {
		content += `    # 加载 tun 模块以防未开机加载
    modprobe tun > /dev/null 2>&1

    # 确保 TUN 设备存在
    if [ ! -c /dev/net/tun ]; then
        mkdir -p /dev/net
        mknod /dev/net/tun c 10 200
        chmod 0666 /dev/net/tun
    fi

    # 开启转发
    sysctl -w net.ipv4.ip_forward=1 > /dev/null

    mkdir -p %s
    mkdir -p /var/run/tailscale

    procd_open_instance
    procd_set_param command /usr/sbin/tailscaled
    
    # 核心差异：移除 userspace-networking，默认使用 tun
    procd_append_param command --state=%s/tailscaled.state
    procd_append_param command --socket=/var/run/tailscale/tailscaled.sock
    procd_append_param command --port=41641
    
    procd_set_param respawn
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_close_instance
}
`
	} else {
		content += `    # 开启内核转发(虽然是用户态，但为了路由功能最好开启)
    sysctl -w net.ipv4.ip_forward=1 > /dev/null

    mkdir -p %s
    mkdir -p /var/run/tailscale

    procd_open_instance
    procd_set_param command /usr/sbin/tailscaled
    
    # 核心差异：用户态网络模式
    procd_append_param command --tun=userspace-networking
    procd_append_param command --state=%s/tailscaled.state
    procd_append_param command --socket=/var/run/tailscale/tailscaled.sock
    procd_append_param command --port=41641
    
    procd_set_param respawn
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_close_instance
}
`
	}

	finalContent := fmt.Sprintf(content, constant.TailscaleStateDir, constant.TailscaleStateDir)
	if err := os.WriteFile(scriptPath, []byte(finalContent), 0755); err != nil {
		return fmt.Errorf("write init script failed: %w", err)
	}
	return nil
}

func createSystemdScript(hasTun bool) error {
	scriptPath := constant.TailscaleSystemdService

	content := `[Unit]
Description=Tailscale node agent
Documentation=https://tailscale.com/kb/
Wants=network-pre.target
After=network-pre.target NetworkManager.service systemd-resolved.service

[Service]
ExecStartPre=/usr/sbin/tailscaled --cleanup
`
	if hasTun {
		content += `ExecStart=/usr/sbin/tailscaled --state=/var/lib/tailscale/tailscaled.state --socket=/var/run/tailscale/tailscaled.sock --port=41641
`
	} else {
		content += `ExecStart=/usr/sbin/tailscaled --tun=userspace-networking --state=/var/lib/tailscale/tailscaled.state --socket=/var/run/tailscale/tailscaled.sock --port=41641
`
	}
	content += `ExecStopPost=/usr/sbin/tailscaled --cleanup
Restart=on-failure
RuntimeDirectory=tailscale
RuntimeDirectoryMode=0755
StateDirectory=tailscale
StateDirectoryMode=0700
CacheDirectory=tailscale
CacheDirectoryMode=0750
Type=notify

[Install]
WantedBy=multi-user.target
`

	_ = os.MkdirAll("/var/lib/tailscale", 0700)
	_ = os.MkdirAll("/var/run/tailscale", 0755)

	if err := os.WriteFile(scriptPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("write systemd script failed: %w", err)
	}
	return nil
}
