// 文件职责：管理 Tailscale 宿主内核 TUN 检测、UDP GRO 网卡加速、OpenWrt UCI 防火墙及 procd/systemd 服务脚本生成。
package tailscale

import (
	"cmp"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"

	"singctl/internal/common/sysinfo"
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
	finalContent := RenderInitScriptWithMem(hasTun, sysinfo.TotalRAMBytes())
	if err := os.WriteFile(scriptPath, []byte(finalContent), 0755); err != nil {
		return fmt.Errorf("write init script failed: %w", err)
	}
	return nil
}

func createSystemdScript(hasTun bool) error {
	scriptPath := constant.TailscaleSystemdService
	content := RenderSystemdScriptWithMem(hasTun, sysinfo.TotalRAMBytes())

	_ = os.MkdirAll("/var/lib/tailscale", 0700)
	_ = os.MkdirAll("/var/run/tailscale", 0755)

	if err := os.WriteFile(scriptPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("write systemd script failed: %w", err)
	}
	return nil
}
