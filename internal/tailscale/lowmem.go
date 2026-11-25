// 文件职责：为小内存路由器（<=512MiB）提供 Tailscale 自适应 GOMEMLIMIT/GOGC 内存护栏计算、服务脚本渲染与既有 procd/systemd 无损幂等补强。
package tailscale

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"singctl/internal/common/sysinfo"
	"singctl/internal/constant"
	"singctl/internal/platform/servicemgr"
)

// ComputeMemoryEnv 根据宿主机总物理内存计算 Tailscale 守护进程的全内存段自适应 Go 内存护栏环境变量：
//   - 0：未知内存返回 nil（不盲猜）
//   - <= 288 MiB（超小内存路由）：GOMEMLIMIT=14MiB, GOGC=25, TS_NO_LOGS_NO_SUPPORT=true
//   - 289~512 MiB（小内存路由）：GOMEMLIMIT=22MiB, GOGC=40, TS_NO_LOGS_NO_SUPPORT=true
//   - 513 MiB~1 GiB：GOMEMLIMIT=48MiB（保持 Go 默认 GOGC=100）
//   - 1~2 GiB：GOMEMLIMIT=64MiB（保持 Go 默认 GOGC=100）
//   - > 2 GiB：GOMEMLIMIT=128MiB（保持 Go 默认 GOGC=100）
func ComputeMemoryEnv(totalRAMBytes uint64) map[string]string {
	const mib uint64 = 1024 * 1024
	if totalRAMBytes == 0 {
		return nil
	}
	switch {
	case sysinfo.IsUltraLowMemoryRAM(totalRAMBytes):
		return map[string]string{
			"GOMEMLIMIT":            "14MiB",
			"GOGC":                  "25",
			"TS_NO_LOGS_NO_SUPPORT": "true",
		}
	case sysinfo.IsLowMemoryRAM(totalRAMBytes):
		return map[string]string{
			"GOMEMLIMIT":            "22MiB",
			"GOGC":                  "40",
			"TS_NO_LOGS_NO_SUPPORT": "true",
		}
	case totalRAMBytes <= 1024*mib:
		return map[string]string{"GOMEMLIMIT": "48MiB"}
	case totalRAMBytes <= 2048*mib:
		return map[string]string{"GOMEMLIMIT": "64MiB"}
	default:
		return map[string]string{"GOMEMLIMIT": "128MiB"}
	}
}

func buildBaseProcdInitScript(hasTun bool) string {
	var b strings.Builder
	b.WriteString(`#!/bin/sh /etc/rc.common
USE_PROCD=1
START=99
STOP=10

start_service() {
`)
	if hasTun {
		fmt.Fprintf(&b, `    # 加载 tun 模块以防未开机加载
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
`, constant.TailscaleStateDir, constant.TailscaleStateDir)
	} else {
		fmt.Fprintf(&b, `    # 开启内核转发(虽然是用户态，但为了路由功能最好开启)
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
`, constant.TailscaleStateDir, constant.TailscaleStateDir)
	}
	return b.String()
}

func buildBaseSystemdScript(hasTun bool) string {
	var b strings.Builder
	b.WriteString(`[Unit]
Description=Tailscale node agent
Documentation=https://tailscale.com/kb/
Wants=network-pre.target
After=network-pre.target NetworkManager.service systemd-resolved.service

[Service]
ExecStartPre=/usr/sbin/tailscaled --cleanup
`)
	if hasTun {
		b.WriteString("ExecStart=/usr/sbin/tailscaled --state=/var/lib/tailscale/tailscaled.state --socket=/var/run/tailscale/tailscaled.sock --port=41641\n")
	} else {
		b.WriteString("ExecStart=/usr/sbin/tailscaled --tun=userspace-networking --state=/var/lib/tailscale/tailscaled.state --socket=/var/run/tailscale/tailscaled.sock --port=41641\n")
	}
	b.WriteString(`ExecStopPost=/usr/sbin/tailscaled --cleanup
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
`)
	return b.String()
}

// RenderInitScriptWithMem 生成带小内存自适应护栏的 OpenWrt procd `/etc/init.d/tailscale` 脚本内容。
func RenderInitScriptWithMem(hasTun bool, totalRAMBytes uint64) string {
	base := buildBaseProcdInitScript(hasTun)
	env := ComputeMemoryEnv(totalRAMBytes)
	if len(env) == 0 {
		return base
	}
	rendered, err := servicemgr.RenderProcdBody(servicemgr.UnitSpec{
		Name:      "tailscale",
		ProcdBody: base,
		Env:       env,
	})
	if err != nil {
		return base
	}
	return rendered
}

// RenderSystemdScriptWithMem 生成带小内存自适应护栏的 systemd `tailscaled.service` 单元内容。
func RenderSystemdScriptWithMem(hasTun bool, totalRAMBytes uint64) string {
	base := buildBaseSystemdScript(hasTun)
	env := ComputeMemoryEnv(totalRAMBytes)
	if len(env) == 0 {
		return base
	}
	rendered, err := servicemgr.RenderSystemdBody(servicemgr.UnitSpec{
		Name:        "tailscaled",
		SystemdBody: base,
		Env:         env,
	})
	if err != nil {
		return base
	}
	return rendered
}

func stripManagedProcdMemEnvLines(body string) string {
	lines := strings.Split(body, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "procd_set_param env ") &&
			strings.Contains(trimmed, "GOMEMLIMIT=") {
			continue
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

func stripManagedSystemdMemEnvLines(body string) string {
	lines := strings.Split(body, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, `Environment="GOMEMLIMIT=`) ||
			strings.HasPrefix(trimmed, `Environment="GOGC=`) ||
			strings.HasPrefix(trimmed, `Environment="TS_NO_LOGS_NO_SUPPORT=`) {
			continue
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

func cleanupDuplicateTailscaleRcSymlink(rcdDir string) bool {
	if strings.TrimSpace(rcdDir) == "" {
		return false
	}
	s99 := filepath.Join(rcdDir, "S99tailscale")
	s80 := filepath.Join(rcdDir, "S80tailscale")
	if _, err := os.Lstat(s99); err != nil {
		return false
	}
	if _, err := os.Lstat(s80); err != nil {
		return false
	}
	return os.Remove(s80) == nil
}

// EnsureLowMemServiceEnv 幂等为既有 Tailscale 服务文件（OpenWrt procd 或 systemd）补齐小内存 GOMEMLIMIT/GOGC 护栏，
// 并顺带清理重复遗留的 S80tailscale 启动软链。大内存宿主机（>512MiB）静默跳过不做任何改动。
func EnsureLowMemServiceEnv(initdPath, systemdPath, rcdDir string, totalRAMBytes uint64) (bool, string, error) {
	env := ComputeMemoryEnv(totalRAMBytes)
	if len(env) == 0 {
		return false, "", nil
	}

	rcCleaned := cleanupDuplicateTailscaleRcSymlink(rcdDir)

	if strings.TrimSpace(initdPath) != "" {
		if raw, err := os.ReadFile(initdPath); err == nil && strings.Contains(string(raw), "procd_open_instance") {
			orig := string(raw)
			cleaned := stripManagedProcdMemEnvLines(orig)
			rendered, rErr := servicemgr.RenderProcdBody(servicemgr.UnitSpec{
				Name:      "tailscale",
				ProcdBody: cleaned,
				Env:       env,
			})
			if rErr != nil {
				return rcCleaned, "procd", rErr
			}
			if rendered != orig {
				if wErr := os.WriteFile(initdPath, []byte(rendered), 0755); wErr != nil {
					return rcCleaned, "procd", wErr
				}
				return true, "procd", nil
			}
			return rcCleaned, "procd", nil
		}
	}

	if strings.TrimSpace(systemdPath) != "" {
		if raw, err := os.ReadFile(systemdPath); err == nil && strings.Contains(string(raw), "[Service]") {
			orig := string(raw)
			cleaned := stripManagedSystemdMemEnvLines(orig)
			rendered, rErr := servicemgr.RenderSystemdBody(servicemgr.UnitSpec{
				Name:        "tailscaled",
				SystemdBody: cleaned,
				Env:         env,
			})
			if rErr != nil {
				return rcCleaned, "systemd", rErr
			}
			if rendered != orig {
				if wErr := os.WriteFile(systemdPath, []byte(rendered), 0644); wErr != nil {
					return rcCleaned, "systemd", wErr
				}
				return true, "systemd", nil
			}
			return rcCleaned, "systemd", nil
		}
	}

	return rcCleaned, "", nil
}
