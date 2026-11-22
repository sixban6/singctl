// 文件职责：嵌入并按目标操作系统、Linux 发行版及 OpenWrt 防火墙后端声明式装配与分发 sing-box 客户端启停脚本。
package scripts

import (
	"cmp"
	_ "embed"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

//go:embed openwrt_common.sh
var openWrtCommon string

//go:embed openwrt_fw_nftables.sh
var openWrtFWNFTables string

//go:embed openwrt_fw_iptables.sh
var openWrtFWIPTables string

//go:embed openwrt_start_main.sh
var openWrtStartMain string

//go:embed openwrt_stop_main.sh
var openWrtStopMain string

//go:embed start_singbox_debian.sh
var startScriptDebian string

//go:embed stop_singbox_debian.sh
var stopScriptDebian string

//go:embed start_singbox_darwin.sh
var startScriptDarwin string

//go:embed stop_singbox_darwin.sh
var stopScriptDarwin string

//go:embed start_singbox_windows.bat
var startScriptWindows string

//go:embed stop_singbox_windows.bat
var stopScriptWindows string

// OpenWrtFirewallBackend 表示 OpenWrt 透明代理防火墙后端策略。
type OpenWrtFirewallBackend string

const (
	BackendNFTables OpenWrtFirewallBackend = "nftables"
	BackendIPTables OpenWrtFirewallBackend = "iptables"
)

// openWrtFWBackends 以声明式注册表映射防火墙后端片段（OCP：新增后端仅需新增脚本文件并注册一行）。
var openWrtFWBackends = map[OpenWrtFirewallBackend]string{
	BackendNFTables: openWrtFWNFTables,
	BackendIPTables: openWrtFWIPTables,
}

// DetectOpenWrtFirewallBackend 探测当前 OpenWrt 宿主应使用的防火墙后端：
// 优先检查 nft 可执行且非 OpenWrt <= 22 纯 iptables 固件，否则返回 BackendIPTables。
func DetectOpenWrtFirewallBackend() OpenWrtFirewallBackend {
	osRelease, _ := os.ReadFile("/etc/os-release")
	openwrtRelease, _ := os.ReadFile("/etc/openwrt_release")
	return ResolveOpenWrtFirewallBackend(string(osRelease), string(openwrtRelease), hasNFTBinary())
}

// ResolveOpenWrtFirewallBackend 根据 os-release、openwrt_release 内容与 nft 可执行状态纯函数推导后端策略。
func ResolveOpenWrtFirewallBackend(osRelease, openwrtRelease string, hasNFT bool) OpenWrtFirewallBackend {
	if !hasNFT {
		return BackendIPTables
	}
	major := parseOpenWrtMajorVersion(osRelease, openwrtRelease)
	if major > 0 && major <= 22 {
		return BackendIPTables
	}
	return BackendNFTables
}

func hasNFTBinary() bool {
	if _, err := exec.LookPath("nft"); err == nil {
		return true
	}
	for _, candidate := range []string{"/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft"} {
		if st, err := os.Stat(candidate); err == nil && !st.IsDir() && st.Mode()&0111 != 0 {
			return true
		}
	}
	return false
}

func parseOpenWrtMajorVersion(osRelease, openwrtRelease string) int {
	if v := parseKeyMajorVersion(osRelease, "VERSION"); v > 0 {
		return v
	}
	if v := parseKeyMajorVersion(osRelease, "VERSION_ID"); v > 0 {
		return v
	}
	return parseKeyMajorVersion(openwrtRelease, "DISTRIB_RELEASE")
}

func parseKeyMajorVersion(raw, key string) int {
	prefix := key + "="
	for line := range strings.SplitSeq(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		val, ok := strings.CutPrefix(trimmed, prefix)
		if !ok {
			continue
		}
		val = strings.Trim(strings.TrimSpace(val), `"'`)
		if val == "" {
			continue
		}
		// 兼容 R21.10 / v23.05 等自定义固件版本前缀，仅当后跟数字时剥离前缀
		if len(val) >= 2 && (val[0] == 'R' || val[0] == 'r' || val[0] == 'v' || val[0] == 'V') && val[1] >= '0' && val[1] <= '9' {
			val = val[1:]
		}
		end := 0
		for end < len(val) && val[end] >= '0' && val[end] <= '9' {
			end++
		}
		if end == 0 {
			continue
		}
		major, err := strconv.Atoi(val[:end])
		if err == nil && major > 0 {
			return major
		}
	}
	return 0
}

func resolveOpenWrtBackend(backend OpenWrtFirewallBackend) (OpenWrtFirewallBackend, string) {
	if snippet, ok := openWrtFWBackends[backend]; ok {
		return backend, snippet
	}
	return BackendNFTables, openWrtFWBackends[BackendNFTables]
}

func assembleOpenWrtScript(title, purpose string, backend OpenWrtFirewallBackend, mainSnippet string) string {
	resolvedBackend, fwSnippet := resolveOpenWrtBackend(backend)
	var b strings.Builder
	b.WriteString("#!/bin/sh\n\n")
	b.WriteString("#################################################\n")
	b.WriteString("# 描述: " + title + " (" + string(resolvedBackend) + ")\n")
	b.WriteString("# 用途: " + purpose + "\n")
	b.WriteString("#################################################\n\n")
	b.WriteString(strings.TrimSpace(openWrtCommon))
	b.WriteString("\n\n")
	b.WriteString(strings.TrimSpace(fwSnippet))
	b.WriteString("\n\n")
	b.WriteString(strings.TrimSpace(mainSnippet))
	b.WriteByte('\n')
	return b.String()
}

// GetOpenWrtStartScript 按指定防火墙后端在内存中装配完整的单文件 OpenWrt 启动脚本。
func GetOpenWrtStartScript(backend OpenWrtFirewallBackend) string {
	return assembleOpenWrtScript(
		"OpenWrt sing-box TProxy模式 配置脚本",
		"配置和启动 sing-box TProxy模式 代理服务",
		backend,
		openWrtStartMain,
	)
}

// GetOpenWrtStopScript 按指定防火墙后端在内存中装配完整的单文件 OpenWrt 停止脚本。
func GetOpenWrtStopScript(backend OpenWrtFirewallBackend) string {
	return assembleOpenWrtScript(
		"OpenWrt sing-box TProxy模式 停止脚本",
		"停止 sing-box 服务并清理防火墙规则与策略路由",
		backend,
		openWrtStopMain,
	)
}

// WriteStartScript 将当前系统匹配的启动脚本以可执行权限写入指定路径。
func WriteStartScript(path string) error {
	return writeScriptFile(path, GetStartScript())
}

// WriteStopScript 将当前系统匹配的停止脚本以可执行权限写入指定路径。
func WriteStopScript(path string) error {
	return writeScriptFile(path, GetStopScript())
}

// GetStartScript 返回当前操作系统对应的启动脚本内容。
func GetStartScript() string {
	return GetStartScriptForTarget(runtime.GOOS, isDebian())
}

// GetStartScriptForTarget 按指定操作系统与是否为 Debian 系发行版返回对应启动脚本内容。
func GetStartScriptForTarget(goos string, debian bool) string {
	switch cmp.Or(goos, runtime.GOOS) {
	case "darwin":
		return startScriptDarwin
	case "windows":
		return startScriptWindows
	case "linux":
		if debian {
			return startScriptDebian
		}
		return GetOpenWrtStartScript(DetectOpenWrtFirewallBackend())
	default:
		return GetOpenWrtStartScript(DetectOpenWrtFirewallBackend())
	}
}

// GetStopScript 返回当前操作系统对应的停止脚本内容。
func GetStopScript() string {
	switch runtime.GOOS {
	case "darwin":
		return stopScriptDarwin
	case "windows":
		return stopScriptWindows
	case "linux":
		if isDebian() {
			return stopScriptDebian
		}
		return GetOpenWrtStopScript(DetectOpenWrtFirewallBackend())
	default:
		return GetOpenWrtStopScript(DetectOpenWrtFirewallBackend())
	}
}

func isDebian() bool {
	for _, file := range []string{"/etc/debian_version", "/etc/apt/sources.list"} {
		if _, err := os.Stat(file); err == nil {
			return true
		}
	}
	if content, err := os.ReadFile("/etc/os-release"); err == nil {
		osRelease := strings.ToLower(string(content))
		if strings.Contains(osRelease, "debian") || strings.Contains(osRelease, "ubuntu") {
			return true
		}
	}
	return false
}

func writeScriptFile(path, content string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), 0755)
}
