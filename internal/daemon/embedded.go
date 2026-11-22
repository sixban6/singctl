// 文件职责：提供单进程合体模式（守护进程内嵌 WebUI）的物理内存阈值判定与内嵌运行态标记文件读写契约。
package daemon

import (
	"cmp"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"singctl/internal/common/fsx"
	"singctl/internal/common/sysinfo"
)

// UnifiedDaemonMaxMemBytes 低内存单进程合体模式自动启用总物理内存上限（复用 sysinfo.LowMemoryThresholdBytes = 512 MiB）。
const UnifiedDaemonMaxMemBytes uint64 = sysinfo.LowMemoryThresholdBytes

// UnifiedDaemonMaxAvailBytes 低内存单进程合体模式自动启用可用内存上限（复用 sysinfo.LowMemoryAvailableThresholdBytes = 256 MiB）。
const UnifiedDaemonMaxAvailBytes uint64 = sysinfo.LowMemoryAvailableThresholdBytes

// EnvUnifiedDaemon 控制守护进程是否启用单进程合体模式（"1" 强制开启，"0" 强制关闭）。
const EnvUnifiedDaemon = "SINGCTL_UNIFIED_DAEMON"

// EnvFromWebUI 标识当前 CLI 子命令是由 WebUI 动作执行器触发。
const EnvFromWebUI = "SINGCTL_FROM_WEBUI"

// EnvDeferWebHandoff 透传给后台 fork 的守护子进程，要求礼貌等待独立 WebUI 推流退出后再接管监听端口。
const EnvDeferWebHandoff = "SINGCTL_DEFER_WEB_HANDOFF"

// WebEmbeddedFileName 内嵌 WebUI 运行态标记文件名。
const WebEmbeddedFileName = "singctl-web.embedded"

// WebEmbeddedState 持久化在 /tmp/singctl-web.embedded 中的内嵌 WebUI 运行状态（0600 权限）。
type WebEmbeddedState struct {
	Pid        int    `json:"pid"`
	Listen     string `json:"listen"`
	ConfigPath string `json:"config_path,omitempty"`
	StartedAt  string `json:"started_at,omitempty"`
}

// IsLowMemoryMemInfo 判断 /proc/meminfo 快照是否命中低内存软硬路由特征（委托 sysinfo.IsLowMemoryMemInfo）。
func IsLowMemoryMemInfo(mi sysinfo.MemInfo) bool {
	return sysinfo.IsLowMemoryMemInfo(mi)
}

// ShouldEnableUnifiedDaemon 根据宿主机内存快照与环境变量值判定是否启用单进程合体模式。
func ShouldEnableUnifiedDaemon(mi sysinfo.MemInfo, envVal string) bool {
	switch strings.ToLower(strings.TrimSpace(envVal)) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return IsLowMemoryMemInfo(mi)
	}
}

// IsLowMemoryDevice 检测当前运行环境是否处于低内存或显式合体模式。
func IsLowMemoryDevice() bool {
	mi, _ := sysinfo.ReadMemInfo()
	return ShouldEnableUnifiedDaemon(mi, os.Getenv(EnvUnifiedDaemon))
}

// GetWebEmbeddedPath 返回默认的内嵌 WebUI 状态标记文件路径。
func GetWebEmbeddedPath() string {
	return cmp.Or(WebEmbeddedPathOverride, filepath.Join(defaultTempDir(), WebEmbeddedFileName))
}

// WriteWebEmbeddedStateAt 以 0600 权限原子写入内嵌 WebUI 状态文件。
func WriteWebEmbeddedStateAt(path string, st WebEmbeddedState) error {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return fsx.WriteAtomic0600(path, b)
}

// RemoveWebEmbeddedFileAt 删除指定路径的内嵌 WebUI 状态文件（不存在时幂等成功）。
func RemoveWebEmbeddedFileAt(path string) error {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	}
	return os.Remove(path)
}

// ReadWebEmbeddedStateAt 从指定状态文件路径读取并校验守护进程存活的内嵌 WebUI 状态。
func ReadWebEmbeddedStateAt(embeddedPath, statePath, pidPath string, pidAlive func(int) bool) (WebEmbeddedState, bool) {
	if pidAlive == nil {
		pidAlive = DaemonProcessMatches
	}
	if strings.TrimSpace(embeddedPath) != "" {
		if raw, err := os.ReadFile(embeddedPath); err == nil && len(raw) > 0 {
			var st WebEmbeddedState
			if json.Unmarshal(raw, &st) == nil && st.Pid > 0 && strings.TrimSpace(st.Listen) != "" {
				if pidAlive(st.Pid) {
					return st, true
				}
				return WebEmbeddedState{}, false
			}
		}
	}
	if strings.TrimSpace(statePath) == "" || strings.TrimSpace(pidPath) == "" {
		return WebEmbeddedState{}, false
	}
	pid, err := ReadDaemonPidAt(pidPath)
	if err != nil && pidPath == GetPidFilePath() {
		pid, err = ReadDaemonPid()
	}
	if err != nil || pid <= 0 || !pidAlive(pid) {
		return WebEmbeddedState{}, false
	}
	snap := NewStateStore(Paths{PidFile: pidPath, StateFile: statePath}).Load()
	if !snap.WebEmbedded || strings.TrimSpace(snap.WebEmbeddedListen) == "" {
		return WebEmbeddedState{}, false
	}
	return WebEmbeddedState{
		Pid:       pid,
		Listen:    snap.WebEmbeddedListen,
		StartedAt: snap.StartedAt,
	}, true
}

// ReadWebEmbeddedState 读取当前宿主机默认路径下存活的内嵌 WebUI 状态。
func ReadWebEmbeddedState() (WebEmbeddedState, bool) {
	return ReadWebEmbeddedStateAt(GetWebEmbeddedPath(), GetStateFilePath(), GetPidFilePath(), DaemonProcessMatches)
}
