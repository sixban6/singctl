// 文件职责：提供面向宿主服务管理器（systemd / OpenWrt procd）的统一适配契约，底层执行委托 common/execx 与 common/sysinfo。
package servicemgr

import (
	"cmp"
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"

	"singctl/internal/common/execx"
	"singctl/internal/common/sysinfo"
)

const (
	defaultActionTimeout = 25 * time.Second
	defaultProbeTimeout  = execx.DefaultProbeTimeout
)

// InitKind 描述当前宿主机的进程管理体系类型。
type InitKind string

const (
	InitUnknown InitKind = "unknown"
	InitSystemd InitKind = "systemd"
	InitProcd   InitKind = "procd"
)

// HostInfo 汇总当前宿主机的系统平台与初始化系统识别结果。
type HostInfo struct {
	OS        string
	IsOpenWrt bool
	Kind      InitKind
}

// CmdRunner 复用 common/execx.Runner 类型别名，保持全部消费侧与测试替身 100% 零改动兼容。
type CmdRunner = execx.Runner

// DefaultRunner 复用 common/execx.DefaultRunner。
type DefaultRunner = execx.DefaultRunner

func activeRunner(runner CmdRunner) CmdRunner {
	return execx.Active(runner)
}

// UnitSpec 描述一个托管守护服务在 systemd 与 OpenWrt procd 下的部署单元规格。
type UnitSpec struct {
	Name        string
	SystemdPath string
	SystemdBody string
	ProcdPath   string
	ProcdBody   string
}

// Manager 定义极薄跨平台宿主服务启停与单元托管接口。
type Manager interface {
	Kind() InitKind
	Start(ctx context.Context, name string) error
	Stop(ctx context.Context, name string) error
	Restart(ctx context.Context, name string) error
	Reload(ctx context.Context, name string) error
	ReloadOrRestart(ctx context.Context, name string) error
	Enable(ctx context.Context, name string) error
	Disable(ctx context.Context, name string) error
	DaemonReload(ctx context.Context) error
	IsActive(ctx context.Context, name string) bool
	InstallUnit(ctx context.Context, spec UnitSpec) error
	RemoveUnit(ctx context.Context, spec UnitSpec) error
}

var unitNameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.@-]*$`)

// ValidateUnitName 严格校验服务名称合法性，拒绝路径穿越、前导短横线参数注入与 Shell 元字符。
func ValidateUnitName(name string) error {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" || trimmed != name || strings.Contains(trimmed, "..") || !unitNameRe.MatchString(trimmed) {
		return fmt.Errorf("invalid service unit name: %q", name)
	}
	return nil
}

// IsOpenWrt 判断当前宿主机是否运行 OpenWrt / ImmortalWrt 固件系统（委托 common/sysinfo）。
func IsOpenWrt() bool {
	return sysinfo.IsOpenWrt()
}

// DetectHost 识别当前宿主机的平台类型与初始化管理器。
func DetectHost() HostInfo {
	info := HostInfo{
		OS:        runtime.GOOS,
		IsOpenWrt: IsOpenWrt(),
		Kind:      InitUnknown,
	}
	if runtime.GOOS != "linux" {
		return info
	}
	if info.IsOpenWrt {
		if _, err := os.Stat("/etc/rc.common"); err == nil {
			info.Kind = InitProcd
			return info
		}
	}
	if _, err := os.Stat("/run/systemd/system"); err == nil {
		if _, err := exec.LookPath("systemctl"); err == nil {
			info.Kind = InitSystemd
		}
	}
	return info
}

// Detect 根据当前宿主机环境自动构建适配的宿主服务管理器；runner 为 nil 时使用 DefaultRunner。
func Detect(runner CmdRunner) Manager {
	host := DetectHost()
	switch host.Kind {
	case InitProcd:
		return NewProcd(runner, "")
	case InitSystemd:
		return NewSystemd(runner)
	default:
		if runtime.GOOS == "linux" && !host.IsOpenWrt {
			return NewSystemd(runner)
		}
		return NewNoop()
	}
}

// NoopManager 用于非 Linux 桌面或无服务管理器环境的安全空操作实现。
type NoopManager struct {
	osName string
}

// NewNoop 创建非受管平台空实现管理器。
func NewNoop() *NoopManager {
	return &NoopManager{osName: cmp.Or(runtime.GOOS, "unknown")}
}

func (n *NoopManager) unsupportedErr(action, name string) error {
	return fmt.Errorf("service %s for %q is unsupported on host OS %s", action, name, n.osName)
}

func (n *NoopManager) Kind() InitKind { return InitUnknown }
func (n *NoopManager) Start(_ context.Context, name string) error {
	return n.unsupportedErr("start", name)
}
func (n *NoopManager) Stop(_ context.Context, name string) error {
	return n.unsupportedErr("stop", name)
}
func (n *NoopManager) Restart(_ context.Context, name string) error {
	return n.unsupportedErr("restart", name)
}
func (n *NoopManager) Reload(_ context.Context, name string) error {
	return n.unsupportedErr("reload", name)
}
func (n *NoopManager) ReloadOrRestart(_ context.Context, name string) error {
	return n.unsupportedErr("reload-or-restart", name)
}
func (n *NoopManager) Enable(_ context.Context, name string) error {
	return n.unsupportedErr("enable", name)
}
func (n *NoopManager) Disable(_ context.Context, name string) error {
	return n.unsupportedErr("disable", name)
}
func (n *NoopManager) DaemonReload(context.Context) error    { return nil }
func (n *NoopManager) IsActive(context.Context, string) bool { return false }
func (n *NoopManager) InstallUnit(_ context.Context, s UnitSpec) error {
	return n.unsupportedErr("install-unit", s.Name)
}
func (n *NoopManager) RemoveUnit(context.Context, UnitSpec) error { return nil }
