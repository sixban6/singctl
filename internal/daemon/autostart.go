// 文件职责：实现路由器开机自启动与掉电恢复（singctl-autostart procd/systemd 单元生成、状态探测、防注入对账及 boot-init 自愈拉起）。
package daemon

import (
	"cmp"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"singctl/internal/common/fsx"
	"singctl/internal/common/proc"
	"singctl/internal/common/sysinfo"
	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/logger"
	"singctl/internal/platform/servicemgr"
	"singctl/internal/updater"
)

const (
	// AutoStartServiceName 是跨平台开机自启动与掉电恢复服务的托管单元名。
	AutoStartServiceName = "singctl-autostart"
	// AutoStartProcdOrder 是 OpenWrt procd 启动顺序编号（99 确保在网络与依赖服务之后启动）。
	AutoStartProcdOrder = 99
	// DefaultBootInitLog 记录路由器冷启掉电恢复执行轨迹（0600，容量封顶 256 KiB）。
	DefaultBootInitLog = "/tmp/singctl-autostart.log"

	defaultBootNetWaitTimeout  = 15 * time.Second
	defaultBootNetPollInterval = 1 * time.Second
	defaultBootRetryAttempts   = 3
	defaultBootRetryDelay      = 3 * time.Second
	unsafeAutoStartPathChars   = " \t\r\n\x00;|&$`'\"\\<>(){}*?!"
)

// AutoStartStatus 描述路由器开机自启动与掉电恢复的当前受控状态。
type AutoStartStatus struct {
	Supported        bool   `json:"supported"`
	Enabled          bool   `json:"enabled"`
	ConfigEnabled    bool   `json:"configEnabled"`
	ServiceInstalled bool   `json:"serviceInstalled"`
	ServiceEnabled   bool   `json:"serviceEnabled"`
	ServiceName      string `json:"serviceName"`
	InitSystem       string `json:"initSystem"`
	UnitPath         string `json:"unitPath"`
	Mode             string `json:"mode"`
	LowMemory        bool   `json:"lowMemory"`
	Summary          string `json:"summary"`
}

// AutoStartDeps 显式注入开机自启动状态探测与对账所需的宿主平台依赖。
type AutoStartDeps struct {
	GOOS           string
	ConfigPath     string
	ExecutablePath string
	ProcdInitDir   string
	SystemdUnitDir string
	RcCommonPath   string
	SystemdRunDir  string
	ServiceMgr     servicemgr.Manager
	ReadMemInfo    func() (sysinfo.MemInfo, error)
}

// BootInitDeps 显式注入开机掉电恢复执行器 (`singctl dm boot-init --worker`) 的探测与拉起依赖。
type BootInitDeps struct {
	ConfigPath             string
	ExecutablePath         string
	SingBoxConfigPath      string
	WaitNetworkReady       func(ctx context.Context) error
	SingBoxConfigExists    func() bool
	IsSingBoxRunning       func() bool
	IsDaemonRunning        func() bool
	IsStandaloneWebRunning func() bool
	IsLowMemory            func() bool
	StartSingBox           func(ctx context.Context) error
	StartDaemon            func(ctx context.Context) error
	StartWeb               func(ctx context.Context) error
	RetryAttempts          int
	RetryDelay             time.Duration
}

func validateAutoStartAbsPath(label, raw string) (string, error) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return "", fmt.Errorf("%s 不能为空", label)
	}
	if !strings.HasPrefix(v, "/") {
		return "", fmt.Errorf("%s 必须为绝对路径: %q", label, v)
	}
	if strings.ContainsAny(v, unsafeAutoStartPathChars) {
		return "", fmt.Errorf("%s 包含非法空白或命令注入字符: %q", label, v)
	}
	for i := 0; i < len(v); i++ {
		if v[i] < 0x20 || v[i] == 0x7f {
			return "", fmt.Errorf("%s 包含非法控制字符", label)
		}
	}
	return filepath.Clean(v), nil
}

// BuildAutoStartUnitSpec 构造 OpenWrt procd (START=99) 与 Linux systemd 开机自启单元规格。
func BuildAutoStartUnitSpec(exePath, cfgPath string) (servicemgr.UnitSpec, error) {
	exe, err := validateAutoStartAbsPath("executable path", exePath)
	if err != nil {
		return servicemgr.UnitSpec{}, err
	}
	cfg, err := validateAutoStartAbsPath("config path", cfgPath)
	if err != nil {
		return servicemgr.UnitSpec{}, err
	}

	procdBody := fmt.Sprintf(`#!/bin/sh /etc/rc.common

START=%d
USE_PROCD=1

start_service() {
    "%s" --config "%s" dm boot-init >/dev/null 2>&1 || true
}
`, AutoStartProcdOrder, exe, cfg)

	systemdBody := fmt.Sprintf(`[Unit]
Description=SingCtl Boot Autostart and Power-Loss Recovery
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart="%s" --config "%s" dm boot-init --worker
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
`, exe, cfg)

	return servicemgr.UnitSpec{
		Name:        AutoStartServiceName,
		ProcdPath:   "/etc/init.d/" + AutoStartServiceName,
		ProcdBody:   procdBody,
		SystemdPath: "/etc/systemd/system/" + AutoStartServiceName + ".service",
		SystemdBody: systemdBody,
		BootOnly:    true,
	}, nil
}

func pathExists(p string) bool {
	if strings.TrimSpace(p) == "" {
		return false
	}
	_, err := os.Stat(p)
	return err == nil
}

func resolveAutoStartHost(deps AutoStartDeps) (initKind, unitPath string, mgr servicemgr.Manager, supported bool) {
	goos := cmp.Or(strings.TrimSpace(deps.GOOS), runtime.GOOS)
	procdDir := cmp.Or(strings.TrimSpace(deps.ProcdInitDir), "/etc/init.d")
	systemdDir := cmp.Or(strings.TrimSpace(deps.SystemdUnitDir), "/etc/systemd/system")
	rcCommon := cmp.Or(strings.TrimSpace(deps.RcCommonPath), "/etc/rc.common")
	systemdRun := cmp.Or(strings.TrimSpace(deps.SystemdRunDir), "/run/systemd/system")

	detectKind := func() string {
		if strings.TrimSpace(deps.ProcdInitDir) != "" || pathExists(rcCommon) {
			return "procd"
		}
		if strings.TrimSpace(deps.SystemdUnitDir) != "" || pathExists(systemdRun) {
			return "systemd"
		}
		if deps.ServiceMgr != nil {
			switch deps.ServiceMgr.Kind() {
			case servicemgr.InitProcd:
				return "procd"
			case servicemgr.InitSystemd:
				return "systemd"
			}
		}
		if goos == "linux" {
			if servicemgr.IsOpenWrt() {
				return "procd"
			}
			return "systemd"
		}
		return "unsupported"
	}

	if deps.ServiceMgr != nil {
		if deps.ServiceMgr.Kind() == servicemgr.InitUnknown {
			return "unsupported", "", deps.ServiceMgr, false
		}
		kind := detectKind()
		if kind == "procd" {
			return "procd", filepath.Join(procdDir, AutoStartServiceName), deps.ServiceMgr, true
		}
		if kind == "systemd" {
			return "systemd", filepath.Join(systemdDir, AutoStartServiceName+".service"), deps.ServiceMgr, true
		}
		return "unsupported", "", deps.ServiceMgr, false
	}

	if goos != "linux" {
		return "unsupported", "", servicemgr.NewNoop(), false
	}
	kind := detectKind()
	if kind == "procd" {
		return "procd", filepath.Join(procdDir, AutoStartServiceName), servicemgr.NewProcd(nil, procdDir), true
	}
	return "systemd", filepath.Join(systemdDir, AutoStartServiceName+".service"), servicemgr.NewSystemdWithDir(nil, systemdDir), true
}

func resolveAutoStartLowMemory(cfg *config.Config, deps AutoStartDeps) bool {
	if cfg != nil {
		switch strings.ToLower(strings.TrimSpace(string(cfg.LowMemory))) {
		case "on", "true", "yes", "1":
			return true
		case "off", "false", "no", "0":
			return false
		}
	}
	if deps.ReadMemInfo != nil {
		mi, _ := deps.ReadMemInfo()
		return ShouldEnableUnifiedDaemon(mi, "")
	}
	return IsLowMemoryDevice()
}

func formatAutoStartSummary(st AutoStartStatus) string {
	if !st.Supported {
		return "当前宿主机环境不支持 procd/systemd 开机自启服务管理"
	}
	if !st.ConfigEnabled {
		return "已在配置中关闭开机自启动与掉电恢复"
	}
	if st.Enabled {
		if st.LowMemory {
			return "已启用（低内存单进程合体模式：掉电重启后自动恢复 sing-box 与内嵌 WebUI）"
		}
		return "已启用（标准模式：掉电重启后自动恢复 sing-box、看门狗与 WebUI）"
	}
	if st.ServiceInstalled {
		return "服务脚本已存在但尚未激活 rc.d/systemd 开机启动"
	}
	return "配置允许开机自启，等待写入系统启动服务脚本"
}

// InspectAutoStartStatus 返回当前路由器开机自启动的配置状态与底层服务托管状态。
func InspectAutoStartStatus(ctx context.Context, cfg *config.Config, deps AutoStartDeps) AutoStartStatus {
	if ctx == nil {
		ctx = context.Background()
	}
	initKind, unitPath, mgr, supported := resolveAutoStartHost(deps)
	configEnabled := cfg == nil || cfg.Watchdog.IsAutoStartEnabled()
	lowMem := resolveAutoStartLowMemory(cfg, deps)
	mode := "standard"
	if lowMem {
		mode = "unified_low_memory"
	}

	serviceEnabled := supported && mgr != nil && mgr.IsEnabled(ctx, AutoStartServiceName)
	unitExists := supported && unitPath != "" && pathExists(unitPath)
	serviceInstalled := unitExists || serviceEnabled || (supported && mgr != nil && mgr.IsActive(ctx, AutoStartServiceName))
	if !supported {
		unitPath = ""
		serviceInstalled = false
		serviceEnabled = false
	}

	st := AutoStartStatus{
		Supported:        supported,
		Enabled:          supported && configEnabled && serviceEnabled,
		ConfigEnabled:    configEnabled,
		ServiceInstalled: serviceInstalled,
		ServiceEnabled:   serviceEnabled,
		ServiceName:      AutoStartServiceName,
		InitSystem:       initKind,
		UnitPath:         unitPath,
		Mode:             mode,
		LowMemory:        lowMem,
	}
	st.Summary = formatAutoStartSummary(st)
	return st
}

func resolveAutoStartExecAndConfig(deps AutoStartDeps) (string, string, error) {
	exePath := strings.TrimSpace(deps.ExecutablePath)
	if exePath == "" {
		resolved, err := updater.ResolveExecutablePath()
		if err != nil {
			return "", "", fmt.Errorf("resolve singctl executable: %w", err)
		}
		exePath = resolved
	}
	cfgPath := strings.TrimSpace(deps.ConfigPath)
	if cfgPath == "" {
		cfgPath = "/etc/singctl/singctl.yaml"
	} else if abs, err := filepath.Abs(cfgPath); err == nil {
		cfgPath = abs
	}
	return exePath, cfgPath, nil
}

// ReconcileAutoStart 根据 enabled 布尔值在宿主 init 系统中安装启用或彻底禁用移除 singctl-autostart。
func ReconcileAutoStart(ctx context.Context, cfg *config.Config, enabled bool, deps AutoStartDeps) (AutoStartStatus, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if cfg != nil {
		cfg.Watchdog.SetAutoStart(enabled)
	}
	initKind, unitPath, mgr, supported := resolveAutoStartHost(deps)
	if !supported || mgr == nil {
		return InspectAutoStartStatus(ctx, cfg, deps), nil
	}

	spec := servicemgr.UnitSpec{Name: AutoStartServiceName, BootOnly: true}
	if initKind == "procd" && unitPath != "" {
		spec.ProcdPath = unitPath
	} else if initKind == "systemd" && unitPath != "" {
		spec.SystemdPath = unitPath
	}

	if enabled {
		exePath, cfgPath, err := resolveAutoStartExecAndConfig(deps)
		if err != nil {
			return AutoStartStatus{}, err
		}
		built, err := BuildAutoStartUnitSpec(exePath, cfgPath)
		if err != nil {
			return AutoStartStatus{}, err
		}
		if spec.ProcdPath != "" {
			built.ProcdPath = spec.ProcdPath
		}
		if spec.SystemdPath != "" {
			built.SystemdPath = spec.SystemdPath
		}
		if err := mgr.InstallUnit(ctx, built); err != nil {
			return AutoStartStatus{}, fmt.Errorf("install %s: %w", AutoStartServiceName, err)
		}
		if err := mgr.Enable(ctx, AutoStartServiceName); err != nil {
			return AutoStartStatus{}, fmt.Errorf("enable %s: %w", AutoStartServiceName, err)
		}
	} else {
		if err := mgr.RemoveUnit(ctx, spec); err != nil {
			return AutoStartStatus{}, fmt.Errorf("remove %s: %w", AutoStartServiceName, err)
		}
	}

	return InspectAutoStartStatus(ctx, cfg, deps), nil
}

// EnsureAutoStartFromConfig 在 Linux 服务启动时幂等对账系统自启脚本，仅在状态漂移时执行写入或清理。
func EnsureAutoStartFromConfig(ctx context.Context, cfg *config.Config, configPath string) {
	if runtime.GOOS != "linux" {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	deps := AutoStartDeps{ConfigPath: configPath}
	st := InspectAutoStartStatus(ctx, cfg, deps)
	if !st.Supported {
		return
	}
	desired := cfg == nil || cfg.Watchdog.IsAutoStartEnabled()
	if (desired && st.ServiceInstalled && st.ServiceEnabled) || (!desired && !st.ServiceInstalled && !st.ServiceEnabled) {
		return
	}
	if _, err := ReconcileAutoStart(ctx, cfg, desired, deps); err != nil {
		logger.Warn("[AutoStart] 自动对账 %s 失败: %v", AutoStartServiceName, err)
		return
	}
	if desired {
		logger.Info("[AutoStart] 已自动启用开机自启动与掉电恢复 (%s · %s)", st.InitSystem, st.UnitPath)
	}
}

func defaultWaitNetworkReady(ctx context.Context) error {
	deadline := time.Now().Add(defaultBootNetWaitTimeout)
	for {
		if hasNonLoopbackIPv4OrV6Up() {
			return nil
		}
		if !time.Now().Before(deadline) {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(defaultBootNetPollInterval):
		}
	}
}

func hasNonLoopbackIPv4OrV6Up() bool {
	ifaces, err := net.Interfaces()
	if err != nil {
		return true
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil || len(addrs) == 0 {
			continue
		}
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				return true
			}
		}
	}
	return false
}

// IsBootInitSatisfied 快速判断当前节点的服务运行态是否已满足自启动要求（已运行时 1ms 返回 true，零开销）。
func IsBootInitSatisfied(cfg *config.Config, deps BootInitDeps) bool {
	if cfg != nil && !cfg.Watchdog.IsAutoStartEnabled() {
		return true
	}
	sbCfgPath := cmp.Or(strings.TrimSpace(deps.SingBoxConfigPath), constant.SingBoxConfigFile)
	sbCfgExists := pathExists(sbCfgPath)
	if deps.SingBoxConfigExists != nil {
		sbCfgExists = deps.SingBoxConfigExists()
	}
	isSBRunning := IsSingBoxRunning
	if deps.IsSingBoxRunning != nil {
		isSBRunning = deps.IsSingBoxRunning
	}
	isDMRunning := IsDaemonRunning
	if deps.IsDaemonRunning != nil {
		isDMRunning = deps.IsDaemonRunning
	}
	lowMem := IsLowMemoryDevice()
	if deps.IsLowMemory != nil {
		lowMem = deps.IsLowMemory()
	}
	isWebRunning := func() bool { return false }
	if deps.IsStandaloneWebRunning != nil {
		isWebRunning = deps.IsStandaloneWebRunning
	}

	if sbCfgExists {
		return isSBRunning() && isDMRunning() && (lowMem || isWebRunning())
	}
	if lowMem {
		return isDMRunning()
	}
	return isWebRunning()
}

// RunBootInit 执行路由器冷启/掉电后的幂等恢复序列。
func RunBootInit(ctx context.Context, cfg *config.Config, deps BootInitDeps) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if cfg != nil && !cfg.Watchdog.IsAutoStartEnabled() {
		return nil
	}
	if IsBootInitSatisfied(cfg, deps) {
		return nil
	}

	waitNet := deps.WaitNetworkReady
	if waitNet == nil {
		waitNet = defaultWaitNetworkReady
	}
	if err := waitNet(ctx); err != nil && ctx.Err() != nil {
		return err
	}

	sbCfgPath := cmp.Or(strings.TrimSpace(deps.SingBoxConfigPath), constant.SingBoxConfigFile)
	sbCfgExists := pathExists(sbCfgPath)
	if deps.SingBoxConfigExists != nil {
		sbCfgExists = deps.SingBoxConfigExists()
	}
	isSBRunning := IsSingBoxRunning
	if deps.IsSingBoxRunning != nil {
		isSBRunning = deps.IsSingBoxRunning
	}
	isDMRunning := IsDaemonRunning
	if deps.IsDaemonRunning != nil {
		isDMRunning = deps.IsDaemonRunning
	}
	lowMem := IsLowMemoryDevice()
	if deps.IsLowMemory != nil {
		lowMem = deps.IsLowMemory()
	}
	isWebRunning := func() bool { return false }
	if deps.IsStandaloneWebRunning != nil {
		isWebRunning = deps.IsStandaloneWebRunning
	}

	if !sbCfgExists {
		if lowMem {
			if !isDMRunning() && deps.StartDaemon != nil {
				return deps.StartDaemon(ctx)
			}
			return nil
		}
		if !isWebRunning() && deps.StartWeb != nil {
			return deps.StartWeb(ctx)
		}
		return nil
	}

	var sbErr error
	if !isSBRunning() || !isDMRunning() {
		if deps.StartSingBox != nil {
			attempts := deps.RetryAttempts
			if attempts <= 0 {
				attempts = defaultBootRetryAttempts
			}
			retryDelay := deps.RetryDelay
			if retryDelay <= 0 {
				retryDelay = defaultBootRetryDelay
			}
			for attempt := 1; attempt <= attempts; attempt++ {
				if err := deps.StartSingBox(ctx); err == nil {
					sbErr = nil
					break
				} else {
					sbErr = err
				}
				if attempt < attempts {
					timer := time.NewTimer(retryDelay)
					select {
					case <-ctx.Done():
						timer.Stop()
						return ctx.Err()
					case <-timer.C:
					}
				}
			}
		}
		if sbErr != nil && !isDMRunning() && deps.StartDaemon != nil {
			_ = deps.StartDaemon(ctx)
		}
	}

	if !lowMem && !isWebRunning() && deps.StartWeb != nil {
		if wErr := deps.StartWeb(ctx); wErr != nil && sbErr == nil {
			sbErr = wErr
		}
	}
	return sbErr
}

// SpawnDetachedBootInitWorker 分离拉起后台 `--worker` 子进程执行冷启恢复，保证 rc.common/procd 毫秒级返回不卡住开机序列。
func SpawnDetachedBootInitWorker(exePath, cfgPath, logPath string) error {
	resolvedExe := strings.TrimSpace(exePath)
	if resolvedExe == "" {
		exe, err := updater.ResolveExecutablePath()
		if err != nil {
			return fmt.Errorf("resolve singctl executable: %w", err)
		}
		resolvedExe = exe
	}
	args := make([]string, 0, 5)
	if cleanCfg := strings.TrimSpace(cfgPath); cleanCfg != "" {
		args = append(args, "--config", cleanCfg)
	}
	args = append(args, "dm", "boot-init", "--worker")

	// Intentional detached background subprocess so OpenWrt procd boot does not block on network settle.
	cmd := exec.Command(resolvedExe, args...)
	cmd.Env = os.Environ()
	proc.SetDetachedAttr(cmd)

	devNull := os.DevNull
	if runtime.GOOS == "windows" {
		devNull = "NUL"
	}
	if nullFile, err := os.OpenFile(devNull, os.O_RDONLY, 0); err == nil {
		cmd.Stdin = nullFile
		defer nullFile.Close()
	}

	targetLog := cmp.Or(strings.TrimSpace(logPath), DefaultBootInitLog)
	if logFile, err := fsx.OpenCappedAppendFile(targetLog, MaxLowMemDaemonLogBytes, 0600); err == nil {
		cmd.Stdout = logFile
		cmd.Stderr = logFile
		defer logFile.Close()
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("spawn boot-init worker: %w", err)
	}
	_ = cmd.Process.Release()
	return nil
}
