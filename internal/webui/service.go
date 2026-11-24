// 文件职责：提供客户端 WebUI 跨平台原生服务（OpenWrt procd / Linux systemd）自动安装、平滑接管、0600 口令持久化与 OOM 保护。
package webui

import (
	"cmp"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"singctl/internal/common/fsx"
	"singctl/internal/daemon"
	"singctl/internal/logger"
	"singctl/internal/platform/servicemgr"
)

const (
	// WebServiceName 客户端 WebUI 系统托管服务名称（procd: /etc/init.d/singctl-web, systemd: singctl-web.service）。
	WebServiceName = "singctl-web"
	// WebPasswordFileName 与 singctl.yaml 同目录落盘的 0600 原始口令文件名（零 Shell 解析、零命令行/ubus 暴露）。
	WebPasswordFileName = "web.password"

	defaultWebServiceTimeout = 25 * time.Second
)

const unsafeUnitChars = " \t\r\n\x00;|&$`'\"\\<>(){}*?!"

func validateUnitArg(label, value string, allowEmpty bool) error {
	if value == "" {
		if allowEmpty {
			return nil
		}
		return fmt.Errorf("%s 不能为空", label)
	}
	if strings.ContainsAny(value, unsafeUnitChars) {
		return fmt.Errorf("%s 包含非法空白或控制/注入字符: %q", label, value)
	}
	for i := 0; i < len(value); i++ {
		if value[i] < 0x20 || value[i] == 0x7f {
			return fmt.Errorf("%s 包含非法控制字符", label)
		}
	}
	return nil
}

// WebPasswordFilePath 返回客户端 WebUI 0600 口令文件的默认落盘路径（与 singctl.yaml 同目录）。
func WebPasswordFilePath(cfgPath string) string {
	trimmed := strings.TrimSpace(cfgPath)
	if trimmed != "" {
		if abs, err := filepath.Abs(trimmed); err == nil {
			return filepath.Join(filepath.Dir(abs), WebPasswordFileName)
		}
		return filepath.Join(filepath.Dir(trimmed), WebPasswordFileName)
	}
	return filepath.Join(filepath.Dir(WebStatePath()), WebPasswordFileName)
}

// WriteWebPasswordFile 以 0600 权限原子持久化 WebUI 口令；口令为空时幂等删除该文件。
func WriteWebPasswordFile(path, password string) error {
	cleanPath := strings.TrimSpace(path)
	if cleanPath == "" {
		return fmt.Errorf("web password file path must not be empty")
	}
	if password == "" {
		if err := os.Remove(cleanPath); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	if dir := filepath.Dir(cleanPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("create password dir %s: %w", dir, err)
		}
	}
	return fsx.WriteAtomic0600(cleanPath, []byte(password))
}

// ReadWebPasswordFile 从 0600 原始文本文件安全读取 WebUI 口令（仅去除尾部换行，不做任何 Shell 解析）。
func ReadWebPasswordFile(path string) (string, error) {
	raw, err := os.ReadFile(strings.TrimSpace(path))
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(raw), "\r\n"), nil
}

// ResolveWebPasswordWithFile 按优先级（命令行 -p > 环境变量 SINGCTL_WEB_PASSWORD > 0600 口令文件）解析访问口令。
func ResolveWebPasswordWithFile(flagVal, cfgPath, overridePath string) string {
	if flagVal != "" {
		return flagVal
	}
	// 逆序扫描环境变量（兼容旧版 <= v1.14.126 ScheduleDetachedRestart 使用 append 追加同名键的场景）
	env := os.Environ()
	for i := len(env) - 1; i >= 0; i-- {
		if k, v, ok := strings.Cut(env[i], "="); ok && k == "SINGCTL_WEB_PASSWORD" && v != "" {
			return v
		}
	}
	if v := os.Getenv("SINGCTL_WEB_PASSWORD"); v != "" {
		return v
	}
	pwPath := cmp.Or(strings.TrimSpace(overridePath), WebPasswordFilePath(cfgPath))
	if pw, err := ReadWebPasswordFile(pwPath); err == nil && pw != "" {
		return pw
	}
	return ""
}

// ResolveWebPassword 使用默认口令文件路径解析 WebUI 访问口令。
func ResolveWebPassword(flagVal, cfgPath string) string {
	return ResolveWebPasswordWithFile(flagVal, cfgPath, "")
}

// BuildWebUnitSpec 构造 OpenWrt procd 与 Linux systemd 跨平台原生托管单元规格（零明文口令、防注入校验）。
func BuildWebUnitSpec(exePath, cfgPath, listen string) (servicemgr.UnitSpec, error) {
	exe := strings.TrimSpace(exePath)
	if err := validateUnitArg("executable path", exe, false); err != nil {
		return servicemgr.UnitSpec{}, err
	}
	cfg := strings.TrimSpace(cfgPath)
	if err := validateUnitArg("config path", cfg, true); err != nil {
		return servicemgr.UnitSpec{}, err
	}

	normListen := cmp.Or(NormalizeLegacyWildcardListen(listen), ":8090")
	if err := validateUnitArg("listen address", normListen, false); err != nil {
		return servicemgr.UnitSpec{}, err
	}
	if _, _, err := net.SplitHostPort(normListen); err != nil {
		return servicemgr.UnitSpec{}, fmt.Errorf("listen address 格式非法 %q: %w", normListen, err)
	}

	args := make([]string, 0, 7)
	args = append(args, exe)
	if cfg != "" {
		args = append(args, "--config", cfg)
	}
	args = append(args, "web", "--managed", "-l", normListen)
	cmdLine := strings.Join(args, " ")

	procdBody := fmt.Sprintf(`#!/bin/sh /etc/rc.common

START=95
STOP=10
USE_PROCD=1

start_service() {
    procd_open_instance "%s"
    procd_set_param command %s
    procd_set_param respawn 3600 5 0
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_close_instance
}

status_service() {
    if ubus call service list '{"name":"%s"}' 2>/dev/null | grep -q '"running":[[:space:]]*true'; then
        echo "running"
        return 0
    fi
    echo "stopped"
    return 3
}
`, WebServiceName, cmdLine, WebServiceName)

	systemdBody := fmt.Sprintf(`[Unit]
Description=SingCtl Web Management UI
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s
Restart=always
RestartSec=3
OOMScoreAdjust=-500
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
`, cmdLine)

	return servicemgr.UnitSpec{
		Name:        WebServiceName,
		ProcdPath:   "/etc/init.d/" + WebServiceName,
		ProcdBody:   procdBody,
		SystemdPath: "/etc/systemd/system/" + WebServiceName + ".service",
		SystemdBody: systemdBody,
	}, nil
}

// SetupManagedRuntime 配置 `singctl web --managed` 的定长 0600 日志落盘与 OOM 保护，返回资源关闭钩子与托管器类型标识。
func SetupManagedRuntime(opts Options) (func(), string) {
	maxLogBytes := int64(MaxWebLogBytes)
	if (opts.LowMemoryMode != nil && *opts.LowMemoryMode) || (opts.LowMemoryMode == nil && daemon.IsLowMemoryDevice()) {
		maxLogBytes = MaxLowMemWebLogBytes
	}

	var logFile *os.File
	if f, err := fsx.OpenCappedAppendFile(WebLogPath(), maxLogBytes, 0600); err == nil {
		logFile = f
		logger.SetColor(false)
		logger.SetOutput(f)
	}

	if runtime.GOOS == "linux" {
		// 尽力降低 OOM 分数，避免 256MB 小内存路由优先误杀管理面板；非特权或受限容器静默忽略
		_ = os.WriteFile("/proc/self/oom_score_adj", []byte("-500\n"), 0644)
	}

	managedBy := "service"
	switch servicemgr.DetectHost().Kind {
	case servicemgr.InitProcd:
		managedBy = string(servicemgr.InitProcd)
	case servicemgr.InitSystemd:
		managedBy = string(servicemgr.InitSystemd)
	}

	cleanup := func() {
		removeOwnWebStateFile()
		if logFile != nil {
			_ = logFile.Close()
		}
	}
	return cleanup, managedBy
}

// WriteManagedReadyState 在受管服务模式下原子写入 0600 状态文件（不落盘明文口令，由 web.password 独立保管）。
func WriteManagedReadyState(opts Options, actualListen, managedBy string) {
	listen := strings.TrimSpace(opts.Listen)
	if listen == "" || strings.HasSuffix(listen, ":0") {
		listen = actualListen
	}
	_ = WriteWebStateAtomic(WebState{
		Pid:        os.Getpid(),
		Listen:     listen,
		ConfigPath: opts.ConfigPath,
		ManagedBy:  managedBy,
	})
}

func resolveServiceMgrForControl(deps BackgroundDeps) servicemgr.Manager {
	if deps.ServiceMgr != nil {
		kind := deps.ServiceMgr.Kind()
		if kind == servicemgr.InitProcd || kind == servicemgr.InitSystemd {
			return deps.ServiceMgr
		}
		return nil
	}
	if runtime.GOOS != "linux" || WebStatePathOverride != "" || strings.TrimSpace(os.Getenv("SINGCTL_WEB_STATE_PATH")) != "" {
		return nil
	}
	host := servicemgr.DetectHost()
	if host.Kind != servicemgr.InitProcd && host.Kind != servicemgr.InitSystemd {
		return nil
	}
	return servicemgr.Detect(nil)
}

func shouldUseSystemService(opts Options, deps BackgroundDeps) (servicemgr.Manager, bool) {
	if opts.NoService {
		return nil, false
	}
	if deps.ServiceMgr != nil {
		kind := deps.ServiceMgr.Kind()
		return deps.ServiceMgr, kind == servicemgr.InitProcd || kind == servicemgr.InitSystemd
	}
	if os.Geteuid() != 0 {
		return nil, false
	}
	mgr := resolveServiceMgrForControl(deps)
	return mgr, mgr != nil
}

func defaultWaitManagedReady(ctx context.Context, mgr servicemgr.Manager) (WebState, bool) {
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		if st, err := ReadWebState(); err == nil && WebProcMatches(st.Pid) {
			if st.ManagedBy == "" {
				st.ManagedBy = string(mgr.Kind())
			}
			return st, true
		}
		select {
		case <-ctx.Done():
			return WebState{}, false
		case <-time.After(150 * time.Millisecond):
		}
	}
	if mgr.IsActive(ctx, WebServiceName) {
		return WebState{ManagedBy: string(mgr.Kind())}, true
	}
	return WebState{}, false
}

func startManagedService(opts Options, mgr servicemgr.Manager, eff BackgroundDeps) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultWebServiceTimeout)
	defer cancel()

	cfgPath := strings.TrimSpace(opts.ConfigPath)
	if cfgPath != "" {
		if abs, err := filepath.Abs(cfgPath); err == nil {
			cfgPath = abs
		}
	}

	exePath := strings.TrimSpace(eff.ExecutablePath)
	if exePath == "" {
		resolved, err := resolveOnDiskExecutable()
		if err != nil {
			return fmt.Errorf("resolve singctl executable: %w", err)
		}
		exePath = resolved
	}

	spec, err := BuildWebUnitSpec(exePath, cfgPath, opts.Listen)
	if err != nil {
		return err
	}

	legacySt, hasLegacy := eff.HasLegacyStandalone()
	pwPath := cmp.Or(strings.TrimSpace(eff.PasswordFilePath), WebPasswordFilePath(cfgPath))
	effectivePassword := opts.Password
	if !opts.ClearPassword && effectivePassword == "" && hasLegacy && legacySt.Password != "" {
		effectivePassword = legacySt.Password
	}
	if opts.ClearPassword {
		if err := WriteWebPasswordFile(pwPath, ""); err != nil {
			return fmt.Errorf("clear web password file: %w", err)
		}
	} else if effectivePassword != "" {
		if err := WriteWebPasswordFile(pwPath, effectivePassword); err != nil {
			return fmt.Errorf("write web password file: %w", err)
		}
	}

	// 关键平滑接管顺序：先停止旧的裸 fork 进程释放监听端口，再由 procd / systemd 拉起托管实例。
	if hasLegacy && !mgr.IsActive(ctx, WebServiceName) {
		if _, err := eff.StopStandalone(); err != nil {
			return fmt.Errorf("stop legacy standalone webui: %w", err)
		}
	}

	if err := mgr.InstallUnit(ctx, spec); err != nil {
		return fmt.Errorf("install %s service (%s): %w", WebServiceName, mgr.Kind(), err)
	}

	st, ok := eff.WaitManagedReady(ctx, mgr)
	listenDisplay := cmp.Or(strings.TrimSpace(st.Listen), NormalizeLegacyWildcardListen(opts.Listen), ":8090")
	if ok && st.Pid > 0 {
		logger.Success("WebUI 已通过系统服务启动并设置开机自启 (%s 托管, pid=%d)", mgr.Kind(), st.Pid)
	} else {
		logger.Success("WebUI 已通过系统服务启动并设置开机自启 (%s 托管)", mgr.Kind())
	}
	for _, u := range FormatListenURLs(listenDisplay) {
		logger.Info("  ➜  http://%s", u)
	}
	if effectivePassword == "" {
		if existing, rerr := ReadWebPasswordFile(pwPath); rerr != nil || existing == "" {
			logger.Warn("  ⚠  未设置访问口令,请确保仅暴露在可信内网(建议 --password 或 SINGCTL_WEB_PASSWORD)")
		}
	}
	logger.Info("停止: singctl web stop   日志: %s", WebLogPath())
	return nil
}
