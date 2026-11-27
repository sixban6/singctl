// 文件职责：提供 Tailscale 内核 TUN 驱动 (/dev/net/tun) 与纯用户态降级检测，以及跨 OpenWrt (apk/opkg) 与 Linux 的一键无损切换内核模式修复能力。
package tailscale

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"singctl/internal/common/sysinfo"
	"singctl/internal/constant"
	"singctl/internal/logger"
	"singctl/internal/platform/servicemgr"
)

// TunDiagnostics 描述宿主机内核 TUN 驱动可用性与当前 Tailscale 运行模式诊断结果。
type TunDiagnostics struct {
	TunAvailable      bool   `json:"tunAvailable"`
	UserspaceMode     bool   `json:"userspaceMode"`
	TunInterfaceUp    bool   `json:"tunInterfaceUp"`
	CanSwitchToKernel bool   `json:"canSwitchToKernel"`
	Reason            string `json:"tunReason,omitempty"`
}

// TunProbeDeps 允许单元测试注入全部宿主机 I/O 探测依赖，避免污染真实宿主机。
type TunProbeDeps struct {
	StatPath         func(path string) bool
	HasInterface     func(name string) bool
	ReadFile         func(path string) ([]byte, error)
	Runner           CmdRunner
	LookPath         func(file string) (string, error)
	IsOpenWrt        func() bool
	InitScriptPath   string
	SystemdUnitPath  string
	TotalRAMBytes    func() uint64
	ConfigureFW      func()
	ApplyLanShieldFn func(ctx context.Context) error
	WaitPollAttempts int
}

func (d TunProbeDeps) statPath(p string) bool {
	if d.StatPath != nil {
		return d.StatPath(p)
	}
	_, err := os.Stat(p)
	return err == nil
}

func (d TunProbeDeps) hasInterface(name string) bool {
	if d.HasInterface != nil {
		return d.HasInterface(name)
	}
	_, err := net.InterfaceByName(name)
	return err == nil
}

func (d TunProbeDeps) readFile(p string) ([]byte, error) {
	if d.ReadFile != nil {
		return d.ReadFile(p)
	}
	return os.ReadFile(p)
}

func (d TunProbeDeps) run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if d.Runner != nil {
		return d.Runner(ctx, "", name, args...)
	}
	return defaultCmdRunner(ctx, "", name, args...)
}

func (d TunProbeDeps) lookPath(file string) (string, error) {
	if d.LookPath != nil {
		return d.LookPath(file)
	}
	return exec.LookPath(file)
}

func (d TunProbeDeps) isOpenWrt() bool {
	if d.IsOpenWrt != nil {
		return d.IsOpenWrt()
	}
	return d.statPath("/etc/openwrt_release")
}

func (d TunProbeDeps) initScriptPath() string {
	if strings.TrimSpace(d.InitScriptPath) != "" {
		return d.InitScriptPath
	}
	return constant.TailscaleInitdScript
}

func (d TunProbeDeps) systemdUnitPath() string {
	if strings.TrimSpace(d.SystemdUnitPath) != "" {
		return d.SystemdUnitPath
	}
	return constant.TailscaleSystemdService
}

func (d TunProbeDeps) totalRAM() uint64 {
	if d.TotalRAMBytes != nil {
		return d.TotalRAMBytes()
	}
	return sysinfo.TotalRAMBytes()
}

func probeTunKernelAvailable(ctx context.Context, deps TunProbeDeps) bool {
	if deps.statPath("/dev/net/tun") || deps.statPath("/sys/class/misc/tun") {
		return true
	}
	if _, err := deps.run(ctx, "modprobe", "tun"); err == nil {
		return true
	}
	return false
}

func scriptConfiguredUserspace(deps TunProbeDeps) bool {
	paths := []string{deps.initScriptPath(), deps.systemdUnitPath()}
	for _, p := range paths {
		raw, err := deps.readFile(p)
		if err != nil {
			continue
		}
		if strings.Contains(string(raw), "--tun=userspace-networking") {
			return true
		}
	}
	return false
}

// InspectTunDiagnostics 综合检测内核 /dev/net/tun、tailscale0 网卡及服务脚本是否处于纯用户态降级模式。
func InspectTunDiagnostics(ctx context.Context, running bool, deps TunProbeDeps) TunDiagnostics {
	tunAvail := probeTunKernelAvailable(ctx, deps)
	ifaceUp := deps.hasInterface("tailscale0")
	scriptUserspace := scriptConfiguredUserspace(deps)

	userspace := !tunAvail || scriptUserspace || (running && !ifaceUp)
	diag := TunDiagnostics{
		TunAvailable:      tunAvail,
		UserspaceMode:     userspace,
		TunInterfaceUp:    ifaceUp,
		CanSwitchToKernel: tunAvail && userspace,
	}
	if !userspace {
		return diag
	}
	if tunAvail {
		diag.Reason = "内核 TUN 驱动已就绪，但 Tailscale 当前仍运行在纯用户态模式（缺少 tailscale0 网卡），局域网设备无法透明访问远端内网，点击一键修复即可切换至内核模式。"
	} else {
		diag.Reason = "当前系统缺少内核 TUN 驱动（/dev/net/tun 不存在，未安装 kmod-tun），Tailscale 已降级为纯用户态模式，局域网设备无法透明访问远端内网子网。"
	}
	return diag
}

// RepairTunMode 执行零断网一键修复：按需安装并加载 kmod-tun、重写内核模式启动脚本、重启 tailscaled 并校验 tailscale0 上线。
func RepairTunMode(ctx context.Context, deps TunProbeDeps) (TunDiagnostics, error) {
	initial := InspectTunDiagnostics(ctx, true, deps)
	if initial.TunAvailable && !initial.UserspaceMode && initial.TunInterfaceUp {
		logger.Success("Tailscale 已处于内核 TUN 模式（tailscale0 正常），无需修复")
		return initial, nil
	}

	tunReady := initial.TunAvailable
	var installErrDetail string
	if !tunReady {
		logger.Info("检测到系统缺少内核 TUN 驱动 (/dev/net/tun)，尝试自动安装 kmod-tun...")
		installErrDetail = tryInstallKmodTun(ctx, deps)
		if !deps.statPath("/dev/net/tun") && deps.statPath("/sys/class/misc/tun") {
			_, _ = deps.run(ctx, "sh", "-c", "mkdir -p /dev/net && mknod /dev/net/tun c 10 200 && chmod 0666 /dev/net/tun")
		}
		tunReady = probeTunKernelAvailable(ctx, deps)
	}

	if !tunReady {
		vermagic := detectKernelVermagic(ctx, deps)
		var detail strings.Builder
		detail.WriteString("无法自动安装内核 TUN 驱动 (kmod-tun)，已安全中止切换并保持现有网络不受影响。")
		if vermagic != "" {
			fmt.Fprintf(&detail, "\n当前固件内核版本: %s", vermagic)
		}
		if installErrDetail != "" {
			fmt.Fprintf(&detail, "\n包管理器返回: %s", installErrDetail)
		}
		detail.WriteString("\n建议方案：\n1. 从当前定制固件作者/构建仓库下载与上述内核版本完全一致的 kmod-tun_*.ipk 安装后，再点击一键修复；\n2. 或刷入自带 kmod-tun 的标准 OpenWrt/ImmortalWrt 固件，亦或将 Tailscale 透明子网网关运行在具备内核 TUN 驱动的上级主路由上。")
		return InspectTunDiagnostics(ctx, true, deps), fmt.Errorf("%s", detail.String())
	}

	if !deps.statPath("/dev/net/tun") {
		_, _ = deps.run(ctx, "modprobe", "tun")
		if !deps.statPath("/dev/net/tun") {
			_, _ = deps.run(ctx, "sh", "-c", "mkdir -p /dev/net && mknod /dev/net/tun c 10 200 && chmod 0666 /dev/net/tun")
		}
	}

	logger.Info("内核 TUN 驱动已就绪，正在重写 Tailscale 为内核模式启动脚本...")
	ram := deps.totalRAM()
	if deps.isOpenWrt() {
		initPath := deps.initScriptPath()
		content := RenderInitScriptWithMem(true, ram)
		if err := os.WriteFile(initPath, []byte(content), 0755); err != nil {
			return InspectTunDiagnostics(ctx, true, deps), fmt.Errorf("写入 %s 失败: %w", initPath, err)
		}
		if deps.ConfigureFW != nil {
			deps.ConfigureFW()
		} else if runtime.GOOS == "linux" {
			configureOpenWrtTailscaleFirewall()
		}
		logger.Info("正在重启 Tailscale 服务进入内核 TUN 模式...")
		if out, err := deps.run(ctx, initPath, "restart"); err != nil {
			return InspectTunDiagnostics(ctx, true, deps), fmt.Errorf("重启 Tailscale 服务失败: %w (%s)", err, strings.TrimSpace(string(out)))
		}
	} else {
		unitPath := deps.systemdUnitPath()
		content := RenderSystemdScriptWithMem(true, ram)
		if err := os.WriteFile(unitPath, []byte(content), 0644); err != nil {
			return InspectTunDiagnostics(ctx, true, deps), fmt.Errorf("写入 %s 失败: %w", unitPath, err)
		}
		var smRunner servicemgr.CmdRunner
		if deps.Runner != nil {
			smRunner = tunServiceRunner{fn: deps.Runner}
		}
		mgr := servicemgr.Detect(smRunner)
		if err := mgr.Restart(ctx, "tailscaled"); err != nil {
			return InspectTunDiagnostics(ctx, true, deps), fmt.Errorf("重启 tailscaled 失败: %w", err)
		}
	}

	attempts := deps.WaitPollAttempts
	if attempts <= 0 {
		attempts = 16
	}
	for range attempts {
		if deps.hasInterface("tailscale0") {
			break
		}
		select {
		case <-ctx.Done():
			return InspectTunDiagnostics(ctx, true, deps), ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}

	if deps.ApplyLanShieldFn != nil {
		_ = deps.ApplyLanShieldFn(ctx)
	} else if runtime.GOOS == "linux" {
		_ = SyncLANCoexistenceShield(ctx, LANShieldOptions{
			IsOpenWrt:          deps.isOpenWrt(),
			EnsureNetfilterOff: true,
		})
	}

	final := InspectTunDiagnostics(ctx, true, deps)
	if !final.TunInterfaceUp {
		return final, fmt.Errorf("已切换内核模式并重启 tailscaled，但暂未检测到 tailscale0 网卡，请检查 logread / journalctl 日志")
	}
	logger.Success("Tailscale 已成功切换至内核 TUN 模式（tailscale0 已上线），局域网设备现可透明访问远端内网")
	return final, nil
}

func tryInstallKmodTun(ctx context.Context, deps TunProbeDeps) string {
	if _, err := deps.lookPath("apk"); err == nil {
		logger.Info("检测到 apk 包管理器，正在执行 apk update && apk add kmod-tun...")
		_, _ = deps.run(ctx, "apk", "update")
		out, err := deps.run(ctx, "apk", "add", "kmod-tun")
		if err == nil {
			_, _ = deps.run(ctx, "modprobe", "tun")
			return ""
		}
		return strings.TrimSpace(string(out))
	}
	if _, err := deps.lookPath("opkg"); err == nil {
		logger.Info("检测到 opkg 包管理器，正在执行 opkg update && opkg install kmod-tun...")
		_, _ = deps.run(ctx, "opkg", "update")
		out, err := deps.run(ctx, "opkg", "install", "kmod-tun")
		if err == nil {
			_, _ = deps.run(ctx, "modprobe", "tun")
			return ""
		}
		return strings.TrimSpace(string(out))
	}
	return "未检测到可用的 apk 或 opkg 包管理器"
}

func detectKernelVermagic(ctx context.Context, deps TunProbeDeps) string {
	if _, err := deps.lookPath("opkg"); err == nil {
		if out, err := deps.run(ctx, "opkg", "info", "kernel"); err == nil {
			for line := range strings.SplitSeq(string(out), "\n") {
				if v, ok := strings.CutPrefix(strings.TrimSpace(line), "Version:"); ok {
					return strings.TrimSpace(v)
				}
			}
		}
	}
	if out, err := deps.run(ctx, "uname", "-r"); err == nil {
		return strings.TrimSpace(string(out))
	}
	return ""
}

type tunServiceRunner struct {
	fn CmdRunner
}

func (r tunServiceRunner) Run(ctx context.Context, _ time.Duration, name string, args ...string) error {
	_, err := r.fn(ctx, "", name, args...)
	return err
}

func (r tunServiceRunner) CombinedOutput(ctx context.Context, _ time.Duration, name string, args ...string) ([]byte, error) {
	return r.fn(ctx, "", name, args...)
}
