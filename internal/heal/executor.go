// 文件职责：以声明式 healStep 流水线编排核心组件金丝雀升级、证书/WARP 修复、系统安全补丁与残留动态库热重载。
package heal

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"time"

	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/deploy"
	"singctl/internal/platform/servicemgr"
)

func healServiceMgr() servicemgr.Manager {
	return servicemgr.NewSystemd(nil)
}

var healRunMu = make(chan struct{}, 1)

// Deps 定义自愈流水线各阶段的可注入协作者（未设置字段自动回退至生产默认实现）。
type Deps struct {
	Scan              func(ctx context.Context, cfgPath, currentVer string) StatusReport
	LoadConfig        func(path string) (*config.Config, error)
	CoreHealer        *CoreHealer
	SyncHysteria2Cert func(cfg *config.Config) (bool, string, error)
	SyncWarpConfig    func() (bool, string, error)
	ServiceMgr        servicemgr.Manager
	HasBinary         func(name string) bool
	IsOpenWrt         func() bool
	GOOS              string
	RunCmd            func(ctx context.Context, env []string, name string, args ...string) ([]byte, error)
	ScanStaleServices func() []string
	VerifySSHD        func() bool
	RestartWebDaemon  func(async bool)
	TriggerReboot     func()
}

type execDeps struct {
	scan              func(ctx context.Context, cfgPath, currentVer string) StatusReport
	loadConfig        func(path string) (*config.Config, error)
	coreHealer        *CoreHealer
	syncHysteria2Cert func(cfg *config.Config) (bool, string, error)
	syncWarpConfig    func() (bool, string, error)
	svcMgr            servicemgr.Manager
	hasBinary         func(name string) bool
	isOpenWrt         func() bool
	goos              string
	runCmd            func(ctx context.Context, env []string, name string, args ...string) ([]byte, error)
	scanStaleServices func() []string
	verifySSHD        func() bool
	restartWebDaemon  func(async bool)
	triggerReboot     func()
}

func resolveExecDeps(deps Deps) execDeps {
	out := execDeps{
		scan:              Scan,
		loadConfig:        config.Load,
		syncHysteria2Cert: deploy.SyncHysteria2CertIfNeeded,
		syncWarpConfig:    deploy.SyncWarpConfigIfNeeded,
		svcMgr:            deps.ServiceMgr,
		hasBinary:         hasBinary,
		isOpenWrt:         isOpenWrtSystem,
		goos:              cmp.Or(strings.TrimSpace(deps.GOOS), runtime.GOOS),
		runCmd:            defaultRunCmd,
		scanStaleServices: ScanStaleSharedLibraryServices,
		verifySSHD:        verifySSHDConfig,
		restartWebDaemon:  restartWebDaemonSafely,
		triggerReboot:     triggerDelayedReboot,
	}
	if out.svcMgr == nil {
		out.svcMgr = healServiceMgr()
	}
	if deps.Scan != nil {
		out.scan = deps.Scan
	}
	if deps.LoadConfig != nil {
		out.loadConfig = deps.LoadConfig
	}
	if deps.SyncHysteria2Cert != nil {
		out.syncHysteria2Cert = deps.SyncHysteria2Cert
	}
	if deps.SyncWarpConfig != nil {
		out.syncWarpConfig = deps.SyncWarpConfig
	}
	if deps.HasBinary != nil {
		out.hasBinary = deps.HasBinary
	}
	if deps.IsOpenWrt != nil {
		out.isOpenWrt = deps.IsOpenWrt
	}
	if deps.RunCmd != nil {
		out.runCmd = deps.RunCmd
	}
	if deps.ScanStaleServices != nil {
		out.scanStaleServices = deps.ScanStaleServices
	}
	if deps.VerifySSHD != nil {
		out.verifySSHD = deps.VerifySSHD
	}
	if deps.RestartWebDaemon != nil {
		out.restartWebDaemon = deps.RestartWebDaemon
	}
	if deps.TriggerReboot != nil {
		out.triggerReboot = deps.TriggerReboot
	}
	out.coreHealer = deps.CoreHealer
	if out.coreHealer == nil {
		out.coreHealer = NewCoreHealer(CoreHealerDeps{
			ServiceMgr:   out.svcMgr,
			RestartWebFn: out.restartWebDaemon,
		})
	}
	return out
}

func defaultRunCmd(ctx context.Context, env []string, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if len(env) > 0 {
		cmd.Env = append(os.Environ(), env...)
	}
	return cmd.CombinedOutput()
}

type healRunState struct {
	opts                RunOptions
	deps                execDeps
	cfgPath             string
	cfg                 *config.Config
	initial             StatusReport
	effectiveSingctlVer string
	actions             []LayerActionDetail
	allOK               bool
	updatedCount        int
	rollbackCount       int
}

func (st *healRunState) recordAction(act LayerActionDetail) {
	st.actions = append(st.actions, act)
	if !act.Success {
		st.allOK = false
	}
	if act.Updated {
		st.updatedCount++
	}
	if act.RolledBack {
		st.rollbackCount++
	}
}

type healStep struct {
	name    string
	applies func(st *healRunState) bool
	run     func(ctx context.Context, st *healRunState)
}

var defaultHealPipeline = []healStep{
	{name: "core_canary_upgrades", run: stepHealCoreComponents},
	{name: "hysteria2_cert_sync", run: stepSyncHysteria2Cert},
	{name: "warp_tunnel_sync", run: stepSyncWarpTunnel},
	{
		name:    "os_security_and_stale_libs",
		applies: func(st *healRunState) bool { return st.deps.goos == "linux" },
		run:     stepHealOSLayer,
	},
}

// Run performs a full 3-layer security scan and (unless opts.CheckOnly) executes availability-safe self-healing.
func Run(ctx context.Context, opts RunOptions) (RunResult, error) {
	return RunWithDeps(ctx, opts, Deps{})
}

// RunWithDeps 使用显式注入依赖执行三层安全自愈流水线（供离线测试与生产 Run 共享）。
func RunWithDeps(ctx context.Context, opts RunOptions, deps Deps) (RunResult, error) {
	resolved := resolveExecDeps(deps)
	cfgPath := resolveHealConfigPath(opts.ConfigPath)

	if opts.CheckOnly {
		report := resolved.scan(ctx, cfgPath, opts.CurrentSingctlVer)
		return RunResult{
			Execution: HealHistoryItem{
				Timestamp:      report.CheckedAt,
				Trigger:        cmp.Or(opts.Trigger, "manual"),
				Success:        true,
				Summary:        report.PostureLabel,
				RebootRequired: report.Kernel.RebootRequired,
			},
			Status: report,
		}, nil
	}

	select {
	case healRunMu <- struct{}{}:
		defer func() { <-healRunMu }()
	default:
		return RunResult{}, fmt.Errorf("当前已有安全自愈任务正在运行，请稍候重试")
	}

	start := time.Now()
	var cfg *config.Config
	if cfgPath != "" {
		cfg, _ = resolved.loadConfig(cfgPath)
	}

	st := &healRunState{
		opts:                opts,
		deps:                resolved,
		cfgPath:             cfgPath,
		cfg:                 cfg,
		initial:             resolved.scan(ctx, cfgPath, opts.CurrentSingctlVer),
		effectiveSingctlVer: opts.CurrentSingctlVer,
		allOK:               true,
	}

	for _, step := range defaultHealPipeline {
		if step.applies != nil && !step.applies(st) {
			continue
		}
		step.run(ctx, st)
	}

	finalReport := runPostHealVerification(ctx, st)
	willReboot := evaluateKernelRebootAction(st, finalReport.Kernel)

	hist := HealHistoryItem{
		Timestamp:      time.Now().Format(time.RFC3339),
		Trigger:        cmp.Or(strings.TrimSpace(opts.Trigger), "manual"),
		Success:        st.allOK,
		DurationMs:     time.Since(start).Milliseconds(),
		Summary:        formatHealSummary(st, willReboot),
		Actions:        st.actions,
		RebootRequired: finalReport.Kernel.RebootRequired && !willReboot,
	}

	_ = RecordExecution(cfgPath, hist, &finalReport)
	finalReport.History = append([]HealHistoryItem{hist}, finalReport.History...)
	if len(finalReport.History) > 30 {
		finalReport.History = finalReport.History[:30]
	}
	if willReboot {
		resolved.triggerReboot()
	}

	return RunResult{Execution: hist, Status: finalReport}, nil
}

func resolveHealConfigPath(raw string) string {
	cfgPath := strings.TrimSpace(raw)
	if cfgPath != "" {
		return cfgPath
	}
	const defaultSingCtlConfigPath = "/etc/singctl/singctl.yaml"
	if _, err := os.Stat(defaultSingCtlConfigPath); err == nil {
		return defaultSingCtlConfigPath
	}
	return ""
}

func stepHealCoreComponents(ctx context.Context, st *healRunState) {
	for _, comp := range st.initial.Core.Components {
		if !comp.Installed || !comp.HasUpdate {
			continue
		}
		act := st.deps.coreHealer.HealComponent(ctx, st.cfg, st.cfgPath, comp, st.opts.AsyncWebRestart)
		st.recordAction(act)
		if act.Updated && comp.Name == "singctl" && comp.LatestVersion != "" {
			st.effectiveSingctlVer = comp.LatestVersion
		}
	}
}

func stepSyncHysteria2Cert(_ context.Context, st *healRunState) {
	healed, msg, err := st.deps.syncHysteria2Cert(st.cfg)
	if err != nil {
		st.recordAction(LayerActionDetail{
			Layer:   "core",
			Target:  "hysteria2-cert",
			Success: false,
			Message: "Hysteria2 证书同步异常: " + err.Error(),
		})
		return
	}
	if healed {
		st.recordAction(LayerActionDetail{
			Layer:   "core",
			Target:  "hysteria2-cert",
			Success: true,
			Updated: true,
			Message: msg,
		})
	}
}

func stepSyncWarpTunnel(_ context.Context, st *healRunState) {
	healed, msg, err := st.deps.syncWarpConfig()
	if err != nil {
		st.recordAction(LayerActionDetail{
			Layer:   "core",
			Target:  "warp-tunnel",
			Success: false,
			Message: "WARP 隧道自愈异常: " + err.Error(),
		})
		return
	}
	if healed {
		st.recordAction(LayerActionDetail{
			Layer:   "core",
			Target:  "warp-tunnel",
			Success: true,
			Updated: true,
			Message: msg,
		})
	}
}

func stepHealOSLayer(ctx context.Context, st *healRunState) {
	if st.deps.isOpenWrt() {
		st.recordAction(LayerActionDetail{
			Layer:   "os",
			Target:  "openwrt-guard",
			Success: true,
			Updated: false,
			Message: "OpenWrt 闪存防变砖保护生效：跳过全量 opkg upgrade，仅维护核心二进制",
		})
		return
	}

	switch {
	case st.deps.hasBinary("apt-get"):
		if act, ok := healAptSecurity(ctx, st.deps); ok {
			st.recordAction(act)
		}
	case st.deps.hasBinary("dnf"):
		if act, ok := healDnfSecurity(ctx, st.deps); ok {
			st.recordAction(act)
		}
	}

	if act, ok := reloadStaleLibServices(ctx, st.deps, st.opts.AsyncWebRestart); ok {
		st.recordAction(act)
	}
}

func healAptSecurity(ctx context.Context, deps execDeps) (LayerActionDetail, bool) {
	uCtx, uCancel := context.WithTimeout(ctx, 90*time.Second)
	_, _ = deps.runCmd(uCtx, []string{"DEBIAN_FRONTEND=noninteractive"}, "apt-get", "update", "-qq")
	uCancel()

	sCtx, sCancel := context.WithTimeout(ctx, 20*time.Second)
	simOut, simErr := deps.runCmd(sCtx, []string{"LC_ALL=C"}, "apt-get", "-s", "-o", "Debug::NoLocking=true", "upgrade")
	sCancel()
	if simErr != nil {
		return LayerActionDetail{}, false
	}

	secPkgs := ParseAptSimulateSecurityUpdates(string(simOut))
	if len(secPkgs) == 0 {
		return LayerActionDetail{}, false
	}

	iCtx, iCancel := context.WithTimeout(ctx, 4*time.Minute)
	args := append([]string{
		"install", "--only-upgrade", "-y",
		"-o", "Dpkg::Options::=--force-confdef",
		"-o", "Dpkg::Options::=--force-confold",
		"--",
	}, secPkgs...)
	out, iErr := deps.runCmd(iCtx, []string{
		"DEBIAN_FRONTEND=noninteractive",
		"NEEDRESTART_MODE=l",
		"APT_LISTCHANGES_FRONTEND=none",
	}, "apt-get", args...)
	iCancel()

	if iErr != nil {
		return LayerActionDetail{
			Layer:   "os",
			Target:  "apt-security",
			Success: false,
			Message: fmt.Sprintf("APT 安全补丁安装异常: %v (%s)", iErr, truncateText(string(out), 160)),
		}, true
	}

	deps.verifySSHD()
	preview := strings.Join(secPkgs[:min(5, len(secPkgs))], ", ")
	if len(secPkgs) > 5 {
		preview += fmt.Sprintf(" 等 %d 个包", len(secPkgs))
	}
	return LayerActionDetail{
		Layer:   "os",
		Target:  "apt-security",
		Success: true,
		Updated: true,
		Message: fmt.Sprintf("已无感安装 %d 个系统安全补丁 (%s)，保留全部自定义配置", len(secPkgs), preview),
	}, true
}

func healDnfSecurity(ctx context.Context, deps execDeps) (LayerActionDetail, bool) {
	cCtx, cCancel := context.WithTimeout(ctx, 20*time.Second)
	chkOut, _ := deps.runCmd(cCtx, nil, "dnf", "check-update", "--security", "-q")
	cCancel()

	secPkgs := ParseDnfSecurityCheckUpdate(string(chkOut))
	if len(secPkgs) == 0 {
		return LayerActionDetail{}, false
	}

	uCtx, uCancel := context.WithTimeout(ctx, 4*time.Minute)
	out, uErr := deps.runCmd(uCtx, nil, "dnf", "update", "--security", "-y")
	uCancel()
	if uErr != nil {
		return LayerActionDetail{
			Layer:   "os",
			Target:  "dnf-security",
			Success: false,
			Message: fmt.Sprintf("DNF 安全更新异常: %v (%s)", uErr, truncateText(string(out), 160)),
		}, true
	}

	deps.verifySSHD()
	return LayerActionDetail{
		Layer:   "os",
		Target:  "dnf-security",
		Success: true,
		Updated: true,
		Message: fmt.Sprintf("已安装 %d 个 RHEL/DNF 安全更新", len(secPkgs)),
	}, true
}

func reloadStaleLibServices(ctx context.Context, deps execDeps, asyncWebRestart bool) (LayerActionDetail, bool) {
	stale := deps.scanStaleServices()
	if len(stale) == 0 {
		return LayerActionDetail{}, false
	}

	var reloaded []string
	for _, svc := range stale {
		switch svc {
		case "sshd":
			if deps.verifySSHD() {
				if deps.svcMgr.Reload(ctx, "sshd") != nil {
					_ = deps.svcMgr.Reload(ctx, "ssh")
				}
				reloaded = append(reloaded, "sshd")
			}
		case "caddy":
			_ = deps.svcMgr.ReloadOrRestart(ctx, "caddy")
			reloaded = append(reloaded, "caddy")
		case "singctl-ui":
			deps.restartWebDaemon(asyncWebRestart)
			reloaded = append(reloaded, "singctl-ui")
		default:
			if deps.svcMgr.Restart(ctx, svc) == nil {
				reloaded = append(reloaded, svc)
			}
		}
	}
	if len(reloaded) == 0 {
		return LayerActionDetail{}, false
	}
	return LayerActionDetail{
		Layer:   "os",
		Target:  "stale-libs",
		Success: true,
		Updated: true,
		Message: "检测到内存残留旧版动态库 (.so)，已平滑热重载服务: " + strings.Join(reloaded, ", "),
	}, true
}

func runPostHealVerification(ctx context.Context, st *healRunState) StatusReport {
	finalReport := st.deps.scan(ctx, st.cfgPath, st.effectiveSingctlVer)
	if st.opts.AsyncWebRestart && len(finalReport.OS.StaleServices) > 0 {
		finalReport.OS.StaleServices = slices.DeleteFunc(finalReport.OS.StaleServices, func(s string) bool {
			return s == "singctl-ui"
		})
		finalReport.OS.Healthy = finalReport.OS.SecurityCount == 0 && len(finalReport.OS.StaleServices) == 0
		finalReport.Posture, finalReport.PostureLabel = evaluatePosture(finalReport.Core, finalReport.OS, finalReport.Kernel)
	}
	return finalReport
}

func evaluateKernelRebootAction(st *healRunState, kernel KernelLayerStatus) bool {
	if !kernel.RebootRequired {
		return false
	}
	if st.opts.AllowReboot && st.deps.goos == "linux" && !st.deps.isOpenWrt() {
		st.recordAction(LayerActionDetail{
			Layer:   "kernel",
			Target:  "kernel-reboot",
			Success: true,
			Updated: true,
			Message: "将在 3 秒后平滑重启以加载新安全内核 (" + cmp.Or(kernel.InstalledKernel, "reboot-required") + ")",
		})
		return true
	}
	st.recordAction(LayerActionDetail{
		Layer:   "kernel",
		Target:  "kernel-pending",
		Success: true,
		Updated: false,
		Message: cmp.Or(kernel.RebootReason, "存在待重启生效的内核补丁（已保留当前会话不断联，可在维护窗口执行滚动重启）"),
	})
	return false
}

func formatHealSummary(st *healRunState, willReboot bool) string {
	switch {
	case st.rollbackCount > 0:
		return fmt.Sprintf("自愈完成：更新 %d 项，触发 %d 项异常自动回滚保护（服务未中断）", st.updatedCount, st.rollbackCount)
	case st.updatedCount > 0 && !st.allOK:
		return fmt.Sprintf("已修复 %d 项安全更新，但部分组件更新遇到异常，请查看明细", st.updatedCount)
	case st.updatedCount > 0 && willReboot:
		return fmt.Sprintf("成功修复 %d 项安全更新，节点即将平滑重启加载新内核", st.updatedCount)
	case st.updatedCount > 0:
		return fmt.Sprintf("成功静默修复 %d 项安全更新，核心代理全程零中断", st.updatedCount)
	case !st.allOK:
		return "部分安全检查或更新步骤遇到异常，请查看明细"
	default:
		return "全栈已是最新安全基线，无需变更"
	}
}

func verifySingBoxHealth(ctx context.Context, binPath string, expectActive bool) error {
	if binPath != "" {
		if _, err := os.Stat(constant.SingBoxConfigFile); err == nil {
			if out, cErr := exec.Command(binPath, "check", "-c", constant.SingBoxConfigFile).CombinedOutput(); cErr != nil {
				return fmt.Errorf("config check failed: %s", truncateText(string(out), 120))
			}
		}
	}
	if expectActive && !waitServiceActive(ctx, "sing-box", 15*time.Second) {
		return fmt.Errorf("sing-box systemd service failed to reach active state within 15s")
	}
	return nil
}

func verifyCaddyHealth(ctx context.Context, binPath string, expectActive bool) error {
	if binPath != "" {
		const caddyFile = "/etc/caddy/Caddyfile"
		if _, err := os.Stat(caddyFile); err == nil {
			if out, cErr := exec.Command(binPath, "validate", "--config", caddyFile, "--adapter", "caddyfile").CombinedOutput(); cErr != nil {
				return fmt.Errorf("Caddyfile validate failed: %s", truncateText(string(out), 120))
			}
		}
	}
	if expectActive && !waitServiceActive(ctx, "caddy", 15*time.Second) {
		return fmt.Errorf("caddy systemd service failed to reach active state within 15s")
	}
	return nil
}

func verifySSHDConfig() bool {
	sshdBin := locateBinary([]string{"/usr/sbin/sshd", "/sbin/sshd"}, "sshd")
	if sshdBin == "" {
		return true
	}
	return exec.Command(sshdBin, "-t").Run() == nil
}

func isServiceActive(unit string) bool {
	if !hasBinary("systemctl") {
		return false
	}
	return healServiceMgr().IsActive(context.Background(), unit)
}

func waitServiceActive(ctx context.Context, unit string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if isServiceActive(unit) {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(1 * time.Second):
		}
	}
	return isServiceActive(unit)
}

func restartWebDaemonSafely(async bool) {
	if isServiceActive("singctl-ui") {
		if async {
			_ = exec.Command("sh", "-c", "sleep 2 && systemctl restart singctl-ui >/dev/null 2>&1").Start()
		} else {
			_ = healServiceMgr().Restart(context.Background(), "singctl-ui")
		}
		return
	}

	if _, err := os.Stat("/tmp/singctl-serverweb.pid"); err == nil {
		binPath := locateBinary([]string{"/usr/local/bin/singctl", "/usr/bin/singctl"}, "singctl")
		if binPath == "" {
			return
		}
		if async {
			_ = exec.Command("sh", "-c", fmt.Sprintf("sleep 2 && %s sr ui restart >/dev/null 2>&1", binPath)).Start()
		} else {
			_ = exec.Command(binPath, "sr", "ui", "restart").Run()
		}
	}
}

func triggerDelayedReboot() {
	cmd := exec.Command("sh", "-c", "nohup sh -c 'sleep 3 && (systemctl reboot || reboot)' >/dev/null 2>&1 &")
	_ = cmd.Start()
}

func locateBinary(candidates []string, name string) string {
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	return ""
}

func backupBinary(src string) string {
	if strings.TrimSpace(src) == "" {
		return ""
	}
	in, err := os.Open(src)
	if err != nil {
		return ""
	}
	defer in.Close()
	bak := src + ".heal.bak"
	out, err := os.OpenFile(bak, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return ""
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		_ = os.Remove(bak)
		return ""
	}
	_ = out.Close()
	return bak
}

func restoreBinary(bak, dst string) error {
	if bak == "" || dst == "" {
		return fmt.Errorf("empty path")
	}
	tmp := dst + ".heal.restore"
	in, err := os.Open(bak)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		_ = os.Remove(tmp)
		return err
	}
	_ = out.Close()
	return os.Rename(tmp, dst)
}

func cleanupBackup(bak string) {
	if bak != "" {
		_ = os.Remove(bak)
	}
}

func truncateText(s string, maxLen int) string {
	s = strings.ReplaceAll(strings.TrimSpace(s), "\n", " | ")
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}
