// 文件职责：提供面向全内存段 Linux/OpenWrt 路由器的通用代码级宿主机内存护栏与自愈调优（全段 /tmp 旧二进制备份清扫、Tailscale/AdGuardHome 自适应 GOMEMLIMIT 服务对账，以及 <=512MiB 内核 sysctl、zram 最优算法与 logd/冗余 web 清理）。
package daemon

import (
	"cmp"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"singctl/internal/adguard"
	"singctl/internal/common/fsx"
	"singctl/internal/common/sysinfo"
	"singctl/internal/constant"
	"singctl/internal/logger"
	"singctl/internal/platform/servicemgr"
	"singctl/internal/tailscale"
)

const (
	staleTmpBackupMinBytes int64 = 1024 * 1024 // 仅清扫 >= 1 MiB 的二进制备份，绝不误删配置备份
	defaultLowMemSysctl          = "/etc/sysctl.d/99-singctl-lowmem.conf"
)

// LowMemHostTuneDeps 显式注入宿主机内存护栏调优器的全部路径与外部执行器依赖（支持完全离线测试）。
type LowMemHostTuneDeps struct {
	TotalRAMBytes       uint64
	IsOpenWrt           bool
	WebEmbedded         bool
	TmpDir              string
	ProcSysRoot         string
	SysctlConfPath      string
	ZramCompAlgoPath    string
	TailscaleInitdPath  string
	TailscaleSystemd    string
	AdGuardInitdPath    string
	AdGuardSystemd      string
	OpenWrtRcdDir       string
	ServiceMgr          servicemgr.Manager
	RestartTailscaleNow bool
	RestartAdGuardNow   bool
	RunUCI              func(ctx context.Context, args ...string) (string, error)
}

// LowMemHostTuneResult 汇总本次宿主机内存护栏自适应调优的执行成效。
type LowMemHostTuneResult struct {
	RemovedTmpBackups     int
	FreedTmpBytes         int64
	SysctlUpdatedKeys     []string
	ZramAlgoUpdated       string
	LogSizeCapped         bool
	DisabledStandaloneWeb bool
	TailscaleEnvUpdated   bool
	AdGuardEnvUpdated     bool
}

// AppliedAny 判断本次调优是否执行了任意实际宿主机优化动作。
func (r LowMemHostTuneResult) AppliedAny() bool {
	return r.RemovedTmpBackups > 0 ||
		len(r.SysctlUpdatedKeys) > 0 ||
		r.ZramAlgoUpdated != "" ||
		r.LogSizeCapped ||
		r.DisabledStandaloneWeb ||
		r.TailscaleEnvUpdated ||
		r.AdGuardEnvUpdated
}

// SelectBestZramCompAlgo 解析 `/sys/block/zram0/comp_algorithm` 内容，按 zstd > lz4 > lzo-rle 优先级挑选更优压缩算法；
// 若当前已是候选最优或内核无更优选项则返回空字符串。
func SelectBestZramCompAlgo(raw string) string {
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return ""
	}
	var current string
	available := make(map[string]struct{}, len(fields))
	for _, f := range fields {
		if strings.HasPrefix(f, "[") && strings.HasSuffix(f, "]") && len(f) > 2 {
			name := f[1 : len(f)-1]
			current = name
			available[name] = struct{}{}
		} else {
			available[f] = struct{}{}
		}
	}
	for _, pref := range []string{"zstd", "lz4", "lzo-rle"} {
		if _, ok := available[pref]; ok {
			if current == pref {
				return ""
			}
			return pref
		}
	}
	return ""
}

func isStaleSingCtlBinaryBackupName(name string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	if !strings.HasPrefix(lower, "singctl.") {
		return false
	}
	if strings.Contains(lower, ".yaml") || strings.Contains(lower, ".json") || strings.Contains(lower, ".conf") || strings.HasSuffix(lower, ".log") {
		return false
	}
	return strings.HasSuffix(lower, ".bak") ||
		strings.HasPrefix(lower, "singctl.bak.") ||
		strings.HasSuffix(lower, ".bak.prev")
}

func sweepStaleTmpBinaryBackups(tmpDir string) (int, int64) {
	if strings.TrimSpace(tmpDir) == "" {
		return 0, 0
	}
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		return 0, 0
	}
	removed := 0
	var freed int64
	for _, ent := range entries {
		if ent.IsDir() || !isStaleSingCtlBinaryBackupName(ent.Name()) {
			continue
		}
		info, iErr := ent.Info()
		if iErr != nil || !info.Mode().IsRegular() || info.Size() < staleTmpBackupMinBytes {
			continue
		}
		full := filepath.Join(tmpDir, ent.Name())
		if rmErr := os.Remove(full); rmErr == nil {
			removed++
			freed += info.Size()
		}
	}
	return removed, freed
}

type sysctlBound struct {
	key     string
	relPath string
	target  int64
	isMax   bool // true: 若当前 > target 则下调；false: 若当前 < target 则上调
}

func desiredLowMemSysctls(totalRAMBytes uint64) []sysctlBound {
	if sysinfo.IsUltraLowMemoryRAM(totalRAMBytes) {
		return []sysctlBound{
			{key: "net.netfilter.nf_conntrack_max", relPath: "net/netfilter/nf_conntrack_max", target: 16384, isMax: true},
			{key: "vm.vfs_cache_pressure", relPath: "vm/vfs_cache_pressure", target: 150, isMax: false},
			// 224~256MiB 单 DMA32 域设备严禁抬高 min_free_kbytes（8192 会把 low 水位线拉至 ~19MiB 导致 MemAvailable 倒挂），上限保持 OpenWrt 默认 4096
			{key: "vm.min_free_kbytes", relPath: "vm/min_free_kbytes", target: 4096, isMax: true},
		}
	}
	if sysinfo.IsLowMemoryRAM(totalRAMBytes) {
		return []sysctlBound{
			{key: "net.netfilter.nf_conntrack_max", relPath: "net/netfilter/nf_conntrack_max", target: 32768, isMax: true},
			{key: "vm.vfs_cache_pressure", relPath: "vm/vfs_cache_pressure", target: 125, isMax: false},
		}
	}
	return nil
}

func applyLowMemSysctls(procSysRoot, sysctlConfPath string, totalRAMBytes uint64) []string {
	bounds := desiredLowMemSysctls(totalRAMBytes)
	if len(bounds) == 0 || strings.TrimSpace(procSysRoot) == "" {
		return nil
	}
	var updated []string
	var persistLines []string
	persistLines = append(persistLines, "# Managed by singctl adaptive low-memory host tuner")

	for _, b := range bounds {
		targetStr := strconv.FormatInt(b.target, 10)
		persistLines = append(persistLines, fmt.Sprintf("%s = %s", b.key, targetStr))
		p := filepath.Join(procSysRoot, filepath.FromSlash(b.relPath))
		raw, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		cur, pErr := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
		if pErr != nil {
			continue
		}
		need := (b.isMax && cur > b.target) || (!b.isMax && cur < b.target)
		if !need {
			continue
		}
		if wErr := os.WriteFile(p, []byte(targetStr+"\n"), 0644); wErr == nil {
			updated = append(updated, b.key)
		}
	}

	if strings.TrimSpace(sysctlConfPath) != "" {
		content := strings.Join(persistLines, "\n") + "\n"
		existing, _ := os.ReadFile(sysctlConfPath)
		if string(existing) != content {
			if dir := filepath.Dir(sysctlConfPath); dir != "" {
				_ = os.MkdirAll(dir, 0755)
			}
			_ = fsx.WriteAtomic(sysctlConfPath, []byte(content), 0644)
		}
	}
	return updated
}

func defaultRunUCI(ctx context.Context, args ...string) (string, error) {
	if _, err := exec.LookPath("uci"); err != nil {
		return "", err
	}
	out, err := exec.CommandContext(ctx, "uci", args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func hasStandaloneWebRcSymlink(rcdDir string) bool {
	if strings.TrimSpace(rcdDir) == "" {
		return false
	}
	matches, _ := filepath.Glob(filepath.Join(rcdDir, "S*singctl-web"))
	return len(matches) > 0
}

// ReconcileLowMemHost 对全内存段路由器执行幂等、零断网、代码级通用的宿主机内存护栏优化：
//   - 全内存段（TotalRAMBytes > 0）：清扫 /tmp 残留大备份 + 为既有 Tailscale/AdGuardHome 补齐自适应 GOMEMLIMIT；
//   - 小内存段（<= 512 MiB）：额外执行内核 sysctl 稳态护栏、zram 压缩算法升级、logd 环形缓冲收敛与冗余 web 自启清理；
//   - 未知内存（TotalRAMBytes == 0）：静默零开销跳过。
func ReconcileLowMemHost(ctx context.Context, deps LowMemHostTuneDeps) LowMemHostTuneResult {
	var res LowMemHostTuneResult
	if deps.TotalRAMBytes == 0 {
		return res
	}
	if ctx == nil {
		ctx = context.Background()
	}

	runUCI := deps.RunUCI
	if runUCI == nil {
		runUCI = defaultRunUCI
	}

	// 1. 全内存段：清扫 /tmp 内存盘残留的 >=1MiB 旧版 singctl 二进制备份
	res.RemovedTmpBackups, res.FreedTmpBytes = sweepStaleTmpBinaryBackups(deps.TmpDir)

	// 2~3. 仅小内存宿主机（<= 512 MiB）：内核 sysctl 稳态护栏 + OpenWrt zram/logd/冗余 web 收敛
	if sysinfo.IsLowMemoryRAM(deps.TotalRAMBytes) {
		res.SysctlUpdatedKeys = applyLowMemSysctls(deps.ProcSysRoot, deps.SysctlConfPath, deps.TotalRAMBytes)

		if deps.IsOpenWrt {
			uciCommitted := false
			if strings.TrimSpace(deps.ZramCompAlgoPath) != "" {
				if raw, err := os.ReadFile(deps.ZramCompAlgoPath); err == nil {
					if best := SelectBestZramCompAlgo(string(raw)); best != "" {
						curUCI, _ := runUCI(ctx, "get", "system.@system[0].zram_comp_algo")
						if strings.TrimSpace(curUCI) != best {
							if _, setErr := runUCI(ctx, "set", "system.@system[0].zram_comp_algo="+best); setErr == nil {
								res.ZramAlgoUpdated = best
								uciCommitted = true
							}
						}
					}
				}
			}

			if sysinfo.IsUltraLowMemoryRAM(deps.TotalRAMBytes) {
				if curLogSz, err := runUCI(ctx, "get", "system.@system[0].log_size"); err == nil {
					if n, pErr := strconv.Atoi(strings.TrimSpace(curLogSz)); pErr == nil && n > 64 {
						if _, setErr := runUCI(ctx, "set", "system.@system[0].log_size=64"); setErr == nil {
							res.LogSizeCapped = true
							uciCommitted = true
						}
					}
				}
			}

			if uciCommitted {
				_, _ = runUCI(ctx, "commit", "system")
				if res.LogSizeCapped && deps.ServiceMgr != nil {
					_ = deps.ServiceMgr.Reload(ctx, "log")
				}
			}

			if deps.WebEmbedded && hasStandaloneWebRcSymlink(deps.OpenWrtRcdDir) {
				if deps.ServiceMgr != nil {
					if err := deps.ServiceMgr.Disable(ctx, "singctl-web"); err == nil {
						res.DisabledStandaloneWeb = true
					}
				}
				// 同步确保测试/受限环境下孤立 S*singctl-web 软链被清理
				if matches, _ := filepath.Glob(filepath.Join(deps.OpenWrtRcdDir, "S*singctl-web")); len(matches) > 0 {
					for _, m := range matches {
						if os.Remove(m) == nil {
							res.DisabledStandaloneWeb = true
						}
					}
				}
			}
		}
	}

	// 4. 全内存段：Tailscale 服务自适应 GOMEMLIMIT 护栏与重复启动软链清理（仅在服务处于运行态时热重启生效）
	if changed, svcType, err := tailscale.EnsureLowMemServiceEnv(
		deps.TailscaleInitdPath,
		deps.TailscaleSystemd,
		deps.OpenWrtRcdDir,
		deps.TotalRAMBytes,
	); err == nil && changed {
		res.TailscaleEnvUpdated = true
		if deps.RestartTailscaleNow && deps.ServiceMgr != nil {
			unitName := "tailscale"
			if svcType == "systemd" {
				unitName = "tailscaled"
				_ = deps.ServiceMgr.DaemonReload(ctx)
			}
			if deps.ServiceMgr.IsActive(ctx, unitName) {
				_ = deps.ServiceMgr.Restart(ctx, unitName)
			}
		}
	}

	// 5. 全内存段：AdGuard Home 服务自适应 GOMEMLIMIT 护栏（仅在服务处于运行态时热重启，严禁误拉起已停用的 DNS 引擎）
	if changed, svcType, err := adguard.EnsureMemoryLimitServiceEnv(
		deps.AdGuardInitdPath,
		deps.AdGuardSystemd,
		deps.TotalRAMBytes,
	); err == nil && changed {
		res.AdGuardEnvUpdated = true
		if deps.RestartAdGuardNow && deps.ServiceMgr != nil {
			if svcType == "systemd" {
				_ = deps.ServiceMgr.DaemonReload(ctx)
			}
			if deps.ServiceMgr.IsActive(ctx, "AdGuardHome") {
				_ = deps.ServiceMgr.Restart(ctx, "AdGuardHome")
			}
		}
	}

	return res
}

// ReconcileLowMemHostDefault 在真实 Linux 路由器启动守护进程后执行全内存段自适应内存护栏与自愈调优。
func ReconcileLowMemHostDefault(ctx context.Context, webEmbedded bool) LowMemHostTuneResult {
	if runtime.GOOS != "linux" {
		return LowMemHostTuneResult{}
	}
	totalRAM := sysinfo.TotalRAMBytes()
	if totalRAM == 0 {
		return LowMemHostTuneResult{}
	}
	res := ReconcileLowMemHost(ctx, LowMemHostTuneDeps{
		TotalRAMBytes:       totalRAM,
		IsOpenWrt:           servicemgr.IsOpenWrt(),
		WebEmbedded:         webEmbedded,
		TmpDir:              cmp.Or(defaultTempDir(), "/tmp"),
		ProcSysRoot:         "/proc/sys",
		SysctlConfPath:      defaultLowMemSysctl,
		ZramCompAlgoPath:    "/sys/block/zram0/comp_algorithm",
		TailscaleInitdPath:  constant.TailscaleInitdScript,
		TailscaleSystemd:    constant.TailscaleSystemdService,
		AdGuardInitdPath:    constant.AdGuardInitdScript,
		AdGuardSystemd:      constant.AdGuardSystemdService,
		OpenWrtRcdDir:       "/etc/rc.d",
		ServiceMgr:          servicemgr.Detect(nil),
		RestartTailscaleNow: true,
		RestartAdGuardNow:   true,
	})
	if res.AppliedAny() {
		logger.Info("[LowMem-Tune] 宿主机内存护栏调优已生效: tmpCleanup=%d(%.1fMiB) sysctl=%v zram=%s log64=%v disableWeb=%v tailscaleEnv=%v adguardEnv=%v",
			res.RemovedTmpBackups, float64(res.FreedTmpBytes)/(1024*1024),
			res.SysctlUpdatedKeys, res.ZramAlgoUpdated, res.LogSizeCapped,
			res.DisabledStandaloneWeb, res.TailscaleEnvUpdated, res.AdGuardEnvUpdated)
	}
	return res
}
