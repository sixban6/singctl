// 文件职责：实现宿主机维度的深度体检算子（硬件资源与低内存档位、tailscaled 远程运维生命线 OOM 免疫、ujail 沙盒与 sing-box 配置合规）。
package doctor

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"singctl/internal/common/sysinfo"
	"singctl/internal/safecommit"
)

const (
	mibBytes uint64 = 1024 * 1024

	diskFailAvailBytes = 8 * mibBytes
	diskWarnAvailBytes = 15 * mibBytes
	diskFailUsedPct    = 92
	diskWarnUsedPct    = 85

	memFailAvailBytes = 48 * mibBytes
	memWarnAvailBytes = 96 * mibBytes
)

type hardwareResourcesChecker struct{}

func (hardwareResourcesChecker) ID() string { return "hardware_resources" }

func (hardwareResourcesChecker) Run(_ context.Context, env *Env) CheckResult {
	res := CheckResult{
		ID:       "hardware_resources",
		Category: "host",
		Title:    "硬件资源与内存档位",
		Status:   StatusPass,
	}

	isOpenWrt := env.IsOpenWrt()
	primaryPath := "/"
	if isOpenWrt {
		primaryPath = "/overlay"
	}

	var details []string
	var advices []string
	var measured int
	status := StatusPass

	if ds, err := env.Statfs(primaryPath); err == nil && ds.TotalBytes > 0 {
		measured++
		details = append(details, fmt.Sprintf("%s 剩余 %s (已用 %d%%)", primaryPath, formatMiB(ds.AvailBytes), ds.UsedPercent))
		switch {
		case ds.AvailBytes < diskFailAvailBytes || ds.UsedPercent >= diskFailUsedPct:
			status = worstStatus(status, StatusFail)
			advices = append(advices, fmt.Sprintf("%s 剩余空间极度紧张（<8MB 或 >=92%%），请立即清理冗余文件或规则集缓存", primaryPath))
		case ds.AvailBytes < diskWarnAvailBytes || ds.UsedPercent >= diskWarnUsedPct:
			status = worstStatus(status, StatusWarn)
			advices = append(advices, fmt.Sprintf("%s 空间偏紧（<15MB 或 >=85%%），建议预留足够闪存用于安全升级", primaryPath))
		}
	} else if err != nil && !errors.Is(err, errors.ErrUnsupported) {
		details = append(details, fmt.Sprintf("%s 探测失败: %v", primaryPath, err))
	}

	if tmpDS, err := env.Statfs("/tmp"); err == nil && tmpDS.TotalBytes > 0 {
		measured++
		details = append(details, fmt.Sprintf("/tmp 已用 %d%% (剩余 %s)", tmpDS.UsedPercent, formatMiB(tmpDS.AvailBytes)))
		switch {
		case tmpDS.UsedPercent >= diskFailUsedPct:
			status = worstStatus(status, StatusFail)
			advices = append(advices, "/tmp 内存盘使用率 >=92%，可能导致 Safe Commit 快照与日志落盘失败")
		case tmpDS.UsedPercent >= diskWarnUsedPct:
			status = worstStatus(status, StatusWarn)
			advices = append(advices, "/tmp 内存盘使用率 >=85%，建议检查临时日志与规则集缓存")
		}
	}

	if mi, err := env.ReadMemInfo(); err == nil && mi.TotalBytes > 0 {
		measured++
		tier := "标准内存档位"
		switch {
		case sysinfo.IsUltraLowMemoryRAM(mi.TotalBytes):
			tier = "超低内存档位 (<=288MB)"
		case sysinfo.IsLowMemoryMemInfo(mi):
			tier = "低内存档位 (<=512MB)"
		}
		lowMemActive := env.Config.EffectiveLowMemory(mi.TotalBytes)
		details = append(details, fmt.Sprintf("MemAvailable %s / %s | %s (low_memory=%v)",
			formatMiB(mi.AvailableBytes), formatMiB(mi.TotalBytes), tier, lowMemActive))

		switch {
		case mi.AvailableBytes < memFailAvailBytes:
			status = worstStatus(status, StatusFail)
			advices = append(advices, "可用内存低于 48MB，极易触发 OOM Killer，请启用低内存模式并精简规则集")
		case mi.AvailableBytes < memWarnAvailBytes:
			status = worstStatus(status, StatusWarn)
			advices = append(advices, "可用内存低于 96MB，建议开启低内存模式并启用 SmartDNS 轻量引擎")
		}
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		details = append(details, fmt.Sprintf("内存探测失败: %v", err))
	}

	if measured == 0 {
		res.Status = StatusSkip
		res.Summary = "当前平台不支持 /proc/meminfo 或 Statfs 硬件资源探测"
		res.Detail = strings.Join(details, " | ")
		return res
	}

	res.Status = status
	res.Detail = strings.Join(details, " | ")
	res.Advice = strings.Join(advices, "；")
	switch status {
	case StatusFail:
		res.Summary = "存储或内存资源告急，存在 OOM 或写入失败风险"
	case StatusWarn:
		res.Summary = "存储或内存余量偏紧，建议开启低内存优化"
	default:
		res.Summary = "存储空间与可用内存均处于健康区间"
	}
	return res
}

type remoteLifelineChecker struct{}

func (remoteLifelineChecker) ID() string { return "remote_lifeline" }

func (remoteLifelineChecker) Run(_ context.Context, env *Env) CheckResult {
	res := CheckResult{
		ID:       "remote_lifeline",
		Category: "host",
		Title:    "远程运维生命线 (Tailscale OOM 免疫)",
	}

	st := safecommit.InspectTailscaledOOM(env.ProcRoot)
	if !st.Found {
		configured := env.Config != nil && (strings.TrimSpace(env.Config.Tailscale.AuthKey) != "" ||
			strings.TrimSpace(env.Config.Tailscale.Subnets) != "" ||
			env.Config.Tailscale.P2PAssist.Enabled)
		if configured {
			res.Status = StatusWarn
			res.Summary = "已配置 Tailscale，但未检测到运行中的 tailscaled 进程"
			res.Detail = st.Message
			res.Advice = "请检查 tailscale 服务状态以保障远程失联兜底通道在线"
			return res
		}
		res.Status = StatusSkip
		res.Summary = "未检测到运行中的 tailscaled 进程"
		res.Detail = st.Message
		return res
	}

	if st.Protected {
		res.Status = StatusPass
		res.Summary = fmt.Sprintf("tailscaled (PID %d) 已开启 OOM 免疫保护 (oom_score_adj=%d)", st.PID, st.ScoreAdj)
		res.Detail = st.Message
		return res
	}

	res.Status = StatusWarn
	res.Summary = fmt.Sprintf("tailscaled (PID %d) 未受 OOM 免疫保护 (oom_score_adj=%d)", st.PID, st.ScoreAdj)
	res.Detail = "小内存设备出现突发抖动时，内核 OOM Killer 可能杀掉 tailscaled 导致远程彻底失联"
	res.Advice = "建议立即将 tailscaled 的 oom_score_adj 锁定为 -1000"
	res.FixAction = "protect-tailscale-oom"
	res.FixLabel = "一键加 OOM 免疫"
	return res
}

type sandboxAndConfigChecker struct{}

func (sandboxAndConfigChecker) ID() string { return "sandbox_and_config" }

func (sandboxAndConfigChecker) Run(ctx context.Context, env *Env) CheckResult {
	res := CheckResult{
		ID:       "sandbox_and_config",
		Category: "host",
		Title:    "沙盒隔离与 sing-box 配置合规",
		Status:   StatusPass,
	}

	sbRunning, ujailActive := inspectSingBoxProcess(ctx, env)
	var details []string
	var advices []string
	status := StatusPass
	needSyncDNSLocal := false

	switch {
	case sbRunning && ujailActive:
		details = append(details, "进程模式: ujail 最小权限沙盒")
	case sbRunning && env.IsOpenWrt():
		details = append(details, "进程模式: 普通模式（未进入 ujail 沙盒）")
		status = worstStatus(status, StatusWarn)
		advices = append(advices, "建议安装 procd-ujail 并重启 sing-box 启用沙盒隔离")
	case sbRunning:
		details = append(details, "进程模式: 常规运行")
	default:
		details = append(details, "进程状态: sing-box 当前未运行")
	}

	rawCfg, err := env.ReadFile(env.SingBoxConfigPath)
	if err != nil {
		res.Status = StatusFail
		res.Summary = "无法读取 sing-box 配置文件"
		res.Detail = fmt.Sprintf("%s: %v", env.SingBoxConfigPath, err)
		res.Advice = "请执行 'singctl sb generate' 重新生成 sing-box 配置"
		return res
	}

	var parsed struct {
		DNS *struct {
			DisableCache *bool `json:"disable_cache"`
			Optimistic   *bool `json:"optimistic"`
		} `json:"dns"`
	}
	if err := json.Unmarshal(rawCfg, &parsed); err != nil {
		res.Status = StatusFail
		res.Summary = "sing-box 配置文件 JSON 语法损坏"
		res.Detail = fmt.Sprintf("%s: %v", env.SingBoxConfigPath, err)
		res.Advice = "请重新生成或通过 Safe Commit 回滚配置"
		return res
	}

	if parsed.DNS == nil {
		status = worstStatus(status, StatusWarn)
		details = append(details, "dns 段落缺失")
		advices = append(advices, "建议同步生成完整的 sing-box DNS 配置")
		needSyncDNSLocal = true
	} else {
		if parsed.DNS.DisableCache == nil || !*parsed.DNS.DisableCache {
			status = worstStatus(status, StatusWarn)
			details = append(details, "dns.disable_cache 未设为 true")
			advices = append(advices, "建议强制关闭 sing-box 内置 DNS 缓存（disable_cache: true），避免双层缓存陈旧")
			needSyncDNSLocal = true
		}
		if parsed.DNS.Optimistic == nil || *parsed.DNS.Optimistic {
			status = worstStatus(status, StatusWarn)
			details = append(details, "dns.optimistic 未设为 false")
			advices = append(advices, "建议显式关闭乐观解析（optimistic: false），避免返回过期 DNS 记录")
			needSyncDNSLocal = true
		}
		if !needSyncDNSLocal {
			details = append(details, "DNS 缓存合规: disable_cache=true, optimistic=false")
		}
	}

	if env.lookPathOK("sing-box") {
		out, checkErr := env.RunCmd(ctx, "sing-box", "check", "-c", env.SingBoxConfigPath)
		if checkErr != nil {
			res.Status = StatusFail
			res.Summary = "sing-box check 配置语法校验失败"
			res.Detail = strings.TrimSpace(cmp.Or(string(out), checkErr.Error()))
			res.Advice = "请修复配置错误或回滚至上一份已知有效配置"
			return res
		}
		details = append(details, "sing-box check: 通过")
	}

	res.Status = status
	res.Detail = strings.Join(details, " | ")
	res.Advice = strings.Join(advices, "；")
	if needSyncDNSLocal {
		res.FixAction = "sync-dns-local"
		res.FixLabel = "一键修正 sing-box DNS 配置"
	}
	switch status {
	case StatusWarn:
		res.Summary = "sing-box 沙盒隔离或 DNS 合规项存在警告"
	default:
		res.Summary = "sing-box 沙盒状态、DNS 缓存策略与配置语法均合规"
	}
	return res
}

type procEntry struct {
	pid     int
	comm    string
	cmdline string
}

func scanProcesses(procRoot string) ([]procEntry, bool) {
	if procRoot == "" && runtime.GOOS != "linux" {
		return nil, false
	}
	root := cmp.Or(procRoot, "/proc")
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, false
	}
	var out []procEntry
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, convErr := strconv.Atoi(entry.Name())
		if convErr != nil || pid <= 0 {
			continue
		}
		pidDir := filepath.Join(root, entry.Name())
		rawComm, _ := os.ReadFile(filepath.Join(pidDir, "comm"))
		rawCmd, _ := os.ReadFile(filepath.Join(pidDir, "cmdline"))
		cmdStr := strings.ReplaceAll(string(rawCmd), "\x00", " ")
		out = append(out, procEntry{
			pid:     pid,
			comm:    strings.TrimSpace(string(rawComm)),
			cmdline: strings.TrimSpace(cmdStr),
		})
	}
	return out, true
}

func inspectSingBoxProcess(ctx context.Context, env *Env) (running bool, inUjail bool) {
	if procs, ok := scanProcesses(env.ProcRoot); ok {
		for _, p := range procs {
			if p.comm == "sing-box" {
				running = true
			}
			if p.comm == "ujail" && strings.Contains(p.cmdline, "sing-box") {
				inUjail = true
			}
		}
		return running, inUjail
	}

	if env.ProcRoot == "" && env.lookPathOK("pgrep") {
		if out, err := env.RunCmd(ctx, "pgrep", "sing-box"); err == nil && strings.TrimSpace(string(out)) != "" {
			running = true
		}
	}
	return running, inUjail
}
