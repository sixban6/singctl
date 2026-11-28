// 文件职责：实现高并发有线底盘状态探测与幂等调优（网卡多核 RPS 均衡 + 内存分档 Conntrack 连接表扩容与持久化）。
package wifiopt

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"singctl/internal/common/socktune"
)

const (
	rpsBeginMarker = "# singctl-rps-begin"
	rpsEndMarker   = "# singctl-rps-end"
	minConntrack   = 16384
	maxConntrack   = 524288
)

// InspectChassis 采集多核 RPS 与 nf_conntrack_max 状态。
func (s *Service) InspectChassis(_ context.Context) ChassisStatus {
	cores := s.cpuCount()
	totalMemMB := s.readTotalMemMB()
	targetMask := fullCPUMaskHex(cores)

	status := ChassisStatus{
		CPUCores:             cores,
		TotalMemMB:           totalMemMB,
		RPSInterfaces:        []RPSInterfaceStatus{},
		RPSOptimal:           true,
		RecommendedConntrack: recommendedConntrackForMem(totalMemMB),
		ConntrackOptimal:     true,
	}

	// 1. 探测物理有线网卡（eth*）的 rx-0/rps_cpus
	paths, _ := s.glob("/sys/class/net/eth*/queues/rx-0/rps_cpus")
	slices.Sort(paths)
	for _, p := range paths {
		parts := strings.Split(filepath.ToSlash(p), "/")
		if len(parts) < 5 {
			continue
		}
		ifName := parts[4]
		// 仅关注主物理网口（不含 VLAN 子口 eth0.1 等）
		if strings.Contains(ifName, ".") {
			continue
		}
		raw, err := s.readFile(p)
		if err != nil {
			continue
		}
		curMask := strings.TrimSpace(string(raw))
		balanced := cores <= 1 || masksEqual(curMask, targetMask)
		if !balanced {
			status.RPSOptimal = false
		}
		status.RPSInterfaces = append(status.RPSInterfaces, RPSInterfaceStatus{
			Interface:   ifName,
			CurrentMask: curMask,
			TargetMask:  targetMask,
			Balanced:    balanced,
		})
	}

	// 2. 探测 nf_conntrack_max 与当前占用
	if raw, err := s.readFile("/proc/sys/net/netfilter/nf_conntrack_max"); err == nil {
		status.ConntrackMax = parseInt(string(raw))
	}
	if raw, err := s.readFile("/proc/sys/net/netfilter/nf_conntrack_count"); err == nil {
		status.ConntrackCount = parseInt(string(raw))
	}
	if status.ConntrackMax > 0 && status.ConntrackMax < status.RecommendedConntrack {
		status.ConntrackOptimal = false
	}

	sb := socktune.Inspect(socktune.ProfileClient, s.socktuneEnv())
	if sb.Supported {
		status.SocketBuffer = &sb
	}

	status.Supported = len(status.RPSInterfaces) > 0 || status.ConntrackMax > 0 || sb.Supported
	status.Optimal = status.RPSOptimal && status.ConntrackOptimal && (!sb.Supported || sb.Optimal)
	return status
}

func (s *Service) socktuneEnv() socktune.Env {
	var writeFileFn func(string, []byte, os.FileMode) error
	if s.env.WriteFile0600 != nil {
		writeFileFn = func(path string, data []byte, _ os.FileMode) error {
			return s.env.WriteFile0600(path, data)
		}
	}
	var writeProcFn func(string, []byte) error
	if s.env.WriteSysfs != nil || s.env.WriteFile0600 != nil {
		writeProcFn = s.writeSysfs
	}
	return socktune.Env{
		GOOS:           s.env.GOOS,
		ReadFile:       s.env.ReadFile,
		WriteFile:      writeFileFn,
		WriteProc:      writeProcFn,
		RunCmd:         s.env.RunCmd,
		QuicSysctlFile: s.env.QuicSysctlFile,
		ConflictSysctlFiles: []string{
			s.sysctlFile(),
			"/etc/sysctl.d/99-custom.conf",
			"/etc/sysctl.d/99-singctl-bbr.conf",
		},
		ModulesDir: s.env.ModulesDir,
	}
}

// ApplyChassis 一键应用并持久化多核 RPS 均衡、Conntrack 上限扩容与 QUIC/UDP Socket 缓冲优化。
func (s *Service) ApplyChassis(ctx context.Context, req ChassisApplyRequest) (*ChassisApplyResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if !req.EnableRPS && !req.TuneConntrack && !req.TuneSocketBuffer {
		return nil, fmt.Errorf("%w: 请至少勾选一项底盘加速项", ErrInvalidRequest)
	}

	cur := s.InspectChassis(ctx)
	actions := []string{}
	var warnings []string
	restartSingBox := false

	if req.EnableRPS && cur.CPUCores > 1 && len(cur.RPSInterfaces) > 0 {
		targetMask := fullCPUMaskHex(cur.CPUCores)
		var rcLines []string
		for _, item := range cur.RPSInterfaces {
			p := fmt.Sprintf("/sys/class/net/%s/queues/rx-0/rps_cpus", item.Interface)
			if err := s.writeSysfs(p, []byte(targetMask+"\n")); err != nil {
				return nil, fmt.Errorf("写入 %s 失败: %w", p, err)
			}
			// 写后回读校验：若内核驱动静默忽略或钳制 rps_cpus，立刻显式报错，杜绝“前端假成功、刷新后还原”
			if rb, rbErr := s.readFile(p); rbErr == nil {
				gotMask := strings.TrimSpace(string(rb))
				if !masksEqual(gotMask, targetMask) {
					return nil, fmt.Errorf("内核未接受 %s 的 RPS 掩码（写入 %s，回读仍为 %s）", item.Interface, targetMask, gotMask)
				}
			}
			rcLines = append(rcLines, fmt.Sprintf("[ -w %s ] && echo %s > %s", p, targetMask, p))
			actions = append(actions, fmt.Sprintf("RPS %s: %s -> %s", item.Interface, item.CurrentMask, targetMask))
		}
		if err := s.persistRCLocalRPS(rcLines); err != nil {
			return nil, fmt.Errorf("持久化 RPS 到 %s 失败: %w", s.rcLocalFile(), err)
		}
	}

	if req.TuneConntrack {
		target := req.ConntrackMax
		if target <= 0 {
			target = cur.RecommendedConntrack
		}
		if target < minConntrack || target > maxConntrack {
			return nil, fmt.Errorf("%w: nf_conntrack_max 需在 %d~%d 之间", ErrInvalidRequest, minConntrack, maxConntrack)
		}
		if _, err := s.runCmd(ctx, "sysctl", "-w", fmt.Sprintf("net.netfilter.nf_conntrack_max=%d", target)); err != nil {
			return nil, fmt.Errorf("应用 nf_conntrack_max 失败: %w", err)
		}
		// 写后回读校验：确认内核实际生效，避免静默未生效
		if rb, rbErr := s.readFile("/proc/sys/net/netfilter/nf_conntrack_max"); rbErr == nil {
			if actual := parseInt(string(rb)); actual > 0 && actual < target {
				return nil, fmt.Errorf("内核未接受 nf_conntrack_max=%d（当前回读仍为 %d）", target, actual)
			}
		}
		if err := s.persistSysctlKey("net.netfilter.nf_conntrack_max", strconv.Itoa(target)); err != nil {
			return nil, fmt.Errorf("持久化 sysctl 失败: %w", err)
		}
		// 同步清理 /etc/sysctl.d/99-singctl-lowmem.conf 中的旧低内存上限，防止重启或守护进程拉起后回压覆盖
		_ = s.stripConflictingSysctlKey(s.lowMemSysctlFile(), "net.netfilter.nf_conntrack_max")
		actions = append(actions, fmt.Sprintf("nf_conntrack_max: %d -> %d", cur.ConntrackMax, target))
	}

	if req.TuneSocketBuffer {
		sbRes, sbErr := socktune.Apply(ctx, socktune.ProfileClient, socktune.ApplyRequest{}, s.socktuneEnv())
		if sbErr != nil {
			switch {
			case errors.Is(sbErr, socktune.ErrInvalidRequest):
				return nil, fmt.Errorf("%w: %w", ErrInvalidRequest, sbErr)
			case errors.Is(sbErr, socktune.ErrUnsupported):
				return nil, fmt.Errorf("%w: %w", ErrUnsupported, sbErr)
			default:
				return nil, sbErr
			}
		}
		actions = append(actions, sbRes.Actions...)
		warnings = append(warnings, sbRes.Warnings...)
		restartSingBox = sbRes.RestartRecommended
	}

	return &ChassisApplyResult{
		OK:                        true,
		Actions:                   actions,
		Warnings:                  warnings,
		RestartSingBoxRecommended: restartSingBox,
		Chassis:                   s.InspectChassis(ctx),
	}, nil
}

func (s *Service) readTotalMemMB() int {
	raw, err := s.readFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	for line := range strings.SplitSeq(string(raw), "\n") {
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				kb := parseInt(fields[1])
				return kb / 1024
			}
		}
	}
	return 0
}

func recommendedConntrackForMem(memMB int) int {
	switch {
	case memMB >= 1024:
		return 131072
	case memMB >= 450:
		return 65536
	default:
		// 230MB~256MB 小内存路由器（如 ax3000t）：32768 仅多占 ~5MB 内存，彻底消除春节 18+ 设备并发冲顶风险
		return 32768
	}
}

func fullCPUMaskHex(cores int) string {
	if cores <= 1 {
		return "1"
	}
	if cores >= 31 {
		return "ffffffff"
	}
	return strconv.FormatUint((uint64(1)<<uint(cores))-1, 16)
}

func normalizeHexMask(raw string) string {
	s := strings.ReplaceAll(strings.TrimSpace(raw), ",", "")
	s = strings.TrimLeft(s, "0")
	if s == "" {
		return "0"
	}
	return strings.ToLower(s)
}

func masksEqual(a, b string) bool {
	na, nb := normalizeHexMask(a), normalizeHexMask(b)
	ua, errA := strconv.ParseUint(na, 16, 64)
	ub, errB := strconv.ParseUint(nb, 16, 64)
	if errA != nil || errB != nil {
		return strings.EqualFold(na, nb)
	}
	return ua == ub
}

func (s *Service) persistRCLocalRPS(lines []string) error {
	origBytes, _ := s.readFile(s.rcLocalFile())
	orig := string(origBytes)
	if strings.TrimSpace(orig) == "" {
		orig = "#!/bin/sh\nexit 0\n"
	}

	// 幂等移除旧 singctl-rps 区块
	var kept []string
	skip := false
	for line := range strings.SplitSeq(strings.TrimRight(orig, "\n"), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == rpsBeginMarker {
			skip = true
			continue
		}
		if trimmed == rpsEndMarker {
			skip = false
			continue
		}
		if !skip {
			kept = append(kept, line)
		}
	}

	block := make([]string, 0, len(lines)+2)
	block = append(block, rpsBeginMarker)
	block = append(block, lines...)
	block = append(block, rpsEndMarker)

	// 插在最后一个 `exit 0` 之前
	insertAt := len(kept)
	for i := len(kept) - 1; i >= 0; i-- {
		if strings.TrimSpace(kept[i]) == "exit 0" {
			insertAt = i
			break
		}
	}
	merged := make([]string, 0, len(kept)+len(block))
	merged = append(merged, kept[:insertAt]...)
	merged = append(merged, block...)
	merged = append(merged, kept[insertAt:]...)
	// /etc/rc.local 必须保持 0755 可执行权限，兼容 OpenWrt 与 systemd rc-local.service
	return s.writeSystemFile(s.rcLocalFile(), []byte(strings.Join(merged, "\n")+"\n"), 0755)
}

func (s *Service) persistSysctlKey(key, val string) error {
	origBytes, _ := s.readFile(s.sysctlFile())
	prefix := key + "="
	var out []string
	replaced := false
	for line := range strings.SplitSeq(strings.TrimRight(string(origBytes), "\n"), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), prefix) || strings.HasPrefix(strings.TrimSpace(line), key+" ") {
			if !replaced {
				out = append(out, key+"="+val)
				replaced = true
			}
			continue
		}
		out = append(out, line)
	}
	if !replaced {
		out = append(out, key+"="+val)
	}
	return s.writeSystemFile(s.sysctlFile(), []byte(strings.Join(out, "\n")+"\n"), 0644)
}

func (s *Service) stripConflictingSysctlKey(path, key string) error {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	origBytes, err := s.readFile(path)
	if err != nil {
		return nil
	}
	var out []string
	changed := false
	for line := range strings.SplitSeq(strings.TrimRight(string(origBytes), "\n"), "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "#") && !strings.HasPrefix(trimmed, ";") {
			if k, _, ok := strings.Cut(trimmed, "="); ok && strings.TrimSpace(k) == key {
				changed = true
				continue
			}
		}
		out = append(out, line)
	}
	if !changed {
		return nil
	}
	return s.writeSystemFile(path, []byte(strings.Join(out, "\n")+"\n"), 0644)
}
