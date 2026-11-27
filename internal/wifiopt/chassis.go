// 文件职责：实现高并发有线底盘状态探测与幂等调优（网卡多核 RPS 均衡 + 内存分档 Conntrack 连接表扩容与持久化）。
package wifiopt

import (
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
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

	status.Supported = len(status.RPSInterfaces) > 0 || status.ConntrackMax > 0
	status.Optimal = status.RPSOptimal && status.ConntrackOptimal
	return status
}

// ApplyChassis 一键应用并持久化多核 RPS 均衡与 Conntrack 上限调优。
func (s *Service) ApplyChassis(ctx context.Context, req ChassisApplyRequest) (*ChassisApplyResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if !req.EnableRPS && !req.TuneConntrack {
		return nil, fmt.Errorf("%w: 请至少勾选一项底盘加速项", ErrInvalidRequest)
	}

	cur := s.InspectChassis(ctx)
	var actions []string

	if req.EnableRPS && cur.CPUCores > 1 && len(cur.RPSInterfaces) > 0 {
		targetMask := fullCPUMaskHex(cur.CPUCores)
		var rcLines []string
		for _, item := range cur.RPSInterfaces {
			p := fmt.Sprintf("/sys/class/net/%s/queues/rx-0/rps_cpus", item.Interface)
			if err := s.writeSysfs(p, []byte(targetMask+"\n")); err != nil {
				return nil, fmt.Errorf("写入 %s 失败: %w", p, err)
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
		if err := s.persistSysctlKey("net.netfilter.nf_conntrack_max", strconv.Itoa(target)); err != nil {
			return nil, fmt.Errorf("持久化 sysctl 失败: %w", err)
		}
		actions = append(actions, fmt.Sprintf("nf_conntrack_max: %d -> %d", cur.ConntrackMax, target))
	}

	return &ChassisApplyResult{
		OK:      true,
		Actions: actions,
		Chassis: s.InspectChassis(ctx),
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

func masksEqual(a, b string) bool {
	ua, errA := strconv.ParseUint(strings.TrimLeft(strings.TrimSpace(a), "0"), 16, 64)
	ub, errB := strconv.ParseUint(strings.TrimLeft(strings.TrimSpace(b), "0"), 16, 64)
	if errA != nil || errB != nil {
		return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
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
	return s.writeFile0600(s.rcLocalFile(), []byte(strings.Join(merged, "\n")+"\n"))
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
	return s.writeFile0600(s.sysctlFile(), []byte(strings.Join(out, "\n")+"\n"))
}
