// 文件职责：实现双引擎防劫持 DNS（SmartDNS / AdGuard Home）的硬件准入评估、自动选型推荐与运行态活跃引擎解析。
package localdns

import (
	"cmp"
	"errors"
	"fmt"
	"strings"

	"singctl/internal/common/sysinfo"
	"singctl/internal/constant"
	"singctl/internal/smartdns"
)

const (
	AdGuardMinTotalRAMBytes  uint64 = 512 * 1024 * 1024
	AdGuardMinAvailRAMBytes  uint64 = 256 * 1024 * 1024
	AdGuardMinDiskMB         uint64 = 80
	SmartDNSMinTotalRAMBytes uint64 = smartdns.MinTotalRAMBytes
	SmartDNSMinAvailRAMBytes uint64 = smartdns.MinAvailRAMBytes
	SmartDNSMinDiskMB        uint64 = smartdns.MinInstallDiskMB
)

// HardwareProfile 描述目标宿主机的物理内存与闪存可用空间画像。
type HardwareProfile struct {
	TotalRAMBytes uint64
	AvailRAMBytes uint64
	AvailDiskMB   uint64
	DiskUnknown   bool
}

// EngineEligibility 描述单个引擎在当前硬件条件下的准入评估与拦截原因。
type EngineEligibility struct {
	Eligible      bool
	DiskBlocked   bool
	MemoryBlocked bool
	BlockedReason string
}

// SelectionResult 汇总自动选型结果：硬件推荐引擎、当前活跃引擎（smartdns / adguard）与双引擎准入详情。
type SelectionResult struct {
	RecommendedEngine string
	RecommendedReason string
	ActiveEngine      string
	Eligibility       map[string]EngineEligibility
}

// ProbeHardwareProfile 采集宿主机物理内存与二进制所在分区的剩余空间画像。
func ProbeHardwareProfile(
	binPath string,
	readMem func() (sysinfo.MemInfo, error),
	readDisk func(string) (sysinfo.DiskSpace, error),
) HardwareProfile {
	var hp HardwareProfile

	memFn := readMem
	if memFn == nil {
		memFn = sysinfo.ReadMemInfo
	}
	if mi, err := memFn(); err == nil {
		hp.TotalRAMBytes = mi.TotalBytes
		hp.AvailRAMBytes = mi.AvailableBytes
	}

	diskFn := readDisk
	if diskFn == nil {
		diskFn = sysinfo.Statfs
	}
	target := cmp.Or(strings.TrimSpace(binPath), "/usr/bin")
	if ds, err := diskFn(target); err == nil {
		hp.AvailDiskMB = ds.AvailBytes / (1024 * 1024)
	} else if errors.Is(err, errors.ErrUnsupported) || err != nil {
		hp.DiskUnknown = true
	}
	return hp
}

func evaluateAdGuardEligibility(hw HardwareProfile, isInstalled bool) EngineEligibility {
	const mib = 1024 * 1024
	var reasons []string
	elig := EngineEligibility{Eligible: true}

	if !isInstalled && !hw.DiskUnknown && hw.AvailDiskMB < AdGuardMinDiskMB {
		elig.Eligible = false
		elig.DiskBlocked = true
		reasons = append(reasons, fmt.Sprintf("闪存可用空间不足（当前剩余 %d MB，安装 AdGuard Home 至少需要 %d MB）", hw.AvailDiskMB, AdGuardMinDiskMB))
	}

	memKnown := hw.TotalRAMBytes > 0 || hw.AvailRAMBytes > 0
	if memKnown {
		totalLow := hw.TotalRAMBytes > 0 && hw.TotalRAMBytes <= AdGuardMinTotalRAMBytes
		availLow := hw.AvailRAMBytes > 0 && hw.AvailRAMBytes <= AdGuardMinAvailRAMBytes
		if totalLow || availLow {
			elig.Eligible = false
			elig.MemoryBlocked = true
			reasons = append(reasons, fmt.Sprintf(
				"内存未达 AdGuard Home 推荐门槛（总内存 %d MB / 可用 %d MB；建议总内存 > 512 MB 且可用 > 256 MB）",
				hw.TotalRAMBytes/mib, hw.AvailRAMBytes/mib,
			))
		}
	}

	if len(reasons) > 0 {
		elig.BlockedReason = strings.Join(reasons, "；")
	}
	return elig
}

func evaluateSmartDNSEligibility(hw HardwareProfile, isInstalled bool) EngineEligibility {
	const mib = 1024 * 1024
	var reasons []string
	elig := EngineEligibility{Eligible: true}

	if !isInstalled && !hw.DiskUnknown && hw.AvailDiskMB < SmartDNSMinDiskMB {
		elig.Eligible = false
		elig.DiskBlocked = true
		reasons = append(reasons, fmt.Sprintf("闪存可用空间不足（当前剩余 %d MB，安装 SmartDNS 至少需要 %d MB）", hw.AvailDiskMB, SmartDNSMinDiskMB))
	}

	memKnown := hw.TotalRAMBytes > 0 || hw.AvailRAMBytes > 0
	if memKnown {
		totalLow := hw.TotalRAMBytes > 0 && hw.TotalRAMBytes < SmartDNSMinTotalRAMBytes
		availLow := hw.AvailRAMBytes > 0 && hw.AvailRAMBytes < SmartDNSMinAvailRAMBytes
		if totalLow || availLow {
			elig.Eligible = false
			elig.MemoryBlocked = true
			reasons = append(reasons, fmt.Sprintf(
				"内存未达 SmartDNS 最低安全门槛（总内存 %d MB / 可用 %d MB；至少需总内存 >= %d MB 且可用 >= %d MB）",
				hw.TotalRAMBytes/mib, hw.AvailRAMBytes/mib, SmartDNSMinTotalRAMBytes/mib, SmartDNSMinAvailRAMBytes/mib,
			))
		}
	}

	if len(reasons) > 0 {
		elig.BlockedReason = strings.Join(reasons, "；")
	}
	return elig
}

// EvaluateEligibility 评估双引擎（SmartDNS / AdGuard Home）在当前硬件与安装状态下的准入性。
func EvaluateEligibility(hw HardwareProfile, installed map[string]bool) map[string]EngineEligibility {
	return map[string]EngineEligibility{
		constant.DNSEngineSmartDNS: evaluateSmartDNSEligibility(hw, installed[constant.DNSEngineSmartDNS]),
		constant.DNSEngineAdGuard:  evaluateAdGuardEligibility(hw, installed[constant.DNSEngineAdGuard]),
	}
}

// RecommendEngine 按存量保护与硬件分级阈值输出 auto 策略推荐结果（仅在 adguard 与 smartdns 之间推荐）。
func RecommendEngine(hw HardwareProfile, installed map[string]bool) SelectionResult {
	elig := EvaluateEligibility(hw, installed)
	res := SelectionResult{
		Eligibility: elig,
	}

	// 1. 存量保护：已安装外部引擎时优先沿用，保障既有用户零惊喜升级。
	if installed[constant.DNSEngineAdGuard] {
		res.RecommendedEngine = constant.DNSEngineAdGuard
		res.ActiveEngine = constant.DNSEngineAdGuard
		res.RecommendedReason = "检测到本机已安装 AdGuard Home，自动沿用现有防劫持引擎并保留全部规则与查询统计"
		return res
	}
	if installed[constant.DNSEngineSmartDNS] {
		res.RecommendedEngine = constant.DNSEngineSmartDNS
		res.ActiveEngine = constant.DNSEngineSmartDNS
		res.RecommendedReason = "检测到本机已安装 SmartDNS，自动沿用极速多上游测速引擎与零闪存磨损审计"
		return res
	}

	// 2. 全新设备未装外部引擎：按内存与闪存门槛推荐 AdGuard Home 或 SmartDNS；
	// 若两家均受硬件门槛限制，仍推荐最轻量的 SmartDNS（eligible=false）并由 sing-box 纯 DoH 静默兜底防劫持。
	if elig[constant.DNSEngineAdGuard].Eligible {
		res.RecommendedEngine = constant.DNSEngineAdGuard
		res.ActiveEngine = constant.DNSEngineAdGuard
		res.RecommendedReason = "设备内存与闪存充裕，推荐安装 AdGuard Home 获得独立 Web 面板、完整查询日志与丰富过滤规则库"
		return res
	}
	if elig[constant.DNSEngineSmartDNS].Eligible {
		res.RecommendedEngine = constant.DNSEngineSmartDNS
		res.ActiveEngine = constant.DNSEngineSmartDNS
		res.RecommendedReason = "检测到中小内存或紧张闪存设备，推荐安装 SmartDNS 极速版（~3 MB 闪存 / ~10 MB 内存），支持多上游毫秒级竞速与内存盘审计"
		return res
	}

	res.RecommendedEngine = constant.DNSEngineSmartDNS
	res.ActiveEngine = constant.DNSEngineSmartDNS
	res.RecommendedReason = "检测到超低内存或极小闪存硬件环境，默认推荐最轻量的 SmartDNS（当前硬件受限，底层 sing-box 已启用纯 IP 加密 DoH 应急兜底防劫持）"
	return res
}

// ResolveActiveEngine 结合用户配置偏好、启用开关、硬件画像与已安装状态解析最终活跃引擎（smartdns / adguard）。
func ResolveActiveEngine(configured string, _ bool, hw HardwareProfile, installed map[string]bool) SelectionResult {
	res := RecommendEngine(hw, installed)
	switch strings.ToLower(strings.TrimSpace(configured)) {
	case constant.DNSEngineSmartDNS:
		res.ActiveEngine = constant.DNSEngineSmartDNS
	case constant.DNSEngineAdGuard:
		res.ActiveEngine = constant.DNSEngineAdGuard
	default:
		// "auto" / 空 / 历史 "singbox" / 未知值：沿用 RecommendEngine 解析结果
	}
	return res
}
