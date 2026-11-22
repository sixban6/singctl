// 文件职责：提供零 fork、零阻塞的宿主机实时资源遥测（CPU 差值采样器、内存/交换分区、挂载点磁盘、Uptime 与负载解析）。
package sysinfo

import (
	"fmt"
	"math"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// CPUSample 记录一次 /proc/stat 全局 cpu 汇总行的总时间片与空闲时间片（idle + iowait）。
type CPUSample struct {
	Total uint64 `json:"total"`
	Idle  uint64 `json:"idle"`
}

// CPUSampler 并发安全地缓存上一次 /proc/stat 样本，以零阻塞差值计算实时 CPU 利用率。
type CPUSampler struct {
	mu           sync.Mutex
	prev         CPUSample
	hasPrev      bool
	readProcStat func() (string, error)
}

// MemTelemetry 汇总宿主机真实业务内存占用（Total - Avail，不含可回收 page cache）与交换分区状态。
type MemTelemetry struct {
	TotalBytes     uint64 `json:"totalBytes"`
	UsedBytes      uint64 `json:"usedBytes"`
	AvailBytes     uint64 `json:"availBytes"`
	SwapTotalBytes uint64 `json:"swapTotalBytes"`
	SwapUsedBytes  uint64 `json:"swapUsedBytes"`
	UsedPercent    int    `json:"usedPercent"`
	LowMemory      bool   `json:"lowMemory"`
}

// DiskTelemetry 描述单个挂载点的磁盘容量遥测与展示标签。
type DiskTelemetry struct {
	MountPath   string `json:"mountPath"`
	Label       string `json:"label"`
	TotalBytes  uint64 `json:"totalBytes"`
	UsedBytes   uint64 `json:"usedBytes"`
	AvailBytes  uint64 `json:"availBytes"`
	UsedPercent int    `json:"usedPercent"`
}

// HostTelemetry 汇总宿主机单次采集的实时系统资源遥测快照（可直接 JSON 序列化给 WebUI 与 Doctor）。
type HostTelemetry struct {
	UptimeSec   int64          `json:"uptimeSec"`
	CPUCores    int            `json:"cpuCores"`
	CPUPercent  float64        `json:"cpuPercent"`
	CPUReady    bool           `json:"cpuReady"`
	LoadAvg     [3]float64     `json:"loadAvg"`
	Mem         MemTelemetry   `json:"mem"`
	Disk        DiskTelemetry  `json:"disk"`
	TmpDisk     *DiskTelemetry `json:"tmpDisk,omitempty"`
	IsOpenWrt   bool           `json:"isOpenWrt"`
	CollectedAt int64          `json:"collectedAt"`
}

// TelemetryDeps 声明 CollectHostTelemetryWithDeps 的显式可注入采集依赖（nil 字段自动回退生产默认实现）。
type TelemetryDeps struct {
	ReadUptimeSec func() int64
	ReadLoadAvg   func() [3]float64
	ReadMemInfo   func() (MemInfo, error)
	Statfs        func(path string) (DiskSpace, error)
	IsOpenWrt     func() bool
	NumCPU        func() int
	Now           func() time.Time
}

// NewCPUSampler 创建使用生产 /proc/stat 读取器的并发安全 CPU 采样器。
func NewCPUSampler() *CPUSampler {
	return &CPUSampler{}
}

// NewCPUSamplerWithReader 创建带自定义 /proc/stat 读取函数的 CPU 采样器（nil 时回退默认实现）。
func NewCPUSamplerWithReader(readProcStat func() (string, error)) *CPUSampler {
	return &CPUSampler{readProcStat: readProcStat}
}

func (s *CPUSampler) readStat() (string, error) {
	if s.readProcStat != nil {
		return s.readProcStat()
	}
	return readProcStatRaw()
}

// Prime 预先采集首次 CPU 基线样本（幂等），便于服务启动后首笔遥测请求即获得实时 CPU%。
func (s *CPUSampler) Prime() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.hasPrev {
		return
	}
	raw, err := s.readStat()
	if err != nil {
		return
	}
	sample, err := ParseCPUStat(raw)
	if err != nil {
		return
	}
	s.prev = sample
	s.hasPrev = true
}

// SamplePercent 基于与上一次样本的差值计算实时 CPU 利用率（0..100，保留 1 位小数）；首次采样记录基线并返回 (0, false)。
func (s *CPUSampler) SamplePercent() (float64, bool) {
	if s == nil {
		return 0, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	raw, err := s.readStat()
	if err != nil {
		return 0, false
	}
	cur, err := ParseCPUStat(raw)
	if err != nil {
		return 0, false
	}
	if !s.hasPrev {
		s.prev = cur
		s.hasPrev = true
		return 0, false
	}

	prev := s.prev
	s.prev = cur

	if cur.Total <= prev.Total {
		return 0, false
	}
	deltaTotal := cur.Total - prev.Total
	var deltaIdle uint64
	if cur.Idle > prev.Idle {
		deltaIdle = cur.Idle - prev.Idle
	}
	var deltaBusy uint64
	if deltaTotal > deltaIdle {
		deltaBusy = deltaTotal - deltaIdle
	}
	pct := float64(deltaBusy) / float64(deltaTotal) * 100.0
	pct = max(0.0, min(100.0, pct))
	pct = math.Round(pct*10) / 10
	return pct, true
}

// ParseUptime 解析 /proc/uptime 文本的第一字段运行时长（秒）。
func ParseUptime(raw string) (int64, error) {
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return 0, fmt.Errorf("empty uptime input")
	}
	secs, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0, fmt.Errorf("parse uptime %q: %w", fields[0], err)
	}
	if math.IsNaN(secs) || math.IsInf(secs, 0) || secs < 0 {
		return 0, fmt.Errorf("invalid uptime value %q", fields[0])
	}
	return int64(secs), nil
}

// ParseLoadAvg 解析 /proc/loadavg 文本的前 3 个平均负载浮点数（1m / 5m / 15m）。
func ParseLoadAvg(raw string) ([3]float64, error) {
	fields := strings.Fields(raw)
	if len(fields) < 3 {
		return [3]float64{}, fmt.Errorf("loadavg requires at least 3 fields, got %d", len(fields))
	}
	var out [3]float64
	for i := range 3 {
		v, err := strconv.ParseFloat(fields[i], 64)
		if err != nil {
			return [3]float64{}, fmt.Errorf("parse loadavg[%d] %q: %w", i, fields[i], err)
		}
		if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 {
			return [3]float64{}, fmt.Errorf("invalid loadavg[%d] value %q", i, fields[i])
		}
		out[i] = v
	}
	return out, nil
}

// ParseCPUStat 解析 /proc/stat 中的 cpu 汇总行，其中 idle = idle + iowait。
// 按 Linux 内核 /proc/stat 约定，guest / guest_nice（第 9、10 数值列）已计入 user / nice，
// 因此总时间片仅汇总前 8 列（user, nice, system, idle, iowait, irq, softirq, steal）以避免重复计入。
func ParseCPUStat(raw string) (CPUSample, error) {
	for line := range strings.SplitSeq(raw, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "cpu" {
			continue
		}
		if len(fields) < 5 {
			return CPUSample{}, fmt.Errorf("cpu stat line requires at least 4 counters, got %d", len(fields)-1)
		}
		var total uint64
		var idle uint64
		for i := 1; i < len(fields); i++ {
			v, err := strconv.ParseUint(fields[i], 10, 64)
			if err != nil {
				return CPUSample{}, fmt.Errorf("parse cpu stat field[%d] %q: %w", i, fields[i], err)
			}
			// fields[1..8] = user, nice, system, idle, iowait, irq, softirq, steal
			if i <= 8 {
				total += v
			}
			if i == 4 || i == 5 {
				idle += v
			}
		}
		return CPUSample{Total: total, Idle: idle}, nil
	}
	return CPUSample{}, fmt.Errorf("aggregate cpu line not found in /proc/stat")
}

func readProcStatRaw() (string, error) {
	if runtime.GOOS != "linux" {
		return "", os.ErrNotExist
	}
	raw, err := os.ReadFile("/proc/stat")
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// ReadUptimeSec 读取当前 Linux 宿主机 /proc/uptime 运行秒数（非 Linux 或失败返回 0）。
func ReadUptimeSec() int64 {
	if runtime.GOOS != "linux" {
		return 0
	}
	raw, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	secs, err := ParseUptime(string(raw))
	if err != nil {
		return 0
	}
	return secs
}

// ReadLoadAvg 读取当前 Linux 宿主机 /proc/loadavg 负载三元组（非 Linux 或失败返回零值）。
func ReadLoadAvg() [3]float64 {
	if runtime.GOOS != "linux" {
		return [3]float64{}
	}
	raw, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return [3]float64{}
	}
	load, err := ParseLoadAvg(string(raw))
	if err != nil {
		return [3]float64{}
	}
	return load
}

// ReadCPUStat 读取并解析当前 Linux 宿主机 /proc/stat 的全局 CPU 样本。
func ReadCPUStat() (CPUSample, error) {
	raw, err := readProcStatRaw()
	if err != nil {
		return CPUSample{}, err
	}
	return ParseCPUStat(raw)
}

// CollectHostTelemetry 使用宿主机默认采集器收集一次实时资源遥测快照。
func CollectHostTelemetry(sampler *CPUSampler) HostTelemetry {
	return CollectHostTelemetryWithDeps(sampler, TelemetryDeps{})
}

// CollectHostTelemetryWithDeps 使用显式注入依赖收集宿主机实时资源遥测快照（nil 字段自动回退生产默认）。
func CollectHostTelemetryWithDeps(sampler *CPUSampler, deps TelemetryDeps) HostTelemetry {
	readUptime := deps.ReadUptimeSec
	if readUptime == nil {
		readUptime = ReadUptimeSec
	}
	readLoad := deps.ReadLoadAvg
	if readLoad == nil {
		readLoad = ReadLoadAvg
	}
	readMem := deps.ReadMemInfo
	if readMem == nil {
		readMem = ReadMemInfo
	}
	statfsFn := deps.Statfs
	if statfsFn == nil {
		statfsFn = Statfs
	}
	isOpenWrtFn := deps.IsOpenWrt
	if isOpenWrtFn == nil {
		isOpenWrtFn = IsOpenWrt
	}
	numCPU := deps.NumCPU
	if numCPU == nil {
		numCPU = runtime.NumCPU
	}
	nowFn := deps.Now
	if nowFn == nil {
		nowFn = time.Now
	}

	isOpenWrt := isOpenWrtFn()
	out := HostTelemetry{
		UptimeSec:   readUptime(),
		CPUCores:    numCPU(),
		LoadAvg:     readLoad(),
		IsOpenWrt:   isOpenWrt,
		CollectedAt: nowFn().Unix(),
	}

	if sampler != nil {
		out.CPUPercent, out.CPUReady = sampler.SamplePercent()
	}

	if mi, err := readMem(); err == nil && mi.TotalBytes > 0 {
		avail := min(mi.AvailableBytes, mi.TotalBytes)
		used := mi.TotalBytes - avail
		usedPct := int(math.Round(float64(used) * 100.0 / float64(mi.TotalBytes)))
		usedPct = max(0, min(100, usedPct))
		var swapUsed uint64
		if mi.SwapTotalBytes > mi.SwapFreeBytes {
			swapUsed = mi.SwapTotalBytes - mi.SwapFreeBytes
		}
		out.Mem = MemTelemetry{
			TotalBytes:     mi.TotalBytes,
			UsedBytes:      used,
			AvailBytes:     avail,
			SwapTotalBytes: mi.SwapTotalBytes,
			SwapUsedBytes:  swapUsed,
			UsedPercent:    usedPct,
			LowMemory:      IsLowMemoryMemInfo(mi),
		}
	}

	if isOpenWrt {
		if ds, err := statfsFn("/overlay"); err == nil && ds.TotalBytes > 0 {
			out.Disk = diskSpaceToTelemetry("/overlay", "闪存 (/overlay)", ds)
		} else if ds, err := statfsFn("/"); err == nil && ds.TotalBytes > 0 {
			out.Disk = diskSpaceToTelemetry("/", "根分区 (/)", ds)
		}
	} else if ds, err := statfsFn("/"); err == nil && ds.TotalBytes > 0 {
		out.Disk = diskSpaceToTelemetry("/", "根分区 (/)", ds)
	}

	if ds, err := statfsFn("/tmp"); err == nil && ds.TotalBytes > 0 {
		tmpDisk := diskSpaceToTelemetry("/tmp", "内存盘 (/tmp)", ds)
		out.TmpDisk = &tmpDisk
	}

	return out
}

func diskSpaceToTelemetry(mountPath, label string, ds DiskSpace) DiskTelemetry {
	return DiskTelemetry{
		MountPath:   mountPath,
		Label:       label,
		TotalBytes:  ds.TotalBytes,
		UsedBytes:   ds.UsedBytes,
		AvailBytes:  ds.AvailBytes,
		UsedPercent: max(0, min(100, ds.UsedPercent)),
	}
}
