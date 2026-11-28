// 文件职责：提供 Linux QUIC/UDP Socket 缓冲区、队列调度与 BBR 状态零子进程探测、内存分档推荐与纯数据模型。
package socktune

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"

	"singctl/internal/common/fsx"
	"singctl/internal/common/sysinfo"
)

// Profile 区分客户端路由（保守 default，按内存分级 max）与服务端节点（为 Caddy L4 UDP 提高 default）。
type Profile string

const (
	ProfileClient Profile = "client"
	ProfileServer Profile = "server"
)

const (
	defaultQuicSysctlFile = "/etc/sysctl.d/99-quic-buffer.conf"
	defaultModulesDir     = "/etc/modules.d"

	procRmemMax      = "/proc/sys/net/core/rmem_max"
	procWmemMax      = "/proc/sys/net/core/wmem_max"
	procRmemDefault  = "/proc/sys/net/core/rmem_default"
	procWmemDefault  = "/proc/sys/net/core/wmem_default"
	procDefaultQdisc = "/proc/sys/net/core/default_qdisc"
	procTCPCC        = "/proc/sys/net/ipv4/tcp_congestion_control"
	procTCPAvailCC   = "/proc/sys/net/ipv4/tcp_available_congestion_control"
	procNetSnmp      = "/proc/net/snmp"
	procMemInfo      = "/proc/meminfo"

	kb = 1024
	mb = 1024 * kb

	minBufferBytes          = 212992     // Linux 默认 208 KiB
	maxAllowedBufferBytes   = 32 * mb    // 允许设置的最大上限 32 MiB
	maxClientDefaultBytes   = 1 * mb     // 客户端默认缓冲安全上限 1 MiB（超过则视为过大需收敛）
	maxServerDefaultBytes   = 16 * mb    // 服务端默认缓冲允许上限 16 MiB
	clientHighDefaultBytes  = 256 * kb   // 1 GiB+ 路由推荐 default 256 KiB
	serverHighDefaultBytes  = 8 * mb     // 900 MiB+ VPS 推荐 Caddy default 8 MiB
	serverMidDefaultBytes   = 4 * mb     // 512~899 MiB VPS 推荐 Caddy default 4 MiB
	serverSmallDefaultBytes = 2 * mb     // < 512 MiB VPS 推荐 default 2 MiB
)

var defaultConflictSysctlFiles = []string{
	"/etc/sysctl.conf",
	"/etc/sysctl.d/99-custom.conf",
	"/etc/sysctl.d/99-singctl-bbr.conf",
}

var (
	// ErrUnsupported 表示当前宿主机非 Linux 或缺少 /proc/sys/net/core 网络调优接口。
	ErrUnsupported = errors.New("当前系统不支持 Linux Socket 缓冲调优")
	// ErrInvalidRequest 表示请求参数超出安全上下限或包含非法预设名称。
	ErrInvalidRequest = errors.New("Socket 缓冲调优参数不合法")
	// ErrReadOnlyKernel 表示当前运行在内核参数只读的容器虚拟化环境中（如 OpenVZ/LXC）。
	ErrReadOnlyKernel = errors.New("当前内核网络参数处于只读隔离环境（容器虚拟化），无法修改 sysctl")
)

// Env 封装全部外部系统依赖，未设置字段自动回退生产默认实现；单测通过注入替身实现宿主机零污染。
type Env struct {
	GOOS                string
	ReadFile            func(path string) ([]byte, error)
	WriteFile           func(path string, data []byte, perm os.FileMode) error
	WriteProc           func(path string, data []byte) error
	Stat                func(path string) (os.FileInfo, error)
	RunCmd              func(ctx context.Context, name string, args ...string) ([]byte, error)
	QuicSysctlFile      string
	ConflictSysctlFiles []string
	ModulesDir          string
}

// Status 描述当前宿主机 QUIC/UDP Socket 缓冲区、队列调度与 TCP 拥塞控制的实时状态与分档建议。
type Status struct {
	Supported              bool    `json:"supported"`
	Profile                Profile `json:"profile"`
	TotalMemMB             int     `json:"totalMemMb"`
	RmemMax                int     `json:"rmemMax"`
	WmemMax                int     `json:"wmemMax"`
	RmemDefault            int     `json:"rmemDefault"`
	WmemDefault            int     `json:"wmemDefault"`
	RecommendedRmemMax     int     `json:"recommendedRmemMax"`
	RecommendedWmemMax     int     `json:"recommendedWmemMax"`
	RecommendedRmemDefault int     `json:"recommendedRmemDefault"`
	RecommendedWmemDefault int     `json:"recommendedWmemDefault"`
	DefaultQdisc           string  `json:"defaultQdisc"`
	RecommendedQdisc       string  `json:"recommendedQdisc"`
	TCPCongestion          string  `json:"tcpCongestion"`
	BBRAvailable           bool    `json:"bbrAvailable"`
	BBREnabled             bool    `json:"bbrEnabled"`
	UDPRcvbufErrors        uint64  `json:"udpRcvbufErrors"`
	UDPSndbufErrors        uint64  `json:"udpSndbufErrors"`
	MaxBufferOptimal       bool    `json:"maxBufferOptimal"`
	DefaultBufferOptimal   bool    `json:"defaultBufferOptimal"`
	ExcessiveDefault       bool    `json:"excessiveDefault"`
	DefaultBottleneck      bool    `json:"defaultBottleneck"`
	QdiscOptimal           bool    `json:"qdiscOptimal"`
	Optimal                bool    `json:"optimal"`
	Summary                string  `json:"summary"`
}

// ApplyRequest 描述 QUIC/UDP Socket 缓冲区与 BBR 优化请求。
type ApplyRequest struct {
	DefaultPreset string `json:"defaultPreset,omitempty"`
	RmemMax       int    `json:"rmemMax,omitempty"`
	WmemMax       int    `json:"wmemMax,omitempty"`
	RmemDefault   int    `json:"rmemDefault,omitempty"`
	WmemDefault   int    `json:"wmemDefault,omitempty"`
	EnableBBR     *bool  `json:"enableBbr,omitempty"`
}

// ApplyResult 描述应用与持久化后的状态摘要及服务重载建议。
type ApplyResult struct {
	OK                   bool     `json:"ok"`
	Actions              []string `json:"actions"`
	Warnings             []string `json:"warnings,omitzero"`
	DefaultBufferChanged bool     `json:"defaultBufferChanged"`
	RestartRecommended   bool     `json:"restartRecommended"`
	Status               Status   `json:"status"`
}

func normalizeProfile(p Profile) Profile {
	if strings.TrimSpace(string(p)) == "" {
		return ProfileClient
	}
	return p
}

func (e Env) goos() string {
	return cmp.Or(strings.TrimSpace(e.GOOS), runtime.GOOS)
}

func (e Env) readFile(path string) ([]byte, error) {
	if e.ReadFile != nil {
		return e.ReadFile(path)
	}
	return os.ReadFile(path)
}

func (e Env) writeFile(path string, data []byte, perm os.FileMode) error {
	if e.WriteFile != nil {
		return e.WriteFile(path, data, perm)
	}
	return fsx.WriteAtomic(path, data, perm)
}

func (e Env) writeProc(path string, data []byte) error {
	if e.WriteProc != nil {
		return e.WriteProc(path, data)
	}
	return os.WriteFile(path, data, 0644)
}

func (e Env) stat(path string) (os.FileInfo, error) {
	if e.Stat != nil {
		return e.Stat(path)
	}
	return os.Stat(path)
}

func (e Env) quicSysctlFile() string {
	return cmp.Or(strings.TrimSpace(e.QuicSysctlFile), defaultQuicSysctlFile)
}

func (e Env) conflictSysctlFiles() []string {
	if e.ConflictSysctlFiles != nil {
		return e.ConflictSysctlFiles
	}
	return defaultConflictSysctlFiles
}

func (e Env) modulesDir() string {
	return cmp.Or(strings.TrimSpace(e.ModulesDir), defaultModulesDir)
}

func (e Env) readProcInt(path string) (int, bool) {
	raw, err := e.readFile(path)
	if err != nil {
		return 0, false
	}
	v, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		return 0, false
	}
	return v, true
}

func (e Env) readProcString(path string) string {
	raw, err := e.readFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

// Inspect 以零子进程纯 /proc 只读方式探测当前宿主机的 Socket 缓冲与 BBR/FQ 状态。
func Inspect(profile Profile, env Env) Status {
	profile = normalizeProfile(profile)
	st := Status{
		Profile: profile,
	}
	if env.goos() != "linux" {
		return st
	}
	rmemMax, ok := env.readProcInt(procRmemMax)
	if !ok {
		return st
	}

	st.Supported = true
	st.RmemMax = rmemMax
	st.WmemMax, _ = env.readProcInt(procWmemMax)
	st.RmemDefault, _ = env.readProcInt(procRmemDefault)
	st.WmemDefault, _ = env.readProcInt(procWmemDefault)
	st.DefaultQdisc = env.readProcString(procDefaultQdisc)
	st.TCPCongestion = env.readProcString(procTCPCC)

	availCC := env.readProcString(procTCPAvailCC)
	st.BBRAvailable = containsWord(availCC, "bbr") || st.TCPCongestion == "bbr"
	st.BBREnabled = st.TCPCongestion == "bbr"

	if memRaw, err := env.readFile(procMemInfo); err == nil {
		mi := sysinfo.ParseMemInfo(string(memRaw))
		st.TotalMemMB = int(mi.TotalBytes / uint64(mb))
	}

	if snmpRaw, err := env.readFile(procNetSnmp); err == nil {
		st.UDPRcvbufErrors, st.UDPSndbufErrors = parseUDPSnmpErrors(string(snmpRaw))
	}

	applyProfileAssessment(&st)
	return st
}

func applyProfileAssessment(st *Status) {
	if st.Profile == ProfileServer {
		if st.TotalMemMB == 0 || st.TotalMemMB >= 512 {
			st.RecommendedRmemMax = 16 * mb
			st.RecommendedWmemMax = 16 * mb
		} else {
			st.RecommendedRmemMax = 8 * mb
			st.RecommendedWmemMax = 8 * mb
		}

		minAcceptableDefault := serverMidDefaultBytes
		switch {
		case st.TotalMemMB == 0 || st.TotalMemMB >= 900:
			st.RecommendedRmemDefault = serverHighDefaultBytes
			st.RecommendedWmemDefault = serverHighDefaultBytes
		case st.TotalMemMB >= 512:
			st.RecommendedRmemDefault = serverMidDefaultBytes
			st.RecommendedWmemDefault = serverMidDefaultBytes
		default:
			st.RecommendedRmemDefault = serverSmallDefaultBytes
			st.RecommendedWmemDefault = serverSmallDefaultBytes
			minAcceptableDefault = serverSmallDefaultBytes
		}

		st.RecommendedQdisc = "fq"
		st.MaxBufferOptimal = st.RmemMax >= st.RecommendedRmemMax && st.WmemMax >= st.RecommendedWmemMax
		st.DefaultBottleneck = st.RmemDefault < minAcceptableDefault || st.WmemDefault < minAcceptableDefault
		st.DefaultBufferOptimal = !st.DefaultBottleneck
		st.QdiscOptimal = st.DefaultQdisc == "fq"
		st.Optimal = st.MaxBufferOptimal && st.DefaultBufferOptimal && st.QdiscOptimal && (!st.BBRAvailable || st.BBREnabled)
		st.Summary = buildServerSummary(*st)
		return
	}

	// 客户端路由模式：rmem_max/wmem_max 按内存分档提高，rmem_default/wmem_default 保持保守防多连接爆内存
	switch {
	case st.TotalMemMB >= 1024:
		st.RecommendedRmemMax = 16 * mb
		st.RecommendedWmemMax = 16 * mb
		st.RecommendedRmemDefault = clientHighDefaultBytes
		st.RecommendedWmemDefault = clientHighDefaultBytes
	case st.TotalMemMB == 0 || st.TotalMemMB >= 400:
		st.RecommendedRmemMax = 4 * mb
		st.RecommendedWmemMax = 4 * mb
		st.RecommendedRmemDefault = minBufferBytes
		st.RecommendedWmemDefault = minBufferBytes
	default:
		st.RecommendedRmemMax = 2 * mb
		st.RecommendedWmemMax = 2 * mb
		st.RecommendedRmemDefault = minBufferBytes
		st.RecommendedWmemDefault = minBufferBytes
	}

	st.RecommendedQdisc = "fq"
	st.MaxBufferOptimal = st.RmemMax >= st.RecommendedRmemMax && st.WmemMax >= st.RecommendedWmemMax
	st.ExcessiveDefault = st.RmemDefault > maxClientDefaultBytes || st.WmemDefault > maxClientDefaultBytes
	st.DefaultBufferOptimal = st.RmemDefault >= minBufferBytes &&
		st.WmemDefault >= minBufferBytes &&
		!st.ExcessiveDefault
	st.QdiscOptimal = st.DefaultQdisc == "fq" || st.DefaultQdisc == "fq_codel"
	st.Optimal = st.MaxBufferOptimal && st.DefaultBufferOptimal && st.QdiscOptimal && (!st.BBRAvailable || st.BBREnabled)
	st.Summary = buildClientSummary(*st)
}

func buildServerSummary(st Status) string {
	switch {
	case st.Optimal:
		return fmt.Sprintf("QUIC/UDP 缓冲与 %s+%s 已优化（Caddy 默认 %s，上限 %s）",
			cmp.Or(st.DefaultQdisc, "fq"), cmp.Or(st.TCPCongestion, "bbr"),
			formatBufferSize(st.RmemDefault), formatBufferSize(st.RmemMax))
	case st.DefaultBottleneck:
		return fmt.Sprintf("检测到 Caddy Layer4 默认 UDP 缓冲偏小（当前 %s），突发流量易丢包，建议提升至 %s",
			formatBufferSize(st.RmemDefault), formatBufferSize(st.RecommendedRmemDefault))
	case !st.MaxBufferOptimal:
		return fmt.Sprintf("内核 UDP 缓冲上限偏小（当前 %s），建议调整至 %s",
			formatBufferSize(st.RmemMax), formatBufferSize(st.RecommendedRmemMax))
	case st.BBRAvailable && !st.BBREnabled:
		return "Socket 缓冲已达标，建议开启 fq + BBR 拥塞控制以进一步降低弱网重传"
	default:
		return "部分内核队列参数尚未达最优，建议一键应用优化"
	}
}

func buildClientSummary(st Status) string {
	switch {
	case st.Optimal:
		return fmt.Sprintf("QUIC/UDP Socket 缓冲已达最优（上限 %s，默认 %s）",
			formatBufferSize(st.RmemMax), formatBufferSize(st.RmemDefault))
	case st.ExcessiveDefault:
		return fmt.Sprintf("检测到默认 Socket 缓冲过大（%s），高并发下易膨胀内存占用，建议收敛至 %s",
			formatBufferSize(max(st.RmemDefault, st.WmemDefault)), formatBufferSize(st.RecommendedRmemDefault))
	case !st.MaxBufferOptimal:
		return fmt.Sprintf("UDP 缓冲上限偏小（当前 %s），建议按本机内存调整至 %s 以提升 Hysteria2 吞吐",
			formatBufferSize(st.RmemMax), formatBufferSize(st.RecommendedRmemMax))
	case st.BBRAvailable && !st.BBREnabled:
		return "缓冲上限已达标，建议开启 BBR 与 FQ 队列加速"
	default:
		return "建议应用推荐的 QUIC/UDP 缓冲参数"
	}
}

func formatBufferSize(bytes int) string {
	switch {
	case bytes >= mb && bytes%mb == 0:
		return fmt.Sprintf("%d MB", bytes/mb)
	case bytes >= mb:
		return fmt.Sprintf("%.1f MB", float64(bytes)/float64(mb))
	case bytes >= kb:
		return fmt.Sprintf("%d KB", bytes/kb)
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}

func containsWord(s, target string) bool {
	for w := range strings.FieldsSeq(s) {
		if w == target {
			return true
		}
	}
	return false
}

func parseUDPSnmpErrors(raw string) (rcvErr, sndErr uint64) {
	var headers []string
	for line := range strings.SplitSeq(raw, "\n") {
		if !strings.HasPrefix(line, "Udp:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if headers == nil {
			headers = fields[1:]
			continue
		}
		values := fields[1:]
		for i, h := range headers {
			if i >= len(values) {
				break
			}
			switch h {
			case "RcvbufErrors":
				rcvErr, _ = strconv.ParseUint(values[i], 10, 64)
			case "SndbufErrors":
				sndErr, _ = strconv.ParseUint(values[i], 10, 64)
			}
		}
		headers = nil
	}
	return rcvErr, sndErr
}
