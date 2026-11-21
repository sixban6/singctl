package memlimit

import (
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
)

const (
	mib = 1024 * 1024

	// linuxMeminfoPath 为 Linux 内核标准内存统计虚拟文件路径。
	linuxMeminfoPath = "/proc/meminfo"
)

// Role 标识当前进程是否为需要启用 Go 软内存上限治理的常驻守护模式。
type Role uint8

const (
	// RoleNone 表示短生命周期 CLI 命令，不做运行时内存限制。
	RoleNone Role = iota
	// RoleSubHub 表示极简订阅聚合 HTTP 服务 (singctl-sub)。
	RoleSubHub
	// RoleDaemonOrWeb 表示软路由看门狗、客户端 WebUI 或服务端管理面板等常驻进程。
	RoleDaemonOrWeb
)

// DetectDaemonRole 从命令行参数中识别当前进程是否处于常驻守护角色。
// 使用栈上固定数组提取前 3 个位置参数，零堆内存分配，确保 CLI 启动路径无额外开销。
func DetectDaemonRole(args []string) Role {
	if len(args) <= 1 {
		return RoleNone
	}

	var pos [3]string
	var nPos int
	skipNextValue := false

	for i := 1; i < len(args); i++ {
		arg := args[i]
		if skipNextValue {
			skipNextValue = false
			continue
		}
		if arg == "" || arg == "--" {
			continue
		}
		if strings.HasPrefix(arg, "-") {
			// 全局与服务监听参数常采用 `-flag value` 两段写法，跳过紧随其后的值避免误识别为子命令
			if !strings.Contains(arg, "=") && takesValueFlag(arg) {
				skipNextValue = true
			}
			continue
		}
		if nPos < len(pos) {
			pos[nPos] = arg
		}
		nPos++
	}

	if nPos == 0 {
		return RoleNone
	}

	switch pos[0] {
	case "dm", "daemon":
		if nPos >= 2 && pos[1] == "start" {
			return RoleDaemonOrWeb
		}
	case "web", "w":
		// 仅 Foreground 运行（无子命令，如 `singctl web -l :8090`）或 `start` 才是常驻服务；
		// `stop` / `status` 等控制命令需保持 RoleNone。
		if nPos == 1 || (nPos >= 2 && pos[1] == "start") {
			return RoleDaemonOrWeb
		}
	case "sr", "server":
		// `sr ui` / `sr web` / `sr sub` 在恰好 2 个位置参数时为守护主进程；
		// 带 `start` / `stop` / `status` 等第 3 参数时是短生命周期控制命令。
		if nPos == 2 {
			switch pos[1] {
			case "sub":
				return RoleSubHub
			case "ui", "web", "w":
				return RoleDaemonOrWeb
			}
		}
	}
	return RoleNone
}

func takesValueFlag(flag string) bool {
	switch flag {
	case "-c", "--config", "-l", "--listen", "-p", "--password", "-u", "--username", "--user", "--dir", "--host":
		return true
	default:
		return false
	}
}

// ParseMeminfoTotalBytes 从 /proc/meminfo 文本中解析 MemTotal 总物理内存（单位：字节）。
func ParseMeminfoTotalBytes(raw string) uint64 {
	for line := range strings.SplitSeq(raw, "\n") {
		if !strings.HasPrefix(line, "MemTotal:") {
			continue
		}
		rest := strings.TrimSpace(strings.TrimPrefix(line, "MemTotal:"))
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			return 0
		}
		kb, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil || kb == 0 {
			return 0
		}
		return kb * 1024
	}
	return 0
}

// ComputeSoftMemoryLimit 按守护角色与宿主机总物理内存计算自适应 Go 软内存上限（字节）。
// 架构原因：512MB~1GB 小内存 VPS 与无 Swap 软路由若不设 GOMEMLIMIT，编译节点或并发连接突发扩容后
// Go 堆水位会持续驻留高点；软上限会引导 GC 在触发阈值前更积极回收冷对象。
func ComputeSoftMemoryLimit(role Role, totalRAMBytes uint64) int64 {
	if role == RoleNone {
		return 0
	}

	if totalRAMBytes == 0 {
		if role == RoleSubHub {
			return 48 * mib
		}
		return 64 * mib
	}

	switch {
	case totalRAMBytes <= 1024*mib:
		if role == RoleSubHub {
			return 32 * mib
		}
		return 48 * mib
	case totalRAMBytes <= 2048*mib:
		if role == RoleSubHub {
			return 48 * mib
		}
		return 64 * mib
	default:
		if role == RoleSubHub {
			return 64 * mib
		}
		return 96 * mib
	}
}

// ApplyForArgs 允许注入环境变量读取、内存探测与 SetMemoryLimit 回调以完成可测的内存治理。
// 若用户或 systemd/supervisor 已显式设置了 GOMEMLIMIT 环境变量，则尊重手动配置不予覆盖。
func ApplyForArgs(
	args []string,
	getenv func(string) string,
	readMemTotal func() uint64,
	setLimit func(int64) int64,
) int64 {
	if getenv == nil || setLimit == nil {
		return 0
	}
	if strings.TrimSpace(getenv("GOMEMLIMIT")) != "" {
		return 0
	}

	role := DetectDaemonRole(args)
	if role == RoleNone && getenv("SINGCTL_WEB_BACKGROUND") == "1" {
		role = RoleDaemonOrWeb
	}
	if role == RoleNone {
		return 0
	}

	var totalRAM uint64
	if readMemTotal != nil {
		totalRAM = readMemTotal()
	}
	limit := ComputeSoftMemoryLimit(role, totalRAM)
	if limit <= 0 {
		return 0
	}
	setLimit(limit)
	return limit
}

// ApplyDefault 根据 os.Args 与宿主机真实内存自动应用 Go 软内存上限（尊重用户显式 GOMEMLIMIT）。
func ApplyDefault(args []string) int64 {
	return ApplyForArgs(
		args,
		os.Getenv,
		func() uint64 {
			if runtime.GOOS != "linux" {
				return 0
			}
			return readMeminfoTotalBytesFromFile(linuxMeminfoPath)
		},
		debug.SetMemoryLimit,
	)
}

func readMeminfoTotalBytesFromFile(path string) uint64 {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	return ParseMeminfoTotalBytes(string(raw))
}
