// 文件职责：识别常驻守护进程角色并依据宿主机总物理内存自适应设置 Go 运行时软内存上限（GOMEMLIMIT）。
package memlimit

import (
	"os"
	"runtime"
	"runtime/debug"
	"strings"

	"singctl/internal/common/sysinfo"
)

const mib = 1024 * 1024

// Role 标识当前进程是否为需要启用 Go 软内存上限治理的常驻守护角色。
type Role uint8

const (
	RoleNone Role = iota
	RoleSubHub
	RoleDaemonOrWeb
)

// DetectDaemonRole 从命令行参数中零堆分配识别当前进程是否处于常驻守护角色。
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
		if nPos == 1 || (nPos >= 2 && pos[1] == "start") {
			return RoleDaemonOrWeb
		}
	case "sr", "server":
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

// ParseMeminfoTotalBytes 从 /proc/meminfo 文本中提取 MemTotal 字节数（委托 sysinfo.ParseMemInfo）。
func ParseMeminfoTotalBytes(raw string) uint64 {
	return sysinfo.ParseMemInfo(raw).TotalBytes
}

// ComputeSoftMemoryLimit 按守护角色与宿主机总物理内存计算自适应 Go 软内存上限（字节）。
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

// ApplyForArgs 允许注入环境变量读取、内存探测与 SetMemoryLimit 回调以完成可测治理（尊重显式 GOMEMLIMIT）。
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

// ApplyDefault 根据 os.Args 与宿主机真实物理内存自动应用 Go 软内存上限。
func ApplyDefault(args []string) int64 {
	return ApplyForArgs(
		args,
		os.Getenv,
		func() uint64 {
			if runtime.GOOS != "linux" {
				return 0
			}
			mi, err := sysinfo.ReadMemInfo()
			if err != nil {
				return 0
			}
			return mi.TotalBytes
		},
		debug.SetMemoryLimit,
	)
}
