//go:build unix

package tailscale

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

func statfsFreeBytes(path string) (uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, err
	}
	if st.Bsize <= 0 {
		return 0, nil
	}
	return uint64(st.Bavail) * uint64(st.Bsize), nil
}

func readSystemMemInfo() (memAvailBytes, swapFreeBytes uint64) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0
	}
	var memAvailKB, memFreeKB, buffersKB, cachedKB, swapFreeKB uint64
	var hasMemAvail bool
	for line := range strings.SplitSeq(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		val, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}
		switch fields[0] {
		case "MemAvailable:":
			memAvailKB = val
			hasMemAvail = true
		case "MemFree:":
			memFreeKB = val
		case "Buffers:":
			buffersKB = val
		case "Cached:":
			cachedKB = val
		case "SwapFree:":
			swapFreeKB = val
		}
	}
	if !hasMemAvail {
		memAvailKB = memFreeKB + buffersKB + cachedKB
	}
	return memAvailKB * 1024, swapFreeKB * 1024
}

func detachCmdAttrs(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}

func isPIDAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	return syscall.Kill(pid, 0) == nil
}
