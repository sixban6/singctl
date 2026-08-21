package osutil

import (
	"os/exec"
	"runtime"
)

// PgrepMatch 检查是否存在指定名称的进程(Unix)。
//
// 背景:busybox pgrep 的 -x 精确匹配存在怪癖 —— 实测 ImmortalWrt 24.10
// (busybox 1.36.1) 上 `pgrep -x tailscaled` 无法匹配正在运行的 tailscaled
// 进程(comm 就是 "tailscaled"),而不带 -x 的子串匹配与 -f 全命令行匹配均正常;
// 同机 `pgrep -x sing-box` 却能命中,原因不明。procps 版 pgrep 则无此问题。
//
// 因此采用两级策略:
//  1. 先试 -x 精确匹配(procps 与多数 busybox 的首选语义)
//  2. 失败后退化为子串匹配(comm 恒为二进制文件名,子串误报概率极低)
//
// 返回 false 表示两种方式都未找到进程。
func PgrepMatch(name string) bool {
	if runtime.GOOS == "windows" {
		return false
	}
	if exec.Command("pgrep", "-x", name).Run() == nil {
		return true
	}
	return exec.Command("pgrep", name).Run() == nil
}
