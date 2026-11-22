//go:build !unix

// 文件职责：提供非 Unix 平台安全回滚看门狗子进程脱离属性回退实现。
package safecommit

import (
	"os/exec"

	"singctl/internal/common/proc"
)

func setWatcherDetached(cmd *exec.Cmd) {
	proc.SetDetachedAttr(cmd)
}
