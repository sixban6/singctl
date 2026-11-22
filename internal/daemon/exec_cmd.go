// 文件职责：封装守护进程有界命令调用与订阅同步候选配置离线预校验，底层执行委托 common/execx。
package daemon

import (
	"cmp"
	"context"
	"os"
	"path/filepath"
	"strings"
	"time"

	"singctl/internal/common/execx"
	"singctl/internal/constant"
)

const (
	defaultDaemonCmdTimeout  = execx.DefaultProbeTimeout
	defaultDaemonRunTimeout  = 30 * time.Second
	defaultSubSyncCheckLimit = 15 * time.Second
)

// OutputCmdTimeout 在超时预算内执行外部命令并返回标准输出。
func OutputCmdTimeout(ctx context.Context, timeout time.Duration, name string, args ...string) ([]byte, error) {
	return execx.Output(ctx, timeout, name, args...)
}

// CombinedOutputCmdTimeout 在超时预算内执行外部命令并返回合并标准输出与标准错误。
func CombinedOutputCmdTimeout(ctx context.Context, timeout time.Duration, name string, args ...string) ([]byte, error) {
	return execx.CombinedOutput(ctx, timeout, name, args...)
}

// RunCmdTimeoutIO 在超时预算内以显式标准流运行外部命令。
func RunCmdTimeoutIO(ctx context.Context, timeout time.Duration, stdin, stdout, stderr *os.File, name string, args ...string) error {
	return execx.RunIO(ctx, timeout, nil, stdin, stdout, stderr, name, args...)
}

// PreValidateSubSyncConfig 将候选配置写入临时 0600 文件并执行 `sing-box check`，失败时自动清理临时文件。
func (d *Daemon) PreValidateSubSyncConfig(cfgPath, candidateJSON string) (string, []byte, error) {
	tmpFile, err := os.CreateTemp(filepath.Dir(cfgPath), "."+filepath.Base(cfgPath)+".subsync-*")
	if err != nil {
		return "", nil, err
	}
	tmpPath := tmpFile.Name()
	_ = tmpFile.Chmod(0600)
	if _, err := tmpFile.WriteString(candidateJSON); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
		return "", nil, err
	}
	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return "", nil, err
	}

	sbBin := constant.SingBoxInstallDir
	checkTimeout := defaultSubSyncCheckLimit
	var baseCtx context.Context
	if d != nil {
		sbBin = cmp.Or(strings.TrimSpace(d.subSyncBinOverride), constant.SingBoxInstallDir)
		if d.subSyncCheckTimeout > 0 {
			checkTimeout = d.subSyncCheckTimeout
		}
		baseCtx = d.ctx
	}
	out, err := CombinedOutputCmdTimeout(baseCtx, checkTimeout, sbBin, "check", "-c", tmpPath)
	if err != nil {
		_ = os.Remove(tmpPath)
		return "", out, err
	}
	return tmpPath, out, nil
}
