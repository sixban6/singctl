// 文件职责：封装客户端 WebUI 有界子进程执行辅助函数，底层委托 common/execx。
package webui

import (
	"context"
	"os"
	"time"

	"singctl/internal/common/execx"
)

const (
	defaultWebProbeTimeout   = execx.DefaultProbeTimeout
	defaultWebRestartTimeout = 25 * time.Second
)

// OutputWebCmdTimeout 以指定超时执行外部命令并返回标准输出。
func OutputWebCmdTimeout(timeout time.Duration, name string, args ...string) ([]byte, error) {
	return execx.Output(context.Background(), timeout, name, args...)
}

// RunWebCmdTimeout 以指定超时和环境变量执行外部命令。
func RunWebCmdTimeout(timeout time.Duration, env []string, stdout, stderr *os.File, name string, args ...string) error {
	return execx.RunIO(context.Background(), timeout, env, nil, stdout, stderr, name, args...)
}

func runWebCmdTimeout(timeout time.Duration, env []string, stdout, stderr *os.File, name string, args ...string) error {
	return RunWebCmdTimeout(timeout, env, stdout, stderr, name, args...)
}
