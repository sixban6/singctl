// 文件职责：提供统一有界超时、防孙进程占管道挂起（WaitDelay）与洁净 LC_ALL=C 环境的子进程执行器。
package execx

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// DefaultProbeTimeout 为未显式指定正数超时时的默认命令保护上限。
const DefaultProbeTimeout = 3 * time.Second

// Runner 抽象带超时上限的同步系统命令执行契约，供业务与测试替身无缝共享。
type Runner interface {
	Run(ctx context.Context, timeout time.Duration, name string, args ...string) error
	CombinedOutput(ctx context.Context, timeout time.Duration, name string, args ...string) ([]byte, error)
}

// DefaultRunner 为生产环境默认有界命令执行器。
type DefaultRunner struct{}

// Active 返回非 nil 的注入 Runner；未注入时回退至 DefaultRunner。
func Active(r Runner) Runner {
	if r != nil {
		return r
	}
	return DefaultRunner{}
}

// NewBoundedCmd 构造绑定超时上下文、WaitDelay 管道超时回收及洁净 LC_ALL=C 环境的 *exec.Cmd。
func NewBoundedCmd(ctx context.Context, timeout time.Duration, name string, args ...string) (*exec.Cmd, context.CancelFunc, error) {
	if strings.TrimSpace(name) == "" {
		return nil, func() {}, errors.New("empty command name")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if timeout <= 0 {
		timeout = DefaultProbeTimeout
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	cmd := exec.CommandContext(runCtx, name, args...)
	cmd.WaitDelay = min(timeout/2+100*time.Millisecond, time.Second)
	cmd.Env = CleanEnv(nil, "LC_ALL=C")
	return cmd, cancel, nil
}

// Run 以给定超时同步执行系统命令。
func (DefaultRunner) Run(ctx context.Context, timeout time.Duration, name string, args ...string) error {
	return Run(ctx, timeout, name, args...)
}

// CombinedOutput 以给定超时执行系统命令并返回合并的标准输出与标准错误。
func (DefaultRunner) CombinedOutput(ctx context.Context, timeout time.Duration, name string, args ...string) ([]byte, error) {
	return CombinedOutput(ctx, timeout, name, args...)
}

// Run 以给定超时同步执行系统命令。
func Run(ctx context.Context, timeout time.Duration, name string, args ...string) error {
	cmd, cancel, err := NewBoundedCmd(ctx, timeout, name, args...)
	if err != nil {
		return err
	}
	defer cancel()
	return cmd.Run()
}

// Output 以给定超时同步执行系统命令并仅捕获标准输出。
func Output(ctx context.Context, timeout time.Duration, name string, args ...string) ([]byte, error) {
	cmd, cancel, err := NewBoundedCmd(ctx, timeout, name, args...)
	if err != nil {
		return nil, err
	}
	defer cancel()
	return cmd.Output()
}

// CombinedOutput 以给定超时执行系统命令并捕获合并输出。
func CombinedOutput(ctx context.Context, timeout time.Duration, name string, args ...string) ([]byte, error) {
	cmd, cancel, err := NewBoundedCmd(ctx, timeout, name, args...)
	if err != nil {
		return nil, err
	}
	defer cancel()
	return cmd.CombinedOutput()
}

// RunIO 以给定超时、可选环境变量切片与显式标准输入输出句柄执行命令。
func RunIO(ctx context.Context, timeout time.Duration, env []string, stdin, stdout, stderr *os.File, name string, args ...string) error {
	cmd, cancel, err := NewBoundedCmd(ctx, timeout, name, args...)
	if err != nil {
		return err
	}
	defer cancel()
	if len(env) > 0 {
		cmd.Env = env
	}
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	return cmd.Run()
}

// CleanEnv 基于当前进程环境变量剥离 stripKeys，并用 extra ("KEY=VAL") 去重覆写；
// 若传入 "KEY="（空值）则显式移除同名父环境变量而不注入空串。
func CleanEnv(stripKeys []string, extra ...string) []string {
	drop := make(map[string]struct{}, len(stripKeys)+len(extra))
	for _, k := range stripKeys {
		if k != "" {
			drop[k] = struct{}{}
		}
	}
	for _, kv := range extra {
		if k, _, ok := strings.Cut(kv, "="); ok && k != "" {
			drop[k] = struct{}{}
		}
	}

	base := os.Environ()
	out := make([]string, 0, len(base)+len(extra))
	for _, kv := range base {
		k, _, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		if _, shouldDrop := drop[k]; shouldDrop {
			continue
		}
		out = append(out, kv)
	}
	for _, kv := range extra {
		if k, v, ok := strings.Cut(kv, "="); ok && k != "" && v != "" {
			out = append(out, kv)
		}
	}
	return out
}

// WithXtablesWait 为 iptables/ip6tables 命令参数自动前置 `-w 5` 等待内核 xtables 锁，
// 防止多模块并发下发规则时触发 `exit status 4 (Another app is currently holding the xtables lock)`。
func WithXtablesWait(name string, args []string) []string {
	base := filepath.Base(strings.TrimSpace(name))
	if base != "iptables" && base != "ip6tables" {
		return args
	}
	for _, a := range args {
		if a == "-w" || a == "--wait" || strings.HasPrefix(a, "--wait=") {
			return args
		}
	}
	out := make([]string, 0, len(args)+2)
	out = append(out, "-w", "5")
	out = append(out, args...)
	return out
}
