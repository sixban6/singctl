package webui

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"time"
)

const (
	defaultWebProbeTimeout   = 3 * time.Second
	defaultWebRestartTimeout = 25 * time.Second
)

func newBoundedWebCmd(timeout time.Duration, name string, args ...string) (*exec.Cmd, context.CancelFunc, error) {
	if strings.TrimSpace(name) == "" {
		return nil, func() {}, errors.New("empty command name")
	}
	if timeout <= 0 {
		timeout = defaultWebProbeTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.WaitDelay = min(timeout/2+100*time.Millisecond, time.Second)
	return cmd, cancel, nil
}

// outputWebCmdTimeout runs a synchronous subprocess with bounded timeout and returns its stdout.
func outputWebCmdTimeout(timeout time.Duration, name string, args ...string) ([]byte, error) {
	cmd, cancel, err := newBoundedWebCmd(timeout, name, args...)
	if err != nil {
		return nil, err
	}
	defer cancel()
	return cmd.Output()
}

// runWebCmdTimeout runs a synchronous subprocess with bounded timeout, optional env, and stdio handles.
func runWebCmdTimeout(timeout time.Duration, env []string, stdout, stderr *os.File, name string, args ...string) error {
	cmd, cancel, err := newBoundedWebCmd(timeout, name, args...)
	if err != nil {
		return err
	}
	defer cancel()
	if len(env) > 0 {
		cmd.Env = env
	}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	return cmd.Run()
}
