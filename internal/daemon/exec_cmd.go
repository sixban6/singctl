package daemon

import (
	"cmp"
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"time"

	"singctl/internal/constant"
)

const (
	defaultDaemonCmdTimeout  = 3 * time.Second
	defaultDaemonRunTimeout  = 30 * time.Second
	defaultSubSyncCheckLimit = 15 * time.Second
)

func newBoundedCmd(ctx context.Context, timeout time.Duration, name string, args ...string) (*exec.Cmd, context.CancelFunc, error) {
	if strings.TrimSpace(name) == "" {
		return nil, func() {}, errors.New("empty command name")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if timeout <= 0 {
		timeout = defaultDaemonCmdTimeout
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	cmd := exec.CommandContext(runCtx, name, args...)
	cmd.WaitDelay = min(timeout/2+100*time.Millisecond, time.Second)
	return cmd, cancel, nil
}

// outputCmdTimeout runs a synchronous subprocess with bounded timeout and returns its stdout.
func outputCmdTimeout(ctx context.Context, timeout time.Duration, name string, args ...string) ([]byte, error) {
	cmd, cancel, err := newBoundedCmd(ctx, timeout, name, args...)
	if err != nil {
		return nil, err
	}
	defer cancel()
	return cmd.Output()
}

// combinedOutputCmdTimeout runs a synchronous subprocess with bounded timeout and returns merged output.
func combinedOutputCmdTimeout(ctx context.Context, timeout time.Duration, name string, args ...string) ([]byte, error) {
	cmd, cancel, err := newBoundedCmd(ctx, timeout, name, args...)
	if err != nil {
		return nil, err
	}
	defer cancel()
	return cmd.CombinedOutput()
}

// runCmdTimeoutIO runs a synchronous subprocess with bounded timeout and explicit stdio handles.
func runCmdTimeoutIO(ctx context.Context, timeout time.Duration, stdin, stdout, stderr *os.File, name string, args ...string) error {
	cmd, cancel, err := newBoundedCmd(ctx, timeout, name, args...)
	if err != nil {
		return err
	}
	defer cancel()
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	return cmd.Run()
}

func (d *Daemon) preValidateSubSyncConfig(cfgPath, candidateJSON string) (string, []byte, error) {
	tmpPath := cfgPath + ".subsync.tmp"
	if err := os.WriteFile(tmpPath, []byte(candidateJSON), 0600); err != nil {
		return "", nil, err
	}
	_ = os.Chmod(tmpPath, 0600)

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
	out, err := combinedOutputCmdTimeout(baseCtx, checkTimeout, sbBin, "check", "-c", tmpPath)
	if err != nil {
		_ = os.Remove(tmpPath)
		return "", out, err
	}
	return tmpPath, out, nil
}
