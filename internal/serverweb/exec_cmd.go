package serverweb

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"time"

	"singctl/internal/platform/servicemgr"
)

const (
	defaultServerProbeTimeout  = 3 * time.Second
	defaultServerCheckTimeout  = 15 * time.Second
	defaultServerActionTimeout = 25 * time.Second
)

// serviceCmdRunner abstracts synchronous system command execution so handlers remain
// bounded in production and deterministically testable without host side effects.
type serviceCmdRunner interface {
	Run(ctx context.Context, timeout time.Duration, name string, args ...string) error
	CombinedOutput(ctx context.Context, timeout time.Duration, name string, args ...string) ([]byte, error)
}

type defaultServiceCmdRunner struct{}

func newBoundedServerCmd(ctx context.Context, timeout time.Duration, name string, args ...string) (*exec.Cmd, context.CancelFunc, error) {
	if strings.TrimSpace(name) == "" {
		return nil, func() {}, errors.New("empty command name")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if timeout <= 0 {
		timeout = defaultServerProbeTimeout
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	cmd := exec.CommandContext(runCtx, name, args...)
	cmd.WaitDelay = min(timeout/2+100*time.Millisecond, time.Second)
	return cmd, cancel, nil
}

func (defaultServiceCmdRunner) Run(ctx context.Context, timeout time.Duration, name string, args ...string) error {
	cmd, cancel, err := newBoundedServerCmd(ctx, timeout, name, args...)
	if err != nil {
		return err
	}
	defer cancel()
	return cmd.Run()
}

func (defaultServiceCmdRunner) CombinedOutput(ctx context.Context, timeout time.Duration, name string, args ...string) ([]byte, error) {
	cmd, cancel, err := newBoundedServerCmd(ctx, timeout, name, args...)
	if err != nil {
		return nil, err
	}
	defer cancel()
	return cmd.CombinedOutput()
}

func runSystemCmdTimeout(timeout time.Duration, name string, args ...string) error {
	return defaultServiceCmdRunner{}.Run(context.Background(), timeout, name, args...)
}

func combinedOutputSystemCmdTimeout(timeout time.Duration, name string, args ...string) ([]byte, error) {
	return defaultServiceCmdRunner{}.CombinedOutput(context.Background(), timeout, name, args...)
}

func (s *Server) activeCmdRunner() serviceCmdRunner {
	if s != nil && s.cmdRunner != nil {
		return s.cmdRunner
	}
	return defaultServiceCmdRunner{}
}

func (s *Server) serviceMgr() servicemgr.Manager {
	return servicemgr.NewSystemd(s.activeCmdRunner())
}

func (s *Server) runCmd(ctx context.Context, timeout time.Duration, name string, args ...string) error {
	return s.activeCmdRunner().Run(ctx, timeout, name, args...)
}

func (s *Server) combinedOutputCmd(ctx context.Context, timeout time.Duration, name string, args ...string) ([]byte, error) {
	return s.activeCmdRunner().CombinedOutput(ctx, timeout, name, args...)
}

func (s *Server) resolveServiceConfigPath(service, fallback string) string {
	if s != nil && s.serviceConfigPaths != nil {
		if override := strings.TrimSpace(s.serviceConfigPaths[service]); override != "" {
			return override
		}
	}
	return fallback
}

func (s *Server) canRunSystemctl() bool {
	if s != nil && s.cmdRunner != nil {
		return true
	}
	_, err := exec.LookPath("systemctl")
	return err == nil
}
