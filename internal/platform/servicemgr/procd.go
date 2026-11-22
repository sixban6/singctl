package servicemgr

import (
	"cmp"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const defaultProcdDir = "/etc/init.d"

// ProcdManager 封装 OpenWrt procd (`/etc/init.d/<name>`) 服务管理操作。
type ProcdManager struct {
	runner  CmdRunner
	initDir string
}

// NewProcd 创建 OpenWrt procd 管理器；initDir 为空时默认使用 `/etc/init.d`。
func NewProcd(runner CmdRunner, initDir string) *ProcdManager {
	return &ProcdManager{
		runner:  activeRunner(runner),
		initDir: cmp.Or(strings.TrimSpace(initDir), defaultProcdDir),
	}
}

func (m *ProcdManager) Kind() InitKind { return InitProcd }

func (m *ProcdManager) scriptPath(name string) string {
	base := strings.TrimSuffix(name, ".service")
	return filepath.Join(m.initDir, base)
}

func (m *ProcdManager) runScript(ctx context.Context, name, verb string, idempotentOnMissing bool) error {
	if err := ValidateUnitName(name); err != nil {
		return err
	}
	script := m.scriptPath(name)
	if _, err := os.Stat(script); err != nil {
		if idempotentOnMissing && os.IsNotExist(err) {
			return nil
		}
		return err
	}
	out, err := m.runner.CombinedOutput(ctx, defaultActionTimeout, script, verb)
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg != "" {
			return fmt.Errorf("%s %s: %w (%s)", script, verb, err, msg)
		}
		return fmt.Errorf("%s %s: %w", script, verb, err)
	}
	return nil
}

func (m *ProcdManager) Start(ctx context.Context, name string) error {
	return m.runScript(ctx, name, "start", false)
}

func (m *ProcdManager) Stop(ctx context.Context, name string) error {
	return m.runScript(ctx, name, "stop", true)
}

func (m *ProcdManager) Restart(ctx context.Context, name string) error {
	return m.runScript(ctx, name, "restart", true)
}

func (m *ProcdManager) Reload(ctx context.Context, name string) error {
	if err := m.runScript(ctx, name, "reload", false); err == nil {
		return nil
	}
	return m.Restart(ctx, name)
}

func (m *ProcdManager) ReloadOrRestart(ctx context.Context, name string) error {
	return m.Reload(ctx, name)
}

func (m *ProcdManager) Enable(ctx context.Context, name string) error {
	return m.runScript(ctx, name, "enable", false)
}

func (m *ProcdManager) Disable(ctx context.Context, name string) error {
	return m.runScript(ctx, name, "disable", true)
}

func (m *ProcdManager) DaemonReload(context.Context) error { return nil }

func (m *ProcdManager) IsActive(ctx context.Context, name string) bool {
	if ValidateUnitName(name) != nil {
		return false
	}
	script := m.scriptPath(name)
	if _, err := os.Stat(script); err != nil {
		return false
	}
	out, err := m.runner.CombinedOutput(ctx, defaultProbeTimeout, script, "status")
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(string(out)), "running")
}

func (m *ProcdManager) InstallUnit(ctx context.Context, spec UnitSpec) error {
	if err := ValidateUnitName(spec.Name); err != nil {
		return err
	}
	renderedBody, err := RenderProcdBody(spec)
	if err != nil {
		return err
	}
	script := cmp.Or(strings.TrimSpace(spec.ProcdPath), m.scriptPath(spec.Name))
	if dir := filepath.Dir(script); dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("create init dir %s: %w", dir, err)
		}
	}
	if err := os.WriteFile(script, []byte(renderedBody), 0755); err != nil {
		return fmt.Errorf("write %s: %w", script, err)
	}
	_ = m.runner.Run(ctx, defaultActionTimeout, script, "enable")
	out, err := m.runner.CombinedOutput(ctx, defaultActionTimeout, script, "restart")
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg != "" {
			return fmt.Errorf("restart %s: %w (%s)", script, err, msg)
		}
		return fmt.Errorf("restart %s: %w", script, err)
	}
	return nil
}

func (m *ProcdManager) RemoveUnit(ctx context.Context, spec UnitSpec) error {
	if err := ValidateUnitName(spec.Name); err != nil {
		return err
	}
	script := cmp.Or(strings.TrimSpace(spec.ProcdPath), m.scriptPath(spec.Name))
	if _, err := os.Stat(script); err == nil {
		_ = m.runner.Run(ctx, defaultActionTimeout, script, "stop")
		_ = m.runner.Run(ctx, defaultActionTimeout, script, "disable")
	}
	if err := os.Remove(script); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove %s: %w", script, err)
	}
	return nil
}
