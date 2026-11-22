package servicemgr

import (
	"cmp"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const defaultSystemdDir = "/etc/systemd/system"

// SystemdManager 封装标准 Linux systemd 服务管理操作。
type SystemdManager struct {
	runner  CmdRunner
	unitDir string
}

// NewSystemd 创建指向默认 `/etc/systemd/system` 的 systemd 管理器。
func NewSystemd(runner CmdRunner) *SystemdManager {
	return NewSystemdWithDir(runner, defaultSystemdDir)
}

// NewSystemdWithDir 创建指定 Unit 目录的 systemd 管理器（便于单元测试隔离宿主机路径）。
func NewSystemdWithDir(runner CmdRunner, unitDir string) *SystemdManager {
	return &SystemdManager{
		runner:  activeRunner(runner),
		unitDir: cmp.Or(strings.TrimSpace(unitDir), defaultSystemdDir),
	}
}

func (m *SystemdManager) Kind() InitKind { return InitSystemd }

func (m *SystemdManager) unitFilePath(name string) string {
	unitName := name
	if !strings.HasSuffix(unitName, ".service") {
		unitName += ".service"
	}
	return filepath.Join(m.unitDir, unitName)
}

func (m *SystemdManager) hasLocalUnitOverride(name string) bool {
	if m.unitDir == "" || m.unitDir == defaultSystemdDir {
		return false
	}
	_, err := os.Stat(m.unitFilePath(name))
	return err != nil
}

func (m *SystemdManager) runAction(ctx context.Context, verb, name string) error {
	if err := ValidateUnitName(name); err != nil {
		return err
	}
	if (verb == "stop" || verb == "restart") && m.hasLocalUnitOverride(name) {
		return nil
	}
	if err := m.runner.Run(ctx, defaultActionTimeout, "systemctl", verb, name); err != nil {
		return fmt.Errorf("systemctl %s %s: %w", verb, name, err)
	}
	return nil
}

func (m *SystemdManager) Start(ctx context.Context, name string) error {
	return m.runAction(ctx, "start", name)
}

func (m *SystemdManager) Stop(ctx context.Context, name string) error {
	return m.runAction(ctx, "stop", name)
}

func (m *SystemdManager) Restart(ctx context.Context, name string) error {
	return m.runAction(ctx, "restart", name)
}

func (m *SystemdManager) Reload(ctx context.Context, name string) error {
	return m.runAction(ctx, "reload", name)
}

func (m *SystemdManager) ReloadOrRestart(ctx context.Context, name string) error {
	return m.runAction(ctx, "reload-or-restart", name)
}

func (m *SystemdManager) Enable(ctx context.Context, name string) error {
	return m.runAction(ctx, "enable", name)
}

func (m *SystemdManager) Disable(ctx context.Context, name string) error {
	return m.runAction(ctx, "disable", name)
}

func (m *SystemdManager) DaemonReload(ctx context.Context) error {
	out, err := m.runner.CombinedOutput(ctx, defaultActionTimeout, "systemctl", "daemon-reload")
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg != "" {
			return fmt.Errorf("systemctl daemon-reload: %w (%s)", err, msg)
		}
		return fmt.Errorf("systemctl daemon-reload: %w", err)
	}
	return nil
}

func (m *SystemdManager) IsActive(ctx context.Context, name string) bool {
	if ValidateUnitName(name) != nil {
		return false
	}
	return m.runner.Run(ctx, defaultProbeTimeout, "systemctl", "is-active", "--quiet", name) == nil
}

func (m *SystemdManager) InstallUnit(ctx context.Context, spec UnitSpec) error {
	if err := ValidateUnitName(spec.Name); err != nil {
		return err
	}
	renderedBody, err := RenderSystemdBody(spec)
	if err != nil {
		return err
	}
	unitPath := cmp.Or(strings.TrimSpace(spec.SystemdPath), m.unitFilePath(spec.Name))
	if dir := filepath.Dir(unitPath); dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("create unit dir %s: %w", dir, err)
		}
	}
	if err := os.WriteFile(unitPath, []byte(renderedBody), 0644); err != nil {
		return fmt.Errorf("write %s: %w", unitPath, err)
	}
	if err := m.DaemonReload(ctx); err != nil {
		return err
	}
	_ = m.Enable(ctx, spec.Name)
	return m.Restart(ctx, spec.Name)
}

func (m *SystemdManager) RemoveUnit(ctx context.Context, spec UnitSpec) error {
	if err := ValidateUnitName(spec.Name); err != nil {
		return err
	}
	_ = m.runAction(ctx, "stop", spec.Name)
	_ = m.runAction(ctx, "disable", spec.Name)
	unitPath := cmp.Or(strings.TrimSpace(spec.SystemdPath), m.unitFilePath(spec.Name))
	if err := os.Remove(unitPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove %s: %w", unitPath, err)
	}
	_ = m.DaemonReload(ctx)
	return nil
}
