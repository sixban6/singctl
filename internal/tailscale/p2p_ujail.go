package tailscale

import (
	"cmp"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"singctl/internal/constant"
)

const (
	DefaultUjailBin = "/sbin/ujail"
	ujailMarker     = "# SINGCTL_UJAIL_SANDBOX"
)

// UjailOptions 配置 Layer 3 OpenWrt ujail 沙盒注入与可回滚选项。
type UjailOptions struct {
	InitScriptPath string
	BackupPath     string
	UjailBin       string
	SocketPath     string
	ServiceRunner  func(ctx context.Context, script string, action string) error
}

func (o UjailOptions) initPath() string {
	return cmp.Or(strings.TrimSpace(o.InitScriptPath), constant.TailscaleInitdScript)
}

func (o UjailOptions) backupPath() string {
	return cmp.Or(strings.TrimSpace(o.BackupPath), constant.TailscaleInitdScript+".singctl.bak")
}

func (o UjailOptions) ujailBin() string {
	return cmp.Or(strings.TrimSpace(o.UjailBin), DefaultUjailBin)
}

func (o UjailOptions) socketPath() string {
	return cmp.Or(strings.TrimSpace(o.SocketPath), DefaultTailscaledSocket)
}

func (o UjailOptions) runService(ctx context.Context, script, action string) error {
	if o.ServiceRunner != nil {
		return o.ServiceRunner(ctx, script, action)
	}
	out, err := exec.CommandContext(ctx, script, action).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w (%s)", script, action, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// IsUjailAvailable 检测当前系统是否具备 OpenWrt ujail 沙盒可执行程序与 tailscale init 脚本。
func IsUjailAvailable() bool {
	if _, err := os.Stat(DefaultUjailBin); err != nil {
		return false
	}
	_, err := os.Stat(constant.TailscaleInitdScript)
	return err == nil
}

// ApplyUjailSandbox 根据 enable 状态安全地为 /etc/init.d/tailscale 开启或还原 Layer 3 ujail 进程沙盒，
// 变更前自动保留备份，重启后若 LocalAPI socket 未就绪则自动回滚。
func ApplyUjailSandbox(ctx context.Context, enable bool, opts UjailOptions) (bool, error) {
	initPath := opts.initPath()
	backupPath := opts.backupPath()

	raw, err := os.ReadFile(initPath)
	if err != nil {
		if !enable && os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("read tailscale init script: %w", err)
	}

	cur := string(raw)
	hasMarker := strings.Contains(cur, ujailMarker)

	if enable {
		if hasMarker {
			return false, nil
		}
		if _, err := os.Stat(opts.ujailBin()); err != nil {
			return false, fmt.Errorf("ujail binary not found at %s: %w", opts.ujailBin(), err)
		}
		if _, err := os.Stat(backupPath); os.IsNotExist(err) {
			if err := os.WriteFile(backupPath, raw, 0755); err != nil {
				return false, fmt.Errorf("backup init script: %w", err)
			}
		}
		injected, err := injectUjailIntoInitScript(cur)
		if err != nil {
			return false, err
		}
		if err := os.WriteFile(initPath, []byte(injected), 0755); err != nil {
			return false, fmt.Errorf("write ujail init script: %w", err)
		}
		if err := opts.runService(ctx, initPath, "restart"); err != nil {
			_ = os.WriteFile(initPath, raw, 0755)
			_ = opts.runService(ctx, initPath, "restart")
			return false, fmt.Errorf("restart jailed tailscaled failed (rolled back): %w", err)
		}
		if err := waitSocketReady(ctx, opts.socketPath(), 5*time.Second); err != nil {
			_ = os.WriteFile(initPath, raw, 0755)
			_ = opts.runService(ctx, initPath, "restart")
			return false, fmt.Errorf("tailscaled socket unavailable under ujail (rolled back): %w", err)
		}
		return true, nil
	}

	if !hasMarker {
		return false, nil
	}
	restoreBytes, err := os.ReadFile(backupPath)
	if err != nil {
		return false, fmt.Errorf("read tailscale init backup %s: %w", backupPath, err)
	}
	if err := os.WriteFile(initPath, restoreBytes, 0755); err != nil {
		return false, fmt.Errorf("restore init script: %w", err)
	}
	if err := opts.runService(ctx, initPath, "restart"); err != nil {
		return false, fmt.Errorf("restart tailscaled after disabling ujail: %w", err)
	}
	return true, nil
}

func injectUjailIntoInitScript(script string) (string, error) {
	anchor := "procd_close_instance"
	idx := strings.LastIndex(script, anchor)
	if idx < 0 {
		return "", fmt.Errorf("unexpected tailscale init script layout: missing %s", anchor)
	}

	jailBlock := strings.Join([]string{
		"    " + ujailMarker,
		"    procd_add_jail tailscale log",
		"    procd_add_jail_mount /usr/sbin/tailscaled /usr/sbin/tailscale /etc/ssl/certs /dev/net/tun /etc/hosts /etc/resolv.conf /tmp/resolv.conf.d",
		"    procd_add_jail_mount_rw /etc/tailscale /var/run/tailscale",
	}, "\n") + "\n"

	lineStart := strings.LastIndex(script[:idx], "\n")
	if lineStart < 0 {
		return jailBlock + script, nil
	}
	return script[:lineStart+1] + jailBlock + script[lineStart+1:], nil
}

func waitSocketReady(ctx context.Context, sockPath string, maxWait time.Duration) error {
	deadline := time.Now().Add(maxWait)
	for {
		if _, err := os.Stat(sockPath); err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timeout waiting for %s", sockPath)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}
