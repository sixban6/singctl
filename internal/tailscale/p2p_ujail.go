// 文件职责：管理 OpenWrt procd/ujail 最小权限沙盒注入、平滑升级与异常自动回滚。
package tailscale

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"singctl/internal/constant"
)

const (
	DefaultUjailBin      = "/sbin/ujail"
	DefaultUjailCapsPath = "/etc/capabilities/tailscale.json"
	DefaultUjailMarker   = "# SINGCTL_UJAIL_SANDBOX"
	DefaultUjailMarkerV2 = "# SINGCTL_UJAIL_SANDBOX_V2"
	ujailMarker          = DefaultUjailMarker
	ujailMarkerV2        = DefaultUjailMarkerV2
)

// UjailOptions 配置 Layer 3 OpenWrt ujail 沙盒注入与可回滚选项。
type UjailOptions struct {
	InitScriptPath string
	BackupPath     string
	CapsFilePath   string
	UjailBin       string
	SocketPath     string
	ServiceRunner  func(ctx context.Context, script string, action string) error
	ProbeFunc      func(ctx context.Context, sockPath string) error
	ReadyTimeout   time.Duration
}

func (o UjailOptions) initPath() string {
	return cmp.Or(strings.TrimSpace(o.InitScriptPath), constant.TailscaleInitdScript)
}

func (o UjailOptions) backupPath() string {
	return cmp.Or(strings.TrimSpace(o.BackupPath), constant.TailscaleInitdScript+".singctl.bak")
}

func (o UjailOptions) capsPath() string {
	return cmp.Or(strings.TrimSpace(o.CapsFilePath), DefaultUjailCapsPath)
}

func (o UjailOptions) ujailBin() string {
	return cmp.Or(strings.TrimSpace(o.UjailBin), DefaultUjailBin)
}

func (o UjailOptions) socketPath() string {
	return cmp.Or(strings.TrimSpace(o.SocketPath), DefaultTailscaledSocket)
}

func (o UjailOptions) readyTimeout() time.Duration {
	if o.ReadyTimeout > 0 {
		return o.ReadyTimeout
	}
	return 8 * time.Second
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

func (o UjailOptions) probe(ctx context.Context, sockPath string) error {
	if o.ProbeFunc != nil {
		return o.ProbeFunc(ctx, sockPath)
	}
	return probeLocalAPIStatus(ctx, sockPath)
}

// BuildTailscaleCapabilitiesJSON 生成符合 OpenWrt procd/ujail 规范的最小网络权限白名单，
// 仅保留 CAP_NET_BIND_SERVICE / CAP_NET_ADMIN / CAP_NET_RAW，剥夺 CAP_SYS_ADMIN、CAP_MKNOD 等逃逸能力。
func BuildTailscaleCapabilitiesJSON() []byte {
	caps := []string{"CAP_NET_BIND_SERVICE", "CAP_NET_ADMIN", "CAP_NET_RAW"}
	doc := struct {
		Bounding    []string `json:"bounding"`
		Effective   []string `json:"effective"`
		Ambient     []string `json:"ambient"`
		Permitted   []string `json:"permitted"`
		Inheritable []string `json:"inheritable"`
	}{
		Bounding:    caps,
		Effective:   caps,
		Ambient:     caps,
		Permitted:   caps,
		Inheritable: caps,
	}
	raw, _ := json.MarshalIndent(doc, "", "\t")
	return append(raw, '\n')
}

func probeLocalAPIStatus(ctx context.Context, sockPath string) error {
	tr := &http.Transport{
		DialContext: func(dCtx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 1500 * time.Millisecond}).DialContext(dCtx, "unix", sockPath)
		},
		DisableKeepAlives: true,
	}
	defer tr.CloseIdleConnections()

	hc := &http.Client{
		Transport: tr,
		Timeout:   2 * time.Second,
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://local-tailscaled.sock/localapi/v0/status", nil)
	if err != nil {
		return err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("read localapi status: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("localapi status http %d", resp.StatusCode)
	}
	var st struct {
		BackendState string `json:"BackendState"`
	}
	if err := json.Unmarshal(body, &st); err != nil {
		return fmt.Errorf("decode localapi status: %w", err)
	}
	if strings.TrimSpace(st.BackendState) == "" {
		return fmt.Errorf("empty BackendState in localapi status")
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

// ApplyUjailSandbox 根据 enable 状态安全地为 /etc/init.d/tailscale 开启、平滑升级至 V2（最小 Capabilities + no_new_privs）
// 或还原 Layer 3 ujail 进程沙盒，变更前自动保留备份，重启后若 LocalAPI /localapi/v0/status 探活未就绪则自动回滚。
func ApplyUjailSandbox(ctx context.Context, enable bool, opts UjailOptions) (bool, error) {
	initPath := opts.initPath()
	backupPath := opts.backupPath()
	capsPath := opts.capsPath()

	raw, err := os.ReadFile(initPath)
	if err != nil {
		if !enable && os.IsNotExist(err) {
			_ = os.Remove(capsPath)
			return false, nil
		}
		return false, fmt.Errorf("read tailscale init script: %w", err)
	}

	cur := string(raw)
	hasMarker := strings.Contains(cur, ujailMarker)
	hasV2 := strings.Contains(cur, ujailMarkerV2)

	rollback := func() {
		_ = os.WriteFile(initPath, raw, 0755)
		_ = opts.runService(ctx, initPath, "restart")
	}

	if enable {
		if _, err := os.Stat(opts.ujailBin()); err != nil {
			return false, fmt.Errorf("ujail binary not found at %s: %w", opts.ujailBin(), err)
		}
		if err := os.MkdirAll(filepath.Dir(capsPath), 0755); err != nil {
			return false, fmt.Errorf("create capabilities dir: %w", err)
		}
		if err := os.WriteFile(capsPath, BuildTailscaleCapabilitiesJSON(), 0644); err != nil {
			return false, fmt.Errorf("write capabilities file: %w", err)
		}
		if hasV2 {
			return false, nil
		}

		baseScript := cur
		if hasMarker {
			// V1 -> V2 平滑升级：优先基于初始备份重新注入，避免重复叠加 procd_add_jail。
			if b, bErr := os.ReadFile(backupPath); bErr == nil && !strings.Contains(string(b), ujailMarker) {
				baseScript = string(b)
			} else {
				return false, fmt.Errorf("found legacy V1 ujail script without clean backup %s", backupPath)
			}
		} else if _, err := os.Stat(backupPath); os.IsNotExist(err) {
			if err := os.WriteFile(backupPath, raw, 0755); err != nil {
				return false, fmt.Errorf("backup init script: %w", err)
			}
		}

		injected, err := injectUjailIntoInitScript(baseScript, capsPath)
		if err != nil {
			return false, err
		}
		if err := os.WriteFile(initPath, []byte(injected), 0755); err != nil {
			return false, fmt.Errorf("write ujail init script: %w", err)
		}

		// 先停止旧实例并等待旧 LocalAPI 下线，规避 procd 异步重启导致误探测到垂死旧进程。
		_ = opts.runService(ctx, initPath, "stop")
		_ = waitLocalAPIDown(ctx, opts, 3*time.Second)

		if err := opts.runService(ctx, initPath, "start"); err != nil {
			rollback()
			return false, fmt.Errorf("start jailed tailscaled failed (rolled back): %w", err)
		}
		if err := waitLocalAPIReady(ctx, opts, opts.readyTimeout()); err != nil {
			rollback()
			return false, fmt.Errorf("tailscaled LocalAPI unavailable under ujail (rolled back): %w", err)
		}
		return true, nil
	}

	_ = os.Remove(capsPath)
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

func injectUjailIntoInitScript(script, capsPath string) (string, error) {
	anchor := "procd_close_instance"
	idx := strings.LastIndex(script, anchor)
	if idx < 0 {
		return "", fmt.Errorf("unexpected tailscale init script layout: missing %s", anchor)
	}

	jailBlock := strings.Join([]string{
		"    mkdir -p /etc/tailscale /var/run/tailscale /var/lib/tailscale",
		"    " + ujailMarkerV2,
		"    procd_add_jail tailscale log procfs sysfs ronly",
		fmt.Sprintf("    [ -f %q ] && procd_set_param capabilities %q", capsPath, capsPath),
		"    procd_set_param no_new_privs 1",
		"    procd_add_jail_mount /usr/sbin/tailscaled /usr/sbin/tailscale /etc/ssl /etc/hosts /etc/resolv.conf",
		"    for _singctl_ro in /etc/ssl/certs /etc/ssl/cert.pem /etc/protocols /etc/services /etc/TZ /tmp/resolv.conf.d /usr/sbin/nft /usr/sbin/iptables /usr/sbin/ip6tables /sbin/ip /usr/libexec/ip-full /bin/busybox; do",
		"        [ -e \"$_singctl_ro\" ] && procd_add_jail_mount \"$_singctl_ro\"",
		"    done",
		"    procd_add_jail_mount_rw /etc/tailscale /var/run/tailscale /var/lib/tailscale /dev/net/tun",
	}, "\n") + "\n"

	lineStart := strings.LastIndex(script[:idx], "\n")
	if lineStart < 0 {
		return jailBlock + script, nil
	}
	return script[:lineStart+1] + jailBlock + script[lineStart+1:], nil
}

func waitLocalAPIDown(ctx context.Context, opts UjailOptions, maxWait time.Duration) error {
	sockPath := opts.socketPath()
	deadline := time.Now().Add(maxWait)
	for {
		if err := opts.probe(ctx, sockPath); err != nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timeout waiting for previous %s shutdown", sockPath)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(150 * time.Millisecond):
		}
	}
}

func waitLocalAPIReady(ctx context.Context, opts UjailOptions, maxWait time.Duration) error {
	sockPath := opts.socketPath()
	deadline := time.Now().Add(maxWait)
	var lastErr error
	for {
		if err := opts.probe(ctx, sockPath); err == nil {
			return nil
		} else {
			lastErr = err
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timeout waiting for %s (%v)", sockPath, lastErr)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}
