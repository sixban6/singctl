// 文件职责：负责 SmartDNS 服务单元渲染（systemd / OpenWrt procd）、servicemgr 生命周期托管、清缓存与本地 DNS 探活。
package smartdns

import (
	"cmp"
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"singctl/internal/common/proc"
	"singctl/internal/platform/servicemgr"
)

func sanitizeUnitValue(raw, fallback string) string {
	s := strings.TrimSpace(raw)
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\n", "")
	return cmp.Or(s, fallback)
}

// BuildSystemdUnit 生成标准 Linux systemd 托管单元内容（Type=simple + Restart=on-failure + MemoryMax=64M）。
func BuildSystemdUnit(binPath, configFile, pidFile string) string {
	bin := sanitizeUnitValue(binPath, DefaultBinaryPath)
	conf := sanitizeUnitValue(configFile, DefaultConfigFile)
	pid := sanitizeUnitValue(pidFile, DefaultPIDFilePath)

	return fmt.Sprintf(`[Unit]
Description=SmartDNS local encrypted DNS engine (managed by singctl)
ConditionFileIsExecutable=%s
After=syslog.target network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s -f -c %s -p %s
Restart=on-failure
RestartSec=3
MemoryMax=64M
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
`, bin, bin, conf, pid)
}

// BuildOpenWrtInitScript 生成 OpenWrt procd 守护脚本（标准 POSIX / BusyBox 兼容语法 + respawn）。
func BuildOpenWrtInitScript(binPath, configFile, pidFile string) string {
	bin := sanitizeUnitValue(binPath, DefaultBinaryPath)
	conf := sanitizeUnitValue(configFile, DefaultConfigFile)
	pid := sanitizeUnitValue(pidFile, DefaultPIDFilePath)

	return fmt.Sprintf(`#!/bin/sh /etc/rc.common

START=89
STOP=15
USE_PROCD=1

PROG="%s"
CONF="%s"
PIDFILE="%s"

start_service() {
    [ -f "$CONF" ] && chmod 600 "$CONF" 2>/dev/null || true
    procd_open_instance "singctl-smartdns"
    procd_set_param command "$PROG" -f -c "$CONF" -p "$PIDFILE"
    procd_set_param respawn 3600 5 5
    procd_set_param limits nofile="65536 65536"
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_close_instance
}

reload_service() {
    stop
    start
}
`, bin, conf, pid)
}

func (m *Manager) activeServiceMgr() servicemgr.Manager {
	if m.serviceMgr != nil {
		return m.serviceMgr
	}
	host := servicemgr.DetectHost()
	switch host.Kind {
	case servicemgr.InitProcd:
		return servicemgr.NewProcd(nil, m.procdDir)
	case servicemgr.InitSystemd:
		return servicemgr.NewSystemdWithDir(nil, m.systemdDir)
	default:
		return servicemgr.NewNoop()
	}
}

func (m *Manager) unitSpec() servicemgr.UnitSpec {
	spec := servicemgr.UnitSpec{
		Name:        m.serviceName,
		SystemdBody: BuildSystemdUnit(m.binPath, m.configFile, m.pidFilePath),
		ProcdBody:   BuildOpenWrtInitScript(m.binPath, m.configFile, m.pidFilePath),
	}
	if m.systemdDir != "" {
		spec.SystemdPath = filepath.Join(m.systemdDir, m.serviceName+".service")
	}
	if m.procdDir != "" {
		spec.ProcdPath = filepath.Join(m.procdDir, m.serviceName)
	}
	return spec
}

func (m *Manager) installAndStartService(ctx context.Context) error {
	mgr := m.activeServiceMgr()
	if err := mgr.InstallUnit(ctx, m.unitSpec()); err != nil {
		return fmt.Errorf("安装并启动托管服务 %s 失败: %w", m.serviceName, err)
	}
	return nil
}

func (m *Manager) isServiceActive() bool {
	mgr := m.activeServiceMgr()
	if mgr.IsActive(context.Background(), m.serviceName) {
		return true
	}
	// 当未显式注入 ServiceMgr（生产宿主机模式）时，辅以进程存在性兜底判定，测试替身模式不扫描宿主机进程。
	if m.serviceMgr == nil {
		return proc.PgrepMatch("smartdns")
	}
	return false
}

// Start 启动 SmartDNS 托管服务（若配置文件缺失则先按当前输入安全落盘）。
func (m *Manager) Start() error {
	if !m.isBinaryPresent() {
		return fmt.Errorf("SmartDNS 尚未安装 (%s)，请先执行安装", m.binPath)
	}
	ctx := context.Background()
	if _, err := os.Stat(m.configFile); os.IsNotExist(err) {
		if err := m.writeConfigAndRules(ctx, m.snapshotConfig()); err != nil {
			return err
		}
	}
	mgr := m.activeServiceMgr()
	if err := mgr.Start(ctx, m.serviceName); err != nil {
		if os.IsNotExist(err) {
			return m.installAndStartService(ctx)
		}
		return fmt.Errorf("启动服务 %s 失败: %w", m.serviceName, err)
	}
	_ = mgr.Enable(ctx, m.serviceName)
	return nil
}

// Stop 停止 SmartDNS 托管服务。
func (m *Manager) Stop() error {
	mgr := m.activeServiceMgr()
	if err := mgr.Stop(context.Background(), m.serviceName); err != nil {
		return fmt.Errorf("停止服务 %s 失败: %w", m.serviceName, err)
	}
	return nil
}

// Restart 重启 SmartDNS 托管服务。
func (m *Manager) Restart() error {
	if !m.isBinaryPresent() {
		return fmt.Errorf("SmartDNS 尚未安装 (%s)，无法重启", m.binPath)
	}
	mgr := m.activeServiceMgr()
	if err := mgr.Restart(context.Background(), m.serviceName); err != nil {
		return fmt.Errorf("重启服务 %s 失败: %w", m.serviceName, err)
	}
	return nil
}

// Reload 平滑重载 SmartDNS 托管服务配置。
func (m *Manager) Reload() error {
	if !m.isBinaryPresent() {
		return fmt.Errorf("SmartDNS 尚未安装 (%s)，无法重载", m.binPath)
	}
	mgr := m.activeServiceMgr()
	if err := mgr.ReloadOrRestart(context.Background(), m.serviceName); err != nil {
		return fmt.Errorf("重载服务 %s 失败: %w", m.serviceName, err)
	}
	return nil
}

// ClearCache 通过安全重启清空 SmartDNS 内存缓存（配合 cache-persist no，重启即清且 < 200ms）。
func (m *Manager) ClearCache() error {
	if !m.isBinaryPresent() {
		return fmt.Errorf("SmartDNS 尚未安装 (%s)，无法清理缓存", m.binPath)
	}
	if err := m.Restart(); err != nil {
		return err
	}
	return m.waitDNSReady(context.Background(), 5*time.Second)
}

func (m *Manager) probeDNS(addr string, timeout time.Duration) error {
	if m.probeDNSFunc != nil {
		return m.probeDNSFunc(addr, timeout)
	}
	return ProbeDNS(addr, timeout)
}

func (m *Manager) probeDNSWithRetry(addr string, timeout time.Duration, attempts int, retryDelay time.Duration) error {
	if attempts <= 1 {
		return m.probeDNS(addr, timeout)
	}
	var lastErr error
	for i := range attempts {
		if err := m.probeDNS(addr, timeout); err == nil {
			return nil
		} else {
			lastErr = err
		}
		if i+1 < attempts && retryDelay > 0 {
			time.Sleep(retryDelay)
		}
	}
	return lastErr
}

func (m *Manager) waitDNSReady(ctx context.Context, maxWait time.Duration) error {
	dnsAddr := m.dnsAddr()
	deadline := time.Now().Add(maxWait)
	var lastErr error
	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := m.probeDNS(dnsAddr, 800*time.Millisecond); err == nil {
			return nil
		} else {
			lastErr = err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
	return fmt.Errorf("等待 SmartDNS 端口 (%s) 就绪超时: %v", dnsAddr, lastErr)
}

// ProbeDNS 向指定本地 UDP DNS 地址发送标准 RFC 1035 探活包（localhost. A），验证监听与响应正常。
func ProbeDNS(addr string, timeout time.Duration) error {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	var txid [2]byte
	_, _ = rand.Read(txid[:])

	query := []byte{
		txid[0], txid[1],
		0x01, 0x00, // Standard query, RD=1
		0x00, 0x01, // QDCOUNT=1
		0x00, 0x00, // ANCOUNT=0
		0x00, 0x00, // NSCOUNT=0
		0x00, 0x00, // ARCOUNT=0
		0x09, 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't', 0x00,
		0x00, 0x01, // QTYPE=A
		0x00, 0x01, // QCLASS=IN
	}

	if _, err := conn.Write(query); err != nil {
		return err
	}

	resp := make([]byte, 512)
	n, err := conn.Read(resp)
	if err != nil {
		return err
	}
	if n < 12 {
		return fmt.Errorf("short DNS response (%d bytes)", n)
	}
	if resp[0] != txid[0] || resp[1] != txid[1] {
		return fmt.Errorf("mismatched DNS transaction ID")
	}
	if resp[2]&0x80 == 0 {
		return fmt.Errorf("response missing QR flag")
	}
	return nil
}
