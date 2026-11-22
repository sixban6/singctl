// 文件职责：提供 AdGuard Home 系统服务单元生成、进程启停卸载、版本缓存与本地 DNS/TCP 探活。
package adguard

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"singctl/internal/common/netx"
	"singctl/internal/common/proc"
	"singctl/internal/config"
	"singctl/internal/logger"
	"singctl/internal/platform/servicemgr"
)

var (
	binVerCacheMu  sync.Mutex
	binVerCacheKey string
	binVerCached   string
)

// CachedBinaryVersion 按二进制文件指纹 (path|mtime|size) 缓存 AdGuardHome --version，
// 二进制升级后 mtime/size 变化同一毫秒自动失效重读，避免高频接口每次 fork 35MB 子进程。
func CachedBinaryVersion(binPath string) string {
	info, err := os.Stat(binPath)
	if err != nil || info.IsDir() {
		return ""
	}
	key := fmt.Sprintf("%s|%d|%d", binPath, info.ModTime().UnixNano(), info.Size())

	binVerCacheMu.Lock()
	if binVerCacheKey == key && binVerCached != "" {
		ver := binVerCached
		binVerCacheMu.Unlock()
		return ver
	}
	binVerCacheMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	out, err := exec.CommandContext(ctx, binPath, "--version").Output()
	cancel()
	if err != nil {
		return ""
	}
	ver := strings.TrimSpace(string(out))
	if ver != "" {
		binVerCacheMu.Lock()
		binVerCacheKey = key
		binVerCached = ver
		binVerCacheMu.Unlock()
	}
	return ver
}

// BuildSystemdUnit 生成 Debian/Ubuntu/Linux 标准 systemd 服务单元内容。
func BuildSystemdUnit(binPath, configFile, workDir string) string {
	return fmt.Sprintf(`[Unit]
Description=AdGuard Home: Network-level blocker (managed by singctl)
ConditionFileIsExecutable=%s
After=syslog.target network-online.target
Wants=network-online.target

[Service]
StartLimitInterval=5
StartLimitBurst=10
ExecStart=%s -s run -c %s -w %s --no-check-update
WorkingDirectory=%s
Restart=always
RestartSec=3
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
`, binPath, binPath, configFile, workDir, workDir)
}

// BuildOpenWrtInitScript 生成 OpenWrt procd 守护脚本内容。
func BuildOpenWrtInitScript(binPath, configFile, workDir string) string {
	return fmt.Sprintf(`#!/bin/sh /etc/rc.common

START=90
STOP=15
USE_PROCD=1

PROG="%s"
CONF="%s"
WORKDIR="%s"

start_service() {
    mkdir -p "$WORKDIR"
    chmod 700 "$WORKDIR" 2>/dev/null || true
    [ -f "$CONF" ] && chmod 600 "$CONF" 2>/dev/null || true
    procd_open_instance "AdGuardHome"
    procd_set_param command "$PROG" -s run -c "$CONF" -w "$WORKDIR" --no-check-update
    procd_set_param respawn 3600 5 5
    procd_set_param limits nofile="65536 65536"
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_close_instance
}
`, binPath, configFile, workDir)
}

func hasSystemd() bool {
	return servicemgr.DetectHost().Kind == servicemgr.InitSystemd
}

func hasOpenWrtProcd() bool {
	return servicemgr.DetectHost().Kind == servicemgr.InitProcd
}

func (m *Manager) installAndStartService() error {
	if err := os.MkdirAll(m.aghWorkDir, 0700); err != nil {
		return err
	}

	if hasOpenWrtProcd() && m.initdScript != "" {
		sanitizeOpenWrtDnsmasqTTL()
		mgr := servicemgr.NewProcd(nil, filepath.Dir(m.initdScript))
		spec := servicemgr.UnitSpec{
			Name:      "AdGuardHome",
			ProcdPath: m.initdScript,
			ProcdBody: BuildOpenWrtInitScript(m.binPath, m.aghConfigFile, m.aghWorkDir),
		}
		if err := mgr.InstallUnit(context.Background(), spec); err != nil {
			if startErr := mgr.Start(context.Background(), "AdGuardHome"); startErr != nil {
				logger.Warn("procd 启动 AdGuardHome 返回异常 (%v / %v)，尝试直接守护拉起", err, startErr)
			}
		}
		time.Sleep(300 * time.Millisecond)
		if !isProcessRunning() {
			return startBackgroundDirect(m.binPath, m.aghConfigFile, m.aghWorkDir)
		}
		return nil
	}

	if hasSystemd() && m.systemdUnit != "" {
		mgr := servicemgr.NewSystemdWithDir(nil, filepath.Dir(m.systemdUnit))
		spec := servicemgr.UnitSpec{
			Name:        "AdGuardHome",
			SystemdPath: m.systemdUnit,
			SystemdBody: BuildSystemdUnit(m.binPath, m.aghConfigFile, m.aghWorkDir),
		}
		if err := mgr.InstallUnit(context.Background(), spec); err != nil {
			return fmt.Errorf("启动 systemd AdGuardHome 服务失败: %w", err)
		}
		return nil
	}

	_ = m.Stop()
	return startBackgroundDirect(m.binPath, m.aghConfigFile, m.aghWorkDir)
}

// sanitizeOpenWrtDnsmasqTTL 清理 OpenWrt/ImmortalWrt 固件自带 dnsmasq 中可能存在的强制 min_cache_ttl / mini_ttl，
// 防止 1 秒 TTL 的动态节点域名被 dnsmasq 强行篡改缓存 3600 秒。
func sanitizeOpenWrtDnsmasqTTL() {
	if _, err := exec.LookPath("uci"); err != nil {
		return
	}
	changed := false
	for _, key := range []string{"min_cache_ttl", "mini_ttl", "minttl", "use_stale_cache"} {
		target := "dhcp.@dnsmasq[0]." + key
		if out, err := exec.Command("uci", "-q", "get", target).Output(); err == nil && len(strings.TrimSpace(string(out))) > 0 {
			if exec.Command("uci", "-q", "delete", target).Run() == nil {
				changed = true
			}
		}
	}
	if changed {
		_ = exec.Command("uci", "commit", "dhcp").Run()
		_ = exec.Command("/etc/init.d/dnsmasq", "reload").Run()
	}
}

func (m *Manager) waitDNSReady(maxWait time.Duration) error {
	dnsAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(m.cfg.DNS.GetDNSPort()))
	deadline := time.Now().Add(maxWait)
	var lastErr error
	for time.Now().Before(deadline) {
		if err := ProbeDNS(dnsAddr, 800*time.Millisecond); err == nil {
			return nil
		} else {
			lastErr = err
		}
		time.Sleep(400 * time.Millisecond)
	}
	return fmt.Errorf("等待 AdGuard Home DNS 端口 (%s) 就绪超时: %v", dnsAddr, lastErr)
}

// Start 启动已安装的 AdGuard Home（若局域网 IP 发生变化会自动同步 Web 监听地址）。
func (m *Manager) Start() error {
	if !m.isBinaryPresent() {
		return fmt.Errorf("AdGuard Home 尚未安装 (%s)，请先运行: singctl dns install", m.binPath)
	}
	if _, err := os.Stat(m.aghConfigFile); os.IsNotExist(err) {
		m.cfg.DNS.EnsureCredentials("")
		if m.configPath != "" {
			_ = config.Save(m.configPath, m.cfg)
		}
		if err := m.ensureConfigFile(sanitizeWebBindIP(netx.GetPrimaryLANIPv4()), true); err != nil {
			return err
		}
	} else {
		lanIP := sanitizeWebBindIP(netx.GetPrimaryLANIPv4())
		_, _ = SyncExistingConfig(m.aghConfigFile, SyncOptions{
			LANIP:             lanIP,
			WebPort:           m.cfg.DNS.GetWebPort(),
			DNSPort:           m.cfg.DNS.GetDNSPort(),
			DisablePrivatePTR: new(true),
		})
	}

	if err := m.installAndStartService(); err != nil {
		return err
	}
	if err := m.waitDNSReady(10 * time.Second); err != nil {
		return err
	}
	_ = os.Chmod(m.aghConfigFile, 0600)
	return nil
}

// Stop 停止正在运行的 AdGuard Home 服务。
func (m *Manager) Stop() error {
	ctx := context.Background()
	if hasOpenWrtProcd() && m.initdScript != "" {
		_ = servicemgr.NewProcd(nil, filepath.Dir(m.initdScript)).Stop(ctx, "AdGuardHome")
	}
	if hasSystemd() {
		_ = servicemgr.NewSystemd(nil).Stop(ctx, "AdGuardHome")
	}
	if isProcessRunning() {
		_ = exec.Command("pkill", "-f", "AdGuardHome").Run()
		_ = exec.Command("killall", "AdGuardHome").Run()
		for range 10 {
			if !isProcessRunning() {
				break
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
	return nil
}

// Disable 停止 AdGuard Home 并禁用开机自启（保留二进制与配置文件，供三引擎无损切换使用）。
func (m *Manager) Disable() error {
	_ = m.Stop()
	ctx := context.Background()
	if hasOpenWrtProcd() && m.initdScript != "" {
		_ = servicemgr.NewProcd(nil, filepath.Dir(m.initdScript)).Disable(ctx, "AdGuardHome")
	}
	if hasSystemd() {
		_ = servicemgr.NewSystemd(nil).Disable(ctx, "AdGuardHome")
	}
	return nil
}

// ConfigFilePath 返回当前管理器使用的 AdGuardHome.yaml 路径（只读辅助）。
func (m *Manager) ConfigFilePath() string {
	if m == nil {
		return ""
	}
	return m.aghConfigFile
}

// Restart 重启 AdGuard Home。
func (m *Manager) Restart() error {
	_ = m.Stop()
	return m.Start()
}

// Uninstall 停止并卸载 AdGuard Home 服务与二进制（可选保留或清理配置目录）。
func (m *Manager) Uninstall(purgeConfig bool) error {
	_ = m.Stop()

	ctx := context.Background()
	if hasOpenWrtProcd() && m.initdScript != "" {
		_ = servicemgr.NewProcd(nil, filepath.Dir(m.initdScript)).RemoveUnit(ctx, servicemgr.UnitSpec{
			Name:      "AdGuardHome",
			ProcdPath: m.initdScript,
		})
	}
	if hasSystemd() && m.systemdUnit != "" {
		_ = servicemgr.NewSystemdWithDir(nil, filepath.Dir(m.systemdUnit)).RemoveUnit(ctx, servicemgr.UnitSpec{
			Name:        "AdGuardHome",
			SystemdPath: m.systemdUnit,
		})
	}
	if m.binPath != "" {
		_ = os.Remove(m.binPath)
	}
	if purgeConfig && m.aghConfigDir != "" {
		_ = os.RemoveAll(m.aghConfigDir)
	}

	m.cfg.DNS.SetEnabled(false)
	if m.configPath != "" {
		_ = config.Save(m.configPath, m.cfg)
	}
	return nil
}

// ProbeDNS 向指定 UDP DNS 地址（如 127.0.0.1:5353）发送标准 RFC 1035 本地探测包（localhost. A），
// 验证 AdGuardHome DNS 引擎已完成绑定并正常响应，无需依赖外部互联网。
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

// ProbeDNSWithRetry 在指定重试次数内执行局部 DNS 探活，避免瞬时调度抖动或单次 UDP 丢包误报异常。
func ProbeDNSWithRetry(addr string, timeout time.Duration, attempts int, retryDelay time.Duration) error {
	if attempts <= 1 {
		return ProbeDNS(addr, timeout)
	}
	var lastErr error
	for i := range attempts {
		if err := ProbeDNS(addr, timeout); err == nil {
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

// ProbeUpstreamResolution 通过本地 AdGuardHome (127.0.0.1:port) 实际解析指定域名，测量端到端 DoH 解析耗时。
func ProbeUpstreamResolution(dnsAddr, domain string, timeout time.Duration) ([]string, time.Duration, error) {
	if timeout <= 0 {
		timeout = 4 * time.Second
	}
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "udp", dnsAddr)
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	start := time.Now()
	addrs, err := r.LookupHost(ctx, domain)
	elapsed := time.Since(start)
	if err != nil {
		return nil, elapsed, err
	}
	return addrs, elapsed, nil
}

// ProbeTCPPort 检测 TCP 地址（如 Web 面板 <LAN_IP>:3000）是否正在监听。
func ProbeTCPPort(addr string, timeout time.Duration) bool {
	if timeout <= 0 {
		timeout = 1 * time.Second
	}
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// SelectAvailableWebPort 若当前 AdGuardHome 未运行且首选端口被其它进程占用，自动挑选可用端口。
func SelectAvailableWebPort(bindIP string, preferredPort int) int {
	if preferredPort <= 0 || preferredPort > 65535 {
		preferredPort = 3000
	}
	candidates := []int{preferredPort, 3000, 3002, 3003, 3080}
	for _, p := range candidates {
		addr := net.JoinHostPort(bindIP, strconv.Itoa(p))
		ln, err := net.Listen("tcp", addr)
		if err == nil {
			_ = ln.Close()
			return p
		}
	}
	return preferredPort
}

func isProcessRunning() bool {
	if proc.PgrepMatch("AdGuardHome") {
		return true
	}
	if _, err := exec.LookPath("pgrep"); err == nil {
		if err := exec.Command("pgrep", "-f", "AdGuardHome").Run(); err == nil {
			return true
		}
	}
	out, err := exec.Command("ps", "w").Output()
	if err != nil {
		out, err = exec.Command("ps", "-ef").Output()
	}
	if err == nil {
		for line := range strings.SplitSeq(string(out), "\n") {
			if strings.Contains(line, "AdGuardHome") && !strings.Contains(line, "grep") && !strings.Contains(line, "singctl") {
				return true
			}
		}
	}
	return false
}

func startBackgroundDirect(binPath, configFile, workDir string) error {
	if err := os.MkdirAll(workDir, 0700); err != nil {
		return err
	}
	devNull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer devNull.Close()

	logPath := "/var/log/AdGuardHome.log"
	if err := os.MkdirAll(filepath.Dir(logPath), 0755); err != nil {
		logPath = filepath.Join(os.TempDir(), "AdGuardHome.log")
	}
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		logFile = devNull
	} else {
		defer logFile.Close()
	}

	cmd := exec.Command(binPath, "-s", "run", "-c", configFile, "-w", workDir, "--no-check-update")
	cmd.Dir = workDir
	cmd.Stdin = devNull
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	proc.SetDetachedAttr(cmd)

	return cmd.Start()
}
