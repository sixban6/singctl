package adguard

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"singctl/internal/util/netinfo"
)

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
	if runtime.GOOS != "linux" || netinfo.IsOpenWrt() {
		return false
	}
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		return false
	}
	_, err := exec.LookPath("systemctl")
	return err == nil
}

func hasOpenWrtProcd() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	if !netinfo.IsOpenWrt() {
		return false
	}
	_, err := os.Stat("/etc/rc.common")
	return err == nil
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

	// DNS query for "localhost." Type A (1) Class IN (1)
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
	setDetachedSysProcAttr(cmd)

	return cmd.Start()
}
