package tailscale_p2p_e2e

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"singctl/internal/tailscale"
)

func ensureOpenWrtE2EImage(t *testing.T, ctx context.Context, repoRoot string) {
	t.Helper()
	if err := exec.CommandContext(ctx, "docker", "image", "inspect", e2eImageTag).Run(); err == nil {
		return
	}
	dfDir := filepath.Join(repoRoot, "test", "docker_env")
	mustRun(t, ctx, "docker", "build", "-t", e2eImageTag, dfDir)
}

func detectImageGoArch(t *testing.T, ctx context.Context, image string) string {
	t.Helper()
	out := strings.ToLower(strings.TrimSpace(mustRun(t, ctx, "docker", "image", "inspect", "--format", "{{.Architecture}}", image)))
	switch {
	case strings.Contains(out, "arm64"), strings.Contains(out, "aarch64"):
		return "arm64"
	case strings.Contains(out, "amd64"), strings.Contains(out, "x86_64"):
		return "amd64"
	default:
		return runtime.GOARCH
	}
}

func buildProbeHelperBinary(t *testing.T, ctx context.Context, workDir, targetArch string) string {
	t.Helper()
	probeDir := filepath.Join(workDir, "probe")
	if err := os.MkdirAll(probeDir, 0755); err != nil {
		t.Fatalf("mkdir probe: %v", err)
	}

	src := `package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"sync/atomic"
	"time"
)

func payloadFor(kind string) []byte {
	switch kind {
	case "disco":
		p := make([]byte, 80)
		copy(p[:6], []byte{0x54, 0x53, 0xf0, 0x9f, 0x92, 0xac})
		return p
	case "wg1":
		// WireGuard Handshake Initiation = 148B payload (156B UDP length)
		p := make([]byte, 148)
		p[0] = 0x01
		return p
	case "wg1bad":
		// Wrong length WireGuard Handshake Initiation = 200B payload (208B UDP length)
		p := make([]byte, 200)
		p[0] = 0x01
		return p
	case "stun":
		// RFC 5389 STUN Binding Request = 20B payload (28B UDP length), magic cookie 0x2112a442 at bytes 4..7
		p := make([]byte, 20)
		p[1] = 0x01
		copy(p[4:8], []byte{0x21, 0x12, 0xa4, 0x42})
		p[8] = 0x11
		return p
	case "garbage":
		return []byte("GARBAGE_PROBE_PACKET")
	case "data":
		return []byte("ESTABLISHED_DIRECT_DATA")
	default:
		return []byte(kind)
	}
}

func main() {
	if len(os.Args) < 2 {
		os.Exit(2)
	}
	switch os.Args[1] {
	case "udp-echo":
		addr, countFile := os.Args[2], os.Args[3]
		pc, err := net.ListenPacket("udp4", addr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "udp listen %s: %v\n", addr, err)
			os.Exit(1)
		}
		_ = os.WriteFile(countFile, []byte("0\n"), 0644)
		var count atomic.Int64
		buf := make([]byte, 4096)
		for {
			_, raddr, rErr := pc.ReadFrom(buf)
			if rErr != nil {
				continue
			}
			n := count.Add(1)
			tmp := countFile + ".tmp"
			_ = os.WriteFile(tmp, []byte(fmt.Sprintf("%d\n", n)), 0644)
			_ = os.Rename(tmp, countFile)
			_, _ = pc.WriteTo([]byte("PONG"), raddr)
		}

	case "udp-send", "udp-exchange":
		localAddr, dstAddr, kind := os.Args[2], os.Args[3], os.Args[4]
		pc, err := net.ListenPacket("udp4", localAddr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "udp bind %s: %v\n", localAddr, err)
			os.Exit(1)
		}
		defer pc.Close()
		raddr, err := net.ResolveUDPAddr("udp4", dstAddr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "resolve %s: %v\n", dstAddr, err)
			os.Exit(1)
		}
		if _, err := pc.WriteTo(payloadFor(kind), raddr); err != nil {
			fmt.Fprintf(os.Stderr, "udp write: %v\n", err)
			os.Exit(1)
		}
		if os.Args[1] == "udp-exchange" {
			_ = pc.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
			buf := make([]byte, 256)
			n, _, rErr := pc.ReadFrom(buf)
			if rErr != nil || string(buf[:n]) != "PONG" {
				fmt.Fprintf(os.Stderr, "udp exchange failed: n=%d err=%v\n", n, rErr)
				os.Exit(1)
			}
		}

	case "tcp-echo":
		ln, err := net.Listen("tcp4", os.Args[2])
		if err != nil {
			fmt.Fprintf(os.Stderr, "tcp listen %s: %v\n", os.Args[2], err)
			os.Exit(1)
		}
		for {
			conn, aErr := ln.Accept()
			if aErr != nil {
				continue
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				_, _ = bufio.NewReader(c).ReadString('\n')
				_, _ = c.Write([]byte("PONG\n"))
			}(conn)
		}

	case "tcp-dial":
		localIP, dstAddr := os.Args[2], os.Args[3]
		d := net.Dialer{
			LocalAddr: &net.TCPAddr{IP: net.ParseIP(localIP)},
			Timeout:   1200 * time.Millisecond,
		}
		conn, err := d.Dial("tcp4", dstAddr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "tcp dial %s -> %s: %v\n", localIP, dstAddr, err)
			os.Exit(1)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(1500 * time.Millisecond))
		_, _ = conn.Write([]byte("PING\n"))
		line, rErr := bufio.NewReader(conn).ReadString('\n')
		if rErr != nil || line != "PONG\n" {
			fmt.Fprintf(os.Stderr, "tcp reply err=%v line=%q\n", rErr, line)
			os.Exit(1)
		}

	default:
		os.Exit(2)
	}
}
`
	if err := os.WriteFile(filepath.Join(probeDir, "main.go"), []byte(src), 0644); err != nil {
		t.Fatalf("write probe main.go: %v", err)
	}
	if err := os.WriteFile(filepath.Join(probeDir, "go.mod"), []byte("module p2pprobe\n\ngo 1.24\n"), 0644); err != nil {
		t.Fatalf("write probe go.mod: %v", err)
	}
	outBin := filepath.Join(workDir, "p2p-probe")
	cmd := exec.CommandContext(ctx, "go", "build", "-o", outBin, ".")
	cmd.Dir = probeDir
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+targetArch)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build p2p-probe failed: %v\n%s", err, string(out))
	}
	return outBin
}

func setupRouterFirewallAndListeners(t *testing.T, ctx context.Context, routerC string) {
	t.Helper()
	script := fmt.Sprintf(`
set -e
WAN_IF=$(ip -o -4 addr show | awk '$4 ~ /^198\.51\.100\./ {print $2; exit}')
LAN_IF=$(ip -o -4 addr show | awk '$4 ~ /^192\.168\.180\./ {print $2; exit}')
TS_IF=$(ip -o -4 addr show | awk '$4 ~ /^100\.64\.200\./ {print $2; exit}')

if [ "$TS_IF" != "tailscale0" ]; then
    ip link set "$TS_IF" down
    ip link set "$TS_IF" name tailscale0
    ip link set tailscale0 up
    ip addr replace %s/24 dev tailscale0
fi
ip route replace %s via %s dev tailscale0

cat << FWEOF > /etc/config/firewall
config defaults
	option input 'REJECT'
	option output 'ACCEPT'
	option forward 'REJECT'
	option synflood_protect '1'

config zone
	option name 'lan'
	list device "$LAN_IF"
	option input 'ACCEPT'
	option output 'ACCEPT'
	option forward 'ACCEPT'

config zone
	option name 'wan'
	list device "$WAN_IF"
	option input 'REJECT'
	option output 'ACCEPT'
	option forward 'REJECT'
	option masq '1'

config zone
	option name 'tailscale'
	list device 'tailscale0'
	option input 'ACCEPT'
	option output 'ACCEPT'
	option forward 'ACCEPT'
	option masq '1'

config forwarding
	option src 'lan'
	option dest 'wan'

config forwarding
	option src 'tailscale'
	option dest 'lan'

config forwarding
	option src 'lan'
	option dest 'tailscale'

config forwarding
	option src 'tailscale'
	option dest 'wan'
FWEOF

mkdir -p /etc/nftables.d /usr/share/nftables.d
/sbin/fw4 -q check
/sbin/fw4 -q start

p2p-probe udp-echo %s:41641 /tmp/udp41641.count </dev/null >/tmp/udp41641.log 2>&1 &
p2p-probe tcp-echo %s:8090 </dev/null >/tmp/tcp8090.log 2>&1 &
for i in 1 2 3 4 5; do
    [ -f /tmp/udp41641.count ] && break
    sleep 1
done
`, routerTSIP, remoteSubnet, remoteRtrTSIP, routerWANIP, routerTSIP)
	mustExec(t, ctx, routerC, script)
}

func setupLANAndTSPeers(t *testing.T, ctx context.Context, lanSrvC, tsPeersC string) {
	t.Helper()
	mustExec(t, ctx, lanSrvC, fmt.Sprintf(`
set -e
ip route replace default via %s
p2p-probe tcp-echo %s:8445 </dev/null >/tmp/tcp8445.log 2>&1 &
p2p-probe tcp-echo %s:8080 </dev/null >/tmp/tcp8080.log 2>&1 &
sleep 1
`, routerLANIP, lanSrvIP, lanSrvIP))

	mustExec(t, ctx, tsPeersC, fmt.Sprintf(`
set -e
TS_DEV=$(ip -o -4 addr show | awk '$4 ~ /^100\.64\.200\./ {print $2; exit}')
ip addr add %s/24 dev "$TS_DEV" || true
ip addr add %s/24 dev "$TS_DEV" || true
ip route replace %s via %s dev "$TS_DEV"
p2p-probe tcp-echo %s:9001 </dev/null >/tmp/tcp9001.log 2>&1 &
sleep 1
`, remoteLANIP, adminLaptopIP, lanSubnet, routerTSIP, remoteRtrTSIP))
}

func dockerExecRunner(container string) tailscale.CmdRunner {
	return func(ctx context.Context, stdin string, name string, args ...string) ([]byte, error) {
		execArgs := append([]string{"exec", "-i", container, name}, args...)
		cmd := exec.CommandContext(ctx, "docker", execArgs...)
		if stdin != "" {
			cmd.Stdin = strings.NewReader(stdin)
		}
		return cmd.CombinedOutput()
	}
}

func readRouterUDPCount(t *testing.T, ctx context.Context, routerC string) int {
	t.Helper()
	raw := strings.TrimSpace(mustExec(t, ctx, routerC, "cat /tmp/udp41641.count"))
	n, err := strconv.Atoi(raw)
	if err != nil {
		t.Fatalf("parse router udp count %q: %v", raw, err)
	}
	return n
}

func assertTCPBlocked(t *testing.T, ctx context.Context, container, srcIP, dstAddr, desc string) {
	t.Helper()
	out, err := execIn(ctx, container, fmt.Sprintf("p2p-probe tcp-dial %s %s", srcIP, dstAddr))
	if err == nil {
		t.Fatalf("SECURITY VIOLATION [%s]: expected TCP %s -> %s BLOCKED, but succeeded! output=%s", desc, srcIP, dstAddr, out)
	}
}

func mustRun(t *testing.T, ctx context.Context, name string, args ...string) string {
	t.Helper()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("command %s %v failed: %v\nOutput:\n%s", name, args, err, string(out))
	}
	return string(out)
}

func execIn(ctx context.Context, container, script string) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", "exec", "-i", container, "/bin/sh", "-s")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func mustExec(t *testing.T, ctx context.Context, container, script string) string {
	t.Helper()
	out, err := execIn(ctx, container, script)
	if err != nil {
		t.Fatalf("exec in %s failed: %v\nScript:\n%s\nOutput:\n%s", container, err, script, out)
	}
	return out
}
