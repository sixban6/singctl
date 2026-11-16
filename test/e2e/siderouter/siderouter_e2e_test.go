package siderouter

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const (
	e2eImageTag = "singctl-siderouter-e2e:local"

	wanSubnet = "198.51.100.0/24"
	wanGW     = "198.51.100.254" // Docker bridge host IP (unused as default gw inside containers)
	wanSrvIP  = "198.51.100.10"
	wanCNIP   = "198.51.100.20"
	wanGlobIP = "198.51.100.30"
	mainWANIP = "198.51.100.2"

	lanSubnet = "192.168.100.0/24"
	lanBridge = "192.168.100.254"
	mainLANIP = "192.168.100.1"
	sideLANIP = "192.168.100.2"
	cliLANIP  = "192.168.100.100"
)

// TestSideRouterClusterE2E 构建 4 容器双网段真实路由集群：
//  1. wan-server  (198.51.100.10/.20/.30): 权威 DNS + 国内直连 HTTP 站 + 海外被墙 HTTP 站 + sing-box 代理服务端
//  2. main-router (WAN 198.51.100.2 MTU=1492, LAN 192.168.100.1): 状态防火墙 ct state invalid drop + WAN NAT + 阻断海外直连
//  3. side-router (单臂 LAN 192.168.100.2): 模拟恶劣宿主环境 (FORWARD DROP + rp_filter=1)，部署 singctl 验证旁路由模式
//  4. lan-client  (LAN 192.168.100.100): 默认网关与 DNS 指向 side-router (192.168.100.2)
func TestSideRouterClusterE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping Docker 4-node side-router cluster E2E in -short mode")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not installed, skipping E2E test")
	}
	if out, err := exec.CommandContext(t.Context(), "docker", "info").CombinedOutput(); err != nil {
		t.Skipf("docker daemon unavailable: %v (%s)", err, strings.TrimSpace(string(out)))
	}

	ctx := t.Context()
	repoRoot, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}

	// 1. 交叉编译 Linux 版 singctl 二进制
	workDir := t.TempDir()
	singctlBin := filepath.Join(workDir, "singctl")
	buildCmd := exec.CommandContext(ctx, "go", "build", "-o", singctlBin, "./cmd/singctl")
	buildCmd.Dir = repoRoot
	buildCmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+runtime.GOARCH)
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("cross-compile singctl for linux/%s failed: %v\n%s", runtime.GOARCH, err, string(out))
	}

	// 2. 构建/复用测试基础镜像（包含 iproute2 / nftables / iptables / curl / python3 / sing-box v1.14.x）
	ensureE2EImage(t, ctx, workDir)

	prefix := fmt.Sprintf("sc-sr-%d", time.Now().UnixNano()%1000000)
	wanNet := prefix + "-wan"
	lanNet := prefix + "-lan"
	wanC := prefix + "-wan-srv"
	mainC := prefix + "-main-rtr"
	sideC := prefix + "-side-rtr"
	cliC := prefix + "-lan-cli"

	t.Cleanup(func() {
		cleanCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		_ = exec.CommandContext(cleanCtx, "docker", "rm", "-f", cliC, sideC, mainC, wanC).Run()
		_ = exec.CommandContext(cleanCtx, "docker", "network", "rm", lanNet, wanNet).Run()
	})

	// 3. 创建双桥接隔离网段 (WAN + LAN)
	mustRun(t, ctx, "docker", "network", "create", "--subnet="+wanSubnet, "--gateway="+wanGW, wanNet)
	mustRun(t, ctx, "docker", "network", "create", "--subnet="+lanSubnet, "--gateway="+lanBridge, lanNet)

	// 4. 启动四台容器并挂载 singctl 二进制到 side-router（路由器容器开启 --privileged 以支持完整的内核 /proc/sys/net 读写与 TProxy 仿真）
	startIdleContainer := func(name, netName, ip string, extraArgs ...string) {
		args := []string{
			"run", "-d", "--name", name,
			"--hostname", name,
			"--privileged",
			"--sysctl", "net.ipv4.ip_forward=1",
			"--network", netName, "--ip", ip,
		}
		args = append(args, extraArgs...)
		args = append(args, e2eImageTag, "sleep", "3600")
		mustRun(t, ctx, "docker", args...)
	}

	startIdleContainer(wanC, wanNet, wanSrvIP)
	startIdleContainer(mainC, wanNet, mainWANIP)
	mustRun(t, ctx, "docker", "network", "connect", "--ip", mainLANIP, lanNet, mainC)

	startIdleContainer(sideC, lanNet, sideLANIP,
		"-v", singctlBin+":/usr/local/bin/singctl:ro",
	)
	startIdleContainer(cliC, lanNet, cliLANIP)

	// 5. 配置 wan-server: 绑定 .20/.30 辅助公网 IP + 启动权威 DNS + 直连/海外双 HTTP 站点 + 订阅与 sing-box 服务端
	setupWANServer(t, ctx, wanC)

	// 6. 配置 main-router: WAN 口模拟 PPPoE MTU=1492 + 状态防火墙 ct state invalid drop + WAN NAT + 封锁 198.51.100.30 直连
	setupMainRouter(t, ctx, mainC)

	// 7. 配置 lan-client: 默认网关与 DNS 全部指向旁路由 192.168.100.2
	mustExec(t, ctx, cliC, fmt.Sprintf(`
set -e
ip route replace default via %s
printf 'nameserver %s\noptions timeout:2 attempts:1\n' > /etc/resolv.conf
`, sideLANIP, sideLANIP))

	// 8. 配置 side-router 初始恶劣环境：模拟装有 Docker 导致 FORWARD DROP 且开启严格 rp_filter=1，网关暂指向 main-router
	mustExec(t, ctx, sideC, fmt.Sprintf(`
set -e
ip route replace default via %s
printf 'nameserver %s\n' > /etc/resolv.conf
iptables -P FORWARD DROP
sysctl -w net.ipv4.conf.all.rp_filter=1 >/dev/null
sysctl -w net.ipv4.conf.eth0.rp_filter=1 >/dev/null
`, mainLANIP, wanSrvIP))

	// 对照实验：未启用旁路由模式前，lan-client 因 FORWARD DROP 无法转发连接，curl 必然超时失败
	if out, err := execIn(ctx, cliC, fmt.Sprintf("curl -fsS --connect-timeout 2 --max-time 3 http://%s/", wanCNIP)); err == nil {
		t.Fatalf("control check expected curl to fail when FORWARD=DROP before side-router setup, but got: %s", out)
	}

	// 9. 在 side-router 上写入旁路由模式 singctl.yaml，生成配置并启动 singctl sb start
	sideCfgYAML := fmt.Sprintf(`subs:
  - name: "main"
    url: "http://%s:8080/sub"
    skip_tls_verify: true
    remove-emoji: true

github:
  mirror_url: "https://gh-proxy.com"

hy2:
  up: 20
  down: 200

dns:
  enabled: false

gateway:
  mode: "side"
  main_router_ip: "%s"

custom_rules:
  dns:
    - domain_suffix: ["example.com"]
      server: "dns_local"
  route:
    - action: "route"
      domain_suffix: ["cn.example.com"]
      outbound: "#DC"
    - action: "route"
      domain_suffix: ["global.example.com"]
      outbound: "Proxy"
`, wanSrvIP, mainLANIP)

	mustExec(t, ctx, sideC, fmt.Sprintf(`
set -e
mkdir -p /etc/singctl
cat << 'EOF' > /etc/singctl/singctl.yaml
%s
EOF
chmod 600 /etc/singctl/singctl.yaml
singctl sb gen -c /etc/singctl/singctl.yaml
singctl sb start -c /etc/singctl/singctl.yaml
`, sideCfgYAML))

	// 断言 1：table inet sing-box 与 table inet singctl-side 均真实存在（没有被脚本退出钩子误删）
	nftOut := mustExec(t, ctx, sideC, "nft list tables")
	if !strings.Contains(nftOut, "inet sing-box") {
		t.Fatalf("expected 'inet sing-box' table to remain active after sb start, got:\n%s", nftOut)
	}
	if !strings.Contains(nftOut, "inet singctl-side") {
		t.Fatalf("expected 'inet singctl-side' table to be active in side mode, got:\n%s", nftOut)
	}

	// 断言 2：lan-client 可以正常解析并 ping 通域名
	mustExec(t, ctx, cliC, "ping -c 2 -W 2 cn.example.com")

	// 断言 3：lan-client 访问国内直连站点 cn.example.com (#DC) 不卡死且返回 200
	cnBody := strings.TrimSpace(mustExec(t, ctx, cliC, "curl -fsS --connect-timeout 4 --max-time 6 http://cn.example.com/"))
	if cnBody != "CN_DIRECT_OK" {
		t.Fatalf("expected CN_DIRECT_OK from cn.example.com, got %q", cnBody)
	}

	// 断言 4：lan-client 访问被 main-router 封锁直连的海外站点 global.example.com，经旁路由 sing-box 代理隧道返回 200
	globBody := strings.TrimSpace(mustExec(t, ctx, cliC, "curl -fsS --connect-timeout 4 --max-time 6 http://global.example.com/"))
	if globBody != "GLOBAL_PROXY_OK" {
		t.Fatalf("expected GLOBAL_PROXY_OK via proxy from global.example.com, got %q", globBody)
	}

	// 断言 5：在 main-router WAN 口 MTU=1492 限制下，128KB 大载荷响应（直连 + 代理）均无分片死锁且字节数精确匹配
	for _, u := range []string{"http://cn.example.com/large", "http://global.example.com/large"} {
		sz := strings.TrimSpace(mustExec(t, ctx, cliC, fmt.Sprintf("curl -fsS --connect-timeout 4 --max-time 8 %s | wc -c", u)))
		if sz != "131072" {
			t.Fatalf("expected 131072 bytes from %s under MTU 1492, got %q", u, sz)
		}
	}

	// 断言 6：验证真实源 IP 审计保留（发起慢速连接期间读取 Clash API /connections，客户端源 IP 必须是 192.168.100.100 而非旁路由 192.168.100.2）
	verifyClientSourceIPPreserved(t, ctx, cliC, sideC)

	// 断言 7：模拟 DHCP 污染导致旁路由自身默认路由丢失，验证 singctl sb restart 自动根据 main_router_ip 自愈恢复
	mustExec(t, ctx, sideC, `
set -e
ip route del default || true
singctl sb restart -c /etc/singctl/singctl.yaml
`)
	routeAfterRestart := mustExec(t, ctx, sideC, "ip route show default")
	if !strings.Contains(routeAfterRestart, mainLANIP) {
		t.Fatalf("expected default route to self-heal to %s, got: %s", mainLANIP, routeAfterRestart)
	}
	globAfterHeal := strings.TrimSpace(mustExec(t, ctx, cliC, "curl -fsS --connect-timeout 4 --max-time 6 http://global.example.com/"))
	if globAfterHeal != "GLOBAL_PROXY_OK" {
		t.Fatalf("expected proxy connectivity after route self-heal, got %q", globAfterHeal)
	}

	// 断言 8：执行 singctl sb stop 后，旁路由专属表 singctl-side 干净卸载，且 sysctl rp_filter 恢复原值
	mustExec(t, ctx, sideC, "singctl sb stop -c /etc/singctl/singctl.yaml")
	tablesAfterStop := mustExec(t, ctx, sideC, "nft list tables")
	if strings.Contains(tablesAfterStop, "inet singctl-side") {
		t.Fatalf("expected 'inet singctl-side' to be removed on sb stop, got:\n%s", tablesAfterStop)
	}
	rpVal := strings.TrimSpace(mustExec(t, ctx, sideC, "sysctl -n net.ipv4.conf.eth0.rp_filter"))
	if rpVal != "1" {
		t.Fatalf("expected eth0 rp_filter to be restored to 1 after sb stop, got %q", rpVal)
	}
}

func ensureE2EImage(t *testing.T, ctx context.Context, workDir string) {
	t.Helper()
	if exec.CommandContext(ctx, "docker", "image", "inspect", e2eImageTag).Run() == nil {
		return
	}

	sbArch := "amd64"
	if runtime.GOARCH == "arm64" {
		sbArch = "arm64"
	}
	dockerfile := fmt.Sprintf(`FROM debian:bookworm-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && apt-get install -y --no-install-recommends \
    ca-certificates curl iproute2 nftables iptables iputils-ping procps python3 net-tools \
    && rm -rf /var/lib/apt/lists/*
RUN SB_VER="1.14.4" && \
    (curl -fsSL --connect-timeout 10 "https://github.com/SagerNet/sing-box/releases/download/v${SB_VER}/sing-box-${SB_VER}-linux-%s.tar.gz" -o /tmp/sb.tgz || \
     curl -fsSL --connect-timeout 15 "https://gh-proxy.com/https://github.com/SagerNet/sing-box/releases/download/v${SB_VER}/sing-box-${SB_VER}-linux-%s.tar.gz" -o /tmp/sb.tgz) && \
    tar -xzf /tmp/sb.tgz -C /tmp && \
    install -m 0755 /tmp/sing-box-*/sing-box /usr/bin/sing-box && \
    ln -sf /usr/bin/sing-box /usr/local/bin/sing-box && \
    rm -rf /tmp/sb.tgz /tmp/sing-box-*
`, sbArch, sbArch)

	dfPath := filepath.Join(workDir, "Dockerfile.e2e")
	if err := os.WriteFile(dfPath, []byte(dockerfile), 0644); err != nil {
		t.Fatalf("write Dockerfile.e2e: %v", err)
	}
	mustRun(t, ctx, "docker", "build", "-t", e2eImageTag, "-f", dfPath, workDir)
}

func setupWANServer(t *testing.T, ctx context.Context, wanC string) {
	t.Helper()
	// Shadowsocks 2022 / AEAD 测试节点（标准假密码，仅容器内闭环通信）
	ssMethod := "aes-128-gcm"
	ssPass := "singctl-e2e-pass"
	userinfo := base64.RawURLEncoding.EncodeToString([]byte(ssMethod + ":" + ssPass))
	ssURI := fmt.Sprintf("ss://%s@%s:8388#TestWANNode\n", userinfo, wanSrvIP)
	subPayload := base64.StdEncoding.EncodeToString([]byte(ssURI))

	script := fmt.Sprintf(`
set -e
ip addr add %s/24 dev eth0 || true
ip addr add %s/24 dev eth0 || true
ip route replace %s via %s

cat << 'PYEOF' > /tmp/wan_services.py
import socket, struct, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

RECORDS = {
    b"cn.example.com.": "%s",
    b"global.example.com.": "%s",
    b"sub.example.com.": "%s",
}

def build_dns_reply(data):
    tid = data[:2]
    # Parse QNAME
    idx = 12
    labels = []
    while idx < len(data) and data[idx] != 0:
        ln = data[idx]
        idx += 1
        labels.append(data[idx:idx+ln])
        idx += ln
    qname_end = idx + 1
    qtype, qclass = struct.unpack("!HH", data[qname_end:qname_end+4])
    question = data[12:qname_end+4]
    fqdn = (b".".join(labels) + b".").lower()
    ip = RECORDS.get(fqdn)
    if ip and qtype == 1:  # A record
        header = tid + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0)
        ans = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(ip)
        return header + question + ans
    # Empty NOERROR for AAAA or other types
    header = tid + struct.pack("!HHHHH", 0x8180, 1, 0, 0, 0)
    return header + question

def serve_udp_dns():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", 53))
    while True:
        data, addr = s.recvfrom(2048)
        try:
            s.sendto(build_dns_reply(data), addr)
        except Exception:
            pass

def make_handler(body_text, sub_data=None):
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/sub" and sub_data is not None:
                raw = sub_data.encode()
            elif self.path == "/large":
                raw = (b"X" * 1024) * 128
            elif self.path == "/hold":
                import time
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"HOLD_START\n")
                self.wfile.flush()
                time.sleep(2.5)
                self.wfile.write(b"HOLD_DONE\n")
                return
            else:
                raw = body_text.encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
        def log_message(self, *args):
            pass
    return H

threading.Thread(target=serve_udp_dns, daemon=True).start()
threading.Thread(target=lambda: HTTPServer(("%s", 8080), make_handler("SUB_ROOT", %q)).serve_forever(), daemon=True).start()
threading.Thread(target=lambda: HTTPServer(("%s", 80), make_handler("CN_DIRECT_OK")).serve_forever(), daemon=True).start()
HTTPServer(("%s", 80), make_handler("GLOBAL_PROXY_OK")).serve_forever()
PYEOF
nohup python3 /tmp/wan_services.py >/tmp/wan_services.log 2>&1 &

mkdir -p /etc/sing-box
cat << 'SBEOF' > /etc/sing-box/server.json
{
  "log": {"level": "warn"},
  "inbounds": [
    {
      "type": "shadowsocks",
      "tag": "ss-in",
      "listen": "%s",
      "listen_port": 8388,
      "method": "%s",
      "password": "%s"
    }
  ],
  "outbounds": [
    {"type": "direct", "tag": "direct"}
  ]
}
SBEOF
nohup sing-box run -c /etc/sing-box/server.json >/tmp/wan_singbox.log 2>&1 &
sleep 1
`, wanCNIP, wanGlobIP, lanSubnet, mainWANIP,
		wanCNIP, wanGlobIP, wanSrvIP,
		wanSrvIP, subPayload, wanCNIP, wanGlobIP,
		wanSrvIP, ssMethod, ssPass)

	mustExec(t, ctx, wanC, script)
}

func setupMainRouter(t *testing.T, ctx context.Context, mainC string) {
	t.Helper()
	// 找出连接 WAN 网段的网卡并设 MTU=1492，同时开启严格 ct state invalid drop 与 GFW 直连阻断 (198.51.100.30)
	script := fmt.Sprintf(`
set -e
WAN_IF=$(ip -o -4 addr show | awk '$4 ~ /^198\.51\.100\./ {print $2; exit}')
LAN_IF=$(ip -o -4 addr show | awk '$4 ~ /^192\.168\.100\./ {print $2; exit}')
ip link set dev "$WAN_IF" mtu 1492
sysctl -w net.ipv4.ip_forward=1 >/dev/null
sysctl -w net.ipv4.conf.all.send_redirects=0 >/dev/null
sysctl -w net.ipv4.conf."$LAN_IF".send_redirects=0 >/dev/null

cat << NFTEOF > /tmp/main-router.nft
flush ruleset
table inet main_fw {
    chain forward {
        type filter hook forward priority filter; policy accept;
        # 家用主路由标准状态防火墙：遇到非对称路由半连接直接丢弃！
        ct state invalid drop
        # 模拟海外站点 198.51.100.30 被直连阻断，强制必须走 198.51.100.10:8388 代理节点才能访问
        ip daddr %s drop
    }
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        oifname "$WAN_IF" masquerade
    }
}
NFTEOF
nft -f /tmp/main-router.nft
`, wanGlobIP)
	mustExec(t, ctx, mainC, script)
}

func verifyClientSourceIPPreserved(t *testing.T, ctx context.Context, cliC, sideC string) {
	t.Helper()
	// 在 lan-client 后台发起一个保持 2.5 秒的 HTTP 连接，同时在 side-router 查询 Clash API /connections
	errCh := make(chan error, 1)
	go func() {
		_, err := execIn(ctx, cliC, "curl -fsS --max-time 6 http://global.example.com/hold >/dev/null")
		errCh <- err
	}()

	time.Sleep(700 * time.Millisecond)

	rawCfg := mustExec(t, ctx, sideC, "cat /etc/sing-box/config.json")
	var doc struct {
		Experimental struct {
			ClashAPI struct {
				ExternalController string `json:"external_controller"`
				Secret             string `json:"secret"`
			} `json:"clash_api"`
		} `json:"experimental"`
	}
	if err := json.Unmarshal([]byte(rawCfg), &doc); err != nil {
		t.Fatalf("parse side-router config.json: %v", err)
	}
	ctrlAddr := doc.Experimental.ClashAPI.ExternalController
	secret := doc.Experimental.ClashAPI.Secret

	connJSON := mustExec(t, ctx, sideC, fmt.Sprintf(
		`curl -fsS -H "Authorization: Bearer %s" "http://%s/connections"`,
		secret, ctrlAddr,
	))
	if err := <-errCh; err != nil {
		t.Fatalf("hold request failed: %v", err)
	}

	var snap struct {
		Connections []struct {
			Metadata struct {
				SourceIP string `json:"sourceIP"`
				Host     string `json:"host"`
			} `json:"metadata"`
		} `json:"connections"`
	}
	if err := json.Unmarshal([]byte(connJSON), &snap); err != nil {
		t.Fatalf("decode /connections: %v (%s)", err, connJSON)
	}

	foundRealClientIP := false
	for _, c := range snap.Connections {
		if c.Metadata.SourceIP == cliLANIP {
			foundRealClientIP = true
			break
		}
	}
	if !foundRealClientIP {
		t.Fatalf("expected Clash /connections to record real LAN client IP %s (not SNATed to %s), got: %s",
			cliLANIP, sideLANIP, connJSON)
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
	cmd := exec.CommandContext(ctx, "docker", "exec", "-i", container, "sh", "-s")
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
