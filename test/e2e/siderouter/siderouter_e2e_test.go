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
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	e2eImageTag = "singctl-openwrt24-e2e:local"

	wanSubnet = "198.51.100.0/24"
	wanGW     = "198.51.100.254" // Docker bridge host IP (unused as default gw inside containers)
	wanSrvIP  = "198.51.100.10"
	wanCNIP   = "198.51.100.20"
	wanGlobIP = "198.51.100.30"
	aliDoHIP  = "223.5.5.5"
	googleDoH = "8.8.8.8"
	mainWANIP = "198.51.100.2"

	lanSubnet = "192.168.100.0/24"
	lanBridge = "192.168.100.254"
	mainLANIP = "192.168.100.1"
	sideLANIP = "192.168.100.2"
	cliLANIP  = "192.168.100.100"
)

// TestSideRouterClusterE2E 使用官方原生 OpenWrt 24.10 (openwrt/rootfs) 构建 4 容器双网段真实路由集群：
//  1. wan-server  (OpenWrt 24.10, 198.51.100.10/.20/.30 + 223.5.5.5 + 8.8.8.8):
//     权威 UDP/DoH DNS (223.5.5.5 & 8.8.8.8) + 国内直连站 + 海外被墙站 + sing-box 代理服务端
//  2. main-router (OpenWrt 24.10, WAN 198.51.100.2 MTU=1492, LAN 192.168.100.1):
//     状态防火墙 ct state invalid drop + WAN NAT + 阻断海外 IP (198.51.100.30 / 8.8.8.8) 直连
//     + 故意将主路由 dnsmasq 上游错误指回旁路由 (192.168.100.2) 验证零死循环
//  3. side-router (OpenWrt 24.10, 单臂 LAN 192.168.100.2):
//     真实运行 OpenWrt dnsmasq (:53 占用) + 真实 fw4 防火墙 (默认 input/forward drop)
//     + 真实 AdGuard Home (127.0.0.1:5353) + 真实 sing-box (:7895 TProxy)
//     + 初始故意将 resolv.conf.auto 污染为旁路由自身 IP (192.168.100.2) 且开启严格 rp_filter=1
//  4. lan-client  (OpenWrt 24.10, LAN 192.168.100.100):
//     默认网关与 DNS 全部指向旁路由 (192.168.100.2)
func TestSideRouterClusterE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping OpenWrt 4-node side-router cluster E2E in -short mode")
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

	// 1. 交叉编译 Linux 版 singctl 二进制与模拟外网权威 DoH/HTTP 服务的 wan-helper 二进制
	workDir := t.TempDir()
	singctlBin := filepath.Join(workDir, "singctl")
	buildCmd := exec.CommandContext(ctx, "go", "build", "-o", singctlBin, "./cmd/singctl")
	buildCmd.Dir = repoRoot
	buildCmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+runtime.GOARCH)
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("cross-compile singctl for linux/%s failed: %v\n%s", runtime.GOARCH, err, string(out))
	}

	wanHelperBin := buildWANHelperBinary(t, ctx, workDir)

	// 2. 构建/复用官方 OpenWrt 24.10 测试镜像（含原生 fw4 / dnsmasq / uci / nft / ujail / curl / sing-box / AdGuardHome）
	ensureOpenWrtE2EImage(t, ctx, workDir)

	prefix := fmt.Sprintf("sc-owrt-%d", time.Now().UnixNano()%1000000)
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

	// 4. 启动四台官方 OpenWrt 24.10 容器
	startOpenWrtContainer := func(name, netName, ip string, extraArgs ...string) {
		args := []string{
			"run", "-d", "--name", name,
			"--hostname", name,
			"--privileged",
			"--sysctl", "net.ipv4.ip_forward=1",
			"--network", netName, "--ip", ip,
		}
		args = append(args, extraArgs...)
		args = append(args, e2eImageTag, "/bin/sh", "-c", "mkdir -p /var/run /var/lock /tmp/resolv.conf.d && exec sleep 3600")
		mustRun(t, ctx, "docker", args...)
	}

	startOpenWrtContainer(wanC, wanNet, wanSrvIP,
		"-v", wanHelperBin+":/usr/bin/wan-helper:ro",
	)
	startOpenWrtContainer(mainC, wanNet, mainWANIP)
	mustRun(t, ctx, "docker", "network", "connect", "--ip", mainLANIP, lanNet, mainC)

	startOpenWrtContainer(sideC, lanNet, sideLANIP,
		"-v", singctlBin+":/usr/bin/singctl:ro",
	)
	startOpenWrtContainer(cliC, lanNet, cliLANIP)

	// 5. 配置 wan-server: 挂载 .20/.30 + 223.5.5.5 + 8.8.8.8，启动 DoH/UDP DNS + HTTP 站点 + sing-box 服务端，并导出测试根证书
	caCertPEM := setupWANServer(t, ctx, wanC)

	// 6. 配置 main-router (OpenWrt): WAN MTU=1492 + ct state invalid drop + 封锁 198.51.100.30 与 8.8.8.8 直连
	//    同时故意启动主路由 dnsmasq 并将上游错误指向旁路由 192.168.100.2，验证绝不产生 DNS 死循环
	setupMainRouter(t, ctx, mainC)

	// 7. 配置 lan-client (OpenWrt): 默认网关与 DNS 全部指向旁路由 192.168.100.2
	mustExec(t, ctx, cliC, fmt.Sprintf(`
set -e
ip route replace default via %s
printf 'nameserver %s\noptions timeout:2 attempts:2\n' > /etc/resolv.conf
`, sideLANIP, sideLANIP))

	// 8. 配置 side-router (真实 OpenWrt 24.10 恶劣环境):
	//    - 注入测试根证书以支持 AdGuardHome -> https://223.5.5.5/dns-query 与 sing-box -> https://8.8.8.8/dns-query 真实 TLS 校验
	//    - 加载真实 OpenWrt fw4 防火墙表（默认 input policy drop / forward policy drop）
	//    - 故意在 resolv.conf.auto 写入自环地址 192.168.100.2（模拟主路由 DHCP 静态租约污染）
	//    - 真实启动 OpenWrt dnsmasq 独占绑定 0.0.0.0:53（复现此前 EADDRINUSE 必挂场景！）
	//    - 开启严格 rp_filter=1，并启用 net.ipv4.conf.all.src_valid_mark=1（Tailscale/WireGuard 策略路由常见配置）
	mustExec(t, ctx, sideC, fmt.Sprintf(`
set -e
cat << 'CAEOF' >> /etc/ssl/certs/ca-certificates.crt
%s
CAEOF
ip route replace default via %s
printf 'nameserver 127.0.0.1\n' > /etc/resolv.conf
printf 'nameserver %s\n' > /tmp/resolv.conf.d/resolv.conf.auto
/usr/sbin/dnsmasq --port=53 --resolv-file=/tmp/resolv.conf.d/resolv.conf.auto --pid-file=/var/run/dnsmasq.pid
/sbin/fw4 print 2>/dev/null | nft -f -
sysctl -w net.ipv4.conf.all.rp_filter=1 >/dev/null
sysctl -w net.ipv4.conf.eth0.rp_filter=1 >/dev/null
sysctl -w net.ipv4.conf.all.src_valid_mark=1 >/dev/null
`, caCertPEM, mainLANIP, sideLANIP))

	// 确认 OpenWrt dnsmasq 确实已独占绑定 0.0.0.0:53 (:0035)
	udpTable := mustExec(t, ctx, sideC, "cat /proc/net/udp")
	if !strings.Contains(strings.ToUpper(udpTable), "00000000:0035") {
		t.Fatalf("expected OpenWrt dnsmasq to bind 0.0.0.0:53 before singctl start, got /proc/net/udp:\n%s", udpTable)
	}

	// 对照实验：未启用旁路由模式前，lan-client 因 fw4 forward policy drop 无法穿透访问外网，且 DNS 因自环无法解析
	if out, err := execIn(ctx, cliC, fmt.Sprintf("curl -fsS --connect-timeout 2 --max-time 3 http://%s/", wanCNIP)); err == nil {
		t.Fatalf("control check expected curl to fail under fw4 forward drop before side-router setup, got: %s", out)
	}

	// 9. 在 OpenWrt side-router 上启用完整生产链路：AdGuard Home (dns.enabled: true) + 旁路由模式 (gateway.mode: side)
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
  enabled: true
  dns_port: 5353
  web_port: 3000

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
singctl dns install --non-interactive -c /etc/singctl/singctl.yaml
singctl sb gen -c /etc/singctl/singctl.yaml
singctl sb start -c /etc/singctl/singctl.yaml
`, sideCfgYAML))

	// 断言 1：验证 OpenWrt 旁路由防火墙表状态——由于 dnsmasq 已监听 :53，singctl-side 绝不生成 dport 53 tproxy 抢占规则
	nftSide := mustExec(t, ctx, sideC, "nft list table inet singctl-side")
	if strings.Contains(nftSide, "dport 53") {
		t.Fatalf("OpenWrt side-router with running dnsmasq must NOT hijack :53 in singctl-side, got:\n%s", nftSide)
	}
	nftTables := mustExec(t, ctx, sideC, "nft list tables")
	for _, wantTbl := range []string{"inet fw4", "inet sing-box", "inet singctl-side"} {
		if !strings.Contains(nftTables, wantTbl) {
			t.Fatalf("expected nft table %q to be active, got:\n%s", wantTbl, nftTables)
		}
	}

	// 断言 2：验证 sing-box dns_local 已真实指向本机 AdGuard Home (127.0.0.1:5353)，且 AdGuardHome 已关闭私网 PTR 防回环
	sbCfgRaw := mustExec(t, ctx, sideC, "cat /etc/sing-box/config.json")
	if !strings.Contains(sbCfgRaw, `"server_port": 5353`) && !strings.Contains(sbCfgRaw, `"server_port":5353`) {
		t.Fatalf("expected sing-box dns_local to point to AdGuard Home 127.0.0.1:5353, got dns snippet:\n%.600s", sbCfgRaw)
	}
	aghCfgRaw := mustExec(t, ctx, sideC, "cat /etc/AdGuardHome/AdGuardHome.yaml")
	if !strings.Contains(aghCfgRaw, "use_private_ptr_resolvers: false") {
		t.Fatalf("expected AdGuardHome.yaml to set use_private_ptr_resolvers: false in side-router mode, got:\n%s", aghCfgRaw)
	}

	// 断言 3（核心回归验证）：局域网终端 lan-client 执行 ping 国内域名与海外被墙域名，均能正常拿到解析地址并连通！
	pingCN := mustExec(t, ctx, cliC, "ping -c 2 -W 3 cn.example.com")
	if !strings.Contains(pingCN, wanCNIP) {
		t.Fatalf("expected lan-client ping cn.example.com to resolve %s, got:\n%s", wanCNIP, pingCN)
	}
	// 海外域名 global.example.com：DNS 通过 dns_proxy (8.8.8.8 DoH 经代理隧道) 解析返回 198.51.100.30
	nsGlob := mustExec(t, ctx, cliC, "nslookup global.example.com "+sideLANIP+" || ping -c 1 -W 2 global.example.com || true")
	if !strings.Contains(nsGlob, wanGlobIP) {
		t.Fatalf("expected lan-client to resolve global.example.com -> %s via side-router, got:\n%s", wanGlobIP, nsGlob)
	}

	// 断言 4：在旁路由本机 (side-router) 终端直接执行 ping 域名，以及显式向私网上级网关 (192.168.100.1:53) 发起 DNS 查询，
	// 均经 output 链 (mark 0x2 -> table 101) 被本机 sing-box 透明接管秒解，绝不因 table 100 throw 逃逸外泄或与主路由死循环！
	sideSelfPing := mustExec(t, ctx, sideC, "ping -c 2 -W 3 cn.example.com")
	if !strings.Contains(sideSelfPing, wanCNIP) {
		t.Fatalf("expected side-router self ping cn.example.com to resolve %s, got:\n%s", wanCNIP, sideSelfPing)
	}
	privateGWQuery := mustExec(t, ctx, sideC, "nslookup cn.example.com "+mainLANIP)
	if !strings.Contains(privateGWQuery, wanCNIP) {
		t.Fatalf("expected direct query to private gateway %s:53 to be intercepted by sing-box (not leaked via table 100 throw), got:\n%s", mainLANIP, privateGWQuery)
	}

	// 断言 5：验证完整闭环 `lan-client -> dnsmasq -> sing-box -> AdGuard Home -> 223.5.5.5 DoH` 真实命中（非绕过或直查）！
	dohStatsRaw := strings.TrimSpace(mustExec(t, ctx, wanC, fmt.Sprintf("curl -fsS http://%s:8080/doh-hits", wanSrvIP)))
	var dohStats struct {
		AliHits int64 `json:"aliHits"`
	}
	if err := json.Unmarshal([]byte(dohStatsRaw), &dohStats); err != nil {
		t.Fatalf("parse doh-hits %q: %v", dohStatsRaw, err)
	}
	if dohStats.AliHits < 1 {
		t.Fatalf("expected AdGuard Home to query https://223.5.5.5/dns-query at least once, got aliHits=%d", dohStats.AliHits)
	}

	// 断言 6：lan-client 访问国内直连站点 (#DC) 与被主路由封锁直连的海外站点 (Proxy) 均返回 200
	cnBody := strings.TrimSpace(mustExec(t, ctx, cliC, "curl -fsS --connect-timeout 4 --max-time 6 http://cn.example.com/"))
	if cnBody != "CN_DIRECT_OK" {
		t.Fatalf("expected CN_DIRECT_OK from cn.example.com, got %q", cnBody)
	}
	globBody := strings.TrimSpace(mustExec(t, ctx, cliC, "curl -fsS --connect-timeout 4 --max-time 6 http://global.example.com/"))
	if globBody != "GLOBAL_PROXY_OK" {
		t.Fatalf("expected GLOBAL_PROXY_OK via proxy from global.example.com, got %q", globBody)
	}

	// 断言 7：在 main-router WAN 口 MTU=1492 + ct state invalid drop 限制下，128KB 大载荷响应（直连 + 代理）无分片卡死
	for _, u := range []string{"http://cn.example.com/large", "http://global.example.com/large"} {
		sz := strings.TrimSpace(mustExec(t, ctx, cliC, fmt.Sprintf("curl -fsS --connect-timeout 4 --max-time 8 %s | wc -c", u)))
		if n, convErr := strconv.Atoi(strings.TrimSpace(sz)); convErr != nil || n != 131072 {
			t.Fatalf("expected 131072 bytes from %s under MTU 1492, got %q", u, sz)
		}
	}

	// 断言 8：验证真实源 IP 审计保留（Clash API /connections 中记录的客户端源 IP 必须是 192.168.100.100 而非旁路由 192.168.100.2）
	verifyClientSourceIPPreserved(t, ctx, cliC, sideC)

	// 断言 9：模拟 OpenWrt 执行防火墙重载 (`/sbin/fw4 print | nft -f -`)，验证 /usr/share/nftables.d/chain-pre/ 持久化规则自动生效不中断！
	mustExec(t, ctx, sideC, "/sbin/fw4 print 2>/dev/null | nft -f -")
	cnAfterFW4Reload := strings.TrimSpace(mustExec(t, ctx, cliC, "curl -fsS --connect-timeout 4 --max-time 6 http://cn.example.com/"))
	globAfterFW4Reload := strings.TrimSpace(mustExec(t, ctx, cliC, "curl -fsS --connect-timeout 4 --max-time 6 http://global.example.com/"))
	if cnAfterFW4Reload != "CN_DIRECT_OK" || globAfterFW4Reload != "GLOBAL_PROXY_OK" {
		t.Fatalf("expected traffic to survive OpenWrt fw4 reload, got cn=%q glob=%q", cnAfterFW4Reload, globAfterFW4Reload)
	}

	// 断言 10：模拟 DHCP 污染导致旁路由默认路由丢失，验证 singctl sb restart 自动根据 main_router_ip 自愈恢复
	mustExec(t, ctx, sideC, `
set -e
ip route del default || true
singctl sb restart -c /etc/singctl/singctl.yaml
`)
	routeAfterRestart := mustExec(t, ctx, sideC, "ip route show default")
	if !strings.Contains(routeAfterRestart, mainLANIP) {
		t.Fatalf("expected default route to self-heal to %s, got: %s", mainLANIP, routeAfterRestart)
	}
	if got := strings.TrimSpace(mustExec(t, ctx, cliC, "curl -fsS --connect-timeout 4 --max-time 6 http://global.example.com/")); got != "GLOBAL_PROXY_OK" {
		t.Fatalf("expected proxy connectivity after route self-heal, got %q", got)
	}

	// 断言 11：执行 singctl sb stop 后，singctl-side 表、fw4 include 文件干净卸载，且 sysctl rp_filter 与原始 resolv.conf.auto 完整还原
	mustExec(t, ctx, sideC, "singctl sb stop -c /etc/singctl/singctl.yaml")
	tablesAfterStop := mustExec(t, ctx, sideC, "nft list tables")
	if strings.Contains(tablesAfterStop, "inet singctl-side") {
		t.Fatalf("expected 'inet singctl-side' to be removed on sb stop, got:\n%s", tablesAfterStop)
	}
	incCheck := strings.TrimSpace(mustExec(t, ctx, sideC, "ls /usr/share/nftables.d/chain-pre/*/singctl-side.nft 2>/dev/null || echo CLEAN"))
	if incCheck != "CLEAN" {
		t.Fatalf("expected fw4 include files to be removed on sb stop, got: %s", incCheck)
	}
	rpVal := strings.TrimSpace(mustExec(t, ctx, sideC, "sysctl -n net.ipv4.conf.eth0.rp_filter"))
	if rpVal != "1" {
		t.Fatalf("expected eth0 rp_filter to be restored to 1 after sb stop, got %q", rpVal)
	}
	restoredResolv := strings.TrimSpace(mustExec(t, ctx, sideC, "cat /tmp/resolv.conf.d/resolv.conf.auto"))
	if restoredResolv != "nameserver "+sideLANIP {
		t.Fatalf("expected resolv.conf.auto to restore original content, got %q", restoredResolv)
	}
	ipRulesAfterStop := mustExec(t, ctx, sideC, "ip rule show")
	if strings.Contains(ipRulesAfterStop, "lookup 100") || strings.Contains(ipRulesAfterStop, "lookup 101") {
		t.Fatalf("expected ip rule tables 100 & 101 to be cleaned on sb stop, got:\n%s", ipRulesAfterStop)
	}
}

func ensureOpenWrtE2EImage(t *testing.T, ctx context.Context, workDir string) {
	t.Helper()
	if exec.CommandContext(ctx, "docker", "image", "inspect", e2eImageTag).Run() == nil {
		return
	}

	owrtTag := "x86-64-openwrt-24.10"
	sbArch := "amd64"
	aghArch := "amd64"
	if runtime.GOARCH == "arm64" {
		owrtTag = "armsr-armv8-openwrt-24.10"
		sbArch = "arm64"
		aghArch = "arm64"
	}

	dockerfile := fmt.Sprintf(`FROM debian:bookworm-slim AS downloader
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && apt-get install -y --no-install-recommends ca-certificates curl tar && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /out && \
    SB_VER="1.14.4" && \
    (curl -fsSL --connect-timeout 10 "https://github.com/SagerNet/sing-box/releases/download/v${SB_VER}/sing-box-${SB_VER}-linux-%s-musl.tar.gz" -o /tmp/sb.tgz || \
     curl -fsSL --connect-timeout 15 "https://gh-proxy.com/https://github.com/SagerNet/sing-box/releases/download/v${SB_VER}/sing-box-${SB_VER}-linux-%s-musl.tar.gz" -o /tmp/sb.tgz) && \
    tar -xzf /tmp/sb.tgz -C /tmp && \
    install -m 0755 /tmp/sing-box-*/sing-box /out/sing-box && \
    AGH_VER="v0.107.57" && \
    (curl -fsSL --connect-timeout 10 "https://github.com/AdguardTeam/AdGuardHome/releases/download/${AGH_VER}/AdGuardHome_linux_%s.tar.gz" -o /tmp/agh.tgz || \
     curl -fsSL --connect-timeout 15 "https://gh-proxy.com/https://github.com/AdguardTeam/AdGuardHome/releases/download/${AGH_VER}/AdGuardHome_linux_%s.tar.gz" -o /tmp/agh.tgz) && \
    tar -xzf /tmp/agh.tgz -C /tmp && \
    install -m 0755 /tmp/AdGuardHome/AdGuardHome /out/AdGuardHome

FROM openwrt/rootfs:%s
RUN mkdir -p /var/lock /var/run /tmp/resolv.conf.d && \
    opkg update && \
    opkg install curl ca-bundle && \
    rm -rf /tmp/opkg-lists
COPY --from=downloader /out/sing-box /usr/bin/sing-box
COPY --from=downloader /out/AdGuardHome /usr/bin/AdGuardHome
`, sbArch, sbArch, aghArch, aghArch, owrtTag)

	dfPath := filepath.Join(workDir, "Dockerfile.openwrt-e2e")
	if err := os.WriteFile(dfPath, []byte(dockerfile), 0644); err != nil {
		t.Fatalf("write Dockerfile.openwrt-e2e: %v", err)
	}
	mustRun(t, ctx, "docker", "build", "-t", e2eImageTag, "-f", dfPath, workDir)
}

func buildWANHelperBinary(t *testing.T, ctx context.Context, workDir string) string {
	t.Helper()
	helperDir := filepath.Join(workDir, "wanhelper")
	if err := os.MkdirAll(helperDir, 0755); err != nil {
		t.Fatalf("mkdir wanhelper: %v", err)
	}

	src := `package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

var (
	aliHits    atomic.Int64
	googleHits atomic.Int64
	records    = map[string][4]byte{
		"cn.example.com.":     {198, 51, 100, 20},
		"global.example.com.": {198, 51, 100, 30},
		"sub.example.com.":    {198, 51, 100, 10},
		"localhost.":          {127, 0, 0, 1},
	}
)

func buildDNSReply(req []byte) []byte {
	if len(req) < 12 {
		return nil
	}
	idx := 12
	var labels []string
	for idx < len(req) && req[idx] != 0 {
		l := int(req[idx])
		idx++
		if idx+l > len(req) {
			return nil
		}
		labels = append(labels, strings.ToLower(string(req[idx:idx+l])))
		idx += l
	}
	if idx+5 > len(req) {
		return nil
	}
	qnameEnd := idx + 1
	qtype := binary.BigEndian.Uint16(req[qnameEnd : qnameEnd+2])
	question := req[12 : qnameEnd+4]
	fqdn := strings.Join(labels, ".") + "."

	resp := make([]byte, 12, 128)
	copy(resp[0:2], req[0:2])
	resp[2] = 0x81
	resp[3] = 0x80
	binary.BigEndian.PutUint16(resp[4:6], 1)

	if ip, ok := records[fqdn]; ok && qtype == 1 {
		binary.BigEndian.PutUint16(resp[6:8], 1)
		resp = append(resp, question...)
		ans := []byte{0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04}
		ans = append(ans, ip[:]...)
		resp = append(resp, ans...)
		return resp
	}
	resp = append(resp, question...)
	return resp
}

func genCerts(caOutPath string) tls.Certificate {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "SingCtl E2E Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	_ = os.WriteFile(caOutPath, caPEM, 0644)

	srvKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	srvTpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "SingCtl E2E DoH"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{
			net.ParseIP("223.5.5.5"),
			net.ParseIP("223.6.6.6"),
			net.ParseIP("1.12.12.12"),
			net.ParseIP("8.8.8.8"),
			net.ParseIP("198.51.100.10"),
		},
		DNSNames: []string{"dns.alidns.com", "dns.google"},
	}
	srvDER, _ := x509.CreateCertificate(rand.Reader, srvTpl, caTpl, &srvKey.PublicKey, caKey)
	srvPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srvDER})
	keyDER, _ := x509.MarshalECPrivateKey(srvKey)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	pair, _ := tls.X509KeyPair(srvPEM, keyPEM)
	return pair
}

func serveUDPDNS(addr string) {
	pc, err := net.ListenPacket("udp4", addr)
	if err != nil {
		return
	}
	buf := make([]byte, 2048)
	for {
		n, raddr, rErr := pc.ReadFrom(buf)
		if rErr != nil {
			continue
		}
		if reply := buildDNSReply(buf[:n]); len(reply) > 0 {
			_, _ = pc.WriteTo(reply, raddr)
		}
	}
}

func serveDoH(bindIP string, cert tls.Certificate, counter *atomic.Int64) {
	mux := http.NewServeMux()
	mux.HandleFunc("/dns-query", func(w http.ResponseWriter, r *http.Request) {
		var raw []byte
		if r.Method == http.MethodGet {
			q := r.URL.Query().Get("dns")
			raw, _ = base64.RawURLEncoding.DecodeString(q)
		} else {
			raw, _ = io.ReadAll(io.LimitReader(r.Body, 4096))
		}
		reply := buildDNSReply(raw)
		if len(reply) == 0 {
			http.Error(w, "bad dns query", http.StatusBadRequest)
			return
		}
		counter.Add(1)
		w.Header().Set("Content-Type", "application/dns-message")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(reply)
	})
	srv := &http.Server{
		Addr:      bindIP + ":443",
		Handler:   mux,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}},
	}
	ln, err := net.Listen("tcp4", srv.Addr)
	if err != nil {
		return
	}
	_ = srv.Serve(tls.NewListener(ln, srv.TLSConfig))
}

func serveSite(addr, bodyText, subPayload string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/sub":
			_, _ = w.Write([]byte(subPayload))
		case "/doh-hits":
			_ = json.NewEncoder(w).Encode(map[string]int64{
				"aliHits":    aliHits.Load(),
				"googleHits": googleHits.Load(),
			})
		case "/large":
			chunk := strings.Repeat("X", 1024)
			for range 128 {
				_, _ = w.Write([]byte(chunk))
			}
		case "/hold":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("HOLD_START\n"))
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			time.Sleep(2500 * time.Millisecond)
			_, _ = w.Write([]byte("HOLD_DONE\n"))
		default:
			_, _ = w.Write([]byte(bodyText))
		}
	})
	_ = http.ListenAndServe(addr, mux)
}

func main() {
	subPayload := os.Getenv("SUB_PAYLOAD")
	caPath := "/tmp/e2e-ca.crt"
	cert := genCerts(caPath)
	if len(os.Args) > 1 && os.Args[1] == "--gen-ca-only" {
		return
	}
	go serveUDPDNS("0.0.0.0:53")
	go serveDoH("223.5.5.5", cert, &aliHits)
	go serveDoH("8.8.8.8", cert, &googleHits)
	go serveSite("198.51.100.10:8080", "SUB_ROOT", subPayload)
	go serveSite("198.51.100.20:80", "CN_DIRECT_OK", "")
	serveSite("198.51.100.30:80", "GLOBAL_PROXY_OK", "")
}
`
	if err := os.WriteFile(filepath.Join(helperDir, "go.mod"), []byte("module wanhelper\n\ngo 1.24\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(helperDir, "main.go"), []byte(src), 0644); err != nil {
		t.Fatal(err)
	}
	outBin := filepath.Join(workDir, "wan-helper")
	cmd := exec.CommandContext(ctx, "go", "build", "-o", outBin, ".")
	cmd.Dir = helperDir
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+runtime.GOARCH)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build wan-helper failed: %v\n%s", err, string(out))
	}
	return outBin
}

func setupWANServer(t *testing.T, ctx context.Context, wanC string) string {
	t.Helper()
	ssMethod := "aes-128-gcm"
	ssPass := "singctl-e2e-pass"
	userinfo := base64.RawURLEncoding.EncodeToString([]byte(ssMethod + ":" + ssPass))
	ssURI := fmt.Sprintf("ss://%s@%s:8388#TestWANNode\n", userinfo, wanSrvIP)
	subPayload := base64.StdEncoding.EncodeToString([]byte(ssURI))

	script := fmt.Sprintf(`
set -e
ip addr add %s/24 dev eth0 || true
ip addr add %s/24 dev eth0 || true
ip addr add %s/32 dev eth0 || true
ip addr add %s/32 dev eth0 || true
ip route replace %s via %s

export SUB_PAYLOAD=%q
/usr/bin/wan-helper </dev/null >/tmp/wan_helper.log 2>&1 &

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
/usr/bin/sing-box run -c /etc/sing-box/server.json </dev/null >/tmp/wan_singbox.log 2>&1 &

for i in 1 2 3 4 5 6 7 8 9 10; do
    [ -s /tmp/e2e-ca.crt ] && break
    sleep 1
done
cat /tmp/e2e-ca.crt
`, wanCNIP, wanGlobIP, aliDoHIP, googleDoH, lanSubnet, mainWANIP,
		subPayload, wanSrvIP, ssMethod, ssPass)

	return strings.TrimSpace(mustExec(t, ctx, wanC, script))
}

func setupMainRouter(t *testing.T, ctx context.Context, mainC string) {
	t.Helper()
	// main-router (OpenWrt):
	//  - WAN 口模拟 PPPoE MTU=1492，默认路由指向 wan-server (198.51.100.10)，使 223.5.5.5 等公网地址可达
	//  - 状态防火墙 ct state invalid drop + WAN MASQUERADE
	//  - 模拟 GFW 封锁海外站点 198.51.100.30 与海外 DNS 8.8.8.8 直连（必须走 198.51.100.10:8388 代理隧道才能通！）
	//  - 故意启动主路由 dnsmasq 并将上游错误指回旁路由 192.168.100.2，验证旁路由绝不产生主旁互指死循环！
	script := fmt.Sprintf(`
set -e
WAN_IF=$(ip -o -4 addr show | awk '$4 ~ /^198\.51\.100\./ {print $2; exit}')
LAN_IF=$(ip -o -4 addr show | awk '$4 ~ /^192\.168\.100\./ {print $2; exit}')
ip link set dev "$WAN_IF" mtu 1492
ip route replace default via %s dev "$WAN_IF"
sysctl -w net.ipv4.ip_forward=1 >/dev/null
sysctl -w net.ipv4.conf.all.send_redirects=0 >/dev/null
sysctl -w net.ipv4.conf."$LAN_IF".send_redirects=0 >/dev/null

/usr/sbin/dnsmasq --port=53 --no-resolv --server=%s --pid-file=/var/run/dnsmasq.pid

cat << NFTEOF > /tmp/main-router.nft
flush ruleset
table inet main_fw {
    chain forward {
        type filter hook forward priority filter; policy accept;
        ct state invalid drop
        ip daddr { %s, %s } drop
    }
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        oifname "$WAN_IF" masquerade
    }
}
NFTEOF
nft -f /tmp/main-router.nft
`, wanSrvIP, sideLANIP, wanGlobIP, googleDoH)
	mustExec(t, ctx, mainC, script)
}

func verifyClientSourceIPPreserved(t *testing.T, ctx context.Context, cliC, sideC string) {
	t.Helper()
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
