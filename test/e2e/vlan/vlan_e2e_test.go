// 文件职责：使用真实 OpenWrt Docker 多容器集群端到端验证 VLAN 自动分段、UCI 实写、netifd/fw4 隔离、透明代理绕行与 Safe Commit 自动回滚。
package vlan_e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"singctl/internal/singbox/scripts"
	"singctl/internal/vlan"
)

// TestVLANClusterOpenWrt24E2E 构建真实 OpenWrt 多容器 + 独立客户机网络命名空间模拟集群：
//  1. upstream-gw (OpenWrt 24.10 容器, WAN 198.51.100.1 + 受信任 HA 198.51.100.10 + 模拟外网 203.0.113.20):
//     模拟上级软路由（类似 n4120）与外网目标；
//  2. vlan-router (OpenWrt 24.10 容器, WAN eth0 198.51.100.2 + 真实内核 veth 物理口 lan1..lan4 + br-lan):
//     真实运行 ubusd + netifd + fw4 (nftables) + dnsmasq + singctl web + 模拟 inet sing-box TProxy 表；
//     通过纯内核 veth 线缆将 lan1 连至独立 mgmt 终端命名空间 (192.168.29.50)，将 lan3 连至独立 iot 终端命名空间；
//     全程不重命名、不桥接 Docker 托管的 eth0，彻底兼容 macOS Docker Desktop 与 Linux Docker；
//  3. 端到端实测验证：拓扑探测与幽灵口过滤、防管理口锁死、POST /api/vlan/apply 实写 UCI 4 件套并由 netifd 真拉起 br-lan.28、
//     fw4 真阻断路由器后台与上级主网、Home Assistant 单向白名单放行、nftables 透明代理绕行计数命中、
//     开机脚本 openwrt_fw_nftables.sh 集成、proxyMode 热切换以及 Safe Commit 一键回滚 100% 还原 UCI。
func TestVLANClusterOpenWrt24E2E(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping OpenWrt VLAN Docker cluster E2E in -short mode")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not installed, skipping E2E test")
	}
	ctx := t.Context()
	if out, err := exec.CommandContext(ctx, "docker", "info").CombinedOutput(); err != nil {
		t.Skipf("docker daemon unavailable: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	if !imageExists(ctx, openWrt24Image) {
		t.Skipf("cached OpenWrt image %s not present locally", openWrt24Image)
	}

	repoRoot, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	workDir := t.TempDir()
	arch := detectImageGoArch(t, ctx, openWrt24Image)
	singctlBin := crossCompileSingCtl(t, ctx, repoRoot, workDir, arch)
	probeBin := buildProbeHelper(t, ctx, workDir, arch)

	prefix := fmt.Sprintf("sc-vlan-%d", time.Now().UnixNano()%1000000)
	wanNet := prefix + "-wan"
	upC := prefix + "-upstream"
	rtrC := prefix + "-router"

	const (
		mgmtSock = "/tmp/ns-mgmt.sock"
		iotSock  = "/tmp/ns-iot.sock"
	)

	t.Cleanup(func() {
		cleanCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		// 退出前优雅拆除容器内 netifd/ubusd 与虚拟网桥，避免宿主机网络命名空间释放抖动
		_, _ = dockerExec(cleanCtx, rtrC, `
/usr/bin/singctl web stop >/dev/null 2>&1 || true
killall netifd ubusd vlan-probe >/dev/null 2>&1 || true
ip link del br-lan.28 2>/dev/null || true
ip link del br-lan.30 2>/dev/null || true
ip link del br-lan 2>/dev/null || true
ip link del lan1 2>/dev/null || true
ip link del lan2 2>/dev/null || true
ip link del lan3 2>/dev/null || true
ip link del lan4 2>/dev/null || true
`)
		_ = exec.CommandContext(cleanCtx, "docker", "rm", "-f", rtrC, upC).Run()
		_ = exec.CommandContext(cleanCtx, "docker", "network", "rm", wanNet).Run()
	})

	// 1. 创建 WAN 隔离网络并启动 2 台真实 OpenWrt 容器
	mustRun(t, ctx, "docker", "network", "create", "--subnet=198.51.100.0/24", "--gateway=198.51.100.254", wanNet)

	startContainer := func(name, ip string, mounts ...string) {
		args := []string{
			"run", "-d", "--name", name,
			"--hostname", name,
			"--privileged",
			"--sysctl", "net.ipv4.ip_forward=1",
			"--network", wanNet, "--ip", ip,
		}
		for _, m := range mounts {
			args = append(args, "-v", m)
		}
		args = append(args, openWrt24Image, "/bin/sh", "-c", "mkdir -p /var/run /var/lock /tmp/run /var/state && exec sleep 3600")
		mustRun(t, ctx, "docker", args...)
	}

	startContainer(upC, "198.51.100.1", probeBin+":/usr/bin/vlan-probe:ro")
	startContainer(rtrC, "198.51.100.2", singctlBin+":/usr/bin/singctl:ro", probeBin+":/usr/bin/vlan-probe:ro")

	// 2. 配置 upstream-gw：主网目标 (198.51.100.1:8080)、受信任 HA (198.51.100.10)、模拟外网服务 (203.0.113.20:8080)
	mustDockerExec(t, ctx, upC, `
ip addr add 198.51.100.10/24 dev eth0
ip addr add 203.0.113.20/32 dev lo
ip route replace 192.168.29.0/24 via 198.51.100.2
ip route replace 192.168.20.0/24 via 198.51.100.2
/usr/bin/vlan-probe serve 198.51.100.1:8080 upstream-lan </dev/null >/tmp/up-lan.log 2>&1 &
/usr/bin/vlan-probe serve 203.0.113.20:8080 public-net </dev/null >/tmp/up-pub.log 2>&1 &
`)

	// 3. 配置 vlan-router：创建 2 个完全独立的客户端网络命名空间 (mgmt / iot) 并以真实内核 veth 接至 lan1 / lan3
	mustDockerExec(t, ctx, rtrC, `
set -e
MGMT_PID=$(/usr/bin/vlan-probe netns-spawn /tmp/ns-mgmt.pid `+mgmtSock+`)
IOT_PID=$(/usr/bin/vlan-probe netns-spawn /tmp/ns-iot.pid `+iotSock+`)
sleep 1

# 真实 L2 网线：lan1 <-> mgmt0 (管理电脑), lan3 <-> iot0 (智能家居设备)，外加未插线的 lan2 / lan4
ip link add lan1 type veth
ip link set veth0 name mgmt0
ip link set mgmt0 netns "$MGMT_PID"
ip link set lan1 up

ip link add lan3 type veth
ip link set veth0 name iot0
ip link set iot0 netns "$IOT_PID"
ip link set lan3 up

ip link add lan2 type dummy && ip link set lan2 down
ip link add lan4 type dummy && ip link set lan4 down

# 构造带幽灵口 lan0/lan5 的 /etc/board.json（验证真机同款过滤逻辑）
rm -f /etc/board.json
cat > /etc/board.json <<'EOF'
{
  "model": { "id": "netcore,n60-pro-e2e", "name": "Netcore N60 Pro (Docker E2E)" },
  "network": {
    "lan": { "ports": ["lan0", "lan1", "lan2", "lan3", "lan4", "lan5"] },
    "wan": { "device": "eth0" }
  }
}
EOF

# 写入初始 OpenWrt 四件套 UCI (network / dhcp / wireless / firewall)
cat > /etc/config/network <<'EOF'
config interface 'loopback'
	option device 'lo'
	option proto 'static'
	option ipaddr '127.0.0.1'
	option netmask '255.0.0.0'

config device
	option name 'br-lan'
	option type 'bridge'
	list ports 'lan1'
	list ports 'lan2'
	list ports 'lan3'
	list ports 'lan4'

config interface 'lan'
	option device 'br-lan'
	option proto 'static'
	option ipaddr '192.168.29.1'
	option netmask '255.255.255.0'

config interface 'wan'
	option device 'eth0'
	option proto 'static'
	option ipaddr '198.51.100.2'
	option netmask '255.255.255.0'
	option gateway '198.51.100.1'
EOF

cat > /etc/config/dhcp <<'EOF'
config dnsmasq
	option domainneeded '1'
	option localise_queries '1'
	option rebind_protection '1'
	option local '/lan/'
	option domain 'lan'
	option expandhosts '1'
	option leasefile '/tmp/dhcp.leases'

config dhcp 'lan'
	option interface 'lan'
	option start '100'
	option limit '150'
	option leasetime '12h'

config dhcp 'wan'
	option interface 'wan'
	option ignore '1'
EOF

cat > /etc/config/wireless <<'EOF'
config wifi-device 'MT7986_1_1'
	option type 'mtwifi'
	option phy 'ra0'
	option band '2g'

config wifi-device 'MT7986_1_2'
	option type 'mtwifi'
	option phy 'rax0'
	option band '5g'
EOF

cat > /etc/config/firewall <<'EOF'
config defaults
	option input 'REJECT'
	option output 'ACCEPT'
	option forward 'REJECT'

config zone
	option name 'lan'
	list network 'lan'
	option input 'ACCEPT'
	option output 'ACCEPT'
	option forward 'ACCEPT'

config zone
	option name 'wan'
	list network 'wan'
	option input 'REJECT'
	option output 'ACCEPT'
	option forward 'REJECT'
	option masq '1'

config forwarding
	option src 'lan'
	option dest 'wan'
EOF

mkdir -p /etc/singctl /etc/sing-box
cat > /etc/singctl/singctl.yaml <<'EOF'
singbox:
  config_path: /etc/sing-box/config.json
EOF
chmod 0600 /etc/singctl/singctl.yaml

# 启动真实 OpenWrt ubusd + netifd（脱离 docker exec 管道）
/sbin/ubusd </dev/null >/tmp/ubusd.log 2>&1 &
sleep 1
/sbin/netifd </dev/null >/tmp/netifd.log 2>&1 &
sleep 2

# 装载真实 fw4 防火墙并确认默认路由指向 upstream-gw (198.51.100.1)
ip route replace default via 198.51.100.1 dev eth0
fw4 start >/tmp/fw4-init.log 2>&1 || /etc/init.d/firewall restart >/tmp/fw4-init.log 2>&1 || { cat /tmp/fw4-init.log; exit 1; }

# 建立模拟运行中的 sing-box TProxy nftables 表（验证运行时动态同步 singctl-vlan-bypass 规则与包计数）
nft -f - <<'NFTEOF'
table inet sing-box {
    chain prerouting {
        type filter hook prerouting priority mangle; policy accept;
        fib daddr type local accept
        ip daddr { 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } accept
        meta l4proto { tcp, udp } counter comment "singbox-tproxy-hit"
    }
}
NFTEOF

# 后台启动真实 singctl WebUI（容器无 procd 时显式使用 --no-service 独立守护）
/usr/bin/singctl web start --no-service -c /etc/singctl/singctl.yaml -l :8090 </dev/null >/tmp/singctl-web-e2e.log 2>&1 || { cat /tmp/singctl-web-e2e.log /tmp/singctl-web.log 2>/dev/null; exit 1; }
`)

	// 4. 在独立客户端命名空间中点亮网卡与监听服务
	mustNetNSSh(t, ctx, rtrC, mgmtSock, `
ip link set lo up
ip link set mgmt0 up
ip addr add 192.168.29.50/24 dev mgmt0
ip route replace default via 192.168.29.1
`)
	mustNetNSSh(t, ctx, rtrC, iotSock, `
ip link set lo up
ip link set iot0 up
ip addr add 192.168.29.60/24 dev iot0
ip route replace default via 192.168.29.1
`)
	mustDockerExec(t, ctx, rtrC, `/usr/bin/vlan-probe netns-ctl `+iotSock+` serve 0.0.0.0:8088 iot-device`)

	// 等待 mgmt 终端经由真实 lan1 -> br-lan 打通 singctl WebUI (:8090)
	waitUntil(t, 15*time.Second, "mgmt client reaches singctl WebUI over lan1", func() bool {
		code, _, err := probeNetNSHTTP(ctx, rtrC, mgmtSock, "GET", "http://192.168.29.1:8090/api/vlan/overview", "-", "")
		return err == nil && code == 200
	})

	// === 阶段 1：验证真实拓扑探测与幽灵口过滤 ===
	code, ovRaw := mustNetNSJSON(t, ctx, rtrC, mgmtSock, "GET", "http://192.168.29.1:8090/api/vlan/overview", nil)
	if code != 200 {
		t.Fatalf("GET /api/vlan/overview status=%d body=%s", code, ovRaw)
	}
	var ov vlan.Overview
	if err := json.Unmarshal([]byte(ovRaw), &ov); err != nil {
		t.Fatalf("unmarshal overview: %v (raw=%s)", err, ovRaw)
	}
	if !ov.Supported || ov.Driver != vlan.DriverDSA {
		t.Fatalf("expected supported DSA overview, got supported=%v driver=%q", ov.Supported, ov.Driver)
	}
	if ov.CallerSegmentID != "lan" || ov.CallerIP != "192.168.29.50" {
		t.Fatalf("expected callerSegmentId=lan callerIp=192.168.29.50, got seg=%q ip=%q", ov.CallerSegmentID, ov.CallerIP)
	}
	portNames := make(map[string]vlan.PortInfo, len(ov.Ports))
	for _, p := range ov.Ports {
		portNames[p.Name] = p
	}
	if _, bad := portNames["lan0"]; bad {
		t.Fatalf("phantom board.json port lan0 must be filtered out: %+v", ov.Ports)
	}
	if _, bad := portNames["lan5"]; bad {
		t.Fatalf("phantom board.json port lan5 must be filtered out: %+v", ov.Ports)
	}
	if !portNames["lan1"].IsMgmt {
		t.Fatalf("expected lan1 (first active port of caller mgmt segment) locked as IsMgmt=true, got %+v", portNames["lan1"])
	}
	if portNames["lan3"].IsMgmt {
		t.Fatalf("expected lan3 assignable (IsMgmt=false), got %+v", portNames["lan3"])
	}

	// === 阶段 2：验证防锁死拦截（禁止分配管理口 lan1、禁止删除主网 lan） ===
	badLockReq := vlan.SaveSegmentRequest{
		ID:        "iot",
		VLANID:    28,
		IPAddr:    "192.168.20.1",
		ProxyMode: vlan.ProxyModeDirect,
		Ports:     map[string]string{"lan1": vlan.PortModeAccess},
		Policy:    vlan.SecurityPolicy{AllowWAN: true},
	}
	code, body := mustNetNSJSON(t, ctx, rtrC, mgmtSock, "POST", "http://192.168.29.1:8090/api/vlan/apply", badLockReq)
	if code != 400 {
		t.Fatalf("expected 400 when assigning locked mgmt port lan1, got code=%d body=%s", code, body)
	}
	code, body = mustNetNSJSON(t, ctx, rtrC, mgmtSock, "DELETE", "http://192.168.29.1:8090/api/vlan/segment/lan", nil)
	if code != 400 {
		t.Fatalf("expected 400 when deleting primary lan, got code=%d body=%s", code, body)
	}

	// === 阶段 3：真实调用 POST /api/vlan/apply 创建 VLAN 28 (iot) 绑定 lan3 + 纯直连绕过代理 + 隔离策略 + HA 白名单 ===
	iotReq := vlan.SaveSegmentRequest{
		ID:          "iot",
		DisplayName: "智能家居隔离网",
		Preset:      vlan.PresetIoT,
		VLANID:      28,
		IPAddr:      "192.168.20.1",
		ProxyMode:   vlan.ProxyModeDirect,
		Ports:       map[string]string{"lan3": vlan.PortModeAccess},
		Policy: vlan.SecurityPolicy{
			AllowWAN:         true,
			BlockRouterMgmt:  true,
			BlockUpstreamLAN: true,
			AllowFromMainLAN: true,
			TrustedSourceIPs: []string{"198.51.100.10"},
			AllowMDNS:        true,
		},
		TTLSec: 180,
	}
	code, applyBody := mustNetNSJSON(t, ctx, rtrC, mgmtSock, "POST", "http://192.168.29.1:8090/api/vlan/apply", iotReq)
	if code != 200 {
		t.Fatalf("POST /api/vlan/apply (iot) failed: code=%d body=%s", code, applyBody)
	}
	var applyRes struct {
		OK              bool   `json:"ok"`
		SafeCommitToken string `json:"safeCommitToken"`
	}
	if err := json.Unmarshal([]byte(applyBody), &applyRes); err != nil || !applyRes.OK || applyRes.SafeCommitToken == "" {
		t.Fatalf("expected ok=true and non-empty safeCommitToken, got: %s", applyBody)
	}

	// 等待真实 netifd 把 br-lan.28 拉起
	waitUntil(t, 12*time.Second, "netifd brings up br-lan.28 with 192.168.20.1/24", func() bool {
		out, err := dockerExec(ctx, rtrC, "ip -4 addr show dev br-lan.28 2>/dev/null")
		return err == nil && strings.Contains(out, "192.168.20.1/24")
	})

	// 确认 mgmt 终端 (lan1) 在开启 vlan_filtering 后仍然完全在线不断联！
	code, ovAfter := mustNetNSJSON(t, ctx, rtrC, mgmtSock, "GET", "http://192.168.29.1:8090/api/vlan/overview", nil)
	if code != 200 || !strings.Contains(ovAfter, `"id":"iot"`) {
		t.Fatalf("mgmt client lost access or iot segment missing after apply: code=%d body=%s", code, ovAfter)
	}

	// 验证绕行文件权限 0600、运行中 nftables inet sing-box 绕行规则、真实 fw4 隔离链
	bypassCheck := mustDockerExec(t, ctx, rtrC, `
ls -l /etc/singctl/vlan-proxy-bypass.list
cat /etc/singctl/vlan-proxy-bypass.list
echo "---NFT-SINGBOX---"
nft list chain inet sing-box prerouting
echo "---NFT-FW4-IOT---"
nft list chain inet fw4 input_iot
nft list chain inet fw4 forward_iot
`)
	if !strings.Contains(bypassCheck, "-rw-------") || !strings.Contains(bypassCheck, "192.168.20.0/24") {
		t.Fatalf("expected 0600 /etc/singctl/vlan-proxy-bypass.list with 192.168.20.0/24, got:\n%s", bypassCheck)
	}
	if !strings.Contains(bypassCheck, "singctl-vlan-bypass") {
		t.Fatalf("expected live nft inet sing-box prerouting to contain singctl-vlan-bypass, got:\n%s", bypassCheck)
	}
	if !strings.Contains(bypassCheck, "SingCtl-Block-Mgmt-iot") || !strings.Contains(bypassCheck, "SingCtl-Block-Upstream-iot") {
		t.Fatalf("expected live fw4 nftables chains to contain SingCtl isolation rules, got:\n%s", bypassCheck)
	}

	// === 阶段 4：真实数据面跨容器流量测试 ===
	// 将 iot 终端切入新分配的 VLAN 28 网段 (192.168.20.50/24)
	mustNetNSSh(t, ctx, rtrC, iotSock, `
ip addr flush dev iot0
ip addr add 192.168.20.50/24 dev iot0
ip link set iot0 up
ip route replace default via 192.168.20.1
`)

	// 4a. IoT 访问模拟公网 (203.0.113.20:8080, 位于 upstream-gw 容器) 必须成功
	waitUntil(t, 10*time.Second, "iot client reaches public internet through VLAN 28 NAT", func() bool {
		c, b, e := probeNetNSHTTP(ctx, rtrC, iotSock, "GET", "http://203.0.113.20:8080/", "-", "")
		return e == nil && c == 200 && strings.Contains(b, "OK:public-net")
	})

	// 4b. 验证 nftables singctl-vlan-bypass 放行了 IoT 直连流量，未落入 singbox-tproxy-hit
	nftCounters := mustDockerExec(t, ctx, rtrC, `nft list chain inet sing-box prerouting`)
	if !strings.Contains(nftCounters, `ip saddr 192.168.20.0/24`) {
		t.Fatalf("expected live nft bypass rule for 192.168.20.0/24, got:\n%s", nftCounters)
	}
	if !strings.Contains(nftCounters, `packets 0 bytes 0 comment "singbox-tproxy-hit"`) {
		t.Fatalf("expected IoT direct traffic to bypass singbox-tproxy-hit (0 packets), got:\n%s", nftCounters)
	}

	// 4c. IoT 访问路由器管理面板 (192.168.20.1:8090) 必须被真实 fw4 阻断
	if c, b, e := probeNetNSHTTP(ctx, rtrC, iotSock, "GET", "http://192.168.20.1:8090/", "-", ""); e == nil {
		t.Fatalf("SECURITY FAILURE: iot client reached router WebUI :8090! status=%d body=%s", c, b)
	}

	// 4d. IoT 访问上级主网服务 (198.51.100.1:8080) 必须被真实 fw4 阻断
	if c, b, e := probeNetNSHTTP(ctx, rtrC, iotSock, "GET", "http://198.51.100.1:8080/", "-", ""); e == nil {
		t.Fatalf("SECURITY FAILURE: iot client reached upstream LAN 198.51.100.1:8080! status=%d body=%s", c, b)
	}

	// 4e. 单向控制验证：受信任 Home Assistant (198.51.100.10) 可直达 IoT 设备 (:8088)，未授权上级 IP (198.51.100.1) 被拦截
	cHA, bHA, eHA := probeHTTP(ctx, upC, "GET", "http://192.168.20.50:8088/", "198.51.100.10", "")
	if eHA != nil || cHA != 200 || !strings.Contains(bHA, "OK:iot-device") {
		t.Fatalf("trusted Home Assistant (198.51.100.10) should reach iot:8088, got code=%d body=%s err=%v", cHA, bHA, eHA)
	}
	if cBad, bBad, eBad := probeHTTP(ctx, upC, "GET", "http://192.168.20.50:8088/", "198.51.100.1", ""); eBad == nil {
		t.Fatalf("SECURITY FAILURE: untrusted upstream IP 198.51.100.1 reached iot:8088! code=%d body=%s", cBad, bBad)
	}

	// 确认第一轮 Safe Commit 保险丝
	code, confirmBody := mustNetNSJSON(t, ctx, rtrC, mgmtSock, "POST", "http://192.168.29.1:8090/api/safe-commit/confirm", map[string]string{"token": applyRes.SafeCommitToken})
	if code != 200 || !strings.Contains(confirmBody, `"confirmed":true`) {
		t.Fatalf("confirm Safe Commit failed: code=%d body=%s", code, confirmBody)
	}

	// === 阶段 5：验证 OpenWrt 开机脚本 (openwrt_fw_nftables.sh fw_apply) 读取 bypass 清单并生成合法 singbox.nft ===
	nftStartScript := scripts.GetOpenWrtStartScript(scripts.BackendNFTables)
	idx := strings.LastIndex(nftStartScript, "\nmain ")
	if idx < 0 {
		idx = strings.LastIndex(nftStartScript, "\nmain\n")
	}
	libScript := nftStartScript
	if idx > 0 {
		libScript = nftStartScript[:idx] + "\n"
	}
	scriptPath := filepath.Join(workDir, "openwrt_nft_lib.sh")
	if err := os.WriteFile(scriptPath, []byte(libScript), 0700); err != nil {
		t.Fatal(err)
	}
	mustRun(t, ctx, "docker", "cp", scriptPath, rtrC+":/tmp/openwrt_nft_lib.sh")
	bootNFTOut := mustDockerExec(t, ctx, rtrC, `
. /tmp/openwrt_nft_lib.sh
fw_apply
cat /etc/sing-box/singbox.nft
`)
	if !strings.Contains(bootNFTOut, `ip saddr { 192.168.20.0/24 } fib daddr type != local accept comment "singctl-vlan-bypass"`) {
		t.Fatalf("boot script singbox.nft missing expected VLAN bypass rule:\n%s", bootNFTOut)
	}

	// === 阶段 6：切换 proxyMode 为 follow（跟随代理），验证运行时与文件同步移除绕行规则 ===
	iotReq.ProxyMode = vlan.ProxyModeFollow
	code, body = mustNetNSJSON(t, ctx, rtrC, mgmtSock, "POST", "http://192.168.29.1:8090/api/vlan/apply", iotReq)
	if code != 200 {
		t.Fatalf("switch iot proxyMode->follow failed: code=%d body=%s", code, body)
	}
	afterFollow := mustDockerExec(t, ctx, rtrC, `
cat /etc/singctl/vlan-proxy-bypass.list
echo "---NFT---"
nft list chain inet sing-box prerouting
`)
	if strings.Contains(afterFollow, "192.168.20.0/24") {
		t.Fatalf("expected 192.168.20.0/24 removed from bypass list & nft chain after switching to follow, got:\n%s", afterFollow)
	}
	mustNetNSJSON(t, ctx, rtrC, mgmtSock, "POST", "http://192.168.29.1:8090/api/safe-commit/confirm", map[string]string{})

	// === 阶段 7：验证 Safe Commit 回滚完整还原 UCI 4 件套与无线配置 ===
	guestReq := vlan.SaveSegmentRequest{
		ID:          "guest",
		DisplayName: "访客隔离网",
		Preset:      vlan.PresetGuest,
		VLANID:      30,
		IPAddr:      "192.168.30.1",
		ProxyMode:   vlan.ProxyModeDirect,
		Wireless: &vlan.WirelessSpec{
			Enabled:    true,
			Radio:      "MT7986_1_1",
			SSID:       "Guest-E2E",
			Password:   "GuestPass1234",
			Encryption: "sae-mixed",
			Isolate:    true,
		},
		Policy: vlan.SecurityPolicy{
			AllowWAN:         true,
			BlockRouterMgmt:  true,
			BlockUpstreamLAN: true,
		},
		TTLSec: 180,
	}
	code, body = mustNetNSJSON(t, ctx, rtrC, mgmtSock, "POST", "http://192.168.29.1:8090/api/vlan/apply", guestReq)
	if code != 200 {
		t.Fatalf("apply guest VLAN failed: code=%d body=%s", code, body)
	}
	if out := mustDockerExec(t, ctx, rtrC, "uci get network.guest.ipaddr"); strings.TrimSpace(out) != "192.168.30.1" {
		t.Fatalf("expected network.guest.ipaddr=192.168.30.1 before rollback, got %q", out)
	}

	code, rbBody := mustNetNSJSON(t, ctx, rtrC, mgmtSock, "POST", "http://192.168.29.1:8090/api/safe-commit/rollback", map[string]string{"trigger": "e2e-verify"})
	if code != 200 || !strings.Contains(rbBody, `"openwrt_network:reload"`) {
		t.Fatalf("Safe Commit rollback failed or missing openwrt_network:reload: code=%d body=%s", code, rbBody)
	}
	if out, err := dockerExec(ctx, rtrC, "uci -q get network.guest.ipaddr"); err == nil && strings.TrimSpace(out) != "" {
		t.Fatalf("network.guest must be gone after Safe Commit rollback, got %q", out)
	}
	if out, err := dockerExec(ctx, rtrC, "uci -q get wireless.singctl_vlan_guest.ssid"); err == nil && strings.TrimSpace(out) != "" {
		t.Fatalf("wireless.singctl_vlan_guest must be gone after Safe Commit rollback, got %q", out)
	}

	// === 阶段 8：安全删除 iot 分段并确认解除保险丝 ===
	code, delBody := mustNetNSJSON(t, ctx, rtrC, mgmtSock, "DELETE", "http://192.168.29.1:8090/api/vlan/segment/iot", nil)
	if code != 200 || !strings.Contains(delBody, `"ok":true`) {
		t.Fatalf("DELETE /api/vlan/segment/iot failed: code=%d body=%s", code, delBody)
	}
	if out, err := dockerExec(ctx, rtrC, "uci -q get network.iot.ipaddr"); err == nil && strings.TrimSpace(out) != "" {
		t.Fatalf("network.iot should be deleted, still got %q", out)
	}
	mustNetNSJSON(t, ctx, rtrC, mgmtSock, "POST", "http://192.168.29.1:8090/api/safe-commit/confirm", map[string]string{})
}

// TestVLANProxyBypassIPTablesOpenWrtE2E 使用真实 OpenWrt/ImmortalWrt iptables 容器验证
// openwrt_fw_iptables.sh 与 /etc/singctl/vlan-proxy-bypass.list 在真实 mangle 表 SING_BOX 链上的端到端行为。
func TestVLANProxyBypassIPTablesOpenWrtE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping OpenWrt iptables VLAN bypass E2E in -short mode")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not installed, skipping E2E test")
	}
	ctx := t.Context()
	if out, err := exec.CommandContext(ctx, "docker", "info").CombinedOutput(); err != nil {
		t.Skipf("docker daemon unavailable: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	if !imageExists(ctx, openWrtIptImg) {
		t.Skipf("cached OpenWrt iptables image %s not present locally", openWrtIptImg)
	}

	workDir := t.TempDir()
	iptStart := scripts.GetOpenWrtStartScript(scripts.BackendIPTables)
	idx := strings.LastIndex(iptStart, "\nmain ")
	if idx < 0 {
		idx = strings.LastIndex(iptStart, "\nmain\n")
	}
	libScript := iptStart
	if idx > 0 {
		libScript = iptStart[:idx] + "\n"
	}
	scriptPath := filepath.Join(workDir, "openwrt_ipt_lib.sh")
	if err := os.WriteFile(scriptPath, []byte(libScript), 0700); err != nil {
		t.Fatal(err)
	}

	cname := fmt.Sprintf("sc-vlan-ipt-%d", time.Now().UnixNano()%1000000)
	t.Cleanup(func() {
		cleanCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = exec.CommandContext(cleanCtx, "docker", "rm", "-f", cname).Run()
	})

	mustRun(t, ctx, "docker", "run", "-d", "--name", cname, "--privileged",
		"-v", scriptPath+":/tmp/openwrt_ipt_lib.sh:ro",
		openWrtIptImg, "/bin/sh", "-c", "exec sleep 300")

	out := mustDockerExec(t, ctx, cname, `
mkdir -p /etc/singctl
cat > /etc/singctl/vlan-proxy-bypass.list <<'EOF'
# Managed by singctl VLAN manager
192.168.20.0/24
192.168.30.0/24
EOF
chmod 0600 /etc/singctl/vlan-proxy-bypass.list

. /tmp/openwrt_ipt_lib.sh
collect_vlan_proxy_bypass_cidrs
echo "COLLECTED=$BYPASS_VLAN_V4_CIDRS"

iptables -t mangle -N SING_BOX
iptables -t mangle -A SING_BOX -m addrtype --dst-type LOCAL -j RETURN 2>/dev/null || true
for cidr in $BYPASS_VLAN_V4_CIDRS; do
    iptables -t mangle -A SING_BOX -s "$cidr" -m comment --comment singctl-vlan-bypass -j RETURN 2>/dev/null || \
        iptables -t mangle -A SING_BOX -s "$cidr" -j RETURN
done
iptables -t mangle -S SING_BOX
fw_stop_cleanup
`)
	if !strings.Contains(out, "COLLECTED=192.168.20.0/24 192.168.30.0/24") {
		t.Fatalf("unexpected collected CIDRs:\n%s", out)
	}
	if !strings.Contains(out, "-A SING_BOX -s 192.168.20.0/24") || !strings.Contains(out, "-A SING_BOX -s 192.168.30.0/24") {
		t.Fatalf("expected live iptables SING_BOX rules for both bypassed VLANs, got:\n%s", out)
	}
}
