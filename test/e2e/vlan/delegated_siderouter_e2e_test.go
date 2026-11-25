// 文件职责：使用真实 OpenWrt 24 与 OpenWrt 21 Docker 多容器集群端到端验证主/旁路由联动、防火墙重载持久化、真实 IP 透传与故障回切。
package vlan_e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"singctl/internal/audit"
	"singctl/internal/vlan"
)

type gatewayModeResp struct {
	OK               bool   `json:"ok"`
	Mode             string `json:"mode"`
	WorkMode         string `json:"workMode"`
	SideRouterStatus *struct {
		Configured bool   `json:"configured"`
		Online     bool   `json:"online"`
		WebUIReady bool   `json:"webuiReady"`
		DNSReady   bool   `json:"dnsReady"`
		IP         string `json:"ip"`
	} `json:"sideRouterStatus"`
}

func requireDockerAndImage(t *testing.T, ctx context.Context, image string) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not installed, skipping E2E test")
	}
	if out, err := exec.CommandContext(ctx, "docker", "info").CombinedOutput(); err != nil {
		t.Skipf("docker daemon unavailable: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	if !imageExists(ctx, image) {
		t.Skipf("cached OpenWrt image %s not present locally", image)
	}
}

// TestOpenWrt24DelegatedVLANToSideRouterE2E 验证：OpenWrt 24 主路由 (delegated + fw4) + OpenWrt 24 旁路由 (fw4 + TProxy)。
func TestOpenWrt24DelegatedVLANToSideRouterE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping OpenWrt 24 delegated+side_router Docker E2E in -short mode")
	}
	runDelegatedSideRouterMatrixE2E(t, false)
}

// TestOpenWrt24DelegatedVLANToOpenWrt21SideRouterE2E 验证：OpenWrt 24 主路由 + OpenWrt 21.02 旁路由 (fw3/iptables + REDIRECT + fw3 restart 持久化)。
func TestOpenWrt24DelegatedVLANToOpenWrt21SideRouterE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping OpenWrt 24 -> OpenWrt 21.02 side_router Docker E2E in -short mode")
	}
	runDelegatedSideRouterMatrixE2E(t, true)
}

func runDelegatedSideRouterMatrixE2E(t *testing.T, sideOpenWrt21 bool) {
	ctx := t.Context()
	requireDockerAndImage(t, ctx, openWrt24Image)
	sideImage := openWrt24Image
	if sideOpenWrt21 {
		requireDockerAndImage(t, ctx, openWrt21Image)
		sideImage = openWrt21Image
	}

	repoRoot, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	workDir := t.TempDir()
	mainArch := detectImageGoArch(t, ctx, openWrt24Image)
	sideArch := detectImageGoArch(t, ctx, sideImage)
	singctlMainBin := crossCompileSingCtl(t, ctx, repoRoot, workDir, mainArch)
	singctlSideBin := crossCompileSingCtlFull(t, ctx, repoRoot, workDir, sideArch)
	mainProbeBin := buildProbeHelper(t, ctx, workDir, mainArch)
	sideProbeBin := mainProbeBin
	if sideArch != mainArch {
		sideProbeBin = buildProbeHelper(t, ctx, workDir, sideArch)
	}

	tag := "ow24"
	if sideOpenWrt21 {
		tag = "ow21"
	}
	prefix := fmt.Sprintf("sc-del-%s-%d", tag, time.Now().UnixNano()%100000)
	wanNet := prefix + "-wan"
	wanC := prefix + "-wan"
	mainC := prefix + "-main"
	sideC := prefix + "-side"

	const (
		mgmtSock = "/tmp/ns-mgmt.sock"
		vlanSock = "/tmp/ns-vlan.sock"
	)

	t.Cleanup(func() {
		cleanCtx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		defer cancel()
		_, _ = dockerExec(cleanCtx, mainC, `
/usr/bin/singctl daemon stop >/dev/null 2>&1 || true
/etc/init.d/dnsmasq stop >/dev/null 2>&1 || true
killall netifd procd ubusd dnsmasq vlan-probe singctl >/dev/null 2>&1 || true
ip link del br-lan.8 2>/dev/null || true
ip link del br-lan.1 2>/dev/null || true
ip link del br-lan 2>/dev/null || true
ip link del lan1 2>/dev/null || true
ip link del lan2 2>/dev/null || true
ip link del lan3 2>/dev/null || true
ip link del lan4 2>/dev/null || true
`)
		_, _ = dockerExec(cleanCtx, sideC, `
/usr/bin/singctl web stop >/dev/null 2>&1 || true
/etc/init.d/dnsmasq stop >/dev/null 2>&1 || true
killall netifd procd ubusd dnsmasq sing-box vlan-probe singctl >/dev/null 2>&1 || true
`)
		_ = exec.CommandContext(cleanCtx, "docker", "rm", "-f", mainC, sideC, wanC).Run()
		_ = exec.CommandContext(cleanCtx, "docker", "network", "rm", wanNet).Run()
	})

	// 1. 创建独立 WAN 网络，并用真实内核 veth L2 直连线接通 main-rtr lan2 <-> side-rtr eth0
	mustRun(t, ctx, "docker", "network", "create", "--subnet=198.51.100.0/24", "--gateway=198.51.100.254", wanNet)
	mustRun(t, ctx, "docker", "run", "-d", "--name", wanC, "--hostname", wanC, "--privileged",
		"--sysctl", "net.ipv4.ip_forward=1", "--network", wanNet, "--ip", "198.51.100.1",
		"-v", mainProbeBin+":/usr/bin/vlan-probe:ro",
		openWrt24Image, "/bin/sh", "-c", "mkdir -p /var/run /var/lock /tmp/run /var/state && exec sleep 3600",
	)
	mustRun(t, ctx, "docker", "run", "-d", "--name", mainC, "--hostname", mainC, "--privileged",
		"--sysctl", "net.ipv4.ip_forward=1", "--network", wanNet, "--ip", "198.51.100.2",
		"-v", singctlMainBin+":/usr/bin/singctl:ro",
		"-v", mainProbeBin+":/usr/bin/vlan-probe:ro",
		openWrt24Image, "/bin/sh", "-c", "mkdir -p /var/run /var/lock /tmp/run /var/state && exec sleep 3600",
	)
	mustRun(t, ctx, "docker", "run", "-d", "--name", sideC, "--hostname", sideC, "--privileged",
		"--sysctl", "net.ipv4.ip_forward=1", "--network", "none",
		"-v", singctlSideBin+":/usr/bin/singctl:ro",
		"-v", sideProbeBin+":/usr/bin/vlan-probe:ro",
		"-v", sideProbeBin+":/usr/bin/sing-box:ro",
		sideImage, "/bin/sh", "-c", "mkdir -p /var/run /var/lock /tmp/run /var/state && exec sleep 3600",
	)
	wireContainerVeth(t, ctx, mainC, "lan2", sideC, "eth0")

	// 2. 配置 wan-srv：公网 HTTP (203.0.113.20:8080) + 上游权威 DNS (223.5.5.5:53)
	mustDockerExec(t, ctx, wanC, `
ip addr add 203.0.113.20/32 dev lo
ip addr add 223.5.5.5/32 dev lo
ip route replace 192.168.55.0/24 via 198.51.100.2
ip route replace 192.168.89.0/24 via 198.51.100.2
/usr/bin/vlan-probe serve 203.0.113.20:8080 public-wan </dev/null >/tmp/wan-http.log 2>&1 &
/usr/bin/vlan-probe dns-serve 223.5.5.5:53 app.example.com=203.0.113.20 </dev/null >/tmp/wan-dns.log 2>&1 &
`)

	// 3. 配置 main-rtr (OpenWrt 24 + fw4[lan masq='1', drop_invalid='1'] + dnsmasq + singctl daemon)
	mustDockerExec(t, ctx, mainC, `
set -e
rm -f /sbin/ujail /etc/board.json
mkdir -p /var/run/dnsmasq /var/lock /tmp/run /var/state /tmp/resolv.conf.d /tmp/hosts /etc/singctl /etc/sing-box
cat > /tmp/dhcp.leases <<'EOF'
4102444800 aa:bb:cc:dd:ee:89 192.168.89.137 yunzhonnhedeMBP 01:aa:bb:cc:dd:ee:89
EOF

MGMT_PID=$(/usr/bin/vlan-probe netns-spawn /tmp/ns-mgmt.pid `+mgmtSock+`)
VLAN_PID=$(/usr/bin/vlan-probe netns-spawn /tmp/ns-vlan.pid `+vlanSock+`)
sleep 1

ip link add lan1 type veth
ip link set veth0 name mgmt0
ip link set mgmt0 netns "$MGMT_PID"
ip link set lan1 up

ip link add lan3 type veth
ip link set veth0 name vlan0
ip link set vlan0 netns "$VLAN_PID"
ip link set lan3 up

ip link add lan4 type dummy && ip link set lan4 down

cat > /etc/board.json <<'EOF'
{
  "model": { "id": "xiaomi,ax3000t-e2e", "name": "Xiaomi AX3000T (OpenWrt 24 E2E)" },
  "network": {
    "lan": { "ports": ["lan1", "lan2", "lan3", "lan4"] },
    "wan": { "device": "eth0" }
  }
}
EOF

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
	option ipaddr '192.168.55.1'
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
	option dhcpv4 'server'

config dhcp 'wan'
	option interface 'wan'
	option ignore '1'
EOF

cat > /etc/config/wireless <<'EOF'
config wifi-device 'radio0'
	option type 'mac80211'
	option band '2g'
EOF

cat > /etc/config/firewall <<'EOF'
config defaults
	option input 'REJECT'
	option output 'ACCEPT'
	option forward 'REJECT'
	option drop_invalid '1'

config zone
	option name 'lan'
	list network 'lan'
	option input 'ACCEPT'
	option output 'ACCEPT'
	option forward 'ACCEPT'
	option masq '1'

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

cat > /etc/singctl/singctl.yaml <<'EOF'
singbox:
  config_path: /etc/sing-box/config.json
EOF
chmod 0600 /etc/singctl/singctl.yaml

/sbin/ubusd </dev/null >/tmp/ubusd.log 2>&1 &
sleep 1
/sbin/procd </dev/null >/tmp/procd.log 2>&1 &
sleep 1
/sbin/netifd </dev/null >/tmp/netifd.log 2>&1 &
sleep 2

ip route replace default via 198.51.100.1 dev eth0
fw4 start >/tmp/fw4-init.log 2>&1 || /etc/init.d/firewall restart >/tmp/fw4-init.log 2>&1 || { cat /tmp/fw4-init.log; exit 1; }
/etc/init.d/dnsmasq start >/tmp/dnsmasq-init.log 2>&1 || { cat /tmp/dnsmasq-init.log; exit 1; }
sleep 1

SINGCTL_UNIFIED_DAEMON=1 SINGCTL_WEB_LISTEN=:8090 /usr/bin/singctl -c /etc/singctl/singctl.yaml daemon start </dev/null >/tmp/singctl-daemon.log 2>&1 || { cat /tmp/singctl-daemon.log /tmp/singctl-daemon*.log 2>/dev/null; exit 1; }
`)

	// 4. 配置 side-rtr (OpenWrt 24 fw4 OR OpenWrt 21.02 fw3)
	sideSetup := `
set -e
rm -f /sbin/ujail
mkdir -p /var/run/dnsmasq /var/lock /tmp/run /var/state /tmp/resolv.conf.d /tmp/hosts /etc/singctl /etc/sing-box
touch /tmp/dhcp.leases

cat > /etc/config/network <<'EOF'
config interface 'loopback'
	option device 'lo'
	option proto 'static'
	option ipaddr '127.0.0.1'
	option netmask '255.0.0.0'

config interface 'lan'
	option device 'eth0'
	option proto 'static'
	option ipaddr '192.168.55.88'
	option netmask '255.255.255.0'
	option gateway '192.168.55.1'
EOF

cat > /etc/config/dhcp <<'EOF'
config dnsmasq
	option domainneeded '1'
	option localise_queries '1'
	option rebind_protection '0'
	option local '/lan/'
	option domain 'lan'
	option noresolv '1'
	option localservice '1'
	option leasefile '/tmp/dhcp.leases'
	list server '223.5.5.5'

config dhcp 'lan'
	option interface 'lan'
	option ignore '1'
EOF

# 设置严谨单臂隔离策略：默认 input/forward REJECT，依赖 singctl 自动挂载 INPUT/FORWARD 放行规则
cat > /etc/config/firewall <<'EOF'
config defaults
	option input 'REJECT'
	option output 'ACCEPT'
	option forward 'REJECT'

config zone
	option name 'lan'
	list network 'lan'
	option input 'REJECT'
	option output 'ACCEPT'
	option forward 'REJECT'
EOF

cat > /etc/sing-box/config.json <<'EOF'
{
  "inbounds": [
    { "type": "tproxy", "tag": "tproxy-in", "listen": "::", "listen_port": 7895, "sniff": true }
  ],
  "outbounds": [
    { "type": "selector", "tag": "Proxy", "outbounds": ["node-a"] },
    { "type": "vless", "tag": "node-a", "server": "198.51.100.1" },
    { "type": "direct", "tag": "#DC" }
  ],
  "dns": {
    "servers": [
      { "tag": "dns_local", "type": "udp", "server": "223.5.5.5" },
      { "tag": "dns_proxy", "type": "udp", "server": "223.5.5.5" }
    ],
    "rules": [
      { "clash_mode": "Direct", "server": "dns_local" },
      { "domain_suffix": ["tracker.example.com"], "action": "reject" },
      { "rule_set": ["geosite-cn"], "server": "dns_local" },
      { "rule_set": ["geosite-geolocation-!cn"], "server": "dns_proxy" }
    ]
  },
  "route": {
    "rules": [
      { "action": "sniff" },
      { "protocol": "dns", "action": "hijack-dns" },
      { "ip_is_private": true, "outbound": "#DC" },
      { "domain_suffix": ["tracker.example.com"], "action": "reject" },
      { "rule_set": ["geosite-cn"], "outbound": "#DC" },
      { "rule_set": ["geosite-geolocation-!cn"], "outbound": "Proxy" }
    ]
  },
  "experimental": {
    "clash_api": {
      "external_controller": "127.0.0.1:9090"
    }
  }
}
EOF
chmod 0600 /etc/sing-box/config.json

cat > /etc/singctl/singctl.yaml <<'EOF'
singbox:
  config_path: /etc/sing-box/config.json
EOF
chmod 0600 /etc/singctl/singctl.yaml

/sbin/ubusd </dev/null >/tmp/ubusd.log 2>&1 &
sleep 1
/sbin/procd </dev/null >/tmp/procd.log 2>&1 &
sleep 1
/sbin/netifd </dev/null >/tmp/netifd.log 2>&1 &
sleep 2
ip -4 addr show dev eth0 | grep -q '192.168.55.88' || ip addr replace 192.168.55.88/24 dev eth0
ip route replace default via 192.168.55.1 dev eth0
`
	if sideOpenWrt21 {
		sideSetup += `
rm -f /usr/sbin/nft /sbin/fw4
fw3 restart >/tmp/fw3-init.log 2>&1 || { cat /tmp/fw3-init.log; exit 1; }
/etc/init.d/dnsmasq start >/tmp/dnsmasq-init.log 2>&1 || { cat /tmp/dnsmasq-init.log; exit 1; }

iptables -w 2 -t nat -N SINGBOX_REDIR
iptables -w 2 -t nat -A SINGBOX_REDIR -m mark --mark 0xff -j RETURN
iptables -w 2 -t nat -A SINGBOX_REDIR -m mark --mark 0x80000 -j RETURN
iptables -w 2 -t nat -A SINGBOX_REDIR -d 127.0.0.0/8 -j RETURN
iptables -w 2 -t nat -A SINGBOX_REDIR -d 10.0.0.0/8 -j RETURN
iptables -w 2 -t nat -A SINGBOX_REDIR -d 172.16.0.0/12 -j RETURN
iptables -w 2 -t nat -A SINGBOX_REDIR -d 192.168.0.0/16 -j RETURN
iptables -w 2 -t nat -A SINGBOX_REDIR -p tcp -j REDIRECT --to-ports 7895
iptables -w 2 -t nat -A PREROUTING -j SINGBOX_REDIR
`
	} else {
		sideSetup += `
fw4 restart >/tmp/fw4-init.log 2>&1 || { cat /tmp/fw4-init.log; exit 1; }
/etc/init.d/dnsmasq start >/tmp/dnsmasq-init.log 2>&1 || { cat /tmp/dnsmasq-init.log; exit 1; }

ip -4 rule add fwmark 0x1 lookup 100
ip -4 route replace local 0.0.0.0/0 dev lo table 100
nft -f - <<'NFTEOF'
table inet sing-box {
    chain prerouting {
        type filter hook prerouting priority mangle; policy accept;
        fib daddr type local counter accept
        ip daddr { 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } counter accept
        meta mark 0xff counter accept
        meta mark 0x80000 counter accept
        meta l4proto tcp counter tproxy ip to :7895 meta mark set 0x1 accept
    }
    chain output {
        type route hook output priority mangle; policy accept;
        meta mark 0xff counter accept
        meta mark 0x80000 counter accept
        ip daddr { 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } counter accept
    }
}
NFTEOF
`
	}
	sideSetup += `
/usr/bin/sing-box run -c /etc/sing-box/config.json </dev/null >/tmp/singbox-shim.log 2>&1 &
sleep 1
/usr/bin/singctl -c /etc/singctl/singctl.yaml web start -l :8090 </dev/null >/tmp/singctl-web.log 2>&1 || { cat /tmp/singctl-web.log; exit 1; }
`
	mustDockerExec(t, ctx, sideC, sideSetup)

	// 点亮 mgmt 终端命名空间 (192.168.55.50/24)
	mustNetNSSh(t, ctx, mainC, mgmtSock, `
ip link set lo up
ip link set mgmt0 up
ip addr add 192.168.55.50/24 dev mgmt0
ip route replace default via 192.168.55.1
`)
	mustDockerExec(t, ctx, mainC, `/usr/bin/vlan-probe netns-ctl `+mgmtSock+` serve 192.168.55.50:8088 mgmt-host`)

	waitUntil(t, 15*time.Second, "mgmt client reaches main-rtr WebUI", func() bool {
		c1, _, e1 := probeNetNSHTTP(ctx, mainC, mgmtSock, "GET", "http://192.168.55.1:8090/api/gateway", "-", "")
		return e1 == nil && c1 == 200
	})

	// 注意在未配置 singctl-side 放行前，fw3/fw4 在 strict REJECT 模式下会拦截旁路由 8090/ping 直到 Controller.Apply 执行；
	// 用本机 exec 切换 side-rtr 为 side_router 模式，并在切换+防火墙重启后再通过 mgmt 验证互通！
	sideGwBody, _ := json.Marshal(map[string]any{
		"mode":         "side",
		"workMode":     "audit",
		"mainRouterIP": "192.168.55.1",
		"lanIface":     "eth0",
	})
	cSide, bSide, eSide := probeHTTP(ctx, sideC, "POST", "http://127.0.0.1:8090/api/gateway", "-", string(sideGwBody))
	if eSide != nil || cSide != 200 {
		t.Fatalf("configure side-rtr gateway mode failed: code=%d body=%s err=%v", cSide, bSide, eSide)
	}
	sideCheckOut := mustDockerExec(t, ctx, sideC, "uci -q get dhcp.@dnsmasq[0].localservice && ip -4 route show 192.168.0.0/16")
	if !strings.Contains(sideCheckOut, "0") || !strings.Contains(sideCheckOut, "192.168.55.1") {
		t.Fatalf("expected side-rtr localservice=0 and 192.168.0.0/16 via 192.168.55.1, got:\n%s", sideCheckOut)
	}
	if sideOpenWrt21 {
		fw3Persist := mustDockerExec(t, ctx, sideC, `
set -e
ls -la /etc/singctl/singctl-side.fw3.sh
fw3 restart >/tmp/fw3-side-restart.log 2>&1 || { cat /tmp/fw3-side-restart.log; exit 1; }
iptables -w 2 -t nat -N SINGBOX_REDIR 2>/dev/null || true
iptables -w 2 -t nat -F SINGBOX_REDIR
iptables -w 2 -t nat -A SINGBOX_REDIR -m mark --mark 0xff -j RETURN
iptables -w 2 -t nat -A SINGBOX_REDIR -m mark --mark 0x80000 -j RETURN
iptables -w 2 -t nat -A SINGBOX_REDIR -d 127.0.0.0/8 -j RETURN
iptables -w 2 -t nat -A SINGBOX_REDIR -d 10.0.0.0/8 -j RETURN
iptables -w 2 -t nat -A SINGBOX_REDIR -d 172.16.0.0/12 -j RETURN
iptables -w 2 -t nat -A SINGBOX_REDIR -d 192.168.0.0/16 -j RETURN
iptables -w 2 -t nat -A SINGBOX_REDIR -p tcp -j REDIRECT --to-ports 7895
iptables -w 2 -t nat -C PREROUTING -j SINGBOX_REDIR 2>/dev/null || iptables -w 2 -t nat -A PREROUTING -j SINGBOX_REDIR
iptables -w 2 -t nat -S SINGCTL_SIDE_NAT
iptables -w 2 -S INPUT
`)
		if !strings.Contains(fw3Persist, "-rw-------") ||
			!strings.Contains(fw3Persist, "-A SINGCTL_SIDE_NAT -s 192.168.0.0/16 -o eth0 -j MASQUERADE") ||
			!strings.Contains(fw3Persist, "-A INPUT -i eth0 -m comment --comment singctl-side -j ACCEPT") {
			t.Fatalf("expected side-rtr OpenWrt 21 fw3 restart persistence + INPUT -i eth0 ACCEPT, got:\n%s", fw3Persist)
		}
	} else {
		fw4Persist := mustDockerExec(t, ctx, sideC, `
ls -la /usr/share/nftables.d/chain-pre/input/singctl-side.nft /usr/share/nftables.d/chain-pre/forward/singctl-side.nft
fw4 restart >/tmp/fw4-side-restart.log 2>&1 || { cat /tmp/fw4-side-restart.log; exit 1; }
nft list table inet singctl-side
nft list chain inet fw4 input
`)
		if !strings.Contains(fw4Persist, `iifname "eth0" accept comment "singctl-side"`) || !strings.Contains(fw4Persist, "masquerade") {
			t.Fatalf("expected side-rtr OpenWrt 24 fw4 restart persistence, got:\n%s", fw4Persist)
		}
	}

	mustNetNSSh(t, ctx, mainC, mgmtSock, "ping -c 1 -W 2 192.168.55.88 >/dev/null")
	{
		deadline := time.Now().Add(15 * time.Second)
		var lastC2 int
		var lastE2, lastDNSErr error
		var lastIPs string
		ready := false
		for time.Now().Before(deadline) {
			lastC2, _, lastE2 = probeNetNSHTTP(ctx, mainC, mgmtSock, "GET", "http://192.168.55.88:8090/api/gateway", "-", "")
			lastIPs, lastDNSErr = probeNetNSDNS(ctx, mainC, mgmtSock, "192.168.55.88:53", "app.example.com")
			if lastE2 == nil && lastC2 == 200 && lastDNSErr == nil && strings.Contains(lastIPs, "203.0.113.20") {
				ready = true
				break
			}
			time.Sleep(300 * time.Millisecond)
		}
		if !ready {
			sideDiag, _ := dockerExec(ctx, sideC, "ps w; netstat -lnup 2>/dev/null || cat /proc/net/tcp /proc/net/udp; cat /var/etc/dnsmasq.conf.* /tmp/dnsmasq*.log /tmp/singctl-web.log 2>/dev/null")
			wanDiag, _ := dockerExec(ctx, wanC, "cat /tmp/wan-dns.log 2>/dev/null; ps w")
			t.Fatalf("side-rtr ready check failed: c2=%d e2=%v ips=%q dnsErr=%v\n=== sideC ===\n%s\n=== wanC ===\n%s",
				lastC2, lastE2, lastIPs, lastDNSErr, sideDiag, wanDiag)
		}
	}

	// === 断言 1：main-rtr 启用 delegated 模式 ===
	code, body := mustNetNSJSON(t, ctx, mainC, mgmtSock, "POST", "http://192.168.55.1:8090/api/gateway", map[string]any{
		"mode":               "main",
		"workMode":           "delegated",
		"sideRouterIP":       "192.168.55.88",
		"sideRouterFailover": true,
	})
	if code != 200 {
		t.Fatalf("POST /api/gateway (delegated) failed: code=%d body=%s", code, body)
	}
	var gwResp gatewayModeResp
	if err := json.Unmarshal([]byte(body), &gwResp); err != nil {
		t.Fatalf("unmarshal delegated gateway response: %v (raw=%s)", err, body)
	}
	if gwResp.SideRouterStatus == nil || !gwResp.SideRouterStatus.Online || !gwResp.SideRouterStatus.WebUIReady || !gwResp.SideRouterStatus.DNSReady {
		t.Fatalf("expected sideRouterStatus online/webUiReady/dnsReady=true, got %+v (raw=%s)", gwResp.SideRouterStatus, body)
	}

	// === 断言 2：创建 DSA VLAN 8 (baidu_lan, side_router) + fw4 restart 持久化 ===
	vlanReq := vlan.SaveSegmentRequest{
		ID:          "baidu_lan",
		DisplayName: "办公分流网",
		VLANID:      8,
		IPAddr:      "192.168.89.1",
		Netmask:     "255.255.255.0",
		DHCPStart:   100,
		DHCPLimit:   150,
		LeaseTime:   "12h",
		ProxyMode:   vlan.ProxyModeSideRouter,
		Ports:       map[string]string{"lan3": vlan.PortModeAccess},
		Policy: vlan.SecurityPolicy{
			AllowWAN:         true,
			BlockRouterMgmt:  true,
			BlockUpstreamLAN: true,
		},
	}
	code, body = mustNetNSJSON(t, ctx, mainC, mgmtSock, "POST", "http://192.168.55.1:8090/api/vlan/apply", vlanReq)
	if code != 200 {
		t.Fatalf("POST /api/vlan/apply (side_router) failed: code=%d body=%s", code, body)
	}
	confirmCode, confirmBody := mustNetNSJSON(t, ctx, mainC, mgmtSock, "POST", "http://192.168.55.1:8090/api/safe-commit/confirm", map[string]string{})
	if confirmCode != 200 {
		t.Fatalf("POST /api/safe-commit/confirm failed: code=%d body=%s", confirmCode, confirmBody)
	}
	waitUntil(t, 15*time.Second, "br-lan.8, br-lan.1, ip rule 18810 and table 188 side route active", func() bool {
		out, err := dockerExec(ctx, mainC, "ip -4 addr show dev br-lan.8 2>/dev/null && ip -4 addr show dev br-lan.1 2>/dev/null && ip -4 rule show && ip -4 route show table 188 2>/dev/null")
		return err == nil &&
			strings.Contains(out, "192.168.89.1/24") &&
			strings.Contains(out, "192.168.55.1/24") &&
			strings.Contains(out, "from 192.168.89.0/24 lookup 188") &&
			strings.Contains(out, "default via 192.168.55.88 dev br-lan.1")
	})

	includeCheck := mustDockerExec(t, ctx, mainC, `
ls -la /usr/share/nftables.d/chain-pre/srcnat_lan/singctl-side-nomasq.nft /usr/share/nftables.d/chain-pre/forward/singctl-vlan-br-l2.nft
fw4 restart >/tmp/fw4-restart.log 2>&1 || { cat /tmp/fw4-restart.log; exit 1; }
nft list chain inet fw4 srcnat_lan
nft list chain inet fw4 forward
grep 'dhcp-range=' /var/etc/dnsmasq.conf.*
`)
	if !strings.Contains(includeCheck, "singctl-side-nomasq.nft") ||
		!strings.Contains(includeCheck, "singctl-vlan-br-l2.nft") ||
		strings.Count(includeCheck, "-rw-------") < 2 {
		t.Fatalf("expected 0600 perms on fw4 nft includes:\n%s", includeCheck)
	}
	nomasqIdx := strings.Index(includeCheck, `comment "singctl-side-nomasq"`)
	masqIdx := strings.Index(includeCheck, "masquerade")
	if nomasqIdx < 0 || masqIdx < 0 || !(nomasqIdx < masqIdx) {
		t.Fatalf("expected singctl-side-nomasq BEFORE masquerade in fw4 srcnat_lan after fw4 restart:\n%s", includeCheck)
	}
	if !strings.Contains(includeCheck, `comment "singctl-vlan-br-l2"`) {
		t.Fatalf("expected singctl-vlan-br-l2 in fw4 forward after fw4 restart:\n%s", includeCheck)
	}
	if !strings.Contains(includeCheck, "dhcp-range=") || !strings.Contains(includeCheck, "192.168.89.") {
		t.Fatalf("expected 192.168.89.x dhcp-range in dnsmasq config after restart:\n%s", includeCheck)
	}

	// === 断言 3：vlan-cli (192.168.89.137) 隔离性 + 跨网段 DNS + ICMP + HTTP 转发 ===
	mustNetNSSh(t, ctx, mainC, vlanSock, `
ip link set lo up
ip link set vlan0 up
ip addr add 192.168.89.137/24 dev vlan0
ip route replace default via 192.168.89.1
`)
	if code, _, err := probeNetNSHTTP(ctx, mainC, vlanSock, "GET", "http://192.168.89.1:8090/", "-", ""); err == nil && code > 0 {
		t.Fatalf("expected vlan-cli blocked from router mgmt 192.168.89.1:8090, got HTTP %d", code)
	}
	if code, _, err := probeNetNSHTTP(ctx, mainC, vlanSock, "GET", "http://192.168.55.50:8088/", "-", ""); err == nil && code > 0 {
		t.Fatalf("expected vlan-cli blocked from mgmt host 192.168.55.50:8088, got HTTP %d", code)
	}
	dnsIPs, err := probeNetNSDNS(ctx, mainC, vlanSock, "192.168.55.88:53", "app.example.com")
	if err != nil || !strings.Contains(dnsIPs, "203.0.113.20") {
		t.Fatalf("cross-subnet DNS @192.168.55.88 failed: ips=%q err=%v", dnsIPs, err)
	}
	mustNetNSSh(t, ctx, mainC, vlanSock, "ping -c 2 -W 2 203.0.113.20 >/dev/null")

	code, body, err = probeNetNSHTTP(ctx, mainC, vlanSock, "GET", "http://203.0.113.20:8080/", "-", "")
	if err != nil || code != 200 || !strings.Contains(body, "OK:public-wan:") {
		t.Fatalf("vlan-cli HTTP over side-rtr failed: code=%d body=%q err=%v", code, body, err)
	}
	if sideOpenWrt21 {
		redirOut := mustDockerExec(t, ctx, sideC, "iptables -w 2 -t nat -L SINGBOX_REDIR -n -v -x")
		redirHit := false
		for line := range strings.SplitSeq(redirOut, "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 3 && fields[2] == "REDIRECT" && fields[0] != "0" {
				redirHit = true
				break
			}
		}
		if !redirHit {
			t.Fatalf("expected non-zero SINGBOX_REDIR REDIRECT packet count on OpenWrt 21 side-rtr, got:\n%s", redirOut)
		}
	} else {
		nftOut := mustDockerExec(t, ctx, sideC, "nft list table inet sing-box")
		tproxyHit := false
		for line := range strings.SplitSeq(nftOut, "\n") {
			if strings.Contains(line, "tproxy") && strings.Contains(line, "packets ") && !strings.Contains(line, "packets 0 ") {
				tproxyHit = true
				break
			}
		}
		if !tproxyHit {
			t.Fatalf("expected non-zero table inet sing-box tproxy counter on OpenWrt 24 side-rtr, got:\n%s", nftOut)
		}
	}

	// === 断言 4：真实终端 IP 192.168.89.137 透传 + side-rtr SO_MARK 0x80000 PTR 反解 yunzhonnhedeMBP ===
	holdCtx, holdCancel := context.WithCancel(ctx)
	defer holdCancel()
	holdDone := make(chan error, 1)
	go func() {
		_, _, hErr := probeNetNSHTTP(holdCtx, mainC, vlanSock, "GET", "http://203.0.113.20:8080/hold", "-", "")
		holdDone <- hErr
	}()

	var lastConnsCode int
	var lastConnsBody string
	var lastConnsErr error
	connsReady := false
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); {
		lastConnsCode, lastConnsBody, lastConnsErr = probeHTTP(ctx, sideC, "GET", "http://127.0.0.1:9090/connections", "-", "")
		if lastConnsErr == nil && lastConnsCode == 200 && strings.Contains(lastConnsBody, "192.168.89.137") {
			connsReady = true
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if !connsReady {
		var hErr error
		select {
		case hErr = <-holdDone:
		default:
		}
		sDiag, _ := dockerExec(ctx, sideC, "cat /tmp/singbox-shim.log 2>/dev/null; nft list table inet sing-box 2>/dev/null || iptables -w 2 -t nat -S PREROUTING; nft list table inet singctl-side 2>/dev/null || iptables -w 2 -t nat -S SINGCTL_SIDE_NAT")
		mDiag, _ := dockerExec(ctx, mainC, "ip -4 route get from 192.168.89.137 iif br-lan.8 203.0.113.20 2>&1; ip -4 rule show; ip -4 route show table 188; nft list chain inet fw4 forward 2>/dev/null")
		wDiag, _ := dockerExec(ctx, wanC, "cat /tmp/wan-http.log 2>/dev/null")
		t.Fatalf("side-rtr Clash API missing 192.168.89.137: holdErr=%v code=%d err=%v body=%s\n=== sideC ===\n%s\n=== mainC ===\n%s\n=== wanC ===\n%s",
			hErr, lastConnsCode, lastConnsErr, lastConnsBody, sDiag, mDiag, wDiag)
	}

	var matchedDev *audit.DeviceSummary
	var lastAuditBody string
	var lastAuditCode int
	var lastAuditErr error
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); {
		lastAuditCode, lastAuditBody, lastAuditErr = probeNetNSHTTP(ctx, mainC, mgmtSock, "GET", "http://192.168.55.88:8090/api/audit", "-", "")
		if lastAuditErr == nil && lastAuditCode == 200 {
			var rep audit.Report
			if json.Unmarshal([]byte(lastAuditBody), &rep) == nil {
				for i := range rep.Devices {
					if rep.Devices[i].DeviceIP == "192.168.89.137" && rep.Devices[i].DeviceName == "yunzhonnhedeMBP" {
						devCopy := rep.Devices[i]
						matchedDev = &devCopy
						break
					}
				}
			}
		}
		if matchedDev != nil {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	if matchedDev == nil {
		mDNS, _ := dockerExec(ctx, mainC, "cat /tmp/dhcp.leases /var/etc/dnsmasq.conf.* /tmp/dnsmasq*.log 2>/dev/null; ps w; nft list chain inet fw4 input 2>/dev/null || true")
		sDNS, _ := dockerExec(ctx, sideC, "ps w; cat /proc/net/tcp /etc/singctl/singctl.yaml 2>/dev/null; cat /tmp/singctl-web.log /var/log/singctl* /tmp/singbox-shim.log 2>/dev/null; nft list chain inet fw4 input 2>/dev/null || iptables -w 2 -S INPUT 2>/dev/null")
		t.Fatalf("side-rtr /api/audit missing 192.168.89.137/yunzhonnhedeMBP: code=%d err=%v body=%s\n=== mainDNS ===\n%s\n=== sideCfg ===\n%s",
			lastAuditCode, lastAuditErr, lastAuditBody, mDNS, sDNS)
	}

	// === 断言 5：side-rtr 单设备禁外网开关更新 0600 config.json 并秒断活跃 /hold 连接 ===
	code, body = mustNetNSJSON(t, ctx, mainC, mgmtSock, "POST", "http://192.168.55.88:8090/api/audit/device-access", map[string]any{
		"deviceIp":      "192.168.89.137",
		"allowOverseas": false,
	})
	if code != 200 {
		t.Fatalf("POST /api/audit/device-access failed: code=%d body=%s", code, body)
	}
	var accResp audit.DeviceAccessResult
	if err := json.Unmarshal([]byte(body), &accResp); err != nil {
		t.Fatalf("unmarshal DeviceAccessResult: %v (raw=%s)", err, body)
	}
	if !accResp.OK || !accResp.SingBoxSynced || accResp.KilledConnections < 1 {
		t.Fatalf("expected singboxSynced=true and killedConnections>=1, got %+v (raw=%s)", accResp, body)
	}
	sbCheck := mustDockerExec(t, ctx, sideC, "ls -la /etc/sing-box/config.json && grep -c '192.168.89.137/32' /etc/sing-box/config.json")
	if !strings.Contains(sbCheck, "-rw-------") {
		t.Fatalf("expected 0600 perms on updated /etc/sing-box/config.json:\n%s", sbCheck)
	}
	select {
	case <-holdDone:
	case <-time.After(5 * time.Second):
		t.Fatal("expected active /hold connection to terminate promptly after Clash DELETE")
	}
	holdCancel()

	// === 断言 6：模拟 side-rtr 离线，main-rtr 自动摘除表 188 与 nft include，vlan-cli 回退主路由 WAN 直连 ===
	mustDockerExec(t, ctx, sideC, `
/etc/init.d/singctl-web stop >/dev/null 2>&1 || true
/usr/bin/singctl web stop >/dev/null 2>&1 || true
/etc/init.d/dnsmasq stop >/dev/null 2>&1 || true
killall singctl dnsmasq 2>/dev/null || true
`)
	waitUntil(t, 50*time.Second, "main-rtr SideRouterFailoverGuard suspends table 188 and cleans singctl-side-nomasq.nft", func() bool {
		out, e := dockerExec(ctx, mainC, `
ip -4 rule show
test ! -e /usr/share/nftables.d/chain-pre/srcnat_lan/singctl-side-nomasq.nft && echo "INCLUDE_REMOVED"
`)
		return e == nil && !strings.Contains(out, "lookup 188") && strings.Contains(out, "INCLUDE_REMOVED")
	})

	code, body, err = probeNetNSHTTP(ctx, mainC, vlanSock, "GET", "http://203.0.113.20:8080/", "-", "")
	if err != nil || code != 200 || !strings.Contains(body, "OK:public-wan:") {
		t.Fatalf("expected vlan-cli seamless fallback to main-rtr WAN direct, got code=%d body=%q err=%v", code, body, err)
	}
}

// TestOpenWrt21MainRouterFW3SideNoMasqPersistenceE2E 验证真实 OpenWrt 21.02 (fw3) 主路由的 singctl-side-nomasq 在 fw3 restart 后持久生效与清理。
func TestOpenWrt21MainRouterFW3SideNoMasqPersistenceE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping OpenWrt 21.02 main-router fw3 E2E in -short mode")
	}
	ctx := t.Context()
	requireDockerAndImage(t, ctx, openWrt21Image)

	repoRoot, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	workDir := t.TempDir()
	arch := detectImageGoArch(t, ctx, openWrt21Image)
	singctlBin := crossCompileSingCtl(t, ctx, repoRoot, workDir, arch)
	probeBin := buildProbeHelper(t, ctx, workDir, arch)
	cname := fmt.Sprintf("sc-fw3-main-%d", time.Now().UnixNano()%100000)

	t.Cleanup(func() {
		cleanCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		_, _ = dockerExec(cleanCtx, cname, `
/usr/bin/singctl web stop >/dev/null 2>&1 || true
killall netifd procd ubusd dnsmasq singctl >/dev/null 2>&1 || true
`)
		_ = exec.CommandContext(cleanCtx, "docker", "rm", "-f", cname).Run()
	})

	mustRun(t, ctx, "docker", "run", "-d", "--name", cname, "--hostname", cname, "--privileged",
		"--sysctl", "net.ipv4.ip_forward=1",
		"-v", singctlBin+":/usr/bin/singctl:ro",
		"-v", probeBin+":/usr/bin/vlan-probe:ro",
		openWrt21Image, "/bin/sh", "-c", "mkdir -p /var/run /var/lock /tmp/run /var/state && exec sleep 3600",
	)

	mustDockerExec(t, ctx, cname, `
set -e
rm -f /sbin/ujail /etc/board.json
mkdir -p /var/run/dnsmasq /var/lock /tmp/run /var/state /etc/singctl /etc/sing-box

ip link add lan1 type dummy && ip link set lan1 up
ip link add lan3 type dummy && ip link set lan3 up

cat > /etc/board.json <<'EOF'
{
  "model": { "id": "test,ow21-fw3", "name": "OpenWrt 21.02 FW3 Main E2E" },
  "network": {
    "lan": { "ports": ["lan1", "lan3"] },
    "wan": { "device": "eth0" }
  }
}
EOF

cat > /etc/config/network <<'EOF'
config interface 'loopback'
	option device 'lo'
	option proto 'static'
	option ipaddr '127.0.0.1'
	option netmask '255.0.0.0'

config interface 'lan'
	option device 'br-lan'
	option type 'bridge'
	list ifname 'lan1'
	list ifname 'lan3'
	option proto 'static'
	option ipaddr '192.168.55.1'
	option netmask '255.255.255.0'
EOF

cat > /etc/config/dhcp <<'EOF'
config dnsmasq
	option domainneeded '1'
	option leasefile '/tmp/dhcp.leases'

config dhcp 'lan'
	option interface 'lan'
	option start '100'
	option limit '150'
EOF

cat > /etc/config/wireless <<'EOF'
config wifi-device 'radio0'
	option type 'mac80211'
	option band '2g'
EOF

cat > /etc/config/firewall <<'EOF'
config defaults
	option input 'ACCEPT'
	option output 'ACCEPT'
	option forward 'ACCEPT'

config zone
	option name 'lan'
	list network 'lan'
	option input 'ACCEPT'
	option output 'ACCEPT'
	option forward 'ACCEPT'
	option masq '1'
EOF

cat > /etc/singctl/singctl.yaml <<'EOF'
singbox:
  config_path: /etc/sing-box/config.json
gateway:
  mode: main
  work_mode: delegated
  side_router_ip: 192.168.55.88
EOF
chmod 0600 /etc/singctl/singctl.yaml

/sbin/ubusd </dev/null >/tmp/ubusd.log 2>&1 &
sleep 1
/sbin/procd </dev/null >/tmp/procd.log 2>&1 &
sleep 1
/sbin/netifd </dev/null >/tmp/netifd.log 2>&1 &
sleep 2
fw3 restart >/tmp/fw3-init.log 2>&1 || { cat /tmp/fw3-init.log; exit 1; }
/usr/bin/singctl -c /etc/singctl/singctl.yaml web start -l 127.0.0.1:8090 </dev/null >/tmp/singctl-web.log 2>&1 || { cat /tmp/singctl-web.log; exit 1; }
`)

	waitUntil(t, 15*time.Second, "OpenWrt 21.02 WebUI ready", func() bool {
		c, _, e := probeHTTP(ctx, cname, "GET", "http://127.0.0.1:8090/api/vlan/overview", "-", "")
		return e == nil && c == 200
	})

	applyBody, _ := json.Marshal(vlan.SaveSegmentRequest{
		ID:        "baidu_lan",
		VLANID:    8,
		IPAddr:    "192.168.89.1",
		Netmask:   "255.255.255.0",
		DHCPStart: 100,
		DHCPLimit: 150,
		LeaseTime: "12h",
		ProxyMode: vlan.ProxyModeSideRouter,
		Ports:     map[string]string{"lan3": vlan.PortModeAccess},
		Policy: vlan.SecurityPolicy{
			AllowWAN:         true,
			BlockRouterMgmt:  true,
			BlockUpstreamLAN: true,
		},
	})
	code, body, err := probeHTTP(ctx, cname, "POST", "http://127.0.0.1:8090/api/vlan/apply", "-", string(applyBody))
	if err != nil || code != 200 {
		t.Fatalf("OpenWrt 21.02 POST /api/vlan/apply failed: code=%d body=%s err=%v", code, body, err)
	}
	confirmCode, confirmBody, confirmErr := probeHTTP(ctx, cname, "POST", "http://127.0.0.1:8090/api/safe-commit/confirm", "-", "{}")
	if confirmErr != nil || confirmCode != 200 {
		t.Fatalf("OpenWrt 21.02 POST /api/safe-commit/confirm failed: code=%d body=%s err=%v", confirmCode, confirmBody, confirmErr)
	}

	waitUntil(t, 10*time.Second, "vlan-br-l2.fw3.sh synced after async reload", func() bool {
		_, e := dockerExec(ctx, cname, "test -f /etc/singctl/vlan-br-l2.fw3.sh")
		return e == nil
	})
	fw3Out := mustDockerExec(t, ctx, cname, `
ls -la /etc/singctl/vlan-side-nomasq.fw3.sh /etc/singctl/vlan-br-l2.fw3.sh
uci get firewall.singctl_vlan_nomasq.path
uci get firewall.singctl_vlan_br_l2.path
fw3 restart >/tmp/fw3-restart.log 2>&1 || { cat /tmp/fw3-restart.log; exit 1; }
iptables -w 2 -t nat -S postrouting_lan_rule
iptables -w 2 -S FORWARD
`)
	if strings.Count(fw3Out, "-rw-------") < 2 ||
		!strings.Contains(fw3Out, "/etc/singctl/vlan-side-nomasq.fw3.sh") ||
		!strings.Contains(fw3Out, "/etc/singctl/vlan-br-l2.fw3.sh") ||
		!strings.Contains(fw3Out, "-A postrouting_lan_rule -s 192.168.89.0/24 -m comment --comment singctl-side-nomasq -j ACCEPT") ||
		!strings.Contains(fw3Out, "-A FORWARD -i br-lan -o br-lan -m comment --comment singctl-vlan-br-l2 -j ACCEPT") {
		t.Fatalf("expected OpenWrt 21.02 fw3 restart to preserve singctl-side-nomasq and singctl-vlan-br-l2 rules, got:\n%s", fw3Out)
	}

	code, body, err = probeHTTP(ctx, cname, "DELETE", "http://127.0.0.1:8090/api/vlan/segment/baidu_lan", "-", "")
	if err != nil || code != 200 {
		t.Fatalf("OpenWrt 21.02 DELETE /api/vlan/segment/baidu_lan failed: code=%d body=%s err=%v", code, body, err)
	}
	cleanOut := mustDockerExec(t, ctx, cname, `
fw3 restart >/tmp/fw3-clean-restart.log 2>&1 || true
iptables -w 2 -t nat -S postrouting_lan_rule
iptables -w 2 -S FORWARD
test ! -e /etc/singctl/vlan-side-nomasq.fw3.sh && echo "FW3_SCRIPT_REMOVED"
uci -q get firewall.singctl_vlan_nomasq || echo "FW3_UCI_REMOVED"
`)
	if strings.Contains(cleanOut, "singctl-side-nomasq") ||
		!strings.Contains(cleanOut, "FW3_SCRIPT_REMOVED") ||
		!strings.Contains(cleanOut, "FW3_UCI_REMOVED") ||
		!strings.Contains(cleanOut, "-A FORWARD -i br-lan -o br-lan -m comment --comment singctl-vlan-br-l2 -j ACCEPT") {
		t.Fatalf("expected OpenWrt 21.02 segment delete to clean fw3 nomasq include while preserving singctl-vlan-br-l2 on br-lan.1, got:\n%s", cleanOut)
	}
}
