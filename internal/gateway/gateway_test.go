package gateway

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"singctl/internal/config"
)

func TestParseProcNetRouteAndSuggestGateway(t *testing.T) {
	// /proc/net/route uses little-endian hex on x86/arm64: 192.168.100.1 -> 0164A8C0
	procSample := strings.Join([]string{
		"Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT",
		"eth0\t00000000\t0164A8C0\t0003\t0\t0\t0\t00000000\t0\t0\t0",
		"eth0\t0064A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0",
	}, "\n")

	iface, gw, ok := ParseProcNetRouteDefault(procSample)
	if !ok {
		t.Fatal("expected default route to be parsed")
	}
	if iface != "eth0" || gw != "192.168.100.1" {
		t.Fatalf("unexpected parsed route: iface=%q gw=%q", iface, gw)
	}

	// 场景 1：正常网关直接保留
	suggested, looped := DeriveSuggestedMainRouterIP("192.168.100.2/24", "192.168.100.1")
	if looped || suggested != "192.168.100.1" {
		t.Fatalf("expected 192.168.100.1 (looped=false), got %q (looped=%v)", suggested, looped)
	}

	// 场景 2：DHCP 误将旁路由自身默认网关指回本机 192.168.100.2 -> 标记自环并推导 .1
	suggested, looped = DeriveSuggestedMainRouterIP("192.168.100.2/24", "192.168.100.2")
	if !looped || suggested != "192.168.100.1" {
		t.Fatalf("expected self-loop fallback to 192.168.100.1 (looped=true), got %q (looped=%v)", suggested, looped)
	}

	// 场景 3：本机恰好占用了 .1 且无默认网关 -> 推导 .254 绝不返回自身
	suggested, looped = DeriveSuggestedMainRouterIP("192.168.100.1/24", "")
	if looped || suggested != "192.168.100.254" {
		t.Fatalf("expected .254 fallback when self is .1, got %q (looped=%v)", suggested, looped)
	}
}

func TestValidate_BlocksSelfLoopAndInjection(t *testing.T) {
	topo := TopologyInfo{
		LANIP:                 "192.168.100.2",
		LANCIDR:               "192.168.100.0/24",
		LANIface:              "eth0",
		CurrentGatewayIP:      "192.168.100.1",
		SuggestedMainRouterIP: "192.168.100.1",
	}

	// 1. 默认 main 模式允许空网关且不触发旁路由校验
	if _, err := ResolveAndValidate(config.GatewayConfig{}, topo); err != nil {
		t.Fatalf("main mode should pass validation: %v", err)
	}

	// 2. 非法模式名应拒绝（不允许隐式 auto）
	if _, err := ResolveAndValidate(config.GatewayConfig{Mode: "auto"}, topo); err == nil {
		t.Fatal("expected mode=auto to be rejected")
	}

	// 3. 旁路由自环 IP 必须拦截
	if _, err := ResolveAndValidate(config.GatewayConfig{
		Mode:         ModeSide,
		MainRouterIP: "192.168.100.2",
	}, topo); err == nil {
		t.Fatal("expected self-loop MainRouterIP == LANIP to be rejected")
	}

	// 4. 非法地址与命令注入拦截
	badInputs := []config.GatewayConfig{
		{Mode: ModeSide, MainRouterIP: "127.0.0.1"},
		{Mode: ModeSide, MainRouterIP: "224.0.0.1"},
		{Mode: ModeSide, MainRouterIP: "fe80::1"},
		{Mode: ModeSide, MainRouterIP: "192.168.100.1; id"},
		{Mode: ModeSide, MainRouterIP: "192.168.100.1", LANIface: "eth0; rm -rf /"},
	}
	for _, in := range badInputs {
		if _, err := ResolveAndValidate(in, topo); err == nil {
			t.Fatalf("expected invalid input %+v to fail validation", in)
		}
	}

	// 5. 合法旁路由参数解析成功
	plan, err := ResolveAndValidate(config.GatewayConfig{
		Mode:         ModeSide,
		MainRouterIP: "192.168.100.1",
	}, topo)
	if err != nil {
		t.Fatalf("valid side router config failed: %v", err)
	}
	if plan.Mode != ModeSide || plan.MainRouterIP != "192.168.100.1" || plan.LANIface != "eth0" || plan.LANCIDR != "192.168.100.0/24" {
		t.Fatalf("unexpected resolved plan: %+v", plan)
	}
}

func TestBuildSideRouterNFTAndSysctls(t *testing.T) {
	// 场景 A：无本地 53 监听（裸 Debian）-> 生成 prerouting :53 -> tproxy :7895 兜底规则
	nftIntercept := BuildSideRouterNFT(ResolvedPlan{
		Mode:              ModeSide,
		MainRouterIP:      "192.168.100.1",
		LANIP:             "192.168.100.2",
		LANCIDR:           "192.168.100.0/24",
		LANIface:          "eth0",
		InterceptLocalDNS: true,
	})
	for _, want := range []string{
		"table inet singctl-side",
		"th dport 53 tproxy to :7895 meta mark set 0x1 accept",
		"tcp flags syn tcp option maxseg size set rt mtu",
		`oifname "eth0" ip saddr 192.168.100.0/24 ip daddr != 192.168.100.0/24 masquerade`,
	} {
		if !strings.Contains(nftIntercept, want) {
			t.Fatalf("generated nft (InterceptLocalDNS=true) missing %q:\n%s", want, nftIntercept)
		}
	}

	// 场景 B：已有本地 dnsmasq 监听 :53（如 OpenWrt）-> 绝不拦截 :53，沿用主路由 fib local -> dnsmasq -> output -> sing-box 链路
	nftOpenWrt := BuildSideRouterNFT(ResolvedPlan{
		Mode:              ModeSide,
		MainRouterIP:      "192.168.100.1",
		LANIP:             "192.168.100.2",
		LANCIDR:           "192.168.100.0/24",
		LANIface:          "br-lan",
		InterceptLocalDNS: false,
	})
	if strings.Contains(nftOpenWrt, "dport 53") || strings.Contains(nftOpenWrt, "chain prerouting") {
		t.Fatalf("OpenWrt with local :53 listener must NOT hijack :53 in prerouting (avoids EADDRINUSE), got:\n%s", nftOpenWrt)
	}
	if !strings.Contains(nftOpenWrt, `oifname "br-lan" ip saddr 192.168.100.0/24 ip daddr != 192.168.100.0/24 masquerade`) {
		t.Fatalf("OpenWrt nft missing masquerade rule:\n%s", nftOpenWrt)
	}

	sysctls := BuildSideRouterSysctls("br-lan", true)
	keys := make([]string, 0, len(sysctls))
	for _, kv := range sysctls {
		keys = append(keys, kv.Key+"="+kv.Value)
	}
	for _, want := range []string{
		"net.ipv4.ip_forward=1",
		"net.ipv4.conf.all.rp_filter=0",
		"net.ipv4.conf.br-lan.rp_filter=0",
		"net.ipv4.conf.all.send_redirects=0",
		"net.ipv4.conf.br-lan.send_redirects=0",
		"net.bridge.bridge-nf-call-iptables=0",
		"net.bridge.bridge-nf-call-ip6tables=0",
	} {
		if !slices.Contains(keys, want) {
			t.Fatalf("missing sysctl %q in %v", want, keys)
		}
	}
}

func TestController_MainModeDoesNotInjectSideRules(t *testing.T) {
	var executed []string
	ctrl := &Controller{
		StateDir: t.TempDir(),
		Prober: func() TopologyInfo {
			return TopologyInfo{
				LANIP:                 "192.168.100.2",
				LANCIDR:               "192.168.100.0/24",
				LANIface:              "eth0",
				CurrentGatewayIP:      "192.168.100.1",
				SuggestedMainRouterIP: "192.168.100.1",
			}
		},
		Exec: func(name string, args ...string) ([]byte, error) {
			executed = append(executed, name+" "+strings.Join(args, " "))
			return nil, nil
		},
	}

	if err := ctrl.Apply(t.Context(), config.GatewayConfig{Mode: ModeMain}); err != nil {
		t.Fatalf("Apply(ModeMain) failed: %v", err)
	}
	for _, cmd := range executed {
		if strings.Contains(cmd, "route replace default") || strings.Contains(cmd, "nft -f") {
			t.Fatalf("main mode must NEVER apply side-router route or nft rules, got command: %s", cmd)
		}
	}
}

func TestController_FW4IncludePersistenceAndCleanup(t *testing.T) {
	fw4Root := t.TempDir()
	stateDir := t.TempDir()

	ctrl := &Controller{
		StateDir:       stateDir,
		FW4IncludeRoot: fw4Root,
		Prober: func() TopologyInfo {
			return TopologyInfo{
				LANIP:                 "192.168.100.2",
				LANCIDR:               "192.168.100.0/24",
				LANIface:              "br-lan",
				CurrentGatewayIP:      "192.168.100.1",
				SuggestedMainRouterIP: "192.168.100.1",
			}
		},
		Exec: func(name string, args ...string) ([]byte, error) {
			return nil, nil
		},
	}

	if err := ctrl.Apply(t.Context(), config.GatewayConfig{
		Mode:         ModeSide,
		MainRouterIP: "192.168.100.1",
	}); err != nil {
		t.Fatalf("Apply(ModeSide) failed: %v", err)
	}

	checks := []struct {
		chain        string
		wantSnippets []string
	}{
		{
			chain: "input",
			wantSnippets: []string{
				`meta mark 0x1 accept comment "singctl-side"`,
				`meta mark 0x2 accept comment "singctl-side"`,
				`iifname "br-lan" accept comment "singctl-side"`,
			},
		},
		{
			chain: "forward",
			wantSnippets: []string{
				`iifname "br-lan" accept comment "singctl-side"`,
				`oifname "br-lan" accept comment "singctl-side"`,
			},
		},
	}

	for _, tc := range checks {
		incPath := filepath.Join(fw4Root, "chain-pre", tc.chain, fw4IncludeFileName)
		st, err := os.Stat(incPath)
		if err != nil {
			t.Fatalf("expected fw4 include %s to exist: %v", incPath, err)
		}
		if st.Mode().Perm() != 0600 {
			t.Fatalf("expected fw4 include %s mode 0600, got %04o", incPath, st.Mode().Perm())
		}
		data, err := os.ReadFile(incPath)
		if err != nil {
			t.Fatalf("read fw4 include %s: %v", incPath, err)
		}
		content := string(data)
		for _, want := range tc.wantSnippets {
			if !strings.Contains(content, want) {
				t.Fatalf("fw4 include %s missing %q:\n%s", incPath, want, content)
			}
		}
	}

	if err := ctrl.Teardown(t.Context()); err != nil {
		t.Fatalf("Teardown failed: %v", err)
	}
	for _, tc := range checks {
		incPath := filepath.Join(fw4Root, "chain-pre", tc.chain, fw4IncludeFileName)
		if _, err := os.Stat(incPath); !os.IsNotExist(err) {
			t.Fatalf("expected fw4 include %s to be removed after Teardown, got err: %v", incPath, err)
		}
	}
}

func TestController_SideModeHealsProxyTableThrowRoutes(t *testing.T) {
	var executed []string
	ctrl := &Controller{
		StateDir:       t.TempDir(),
		FW4IncludeRoot: t.TempDir(),
		Prober: func() TopologyInfo {
			return TopologyInfo{
				LANIP:                 "192.168.100.2",
				LANCIDR:               "192.168.100.0/24",
				LANIface:              "eth0",
				CurrentGatewayIP:      "192.168.100.1",
				SuggestedMainRouterIP: "192.168.100.1",
			}
		},
		Exec: func(name string, args ...string) ([]byte, error) {
			cmd := name + " " + strings.Join(args, " ")
			executed = append(executed, cmd)
			if cmd == "ip -4 route show table 100" {
				return []byte("local default dev lo scope host\n"), nil
			}
			return nil, nil
		},
	}

	if err := ctrl.Apply(t.Context(), config.GatewayConfig{
		Mode:         ModeSide,
		MainRouterIP: "192.168.100.1",
	}); err != nil {
		t.Fatalf("Apply(ModeSide) failed: %v", err)
	}

	for _, want := range []string{
		"ip -4 route replace throw 192.168.0.0/16 table 100",
		"ip -4 route replace throw 100.64.0.0/10 table 100",
		"ip -4 route replace throw 192.168.100.0/24 table 100",
		"ip -4 route replace local default dev lo table 101",
	} {
		if !slices.Contains(executed, want) {
			t.Fatalf("expected %q to be executed, got:\n%s", want, strings.Join(executed, "\n"))
		}
	}
}

func TestParseProcNetUDPHasLANPort53AndResolvSelfHeal(t *testing.T) {
	// 1. 仅 127.0.0.53:53 (little-endian: 3500007F:0035) 回环监听 -> 不冲突，返回 false
	stubOnly := "  sl  local_address rem_address   st\n   1: 3500007F:0035 00000000:0000 07\n"
	if ParseProcNetUDPHasLANPort53("192.168.100.2", stubOnly, "") {
		t.Fatal("expected systemd-resolved loopback 127.0.0.53:53 to return false")
	}

	// 2. OpenWrt dnsmasq 0.0.0.0:53 (00000000:0035) -> 返回 true
	wildcardV4 := "  sl  local_address rem_address   st\n   1: 00000000:0035 00000000:0000 07\n"
	if !ParseProcNetUDPHasLANPort53("192.168.100.2", wildcardV4, "") {
		t.Fatal("expected wildcard 0.0.0.0:53 listener to return true")
	}

	// 3. OpenWrt resolv.conf.auto 被 DHCP 污染为旁路由本机 IP (192.168.100.2) 时自动修复并在卸载时还原
	tmp := t.TempDir()
	resolvAuto := filepath.Join(tmp, "resolv.conf.auto")
	origContent := "nameserver 192.168.100.2\nnameserver 127.0.0.1\n"
	if err := os.WriteFile(resolvAuto, []byte(origContent), 0644); err != nil {
		t.Fatal(err)
	}

	ctrl := &Controller{
		StateDir:        filepath.Join(tmp, "state"),
		FW4IncludeRoot:  filepath.Join(tmp, "fw4"),
		ResolvGuardPath: resolvAuto,
		Prober: func() TopologyInfo {
			return TopologyInfo{
				LANIP:               "192.168.100.2",
				LANCIDR:             "192.168.100.0/24",
				LANIface:            "br-lan",
				CurrentGatewayIP:    "192.168.100.1",
				HasLocalDNSListener: true,
			}
		},
		Exec: func(name string, args ...string) ([]byte, error) {
			return nil, nil
		},
	}

	if err := ctrl.Apply(t.Context(), config.GatewayConfig{Mode: ModeSide, MainRouterIP: "192.168.100.1"}); err != nil {
		t.Fatalf("Apply failed: %v", err)
	}
	healed, err := os.ReadFile(resolvAuto)
	if err != nil || !strings.Contains(string(healed), "223.5.5.5") {
		t.Fatalf("expected resolv.conf.auto to be healed with 223.5.5.5, got %q (err=%v)", string(healed), err)
	}

	if err := ctrl.Teardown(t.Context()); err != nil {
		t.Fatalf("Teardown failed: %v", err)
	}
	restored, err := os.ReadFile(resolvAuto)
	if err != nil || string(restored) != origContent {
		t.Fatalf("expected resolv.conf.auto restored to %q, got %q (err=%v)", origContent, string(restored), err)
	}
}

func TestController_SideModeConvergesPrivateDNSUpstream(t *testing.T) {
	// 旁路由 TProxy 表 100 含 RFC1918 throw 逃生路由：若 dnsmasq 上游仍是私网主路由（如 192.168.100.1），
	// 其 :53 报文会命中 throw 明文外发绕过 sing-box/AdGuard Home（甚至与主路由 DNS 互指死循环），
	// 必须收敛为公网引导 DNS；同时 CGNAT 上游（Tailscale MagicDNS）保持不变。
	tmp := t.TempDir()
	resolvAuto := filepath.Join(tmp, "resolv.conf.auto")

	newCtrl := func() *Controller {
		return &Controller{
			StateDir:        filepath.Join(tmp, "state"),
			FW4IncludeRoot:  filepath.Join(tmp, "fw4"),
			ResolvGuardPath: resolvAuto,
			Prober: func() TopologyInfo {
				return TopologyInfo{
					LANIP:               "192.168.100.2",
					LANCIDR:             "192.168.100.0/24",
					LANIface:            "br-lan",
					CurrentGatewayIP:    "192.168.100.1",
					HasLocalDNSListener: true,
				}
			},
			Exec: func(name string, args ...string) ([]byte, error) {
				return nil, nil
			},
		}
	}

	// 1) 私网网关上游 -> 必须收敛为公网引导 DNS
	origPrivate := "nameserver 192.168.100.1\n"
	if err := os.WriteFile(resolvAuto, []byte(origPrivate), 0644); err != nil {
		t.Fatal(err)
	}
	ctrl := newCtrl()
	if err := ctrl.Apply(t.Context(), config.GatewayConfig{Mode: ModeSide, MainRouterIP: "192.168.100.1"}); err != nil {
		t.Fatalf("Apply failed: %v", err)
	}
	healed, err := os.ReadFile(resolvAuto)
	if err != nil || !strings.Contains(string(healed), "223.5.5.5") {
		t.Fatalf("expected private-gateway upstream to converge to 223.5.5.5, got %q (err=%v)", string(healed), err)
	}
	if strings.Contains(string(healed), "192.168.100.1") {
		t.Fatalf("private gateway upstream must be removed, got %q", string(healed))
	}
	if err := ctrl.Teardown(t.Context()); err != nil {
		t.Fatalf("Teardown failed: %v", err)
	}
	restored, err := os.ReadFile(resolvAuto)
	if err != nil || string(restored) != origPrivate {
		t.Fatalf("expected resolv.conf.auto restored to %q, got %q (err=%v)", origPrivate, string(restored), err)
	}

	// 2) CGNAT（Tailscale MagicDNS）上游 -> 必须原样保留，不能被误收敛
	origCGNAT := "nameserver 100.100.100.100\n"
	if err := os.WriteFile(resolvAuto, []byte(origCGNAT), 0644); err != nil {
		t.Fatal(err)
	}
	ctrl2 := newCtrl()
	if err := ctrl2.Apply(t.Context(), config.GatewayConfig{Mode: ModeSide, MainRouterIP: "192.168.100.1"}); err != nil {
		t.Fatalf("Apply failed: %v", err)
	}
	kept, err := os.ReadFile(resolvAuto)
	if err != nil || string(kept) != origCGNAT {
		t.Fatalf("expected CGNAT upstream to be preserved, got %q (err=%v)", string(kept), err)
	}
	if err := ctrl2.Teardown(t.Context()); err != nil {
		t.Fatalf("Teardown failed: %v", err)
	}

	// 3) 非 OpenWrt (Debian/Ubuntu) /etc/resolv.conf 场景：私网上游同样收敛为 223.5.5.5，而本机 stub 127.0.0.53 保持不变
	debianResolv := filepath.Join(tmp, "resolv.conf")
	newDebianCtrl := func() *Controller {
		return &Controller{
			StateDir:        filepath.Join(tmp, "state-deb"),
			FW4IncludeRoot:  filepath.Join(tmp, "fw4-deb"),
			ResolvGuardPath: debianResolv,
			Prober: func() TopologyInfo {
				return TopologyInfo{
					LANIP:               "192.168.100.2",
					LANCIDR:             "192.168.100.0/24",
					LANIface:            "eth0",
					CurrentGatewayIP:    "192.168.100.1",
					HasLocalDNSListener: false,
				}
			},
			Exec: func(name string, args ...string) ([]byte, error) {
				return nil, nil
			},
		}
	}

	if err := os.WriteFile(debianResolv, []byte("nameserver 192.168.100.1\n"), 0644); err != nil {
		t.Fatal(err)
	}
	debCtrl := newDebianCtrl()
	if err := debCtrl.Apply(t.Context(), config.GatewayConfig{Mode: ModeSide, MainRouterIP: "192.168.100.1"}); err != nil {
		t.Fatalf("Debian Apply failed: %v", err)
	}
	debHealed, err := os.ReadFile(debianResolv)
	if err != nil || !strings.Contains(string(debHealed), "223.5.5.5") || strings.Contains(string(debHealed), "192.168.100.1") {
		t.Fatalf("expected Debian private resolv.conf to converge to 223.5.5.5, got %q (err=%v)", string(debHealed), err)
	}
	_ = debCtrl.Teardown(t.Context())

	origStub := "nameserver 127.0.0.53\n"
	if err := os.WriteFile(debianResolv, []byte(origStub), 0644); err != nil {
		t.Fatal(err)
	}
	debCtrlStub := newDebianCtrl()
	if err := debCtrlStub.Apply(t.Context(), config.GatewayConfig{Mode: ModeSide, MainRouterIP: "192.168.100.1"}); err != nil {
		t.Fatalf("Debian stub Apply failed: %v", err)
	}
	keptStub, err := os.ReadFile(debianResolv)
	if err != nil || string(keptStub) != origStub {
		t.Fatalf("expected Debian loopback stub 127.0.0.53 to be preserved, got %q (err=%v)", string(keptStub), err)
	}
	_ = debCtrlStub.Teardown(t.Context())
}
