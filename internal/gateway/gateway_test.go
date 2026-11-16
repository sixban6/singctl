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
	nft := BuildSideRouterNFT(ResolvedPlan{
		Mode:         ModeSide,
		MainRouterIP: "192.168.100.1",
		LANIP:        "192.168.100.2",
		LANCIDR:      "192.168.100.0/24",
		LANIface:     "eth0",
	})
	mustContain := []string{
		"table inet singctl-side",
		"th dport 53 tproxy to :7895 meta mark set 0x1 accept",
		"tcp flags syn tcp option maxseg size set rt mtu",
		`oifname "eth0" ip saddr 192.168.100.0/24 ip daddr != 192.168.100.0/24 masquerade`,
	}
	for _, want := range mustContain {
		if !strings.Contains(nft, want) {
			t.Fatalf("generated nft missing %q:\n%s", want, nft)
		}
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
			chain:        "input",
			wantSnippets: []string{`meta mark 0x1 accept comment "singctl-side"`},
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
	} {
		if !slices.Contains(executed, want) {
			t.Fatalf("expected %q to be executed, got:\n%s", want, strings.Join(executed, "\n"))
		}
	}
}
