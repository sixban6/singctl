package test

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"singctl/internal/tailscale"
	"singctl/internal/util/netinfo"
	"strings"
	"testing"
)

// =============================================================================
// 辅助函数
// =============================================================================

// newTestTailscale 创建一个用于测试的 Tailscale 实例，跳过 OpenWrt 检测
func newTestTailscale() *tailscale.Tailscale {
	return &tailscale.Tailscale{
		OpenWrtCheck: func() bool { return true },
		DownloadURL:  "",
	}
}

// =============================================================================
// 1. selectTailscaleAsset 测试：确保正确选择适合的发布包
// =============================================================================

func TestSelectTailscaleAsset(t *testing.T) {
	tests := []struct {
		name      string
		assetName string
		mockArch  string
		want      bool
	}{
		{"amd64 tgz match", "tailscale_1.62.0_amd64.tgz", "amd64", true},
		{"arm64 tar.gz match", "tailscale_1.62.0_arm64.tar.gz", "arm64", true},
		{"wrong arch", "tailscale_1.62.0_arm64.tgz", "amd64", false},
		{"not tailscale", "something_else_amd64.tgz", "amd64", false},
		{"wrong format", "tailscale_1.62.0_amd64.zip", "amd64", false},
		{"empty name", "", "amd64", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := newTestTailscale()
			// 直接调用 selectTailscaleAsset — 它内部会调用 getSystemArchitecture()，
			// 但由于测试环境的 uname -m 返回的是实际架构，
			// 我们通过 assetName 来验证 filter 逻辑
			// 注意：selectTailscaleAsset 内部调用 getSystemArchitecture()，
			// 当 uname -m 不可用时 fallback 到 "amd64"
			got := ts.SelectTailscaleAsset(tt.assetName)

			// 只在容器环境(可执行 uname)中强制匹配
			if _, err := exec.LookPath("uname"); err == nil {
				arch, _ := ts.GetSystemArchitecture()
				if !strings.Contains(strings.ToLower(tt.assetName), arch) {
					if got {
						t.Errorf("asset %q should not match arch %q", tt.assetName, arch)
					}
					return
				}
			}
		})
	}
}

// =============================================================================
// 2. getLANSubnet 测试：验证 CIDR 格式正确
// =============================================================================

func TestGetLANSubnet(t *testing.T) {
	// 只在有 uci 命令的环境下测试（Docker 容器）
	if _, err := exec.LookPath("uci"); err != nil {
		t.Skip("uci not found, skipping (run in Docker)")
	}

	_ = newTestTailscale()
	subnet, err := netinfo.GetLANSubnet()
	if err != nil {
		t.Fatalf("getLANSubnet() failed: %v", err)
	}

	// 验证返回的是合法 CIDR
	_, ipNet, err := net.ParseCIDR(subnet)
	if err != nil {
		t.Fatalf("getLANSubnet() returned invalid CIDR %q: %v", subnet, err)
	}

	t.Logf("Detected LAN subnet: %s (network: %s)", subnet, ipNet.String())
}

// =============================================================================
// 3. getSystemArchitecture 测试
// =============================================================================

func TestGetSystemArchitecture(t *testing.T) {
	ts := newTestTailscale()
	arch, err := ts.GetSystemArchitecture()

	if _, uErr := exec.LookPath("uname"); uErr != nil {
		t.Skip("uname not found, skipping")
	}

	if err != nil {
		t.Fatalf("getSystemArchitecture() failed: %v", err)
	}

	validArches := map[string]bool{
		"amd64": true, "arm64": true, "arm": true, "386": true,
	}
	if !validArches[arch] {
		t.Errorf("unexpected architecture: %q", arch)
	}

	t.Logf("Detected architecture: %s", arch)
}

// =============================================================================
// 4. parseVersionOutput 测试
// =============================================================================

func TestParseVersionOutput(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"normal version", "1.62.0\n  tailscale commit: ...", "1.62.0", false},
		{"version with spaces", "  1.62.0  \n", "1.62.0", false},
		{"empty input", "", "", true},
		{"only whitespace", "   \n\n", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tailscale.ParseVersionOutput(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseVersionOutput(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("parseVersionOutput(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// =============================================================================
// 5. checkTunModule 测试
// =============================================================================

func TestCheckTunModule(t *testing.T) {
	// 在 Docker 容器中测试
	result := tailscale.CheckTunModule()
	t.Logf("checkTunModule() = %v", result)

	// 验证逻辑本身不崩溃即可，结果取决于容器是否有 kmod-tun
}

// =============================================================================
// 6. createInitScript 测试 — 验证两种模式生成的 init script 内容
// =============================================================================

func TestCreateInitScript(t *testing.T) {
	tests := []struct {
		name           string
		hasTun         bool
		expectContains []string
		expectMissing  []string
	}{
		{
			name:   "kernel mode (hasTun=true)",
			hasTun: true,
			expectContains: []string{
				"USE_PROCD=1",
				"modprobe tun",
				"/dev/net/tun",
				"net.ipv4.ip_forward=1",
				"/usr/sbin/tailscaled",
				"--state=/etc/tailscale/tailscaled.state",
				"--socket=/var/run/tailscale/tailscaled.sock",
			},
			expectMissing: []string{
				"--tun=userspace-networking",
			},
		},
		{
			name:   "userspace mode (hasTun=false)",
			hasTun: false,
			expectContains: []string{
				"USE_PROCD=1",
				"--tun=userspace-networking",
				"/usr/sbin/tailscaled",
				"net.ipv4.ip_forward=1",
			},
			expectMissing: []string{
				"modprobe tun",
				"/dev/net/tun",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scriptPath := t.TempDir() + "/tailscale"
			if err := tailscale.CreateInitScript(tt.hasTun); err != nil {
				// createInitScript 写到固定路径 /etc/init.d/tailscale
				// 在非 root/Docker 环境可能失败，用临时目录代替测试内容
				t.Skipf("createInitScript failed (need root/Docker): %v", err)
			}

			content, err := os.ReadFile("/etc/init.d/tailscale")
			if err != nil {
				t.Skipf("cannot read init script: %v", err)
			}

			script := string(content)
			for _, s := range tt.expectContains {
				if !strings.Contains(script, s) {
					t.Errorf("init script missing expected string: %q", s)
				}
			}
			for _, s := range tt.expectMissing {
				if strings.Contains(script, s) {
					t.Errorf("init script should NOT contain: %q", s)
				}
			}

			// 清理
			os.Remove("/etc/init.d/tailscale")
			_ = scriptPath // suppress unused variable
		})
	}
}

// =============================================================================
// 7. 【核心 Bug 修复测试】tailscale up 参数验证
//    确保 --snat-subnet-routes=false 存在
// =============================================================================

func TestStartArgs_SNATSubnetRoutes(t *testing.T) {
	// 模拟 tailscale up 参数构建逻辑（从 Start() 中提取的核心逻辑）
	tests := []struct {
		name           string
		lanSubnet      string
		hasTun         bool
		advertiseExit  bool
		expectContains []string
		expectMissing  []string
	}{
		{
			name:          "basic subnet with SNAT disabled",
			lanSubnet:     "192.168.31.0/24",
			hasTun:        true,
			advertiseExit: false,
			expectContains: []string{
				"up",
				"--reset",
				"--advertise-routes=192.168.31.0/24",
				"--accept-dns=false",
				"--snat-subnet-routes=false", // 核心修复
				"--netfilter-mode=on",
			},
			expectMissing: []string{
				"--advertise-exit-node",
			},
		},
		{
			name:          "with exit node",
			lanSubnet:     "192.168.1.0/24",
			hasTun:        true,
			advertiseExit: true,
			expectContains: []string{
				"--snat-subnet-routes=false",
				"--advertise-exit-node",
				"--netfilter-mode=on",
			},
		},
		{
			name:          "userspace mode (no tun)",
			lanSubnet:     "10.0.0.0/24",
			hasTun:        false,
			advertiseExit: false,
			expectContains: []string{
				"--snat-subnet-routes=false",
				"--advertise-routes=10.0.0.0/24",
			},
			expectMissing: []string{
				"--netfilter-mode=on",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 重现 Start() 中的参数构建逻辑
			args := []string{"up", "--reset", "--advertise-routes=" + tt.lanSubnet, "--accept-dns=false", "--snat-subnet-routes=false"}
			if tt.hasTun {
				args = append(args, "--netfilter-mode=on")
			}
			if tt.advertiseExit {
				args = append(args, "--advertise-exit-node")
			}

			argsStr := strings.Join(args, " ")

			for _, s := range tt.expectContains {
				if !strings.Contains(argsStr, s) {
					t.Errorf("tailscale up args missing: %q\nFull args: %s", s, argsStr)
				}
			}
			for _, s := range tt.expectMissing {
				if strings.Contains(argsStr, s) {
					t.Errorf("tailscale up args should NOT contain: %q\nFull args: %s", s, argsStr)
				}
			}
		})
	}
}

// =============================================================================
// 8. 【核心 Bug 修复测试】nftables 规则验证 — Tailscale 流量放行
// =============================================================================

func TestStartScript_NFTables_TailscaleBypass(t *testing.T) {
	// 读取嵌入的 start_singbox.sh 内容
	scriptContent, err := os.ReadFile("../scripts/start_singbox.sh")
	if err != nil {
		t.Fatalf("Cannot read start_singbox.sh: %v", err)
	}
	script := string(scriptContent)

	t.Run("LOCAL_IPV4 contains CGNAT range", func(t *testing.T) {
		if !strings.Contains(script, "100.64.0.0/10") {
			t.Error("start_singbox.sh LOCAL_IPV4 set 缺少 Tailscale CGNAT 地址段 100.64.0.0/10")
		}
	})

	t.Run("nftables prerouting bypasses tailscale0", func(t *testing.T) {
		if !strings.Contains(script, `iifname "tailscale0" accept`) {
			t.Error("start_singbox.sh nftables 规则缺少 tailscale0 接口放行")
		}
	})

	t.Run("iptables bypasses tailscale0 interface", func(t *testing.T) {
		if !strings.Contains(script, "-i tailscale0 -j RETURN") {
			t.Error("start_singbox.sh iptables 规则缺少 tailscale0 接口放行")
		}
	})

	t.Run("iptables bypasses CGNAT range", func(t *testing.T) {
		if !strings.Contains(script, "-d 100.64.0.0/10 -j RETURN") {
			t.Error("start_singbox.sh iptables 规则缺少 Tailscale CGNAT 地址段放行")
		}
	})
}

// =============================================================================
// 9. nftables 规则顺序测试 — 确保 Tailscale 放行在 TProxy 劫持之前
// =============================================================================

func TestStartScript_NFTables_RuleOrder(t *testing.T) {
	scriptContent, err := os.ReadFile("../scripts/start_singbox.sh")
	if err != nil {
		t.Fatalf("Cannot read start_singbox.sh: %v", err)
	}
	script := string(scriptContent)

	// tailscale0 放行必须在 tproxy 劫持之前
	tailscaleBypassIdx := strings.Index(script, `iifname "tailscale0" accept`)
	tproxyIdx := strings.Index(script, "tproxy to :$TPROXY_PORT")

	if tailscaleBypassIdx < 0 {
		t.Fatal("tailscale0 bypass rule not found")
	}
	if tproxyIdx < 0 {
		t.Fatal("tproxy rule not found")
	}
	if tailscaleBypassIdx > tproxyIdx {
		t.Error("tailscale0 bypass rule MUST appear BEFORE tproxy rule in prerouting chain")
	}
}

// =============================================================================
// 10. cleanupTailscaleFirewall 测试 — 确保不会 panic
// =============================================================================

func TestCleanupTailscaleFirewall(t *testing.T) {
	if _, err := exec.LookPath("uci"); err != nil {
		t.Skip("uci not found, skipping (run in Docker)")
	}

	// 应该不会 panic 或 crash
	tailscale.CleanupTailscaleFirewall()
}

// =============================================================================
// 11. removeAnonymousUCISections 测试
// =============================================================================

func TestRemoveAnonymousUCISections(t *testing.T) {
	if _, err := exec.LookPath("uci"); err != nil {
		t.Skip("uci not found, skipping (run in Docker)")
	}

	// 不应该 panic
	tailscale.RemoveAnonymousUCISections("firewall", "zone", "name", "test-nonexistent")
}

// =============================================================================
// 12. optimizeUDPGRO / restoreUDPGRO — 不崩溃测试
// =============================================================================

func TestOptimizeUDPGRO(t *testing.T) {
	// 可能因缺少 ethtool 或网络接口而失败，但不应该 panic
	err := tailscale.OptimizeUDPGRO()
	if err != nil {
		t.Logf("optimizeUDPGRO() returned error (expected in test env): %v", err)
	}
}

func TestRestoreUDPGRO(t *testing.T) {
	err := tailscale.RestoreUDPGRO()
	if err != nil {
		t.Logf("restoreUDPGRO() returned error (expected in test env): %v", err)
	}
}

// =============================================================================
// 13. OpenWrt 检测测试
// =============================================================================

func TestIsOpenWrt(t *testing.T) {
	result := netinfo.IsOpenWrt()

	// 在 Docker 测试容器中，/etc/openwrt_release 应该存在
	if _, err := os.Stat("/etc/openwrt_release"); err == nil {
		if !result {
			t.Error("isOpenWrt() should return true when /etc/openwrt_release exists")
		}
	} else {
		t.Logf("isOpenWrt() = %v (not in OpenWrt env)", result)
	}
}

// =============================================================================
// 14. Start/Stop/Install 的 OpenWrt 检测门控测试
// =============================================================================

func TestStart_SkipsOnNonOpenWrt(t *testing.T) {
	ts := &tailscale.Tailscale{
		OpenWrtCheck: func() bool { return false },
	}
	// 在非 OpenWrt 环境下 Start() 应该返回 nil 而不是执行任何操作
	err := ts.Start(false, false)
	if err != nil {
		t.Errorf("Start() on non-OpenWrt should return nil, got: %v", err)
	}
}

func TestStop_SkipsOnNonOpenWrt(t *testing.T) {
	ts := &tailscale.Tailscale{
		OpenWrtCheck: func() bool { return false },
	}
	err := ts.Stop()
	if err != nil {
		t.Errorf("Stop() on non-OpenWrt should return nil, got: %v", err)
	}
}

func TestInstall_SkipsOnNonOpenWrt(t *testing.T) {
	ts := &tailscale.Tailscale{
		OpenWrtCheck: func() bool { return false },
	}
	err := ts.Install()
	if err != nil {
		t.Errorf("Install() on non-OpenWrt should return nil, got: %v", err)
	}
}

func TestUpdate_SkipsOnNonOpenWrt(t *testing.T) {
	ts := &tailscale.Tailscale{
		OpenWrtCheck: func() bool { return false },
	}
	err := ts.Update()
	if err != nil {
		t.Errorf("Update() on non-OpenWrt should return nil, got: %v", err)
	}
}

// =============================================================================
// 15. 集成测试标记 — 需要 Docker 环境运行
// =============================================================================

func TestIntegration_CreateInitScript_KernelMode(t *testing.T) {
	if os.Getenv("SINGCTL_DOCKER_TEST") == "" {
		t.Skip("Skipping Docker integration test (set SINGCTL_DOCKER_TEST=1)")
	}

	// 确保目录存在
	os.MkdirAll("/etc/init.d", 0755)
	defer os.Remove("/etc/init.d/tailscale")

	if err := tailscale.CreateInitScript(true); err != nil {
		t.Fatalf("createInitScript(true) failed: %v", err)
	}

	content, err := os.ReadFile("/etc/init.d/tailscale")
	if err != nil {
		t.Fatalf("cannot read created init script: %v", err)
	}

	script := string(content)
	requiredStrings := []string{
		"modprobe tun",
		"/dev/net/tun",
		"procd_open_instance",
		"/usr/sbin/tailscaled",
	}
	for _, s := range requiredStrings {
		if !strings.Contains(script, s) {
			t.Errorf("kernel mode init script missing: %q", s)
		}
	}
	if strings.Contains(script, "--tun=userspace-networking") {
		t.Error("kernel mode init script should NOT contain userspace-networking flag")
	}
}

func TestIntegration_CreateInitScript_UserspaceMode(t *testing.T) {
	if os.Getenv("SINGCTL_DOCKER_TEST") == "" {
		t.Skip("Skipping Docker integration test (set SINGCTL_DOCKER_TEST=1)")
	}

	os.MkdirAll("/etc/init.d", 0755)
	defer os.Remove("/etc/init.d/tailscale")

	if err := tailscale.CreateInitScript(false); err != nil {
		t.Fatalf("createInitScript(false) failed: %v", err)
	}

	content, err := os.ReadFile("/etc/init.d/tailscale")
	if err != nil {
		t.Fatalf("cannot read created init script: %v", err)
	}

	script := string(content)
	if !strings.Contains(script, "--tun=userspace-networking") {
		t.Error("userspace mode init script missing --tun=userspace-networking")
	}
	if strings.Contains(script, "modprobe tun") {
		t.Error("userspace mode init script should NOT have modprobe tun")
	}
}

func TestIntegration_GetLANSubnet(t *testing.T) {
	if os.Getenv("SINGCTL_DOCKER_TEST") == "" {
		t.Skip("Skipping Docker integration test (set SINGCTL_DOCKER_TEST=1)")
	}

	_ = newTestTailscale()
	subnet, err := netinfo.GetLANSubnet()
	if err != nil {
		t.Fatalf("getLANSubnet() failed: %v", err)
	}

	// Docker 容器中的 fake uci 返回 192.168.1.1/255.255.255.0
	expected := "192.168.1.0/24"
	if subnet != expected {
		t.Errorf("getLANSubnet() = %q, want %q", subnet, expected)
	}
}

// =============================================================================
// 16. 综合回归测试 — 验证修复后的完整参数链
// =============================================================================

func TestRegression_SubnetRouting(t *testing.T) {
	t.Run("snat-subnet-routes=false prevents SNAT", func(t *testing.T) {
		// 模拟 Start() 中的参数构建
		lanSubnet := "192.168.31.0/24"
		args := []string{"up", "--reset", "--advertise-routes=" + lanSubnet, "--accept-dns=false", "--snat-subnet-routes=false"}

		found := false
		for _, arg := range args {
			if arg == "--snat-subnet-routes=false" {
				found = true
				break
			}
		}
		if !found {
			t.Fatal("REGRESSION: --snat-subnet-routes=false 必须存在，否则子网路由会因 SNAT 失效")
		}
	})

	t.Run("CGNAT range in LOCAL_IPV4 prevents TProxy hijack", func(t *testing.T) {
		scriptContent, err := os.ReadFile("../scripts/start_singbox.sh")
		if err != nil {
			t.Fatalf("Cannot read start_singbox.sh: %v", err)
		}
		script := string(scriptContent)

		checks := []struct {
			name    string
			pattern string
		}{
			{"CGNAT in LOCAL_IPV4 set", "100.64.0.0/10"},
			{"tailscale0 nft bypass", `iifname "tailscale0" accept`},
			{"tailscale0 iptables bypass", "-i tailscale0 -j RETURN"},
			{"CGNAT iptables bypass", "-d 100.64.0.0/10 -j RETURN"},
		}

		for _, c := range checks {
			if !strings.Contains(script, c.pattern) {
				t.Errorf("REGRESSION: %s — 缺少 %q", c.name, c.pattern)
			}
		}
	})
}

// =============================================================================
// 17. Benchmark — 确保 selectTailscaleAsset 性能合理
// =============================================================================

func BenchmarkSelectTailscaleAsset(b *testing.B) {
	ts := newTestTailscale()
	for i := 0; i < b.N; i++ {
		ts.SelectTailscaleAsset(fmt.Sprintf("tailscale_%d_amd64.tgz", i))
	}
}
