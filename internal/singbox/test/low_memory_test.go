// 文件职责：验证 sing-box 低内存规则集裁剪（geosite-ad2）、自适应 GOMEMLIMIT/GOGC 计算、启动脚本环境变量透传与 256KiB 日志截断保护。
package singbox_test

import (
	"bytes"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"singctl/internal/config"
	"singctl/internal/platform/servicemgr"
	"singctl/internal/singbox"
	"singctl/internal/singbox/sboption"
	"singctl/internal/singbox/scripts"
)

func TestPruneLowMemoryRuleSets_PipelineStageBoundaries(t *testing.T) {
	const (
		mib      uint64 = 1024 * 1024
		n60ProKB uint64 = 491040 * 1024
	)

	seedJSON := `{
		"log": {"level": "info"},
		"outbounds": [
			{"tag": "node-1", "type": "vless", "server": "198.51.100.1", "server_port": 443},
			{"tag": "Proxy", "type": "selector", "outbounds": ["node-1"]},
			{"tag": "#DC", "type": "direct"}
		],
		"dns": {
			"servers": [{"tag": "dns_local", "type": "udp", "server": "223.5.5.5"}],
			"rules": [
				{"rule_set": ["geosite-ad1", "geosite-ad2"], "action": "reject"},
				{"rule_set": "geosite-ad2", "action": "reject"},
				{"rule_set": ["geosite-ad2"], "action": "reject"},
				{"type": "logical", "mode": "or", "rules": [{"rule_set": "geosite-ad2"}], "action": "reject"},
				{"rule_set": ["geosite-cn"], "server": "dns_local"}
			]
		},
		"route": {
			"default_mark": 1,
			"rules": [
				{"action": "sniff"},
				{"rule_set": ["geosite-ad1", "geosite-ad2"], "action": "reject"},
				{"rule_set": "geosite-ad2", "action": "reject"},
				{"rule_set": ["geosite-ad2"], "action": "reject"},
				{"type": "logical", "mode": "and", "rules": [{"rule_set": ["geosite-ad2"]}], "action": "reject"},
				{"rule_set": ["geosite-cn"], "outbound": "#DC"}
			],
			"rule_set": [
				{"tag": "geosite-ad1", "type": "remote", "format": "binary", "url": "https://example.com/geosite-ad1.srs"},
				{"tag": "geosite-ad2", "type": "remote", "format": "binary", "url": "https://example.com/geosite-ad2.srs"},
				{"tag": "geosite-cn", "type": "remote", "format": "binary", "url": "https://example.com/geosite-cn.srs"}
			]
		},
		"experimental": {
			"clash_api": {"external_controller": "127.0.0.1:9090"}
		}
	}`

	assertPruned := func(t *testing.T, out string) {
		t.Helper()
		if strings.Contains(out, "geosite-ad2") {
			t.Fatalf("expected geosite-ad2 completely pruned from config, still found in:\n%s", out)
		}
		doc, err := sboption.ParseDocument([]byte(out))
		if err != nil {
			t.Fatalf("parse compiled output: %v", err)
		}
		var rsTags []string
		for _, rs := range doc.Route.RuleSet {
			rsTags = append(rsTags, rs.Tag)
		}
		if !slices.Contains(rsTags, "geosite-ad1") || !slices.Contains(rsTags, singbox.BuiltinPCDNRuleSetTag) || !slices.Contains(rsTags, "geosite-cn") {
			t.Fatalf("expected geosite-ad1, %s and geosite-cn preserved, got rule_set tags: %v", singbox.BuiltinPCDNRuleSetTag, rsTags)
		}
		// Ensure zero dangling or empty rule_set rules in Route & DNS
		for i, r := range doc.Route.Rules {
			if slices.Contains(r.RuleSet.Slice(), "geosite-ad2") {
				t.Fatalf("route.rules[%d] still references geosite-ad2", i)
			}
			if r.Type == "logical" && len(r.Rules) == 0 {
				t.Fatalf("route.rules[%d] has empty logical subrules", i)
			}
		}
		for i, r := range doc.DNS.Rules {
			if slices.Contains(r.RuleSet.Slice(), "geosite-ad2") {
				t.Fatalf("dns.rules[%d] still references geosite-ad2", i)
			}
			if r.Type == "logical" && len(r.Rules) == 0 {
				t.Fatalf("dns.rules[%d] has empty logical subrules", i)
			}
		}
	}

	t.Run("auto_prunes_on_224m_256m_n60pro_and_512m_and_preserves_ad1_and_pcdn", func(t *testing.T) {
		for _, ram := range []uint64{224 * mib, 256 * mib, n60ProKB, 512 * mib} {
			cfg := &config.Config{} // default PCDNBlock enabled + low_memory="auto"
			g := singbox.NewOfflineConfigGenerator(cfg)
			g.SetTotalRAMBytes(ram)
			if !g.EffectiveLowMemory() {
				t.Fatalf("expected EffectiveLowMemory()=true for RAM=%d", ram)
			}

			doc := singbox.NewCompileDoc(seedJSON, "linux")
			if err := singbox.RunCompileStages(g, doc, singbox.DefaultCompileStages()); err != nil {
				t.Fatalf("RunCompileStages(ram=%d) failed: %v", ram, err)
			}
			if doc.UnmarshalCount() != 1 || doc.MarshalCount() != 0 {
				t.Fatalf("single-tree invariant broken: unmarshal=%d marshal=%d", doc.UnmarshalCount(), doc.MarshalCount())
			}
			parsed, err := doc.EnsureDoc()
			if err != nil {
				t.Fatal(err)
			}
			out, err := parsed.MarshalPretty()
			if err != nil {
				t.Fatal(err)
			}
			assertPruned(t, out)

			// Idempotency on second pass
			pass2, err := g.RunCompilePipeline(out, "linux")
			if err != nil {
				t.Fatalf("idempotent second RunCompilePipeline failed: %v", err)
			}
			assertPruned(t, pass2)
		}
	})

	t.Run("forced_on_prunes_even_on_large_ram_and_forced_off_keeps_ad2_on_224m", func(t *testing.T) {
		gOn := singbox.NewOfflineConfigGenerator(&config.Config{LowMemory: config.LowMemoryOn})
		gOn.SetTotalRAMBytes(8192 * mib)
		outOn, err := gOn.RunCompilePipeline(seedJSON, "linux")
		if err != nil {
			t.Fatalf("RunCompilePipeline(on) failed: %v", err)
		}
		assertPruned(t, outOn)

		gOff := singbox.NewOfflineConfigGenerator(&config.Config{LowMemory: config.LowMemoryOff})
		gOff.SetTotalRAMBytes(224 * mib)
		if gOff.EffectiveLowMemory() {
			t.Fatal("expected EffectiveLowMemory()=false when low_memory=off")
		}
		outOff, err := gOff.RunCompilePipeline(seedJSON, "linux")
		if err != nil {
			t.Fatalf("RunCompilePipeline(off) failed: %v", err)
		}
		if !strings.Contains(outOff, `"geosite-ad2"`) {
			t.Fatalf("expected geosite-ad2 preserved when low_memory=off, got:\n%s", outOff)
		}

		gLarge := singbox.NewOfflineConfigGenerator(&config.Config{})
		gLarge.SetTotalRAMBytes(512*mib + 1)
		outLarge, err := gLarge.RunCompilePipeline(seedJSON, "linux")
		if err != nil {
			t.Fatalf("RunCompilePipeline(>512MiB) failed: %v", err)
		}
		if !strings.Contains(outLarge, `"geosite-ad2"`) {
			t.Fatalf("expected geosite-ad2 preserved when RAM > 512 MiB")
		}
	})
}

func TestComputeSingBoxMemoryEnv_And_UnitSpec_And_LogCap(t *testing.T) {
	const (
		mib      uint64 = 1024 * 1024
		n60ProKB uint64 = 491040 * 1024
	)

	t.Run("compute_singbox_memory_env_tiers", func(t *testing.T) {
		cases := []struct {
			ram       uint64
			wantLimit string
			wantGOGC  string
		}{
			{0, "", ""},
			{1, "40MiB", "50"},
			{128 * mib, "40MiB", "50"},
			{224 * mib, "40MiB", "50"},
			{288 * mib, "40MiB", "50"},
			{288*mib + 1, "44MiB", "50"},
			{n60ProKB, "44MiB", "50"},
			{512 * mib, "44MiB", "50"},
			{512*mib + 1, "", ""},
			{1024 * mib, "", ""},
			{math.MaxUint64, "", ""},
		}
		for _, tc := range cases {
			limit, gogc := singbox.ComputeSingBoxMemoryEnv(tc.ram)
			if limit != tc.wantLimit || gogc != tc.wantGOGC {
				t.Fatalf("ComputeSingBoxMemoryEnv(%d) = (%q, %q), want (%q, %q)", tc.ram, limit, gogc, tc.wantLimit, tc.wantGOGC)
			}
			envMap := singbox.SingBoxMemoryEnvMap(tc.ram)
			if tc.wantLimit == "" {
				if len(envMap) != 0 {
					t.Fatalf("expected nil/empty env map for ram=%d, got %v", tc.ram, envMap)
				}
			} else if envMap["GOMEMLIMIT"] != tc.wantLimit || envMap["GOGC"] != tc.wantGOGC {
				t.Fatalf("unexpected SingBoxMemoryEnvMap(%d) = %v", tc.ram, envMap)
			}
		}
	})

	t.Run("unit_spec_and_command_env_integration", func(t *testing.T) {
		spec := singbox.BuildSingBoxClientUnitSpec("/usr/bin/sing-box", "/etc/sing-box/config.json", n60ProKB)
		procdRendered, err := servicemgr.RenderProcdBody(spec)
		if err != nil || !strings.Contains(procdRendered, "procd_set_param env GOGC=50 GOMEMLIMIT=44MiB") {
			t.Fatalf("unexpected procd render: err=%v\n%s", err, procdRendered)
		}
		sysRendered, err := servicemgr.RenderSystemdBody(spec)
		if err != nil || !strings.Contains(sysRendered, `Environment="GOMEMLIMIT=44MiB"`) || !strings.Contains(sysRendered, `Environment="GOGC=50"`) {
			t.Fatalf("unexpected systemd render: err=%v\n%s", err, sysRendered)
		}

		cmdEnv := singbox.BuildSingBoxCommandEnv([]string{"PATH=/usr/bin"}, &config.Config{}, 224*mib)
		joined := strings.Join(cmdEnv, "\n")
		if !strings.Contains(joined, "GOMEMLIMIT=40MiB") || !strings.Contains(joined, "GOGC=50") || !strings.Contains(joined, "SINGCTL_LOW_MEMORY=1") {
			t.Fatalf("BuildSingBoxCommandEnv(224MiB) missing expected vars:\n%s", joined)
		}

		cmdEnvOff := singbox.BuildSingBoxCommandEnv([]string{"PATH=/usr/bin"}, &config.Config{LowMemory: config.LowMemoryOff}, 224*mib)
		joinedOff := strings.Join(cmdEnvOff, "\n")
		if strings.Contains(joinedOff, "GOMEMLIMIT=") || !strings.Contains(joinedOff, "SINGCTL_LOW_MEMORY=0") {
			t.Fatalf("BuildSingBoxCommandEnv(off) should not force GOMEMLIMIT:\n%s", joinedOff)
		}
	})

	t.Run("cap_singbox_basic_log_256k_in_place_inode_preserved", func(t *testing.T) {
		dir := t.TempDir()
		missing := filepath.Join(dir, "missing.log")
		if err := singbox.CapSingBoxBasicLog(missing, singbox.LowMemoryBasicLogMaxBytes); err != nil {
			t.Fatalf("CapSingBoxBasicLog on missing file should succeed: %v", err)
		}

		logPath := filepath.Join(dir, "sing-box-basic.log")
		headChunk := bytes.Repeat([]byte("OLD_NOISE_LINE_0123456789ABCDEF\n"), 12000) // ~384 KB
		tailMarker := "FINAL_CRITICAL_TAIL_MARKER_LINE\n"
		payload := append(headChunk, []byte(tailMarker)...)
		if err := os.WriteFile(logPath, payload, 0644); err != nil {
			t.Fatal(err)
		}
		stBefore, err := os.Stat(logPath)
		if err != nil {
			t.Fatal(err)
		}

		// When low_memory=off, EnforceLowMemoryBasicLogCap leaves file untouched
		if err := singbox.EnforceLowMemoryBasicLogCap(&config.Config{LowMemory: config.LowMemoryOff}, 224*mib, logPath); err != nil {
			t.Fatal(err)
		}
		if st, _ := os.Stat(logPath); st.Size() != int64(len(payload)) {
			t.Fatalf("expected file untouched when low_memory=off, got size=%d", st.Size())
		}

		// When low_memory active, truncates in-place to <= 256 KiB and tightens mode to 0600
		if err := singbox.EnforceLowMemoryBasicLogCap(&config.Config{}, 224*mib, logPath); err != nil {
			t.Fatalf("EnforceLowMemoryBasicLogCap failed: %v", err)
		}
		stAfter, err := os.Stat(logPath)
		if err != nil {
			t.Fatal(err)
		}
		if stAfter.Size() > singbox.LowMemoryBasicLogMaxBytes {
			t.Fatalf("expected truncated size <= %d, got %d", singbox.LowMemoryBasicLogMaxBytes, stAfter.Size())
		}
		if stAfter.Mode().Perm() != 0600 {
			t.Fatalf("expected 0600 permissions after truncation, got %04o", stAfter.Mode().Perm())
		}
		if !os.SameFile(stBefore, stAfter) {
			t.Fatalf("expected in-place truncation preserving open O_APPEND inode")
		}
		afterData, err := os.ReadFile(logPath)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasSuffix(string(afterData), tailMarker) {
			t.Fatalf("expected tail marker preserved at end of truncated log")
		}
	})

	t.Run("embedded_linux_start_scripts_inject_gomemlimit_ujail_env_and_256k_cap", func(t *testing.T) {
		for _, backend := range []scripts.OpenWrtFirewallBackend{
			scripts.BackendNFTables,
			scripts.BackendIPTables,
		} {
			openwrtScript := scripts.GetOpenWrtStartScript(backend)
			if !strings.Contains(openwrtScript, "GOMEMLIMIT") ||
				!strings.Contains(openwrtScript, "40MiB") ||
				!strings.Contains(openwrtScript, "44MiB") ||
				!strings.Contains(openwrtScript, "-e GOMEMLIMIT") ||
				!strings.Contains(openwrtScript, "262144") ||
				!strings.Contains(openwrtScript, "ensure_openwrt_ujail") {
				t.Fatalf("OpenWrt start script (%s) missing adaptive GOMEMLIMIT / ujail -e / 256KiB log cap / auto-ujail", backend)
			}
		}
		openwrtTargetScript := scripts.GetStartScriptForTarget("linux", false)
		if !strings.Contains(openwrtTargetScript, "GOMEMLIMIT") ||
			!strings.Contains(openwrtTargetScript, "40MiB") ||
			!strings.Contains(openwrtTargetScript, "44MiB") ||
			!strings.Contains(openwrtTargetScript, "-e GOMEMLIMIT") ||
			!strings.Contains(openwrtTargetScript, "262144") {
			t.Fatalf("OpenWrt target start script missing adaptive GOMEMLIMIT / ujail -e / 256KiB log cap")
		}
		debianScript := scripts.GetStartScriptForTarget("linux", true)
		if !strings.Contains(debianScript, "GOMEMLIMIT") ||
			!strings.Contains(debianScript, "40MiB") ||
			!strings.Contains(debianScript, "44MiB") {
			t.Fatalf("Debian start_singbox_debian.sh missing adaptive GOMEMLIMIT")
		}
	})

	t.Run("concurrent_low_memory_helpers_race_safe", func(t *testing.T) {
		g := singbox.NewOfflineConfigGenerator(&config.Config{})
		g.SetTotalRAMBytes(n60ProKB)
		var wg sync.WaitGroup
		for range 8 {
			wg.Go(func() {
				_, _ = singbox.ComputeSingBoxMemoryEnv(n60ProKB)
				_ = singbox.SingBoxMemoryEnvMap(224 * mib)
				_ = g.EffectiveLowMemory()
			})
		}
		wg.Wait()
	})
}

func TestPruneLowMemoryRuleSetsJSON(t *testing.T) {
	t.Run("empty_and_whitespace_noop", func(t *testing.T) {
		for _, in := range []string{"", "   \n\t  "} {
			out, changed, err := singbox.PruneLowMemoryRuleSetsJSON(in)
			if err != nil || changed || out != in {
				t.Fatalf("input %q: got (%q, %v, %v), want (%q, false, nil)", in, out, changed, err, in)
			}
		}
	})

	t.Run("invalid_json_returns_error", func(t *testing.T) {
		if _, _, err := singbox.PruneLowMemoryRuleSetsJSON("{bad-json"); err == nil {
			t.Fatal("expected error for invalid JSON")
		}
	})

	t.Run("no_geosite_ad2_returns_unchanged", func(t *testing.T) {
		in := `{"route":{"rule_set":[{"tag":"geosite-ad1","type":"remote","format":"binary","url":"https://example.com/ad1.srs"}]}}`
		out, changed, err := singbox.PruneLowMemoryRuleSetsJSON(in)
		if err != nil || changed || out != in {
			t.Fatalf("expected unchanged when geosite-ad2 absent, got changed=%v err=%v", changed, err)
		}
	})

	t.Run("prunes_geosite_ad2_from_dns_route_and_ruleset_preserving_ad1", func(t *testing.T) {
		in := `{
			"dns": {
				"servers": [{"tag": "dns_local", "type": "udp", "server": "223.5.5.5"}],
				"rules": [
					{"rule_set": ["geosite-ad1", "geosite-ad2"], "action": "reject"},
					{"rule_set": "geosite-ad2", "action": "reject"},
					{"type": "logical", "mode": "or", "rules": [{"rule_set": ["geosite-ad2"]}], "action": "reject"},
					{"rule_set": "geosite-cn", "server": "dns_local"}
				]
			},
			"route": {
				"rules": [
					{"action": "sniff"},
					{"rule_set": ["geosite-ad1", "geosite-ad2"], "action": "reject"},
					{"rule_set": "geosite-ad2", "action": "reject"},
					{"rule_set": "geosite-cn", "outbound": "#DC"}
				],
				"rule_set": [
					{"tag": "geosite-ad1", "type": "remote", "format": "binary", "url": "https://example.com/ad1.srs"},
					{"tag": "geosite-ad2", "type": "remote", "format": "binary", "url": "https://example.com/ad2.srs"},
					{"tag": "geosite-cn", "type": "remote", "format": "binary", "url": "https://example.com/cn.srs"}
				]
			}
		}`
		out, changed, err := singbox.PruneLowMemoryRuleSetsJSON(in)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !changed {
			t.Fatal("expected changed=true when geosite-ad2 present")
		}
		if strings.Contains(out, "geosite-ad2") {
			t.Fatalf("expected geosite-ad2 completely removed, got:\n%s", out)
		}
		if !strings.Contains(out, "geosite-ad1") || !strings.Contains(out, "geosite-cn") {
			t.Fatalf("expected geosite-ad1 and geosite-cn preserved, got:\n%s", out)
		}
		out2, changed2, err2 := singbox.PruneLowMemoryRuleSetsJSON(out)
		if err2 != nil || changed2 || out2 != out {
			t.Fatalf("expected second call idempotent, got changed=%v err=%v", changed2, err2)
		}
	})
}
