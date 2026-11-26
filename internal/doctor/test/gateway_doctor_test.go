// 文件职责：测试深度体检调度器（Runner）的 OCP 注册顺序、并发执行、超时/panic 隔离、评分汇总、Fix 一键修复与 FormatText 输出。
package doctor_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"singctl/internal/doctor"
	"singctl/internal/platform/servicemgr"
)

type stubChecker struct {
	id string
	fn func(ctx context.Context, env *doctor.Env) doctor.CheckResult
}

func (s stubChecker) ID() string { return s.id }
func (s stubChecker) Run(ctx context.Context, env *doctor.Env) doctor.CheckResult {
	return s.fn(ctx, env)
}

func TestRunner_DefaultCheckersOrderAndCount(t *testing.T) {
	checkers := doctor.DefaultCheckers()
	wantIDs := []string{
		"hardware_resources",
		"remote_lifeline",
		"firewall_backend",
		"policy_routing",
		"hw_offload_conflict",
		"sandbox_and_config",
		"dns_anti_hijack",
		"dual_stack_connectivity",
	}
	if len(checkers) != len(wantIDs) {
		t.Fatalf("DefaultCheckers count = %d, want %d", len(checkers), len(wantIDs))
	}
	for i, want := range wantIDs {
		if checkers[i].ID() != want {
			t.Fatalf("checker[%d].ID() = %q, want %q", i, checkers[i].ID(), want)
		}
	}
	runner := doctor.NewDefaultRunner()
	if len(runner.Checkers()) != len(wantIDs) {
		t.Fatalf("NewDefaultRunner checkers count = %d, want %d", len(runner.Checkers()), len(wantIDs))
	}
}

func TestRunner_ConcurrentExecutionPreservesRegistrationOrder(t *testing.T) {
	var inFlight atomic.Int32
	var maxConcurrent atomic.Int32

	recordConcurrency := func() func() {
		cur := inFlight.Add(1)
		for {
			prev := maxConcurrent.Load()
			if cur <= prev || maxConcurrent.CompareAndSwap(prev, cur) {
				break
			}
		}
		return func() { inFlight.Add(-1) }
	}

	runner := doctor.NewRunner()
	runner.Register(
		stubChecker{
			id: "first_slow",
			fn: func(ctx context.Context, env *doctor.Env) doctor.CheckResult {
				defer recordConcurrency()()
				time.Sleep(40 * time.Millisecond)
				return doctor.CheckResult{ID: "first_slow", Category: "host", Title: "First", Status: doctor.StatusPass, Summary: "ok"}
			},
		},
		stubChecker{
			id: "second_fast",
			fn: func(ctx context.Context, env *doctor.Env) doctor.CheckResult {
				defer recordConcurrency()()
				time.Sleep(5 * time.Millisecond)
				return doctor.CheckResult{ID: "second_fast", Category: "network", Title: "Second", Status: doctor.StatusWarn, Summary: "warn"}
			},
		},
		stubChecker{
			id: "third_skip",
			fn: func(ctx context.Context, env *doctor.Env) doctor.CheckResult {
				defer recordConcurrency()()
				time.Sleep(15 * time.Millisecond)
				return doctor.CheckResult{ID: "third_skip", Category: "dns", Title: "Third", Status: doctor.StatusSkip, Summary: "skip"}
			},
		},
	)

	fixedNow := time.Date(2026, 11, 22, 18, 30, 0, 0, time.UTC)
	rep := runner.Run(t.Context(), &doctor.Env{
		NowFunc: func() time.Time { return fixedNow },
	})

	if maxConcurrent.Load() < 2 {
		t.Fatalf("expected concurrent checker execution (maxConcurrent >= 2), got %d", maxConcurrent.Load())
	}
	if len(rep.Checks) != 3 || rep.Checks[0].ID != "first_slow" || rep.Checks[1].ID != "second_fast" || rep.Checks[2].ID != "third_skip" {
		t.Fatalf("registration order not preserved: %+v", rep.Checks)
	}
	if rep.Passed != 1 || rep.Warnings != 1 || rep.Failed != 0 || rep.Skipped != 1 {
		t.Fatalf("unexpected counts: %+v", rep)
	}
	if rep.Overall != doctor.StatusWarn || rep.Score >= 100 || rep.Score <= 0 {
		t.Fatalf("unexpected overall/score: overall=%q score=%d", rep.Overall, rep.Score)
	}
	if rep.CheckedAt == "" {
		t.Fatal("expected CheckedAt populated")
	}
}

func TestRunner_TimeoutPanicAndScoringBoundaries(t *testing.T) {
	t.Run("per_check_timeout_and_panic_isolated", func(t *testing.T) {
		runner := doctor.NewRunner(
			stubChecker{
				id: "hung",
				fn: func(ctx context.Context, _ *doctor.Env) doctor.CheckResult {
					<-ctx.Done()
					return doctor.CheckResult{ID: "hung", Title: "Hung", Status: doctor.StatusWarn, Summary: "cancelled"}
				},
			},
			stubChecker{
				id: "panicker",
				fn: func(context.Context, *doctor.Env) doctor.CheckResult {
					panic("synthetic panic")
				},
			},
			stubChecker{
				id: "healthy",
				fn: func(context.Context, *doctor.Env) doctor.CheckResult {
					return doctor.CheckResult{ID: "healthy", Title: "Healthy", Status: doctor.StatusPass, Summary: "ok"}
				},
			},
		)
		runner.SetCheckTimeout(40 * time.Millisecond)

		start := time.Now()
		rep := runner.Run(t.Context(), &doctor.Env{})
		if time.Since(start) > 2*time.Second {
			t.Fatalf("per-check timeout did not bound execution: %v", time.Since(start))
		}
		if len(rep.Checks) != 3 {
			t.Fatalf("expected 3 results, got %d", len(rep.Checks))
		}
		if rep.Checks[0].Status != doctor.StatusWarn && rep.Checks[0].Status != doctor.StatusFail {
			t.Fatalf("expected timeout check to warn/fail, got %+v", rep.Checks[0])
		}
		if rep.Checks[1].Status != doctor.StatusFail || !strings.Contains(rep.Checks[1].Detail, "synthetic panic") {
			t.Fatalf("expected panic recovered as fail, got %+v", rep.Checks[1])
		}
		if rep.Checks[2].Status != doctor.StatusPass {
			t.Fatalf("healthy check must not be impacted, got %+v", rep.Checks[2])
		}
		if rep.Overall != doctor.StatusFail {
			t.Fatalf("expected Overall=fail when any check fails, got %q", rep.Overall)
		}
	})

	t.Run("score_clamped_to_zero_under_many_failures", func(t *testing.T) {
		var checkers []doctor.Checker
		for range 8 {
			checkers = append(checkers, stubChecker{
				id: "fail",
				fn: func(context.Context, *doctor.Env) doctor.CheckResult {
					return doctor.CheckResult{ID: "fail", Status: doctor.StatusFail, Summary: "bad"}
				},
			})
		}
		rep := doctor.NewRunner(checkers...).Run(t.Context(), &doctor.Env{})
		if rep.Score != 0 || rep.Overall != doctor.StatusFail || rep.Failed != 8 {
			t.Fatalf("expected Score=0 Overall=fail Failed=8, got %+v", rep)
		}
	})

	t.Run("concurrent_runs_race_free", func(t *testing.T) {
		runner := doctor.NewRunner(stubChecker{
			id: "ok",
			fn: func(context.Context, *doctor.Env) doctor.CheckResult {
				return doctor.CheckResult{ID: "ok", Status: doctor.StatusPass, Summary: "ok"}
			},
		})
		var wg sync.WaitGroup
		for range 8 {
			wg.Go(func() {
				rep := runner.Run(t.Context(), &doctor.Env{})
				if rep.Score != 100 || rep.Overall != doctor.StatusPass {
					t.Errorf("unexpected report: %+v", rep)
				}
			})
		}
		wg.Wait()
	})
}

func TestRunner_FixDispatchAndBuiltinOOMShield(t *testing.T) {
	runner := doctor.NewDefaultRunner()

	// 1. Custom QuickFixHandlers override.
	customCalled := false
	envCustom := &doctor.Env{
		QuickFixHandlers: map[string]func(ctx context.Context) (string, error){
			"sync-smartdns-ipv6": func(ctx context.Context) (string, error) {
				customCalled = true
				return "已同步 SmartDNS IPv6 策略", nil
			},
		},
	}
	msg, err := runner.Fix(t.Context(), envCustom, "sync-smartdns-ipv6")
	if err != nil || !customCalled || !strings.Contains(msg, "SmartDNS") {
		t.Fatalf("custom quick fix failed: msg=%q err=%v called=%v", msg, err, customCalled)
	}

	// 2. Built-in protect-tailscale-oom works out of the box when QuickFixHandlers doesn't override it.
	procRoot := t.TempDir()
	pidDir := filepath.Join(procRoot, "1234")
	if err := os.MkdirAll(pidDir, 0755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(pidDir, "comm"), []byte("tailscaled\n"), 0644)
	_ = os.WriteFile(filepath.Join(pidDir, "oom_score_adj"), []byte("0\n"), 0644)

	msg, err = runner.Fix(t.Context(), &doctor.Env{ProcRoot: procRoot}, "protect-tailscale-oom")
	if err != nil || msg == "" || strings.Contains(msg, "-1000") || strings.Contains(msg, "oom_score_adj") {
		t.Fatalf("builtin protect-tailscale-oom failed or leaked low-level OOM details: msg=%q err=%v", msg, err)
	}
	rawAdj, _ := os.ReadFile(filepath.Join(pidDir, "oom_score_adj"))
	if strings.TrimSpace(string(rawAdj)) != "-1000" {
		t.Fatalf("expected -1000 written, got %q", string(rawAdj))
	}

	// 3. Unknown action returns clear error.
	if _, err := runner.Fix(t.Context(), &doctor.Env{}, "unknown-action"); err == nil {
		t.Fatal("expected error for unknown quick-fix action")
	}
}

func TestRunner_FixDisableFlowOffload(t *testing.T) {
	runner := doctor.NewDefaultRunner()

	t.Run("success_with_uci_and_fw4_reload", func(t *testing.T) {
		var cmds []string
		env := &doctor.Env{
			LookPath: func(file string) (string, error) {
				if file == "uci" || file == "fw4" {
					return "/sbin/" + file, nil
				}
				return "", errors.New("not found")
			},
			RunCmd: func(_ context.Context, name string, args ...string) ([]byte, error) {
				cmds = append(cmds, name+" "+strings.Join(args, " "))
				return []byte("ok\n"), nil
			},
		}
		msg, err := runner.Fix(t.Context(), env, "disable-flow-offload")
		if err != nil {
			t.Fatalf("disable-flow-offload failed: %v", err)
		}
		if !strings.Contains(msg, "流量卸载") {
			t.Fatalf("unexpected success message: %q", msg)
		}
		want := []string{
			"uci set firewall.@defaults[0].flow_offloading=0",
			"uci set firewall.@defaults[0].flow_offloading_hw=0",
			"uci commit firewall",
			"fw4 reload",
		}
		if len(cmds) != len(want) {
			t.Fatalf("commands = %v, want %v", cmds, want)
		}
		for i := range want {
			if cmds[i] != want[i] {
				t.Fatalf("cmd[%d] = %q, want %q", i, cmds[i], want[i])
			}
		}
	})

	t.Run("fallback_to_servicemgr_reload_when_fw4_absent", func(t *testing.T) {
		mockMgr := servicemgr.NewMock()
		env := &doctor.Env{
			LookPath: func(file string) (string, error) {
				if file == "uci" {
					return "/sbin/uci", nil
				}
				return "", errors.New("not found")
			},
			RunCmd: func(_ context.Context, _ string, _ ...string) ([]byte, error) {
				return []byte("ok\n"), nil
			},
			ServiceManager: mockMgr,
		}
		msg, err := runner.Fix(t.Context(), env, "disable-flow-offload")
		if err != nil {
			t.Fatalf("disable-flow-offload fallback failed: %v", err)
		}
		if !strings.Contains(msg, "firewall") {
			t.Fatalf("unexpected fallback message: %q", msg)
		}
		if got := mockMgr.Calls(); len(got) != 1 || got[0] != "reload firewall" {
			t.Fatalf("expected servicemgr reload firewall call, got %v", got)
		}
	})

	t.Run("missing_uci_returns_error", func(t *testing.T) {
		env := &doctor.Env{
			LookPath: func(string) (string, error) { return "", errors.New("not found") },
		}
		if _, err := runner.Fix(t.Context(), env, "disable-flow-offload"); err == nil {
			t.Fatal("expected error when uci is missing")
		}
	})

	t.Run("turboacc_hnat_fix_clears_turboacc_and_hook_toggle", func(t *testing.T) {
		procRoot := t.TempDir()
		_ = os.MkdirAll(filepath.Join(procRoot, "etc/config"), 0755)
		_ = os.WriteFile(filepath.Join(procRoot, "etc/config/turboacc"), []byte("config turboacc 'config'\n\toption fastpath 'mediatek_hnat'\n\toption fastpath_mh_eth_hnat '1'\n\toption tcpcca 'bbr'\n"), 0644)
		hookPath := filepath.Join(procRoot, "sys/kernel/debug/hnat/hook_toggle")
		_ = os.MkdirAll(filepath.Dir(hookPath), 0755)
		_ = os.WriteFile(hookPath, []byte("enabled\n"), 0644)

		var cmds []string
		mockMgr := servicemgr.NewMock()
		env := &doctor.Env{
			ProcRoot: procRoot,
			LookPath: func(file string) (string, error) {
				if file == "uci" {
					return "/sbin/uci", nil
				}
				return "", errors.New("not found")
			},
			RunCmd: func(_ context.Context, name string, args ...string) ([]byte, error) {
				cmds = append(cmds, name+" "+strings.Join(args, " "))
				return []byte("ok\n"), nil
			},
			ServiceManager: mockMgr,
		}
		if _, err := runner.Fix(t.Context(), env, "disable-flow-offload"); err != nil {
			t.Fatalf("turboacc disable-flow-offload failed: %v", err)
		}
		if !slices.Contains(cmds, "uci set turboacc.config.fastpath=none") || !slices.Contains(cmds, "uci commit turboacc") {
			t.Fatalf("expected turboacc UCI disable & commit commands, got %v", cmds)
		}
		rawHook, _ := os.ReadFile(hookPath)
		if strings.TrimSpace(string(rawHook)) != "0" {
			t.Fatalf("expected hook_toggle updated to 0, got %q", string(rawHook))
		}
	})
}

func TestFormatText_RendersStatusesDetailsAndFixHints(t *testing.T) {
	rep := doctor.Report{
		Score:      72,
		Overall:    doctor.StatusFail,
		Passed:     1,
		Warnings:   1,
		Failed:     1,
		Skipped:    1,
		DurationMs: 145,
		CheckedAt:  "2026-11-22 18:30:00",
		Checks: []doctor.CheckResult{
			{ID: "hardware_resources", Category: "host", Title: "硬件资源与内存档位", Status: doctor.StatusPass, Summary: "存储与内存充裕", DurationMs: 2},
			{ID: "remote_lifeline", Category: "host", Title: "远程运维生命线", Status: doctor.StatusWarn, Summary: "未受 OOM 保护", Detail: "oom_score_adj=0", Advice: "建议设为 -1000", FixAction: "protect-tailscale-oom", FixLabel: "一键加 OOM 免疫", DurationMs: 3},
			{ID: "dns_anti_hijack", Category: "dns", Title: "DNS 防劫持链路", Status: doctor.StatusFail, Summary: "检测到明文 UDP 53", Advice: "切换为加密 DoH", FixAction: "sync-dns-local", FixLabel: "一键修复 DNS", DurationMs: 5},
			{ID: "extra", Category: "network", Title: "可选检查", Status: doctor.StatusSkip, Summary: "已跳过", DurationMs: 1},
		},
	}

	out := doctor.FormatText(rep)
	for _, want := range []string{
		"72",
		"[✓]", "[!]", "[✗]", "[-]",
		"硬件资源与内存档位",
		"远程运维生命线",
		"protect-tailscale-oom",
		"一键加 OOM 免疫",
		"检测到明文 UDP 53",
		"2026-11-22 18:30:00",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("FormatText missing %q in output:\n%s", want, out)
		}
	}
}
