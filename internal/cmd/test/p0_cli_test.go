// 文件职责：覆盖 CLI P0 命令集成测试（safe-commit 子命令族与 _watch 超时回滚、sb start --safe-commit 校验、doctor --mode/--json/--fix 与旧服务端模式兼容）。
package cmd_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"singctl/internal/cmd"
	"singctl/internal/common/sysinfo"
	"singctl/internal/config"
	"singctl/internal/doctor"
	"singctl/internal/safecommit"
)

func TestRootCmd_MountsSafeCommitSubcommand(t *testing.T) {
	root := cmd.NewRootCmd("/tmp/test-singctl.yaml", "/tmp/test-singctl.yaml", cmd.BuildInfo{Version: "test"})
	found, _, err := root.Find([]string{"safe-commit"})
	if err != nil || found == nil || found.Name() != "safe-commit" {
		t.Fatalf("expected safe-commit mounted on root, got found=%v err=%v", found, err)
	}
	for _, sub := range []string{"arm", "confirm", "rollback", "status", "_watch"} {
		c, _, fErr := root.Find([]string{"safe-commit", sub})
		if fErr != nil || c == nil || c.Name() != sub {
			t.Fatalf("expected safe-commit subcommand %q, got %v err=%v", sub, c, fErr)
		}
	}
}

func TestSafeCommitCLI_ArmStatusConfirmRollbackAndWatch(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "singctl.yaml")
	sbPath := filepath.Join(dir, "sing-box.json")
	stateDir := filepath.Join(dir, "sc-state")
	if err := os.WriteFile(cfgPath, []byte("hy2:\n  up: 50\n  down: 200\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sbPath, []byte(`{"original":true}`), 0600); err != nil {
		t.Fatal(err)
	}

	now := time.Unix(1700000000, 0)
	var rbCalled atomic.Bool
	deps := cmd.SafeCommitCmdDeps{
		StateDir:          stateDir,
		SingBoxConfigPath: sbPath,
		NowFunc:           func() time.Time { return now },
		WatchInterval:     5 * time.Millisecond,
		SpawnWatcher:      func(token string) (int, error) { return 0, nil },
		KillWatcher:       func(pid int) error { return nil },
		BaselineProbe:     func() (bool, bool) { return true, false },
		RollbackOps: &safecommit.RollbackOps{
			StartOrReloadSingBox: func(context.Context) error { rbCalled.Store(true); return nil },
		},
	}

	run := func(args ...string) (string, error) {
		c := cmd.NewSafeCommitCmdWithDeps(cfgPath, deps)
		var out bytes.Buffer
		c.SetOut(&out)
		c.SetErr(&out)
		c.SetArgs(args)
		err := c.ExecuteContext(t.Context())
		return out.String(), err
	}

	// 1. 非法 TTL 报错
	if _, err := run("arm", "--ttl", "10"); err == nil {
		t.Fatal("expected error for invalid TTL 10")
	}

	// 2. arm 成功 + status --json 可读
	armOut, err := run("arm", "--ttl", "120", "--reason", "cli-test")
	if err != nil {
		t.Fatalf("safe-commit arm failed: %v (out=%s)", err, armOut)
	}
	statusOut, err := run("status", "--json")
	if err != nil {
		t.Fatalf("safe-commit status --json failed: %v", err)
	}
	var st safecommit.StatusReport
	if err := json.Unmarshal([]byte(statusOut), &st); err != nil {
		t.Fatalf("unmarshal status --json: %v (raw=%s)", err, statusOut)
	}
	if !st.Active || st.State == nil || st.State.TTLSec != 120 || st.State.Reason != "cli-test" {
		t.Fatalf("unexpected status report: %+v", st)
	}
	token := st.State.Token

	// 3. confirm 错误 token 失败，正确 token 成功
	if _, err := run("confirm", "--token", "bad-token"); err == nil {
		t.Fatal("expected error on wrong confirm token")
	}
	if _, err := run("confirm", "--token", token); err != nil {
		t.Fatalf("confirm with valid token failed: %v", err)
	}
	statusAfter, _ := run("status", "--json")
	if !strings.Contains(statusAfter, `"active": false`) && !strings.Contains(statusAfter, `"active":false`) {
		t.Fatalf("expected inactive after confirm, got %s", statusAfter)
	}

	// 4. 重新 arm -> 篡改配置 -> 时间前进超过 deadline -> _watch 自动回滚
	if _, err := run("arm", "--ttl", "60", "--reason", "timeout-test"); err != nil {
		t.Fatalf("arm2 failed: %v", err)
	}
	st2Out, _ := run("status", "--json")
	var st2 safecommit.StatusReport
	_ = json.Unmarshal([]byte(st2Out), &st2)
	if err := os.WriteFile(sbPath, []byte(`{"broken":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	now = now.Add(65 * time.Second)
	if _, err := run("_watch", "--token", st2.State.Token); err != nil {
		t.Fatalf("_watch failed: %v", err)
	}
	if !rbCalled.Load() {
		t.Fatal("expected _watch timeout to invoke RollbackOps")
	}
	restored, _ := os.ReadFile(sbPath)
	if string(restored) != `{"original":true}` {
		t.Fatalf("expected sing-box.json restored by _watch, got %q", string(restored))
	}
}

func TestSingboxStartCLI_SafeCommitFlag(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "singctl.yaml")
	stateDir := filepath.Join(dir, "sc-sb")
	if err := os.WriteFile(cfgPath, []byte("hy2:\n  up: 50\n  down: 200\n"), 0600); err != nil {
		t.Fatal(err)
	}

	var started atomic.Bool
	deps := cmd.StartSingboxDeps{
		SafeCommit: cmd.SafeCommitCmdDeps{
			StateDir:      stateDir,
			SpawnWatcher:  func(token string) (int, error) { return 0, nil },
			KillWatcher:   func(pid int) error { return nil },
			BaselineProbe: func() (bool, bool) { return false, false },
		},
		StartFunc: func(cfg *config.Config, path string) error {
			started.Store(true)
			return nil
		},
	}

	// 1. 越界 TTL 必须在启动前报错且绝不执行 StartFunc
	cBad := cmd.NewSingboxCommandWithDeps(cfgPath, deps)
	cBad.SetArgs([]string{"start", "--safe-commit", "30"})
	if err := cBad.ExecuteContext(t.Context()); err == nil {
		t.Fatal("expected error for --safe-commit 30")
	}
	if started.Load() {
		t.Fatal("StartFunc must not run when --safe-commit TTL is invalid")
	}

	// 2. 合法 --safe-commit 120 先 Arm 再执行 StartFunc
	cOK := cmd.NewSingboxCommandWithDeps(cfgPath, deps)
	var out bytes.Buffer
	cOK.SetOut(&out)
	cOK.SetArgs([]string{"start", "--safe-commit", "120"})
	if err := cOK.ExecuteContext(t.Context()); err != nil {
		t.Fatalf("sb start --safe-commit 120 failed: %v", err)
	}
	if !started.Load() {
		t.Fatal("expected StartFunc invoked")
	}
	mgr := safecommit.NewManager(safecommit.ManagerOptions{StateDir: stateDir})
	st := mgr.Status()
	if !st.Active || st.State == nil || st.State.TTLSec != 120 {
		t.Fatalf("expected active safe commit armed with ttl=120, got %+v", st)
	}
}

func TestDoctorCLI_ModesJSONAndQuickFix(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "singctl.yaml")
	sbPath := filepath.Join(dir, "sing-box.json")
	procRoot := filepath.Join(dir, "proc")
	pidDir := filepath.Join(procRoot, "9090")
	if err := os.MkdirAll(pidDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pidDir, "comm"), []byte("tailscaled\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pidDir, "oom_score_adj"), []byte("0\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, []byte("hy2:\n  up: 50\n  down: 200\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sbPath, []byte(`{"dns":{"servers":[{"tag":"dns_local","type":"https","server":"223.5.5.5"}],"disable_cache":true,"optimistic":false}}`), 0600); err != nil {
		t.Fatal(err)
	}

	var serverDoctorCalled atomic.Bool
	deps := cmd.DoctorCmdDeps{
		ProcRoot:          procRoot,
		SingBoxConfigPath: sbPath,
		BuildEnv: func(cfg *config.Config, resolvedPath string) *doctor.Env {
			return &doctor.Env{
				Config:            cfg,
				ConfigPath:        resolvedPath,
				SingBoxConfigPath: sbPath,
				ProcRoot:          procRoot,
				IsOpenWrt:         func() bool { return false },
				LookPath:          func(string) (string, error) { return "", os.ErrNotExist },
				DialTCP:           func(context.Context, string) error { return nil },
				HTTPProbe:         func(context.Context, string) (int, int64, error) { return 204, 10, nil },
				Statfs: func(string) (sysinfo.DiskSpace, error) {
					return sysinfo.DiskSpace{TotalBytes: 200 << 20, AvailBytes: 150 << 20, UsedPercent: 25}, nil
				},
				ReadMemInfo: func() (sysinfo.MemInfo, error) {
					return sysinfo.MemInfo{TotalBytes: 512 << 20, AvailableBytes: 300 << 20}, nil
				},
			}
		},
		RunServerDoctor: func(cfg *config.Config) *doctor.DoctorReport {
			serverDoctorCalled.Store(true)
			return &doctor.DoctorReport{
				Score:     100,
				CheckedAt: "2026-01-01 00:00:00",
				Summary:   "ok",
				Items:     []doctor.DoctorItem{{Name: "test", Status: "ok", Summary: "ok"}},
			}
		},
	}

	run := func(args ...string) (string, error) {
		c := cmd.NewDoctorCmdWithDeps(cfgPath, deps)
		var out bytes.Buffer
		c.SetOut(&out)
		c.SetErr(&out)
		c.SetArgs(args)
		err := c.ExecuteContext(t.Context())
		return out.String(), err
	}

	// 1. --mode client --json 输出 8 项深度体检 JSON
	clientJSON, err := run("--mode", "client", "--json")
	if err != nil {
		t.Fatalf("doctor --mode client --json failed: %v", err)
	}
	var rep doctor.Report
	if err := json.Unmarshal([]byte(clientJSON), &rep); err != nil {
		t.Fatalf("unmarshal client doctor JSON: %v (raw=%s)", err, clientJSON)
	}
	if len(rep.Checks) != 8 {
		t.Fatalf("expected 8 checks in client mode, got %d", len(rep.Checks))
	}

	// 2. --mode client 文本模式使用 FormatText 输出
	clientText, err := run("--mode", "client")
	if err != nil {
		t.Fatalf("doctor --mode client text failed: %v", err)
	}
	if !strings.Contains(clientText, "SingCtl 全链路深度体检报告") {
		t.Fatalf("expected FormatText header in client mode output, got:\n%s", clientText)
	}

	// 3. --mode server --json 兼容旧服务端体检报告
	srvJSON, err := run("--mode", "server", "--json")
	if err != nil {
		t.Fatalf("doctor --mode server --json failed: %v", err)
	}
	if !serverDoctorCalled.Load() || !strings.Contains(srvJSON, `"score": 100`) && !strings.Contains(srvJSON, `"score":100`) {
		t.Fatalf("expected legacy server doctor called, called=%v out=%s", serverDoctorCalled.Load(), srvJSON)
	}

	// 4. --mode invalid 返回错误
	if _, err := run("--mode", "invalid"); err == nil {
		t.Fatal("expected error for invalid --mode")
	}

	// 5. --fix protect-tailscale-oom 成功，--fix unknown 报错
	fixOut, err := run("--fix", "protect-tailscale-oom", "--json")
	if err != nil {
		t.Fatalf("doctor --fix protect-tailscale-oom failed: %v (out=%s)", err, fixOut)
	}
	if st := safecommit.InspectTailscaledOOM(procRoot); !st.Protected {
		t.Fatalf("expected tailscaled protected after CLI --fix, got %+v", st)
	}
	if _, err := run("--fix", "unknown-action"); err == nil {
		t.Fatal("expected error for unknown --fix action")
	}
}
