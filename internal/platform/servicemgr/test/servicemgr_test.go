// 文件职责：验证平台服务托管适配器（Systemd / Procd / Noop / Mock）的单元名防注入校验、文件权限与生命周期幂等性。
package servicemgr_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"singctl/internal/platform/servicemgr"
)

type recordedCmd struct {
	name string
	args []string
}

type fakeCmdRunner struct {
	mu      sync.Mutex
	calls   []recordedCmd
	failOn  map[string]error
	outText map[string]string
}

func newFakeCmdRunner() *fakeCmdRunner {
	return &fakeCmdRunner{
		failOn:  make(map[string]error),
		outText: make(map[string]string),
	}
}

func cmdKey(name string, args ...string) string {
	return name + " " + strings.Join(args, " ")
}

func (f *fakeCmdRunner) Run(_ context.Context, _ time.Duration, name string, args ...string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, recordedCmd{name: name, args: append([]string(nil), args...)})
	if err, ok := f.failOn[cmdKey(name, args...)]; ok {
		return err
	}
	return nil
}

func (f *fakeCmdRunner) CombinedOutput(_ context.Context, _ time.Duration, name string, args ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, recordedCmd{name: name, args: append([]string(nil), args...)})
	key := cmdKey(name, args...)
	out := []byte(f.outText[key])
	if err, ok := f.failOn[key]; ok {
		return out, err
	}
	return out, nil
}

func (f *fakeCmdRunner) callStrings() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	res := make([]string, 0, len(f.calls))
	for _, c := range f.calls {
		res = append(res, cmdKey(c.name, c.args...))
	}
	return res
}

func TestValidateUnitName(t *testing.T) {
	valid := []string{"sing-box", "singctl-sub", "singctl-ui.service", "tailscaled", "caddy@prod", "wireproxy_0"}
	for _, name := range valid {
		if err := servicemgr.ValidateUnitName(name); err != nil {
			t.Fatalf("expected valid unit name %q, got error: %v", name, err)
		}
	}

	invalid := []string{"", "   ", "../evil", "foo/bar", "a;rm -rf /", "foo bar", "-dash-flag", "a\nb", "foo`id`", "foo$(id)"}
	for _, name := range invalid {
		if err := servicemgr.ValidateUnitName(name); err == nil {
			t.Fatalf("expected invalid unit name %q to be rejected", name)
		}
	}
}

func TestSystemdManager_LifecycleAndUnitFiles(t *testing.T) {
	dir := t.TempDir()
	runner := newFakeCmdRunner()
	mgr := servicemgr.NewSystemdWithDir(runner, dir)
	if mgr.Kind() != servicemgr.InitSystemd {
		t.Fatalf("Kind() = %v, want InitSystemd", mgr.Kind())
	}

	ctx := t.Context()
	unitPath := filepath.Join(dir, "singctl-sub.service")
	spec := servicemgr.UnitSpec{
		Name:        "singctl-sub",
		SystemdPath: unitPath,
		SystemdBody: "[Unit]\nDescription=SubHub\n",
	}

	if err := mgr.InstallUnit(ctx, spec); err != nil {
		t.Fatalf("InstallUnit failed: %v", err)
	}

	info, err := os.Stat(unitPath)
	if err != nil {
		t.Fatalf("expected unit file created: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0644 {
		t.Fatalf("unit file mode = %o, want 0644", perm)
	}

	gotCalls := runner.callStrings()
	wantSeq := []string{
		"systemctl daemon-reload",
		"systemctl enable singctl-sub",
		"systemctl restart singctl-sub",
	}
	for i, w := range wantSeq {
		if i >= len(gotCalls) || gotCalls[i] != w {
			t.Fatalf("call[%d] = %v, want %q (all=%v)", i, gotCalls, w, gotCalls)
		}
	}

	if !mgr.IsActive(ctx, "singctl-sub") {
		t.Fatalf("expected IsActive true when systemctl is-active --quiet succeeds")
	}

	runner.failOn["systemctl is-active --quiet singctl-sub"] = errors.New("inactive")
	if mgr.IsActive(ctx, "singctl-sub") {
		t.Fatalf("expected IsActive false when systemctl returns error")
	}

	if err := mgr.Start(ctx, "singctl-sub"); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	if err := mgr.Reload(ctx, "singctl-sub"); err != nil {
		t.Fatalf("Reload failed: %v", err)
	}
	if err := mgr.ReloadOrRestart(ctx, "singctl-sub"); err != nil {
		t.Fatalf("ReloadOrRestart failed: %v", err)
	}
	if err := mgr.Disable(ctx, "singctl-sub"); err != nil {
		t.Fatalf("Disable failed: %v", err)
	}
	if err := mgr.RemoveUnit(ctx, spec); err != nil {
		t.Fatalf("RemoveUnit failed: %v", err)
	}
	if _, err := os.Stat(unitPath); !os.IsNotExist(err) {
		t.Fatalf("expected unit file removed after RemoveUnit")
	}

	// Unit file missing -> Stop/Restart on missing unit stays idempotent (no error)
	runner2 := newFakeCmdRunner()
	mgr2 := servicemgr.NewSystemdWithDir(runner2, dir)
	if err := mgr2.Stop(ctx, "missing-unit"); err != nil {
		t.Fatalf("Stop on missing unit should be idempotent, got: %v", err)
	}
	if err := mgr2.Restart(ctx, "missing-unit"); err != nil {
		t.Fatalf("Restart on missing unit should be idempotent, got: %v", err)
	}
	if len(runner2.callStrings()) != 0 {
		t.Fatalf("expected no systemctl calls for missing unit files, got %v", runner2.callStrings())
	}

	// Injection guard on all actions
	if err := mgr.Start(ctx, "bad;id"); err == nil {
		t.Fatalf("expected injection guard error on Start")
	}
}

func TestProcdManager_LifecycleAndPermissions(t *testing.T) {
	dir := t.TempDir()
	runner := newFakeCmdRunner()
	mgr := servicemgr.NewProcd(runner, dir)
	if mgr.Kind() != servicemgr.InitProcd {
		t.Fatalf("Kind() = %v, want InitProcd", mgr.Kind())
	}

	ctx := t.Context()
	initPath := filepath.Join(dir, "singctl-sub")
	spec := servicemgr.UnitSpec{
		Name:      "singctl-sub",
		ProcdPath: initPath,
		ProcdBody: "#!/bin/sh /etc/rc.common\nUSE_PROCD=1\n",
	}

	if err := mgr.InstallUnit(ctx, spec); err != nil {
		t.Fatalf("Procd InstallUnit failed: %v", err)
	}
	info, err := os.Stat(initPath)
	if err != nil {
		t.Fatalf("expected init script created: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0755 {
		t.Fatalf("procd script mode = %o, want 0755", perm)
	}

	calls := runner.callStrings()
	if len(calls) < 2 || calls[0] != initPath+" enable" || calls[1] != initPath+" restart" {
		t.Fatalf("unexpected procd InstallUnit calls: %v", calls)
	}

	if err := mgr.Start(ctx, "singctl-sub"); err != nil {
		t.Fatalf("Procd Start failed: %v", err)
	}
	if err := mgr.Reload(ctx, "singctl-sub"); err != nil {
		t.Fatalf("Procd Reload failed: %v", err)
	}
	if err := mgr.ReloadOrRestart(ctx, "singctl-sub"); err != nil {
		t.Fatalf("Procd ReloadOrRestart failed: %v", err)
	}
	runner.outText[initPath+" status"] = "running\n"
	if !mgr.IsActive(ctx, "singctl-sub") {
		t.Fatalf("expected Procd IsActive true when status reports running")
	}
	if err := mgr.DaemonReload(ctx); err != nil {
		t.Fatalf("Procd DaemonReload should be no-op nil: %v", err)
	}
	if err := mgr.RemoveUnit(ctx, spec); err != nil {
		t.Fatalf("Procd RemoveUnit failed: %v", err)
	}
	if _, err := os.Stat(initPath); !os.IsNotExist(err) {
		t.Fatalf("expected procd script removed after RemoveUnit")
	}

	// Missing init script stays idempotent on Stop/Restart and IsActive returns false
	if mgr.IsActive(ctx, "missing-svc") {
		t.Fatalf("expected IsActive false for missing procd script")
	}
	if err := mgr.Stop(ctx, "missing-svc"); err != nil {
		t.Fatalf("Procd Stop on missing script should be idempotent, got: %v", err)
	}
	if err := mgr.Restart(ctx, "missing-svc"); err != nil {
		t.Fatalf("Procd Restart on missing script should be idempotent, got: %v", err)
	}
}

func TestNoopAndMockManagers_RaceSafety(t *testing.T) {
	ctx := t.Context()
	noop := servicemgr.NewNoop()
	if noop.Kind() != servicemgr.InitUnknown {
		t.Fatalf("Noop Kind() = %v, want InitUnknown", noop.Kind())
	}
	if noop.IsActive(ctx, "sing-box") {
		t.Fatalf("Noop IsActive must be false")
	}
	if err := noop.Start(ctx, "sing-box"); err == nil {
		t.Fatalf("expected Noop Start to return unsupported error")
	}
	if err := noop.DaemonReload(ctx); err != nil {
		t.Fatalf("Noop DaemonReload should be harmless nil: %v", err)
	}
	if err := noop.Stop(ctx, "sing-box"); err == nil {
		t.Fatalf("expected Noop Stop error")
	}
	if err := noop.Restart(ctx, "sing-box"); err == nil {
		t.Fatalf("expected Noop Restart error")
	}
	if err := noop.Reload(ctx, "sing-box"); err == nil {
		t.Fatalf("expected Noop Reload error")
	}
	if err := noop.ReloadOrRestart(ctx, "sing-box"); err == nil {
		t.Fatalf("expected Noop ReloadOrRestart error")
	}
	if err := noop.Enable(ctx, "sing-box"); err == nil {
		t.Fatalf("expected Noop Enable error")
	}
	if err := noop.Disable(ctx, "sing-box"); err == nil {
		t.Fatalf("expected Noop Disable error")
	}
	if err := noop.InstallUnit(ctx, servicemgr.UnitSpec{Name: "sing-box"}); err == nil {
		t.Fatalf("expected Noop InstallUnit error")
	}
	if err := noop.RemoveUnit(ctx, servicemgr.UnitSpec{Name: "sing-box"}); err != nil {
		t.Fatalf("Noop RemoveUnit should be safe nil: %v", err)
	}

	mock := servicemgr.NewMock()
	if mock.Kind() != servicemgr.InitSystemd {
		t.Fatalf("Mock Kind() = %v", mock.Kind())
	}
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			name := "svc-a"
			if i%2 == 1 {
				name = "svc-b"
			}
			_ = mock.Enable(ctx, name)
			_ = mock.Start(ctx, name)
			_ = mock.Reload(ctx, name)
			_ = mock.ReloadOrRestart(ctx, name)
			_ = mock.Restart(ctx, name)
			_ = mock.IsActive(ctx, name)
			_ = mock.Stop(ctx, name)
			_ = mock.Disable(ctx, name)
			_ = mock.DaemonReload(ctx)
			_ = mock.InstallUnit(ctx, servicemgr.UnitSpec{Name: name})
			_ = mock.RemoveUnit(ctx, servicemgr.UnitSpec{Name: name})
		})
	}
	wg.Wait()
	if len(mock.Calls()) == 0 {
		t.Fatalf("expected recorded calls on MockManager")
	}
}
