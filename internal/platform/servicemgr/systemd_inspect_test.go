// 文件职责：测试 systemd 批量状态探测、单元属性查询与立即启停（--now）的边界条件、防注入与并发安全。
package servicemgr

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func TestParseSystemdShowBatchAndShowUnitsBatch(t *testing.T) {
	ctx := t.Context()
	raw := `
Id=caddy.service
ActiveState=active
MainPID=568
ActiveEnterTimestamp=Mon 2026-11-16 15:06:25 EST

Id=sing-box.service
ActiveState=active
MainPID=571
ActiveEnterTimestamp=

Id=singctl-sub.service
ActiveState=inactive
MainPID=0
ActiveEnterTimestamp=n/a

Id=wireproxy.service
ActiveState=active
MainPID=983
ActiveEnterTimestamp=Mon 2026-11-16 15:07:37 EST
`
	parsed := ParseSystemdShowBatch(raw)
	if len(parsed) != 4 {
		t.Fatalf("expected 4 parsed units, got %d (%+v)", len(parsed), parsed)
	}
	if !parsed["caddy"].Running || parsed["caddy"].PID != "568" || parsed["caddy"].ActiveEnterTimestamp == "" {
		t.Fatalf("unexpected caddy status: %+v", parsed["caddy"])
	}
	if !parsed["sing-box"].Running || parsed["sing-box"].PID != "571" || parsed["sing-box"].ActiveEnterTimestamp != "" {
		t.Fatalf("unexpected sing-box status: %+v", parsed["sing-box"])
	}
	if parsed["singctl-sub"].Running || parsed["singctl-sub"].PID != "" || parsed["singctl-sub"].ActiveEnterTimestamp != "" {
		t.Fatalf("unexpected singctl-sub status: %+v", parsed["singctl-sub"])
	}

	if empty := ParseSystemdShowBatch("   \n\ninvalid-line-without-eq\n"); len(empty) != 0 {
		t.Fatalf("expected empty map for malformed/blank input, got %+v", empty)
	}

	runner := newFakeCmdRunner()
	cmdKeyBatch := "systemctl show --property=Id,ActiveState,MainPID,ActiveEnterTimestamp caddy sing-box"
	runner.outText[cmdKeyBatch] = raw
	mgr := NewSystemdWithDir(runner, t.TempDir())

	got := mgr.ShowUnitsBatch(ctx, time.Second, "caddy", "sing-box")
	if !got["caddy"].Running || got["caddy"].PID != "568" {
		t.Fatalf("unexpected ShowUnitsBatch result: %+v", got)
	}

	// Empty units slice -> zero systemctl invocations
	prevCalls := len(runner.callStrings())
	if emptyRes := mgr.ShowUnitsBatch(ctx, time.Second); len(emptyRes) != 0 {
		t.Fatalf("expected empty result for empty units, got %+v", emptyRes)
	}
	if len(runner.callStrings()) != prevCalls {
		t.Fatalf("expected zero runner calls for empty units")
	}

	// Injection attempt in any unit name -> rejected without invoking systemctl
	if injRes := mgr.ShowUnitsBatch(ctx, time.Second, "caddy", "bad;id"); len(injRes) != 0 {
		t.Fatalf("expected empty result when unit slice contains invalid name, got %+v", injRes)
	}
	if len(runner.callStrings()) != prevCalls {
		t.Fatalf("expected zero runner calls on invalid unit name")
	}

	// Command failure with empty output -> returns empty map safely
	runnerFail := newFakeCmdRunner()
	runnerFail.failOn["systemctl show --property=Id,ActiveState,MainPID,ActiveEnterTimestamp caddy"] = errors.New("systemd down")
	mgrFail := NewSystemdWithDir(runnerFail, t.TempDir())
	if failRes := mgrFail.ShowUnitsBatch(ctx, time.Second, "caddy"); len(failRes) != 0 {
		t.Fatalf("expected empty map on failed command with empty output, got %+v", failRes)
	}
}

func TestSystemdManager_TimerAndPropertyOperations(t *testing.T) {
	ctx := t.Context()
	runner := newFakeCmdRunner()
	mgr := NewSystemdWithDir(runner, t.TempDir())

	// IsEnabled states: enabled / static / disabled / invalid name / error
	runner.outText["systemctl is-enabled singctl-heal.timer"] = "enabled\n"
	if !mgr.IsEnabled(ctx, "singctl-heal.timer") {
		t.Fatal("expected IsEnabled true for 'enabled'")
	}
	runner.outText["systemctl is-enabled singctl-heal.timer"] = "static\n"
	if !mgr.IsEnabled(ctx, "singctl-heal.timer") {
		t.Fatal("expected IsEnabled true for 'static'")
	}
	runner.outText["systemctl is-enabled singctl-heal.timer"] = "disabled\n"
	if mgr.IsEnabled(ctx, "singctl-heal.timer") {
		t.Fatal("expected IsEnabled false for 'disabled'")
	}
	if mgr.IsEnabled(ctx, "-bad-flag") {
		t.Fatal("expected IsEnabled false for invalid unit name")
	}

	// EnableNow / DisableNow normal + error + injection
	if err := mgr.EnableNow(ctx, "singctl-heal.timer"); err != nil {
		t.Fatalf("EnableNow failed: %v", err)
	}
	if err := mgr.DisableNow(ctx, "singctl-heal.timer"); err != nil {
		t.Fatalf("DisableNow failed: %v", err)
	}
	if err := mgr.EnableNow(ctx, "evil;rm"); err == nil {
		t.Fatal("expected EnableNow injection error")
	}
	if err := mgr.DisableNow(ctx, "../evil"); err == nil {
		t.Fatal("expected DisableNow injection error")
	}
	runner.failOn["systemctl enable --now broken.timer"] = errors.New("exit 1")
	runner.outText["systemctl enable --now broken.timer"] = "Unit broken.timer not found"
	if err := mgr.EnableNow(ctx, "broken.timer"); err == nil {
		t.Fatal("expected EnableNow error when systemctl fails")
	}

	// ShowProperties normal + invalid unit + invalid property + empty properties
	propKey := "systemctl show singctl-heal.timer --property=NextElapseUSecRealtime,LastTriggerUSec"
	runner.outText[propKey] = "NextElapseUSecRealtime=Tue 2026-11-24 04:00:00 UTC\nLastTriggerUSec=n/a\n"
	props, err := mgr.ShowProperties(ctx, time.Second, "singctl-heal.timer", "NextElapseUSecRealtime", "LastTriggerUSec")
	if err != nil {
		t.Fatalf("ShowProperties failed: %v", err)
	}
	if props["NextElapseUSecRealtime"] != "Tue 2026-11-24 04:00:00 UTC" {
		t.Fatalf("unexpected NextElapseUSecRealtime: %+v", props)
	}
	if props["LastTriggerUSec"] != "" {
		t.Fatalf("expected n/a normalized to empty string, got %q", props["LastTriggerUSec"])
	}

	if _, err := mgr.ShowProperties(ctx, time.Second, "singctl-heal.timer"); err == nil {
		t.Fatal("expected error for empty property list")
	}
	if _, err := mgr.ShowProperties(ctx, time.Second, "bad;unit", "ActiveState"); err == nil {
		t.Fatal("expected error for invalid unit name")
	}
	if _, err := mgr.ShowProperties(ctx, time.Second, "singctl-heal.timer", "Bad;Prop"); err == nil {
		t.Fatal("expected error for invalid property name")
	}

	// Concurrent race check
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			_ = mgr.ShowUnitsBatch(ctx, time.Second, "caddy", "sing-box")
			_, _ = mgr.ShowProperties(ctx, time.Second, "singctl-heal.timer", "NextElapseUSecRealtime", "LastTriggerUSec")
			_ = mgr.IsEnabled(ctx, "singctl-heal.timer")
		})
	}
	wg.Wait()
}
