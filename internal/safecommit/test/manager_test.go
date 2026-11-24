// 文件职责：全面测试 Safe Commit 保险丝的 Arm/Confirm/Rollback/Watch/Status 状态机、0600 快照、边界校验、幂等与并发安全。
package safecommit_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"singctl/internal/safecommit"
)

func TestManager_ArmTTLValidationAndInputSanitization(t *testing.T) {
	base := t.TempDir()
	goodFile := filepath.Join(base, "singctl.yaml")
	if err := os.WriteFile(goodFile, []byte("dns:\n  engine: smartdns\n"), 0600); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name    string
		req     safecommit.ArmRequest
		wantTTL int
		wantErr error
	}{
		{
			name:    "zero_ttl_uses_default_180",
			req:     safecommit.ArmRequest{TTLSec: 0, Reason: "default ttl"},
			wantTTL: safecommit.DefaultTTLSec,
		},
		{
			name:    "min_ttl_60_valid",
			req:     safecommit.ArmRequest{TTLSec: safecommit.MinTTLSec, Reason: "min ttl"},
			wantTTL: safecommit.MinTTLSec,
		},
		{
			name:    "max_ttl_600_valid",
			req:     safecommit.ArmRequest{TTLSec: safecommit.MaxTTLSec, Reason: "max ttl"},
			wantTTL: safecommit.MaxTTLSec,
		},
		{
			name:    "below_min_ttl_rejected",
			req:     safecommit.ArmRequest{TTLSec: 59, Reason: "too short"},
			wantErr: safecommit.ErrInvalidTTL,
		},
		{
			name:    "negative_ttl_rejected",
			req:     safecommit.ArmRequest{TTLSec: -10, Reason: "negative"},
			wantErr: safecommit.ErrInvalidTTL,
		},
		{
			name:    "above_max_ttl_rejected",
			req:     safecommit.ArmRequest{TTLSec: 601, Reason: "too long"},
			wantErr: safecommit.ErrInvalidTTL,
		},
		{
			name: "path_traversal_logical_name_rejected",
			req: safecommit.ArmRequest{
				TTLSec:        120,
				SnapshotFiles: map[string]string{"../escape": goodFile},
			},
			wantErr: errors.New("invalid"),
		},
		{
			name: "relative_snapshot_path_rejected",
			req: safecommit.ArmRequest{
				TTLSec:        120,
				SnapshotFiles: map[string]string{"singctl.yaml": "relative/singctl.yaml"},
			},
			wantErr: errors.New("invalid"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stateDir := filepath.Join(t.TempDir(), "sc")
			now := time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)
			mgr := safecommit.NewManager(safecommit.ManagerOptions{
				StateDir: stateDir,
				ProcRoot: t.TempDir(),
				NowFunc:  func() time.Time { return now },
				SpawnWatcher: func(token string) (int, error) {
					return 4242, nil
				},
				KillWatcher: func(int) error { return nil },
			})

			st, err := mgr.Arm(t.Context(), tc.req)
			if tc.wantErr != nil {
				if err == nil {
					t.Fatalf("expected error, got state=%+v", st)
				}
				if errors.Is(tc.wantErr, safecommit.ErrInvalidTTL) && !errors.Is(err, safecommit.ErrInvalidTTL) {
					t.Fatalf("expected ErrInvalidTTL, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Arm unexpected error: %v", err)
			}
			if st.TTLSec != tc.wantTTL || st.ArmedAt != now.Unix() || st.DeadlineUnix != now.Unix()+int64(tc.wantTTL) {
				t.Fatalf("unexpected timestamps/TTL: %+v", st)
			}
			if len(st.Token) != 32 {
				t.Fatalf("expected 32-char random hex token, got %q", st.Token)
			}
			if st.WatcherPID != 4242 {
				t.Fatalf("expected WatcherPID=4242, got %d", st.WatcherPID)
			}
		})
	}
}

func TestManager_ArmSnapshotsPermissionsRenewalAndConfirm(t *testing.T) {
	workDir := t.TempDir()
	stateDir := filepath.Join(workDir, "state")
	procRoot := filepath.Join(workDir, "proc")
	makeFakeProcEntry(t, procRoot, "901", "tailscaled", "-1000\n", 0644)

	cfgPath := filepath.Join(workDir, "singctl.yaml")
	sbPath := filepath.Join(workDir, "config.json")
	missingPath := filepath.Join(workDir, "does-not-exist.conf")
	if err := os.WriteFile(cfgPath, []byte("gateway:\n  mode: main\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sbPath, []byte(`{"dns":{"disable_cache":true}}`), 0600); err != nil {
		t.Fatal(err)
	}

	curTime := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	var spawnedTokens []string
	var killedPIDs []int
	nextPID := 5000

	mgr := safecommit.NewManager(safecommit.ManagerOptions{
		StateDir: stateDir,
		ProcRoot: procRoot,
		NowFunc:  func() time.Time { return curTime },
		SpawnWatcher: func(token string) (int, error) {
			spawnedTokens = append(spawnedTokens, token)
			nextPID++
			return nextPID, nil
		},
		KillWatcher: func(pid int) error {
			killedPIDs = append(killedPIDs, pid)
			return nil
		},
	})

	// Confirm while inactive returns (false, nil).
	ok, err := mgr.Confirm("")
	if err != nil || ok {
		t.Fatalf("expected inactive Confirm=(false, nil), got (%v, %v)", ok, err)
	}

	// Arm #1: only existing files snapshotted.
	st1, err := mgr.Arm(t.Context(), safecommit.ArmRequest{
		TTLSec:            180,
		Reason:            "switch firewall",
		SingBoxWasRunning: true,
		FirewallWasActive: true,
		DNSEngine:         "smartdns",
		SnapshotFiles: map[string]string{
			"singctl.yaml":  cfgPath,
			"config.json":   sbPath,
			"smartdns.conf": missingPath,
		},
	})
	if err != nil {
		t.Fatalf("Arm #1 error: %v", err)
	}
	if len(st1.Snapshots) != 2 || st1.Snapshots["singctl.yaml"] != cfgPath || st1.Snapshots["config.json"] != sbPath {
		t.Fatalf("unexpected snapshots map: %+v", st1.Snapshots)
	}
	if _, exists := st1.Snapshots["smartdns.conf"]; exists {
		t.Fatalf("non-existent file should not be snapshotted: %+v", st1.Snapshots)
	}

	// Verify 0700 stateDir & 0600 state.json permissions on Unix.
	if runtime.GOOS != "windows" {
		dirInfo, err := os.Stat(stateDir)
		if err != nil {
			t.Fatal(err)
		}
		if dirInfo.Mode().Perm() != 0700 {
			t.Fatalf("expected stateDir perm 0700, got %o", dirInfo.Mode().Perm())
		}
		stInfo, err := os.Stat(filepath.Join(stateDir, "state.json"))
		if err != nil {
			t.Fatal(err)
		}
		if stInfo.Mode().Perm() != 0600 {
			t.Fatalf("expected state.json perm 0600, got %o", stInfo.Mode().Perm())
		}
	}

	// Status reflects active state, remaining seconds & TailscaleOOM.
	curTime = curTime.Add(30 * time.Second)
	status := mgr.Status()
	if !status.Active || status.State == nil || status.State.Token != st1.Token || status.RemainingSec != 150 {
		t.Fatalf("unexpected active Status: %+v", status)
	}
	if !status.TailscaleOOM.Found || !status.TailscaleOOM.Protected {
		t.Fatalf("expected TailscaleOOM protected in Status, got %+v", status.TailscaleOOM)
	}

	// Arm #2 renews cleanly and stops previous watcher PID (5001).
	st2, err := mgr.Arm(t.Context(), safecommit.ArmRequest{
		TTLSec:        240,
		Reason:        "renew fuse",
		SnapshotFiles: map[string]string{"singctl.yaml": cfgPath},
	})
	if err != nil {
		t.Fatalf("Arm #2 error: %v", err)
	}
	if st2.Token == st1.Token {
		t.Fatalf("expected new random token on renewal, got same %q", st2.Token)
	}
	if len(killedPIDs) != 1 || killedPIDs[0] != st1.WatcherPID {
		t.Fatalf("expected previous watcher PID %d killed on renewal, got %v", st1.WatcherPID, killedPIDs)
	}

	// Confirm with wrong token must fail and keep fuse armed.
	ok, err = mgr.Confirm("wrong-token")
	if !errors.Is(err, safecommit.ErrTokenMismatch) || ok {
		t.Fatalf("expected ErrTokenMismatch, got (%v, %v)", ok, err)
	}
	if !mgr.Status().Active {
		t.Fatal("fuse must remain active after mismatched Confirm")
	}

	// Confirm with matching token disarms atomically and stops watcher #2.
	ok, err = mgr.Confirm(st2.Token)
	if err != nil || !ok {
		t.Fatalf("Confirm with valid token failed: (%v, %v)", ok, err)
	}
	if mgr.Status().Active {
		t.Fatal("fuse must be inactive after Confirm")
	}
	if len(killedPIDs) != 2 || killedPIDs[1] != st2.WatcherPID {
		t.Fatalf("expected watcher PID %d killed on confirm, got %v", st2.WatcherPID, killedPIDs)
	}
	if len(spawnedTokens) != 2 {
		t.Fatalf("expected 2 spawned watchers, got %d", len(spawnedTokens))
	}
}

func TestManager_RollbackRestoresFilesAndInvokesServiceOps(t *testing.T) {
	t.Run("running_singbox_active_firewall_with_dns", func(t *testing.T) {
		workDir := t.TempDir()
		stateDir := filepath.Join(workDir, "state")
		cfgPath := filepath.Join(workDir, "singctl.yaml")
		sbPath := filepath.Join(workDir, "config.json")
		origCfg := "gateway:\n  ipv6_mode: off\n"
		origSB := `{"dns":{"optimistic":false,"disable_cache":true}}`
		if err := os.WriteFile(cfgPath, []byte(origCfg), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(sbPath, []byte(origSB), 0600); err != nil {
			t.Fatal(err)
		}

		var calls []string
		var callbackRec *safecommit.RollbackRecord
		now := time.Date(2026, 11, 22, 14, 0, 0, 0, time.UTC)

		mgr := safecommit.NewManager(safecommit.ManagerOptions{
			StateDir:     stateDir,
			ProcRoot:     t.TempDir(),
			NowFunc:      func() time.Time { return now },
			SpawnWatcher: func(string) (int, error) { return 6101, nil },
			KillWatcher:  func(int) error { return nil },
			RollbackOps: safecommit.RollbackOps{
				StopSingBox: func(context.Context) error {
					calls = append(calls, "stop_sb")
					return nil
				},
				StartOrReloadSingBox: func(context.Context) error {
					calls = append(calls, "reload_sb")
					return nil
				},
				DisableFirewall: func(context.Context) error {
					calls = append(calls, "disable_fw")
					return nil
				},
				ReloadFirewall: func(context.Context) error {
					calls = append(calls, "reload_fw")
					return nil
				},
				ReloadDNS: func(_ context.Context, engine string) error {
					calls = append(calls, "reload_dns:"+engine)
					return nil
				},
				OnRolledBack: func(rec safecommit.RollbackRecord) {
					cp := rec
					callbackRec = &cp
				},
			},
		})

		st, err := mgr.Arm(t.Context(), safecommit.ArmRequest{
			TTLSec:            120,
			Reason:            "apply risky gateway change",
			SingBoxWasRunning: true,
			FirewallWasActive: true,
			DNSEngine:         "smartdns",
			SnapshotFiles: map[string]string{
				"singctl.yaml": cfgPath,
				"config.json":  sbPath,
			},
		})
		if err != nil {
			t.Fatal(err)
		}

		// Simulate broken config mutation after Arm.
		if err := os.WriteFile(cfgPath, []byte("BROKEN: !!!"), 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(sbPath, []byte(`{"broken":true}`), 0644); err != nil {
			t.Fatal(err)
		}

		now = now.Add(125 * time.Second)
		rec, err := mgr.Rollback(t.Context(), "timeout")
		if err != nil {
			t.Fatalf("Rollback unexpected error: %v", err)
		}
		if rec == nil || !rec.Success || rec.Token != st.Token || rec.Trigger != "timeout" {
			t.Fatalf("unexpected RollbackRecord: %+v", rec)
		}

		// Files must be restored with 0600 permissions.
		gotCfg, _ := os.ReadFile(cfgPath)
		gotSB, _ := os.ReadFile(sbPath)
		if string(gotCfg) != origCfg || string(gotSB) != origSB {
			t.Fatalf("files not restored: cfg=%q sb=%q", string(gotCfg), string(gotSB))
		}
		if runtime.GOOS != "windows" {
			if info, _ := os.Stat(cfgPath); info.Mode().Perm() != 0600 {
				t.Fatalf("expected restored file perm 0600, got %o", info.Mode().Perm())
			}
			if info, _ := os.Stat(filepath.Join(stateDir, "last_rollback.json")); info.Mode().Perm() != 0600 {
				t.Fatalf("expected last_rollback.json perm 0600, got %o", info.Mode().Perm())
			}
		}

		// Exact ops invoked.
		wantCalls := "reload_sb,reload_fw,reload_dns:smartdns"
		if strings.Join(calls, ",") != wantCalls {
			t.Fatalf("ops calls = %q, want %q", strings.Join(calls, ","), wantCalls)
		}
		if callbackRec == nil || !callbackRec.Success {
			t.Fatalf("expected OnRolledBack invoked with success, got %+v", callbackRec)
		}

		// Status now shows inactive + LastRollback persisted.
		status := mgr.Status()
		if status.Active || status.LastRollback == nil || status.LastRollback.Token != st.Token {
			t.Fatalf("unexpected post-rollback Status: %+v", status)
		}

		// Idempotency: second Rollback is a no-op and must not re-invoke ops.
		rec2, err := mgr.Rollback(t.Context(), "manual")
		if err != nil || rec2 != nil {
			t.Fatalf("expected idempotent second Rollback=(nil, nil), got (%+v, %v)", rec2, err)
		}
		if strings.Join(calls, ",") != wantCalls {
			t.Fatalf("ops must not be re-invoked on second Rollback, got %v", calls)
		}
	})

	t.Run("uci_network_snapshot_triggers_reload_openwrt_network", func(t *testing.T) {
		workDir := t.TempDir()
		stateDir := filepath.Join(workDir, "state")
		netCfg := filepath.Join(workDir, "uci-network")
		orig := "config interface 'lan'\n\toption ipaddr '192.168.29.1'\n"
		if err := os.WriteFile(netCfg, []byte(orig), 0600); err != nil {
			t.Fatal(err)
		}

		var reloadedUCI bool
		mgr := safecommit.NewManager(safecommit.ManagerOptions{
			StateDir:     stateDir,
			ProcRoot:     t.TempDir(),
			SpawnWatcher: func(string) (int, error) { return 6109, nil },
			KillWatcher:  func(int) error { return nil },
			RollbackOps: safecommit.RollbackOps{
				ReloadOpenWrtNetwork: func(context.Context) error {
					reloadedUCI = true
					return nil
				},
			},
		})

		if _, err := mgr.Arm(t.Context(), safecommit.ArmRequest{
			TTLSec: 120,
			Reason: "vlan segment update",
			SnapshotFiles: map[string]string{
				"uci_network": netCfg,
			},
		}); err != nil {
			t.Fatal(err)
		}
		_ = os.WriteFile(netCfg, []byte("broken"), 0600)

		rec, err := mgr.Rollback(t.Context(), "timeout")
		if err != nil || rec == nil || !rec.Success {
			t.Fatalf("UCI rollback failed: rec=%+v err=%v", rec, err)
		}
		if !reloadedUCI {
			t.Fatal("expected ReloadOpenWrtNetwork callback invoked when uci_* snapshot restored")
		}
		got, _ := os.ReadFile(netCfg)
		if string(got) != orig {
			t.Fatalf("uci network file not restored: %q", string(got))
		}
	})

	t.Run("stopped_singbox_inactive_firewall_and_partial_error_continues", func(t *testing.T) {
		stateDir := filepath.Join(t.TempDir(), "state")
		var calls []string
		var callbackCalled bool

		mgr := safecommit.NewManager(safecommit.ManagerOptions{
			StateDir:     stateDir,
			ProcRoot:     t.TempDir(),
			SpawnWatcher: func(string) (int, error) { return 6102, nil },
			KillWatcher:  func(int) error { return nil },
			RollbackOps: safecommit.RollbackOps{
				StopSingBox: func(context.Context) error {
					calls = append(calls, "stop_sb")
					return errors.New("stop failed")
				},
				DisableFirewall: func(context.Context) error {
					calls = append(calls, "disable_fw")
					return nil
				},
				OnRolledBack: func(rec safecommit.RollbackRecord) {
					callbackCalled = true
					if rec.Success || !strings.Contains(rec.Error, "stop failed") {
						t.Errorf("expected failed record with error message, got %+v", rec)
					}
				},
			},
		})

		if _, err := mgr.Arm(t.Context(), safecommit.ArmRequest{
			TTLSec:            60,
			Reason:            "initial bring-up",
			SingBoxWasRunning: false,
			FirewallWasActive: false,
		}); err != nil {
			t.Fatal(err)
		}

		rec, err := mgr.Rollback(t.Context(), "manual")
		if err == nil {
			t.Fatal("expected joined error from StopSingBox failure")
		}
		if rec == nil || rec.Success {
			t.Fatalf("expected non-nil failed RollbackRecord, got %+v", rec)
		}
		// Must still execute DisableFirewall even after StopSingBox failed!
		if strings.Join(calls, ",") != "stop_sb,disable_fw" {
			t.Fatalf("expected DisableFirewall to run despite StopSingBox error, got %v", calls)
		}
		if !callbackCalled {
			t.Fatal("expected OnRolledBack callback even on partial failure")
		}
	})
}

func TestManager_WatchTimeoutConfirmSupersedeAndRace(t *testing.T) {
	t.Run("watch_triggers_rollback_on_deadline", func(t *testing.T) {
		stateDir := filepath.Join(t.TempDir(), "state")
		var nowUnix atomic.Int64
		nowUnix.Store(1_700_000_000)
		var rolledBack atomic.Int32

		mgr := safecommit.NewManager(safecommit.ManagerOptions{
			StateDir:      stateDir,
			ProcRoot:      t.TempDir(),
			WatchInterval: 10 * time.Millisecond,
			NowFunc:       func() time.Time { return time.Unix(nowUnix.Load(), 0) },
			SpawnWatcher:  func(string) (int, error) { return 7001, nil },
			KillWatcher:   func(int) error { return nil },
			RollbackOps: safecommit.RollbackOps{
				StopSingBox: func(context.Context) error {
					rolledBack.Add(1)
					return nil
				},
			},
		})

		st, err := mgr.Arm(t.Context(), safecommit.ArmRequest{TTLSec: 60, Reason: "watch test"})
		if err != nil {
			t.Fatal(err)
		}

		done := make(chan error, 1)
		go func() {
			done <- mgr.Watch(t.Context(), st.Token)
		}()

		// Advance clock past deadline.
		time.Sleep(25 * time.Millisecond)
		nowUnix.Add(65)

		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("Watch returned error: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("Watch did not trigger timeout rollback in time")
		}
		if rolledBack.Load() != 1 {
			t.Fatalf("expected exactly 1 timeout rollback, got %d", rolledBack.Load())
		}
	})

	t.Run("watch_exits_cleanly_on_confirm_or_token_change", func(t *testing.T) {
		stateDir := filepath.Join(t.TempDir(), "state")
		var rolledBack atomic.Int32
		mgr := safecommit.NewManager(safecommit.ManagerOptions{
			StateDir:      stateDir,
			ProcRoot:      t.TempDir(),
			WatchInterval: 10 * time.Millisecond,
			SpawnWatcher:  func(string) (int, error) { return 7002, nil },
			KillWatcher:   func(int) error { return nil },
			RollbackOps: safecommit.RollbackOps{
				StopSingBox: func(context.Context) error {
					rolledBack.Add(1)
					return nil
				},
			},
		})

		st, err := mgr.Arm(t.Context(), safecommit.ArmRequest{TTLSec: 120})
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() {
			done <- mgr.Watch(t.Context(), st.Token)
		}()

		time.Sleep(20 * time.Millisecond)
		if ok, err := mgr.Confirm(st.Token); err != nil || !ok {
			t.Fatalf("Confirm failed: (%v, %v)", ok, err)
		}

		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("Watch should exit nil on Confirm, got %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("Watch did not exit after Confirm")
		}
		if rolledBack.Load() != 0 {
			t.Fatalf("rollback must not run after Confirm, got %d", rolledBack.Load())
		}
	})

	t.Run("watch_exits_cleanly_on_token_supersede_and_ctx_cancel", func(t *testing.T) {
		stateDir := filepath.Join(t.TempDir(), "state")
		var rolledBack atomic.Int32
		mgr := safecommit.NewManager(safecommit.ManagerOptions{
			StateDir:      stateDir,
			ProcRoot:      t.TempDir(),
			WatchInterval: 10 * time.Millisecond,
			SpawnWatcher:  func(string) (int, error) { return 7004, nil },
			KillWatcher:   func(int) error { return nil },
			RollbackOps: safecommit.RollbackOps{
				StopSingBox: func(context.Context) error {
					rolledBack.Add(1)
					return nil
				},
			},
		})

		st1, err := mgr.Arm(t.Context(), safecommit.ArmRequest{TTLSec: 120})
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() {
			done <- mgr.Watch(t.Context(), st1.Token)
		}()

		// Re-arm replaces token; old watcher must exit nil without rolling back.
		time.Sleep(20 * time.Millisecond)
		st2, err := mgr.Arm(t.Context(), safecommit.ArmRequest{TTLSec: 120})
		if err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("superseded Watch should exit nil, got %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("superseded Watch did not exit")
		}
		if rolledBack.Load() != 0 {
			t.Fatalf("superseded Watch must not trigger rollback")
		}

		// Context cancellation exits Watch cleanly with context.Canceled.
		cCtx, cancel := context.WithCancel(t.Context())
		done2 := make(chan error, 1)
		go func() {
			done2 <- mgr.Watch(cCtx, st2.Token)
		}()
		time.Sleep(20 * time.Millisecond)
		cancel()
		select {
		case err := <-done2:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("expected context.Canceled, got %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("cancelled Watch did not exit")
		}
	})

	t.Run("arm_cleans_up_state_when_spawn_watcher_fails", func(t *testing.T) {
		stateDir := filepath.Join(t.TempDir(), "state")
		mgr := safecommit.NewManager(safecommit.ManagerOptions{
			StateDir: stateDir,
			ProcRoot: t.TempDir(),
			SpawnWatcher: func(string) (int, error) {
				return 0, errors.New("fork failed")
			},
		})
		if _, err := mgr.Arm(t.Context(), safecommit.ArmRequest{TTLSec: 120}); err == nil {
			t.Fatal("expected error when SpawnWatcher fails")
		}
		if mgr.Status().Active {
			t.Fatal("state.json must be cleaned up when SpawnWatcher fails")
		}
	})

	t.Run("concurrent_confirm_and_rollback_race_free_exactly_once", func(t *testing.T) {
		stateDir := filepath.Join(t.TempDir(), "state")
		var rbOpsCount atomic.Int32
		mgr := safecommit.NewManager(safecommit.ManagerOptions{
			StateDir:     stateDir,
			ProcRoot:     t.TempDir(),
			SpawnWatcher: func(string) (int, error) { return 7003, nil },
			KillWatcher:  func(int) error { return nil },
			RollbackOps: safecommit.RollbackOps{
				StopSingBox: func(context.Context) error {
					rbOpsCount.Add(1)
					return nil
				},
			},
		})
		st, err := mgr.Arm(t.Context(), safecommit.ArmRequest{TTLSec: 120})
		if err != nil {
			t.Fatal(err)
		}

		var confirmWins atomic.Int32
		var rollbackWins atomic.Int32
		var wg sync.WaitGroup
		for range 8 {
			wg.Go(func() {
				if ok, err := mgr.Confirm(st.Token); err == nil && ok {
					confirmWins.Add(1)
				}
			})
			wg.Go(func() {
				if rec, err := mgr.Rollback(t.Context(), "race"); err == nil && rec != nil {
					rollbackWins.Add(1)
				}
			})
			wg.Go(func() {
				_ = mgr.Status()
			})
		}
		wg.Wait()

		totalWins := confirmWins.Load() + rollbackWins.Load()
		if totalWins != 1 {
			t.Fatalf("expected exactly 1 winner across concurrent Confirm/Rollback, got confirm=%d rollback=%d",
				confirmWins.Load(), rollbackWins.Load())
		}
		if rbOpsCount.Load() != rollbackWins.Load() {
			t.Fatalf("rbOpsCount=%d must equal rollbackWins=%d", rbOpsCount.Load(), rollbackWins.Load())
		}
	})
}

func TestManager_DefaultOptionsInstantiation(t *testing.T) {
	// Ensures default production helpers (SpawnWatcher / KillWatcher / WatchInterval / NowFunc) are wired cleanly.
	mgr := safecommit.NewManager(safecommit.ManagerOptions{
		StateDir: filepath.Join(t.TempDir(), "defaults"),
		ProcRoot: t.TempDir(),
	})
	rep := mgr.Status()
	if rep.Active {
		t.Fatalf("expected inactive default status, got %+v", rep)
	}
	if err := mgr.Watch(t.Context(), ""); err == nil {
		t.Fatal("expected error for empty watch token")
	}
}

func TestManager_ReArmWhileActivePreservesOriginalBaseline(t *testing.T) {
	workDir := t.TempDir()
	stateDir := filepath.Join(workDir, "state")
	cfgPath := filepath.Join(workDir, "network.cfg")
	if err := os.WriteFile(cfgPath, []byte("known-good-v1"), 0600); err != nil {
		t.Fatal(err)
	}

	curTime := time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC)
	pid := 8100
	mgr := safecommit.NewManager(safecommit.ManagerOptions{
		StateDir:     stateDir,
		ProcRoot:     t.TempDir(),
		NowFunc:      func() time.Time { return curTime },
		SpawnWatcher: func(string) (int, error) { pid++; return pid, nil },
		KillWatcher:  func(int) error { return nil },
	})

	// Arm #1 captures original known-good-v1
	if _, err := mgr.Arm(t.Context(), safecommit.ArmRequest{
		TTLSec:        180,
		Reason:        "edit 1",
		SnapshotFiles: map[string]string{"uci_network": cfgPath},
	}); err != nil {
		t.Fatalf("Arm #1 failed: %v", err)
	}

	// Simulate unconfirmed mutation #1 on disk
	if err := os.WriteFile(cfgPath, []byte("unconfirmed-v2"), 0600); err != nil {
		t.Fatal(err)
	}

	// Arm #2 while Arm #1 is still active (now < DeadlineUnix) MUST inherit known-good-v1, NOT overwrite with unconfirmed-v2
	curTime = curTime.Add(30 * time.Second)
	if _, err := mgr.Arm(t.Context(), safecommit.ArmRequest{
		TTLSec:        180,
		Reason:        "edit 2",
		SnapshotFiles: map[string]string{"uci_network": cfgPath},
	}); err != nil {
		t.Fatalf("Arm #2 failed: %v", err)
	}

	// Simulate unconfirmed mutation #2 on disk
	if err := os.WriteFile(cfgPath, []byte("unconfirmed-v3"), 0600); err != nil {
		t.Fatal(err)
	}

	// Rollback MUST restore original known-good-v1
	rec, err := mgr.Rollback(t.Context(), "timeout")
	if err != nil || rec == nil {
		t.Fatalf("Rollback failed: rec=%+v err=%v", rec, err)
	}
	got, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "known-good-v1" {
		t.Fatalf("expected original known-good-v1 restored after consecutive unconfirmed edits, got %q", string(got))
	}
}
