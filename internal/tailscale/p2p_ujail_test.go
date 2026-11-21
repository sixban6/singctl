package tailscale

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

const sampleStockTailscaleInit = `#!/bin/sh /etc/rc.common
USE_PROCD=1
START=99
STOP=10

start_service() {
    mkdir -p /etc/tailscale
    mkdir -p /var/run/tailscale

    procd_open_instance
    procd_set_param command /usr/sbin/tailscaled
    procd_append_param command --state=/etc/tailscale/tailscaled.state
    procd_append_param command --socket=/var/run/tailscale/tailscaled.sock
    procd_append_param command --port=41641
    procd_set_param respawn
    procd_close_instance
}
`

func startMockLocalAPIServer(t *testing.T, sockPath, state string) func() {
	t.Helper()
	_ = os.Remove(sockPath)
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen unix %s: %v", sockPath, err)
	}
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/localapi/v0/status" {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"BackendState":"` + state + `"}`))
		}),
	}
	go func() { _ = srv.Serve(ln) }()
	stopFn := func() {
		_ = srv.Close()
		_ = ln.Close()
		_ = os.Remove(sockPath)
	}
	t.Cleanup(stopFn)
	return stopFn
}

func TestApplyUjailSandbox_InjectIdempotentRestoreAndSyntax(t *testing.T) {
	ctx := t.Context()
	dir := t.TempDir()
	initPath := filepath.Join(dir, "tailscale")
	backupPath := filepath.Join(dir, "tailscale.singctl.bak")
	capsPath := filepath.Join(dir, "capabilities", "tailscale.json")
	ujailBin := filepath.Join(dir, "ujail")

	sockDir, err := os.MkdirTemp("/tmp", "ts-ujail-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	sockPath := filepath.Join(sockDir, "ts.sock")

	if err := os.WriteFile(initPath, []byte(sampleStockTailscaleInit), 0755); err != nil {
		t.Fatalf("write stock init: %v", err)
	}
	// Missing ujail binary must fail cleanly when enabling
	if _, err := ApplyUjailSandbox(ctx, true, UjailOptions{
		InitScriptPath: initPath,
		BackupPath:     backupPath,
		CapsFilePath:   capsPath,
		UjailBin:       ujailBin,
		SocketPath:     sockPath,
	}); err == nil {
		t.Fatal("expected error when ujail binary does not exist")
	}

	if err := os.WriteFile(ujailBin, []byte("#!/bin/sh\n"), 0755); err != nil {
		t.Fatalf("write dummy ujail: %v", err)
	}

	// Simulate an already-running pre-jail tailscaled LocalAPI that stops on "stop"
	stopOld := startMockLocalAPIServer(t, sockPath, "Running")
	var actions []string
	opts := UjailOptions{
		InitScriptPath: initPath,
		BackupPath:     backupPath,
		CapsFilePath:   capsPath,
		UjailBin:       ujailBin,
		SocketPath:     sockPath,
		ReadyTimeout:   3 * time.Second,
		ServiceRunner: func(ctx context.Context, script string, action string) error {
			actions = append(actions, action)
			switch action {
			case "stop":
				stopOld()
			case "start":
				startMockLocalAPIServer(t, sockPath, "Running")
			}
			return nil
		},
	}

	changed, err := ApplyUjailSandbox(ctx, true, opts)
	if err != nil || !changed {
		t.Fatalf("enable failed: changed=%v actions=%v err=%v", changed, actions, err)
	}
	if !slices.Equal(actions, []string{"stop", "start"}) {
		t.Fatalf("expected [stop start] sequence, got %v", actions)
	}

	gotBytes, _ := os.ReadFile(initPath)
	got := string(gotBytes)
	for _, want := range []string{
		ujailMarker,
		ujailMarkerV2,
		"procd_add_jail tailscale log procfs sysfs ronly",
		"procd_set_param capabilities",
		"procd_set_param no_new_privs 1",
		"procd_add_jail_mount_rw /etc/tailscale /var/run/tailscale /var/lib/tailscale /dev/net/tun",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("expected %q in injected script:\n%s", want, got)
		}
	}

	capsRaw, err := os.ReadFile(capsPath)
	if err != nil {
		t.Fatalf("expected capabilities file %s: %v", capsPath, err)
	}
	var parsedCaps map[string][]string
	if err := json.Unmarshal(capsRaw, &parsedCaps); err != nil {
		t.Fatalf("decode capabilities json: %v", err)
	}
	wantCaps := []string{"CAP_NET_BIND_SERVICE", "CAP_NET_ADMIN", "CAP_NET_RAW"}
	for _, field := range []string{"bounding", "effective", "ambient", "permitted", "inheritable"} {
		if !slices.Equal(parsedCaps[field], wantCaps) {
			t.Fatalf("capabilities[%s] = %v, want ONLY %v", field, parsedCaps[field], wantCaps)
		}
	}
	// /dev/net/tun must NEVER appear as a read-only mount
	if strings.Contains(got, "procd_add_jail_mount /usr/sbin/tailscaled /usr/sbin/tailscale /etc/ssl/certs /dev/net/tun") ||
		strings.Contains(got, "procd_add_jail_mount_rw /etc/tailscale /var/run/tailscale\n") {
		t.Fatalf("found unsafe legacy mount lines:\n%s", got)
	}
	// /tmp root directory itself must never be mounted wholesale
	for line := range strings.SplitSeq(got, "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && (fields[0] == "procd_add_jail_mount" || fields[0] == "procd_add_jail_mount_rw") {
			if slices.Contains(fields[1:], "/tmp") {
				t.Fatalf("jail must never mount whole /tmp directory: %q", line)
			}
		}
	}

	// Verify generated script passes POSIX sh syntax validation
	if shBin, err := exec.LookPath("sh"); err == nil {
		if out, err := exec.CommandContext(ctx, shBin, "-n", initPath).CombinedOutput(); err != nil {
			t.Fatalf("injected init script failed sh -n syntax check: %v (%s)", err, out)
		}
	}

	// Re-applying enable=true is a no-op
	prevLen := len(actions)
	changed, err = ApplyUjailSandbox(ctx, true, opts)
	if err != nil || changed || len(actions) != prevLen {
		t.Fatalf("expected idempotent enable=true, got changed=%v actions=%v err=%v", changed, actions, err)
	}

	// Disabling restores exact stock script, deletes caps JSON, and restarts once
	changed, err = ApplyUjailSandbox(ctx, false, opts)
	if err != nil || !changed || actions[len(actions)-1] != "restart" {
		t.Fatalf("disable failed: changed=%v actions=%v err=%v", changed, actions, err)
	}
	if _, err := os.Stat(capsPath); !os.IsNotExist(err) {
		t.Fatalf("expected capabilities file removed on disable, stat err=%v", err)
	}
	restored, _ := os.ReadFile(initPath)
	if string(restored) != sampleStockTailscaleInit {
		t.Fatalf("expected exact stock script restored:\n%s", string(restored))
	}
}

func TestApplyUjailSandbox_UpgradesV1ToV2Cleanly(t *testing.T) {
	ctx := t.Context()
	dir := t.TempDir()
	initPath := filepath.Join(dir, "tailscale")
	backupPath := filepath.Join(dir, "tailscale.singctl.bak")
	capsPath := filepath.Join(dir, "capabilities", "tailscale.json")
	ujailBin := filepath.Join(dir, "ujail")

	sockDir, err := os.MkdirTemp("/tmp", "ts-ujail-v2-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	sockPath := filepath.Join(sockDir, "ts.sock")

	legacyV1 := strings.Replace(
		sampleStockTailscaleInit,
		"    procd_close_instance",
		"    "+ujailMarker+"\n    procd_add_jail tailscale log procfs sysfs ronly\n    procd_close_instance",
		1,
	)
	if err := os.WriteFile(initPath, []byte(legacyV1), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(backupPath, []byte(sampleStockTailscaleInit), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ujailBin, []byte("#!/bin/sh\n"), 0755); err != nil {
		t.Fatal(err)
	}

	stopOld := startMockLocalAPIServer(t, sockPath, "Running")
	var actions []string
	opts := UjailOptions{
		InitScriptPath: initPath,
		BackupPath:     backupPath,
		CapsFilePath:   capsPath,
		UjailBin:       ujailBin,
		SocketPath:     sockPath,
		ReadyTimeout:   3 * time.Second,
		ServiceRunner: func(_ context.Context, _ string, action string) error {
			actions = append(actions, action)
			switch action {
			case "stop":
				stopOld()
			case "start":
				startMockLocalAPIServer(t, sockPath, "Running")
			}
			return nil
		},
	}

	changed, err := ApplyUjailSandbox(ctx, true, opts)
	if err != nil || !changed {
		t.Fatalf("expected V1->V2 upgrade to succeed with changed=true, got changed=%v err=%v", changed, err)
	}
	if !slices.Equal(actions, []string{"stop", "start"}) {
		t.Fatalf("expected [stop start], got %v", actions)
	}

	upgradedBytes, err := os.ReadFile(initPath)
	if err != nil {
		t.Fatal(err)
	}
	upgraded := string(upgradedBytes)
	if strings.Count(upgraded, "procd_add_jail ") != 1 {
		t.Fatalf("expected exactly one procd_add_jail block after V1->V2 upgrade, got:\n%s", upgraded)
	}
	for _, want := range []string{
		ujailMarkerV2,
		"procd_set_param capabilities",
		"procd_set_param no_new_privs 1",
	} {
		if !strings.Contains(upgraded, want) {
			t.Fatalf("expected %q after upgrade:\n%s", want, upgraded)
		}
	}
	if shBin, err := exec.LookPath("sh"); err == nil {
		if out, err := exec.CommandContext(ctx, shBin, "-n", initPath).CombinedOutput(); err != nil {
			t.Fatalf("upgraded script failed sh -n: %v (%s)", err, out)
		}
	}
	// Missing clean backup for a legacy V1 script fails cleanly without duplicating directives.
	noBakDir := t.TempDir()
	noBakInit := filepath.Join(noBakDir, "tailscale")
	_ = os.WriteFile(noBakInit, []byte(legacyV1), 0755)
	if changed, err := ApplyUjailSandbox(ctx, true, UjailOptions{
		InitScriptPath: noBakInit,
		BackupPath:     filepath.Join(noBakDir, "missing.bak"),
		CapsFilePath:   filepath.Join(noBakDir, "caps.json"),
		UjailBin:       ujailBin,
		SocketPath:     sockPath,
	}); err == nil || changed {
		t.Fatalf("expected error when upgrading V1 script without clean backup, got changed=%v err=%v", changed, err)
	}
}

func TestApplyUjailSandbox_StaleSocketTriggersRollback(t *testing.T) {
	ctx := t.Context()
	dir := t.TempDir()
	initPath := filepath.Join(dir, "tailscale")
	backupPath := filepath.Join(dir, "tailscale.singctl.bak")
	ujailBin := filepath.Join(dir, "ujail")

	sockDir, err := os.MkdirTemp("/tmp", "ts-stale-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	sockPath := filepath.Join(sockDir, "tailscaled.sock")

	if err := os.WriteFile(initPath, []byte(sampleStockTailscaleInit), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ujailBin, []byte("#!/bin/sh\n"), 0755); err != nil {
		t.Fatal(err)
	}
	// Leave a dead stale socket file on disk (no listener behind it!)
	if err := os.WriteFile(sockPath, []byte{}, 0600); err != nil {
		t.Fatal(err)
	}

	var actions []string
	changed, err := ApplyUjailSandbox(ctx, true, UjailOptions{
		InitScriptPath: initPath,
		BackupPath:     backupPath,
		CapsFilePath:   filepath.Join(dir, "caps.json"),
		UjailBin:       ujailBin,
		SocketPath:     sockPath,
		ReadyTimeout:   600 * time.Millisecond,
		ServiceRunner: func(_ context.Context, _ string, action string) error {
			actions = append(actions, action)
			return nil
		},
	})
	if err == nil || changed {
		t.Fatalf("expected stale socket to fail and roll back, got changed=%v err=%v", changed, err)
	}
	if !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("expected rollback error message, got %v", err)
	}
	if !slices.Equal(actions, []string{"stop", "start", "restart"}) {
		t.Fatalf("expected [stop start restart(rollback)], got %v", actions)
	}
	restored, _ := os.ReadFile(initPath)
	if string(restored) != sampleStockTailscaleInit {
		t.Fatalf("expected init script rolled back to exact original:\n%s", string(restored))
	}
}
