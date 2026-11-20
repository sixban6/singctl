package tailscale

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
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

func TestApplyUjailSandbox_InjectIdempotentAndRestore(t *testing.T) {
	ctx := t.Context()
	dir := t.TempDir()
	initPath := filepath.Join(dir, "tailscale")
	backupPath := filepath.Join(dir, "tailscale.singctl.bak")
	ujailBin := filepath.Join(dir, "ujail")
	sockPath := filepath.Join(dir, "tailscaled.sock")

	if err := os.WriteFile(initPath, []byte(sampleStockTailscaleInit), 0755); err != nil {
		t.Fatalf("write stock init: %v", err)
	}
	// Missing ujail binary must fail cleanly when enabling
	if _, err := ApplyUjailSandbox(ctx, true, UjailOptions{
		InitScriptPath: initPath,
		BackupPath:     backupPath,
		UjailBin:       ujailBin,
		SocketPath:     sockPath,
	}); err == nil {
		t.Fatal("expected error when ujail binary does not exist")
	}

	if err := os.WriteFile(ujailBin, []byte("#!/bin/sh\n"), 0755); err != nil {
		t.Fatalf("write dummy ujail: %v", err)
	}
	if err := os.WriteFile(sockPath, []byte{}, 0600); err != nil {
		t.Fatalf("write dummy sock: %v", err)
	}

	restarts := 0
	opts := UjailOptions{
		InitScriptPath: initPath,
		BackupPath:     backupPath,
		UjailBin:       ujailBin,
		SocketPath:     sockPath,
		ServiceRunner: func(ctx context.Context, script string, action string) error {
			if action == "restart" {
				restarts++
			}
			return nil
		},
	}

	changed, err := ApplyUjailSandbox(ctx, true, opts)
	if err != nil || !changed || restarts != 1 {
		t.Fatalf("enable failed: changed=%v restarts=%d err=%v", changed, restarts, err)
	}
	got, _ := os.ReadFile(initPath)
	if !strings.Contains(string(got), "procd_add_jail tailscale") || !strings.Contains(string(got), ujailMarker) {
		t.Fatalf("expected ujail lines injected:\n%s", string(got))
	}

	// Re-applying enable=true is a no-op (0 restarts)
	changed, err = ApplyUjailSandbox(ctx, true, opts)
	if err != nil || changed || restarts != 1 {
		t.Fatalf("expected idempotent enable=true, got changed=%v restarts=%d err=%v", changed, restarts, err)
	}

	// Disabling restores exact stock script and restarts once
	changed, err = ApplyUjailSandbox(ctx, false, opts)
	if err != nil || !changed || restarts != 2 {
		t.Fatalf("disable failed: changed=%v restarts=%d err=%v", changed, restarts, err)
	}
	restored, _ := os.ReadFile(initPath)
	if string(restored) != sampleStockTailscaleInit {
		t.Fatalf("expected exact stock script restored:\n%s", string(restored))
	}
}
