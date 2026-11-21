package serverweb

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"singctl/internal/heal"
)

func TestServeContext_RejectsEmptyPassword(t *testing.T) {
	tmpDir := t.TempDir()
	srv := New(Options{
		SubStoreDir:   filepath.Join(tmpDir, "sub-store"),
		FleetFilePath: filepath.Join(tmpDir, "fleet.yaml"),
		BanFilePath:   filepath.Join(tmpDir, "bans.json"),
		AuditFilePath: filepath.Join(tmpDir, "audit.json"),
		Listen:        "127.0.0.1:0",
		Username:      "opsadmin",
		Password:      "",
	})
	srv.sniff.EnableSystemProbe = false

	err := srv.ServeContext(t.Context())
	if err == nil || !strings.Contains(err.Error(), "密码为空") {
		t.Fatalf("expected empty password error, got %v", err)
	}
}

func TestServeContext_GracefulShutdownFlushesAndStops(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "singctl.yaml")
	if err := os.WriteFile(cfgPath, []byte(`
server:
  node_domain: "node.example.com"
  web_admin:
    enabled: true
    port: 8092
    path: "/sr/abcdefghijklmnop"
    username: "opsadmin"
    password: "Password123"
`), 0600); err != nil {
		t.Fatal(err)
	}

	readyCh := make(chan string, 1)
	auditPath := filepath.Join(tmpDir, "audit.json")
	srv := New(Options{
		ConfigPath:    cfgPath,
		SubStoreDir:   filepath.Join(tmpDir, "sub-store"),
		FleetFilePath: filepath.Join(tmpDir, "fleet.yaml"),
		BanFilePath:   filepath.Join(tmpDir, "bans.json"),
		AuditFilePath: auditPath,
		Listen:        "127.0.0.1:0",
		Username:      "opsadmin",
		Password:      "Password123",
		OnReady: func(listenAddr string) {
			select {
			case readyCh <- listenAddr:
			default:
			}
		},
	})
	srv.sniff.EnableSystemProbe = false
	srv.healScannerOverride = func(_ context.Context, _ string, _ string) heal.StatusReport {
		return heal.StatusReport{}
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ServeContext(ctx)
	}()

	var listenAddr string
	select {
	case listenAddr = <-readyCh:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for server ready")
	}

	// Verify HTTP endpoint responds while lifecycle is active.
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Post(
		"http://"+listenAddr+"/api/server/login",
		"application/json",
		strings.NewReader(`{"username":"opsadmin","password":"Password123"}`),
	)
	if err != nil {
		t.Fatalf("login request failed: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK from login, got %d", resp.StatusCode)
	}

	// Cancel context and verify bounded clean shutdown + persistence flush.
	cancel()
	select {
	case serveErr := <-errCh:
		if serveErr != nil {
			t.Fatalf("ServeContext returned non-nil error after cancel: %v", serveErr)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("ServeContext did not shut down within 3s after context cancel")
	}

	if _, err := os.Stat(auditPath); err != nil {
		t.Fatalf("expected audit state to be flushed on shutdown, got err=%v", err)
	}
}
