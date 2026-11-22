// 文件职责：验证客户端 WebUI 服务的 lifecycle.Group 三阶段确定性启停、逆序回收与取消传递。
package webui_test

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"singctl/internal/webui"
	"testing"
	"time"
)

func TestWebUIServeContext_LifecycleAndGracefulShutdown(t *testing.T) {
	t.Run("graceful_start_and_fast_shutdown_without_goroutine_hang", func(t *testing.T) {
		dir := t.TempDir()
		cfgPath := filepath.Join(dir, "singctl.yaml")
		if err := os.WriteFile(cfgPath, []byte("hy2:\n  up: 50\n  down: 200\n"), 0600); err != nil {
			t.Fatal(err)
		}

		readyCh := make(chan string, 1)
		srv := webui.New(webui.Options{
			ConfigPath:              cfgPath,
			Listen:                  "127.0.0.1:0",
			Password:                "test-secret",
			Version:                 "v1.14.158",
			SkipAdGuardProbeForTest: true,
			OnReady: func(listenAddr string) {
				select {
				case readyCh <- listenAddr:
				default:
				}
			},
		})

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		errCh := make(chan error, 1)
		go func() {
			errCh <- srv.ServeContext(ctx)
		}()

		var addr string
		select {
		case addr = <-readyCh:
		case <-time.After(3 * time.Second):
			t.Fatal("timed out waiting for webui OnReady")
		}

		resp, err := http.Get("http://" + addr + "/api/auth/check")
		if err != nil {
			t.Fatalf("GET /api/auth/check failed: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 OK from /api/auth/check, got %d", resp.StatusCode)
		}

		startShutdown := time.Now()
		cancel()
		select {
		case serveErr := <-errCh:
			if serveErr != nil {
				t.Fatalf("expected nil error on graceful ctx cancel, got %v", serveErr)
			}
			if elapsed := time.Since(startShutdown); elapsed > 2*time.Second {
				t.Fatalf("expected fast shutdown without waiting on 3s sleep, took %v", elapsed)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("ServeContext did not shut down within 3s")
		}
	})

	t.Run("already_cancelled_context_fails_immediately", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		srv := webui.New(webui.Options{
			Listen:                  "127.0.0.1:0",
			SkipAdGuardProbeForTest: true,
		})
		if err := srv.ServeContext(ctx); err == nil {
			t.Fatal("expected error when ServeContext called with cancelled ctx")
		}
	})
}
