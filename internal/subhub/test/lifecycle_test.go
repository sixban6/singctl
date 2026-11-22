// 文件职责：验证 SubHub 订阅聚合服务的 lifecycle.Group 三阶段确定性启停、优雅关停与 config.Store 热路径快照隔离。
package subhub_test

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"singctl/internal/config"
	"singctl/internal/subhub"
)

func TestSubHubLifecycleAndConfigStore(t *testing.T) {
	t.Run("serve_context_lifecycle_and_graceful_shutdown", func(t *testing.T) {
		dir := t.TempDir()
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		readyCh := make(chan string, 1)
		srv := subhub.NewServer(subhub.Options{
			Listen:  "127.0.0.1:0",
			DataDir: dir,
			Version: "v1.14.158",
			OnReady: func(addr string) {
				readyCh <- addr
			},
		})

		errCh := make(chan error, 1)
		go func() {
			errCh <- srv.ServeContext(ctx)
		}()

		var addr string
		select {
		case addr = <-readyCh:
		case <-time.After(3 * time.Second):
			t.Fatal("timed out waiting for SubHub OnReady")
		}

		keyInfo, err := os.Stat(filepath.Join(dir, "key"))
		if err != nil || keyInfo.Mode().Perm() != 0600 {
			t.Fatalf("expected 0600 key file initialized in StageInit, got info=%v err=%v", keyInfo, err)
		}

		resp, err := http.Get("http://" + addr + "/healthz")
		if err != nil {
			t.Fatalf("GET /healthz failed: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 OK from /healthz, got %d", resp.StatusCode)
		}

		cancel()
		select {
		case serveErr := <-errCh:
			if serveErr != nil {
				t.Fatalf("expected nil error on graceful ctx cancel, got %v", serveErr)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("ServeContext did not shut down within timeout")
		}
	})

	t.Run("cancelled_context_aborts_cleanly", func(t *testing.T) {
		dir := t.TempDir()
		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		srv := subhub.NewServer(subhub.Options{
			Listen:  "127.0.0.1:0",
			DataDir: dir,
		})
		if err := srv.ServeContext(ctx); err == nil {
			t.Fatal("expected non-nil error when starting with already cancelled context")
		}
	})

	t.Run("hot_path_uses_config_store_snapshot_without_repeated_disk_yaml_parse", func(t *testing.T) {
		dir := t.TempDir()
		cfgPath := filepath.Join(dir, "singctl.yaml")
		initialYAML := "github:\n  mirror_url: \"https://mirror.example.com\"\nhy2:\n  up: 80\n  down: 260\n"
		if err := os.WriteFile(cfgPath, []byte(initialYAML), 0600); err != nil {
			t.Fatal(err)
		}

		var loadCalls atomic.Int32
		store := config.NewStore(cfgPath, config.WithLoader(func(p string) (*config.Config, error) {
			loadCalls.Add(1)
			return config.Load(p)
		}))

		srv := subhub.NewServer(subhub.Options{
			DataDir:     dir,
			ConfigPath:  cfgPath,
			ConfigStore: store,
		})
		key, err := srv.Store().EnsureKey()
		if err != nil {
			t.Fatal(err)
		}
		enabled := true
		if _, err := srv.Store().UpsertSource(t.Context(), subhub.SourceUpsertInput{
			Name:    "test_src",
			Source:  "local",
			Content: "hysteria2://test-pass@198.51.100.10:443?sni=node.example.com#hy2-node",
			Enabled: &enabled,
		}); err != nil {
			t.Fatal(err)
		}

		for range 5 {
			req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://127.0.0.1:3001/"+key+"/download/collection/all?target=ClashMeta", nil)
			req.RemoteAddr = "198.51.100.25:51234"
			opts := srv.LoadRenderOptions(req, subhub.TargetClashMeta)
			if opts.MirrorURL != "https://mirror.example.com" || opts.UpMbps != 80 || opts.DownMbps != 260 {
				t.Fatalf("unexpected render options from store: %+v", opts)
			}
		}
		if got := loadCalls.Load(); got != 1 {
			t.Fatalf("expected 1 YAML load across repeated hot-path requests, got %d", got)
		}

		updatedYAML := "github:\n  mirror_url: \"https://mirror2.example.com/gh\"\nhy2:\n  up: 150\n  down: 500\n"
		if err := os.WriteFile(cfgPath, []byte(updatedYAML), 0600); err != nil {
			t.Fatal(err)
		}
		req2, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://127.0.0.1:3001/"+key+"/download/collection/all?target=ClashMeta", nil)
		opts2 := srv.LoadRenderOptions(req2, subhub.TargetClashMeta)
		if !strings.Contains(opts2.MirrorURL, "mirror2.example.com") || opts2.UpMbps != 150 || opts2.DownMbps != 500 {
			t.Fatalf("expected updated render options after config file change, got %+v", opts2)
		}
		if got := loadCalls.Load(); got != 2 {
			t.Fatalf("expected 2 total YAML loads after 1 file change, got %d", got)
		}
	})
}
