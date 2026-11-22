// 文件职责：覆盖客户端网关（主路由/旁路由）启动编排与旁路由失败自动回滚保护测试。
package singbox_test

import (
	"context"
	"errors"
	"testing"

	"singctl/internal/config"
	"singctl/internal/singbox"
)

type stubGatewayOrchestrator struct {
	applyCalls    int
	teardownCalls int
	lastCfg       config.GatewayConfig
	applyErr      error
	teardownErr   error
}

func (s *stubGatewayOrchestrator) Apply(_ context.Context, cfg config.GatewayConfig) error {
	s.applyCalls++
	s.lastCfg = cfg
	return s.applyErr
}

func (s *stubGatewayOrchestrator) Teardown(_ context.Context) error {
	s.teardownCalls++
	return s.teardownErr
}

func TestStartWithGateway_RollbackAndLifecycle(t *testing.T) {
	sideCfg := config.GatewayConfig{
		Mode:         "side",
		MainRouterIP: "192.168.100.1",
	}
	mainCfg := config.GatewayConfig{
		Mode: "main",
	}

	t.Run("side_mode_rolls_back_on_start_failure", func(t *testing.T) {
		gw := &stubGatewayOrchestrator{}
		wantErr := errors.New("mock start script failed")

		err := singbox.StartWithGateway(t.Context(), true, sideCfg, gw, func() error {
			return wantErr
		})
		if !errors.Is(err, wantErr) {
			t.Fatalf("expected error %v, got %v", wantErr, err)
		}
		if gw.applyCalls != 1 {
			t.Fatalf("expected applyCalls=1, got %d", gw.applyCalls)
		}
		if gw.teardownCalls != 1 {
			t.Fatalf("expected teardownCalls=1 on side-router start failure, got %d", gw.teardownCalls)
		}
	})

	t.Run("side_mode_keeps_rules_on_start_success", func(t *testing.T) {
		gw := &stubGatewayOrchestrator{}

		err := singbox.StartWithGateway(t.Context(), true, sideCfg, gw, func() error {
			return nil
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if gw.applyCalls != 1 {
			t.Fatalf("expected applyCalls=1, got %d", gw.applyCalls)
		}
		if gw.teardownCalls != 0 {
			t.Fatalf("expected teardownCalls=0 on start success, got %d", gw.teardownCalls)
		}
	})

	t.Run("main_mode_skips_side_rollback_on_start_failure", func(t *testing.T) {
		gw := &stubGatewayOrchestrator{}
		wantErr := errors.New("mock main start failed")

		err := singbox.StartWithGateway(t.Context(), true, mainCfg, gw, func() error {
			return wantErr
		})
		if !errors.Is(err, wantErr) {
			t.Fatalf("expected error %v, got %v", wantErr, err)
		}
		if gw.applyCalls != 1 {
			t.Fatalf("expected applyCalls=1, got %d", gw.applyCalls)
		}
		if gw.teardownCalls != 0 {
			t.Fatalf("expected teardownCalls=0 in main mode, got %d", gw.teardownCalls)
		}
	})

	t.Run("non_linux_skips_gateway_calls", func(t *testing.T) {
		gw := &stubGatewayOrchestrator{}
		wantErr := errors.New("mock darwin start failed")

		err := singbox.StartWithGateway(t.Context(), false, sideCfg, gw, func() error {
			return wantErr
		})
		if !errors.Is(err, wantErr) {
			t.Fatalf("expected error %v, got %v", wantErr, err)
		}
		if gw.applyCalls != 0 || gw.teardownCalls != 0 {
			t.Fatalf("expected zero gateway calls on non-linux, got apply=%d teardown=%d", gw.applyCalls, gw.teardownCalls)
		}
	})
}
