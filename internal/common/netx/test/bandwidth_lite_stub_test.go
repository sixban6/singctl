//go:build lite

// 文件职责：验证 -tags lite 下默认 Speedtest 探针返回精简版友好提示且保持全部导出签名与桩注入兼容。
package netx_test

import (
	"strings"
	"testing"

	"singctl/internal/common/netx"
)

func TestNetxLite_DefaultSpeedTestReturnsFriendlyError(t *testing.T) {
	err := netx.RunSpeedTest()
	if err == nil {
		t.Fatal("expected lite RunSpeedTest to return friendly unsupported error")
	}
	if !strings.Contains(err.Error(), "SingCtl -lite") {
		t.Fatalf("expected SingCtl -lite message, got: %v", err)
	}
}
