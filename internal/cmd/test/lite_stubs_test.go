//go:build lite

// 文件职责：验证 -tags lite 构建下服务端/机群/SSH/终端/测速命令以极薄 stub 返回友好中文引导且不触发标志解析崩溃。
package cmd_test

import (
	"bytes"
	"strings"
	"testing"

	"singctl/internal/cmd"
)

func TestLiteEdition_ServerCommandStubsReturnFriendlyError(t *testing.T) {
	cases := [][]string{
		{"sr"},
		{"server", "install"},
		{"sr", "ui", "start"},
		{"fl", "list"},
		{"fleet", "sync", "--all"},
		{"reinstall"},
		{"cf-token"},
		{"ssh", "node1"},
		{"term", "install"},
		{"ut", "testbd"},
	}

	for _, args := range cases {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			root := cmd.NewRootCmd("/tmp/test-singctl.yaml", "/tmp/test-singctl.yaml", cmd.BuildInfo{Version: "v1.14.0-lite"})
			var out bytes.Buffer
			root.SetOut(&out)
			root.SetErr(&out)
			root.SetArgs(args)

			err := root.ExecuteContext(t.Context())
			if err == nil {
				t.Fatalf("expected lite stub error for %v, got nil", args)
			}
			if !strings.Contains(err.Error(), "SingCtl -lite") {
				t.Fatalf("expected friendly SingCtl -lite error message for %v, got: %v", args, err)
			}
		})
	}
}
