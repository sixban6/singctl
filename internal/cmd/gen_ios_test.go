package cmd

import (
	"path/filepath"
	"strings"
	"testing"

	"singctl/internal/constant"
)

func TestGuardIOSOutputPath(t *testing.T) {
	localCfg := constant.SingBoxConfigFile

	t.Run("空路径放行(走默认导出路径)", func(t *testing.T) {
		if err := guardIOSOutputPath(""); err != nil {
			t.Fatalf("empty path should pass: %v", err)
		}
	})

	t.Run("完全相同的路径拦截", func(t *testing.T) {
		err := guardIOSOutputPath(localCfg)
		if err == nil {
			t.Fatal("writing local sing-box config should be rejected")
		}
		if !strings.Contains(err.Error(), "拒绝写入") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("Linux 官方路径跨平台拦截", func(t *testing.T) {
		// 即使在本机(macOS/Windows)上, /etc/sing-box/config.json 也可能因手工部署而真实存在
		if err := guardIOSOutputPath("/etc/sing-box/config.json"); err == nil {
			t.Fatal("/etc/sing-box/config.json should be rejected on any OS")
		}
	})

	t.Run("相对路径绕过被拦截", func(t *testing.T) {
		// 构造与本地配置等价的相对路径(../.. 逐级抵消)
		rel := "../../.." + localCfg
		if err := guardIOSOutputPath(rel); err == nil {
			t.Fatalf("relative path %q escaping to local config should be rejected", rel)
		}
	})

	t.Run("其它路径放行", func(t *testing.T) {
		other := filepath.Join(t.TempDir(), "my-ios.json")
		if err := guardIOSOutputPath(other); err != nil {
			t.Fatalf("other path should pass: %v", err)
		}
	})
}

func TestDefaultIOSOutputPath(t *testing.T) {
	got := defaultIOSOutputPath()
	if !strings.HasSuffix(got, "singctl-ios.json") {
		t.Fatalf("default path should end with singctl-ios.json, got %q", got)
	}
	if strings.HasPrefix(got, string(filepath.Separator)+"etc") ||
		strings.Contains(got, "sing-box") && strings.HasSuffix(got, "config.json") {
		t.Fatalf("default path must not collide with local sing-box config, got %q", got)
	}
}
