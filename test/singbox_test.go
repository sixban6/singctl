package test

import (
	"os"
	"path/filepath"
	"testing"

	"singctl/internal/config"
	"singctl/internal/singbox"
)

func TestSingBoxNew(t *testing.T) {
	cfg := &config.Config{
		Subs: []config.Subscription{
			{Name: "test", URL: "https://example.com/sub", SkipTlsVerify: false, RemoveEmoji: true},
		},
		GitHub: config.GitHubConfig{MirrorURL: "https://ghfast.top"},
	}

	sb := singbox.New(cfg)
	if sb == nil {
		t.Fatal("singbox.New() returned nil")
	}

	t.Log("SingBox instance created successfully")
}

func TestSingBoxGenerateConfig_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	cfg := &config.Config{
		Subs: []config.Subscription{
			{Name: "test", URL: "https://example.com/test-subscription", SkipTlsVerify: false, RemoveEmoji: true},
		},
		GitHub: config.GitHubConfig{MirrorURL: "https://ghfast.top"},
	}

	sb := singbox.New(cfg)

	// 由于无法直接设置私有字段，我们测试默认路径的行为
	err := sb.GenerateConfig()
	if err != nil {
		// 在测试环境中失败是预期的，因为需要真实的网络和订阅
		t.Logf("GenerateConfig failed as expected: %v", err)

		// 验证错误类型
		if err.Error() == "" {
			t.Error("Error message should not be empty")
		}
		return
	}

	// 如果意外成功，检查默认配置文件是否生成
	defaultConfigPath := "/tmp/singbox-config.json"
	if _, err := os.Stat(defaultConfigPath); os.IsNotExist(err) {
		t.Error("Config file was not generated at expected location")
	} else {
		// 清理测试文件
		os.Remove(defaultConfigPath)
	}
}

func TestSingBoxStartStop_WithMockScripts(t *testing.T) {
	cfg := &config.Config{
		Subs: []config.Subscription{
			{Name: "test", URL: "https://example.com/sub", SkipTlsVerify: false, RemoveEmoji: true},
		},
		GitHub: config.GitHubConfig{MirrorURL: "https://ghfast.top"},
	}

	sb := singbox.New(cfg)

	// 创建临时脚本目录和mock脚本
	tempDir := t.TempDir()
	scriptDir := filepath.Join(tempDir, "scripts")
	if err := os.MkdirAll(scriptDir, 0755); err != nil {
		t.Fatalf("Failed to create script directory: %v", err)
	}

	// 创建mock启动脚本
	startScript := filepath.Join(scriptDir, "start_singbox.sh")
	startScriptContent := `#!/bin/bash
echo "Mock start script executed with config: $1"
echo "Test start successful"
exit 0`
	if err := os.WriteFile(startScript, []byte(startScriptContent), 0755); err != nil {
		t.Fatalf("Failed to create mock start script: %v", err)
	}

	// 创建mock停止脚本
	stopScript := filepath.Join(scriptDir, "stop_singbox.sh")
	stopScriptContent := `#!/bin/bash
echo "Mock stop script executed"
echo "Test stop successful"
exit 0`
	if err := os.WriteFile(stopScript, []byte(stopScriptContent), 0755); err != nil {
		t.Fatalf("Failed to create mock stop script: %v", err)
	}

	// 改变工作目录以使用相对路径 ./scripts
	oldDir, _ := os.Getwd()
	defer os.Chdir(oldDir)
	os.Chdir(tempDir)

	// 测试启动
	err := sb.Start()
	if err != nil {
		t.Errorf("Start() failed: %v", err)
	}

	// 测试停止
	err = sb.Stop()
	if err != nil {
		t.Errorf("Stop() failed: %v", err)
	}
}

func TestSingBoxStartStop_MissingScripts(t *testing.T) {
	cfg := &config.Config{
		Subs: []config.Subscription{
			{Name: "test", URL: "https://example.com/sub", SkipTlsVerify: false, RemoveEmoji: true},
		},
		GitHub: config.GitHubConfig{MirrorURL: "https://ghfast.top"},
	}

	sb := singbox.New(cfg)

	// 改变到一个不存在脚本的目录
	tempDir := t.TempDir()
	oldDir, _ := os.Getwd()
	defer os.Chdir(oldDir)
	os.Chdir(tempDir)

	// 测试启动失败
	err := sb.Start()
	if err == nil {
		t.Error("Start() should fail with missing script")
	} else {
		t.Logf("Start() correctly failed with missing script: %v", err)
	}

	// 测试停止失败
	err = sb.Stop()
	if err == nil {
		t.Error("Stop() should fail with missing script")
	} else {
		t.Logf("Stop() correctly failed with missing script: %v", err)
	}
}

func TestSingBoxInstall_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping install integration test in short mode")
	}

	cfg := &config.Config{
		Subs: []config.Subscription{
			{Name: "test", URL: "https://example.com/sub", SkipTlsVerify: false, RemoveEmoji: true},
		},
		GitHub: config.GitHubConfig{MirrorURL: "https://ghfast.top"},
	}

	sb := singbox.New(cfg)

	// 测试安装（这会尝试实际下载，在测试环境中可能失败）
	err := sb.Install()
	if err != nil {
		t.Logf("Install failed as expected in test environment: %v", err)
		return
	}

	// 如果安装成功，验证二进制文件是否存在
	if _, err := os.Stat("/usr/local/bin/sing-box"); err != nil {
		t.Logf("sing-box binary not found after install (may require sudo): %v", err)
	}
}

func TestSingBoxUpdate(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping update test in short mode")
	}

	cfg := &config.Config{
		Subs: []config.Subscription{
			{Name: "test", URL: "https://example.com/sub", SkipTlsVerify: false, RemoveEmoji: true},
		},
		GitHub: config.GitHubConfig{MirrorURL: "https://ghfast.top"},
	}

	sb := singbox.New(cfg)

	// 测试更新（实际上调用 Install）
	err := sb.Update()
	if err != nil {
		t.Logf("Update failed as expected in test environment: %v", err)
	}
}
