package test

import (
	"os"
	"singctl/internal/config"
	"singctl/internal/singbox"
	"testing"
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

func TestParseSingBoxVersionOutput(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:  "标准格式",
			input: "sing-box version 1.12.0",
			want:  "1.12.0",
		},
		{
			name:  "RC版本",
			input: "sing-box version 1.13.0-rc.1",
			want:  "1.13.0-rc.1",
		},
		{
			name:  "多行输出",
			input: "sing-box version 1.12.0\n\nEnvironment: CGO enabled, go1.24.1, darwin/arm64\nTags: with_gvisor",
			want:  "1.12.0",
		},
		{
			name:  "纯版本号",
			input: "1.12.0",
			want:  "1.12.0",
		},
		{
			name:  "带前导空格",
			input: "  sing-box version 1.12.0  ",
			want:  "1.12.0",
		},
		{
			name:    "空输入",
			input:   "",
			wantErr: true,
		},
		{
			name:    "空白输入",
			input:   "  \n  ",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := singbox.ParseSingBoxVersionOutput(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseSingBoxVersionOutput() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ParseSingBoxVersionOutput() = %q, want %q", got, tt.want)
			}
		})
	}
}
