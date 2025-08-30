package test

import (
	"os"
	"path/filepath"
	"testing"

	"singctl/internal/config"
)

func TestConfigLoad(t *testing.T) {
	tests := []struct {
		name      string
		content   string
		wantError bool
	}{
		{
			name: "valid single config",
			content: `
subs:
  - url: "https://example.com/sub1"
    skip_tls_verify: false
    remove-emoji: true

github:
  mirror_url: "https://ghfast.top"
`,
			wantError: false,
		},
		{
			name: "valid multiple config with names",
			content: `
subs:
  - name: "work"
    url: "https://example.com/sub1"
    skip_tls_verify: false
    remove-emoji: true
  - name: "home"
    url: "https://example.com/sub2"
    skip_tls_verify: true
    remove-emoji: false

github:
  mirror_url: "https://ghfast.top"
`,
			wantError: false,
		},
		{
			name: "invalid multiple config without names",
			content: `
subs:
  - url: "https://example.com/sub1"
    skip_tls_verify: false
    remove-emoji: true
  - url: "https://example.com/sub2"
    skip_tls_verify: true
    remove-emoji: false

github:
  mirror_url: "https://ghfast.top"
`,
			wantError: true,
		},
		{
			name: "invalid duplicate names",
			content: `
subs:
  - name: "work"
    url: "https://example.com/sub1"
    skip_tls_verify: false
    remove-emoji: true
  - name: "work"
    url: "https://example.com/sub2"
    skip_tls_verify: true
    remove-emoji: false

github:
  mirror_url: "https://ghfast.top"
`,
			wantError: true,
		},
		{
			name: "empty subscriptions",
			content: `
subs: []

dns:
  auto_optimize: true

github:
  mirror_url: "https://github.com"
`,
			wantError: true,
		},
		{
			name: "missing subscription URL",
			content: `
subs:
  - url: ""
    skip_tls_verify: false
    remove-emoji: true

dns:
  auto_optimize: true

github:
  mirror_url: "https://github.com"
`,
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 创建临时配置文件
			tempFile := filepath.Join(t.TempDir(), "config.yaml")
			err := os.WriteFile(tempFile, []byte(tt.content), 0644)
			if err != nil {
				t.Fatalf("Failed to create temp config file: %v", err)
			}

			// 测试加载配置
			cfg, err := config.Load(tempFile)
			if (err != nil) != tt.wantError {
				t.Errorf("config.Load() error = %v, wantError %v", err, tt.wantError)
				return
			}

			if !tt.wantError {
				// 验证配置内容
				if len(cfg.Subs) < 1 {
					t.Error("Expected at least one subscription")
				}
				if cfg.GitHub.MirrorURL == "" {
					t.Error("Expected GitHub mirror URL to be set")
				}
			}
		})
	}
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name      string
		config    config.Config
		wantError bool
	}{
		{
			name: "valid single config",
			config: config.Config{
				Subs: []config.Subscription{
					{URL: "https://example.com/sub", SkipTlsVerify: false, RemoveEmoji: true},
				},
				GitHub: config.GitHubConfig{MirrorURL: "https://github.com"},
			},
			wantError: false,
		},
		{
			name: "valid multiple config with names",
			config: config.Config{
				Subs: []config.Subscription{
					{Name: "work", URL: "https://example.com/sub1", SkipTlsVerify: false, RemoveEmoji: true},
					{Name: "home", URL: "https://example.com/sub2", SkipTlsVerify: false, RemoveEmoji: true},
				},
				GitHub: config.GitHubConfig{MirrorURL: "https://github.com"},
			},
			wantError: false,
		},
		{
			name: "invalid multiple config without names",
			config: config.Config{
				Subs: []config.Subscription{
					{URL: "https://example.com/sub1", SkipTlsVerify: false, RemoveEmoji: true},
					{URL: "https://example.com/sub2", SkipTlsVerify: false, RemoveEmoji: true},
				},
				GitHub: config.GitHubConfig{MirrorURL: "https://github.com"},
			},
			wantError: true,
		},
		{
			name: "invalid duplicate names",
			config: config.Config{
				Subs: []config.Subscription{
					{Name: "work", URL: "https://example.com/sub1", SkipTlsVerify: false, RemoveEmoji: true},
					{Name: "work", URL: "https://example.com/sub2", SkipTlsVerify: false, RemoveEmoji: true},
				},
				GitHub: config.GitHubConfig{MirrorURL: "https://github.com"},
			},
			wantError: true,
		},
		{
			name: "empty subscriptions",
			config: config.Config{
				Subs:   []config.Subscription{},
				GitHub: config.GitHubConfig{MirrorURL: "https://github.com"},
			},
			wantError: true,
		},
		{
			name: "empty subscription URL",
			config: config.Config{
				Subs: []config.Subscription{
					{URL: "", SkipTlsVerify: false, RemoveEmoji: true},
				},
				GitHub: config.GitHubConfig{MirrorURL: "https://github.com"},
			},
			wantError: true,
		},
		{
			name: "empty mirror URL gets default",
			config: config.Config{
				Subs: []config.Subscription{
					{URL: "https://example.com/sub", SkipTlsVerify: false, RemoveEmoji: true},
				},
				GitHub: config.GitHubConfig{MirrorURL: ""},
			},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantError {
				t.Errorf("Config.Validate() error = %v, wantError %v", err, tt.wantError)
			}

			// 检查默认值设置
			if tt.name == "empty mirror URL gets default" && tt.config.GitHub.MirrorURL != "https://github.com" {
				t.Errorf("Expected default mirror URL to be set to 'https://github.com', got '%s'", tt.config.GitHub.MirrorURL)
			}
		})
	}
}
