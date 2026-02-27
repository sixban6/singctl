package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Subs      []Subscription  `yaml:"subs"`
	GitHub    GitHubConfig    `yaml:"github"`
	GUI       GUIConfig       `yaml:"gui"`
	Hy2       Hy2Config       `yaml:"hy2"`
	Tailscale TailscaleConfig `yaml:"tailscale"`
}

type Subscription struct {
	Name          string `yaml:"name"`
	URL           string `yaml:"url"`
	SkipTlsVerify bool   `yaml:"skip_tls_verify"`
	RemoveEmoji   bool   `yaml:"remove-emoji"`
}

type GitHubConfig struct {
	MirrorURL string `yaml:"mirror_url"`
}

type GUIConfig struct {
	MacURL  string `yaml:"mac_url"`
	WinURL  string `yaml:"win_url"`
	AppName string `yaml:"app_name"`
}

type Hy2Config struct {
	Up   int `yaml:"up"`
	Down int `yaml:"down"`
}

type TailscaleConfig struct {
	AuthKey string `yaml:"auth_key"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if cfg.GitHub.MirrorURL == "" {
		cfg.GitHub.MirrorURL = "https://github.com"
	}
	if cfg.GUI.AppName == "" {
		cfg.GUI.AppName = "SFM"
	}
	if cfg.Hy2.Up == 0 {
		cfg.Hy2.Up = 30
	}
	if cfg.Hy2.Down == 0 {
		cfg.Hy2.Down = 300
	}

	return &cfg, nil
}

func (c *Config) ValidateSubs() error {
	if len(c.Subs) == 0 {
		return fmt.Errorf("no subscriptions configured")
	}

	nameMap := make(map[string]int)

	for i, sub := range c.Subs {
		if sub.URL == "" {
			return fmt.Errorf("subscription[%d]: URL is required", i)
		}

		// 验证Name字段：如果有多个订阅但Name为空，则报错
		if len(c.Subs) > 1 && sub.Name == "" {
			return fmt.Errorf("subscription[%d]: Name is required when using multiple subscriptions", i)
		}

		// 验证Name字段：不能重复
		if sub.Name != "" {
			if existingIndex, exists := nameMap[sub.Name]; exists {
				return fmt.Errorf("subscription[%d]: Name '%s' is already used by subscription[%d]", i, sub.Name, existingIndex)
			}
			nameMap[sub.Name] = i
		}
	}

	return nil
}

// MigrateConfig reads the existing config file as text and appends purely new blocks
// that might have been introduced in a newer singctl version, without destroying user comments.
func MigrateConfig(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // No config file to migrate
		}
		return fmt.Errorf("failed to read config file for migration: %w", err)
	}

	content := string(data)
	needsSave := false

	// Example: migrate tailscale config
	if !strings.Contains(content, "tailscale:") {
		tailscaleBlock := `
# (singctl update) 自动填补：Tailscale 自动化配置
tailscale:
  auth_key: ""                                  # (可选) Tailscale 授权密钥，用于免交互自动注册节点
`
		content += tailscaleBlock
		needsSave = true
	}

	// Future migrations can be added here using similar string contains logic

	if needsSave {
		// Create backup
		backupPath := path + ".migration.bak"
		_ = os.WriteFile(backupPath, data, 0644)

		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			return fmt.Errorf("failed to write migrated config: %w", err)
		}
		// logger warning/info handled by caller or just silently succeed
	}

	return nil
}
