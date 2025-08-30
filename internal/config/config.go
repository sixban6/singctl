package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Subs   []Subscription `yaml:"subs"`
	GitHub GitHubConfig   `yaml:"github"`
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

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}

	return &cfg, nil
}

func (c *Config) Validate() error {
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

	if c.GitHub.MirrorURL == "" {
		c.GitHub.MirrorURL = "https://github.com"
	}

	return nil
}
