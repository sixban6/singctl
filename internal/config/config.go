package config

import (
	"cmp"
	"fmt"
	"os"
	"regexp"
	"strings"

	"singctl/internal/constant"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Subs   []Subscription `yaml:"subs"`
	GitHub GitHubConfig   `yaml:"github"`
	//GUI       GUIConfig       `yaml:"gui"`
	Hy2       Hy2Config       `yaml:"hy2"`
	Tailscale TailscaleConfig `yaml:"tailscale"`
	Server    ServerConfig    `yaml:"server"`
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
type Hy2Config struct {
	Up   int `yaml:"up"`
	Down int `yaml:"down"`
}

type TailscaleConfig struct {
	AuthKey  string `yaml:"auth_key"`
	UseBuild bool   `yaml:"use_build"`
	Subnets  string `yaml:"subnets"`
}

type ServerConfig struct {
	SBDomain string `yaml:"sb_domain"`
	CFDNSKey string `yaml:"cf_dns_key"`
	Sni      string `yaml:"sni"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	// Pre-process the YAML to fix common syntax errors such as missing spaces after colons.
	// For example: `url:"https://test.com"` -> `url: "https://test.com"`
	// We only match known keys to avoid accidentally modifying strings containing colons.
	keys := []string{
		"subs", "name", "url", "skip_tls_verify", "remove-emoji",
		"github", "mirror_url", "hy2", "up", "down",
		"tailscale", "auth_key", "use_build", constant.TailscaleSubnets,
		"server", "sb_domain", "cf_dns_key", "sni",
	}
	pattern := fmt.Sprintf("(?m)^([ \\t-]*(?:%s)):([^\\s].*)", strings.Join(keys, "|"))
	re := regexp.MustCompile(pattern)
	data = re.ReplaceAll(data, []byte("$1: $2"))

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	cfg.GitHub.MirrorURL = cmp.Or(cfg.GitHub.MirrorURL, "https://gh-proxy.com")
	if cfg.Hy2.Up == 0 {
		cfg.Hy2.Up = 21
	}
	if cfg.Hy2.Down == 0 {
		cfg.Hy2.Down = 200
	}
	if cfg.Server.Sni == "" {
		cfg.Server.Sni = "swdist.apple.com"
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

// MigrateConfig reads the existing config file and merges it into the baseline template using YAML AST.
// It preserves structure, `#` comments from the template, and intentional user zero-values.
func MigrateConfig(configPath string, templateData []byte) error {
	oldData, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			// If no old config, simply write the template
			return os.WriteFile(configPath, templateData, 0644)
		}
		return fmt.Errorf("failed to read old config: %w", err)
	}

	// Pre-process the old YAML to fix common syntax errors such as missing spaces after colons.
	// This ensures `oldCfg` populates zero-values properly instead of treating the whole line as a string.
	keys := []string{
		"subs", "name", "url", "skip_tls_verify", "remove-emoji",
		"github", "mirror_url", "hy2", "up", "down",
		"tailscale", "auth_key", "use_build", constant.TailscaleSubnets,
		"server", "sb_domain", "cf_dns_key", "sni",
	}
	pattern := fmt.Sprintf("(?m)^([ \\t-]*(?:%s)):([^\\s].*)", strings.Join(keys, "|"))
	re := regexp.MustCompile(pattern)
	cleanOldData := re.ReplaceAll(oldData, []byte("$1: $2"))

	var oldCfg Config
	if err := yaml.Unmarshal(cleanOldData, &oldCfg); err != nil {
		return fmt.Errorf("failed to parse old config: %w", err)
	}

	var rootNode yaml.Node
	if err := yaml.Unmarshal(templateData, &rootNode); err != nil {
		return fmt.Errorf("failed to parse template AST: %w", err)
	}

	if len(rootNode.Content) == 0 {
		return fmt.Errorf("template AST is empty")
	}

	docNode := rootNode.Content[0]

	// Helper to replace an entire top-level node (like 'subs' array)
	replaceNode := func(parent *yaml.Node, key string, val interface{}) {
		for i := 0; i < len(parent.Content); i += 2 {
			if parent.Content[i].Value == key {
				var newNode yaml.Node
				b, _ := yaml.Marshal(val)
				_ = yaml.Unmarshal(b, &newNode)
				if len(newNode.Content) > 0 {
					originalNode := parent.Content[i+1]
					newNodeChild := newNode.Content[0]
					newNodeChild.HeadComment = originalNode.HeadComment
					newNodeChild.LineComment = originalNode.LineComment
					newNodeChild.FootComment = originalNode.FootComment

					if originalNode.Kind == yaml.ScalarNode && newNodeChild.Kind == yaml.ScalarNode {
						originalNode.Value = newNodeChild.Value
					} else {
						parent.Content[i+1] = newNodeChild
					}
				}
				return
			}
		}
	}

	// Helper to replace a scalar field under a specific map
	replaceField := func(parent *yaml.Node, parentKey, childKey, childVal string) {
		for i := 0; i < len(parent.Content); i += 2 {
			if parent.Content[i].Value == parentKey {
				mapNode := parent.Content[i+1]
				for j := 0; j < len(mapNode.Content); j += 2 {
					if mapNode.Content[j].Value == childKey {
						mapNode.Content[j+1].Value = childVal
						return
					}
				}
			}
		}
	}

	// 1. Merge Subs (only if user actually configured something)
	if len(oldCfg.Subs) > 0 {
		hasRealSub := false
		for _, s := range oldCfg.Subs {
			if s.URL != "" || s.Name != "" {
				hasRealSub = true
				break
			}
		}
		if hasRealSub {
			replaceNode(docNode, "subs", oldCfg.Subs)
		}
	}

	// 2. Merge GitHub Mirror URL (Preserve even if it's explicitly empty)
	// We can check the raw yaml text to see if github.mirror_url was specified in oldData
	// or we just unconditionally preserve what was Unmarshaled.
	// Since go yaml.Unmarshal will set strings to "" if they exist and are empty,
	// but also "" if they are missing. In config loading context, preserving oldCfg.GitHub.MirrorURL is safe.
	// However, to only override if the block existed, we can do a quick check:
	if strings.Contains(string(oldData), "mirror_url:") {
		replaceField(docNode, "github", "mirror_url", oldCfg.GitHub.MirrorURL)
	}

	// 3. Merge Hy2
	if strings.Contains(string(oldData), "hy2:") {
		replaceField(docNode, "hy2", "up", fmt.Sprintf("%d", oldCfg.Hy2.Up))
		replaceField(docNode, "hy2", "down", fmt.Sprintf("%d", oldCfg.Hy2.Down))
	}

	// 4. Merge Tailscale
	// Check if the tailscale section existed in the old data.
	// In the unmarshaled oldCfg, if auth_key was empty, it will be "" which is valid.
	if strings.Contains(string(oldData), "tailscale:") {
		// Replace everything under tailscale that isn't the struct default if it existed in text
		// or just safely copy the struct value because if they deleted it the oldCfg has "" which overrides the template "" anyway
		replaceField(docNode, "tailscale", "auth_key", oldCfg.Tailscale.AuthKey)
		replaceField(docNode, "tailscale", "subnets", oldCfg.Tailscale.Subnets)
		if oldCfg.Tailscale.UseBuild {
			replaceField(docNode, "tailscale", "use_build", "true")
		} else {
			replaceField(docNode, "tailscale", "use_build", "false")
		}
	}

	// 5. Merge Server
	if strings.Contains(string(oldData), "server:") {
		replaceField(docNode, "server", "sb_domain", oldCfg.Server.SBDomain)
		replaceField(docNode, "server", "cf_dns_key", oldCfg.Server.CFDNSKey)
		if strings.Contains(string(oldData), "sni:") {
			replaceField(docNode, "server", "sni", oldCfg.Server.Sni)
		}
	}

	newData, err := yaml.Marshal(&rootNode)
	if err != nil {
		return fmt.Errorf("failed to marshal merged AST: %w", err)
	}

	// If identical to old string, exit early to avoid noisy writes
	if string(oldData) == string(newData) {
		return nil
	}

	// Create backup
	backupPath := configPath + ".bak"
	_ = os.WriteFile(backupPath, oldData, 0644)

	// Write Atomically
	tempPath := configPath + ".tmp"
	if err := os.WriteFile(tempPath, newData, 0644); err != nil {
		return fmt.Errorf("failed to write tmp config: %w", err)
	}

	if err := os.Rename(tempPath, configPath); err != nil {
		return fmt.Errorf("failed to rename tmp config to target: %w", err)
	}

	return nil
}

// Save serializes cfg to YAML and writes it to path.
// Note: YAML comments are not preserved by this operation.
func Save(path string, cfg *Config) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	return os.WriteFile(path, data, 0644)
}
