package test

import (
	"os"
	"path/filepath"
	"singctl/internal/config"
	"strings"
	"testing"
)

func TestLoad(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "singctl.yaml")

	yamlContent := `
subs:
  - name:"main"
    url:"https://test.com"
    skip_tls_verify:false
    correct: "value"
github:
  mirror_url:"https://proxy.example.com"
`

	err := os.WriteFile(configPath, []byte(yamlContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if len(cfg.Subs) != 1 {
		t.Fatalf("Expected 1 subscription, got %d", len(cfg.Subs))
	}

	sub := cfg.Subs[0]
	if sub.Name != "main" {
		t.Errorf("Expected sub.Name to be 'main', got '%s'", sub.Name)
	}
	if sub.URL != "https://test.com" {
		t.Errorf("Expected sub.URL to be 'https://test.com', got '%s'", sub.URL)
	}
	if sub.SkipTlsVerify != false {
		t.Errorf("Expected sub.SkipTlsVerify to be false, got true")
	}

	if cfg.GitHub.MirrorURL != "https://proxy.example.com" {
		t.Errorf("Expected GitHub.MirrorURL to be 'https://proxy.example.com', got '%s'", cfg.GitHub.MirrorURL)
	}
}

func TestLoad_NormalConfig(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "singctl_normal.yaml")

	yamlContent := `
subs:
  - name: "normal"
    url: "https://normal.com"
    skip_tls_verify: true
`

	err := os.WriteFile(configPath, []byte(yamlContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if len(cfg.Subs) != 1 {
		t.Fatalf("Expected 1 subscription, got %d", len(cfg.Subs))
	}

	sub := cfg.Subs[0]
	if sub.Name != "normal" {
		t.Errorf("Expected sub.Name to be 'normal', got '%s'", sub.Name)
	}
	if sub.URL != "https://normal.com" {
		t.Errorf("Expected sub.URL to be 'https://normal.com', got '%s'", sub.URL)
	}
	if sub.SkipTlsVerify != true {
		t.Errorf("Expected sub.SkipTlsVerify to be true, got false")
	}
}

func TestMigrateConfig(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "singctl_migrate.yaml")

	oldYaml := `
subs:
  - name: "my_custom"
    url: "https://foo.bar"
    skip_tls_verify: true
github:
  mirror_url: ""
hy2:
  up: 50
  down: 500
tailscale:
  auth_key: "tskey-custom"
  use_build: false
server:
  sb_domain: "sub.custom.com"
`

	templateYaml := `
subs:
  - name: "main"                              # 订阅名称 (多订阅时必填)
    url: ""                                   # 你VPN订阅地址
    skip_tls_verify: false                    # 是否跳过TLS验证
    remove-emoji: true

github:
  mirror_url: "https://gh-proxy.com"            # GitHub镜像地址,用于加速

hy2:
  up: 20                                         # Hysteria2 上行带宽 (Mbps)
  down: 200                                      # Hysteria2 下行带宽 (Mbps)

tailscale:                                      # (可选) Tailscale 部署配置
  auth_key: ""                                  # (可选) Tailscale 授权密钥。默认是: ""
  subnets: ""                                   # (可选) 配置通告的子网，默认为空，程序会自动获取
  use_build: false                              # (可选) 是否使用singbox内置的TailScale。默认：false, 不启用

server:                                         # (可选) 服务器部署配置.当需要部署singbox服务端的时候配置
  sb_domain: "sub.yourdomain.com"               # 你的域名
  cf_dns_key: "your_cloudflare_api_token"       # 你的 Cloudflare API Token
`

	err := os.WriteFile(configPath, []byte(oldYaml), 0644)
	if err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	err = config.MigrateConfig(configPath, []byte(templateYaml))
	if err != nil {
		t.Fatalf("Failed to migrate config: %v", err)
	}

	mergedData, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("Failed to read merged config: %v", err)
	}

	mergedStr := string(mergedData)

	// Verify comments from template are retained
	if !strings.Contains(mergedStr, "# GitHub镜像地址,用于加速") {
		t.Errorf("Expected mirrored comment to be retained")
	}
	if !strings.Contains(mergedStr, "# Hysteria2 上行带宽 (Mbps)") {
		t.Errorf("Expected hy2 comment to be retained")
	}

	// Verify old values are retained
	if !strings.Contains(mergedStr, "url: https://foo.bar") {
		t.Errorf("Expected custom url to be retained")
	}
	if !strings.Contains(mergedStr, `mirror_url: ""`) {
		t.Errorf("Expected explicit empty mirror_url to be retained")
	}
	if strings.Contains(mergedStr, `mirror_url: "https://gh-proxy.com"`) {
		t.Errorf("Expected default mirror_url to be overwritten by explicit empty value")
	}
	if !strings.Contains(mergedStr, "up: 50") {
		t.Errorf("Expected custom up bandwidth to be retained")
	}
	if !strings.Contains(mergedStr, `auth_key: "tskey-custom"`) {
		t.Errorf("Expected custom auth_key to be retained")
	}
	if !strings.Contains(mergedStr, `sb_domain: "sub.custom.com"`) {
		t.Errorf("Expected custom sb_domain to be retained")
	}

	// 验证配置文件权限：含 auth_key/cf_dns_key 等密钥，必须是 0600
	fi, err := os.Stat(configPath)
	if err != nil {
		t.Fatalf("Failed to stat merged config: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0600 {
		t.Errorf("Expected merged config permission 0600, got %o", perm)
	}
	// 备份文件同样含密钥
	bfi, err := os.Stat(configPath + ".bak")
	if err != nil {
		t.Fatalf("Failed to stat backup config: %v", err)
	}
	if perm := bfi.Mode().Perm(); perm != 0600 {
		t.Errorf("Expected backup config permission 0600, got %o", perm)
	}
}

func TestSavePreservesCommentsAndCustomRules(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "singctl_save.yaml")

	initialYAML := `# 顶部配置说明注释
subs:
  - name: "main"
    url: "https://sub1.example.com"
    skip_tls_verify: false
    remove-emoji: true

github:
  mirror_url: "https://gh-proxy.com" # 镜像注释

hy2:
  up: 30
  down: 300

server:
  sb_domain: "sb.example.com"
  node_domain: "node.example.com"
  substore_domain: "sub.example.com"

watchdog:
  interval: 45

custom_rules:
  route:
    - domain_suffix:
        - "internal.example.com"
      outbound: "direct"
`
	if err := os.WriteFile(configPath, []byte(initialYAML), 0600); err != nil {
		t.Fatalf("write initial config: %v", err)
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	// 模拟修改部分字段后调用 config.Save
	cfg.Hy2.Up = 50
	cfg.Hy2.Down = 500
	cfg.GitHub.MirrorURL = "https://mirror.example.org"

	if err := config.Save(configPath, cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}

	savedBytes, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read saved config: %v", err)
	}
	savedStr := string(savedBytes)

	if !strings.Contains(savedStr, "# 镜像注释") {
		t.Errorf("expected inline comment to be preserved, got:\n%s", savedStr)
	}

	reloaded, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("reload saved config: %v", err)
	}
	if reloaded.Hy2.Up != 50 || reloaded.Hy2.Down != 500 {
		t.Errorf("unexpected hy2 bandwidth: %+v", reloaded.Hy2)
	}
	if reloaded.Server.NodeDomain != "node.example.com" || reloaded.Server.SubstoreDomain != "sub.example.com" {
		t.Errorf("expected server domains to be preserved, got: %+v", reloaded.Server)
	}
	if len(reloaded.CustomRules.Route) != 1 {
		t.Errorf("expected custom_rules.route to be preserved, got: %+v", reloaded.CustomRules)
	}
}
