package test

import (
	"os"
	"path/filepath"
	"singctl/internal/config"
	"strings"
	"testing"
	"time"
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

func TestServerConfig_GetServerIP_Explicit(t *testing.T) {
	s := &config.ServerConfig{
		ServerIP: "1.2.3.4",
	}
	if ip := s.GetServerIP(); ip != "1.2.3.4" {
		t.Errorf("expected 1.2.3.4, got %s", ip)
	}
}

func TestServerConfig_GetServerIP_MockDiscovered(t *testing.T) {
	config.ResetDiscoveredPublicIPForTest()
	defer config.ResetDiscoveredPublicIPForTest()

	config.SetDiscoveredPublicIPForTest("5.6.7.8")
	s := &config.ServerConfig{}
	if ip := s.GetServerIP(); ip != "5.6.7.8" {
		t.Errorf("expected 5.6.7.8, got %s", ip)
	}
}

func TestMigrateConfig_PreserveNodeDomainAndServerFields(t *testing.T) {
	oldYAML := `
server:
  sb_domain: "sub.example.com"
  node_domain: "cdn.l1.example.com"
  substore_domain: "l-s.example.com"
  server_ip: "198.51.100.1"
  cf_dns_key: "my_token"
  sni: "swdist.apple.com"
`
	// Template that does NOT contain node_domain or substore_domain
	templateYAML := `
server:
  sb_domain: "template.example.com"
  cf_dns_key: "template_token"
`
	tmpFile, err := os.CreateTemp("", "singctl_test_*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(oldYAML); err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()

	if err := config.MigrateConfig(tmpFile.Name(), []byte(templateYAML)); err != nil {
		t.Fatalf("MigrateConfig failed: %v", err)
	}

	loaded, err := config.Load(tmpFile.Name())
	if err != nil {
		t.Fatalf("Load migrated config failed: %v", err)
	}

	if loaded.Server.NodeDomain != "cdn.l1.example.com" {
		t.Errorf("expected node_domain 'cdn.l1.example.com', got '%s'", loaded.Server.NodeDomain)
	}
	if loaded.Server.SubstoreDomain != "l-s.example.com" {
		t.Errorf("expected substore_domain 'l-s.example.com', got '%s'", loaded.Server.SubstoreDomain)
	}
	if loaded.Server.ServerIP != "198.51.100.1" {
		t.Errorf("expected server_ip '198.51.100.1', got '%s'", loaded.Server.ServerIP)
	}
	if loaded.Server.SBDomain != "sub.example.com" {
		t.Errorf("expected sb_domain 'sub.example.com', got '%s'", loaded.Server.SBDomain)
	}
	if loaded.Server.CFDNSKey != "my_token" {
		t.Errorf("expected cf_dns_key 'my_token', got '%s'", loaded.Server.CFDNSKey)
	}
	if loaded.Server.Sni != "swdist.apple.com" {
		t.Errorf("expected sni 'swdist.apple.com', got '%s'", loaded.Server.Sni)
	}
}

func TestMigrateConfig_MultiDomainServer(t *testing.T) {
	serverYAML := `subs:
    - name: main
      url: ""
      skip_tls_verify: false
      remove-emoji: true
github:
    mirror_url: "https://gh-proxy.com"
hy2:
    up: 20
    down: 200
tailscale:
    auth_key: ""
    subnets: ""
    use_build: false
server:
    node_domain: "cdn.s1.example.com"
    substore_domain: "s-s.example.com"
    cf_dns_key: "mock_cf_token_value_123456"
    sni: ""
watchdog:
    interval: 180
    confirm_wait: 30
    max_restarts: 3
`
	templateBytes, err := os.ReadFile("../configs/singctl.yaml")
	if err != nil {
		t.Fatal(err)
	}

	tmpFile, err := os.CreateTemp("", "singctl_multidomain_*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(serverYAML); err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()

	if err := config.MigrateConfig(tmpFile.Name(), templateBytes); err != nil {
		t.Fatalf("MigrateConfig failed: %v", err)
	}

	resultBytes, err := os.ReadFile(tmpFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Migrated YAML:\n%s", string(resultBytes))

	loaded, err := config.Load(tmpFile.Name())
	if err != nil {
		t.Fatalf("Load migrated config failed: %v", err)
	}

	if loaded.Server.NodeDomain != "cdn.s1.example.com" {
		t.Errorf("expected node_domain 'cdn.s1.example.com', got '%s'", loaded.Server.NodeDomain)
	}
	if loaded.Server.SubstoreDomain != "s-s.example.com" {
		t.Errorf("expected substore_domain 's-s.example.com', got '%s'", loaded.Server.SubstoreDomain)
	}
}

func TestMigrateConfig_LegacySBDomainMigration(t *testing.T) {
	legacyYAML := `
server:
  sb_domain: "legacy.example.com"
  cf_dns_key: "my_key"
`
	templateBytes, err := os.ReadFile("../configs/singctl.yaml")
	if err != nil {
		t.Fatal(err)
	}

	tmpFile, err := os.CreateTemp("", "singctl_legacy_*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(legacyYAML); err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()

	if err := config.MigrateConfig(tmpFile.Name(), templateBytes); err != nil {
		t.Fatalf("MigrateConfig failed: %v", err)
	}

	loaded, err := config.Load(tmpFile.Name())
	if err != nil {
		t.Fatalf("Load migrated config failed: %v", err)
	}

	if loaded.Server.NodeDomain != "legacy.example.com" {
		t.Errorf("expected node_domain 'legacy.example.com', got '%s'", loaded.Server.NodeDomain)
	}
	if loaded.Server.CFDNSKey != "my_key" {
		t.Errorf("expected cf_dns_key 'my_key', got '%s'", loaded.Server.CFDNSKey)
	}
}

func TestLoad_StringPorts(t *testing.T) {
	yamlContent := `
hy2:
  up: "30"
  down: "300"
server:
  node_domain: "node.example.com"
  anytls_port: "443"
  web_terminal:
    enabled: true
    port: "18080"
    path: "/ops-shell-123"
watchdog:
  interval: "180"
  confirm_wait: "30"
  max_restarts: "5"
`
	tmpFile, err := os.CreateTemp("", "singctl_str_ports_*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(yamlContent); err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()

	loaded, err := config.Load(tmpFile.Name())
	if err != nil {
		t.Fatalf("Load with string ports failed: %v", err)
	}

	if loaded.Server.WebTerminal.Port != 18080 {
		t.Errorf("expected WebTerminal.Port 18080, got %d", loaded.Server.WebTerminal.Port)
	}
	if loaded.Hy2.Up != 30 || loaded.Hy2.Down != 300 {
		t.Errorf("expected Hy2 30/300, got %d/%d", loaded.Hy2.Up, loaded.Hy2.Down)
	}
	if loaded.Watchdog.Interval != 180 || loaded.Watchdog.MaxRestarts != 5 {
		t.Errorf("expected Watchdog 180/5, got %d/%d", loaded.Watchdog.Interval, loaded.Watchdog.MaxRestarts)
	}
}

func TestMigrateConfig_AnyTLSPortPurgedAndResilient(t *testing.T) {
	oldYAML := `
server:
  node_domain: "node.example.com"
  anytls_port: "443"
`
	templateBytes, err := os.ReadFile("../configs/singctl.yaml")
	if err != nil {
		t.Fatal(err)
	}

	tmpFile, err := os.CreateTemp("", "singctl_migrate_port_*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(oldYAML); err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()

	if err := config.MigrateConfig(tmpFile.Name(), templateBytes); err != nil {
		t.Fatalf("MigrateConfig failed: %v", err)
	}

	content, err := os.ReadFile(tmpFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(content), "anytls_port") {
		t.Errorf("expected anytls_port to be purged from migrated config, but found it in:\n%s", string(content))
	}

	loaded, err := config.Load(tmpFile.Name())
	if err != nil {
		t.Fatalf("Load migrated config failed: %v", err)
	}

	if loaded.Server.NodeDomain != "node.example.com" {
		t.Errorf("expected node_domain 'node.example.com', got '%s'", loaded.Server.NodeDomain)
	}
}

func TestGenerateRandomAdminPath(t *testing.T) {
	for i := 0; i < 20; i++ {
		p := config.GenerateRandomAdminPath()
		if !strings.HasPrefix(p, "/sr/") {
			t.Fatalf("expected prefix /sr/, got %s", p)
		}
		token := strings.TrimPrefix(p, "/sr/")
		if len(token) != 24 {
			t.Fatalf("expected token length 24, got %d (%s)", len(token), token)
		}

		hasUpper := false
		hasLower := false
		hasDigit := false
		for _, r := range token {
			switch {
			case r >= 'A' && r <= 'Z':
				hasUpper = true
			case r >= 'a' && r <= 'z':
				hasLower = true
			case r >= '0' && r <= '9':
				hasDigit = true
			default:
				t.Fatalf("unexpected char %c in token %s", r, token)
			}
		}
		if !hasUpper || !hasLower || !hasDigit {
			t.Fatalf("token %s must contain upper, lower, and digit", token)
		}
	}
}

func TestEnsureWebAdminCredentials_PathUpgrade(t *testing.T) {
	s := &config.ServerConfig{
		WebAdmin: config.WebAdminConfig{
			Path: "/sr_3002961010c61739", // old hex path
		},
	}
	changed := s.EnsureWebAdminCredentials()
	if !changed {
		t.Fatalf("expected changed=true when upgrading old hex path")
	}
	if !strings.HasPrefix(s.WebAdmin.Path, "/sr/") {
		t.Fatalf("expected upgraded path with /sr/ prefix, got %s", s.WebAdmin.Path)
	}
	token := strings.TrimPrefix(s.WebAdmin.Path, "/sr/")
	if len(token) != 24 {
		t.Fatalf("expected 24-char token, got %s (len %d)", token, len(token))
	}
}

func TestEnsureWebAdminCredentials_Generates16CharPassword(t *testing.T) {
	s := &config.ServerConfig{}
	if !s.EnsureWebAdminCredentials() {
		t.Fatal("expected credentials to be generated")
	}
	if len(s.WebAdmin.Password) != 16 {
		t.Fatalf("expected 16-char password, got %q", s.WebAdmin.Password)
	}
	if !s.WebAdmin.PasswordPendingAck {
		t.Fatal("expected newly generated password to require acknowledgement")
	}
	if !validatePasswordChars(s.WebAdmin.Password) {
		t.Fatalf("password %q missing required character classes", s.WebAdmin.Password)
	}
}

func validatePasswordChars(pass string) bool {
	var hasUpper, hasLower, hasDigit bool
	for _, r := range pass {
		switch {
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= 'a' && r <= 'z':
			hasLower = true
		case r >= '0' && r <= '9':
			hasDigit = true
		}
	}
	return hasUpper && hasLower && hasDigit
}

func TestMigrateConfig_PreserveWebAdmin(t *testing.T) {
	oldYAML := `
server:
  node_domain: "node.example.com"
  substore_domain: "sub.example.com"
  web_admin:
    enabled: true
    port: 8092
    path: "/sr/ExistingPath987654321012"
    username: "singctl"
    password: "MySecurePassword123"
`
	templateYAML := `
server:
  node_domain: "template.example.com"
  # web_admin:
  #   enabled: true
`
	tmpFile, err := os.CreateTemp("", "singctl_test_webadmin_*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(oldYAML); err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()

	if err := config.MigrateConfig(tmpFile.Name(), []byte(templateYAML)); err != nil {
		t.Fatalf("MigrateConfig failed: %v", err)
	}

	loaded, err := config.Load(tmpFile.Name())
	if err != nil {
		t.Fatalf("Load migrated config failed: %v", err)
	}

	if loaded.Server.WebAdmin.Path != "/sr/ExistingPath987654321012" {
		t.Errorf("expected web_admin.path '/sr/ExistingPath987654321012', got '%s'", loaded.Server.WebAdmin.Path)
	}
	if loaded.Server.WebAdmin.Password != "MySecurePassword123" {
		t.Errorf("expected web_admin.password 'MySecurePassword123', got '%s'", loaded.Server.WebAdmin.Password)
	}
}

func TestSave_PasswordPendingAckFlip(t *testing.T) {
	initialYAML := `server:
  web_admin:
    enabled: true
    port: 8092
    path: /sr/ExistingPath987654321012
    username: singctl
    password: MySecurePassword123
    password_pending_ack: true
`
	tmpFile, err := os.CreateTemp("", "singctl_test_ack_*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(initialYAML); err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()

	cfg, err := config.Load(tmpFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Server.WebAdmin.PasswordPendingAck {
		t.Fatal("expected password_pending_ack to be true initially")
	}

	// Flip to false and save
	cfg.Server.WebAdmin.PasswordPendingAck = false
	if err := config.Save(tmpFile.Name(), cfg); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Verify file content directly
	content, err := os.ReadFile(tmpFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(content), "password_pending_ack: true") {
		t.Fatalf("expected password_pending_ack to be false in YAML, got:\n%s", string(content))
	}
	if !strings.Contains(string(content), "password_pending_ack: false") {
		t.Fatalf("expected password_pending_ack: false in YAML, got:\n%s", string(content))
	}

	// Reload and verify
	reloaded, err := config.Load(tmpFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Server.WebAdmin.PasswordPendingAck {
		t.Fatal("expected reloaded password_pending_ack to be false")
	}
}

func TestMigrateConfig_PreservesWebTerminalAndCustomRules(t *testing.T) {
	oldYAML := `server:
  node_domain: "node.example.com"
  web_terminal:
    enabled: true
    port: 18080
    path: "/ops-shell-test"
    mtls_ca: "/etc/singctl/mtls/ca.crt"
    password: "P12SecretPassword"
    ssh_tunnel_port: 18081
    ssh_tunnel_path: "/ssh-ws"
    ssh_port: 2222
custom_rules:
  outbounds:
    - tag: "#Auto"
      include: "香港|HK|獅城|SG"
      exclude: "美國|澳門"
      interval: "3m"
      tolerance: 80
      interrupt_exist_connections: false
  route:
    - action: route
      domain_suffix: [example.org]
      outbound: DirectConn
`
	templateBytes, err := os.ReadFile("../configs/singctl.yaml")
	if err != nil {
		t.Fatal(err)
	}

	tmpFile, err := os.CreateTemp("", "singctl_test_wt_*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(oldYAML); err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()

	if err := config.MigrateConfig(tmpFile.Name(), templateBytes); err != nil {
		t.Fatalf("MigrateConfig failed: %v", err)
	}

	loaded, err := config.Load(tmpFile.Name())
	if err != nil {
		t.Fatalf("Load migrated config failed: %v", err)
	}

	wt := loaded.Server.WebTerminal
	if !wt.Enabled || wt.Port != 18080 || wt.Path != "/ops-shell-test" || wt.SSHTunnelPort != 18081 || wt.SSHPort != 2222 {
		t.Fatalf("expected web_terminal to survive migration intact, got %+v", wt)
	}
	if len(loaded.CustomRules.Route) != 1 {
		t.Fatalf("expected 1 custom_rules.route entry after migration, got %d", len(loaded.CustomRules.Route))
	}
	if len(loaded.CustomRules.Outbounds) != 1 {
		t.Fatalf("expected 1 custom_rules.outbounds entry after migration, got %d", len(loaded.CustomRules.Outbounds))
	}
	ob := loaded.CustomRules.Outbounds[0]
	if ob.Tag != "#Auto" || ob.Tolerance != 80 || ob.Interval != "3m" || ob.InterruptExistConnections == nil || *ob.InterruptExistConnections {
		t.Fatalf("unexpected migrated outbound rule: %+v", ob)
	}
	if err := loaded.ValidateCustomRules(); err != nil {
		t.Fatalf("ValidateCustomRules failed: %v", err)
	}

	badCfg := &config.Config{
		CustomRules: config.CustomRulesConfig{
			Outbounds: []config.OutboundRule{{Tag: "#Auto", Include: "[unclosed"}},
		},
	}
	if err := badCfg.ValidateCustomRules(); err == nil {
		t.Fatal("expected ValidateCustomRules to reject invalid regex")
	}
}

func TestMigrateConfig_CommentedCustomRulesNotInjected(t *testing.T) {
	templateBytes, err := os.ReadFile("../configs/singctl.yaml")
	if err != nil {
		t.Fatal(err)
	}

	tmpFile, err := os.CreateTemp("", "singctl_test_comments_*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write(templateBytes); err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()

	if err := config.MigrateConfig(tmpFile.Name(), templateBytes); err != nil {
		t.Fatalf("MigrateConfig failed: %v", err)
	}

	raw, err := os.ReadFile(tmpFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	for line := range strings.SplitSeq(string(raw), "\n") {
		if strings.HasPrefix(line, "custom_rules:") || strings.HasPrefix(line, "  web_admin:") {
			t.Fatalf("commented template keys must not become active YAML keys: %q", line)
		}
	}
}

func TestPasswordHashingAndGatewayToken(t *testing.T) {
	plain := "SuperSecretPass99"
	if config.IsHashedPassword(plain) {
		t.Fatal("plaintext should not be detected as hashed")
	}
	if !config.VerifyPassword(plain, plain) {
		t.Fatal("plaintext VerifyPassword failed")
	}
	if config.VerifyPassword(plain, "wrong") {
		t.Fatal("plaintext VerifyPassword accepted wrong password")
	}

	hashed, err := config.HashPassword(plain)
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}
	if !config.IsHashedPassword(hashed) {
		t.Fatalf("expected bcrypt hash prefix, got %q", hashed)
	}
	idempotent, err := config.HashPassword(hashed)
	if err != nil || idempotent != hashed {
		t.Fatalf("HashPassword should be idempotent on existing hash")
	}
	if !config.VerifyPassword(hashed, plain) {
		t.Fatal("bcrypt VerifyPassword rejected valid password")
	}
	if config.VerifyPassword(hashed, "wrong") {
		t.Fatal("bcrypt VerifyPassword accepted wrong password")
	}

	tok1 := config.DeriveGatewayToken("/sr/AbCdEfGh1234567890123456")
	tok2 := config.DeriveGatewayToken("/sr/AbCdEfGh1234567890123456/")
	if tok1 == "" || tok1 != tok2 {
		t.Fatalf("DeriveGatewayToken normalization mismatch: %q vs %q", tok1, tok2)
	}
	if config.DeriveGatewayToken("") != "" {
		t.Fatal("DeriveGatewayToken should be empty when adminPath is empty")
	}
}

func TestSubscriptionNodeRulesLoadValidateAndMigrate(t *testing.T) {
	rawYAML := `subs:
  - name: "main"
    url: "https://example.com/sub"
    skip_tls_verify: false
    remove-emoji: true
    include:"HK|SG|JP"
    exclude: "剩余|到期"
    rename:
      - match: " Premium$"
        replace: ""
`
	tmpDir := t.TempDir()
	cfgPath := tmpDir + "/singctl.yaml"
	if err := os.WriteFile(cfgPath, []byte(rawYAML), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if len(cfg.Subs) != 1 {
		t.Fatalf("expected 1 sub, got %d", len(cfg.Subs))
	}
	sub := cfg.Subs[0]
	if sub.Include != "HK|SG|JP" || sub.Exclude != "剩余|到期" || len(sub.Rename) != 1 || sub.Rename[0].Match != " Premium$" {
		t.Fatalf("unexpected parsed node rules: %+v", sub)
	}
	if err := cfg.ValidateSubs(); err != nil {
		t.Fatalf("ValidateSubs failed for valid regexes: %v", err)
	}

	// Invalid regex must be rejected
	badCfg := &config.Config{
		Subs: []config.Subscription{
			{Name: "bad", URL: "https://example.com/sub", Include: "[unclosed"},
		},
	}
	if err := badCfg.ValidateSubs(); err == nil {
		t.Fatal("expected ValidateSubs to reject invalid include regex")
	}

	// MigrateConfig must preserve include/exclude/rename on subs
	templateBytes, err := os.ReadFile("../configs/singctl.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if err := config.MigrateConfig(cfgPath, templateBytes); err != nil {
		t.Fatalf("MigrateConfig failed: %v", err)
	}
	migrated, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("Load after MigrateConfig failed: %v", err)
	}
	if migrated.Subs[0].Include != "HK|SG|JP" || len(migrated.Subs[0].Rename) != 1 {
		t.Fatalf("expected node rules preserved after MigrateConfig, got %+v", migrated.Subs[0])
	}
}

func TestClientDNSConfig_EnsureCredentialsAndMigrate(t *testing.T) {
	var d config.ClientDNSConfig
	if !d.IsEnabled() {
		t.Fatal("default ClientDNSConfig should be enabled")
	}
	if d.GetDNSPort() != 5353 || d.GetWebPort() != 3000 || d.GetUsername() != "root" {
		t.Fatalf("unexpected defaults: dns=%d web=%d user=%s", d.GetDNSPort(), d.GetWebPort(), d.GetUsername())
	}

	// Empty preferred username defaults to "root" and generates 16-char password
	if !d.EnsureCredentials("") {
		t.Fatal("expected EnsureCredentials to report changed")
	}
	if d.Username != "root" || len(d.Password) != 16 || !validatePasswordChars(d.Password) {
		t.Fatalf("unexpected generated credentials: user=%q pass=%q", d.Username, d.Password)
	}

	// Custom preferred username overrides
	savedPass := d.Password
	if !d.EnsureCredentials("myadmin") {
		t.Fatal("expected custom username update to report changed")
	}
	if d.Username != "myadmin" || d.Password != savedPass {
		t.Fatalf("expected username=myadmin and preserved password, got user=%q pass=%q", d.Username, d.Password)
	}

	// MigrateConfig preserves dns block including explicit enabled: false
	oldYAML := `subs:
  - name: "main"
    url: "https://example.com/sub"
dns:
  enabled: false
  dns_port: 5354
  web_port: 3005
  username: "customuser"
  password: "CustomPassword12"
`
	tmpPath := t.TempDir() + "/singctl.yaml"
	if err := os.WriteFile(tmpPath, []byte(oldYAML), 0600); err != nil {
		t.Fatal(err)
	}
	templateBytes, err := os.ReadFile("../configs/singctl.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if err := config.MigrateConfig(tmpPath, templateBytes); err != nil {
		t.Fatalf("MigrateConfig failed: %v", err)
	}
	loaded, err := config.Load(tmpPath)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if loaded.DNS.IsEnabled() {
		t.Fatal("expected dns.enabled=false to be preserved after migration")
	}
	if loaded.DNS.GetDNSPort() != 5354 || loaded.DNS.GetWebPort() != 3005 ||
		loaded.DNS.GetUsername() != "customuser" || loaded.DNS.GetPassword() != "CustomPassword12" {
		t.Fatalf("unexpected migrated DNS config: %+v", loaded.DNS)
	}
}

func TestCityCountryToTag(t *testing.T) {
	tests := []struct {
		city        string
		countryCode string
		expected    string
	}{
		{"Los Angeles", "US", "los"},
		{"los angeles", "us", "los"},
		{"Singapore", "SG", "sg"},
		{"Hong Kong", "HK", "hk"},
		{"Tokyo", "JP", "jp"},
		{"Osaka", "JP", "osaka"},
		{"San Jose", "US", "sj"},
		{"Santa Clara", "US", "sj"},
		{"Fremont", "US", "sj"},
		{"Seattle", "US", "sea"},
		{"New York", "US", "ny"},
		{"Chicago", "US", "chi"},
		{"Dallas", "US", "dal"},
		{"London", "GB", "lon"},
		{"Frankfurt", "DE", "fra"},
		{"Paris", "FR", "par"},
		{"Amsterdam", "NL", "ams"},
		{"Sydney", "AU", "syd"},
		{"Taipei", "TW", "tw"},
		{"Seoul", "KR", "kr"},
		{"Zurich", "CH", "ch"},
		{"Unknown City", "AU", "au"},
	}

	for _, tc := range tests {
		got := config.CityCountryToTag(tc.city, tc.countryCode)
		if got != tc.expected {
			t.Errorf("CityCountryToTag(%q, %q) = %q, expected %q", tc.city, tc.countryCode, got, tc.expected)
		}
	}
}

func TestServerConfig_GetNodeTag_Explicit(t *testing.T) {
	s := &config.ServerConfig{
		NodeTag: "los",
	}
	if tag := s.GetNodeTag(); tag != "los" {
		t.Errorf("expected 'los', got '%s'", tag)
	}
}

func TestServerConfig_GetNodeTag_Discovered(t *testing.T) {
	config.ResetDiscoveredLocationTagForTest()
	defer config.ResetDiscoveredLocationTagForTest()

	config.SetDiscoveredLocationTagForTest("sg")
	s := &config.ServerConfig{}
	if tag := s.GetNodeTag(); tag != "sg" {
		t.Errorf("expected 'sg', got '%s'", tag)
	}
}

func TestServerConfig_GetNodeTag_Fallback(t *testing.T) {
	config.ResetDiscoveredLocationTagForTest()
	defer config.ResetDiscoveredLocationTagForTest()

	s := &config.ServerConfig{
		ServerIP:   "127.0.0.1",
		NodeDomain: "cdn.s1.example.com",
	}
	if tag := s.GetNodeTag(); tag != "cdn" {
		t.Errorf("expected 'cdn', got '%s'", tag)
	}
}

func TestRoleSpecificTemplatesAndSaveMigrate(t *testing.T) {
	// 1. TemplateForCommandArgs picks ServerConfigYAML for server commands and ClientConfigYAML for client commands
	srvTpl := string(config.TemplateForCommandArgs([]string{"singctl", "sr", "install"}))
	if !strings.Contains(srvTpl, "server:") || strings.Contains(srvTpl, "subs:") || strings.Contains(srvTpl, "hy2:") || strings.Contains(srvTpl, "watchdog:") {
		t.Fatalf("ServerConfigYAML should only contain server block, got:\n%s", srvTpl)
	}

	cliTpl := string(config.TemplateForCommandArgs([]string{"singctl", "-c", "/tmp/x.yaml", "sb", "start"}))
	if !strings.Contains(cliTpl, "subs:") || !strings.Contains(cliTpl, "hy2:") || strings.Contains(cliTpl, "\nserver:") {
		t.Fatalf("ClientConfigYAML should only contain client blocks without server, got:\n%s", cliTpl)
	}

	// 2. Saving a new server config creates a concise server-only YAML without subs/hy2/tailscale/watchdog
	tmpDir := t.TempDir()
	srvPath := filepath.Join(tmpDir, "server_singctl.yaml")
	srvCfg := &config.Config{
		Server: config.ServerConfig{
			NodeTag:    "sg",
			NodeDomain: "sg1.example.com",
			CFDNSKey:   "cf-test-token",
			Sni:        "swdist.apple.com",
		},
	}
	srvCfg.Server.EnsureWebAdminCredentials()
	if err := config.Save(srvPath, srvCfg); err != nil {
		t.Fatalf("Save server config failed: %v", err)
	}
	srvRaw, err := os.ReadFile(srvPath)
	if err != nil {
		t.Fatal(err)
	}
	srvStr := string(srvRaw)
	if !strings.Contains(srvStr, "server:") || !strings.Contains(srvStr, "sg1.example.com") {
		t.Fatalf("expected server fields in saved server config:\n%s", srvStr)
	}
	for _, forbidden := range []string{"subs:", "hy2:", "tailscale:", "watchdog:", "dns:"} {
		if strings.Contains(srvStr, forbidden) {
			t.Fatalf("server singctl.yaml must not contain %q, got:\n%s", forbidden, srvStr)
		}
	}

	// 3. Saving a client config preserves client-only structure without injecting server block
	cliPath := filepath.Join(tmpDir, "client_singctl.yaml")
	cliCfg := &config.Config{
		Subs: []config.Subscription{
			{Name: "main", URL: "https://example.com/sub", RemoveEmoji: true},
		},
		Hy2: config.Hy2Config{Up: 35, Down: 300},
	}
	if err := config.Save(cliPath, cliCfg); err != nil {
		t.Fatalf("Save client config failed: %v", err)
	}
	cliRaw, err := os.ReadFile(cliPath)
	if err != nil {
		t.Fatal(err)
	}
	cliStr := string(cliRaw)
	if !strings.Contains(cliStr, "subs:") || !strings.Contains(cliStr, "hy2:") {
		t.Fatalf("expected subs and hy2 in saved client config:\n%s", cliStr)
	}
	if strings.Contains(cliStr, "\nserver:") || strings.HasPrefix(cliStr, "server:") {
		t.Fatalf("client singctl.yaml must not contain server block, got:\n%s", cliStr)
	}

	// 4. MigrateConfig against full template keeps server config server-only and client config client-only
	fullTpl, err := os.ReadFile("../configs/singctl.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if err := config.MigrateConfig(srvPath, fullTpl); err != nil {
		t.Fatalf("MigrateConfig on server config failed: %v", err)
	}
	srvMigrated, _ := os.ReadFile(srvPath)
	for _, forbidden := range []string{"subs:", "hy2:", "tailscale:", "watchdog:"} {
		if strings.Contains(string(srvMigrated), forbidden) {
			t.Fatalf("migrated server config must not contain %q, got:\n%s", forbidden, string(srvMigrated))
		}
	}

	if err := config.MigrateConfig(cliPath, fullTpl); err != nil {
		t.Fatalf("MigrateConfig on client config failed: %v", err)
	}
	cliMigrated, _ := os.ReadFile(cliPath)
	if strings.Contains(string(cliMigrated), "\nserver:") || strings.HasPrefix(string(cliMigrated), "server:") {
		t.Fatalf("migrated client config must not contain server block, got:\n%s", string(cliMigrated))
	}
}

func TestWatchdogFailoverConfig_LoadSaveAndMigrate(t *testing.T) {
	// 1. Default zero-value config enables failover with production defaults
	var defCfg config.Config
	if !defCfg.Watchdog.Failover.IsEnabled() {
		t.Fatal("expected Watchdog.Failover.IsEnabled() to default to true")
	}
	if len(defCfg.Watchdog.Failover.EffectiveGroups()) != len(config.DefaultWatchdogFailoverGroups) {
		t.Fatalf("unexpected default groups: %v", defCfg.Watchdog.Failover.EffectiveGroups())
	}
	if defCfg.Watchdog.Failover.EffectiveConfirmRetries() != 1 {
		t.Fatalf("expected default confirm_retries=1, got %d", defCfg.Watchdog.Failover.EffectiveConfirmRetries())
	}
	if defCfg.Watchdog.Failover.EffectiveFailbackCooldown() != 180*time.Second {
		t.Fatalf("expected default failback_cooldown=180s, got %v", defCfg.Watchdog.Failover.EffectiveFailbackCooldown())
	}
	if defCfg.Watchdog.Failover.EffectiveMaxFailbackDelayMs() != 600 {
		t.Fatalf("expected default max_failback_delay_ms=600, got %d", defCfg.Watchdog.Failover.EffectiveMaxFailbackDelayMs())
	}

	// 2. UnmarshalYAML decodes sub_sync_interval (including -1) and failover string/int fields
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "singctl.yaml")
	rawYAML := `subs:
  - name: "main"
    url: "https://example.com/sub"
watchdog:
  interval: "120"
  confirm_wait: "25"
  max_restarts: "4"
  sub_sync_interval: "-1"
  failover:
    enabled: false
    groups:
      - "#VPS"
      - "Streaming"
    patrol_interval: "45"
    probe_timeout_ms: "3200"
    confirm_retries: "-1"
    failback_cooldown: "-1"
    max_failback_delay_ms: "450"
    probe_urls:
      - "https://example.com/generate_204"
`
	if err := os.WriteFile(cfgPath, []byte(rawYAML), 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if loaded.Watchdog.SubSyncInterval != -1 {
		t.Fatalf("expected sub_sync_interval=-1, got %d", loaded.Watchdog.SubSyncInterval)
	}
	if loaded.Watchdog.Failover.IsEnabled() {
		t.Fatal("expected failover.enabled=false")
	}
	if loaded.Watchdog.Failover.EffectiveConfirmRetries() != 0 {
		t.Fatalf("expected confirm_retries=-1 to yield 0 retries, got %d", loaded.Watchdog.Failover.EffectiveConfirmRetries())
	}
	if loaded.Watchdog.Failover.AutoFailbackEnabled() {
		t.Fatal("expected failback_cooldown=-1 to disable auto-failback")
	}
	if len(loaded.Watchdog.Failover.EffectiveGroups()) != 2 || loaded.Watchdog.Failover.EffectiveGroups()[1] != "Streaming" {
		t.Fatalf("unexpected custom groups: %v", loaded.Watchdog.Failover.EffectiveGroups())
	}

	// 3. MigrateConfig preserves sub_sync_interval and failover block
	fullTpl, err := os.ReadFile("../configs/singctl.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if err := config.MigrateConfig(cfgPath, fullTpl); err != nil {
		t.Fatalf("MigrateConfig failed: %v", err)
	}
	afterMigrate, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("Load after MigrateConfig failed: %v", err)
	}
	if afterMigrate.Watchdog.SubSyncInterval != -1 || afterMigrate.Watchdog.Failover.IsEnabled() {
		t.Fatalf("MigrateConfig lost watchdog fields: %+v", afterMigrate.Watchdog)
	}

	// 4. Resetting failover back to defaults and calling Save cleans stale sub-keys and keeps 0600 mode
	afterMigrate.Watchdog.SubSyncInterval = 600
	afterMigrate.Watchdog.Failover = config.WatchdogFailoverConfig{}
	if err := config.Save(cfgPath, afterMigrate); err != nil {
		t.Fatalf("Save after reset failed: %v", err)
	}
	fi, err := os.Stat(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Fatalf("expected saved config mode 0600, got %o", fi.Mode().Perm())
	}
	reloaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("Reload after reset failed: %v", err)
	}
	if !reloaded.Watchdog.Failover.IsEnabled() || len(reloaded.Watchdog.Failover.Groups) != 0 {
		t.Fatalf("expected failover reset to clean defaults, got %+v", reloaded.Watchdog.Failover)
	}
}

func TestSaveAndMigrateWarpRouting_NoStaleResidue(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "singctl.yaml")

	initialYAML := `server:
  node_domain: "node.example.com"
  cf_dns_key: "cf-test-token"
  warp_routing:
    mode: "split"
    presets:
      reddit: false
      missav: true
    warp_domains:
      - "custom.example.com"
    warp_cidrs:
      - "198.51.100.0/24"
`
	if err := os.WriteFile(cfgPath, []byte(initialYAML), 0600); err != nil {
		t.Fatal(err)
	}

	loaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if loaded.Server.WarpRouting.IsPresetEnabled("reddit", true) {
		t.Fatal("expected reddit preset=false to load cleanly")
	}
	if !loaded.Server.WarpRouting.IsPresetEnabled("missav", false) {
		t.Fatal("expected missav preset=true to load cleanly")
	}

	// MigrateConfig 应完整保留 warp_routing
	fullTpl, err := os.ReadFile("../configs/singctl.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if err := config.MigrateConfig(cfgPath, fullTpl); err != nil {
		t.Fatalf("MigrateConfig failed: %v", err)
	}
	afterMigrate, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if afterMigrate.Server.WarpRouting.IsPresetEnabled("reddit", true) ||
		!afterMigrate.Server.WarpRouting.IsPresetEnabled("missav", false) ||
		len(afterMigrate.Server.WarpRouting.WarpDomains) != 1 {
		t.Fatalf("MigrateConfig lost warp_routing state: %+v", afterMigrate.Server.WarpRouting)
	}

	// 清空 warp_domains 并恢复默认，验证 Save 后 YAML 无任何旧列表残留且保持 0600
	afterMigrate.Server.WarpRouting = config.WarpRoutingConfig{}
	if err := config.Save(cfgPath, afterMigrate); err != nil {
		t.Fatalf("Save after reset failed: %v", err)
	}
	rawBytes, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(rawBytes), "custom.example.com") ||
		strings.Contains(string(rawBytes), "\n  warp_routing:") ||
		strings.Contains(string(rawBytes), "\n    warp_domains:") ||
		strings.Contains(string(rawBytes), "\n    warp_cidrs:") {
		t.Fatalf("expected cleared warp_routing entries not to leave stale YAML residue:\n%s", string(rawBytes))
	}
	reloaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !reloaded.Server.WarpRouting.IsEmpty() {
		t.Fatalf("expected reloaded WarpRouting to be empty, got %+v", reloaded.Server.WarpRouting)
	}
	fi, err := os.Stat(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 config permission, got %o", fi.Mode().Perm())
	}
}
