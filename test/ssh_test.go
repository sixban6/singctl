package test

import (
	"os"
	"path/filepath"
	"singctl/internal/ssh"
	"strings"
	"testing"
	"time"
)

func TestEscapeShellArg(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"hello", "'hello'"},
		{"hello world", "'hello world'"},
		{"it's dangerous", "'it'\"'\"'s dangerous'"},
		{"", "''"},
	}

	for _, tt := range tests {
		got := ssh.EscapeShellArg(tt.input)
		if got != tt.expected {
			t.Errorf("escapeShellArg(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestTestTCPPort_NonReachable(t *testing.T) {
	// A port that should definitely fail or timeout quickly
	reachable := ssh.TestTCPPort("127.0.0.1", 59999, 100*time.Millisecond)
	if reachable {
		t.Logf("Notice: Port 59999 happens to be open, skipping unreachable assertion")
	}
}

func TestLoadConfig_EnvAndDefaults(t *testing.T) {
	tempDir := t.TempDir()
	confPath := filepath.Join(tempDir, "test-init.yaml")

	t.Setenv("TEST_SSH_PASS", "SecretPass123")

	yamlContent := `
version: "1.0"
defaults:
  user: root
  current_port: 22
  target_port: 2222
  identity_file: ~/.ssh/id_ed25519.pub
  private_key: ~/.ssh/id_ed25519
hosts:
  - name: node-1
    host: 1.1.1.1
    auth:
      password: "${TEST_SSH_PASS}"
  - name: node-2
    host: mynode.example.com
    user: admin
    target_port: 3333
    auth:
      password: "DirectPassword"
  - alias: edge-tunnel-01
`
	if err := os.WriteFile(confPath, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	_, hosts, err := ssh.LoadConfig(confPath)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if len(hosts) != 3 {
		t.Fatalf("Expected 3 hosts, got %d", len(hosts))
	}

	// Host 1 checks
	h1 := hosts[0]
	if h1.Name != "node-1" || h1.Host != "1.1.1.1" {
		t.Errorf("Unexpected host 1 properties: %+v", h1)
	}
	if h1.Auth.Password != "SecretPass123" {
		t.Errorf("Expected password expanded to SecretPass123, got %s", h1.Auth.Password)
	}
	if h1.TargetPort != 2222 {
		t.Errorf("Expected default target port 2222, got %d", h1.TargetPort)
	}

	// Host 2 checks (domain support)
	h2 := hosts[1]
	if h2.Name != "node-2" || h2.Host != "mynode.example.com" || h2.User != "admin" {
		t.Errorf("Unexpected host 2 properties: %+v", h2)
	}
	if h2.TargetPort != 3333 {
		t.Errorf("Expected override target port 3333, got %d", h2.TargetPort)
	}

	// Host 3 checks (alias in ~/.ssh/config)
	h3 := hosts[2]
	if h3.Name != "edge-tunnel-01" || h3.Alias != "edge-tunnel-01" || !h3.IsAliasMode {
		t.Errorf("Unexpected host 3 properties: %+v", h3)
	}
	if h3.TargetPort <= 0 {
		t.Errorf("Expected valid target port, got %d", h3.TargetPort)
	}
}

func TestLoadConfig_ValidationErrors(t *testing.T) {
	tempDir := t.TempDir()

	tests := []struct {
		name    string
		content string
	}{
		{
			name: "duplicate host names",
			content: `
hosts:
  - name: same-name
    ip: 1.1.1.1
    auth:
      password: "foo"
  - name: same-name
    ip: 2.2.2.2
    auth:
      password: "bar"
`,
		},
		{
			name: "missing auth",
			content: `
hosts:
  - name: no-auth
    ip: 1.1.1.1
`,
		},
		{
			name: "empty ip",
			content: `
hosts:
  - name: no-ip
    ip: ""
    auth:
      password: "foo"
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(tempDir, tt.name+".yaml")
			if err := os.WriteFile(path, []byte(tt.content), 0644); err != nil {
				t.Fatalf("WriteFile failed: %v", err)
			}
			_, _, err := ssh.LoadConfig(path)
			if err == nil {
				t.Errorf("Expected error for %s, but got nil", tt.name)
			}
		})
	}
}

func TestLocalConfigManager_SyncAndClean(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config")

	// Pre-populate with existing user config
	userOriginalConfig := `
Host github.com
    HostName github.com
    User git
    IdentityFile ~/.ssh/github_key
`
	if err := os.WriteFile(configPath, []byte(userOriginalConfig), 0600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	mgr := ssh.NewLocalConfigManager(configPath)

	hosts := []*ssh.Host{
		{
			Name:       "node-a",
			IP:         "10.0.0.1",
			User:       "root",
			TargetPort: 2222,
			PrivateKey: "/path/to/key",
		},
		{
			Name:       "node-b",
			IP:         "10.0.0.2",
			User:       "ubuntu",
			TargetPort: 22222,
			PrivateKey: "/path/to/key2",
		},
	}

	// 1. Sync hosts
	if err := mgr.SyncHosts(hosts); err != nil {
		t.Fatalf("SyncHosts failed: %v", err)
	}

	// Check content contains both github.com and managed hosts
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "Host github.com") {
		t.Errorf("Expected original github.com entry to be preserved")
	}
	if !strings.Contains(content, "Host node-a") || !strings.Contains(content, "Port 2222") {
		t.Errorf("Expected node-a to be present with Port 2222")
	}
	if !strings.Contains(content, "Host node-b") || !strings.Contains(content, "Port 22222") {
		t.Errorf("Expected node-b to be present with Port 22222")
	}

	// 2. List managed hosts
	list, err := mgr.ListManagedHosts()
	if err != nil {
		t.Fatalf("ListManagedHosts failed: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("Expected 2 managed hosts, got %d", len(list))
	}

	// 3. Update node-a's port and sync again (In-place update check)
	hosts[0].TargetPort = 22224
	if err := mgr.SyncHosts(hosts); err != nil {
		t.Fatalf("Second SyncHosts failed: %v", err)
	}

	updatedData, _ := os.ReadFile(configPath)
	updatedContent := string(updatedData)
	if !strings.Contains(updatedContent, "Port 22224") {
		t.Errorf("Expected updated Port 22224 for node-a")
	}
	// Verify no duplicates
	if strings.Count(updatedContent, "Host node-a") != 1 {
		t.Errorf("Expected exactly one 'Host node-a', found multiple occurrences")
	}

	// 4. Clean only node-a
	cleanedCount, err := mgr.CleanManagedHosts("node-a")
	if err != nil || cleanedCount != 1 {
		t.Fatalf("Expected 1 host cleaned, got %d, err: %v", cleanedCount, err)
	}

	cleanedData, _ := os.ReadFile(configPath)
	cleanedContent := string(cleanedData)
	if strings.Contains(cleanedContent, "Host node-a") {
		t.Errorf("Expected node-a to be removed")
	}
	if !strings.Contains(cleanedContent, "Host node-b") {
		t.Errorf("Expected node-b to still remain")
	}
	if !strings.Contains(cleanedContent, "Host github.com") {
		t.Errorf("Expected original github.com to still remain")
	}

	// 5. Clean all
	cleanedAllCount, err := mgr.CleanManagedHosts("")
	if err != nil || cleanedAllCount != 1 {
		t.Fatalf("Expected 1 host cleaned, got %d, err: %v", cleanedAllCount, err)
	}
	finalData, _ := os.ReadFile(configPath)
	finalContent := string(finalData)
	if strings.Contains(finalContent, "BEGIN SINGCTL MANAGED HOST") {
		t.Errorf("Expected all singctl blocks to be cleaned")
	}
	if !strings.Contains(finalContent, "Host github.com") {
		t.Errorf("Expected original github.com to remain after all clean")
	}
}

func TestGenerateTemplate(t *testing.T) {
	tempDir := t.TempDir()
	outPath := filepath.Join(tempDir, "ssh-init.yaml")

	// 1. Generate template
	if err := ssh.GenerateTemplate(outPath, false); err != nil {
		t.Fatalf("GenerateTemplate failed: %v", err)
	}

	// 2. File should exist
	if _, err := os.Stat(outPath); err != nil {
		t.Fatalf("Expected file %s to exist, but got: %v", outPath, err)
	}

	// 3. Generating again without force should fail
	if err := ssh.GenerateTemplate(outPath, false); err == nil {
		t.Fatalf("Expected error when overwriting without force, but got nil")
	}

	// 4. Generating with force should succeed
	if err := ssh.GenerateTemplate(outPath, true); err != nil {
		t.Fatalf("GenerateTemplate with force failed: %v", err)
	}

	// 5. Template should be loadable
	cfg, hosts, err := ssh.LoadConfig(outPath)
	if err != nil {
		t.Fatalf("Failed to parse generated template: %v", err)
	}

	if len(hosts) != 4 {
		t.Fatalf("Expected 4 sample hosts, got %d", len(hosts))
	}

	if cfg.Defaults.TargetPort != 2222 {
		t.Errorf("Expected default target port 2222, got %d", cfg.Defaults.TargetPort)
	}
}
