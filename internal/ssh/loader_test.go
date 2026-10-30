package ssh

import (
	"os"
	"path/filepath"
	"testing"
)

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
  - alias: vps_rn
`
	if err := os.WriteFile(confPath, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	_, hosts, err := LoadConfig(confPath)
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
	if h3.Name != "vps_rn" || h3.Alias != "vps_rn" || !h3.IsAliasMode {
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
			_, _, err := LoadConfig(path)
			if err == nil {
				t.Errorf("Expected error for %s, but got nil", tt.name)
			}
		})
	}
}
