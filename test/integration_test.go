package test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestCLICommands 测试主要的CLI命令
func TestCLICommands(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping CLI integration tests in short mode")
	}

	// 构建测试二进制文件
	binaryPath := buildTestBinary(t)
	defer os.Remove(binaryPath)

	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{
			name:    "version command",
			args:    []string{"version"},
			wantErr: false,
		},
		{
			name:    "help command",
			args:    []string{"--help"},
			wantErr: false,
		},
		{
			name:    "invalid command",
			args:    []string{"invalid-command"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := exec.Command(binaryPath, tt.args...)
			err := cmd.Run()

			if (err != nil) != tt.wantErr {
				t.Errorf("Command %v error = %v, wantErr %v", tt.args, err, tt.wantErr)
			}
		})
	}
}

// TestFullWorkflow 测试完整工作流程
func TestFullWorkflow(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping full workflow test in short mode")
	}

	binaryPath := buildTestBinary(t)
	defer os.Remove(binaryPath)

	configPath := createTestConfig(t)
	defer os.Remove(configPath)

	// 创建mock脚本
	scriptDir := createMockScripts(t)
	defer os.RemoveAll(scriptDir)

	// 改变工作目录
	oldDir, _ := os.Getwd()
	defer os.Chdir(oldDir)
	os.Chdir(filepath.Dir(scriptDir))

	t.Run("start command", func(t *testing.T) {
		cmd := exec.Command(binaryPath, "-c", configPath, "start")
		output, err := cmd.CombinedOutput()
		
		// 预期会失败，因为订阅无效
		t.Logf("Start command output: %s", string(output))
		t.Logf("Start command error: %v (expected in test)", err)
	})

	t.Run("stop command", func(t *testing.T) {
		cmd := exec.Command(binaryPath, "-c", configPath, "stop")
		output, err := cmd.CombinedOutput()
		
		t.Logf("Stop command output: %s", string(output))
		if err != nil {
			t.Logf("Stop command failed: %v (expected if nothing running)", err)
		}
	})
}

// 辅助函数
func buildTestBinary(t *testing.T) string {
	tempDir := t.TempDir()
	binaryPath := filepath.Join(tempDir, "singctl-test")

	projectRoot := getProjectRoot(t)
	
	cmd := exec.Command("go", "build", "-o", binaryPath, "./cmd/singctl")
	cmd.Dir = projectRoot
	
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to build test binary: %v", err)
	}

	return binaryPath
}

func createTestConfig(t *testing.T) string {
	content := `
subs:
  - url: "https://example.com/test-subscription"
    skip_tls_verify: false
    remove-emoji: true

dns:
  auto_optimize: true

github:
  mirror_url: "https://ghfast.top"
`

	tempFile := filepath.Join(t.TempDir(), "test-config.yaml")
	if err := os.WriteFile(tempFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test config: %v", err)
	}

	return tempFile
}

func createMockScripts(t *testing.T) string {
	tempDir := t.TempDir()
	scriptDir := filepath.Join(tempDir, "scripts")
	
	if err := os.MkdirAll(scriptDir, 0755); err != nil {
		t.Fatalf("Failed to create script directory: %v", err)
	}

	// 创建mock start脚本
	startScript := `#!/bin/bash
echo "Mock start script executed with config: $1"
exit 0
`
	startPath := filepath.Join(scriptDir, "start_singbox.sh")
	if err := os.WriteFile(startPath, []byte(startScript), 0755); err != nil {
		t.Fatalf("Failed to create mock start script: %v", err)
	}

	// 创建mock stop脚本
	stopScript := `#!/bin/bash
echo "Mock stop script executed"
exit 0
`
	stopPath := filepath.Join(scriptDir, "stop_singbox.sh")
	if err := os.WriteFile(stopPath, []byte(stopScript), 0755); err != nil {
		t.Fatalf("Failed to create mock stop script: %v", err)
	}

	return scriptDir
}

func getProjectRoot(t *testing.T) string {
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get working directory: %v", err)
	}

	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("Could not find project root (go.mod)")
		}
		dir = parent
	}
}