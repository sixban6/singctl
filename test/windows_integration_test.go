package test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestWindowsInstallationScript 测试 install.ps1 的基本结构和关键组件
func TestWindowsInstallationScript(t *testing.T) {
	installPs1Path := filepath.Join("..", "install.ps1")

	if _, err := os.Stat(installPs1Path); os.IsNotExist(err) {
		t.Fatalf("install.ps1 file does not exist at %s", installPs1Path)
	}

	content, err := os.ReadFile(installPs1Path)
	if err != nil {
		t.Fatalf("Failed to read install.ps1: %v", err)
	}

	contentStr := string(content)

	// 验证 PowerShell 安装脚本的关键组件
	requiredComponents := []struct {
		name    string
		pattern string
	}{
		{"GitHub API download", "api.github.com/repos/$GitHubRepo/releases/latest"},
		{"ARM64 architecture support", "arm64"},
		{"PowerShell extraction", "Expand-Archive"},
		{"singctl installation dir", `$env:LOCALAPPDATA\Programs\singctl`},
		{"PATH setup via registry", "Registry::HKEY_CURRENT_USER\\Environment"},
		{"Config creation (singctl.yaml)", "singctl.yaml"},
		{"Native Windows banner", "Native Windows sing-box support"},
		{"Error on download failure", "exit 1"},
		{"User feedback (Write-Info)", "Write-Info"},
	}

	for _, component := range requiredComponents {
		if !strings.Contains(contentStr, component.pattern) {
			t.Errorf("install.ps1 missing required component '%s' (pattern: %s)", component.name, component.pattern)
		} else {
			t.Logf("✓ Found required component: %s", component.name)
		}
	}

	// 验证脚本结构
	t.Run("Script structure validation", func(t *testing.T) {
		// PowerShell 使用 exit 1 作为错误退出码
		if !strings.Contains(contentStr, "exit 1") {
			t.Error("install.ps1 should contain proper error handling with exit codes")
		}

		// 检查 PowerShell 用户反馈函数（Write-Info / Write-Success 等）
		if !strings.Contains(contentStr, "Write-Host") {
			t.Error("install.ps1 should contain user feedback messages")
		}

		// 验证不包含 WSL2 相关内容
		wslPatterns := []string{
			"wsl --install", "WSL2", "Ubuntu", "Debian", "wsl -d",
		}
		for _, pattern := range wslPatterns {
			if strings.Contains(contentStr, pattern) {
				t.Errorf("install.ps1 should not contain WSL2-related content: %s", pattern)
			}
		}
	})
}

// TestREADMEWindowsInstructions 测试 README 中的 Windows 安装说明
func TestREADMEWindowsInstructions(t *testing.T) {
	readmePath := filepath.Join("..", "README.md")

	content, err := os.ReadFile(readmePath)
	if err != nil {
		t.Fatalf("Failed to read README.md: %v", err)
	}

	contentStr := string(content)

	// README 中应包含的 Windows 安装相关元素
	requiredElements := []string{
		"Windows",
		"install.ps1",
		"powershell",
	}

	for _, element := range requiredElements {
		if !strings.Contains(contentStr, element) {
			t.Errorf("README.md missing required Windows instruction element: %s", element)
		} else {
			t.Logf("✓ Found Windows instruction element: %s", element)
		}
	}

	// 验证不再包含过时的 WSL2 安装指引
	outdatedElements := []string{
		"WSL2 and Ubuntu environment",
		"system restart",
		"WSL2 environment",
	}

	for _, element := range outdatedElements {
		if strings.Contains(contentStr, element) {
			t.Errorf("README.md should not contain outdated WSL2 reference: %s", element)
		}
	}
}

// TestWindowsWorkflowSimulation 模拟 Windows 原生安装工作流程（基于 install.ps1 内容验证）
func TestWindowsWorkflowSimulation(t *testing.T) {
	t.Run("Simulate native Windows installation workflow", func(t *testing.T) {
		ps1Path := filepath.Join("..", "install.ps1")

		readScript := func() (string, bool) {
			content, err := os.ReadFile(ps1Path)
			if err != nil {
				return "", false
			}
			return string(content), true
		}

		steps := []struct {
			step        string
			description string
			simulation  func() bool
		}{
			{
				step:        "Download install.ps1",
				description: "User downloads install.ps1 from GitHub",
				simulation: func() bool {
					_, err := os.Stat(ps1Path)
					return err == nil
				},
			},
			{
				step:        "Run as administrator (PowerShell)",
				description: "Script uses #Requires -RunAsAdministrator directive",
				simulation: func() bool {
					s, ok := readScript()
					if !ok {
						return false
					}
					return strings.Contains(s, "#Requires -RunAsAdministrator")
				},
			},
			{
				step:        "Download singctl from GitHub",
				description: "Script downloads singctl Windows binary from GitHub releases",
				simulation: func() bool {
					s, ok := readScript()
					if !ok {
						return false
					}
					return strings.Contains(s, "api.github.com/repos/$GitHubRepo/releases/latest")
				},
			},
			{
				step:        "Install to LOCALAPPDATA",
				description: "Script installs singctl to Windows user Programs directory",
				simulation: func() bool {
					s, ok := readScript()
					if !ok {
						return false
					}
					return strings.Contains(s, `$env:LOCALAPPDATA\Programs\singctl`)
				},
			},
			{
				step:        "Create config directory",
				description: "Script creates configuration directory and default config",
				simulation: func() bool {
					s, ok := readScript()
					if !ok {
						return false
					}
					return strings.Contains(s, "singctl.yaml") &&
						strings.Contains(s, `$env:LOCALAPPDATA\singctl`)
				},
			},
		}

		for i, step := range steps {
			t.Logf("Step %d: %s", i+1, step.step)
			if !step.simulation() {
				t.Errorf("Step %d failed: %s - %s", i+1, step.step, step.description)
			} else {
				t.Logf("✓ Step %d passed: %s", i+1, step.description)
			}
		}
	})
}

// TestInstallScriptConsistency 测试安装脚本一致性
func TestInstallScriptConsistency(t *testing.T) {
	t.Skip("Skipping legacy script consistency test")
}

// TestWindowsScriptFiles 测试 Windows 脚本文件
func TestWindowsScriptFiles(t *testing.T) {
	t.Run("Windows script files validation", func(t *testing.T) {
		// 检查 Windows 启动脚本
		startScriptPath := filepath.Join("..", "internal", "scripts", "start_singbox_windows.bat")
		if _, err := os.Stat(startScriptPath); err == nil {
			content, err := os.ReadFile(startScriptPath)
			if err != nil {
				t.Fatalf("Failed to read start script: %v", err)
			}

			scriptContent := string(content)
			requiredPatterns := []string{
				"CONFIG_FILE=%LOCALAPPDATA%\\sing-box\\config.json",
				"SING_BOX_EXE=%LOCALAPPDATA%\\Programs\\sing-box\\sing-box.exe",
				"tasklist /FI \"IMAGENAME eq sing-box.exe\"",
				"start /B \"\" \"%SING_BOX_EXE%\" run",
			}

			for _, pattern := range requiredPatterns {
				if !strings.Contains(scriptContent, pattern) {
					t.Errorf("Windows start script missing pattern: %s", pattern)
				}
			}
			t.Log("✓ Windows start script validation passed")
		} else {
			t.Error("Windows start script not found")
		}

		// 检查 Windows 停止脚本
		stopScriptPath := filepath.Join("..", "internal", "scripts", "stop_singbox_windows.bat")
		if _, err := os.Stat(stopScriptPath); err == nil {
			content, err := os.ReadFile(stopScriptPath)
			if err != nil {
				t.Fatalf("Failed to read stop script: %v", err)
			}

			scriptContent := string(content)
			requiredPatterns := []string{
				"tasklist /FI \"IMAGENAME eq sing-box.exe\"",
				"taskkill /IM sing-box.exe",
				"taskkill /F /IM sing-box.exe",
			}

			for _, pattern := range requiredPatterns {
				if !strings.Contains(scriptContent, pattern) {
					t.Errorf("Windows stop script missing pattern: %s", pattern)
				}
			}
			t.Log("✓ Windows stop script validation passed")
		} else {
			t.Error("Windows stop script not found")
		}
	})
}
