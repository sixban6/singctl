package test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestWindowsInstallationScript 测试Windows安装脚本的基本结构
func TestWindowsInstallationScript(t *testing.T) {
	// 测试原生Windows批处理脚本
	installBatPath := filepath.Join("..", "install.ps1")

	// 检查install.bat文件是否存在
	if _, err := os.Stat(installBatPath); os.IsNotExist(err) {
		t.Fatalf("install.ps1 file does not exist at %s", installBatPath)
	}

	// 读取install.bat内容
	content, err := os.ReadFile(installBatPath)
	if err != nil {
		t.Fatalf("Failed to read install.ps1: %v", err)
	}

	contentStr := string(content)

	// 验证原生Windows安装的关键组件
	requiredComponents := []struct {
		name    string
		pattern string
	}{
		{"Admin check", "net session"},
		{"Windows version check", "for /f \"tokens=4-7 delims=[.] \" %%i in ('ver')"},
		{"GitHub API download", "api.github.com/repos/sixban6/singctl/releases/latest"},
		{"Windows asset selection", "*windows*amd64*.zip"},
		{"ARM64 architecture support", "ARM64"},
		{"PowerShell extraction", "Expand-Archive"},
		{"singctl installation", "%LOCALAPPDATA%\\Programs\\singctl"},
		{"PATH setup", "setx PATH"},
		{"Config creation", "singctl.yaml"},
		{"Native Windows title", "Native Windows sing-box support"},
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
		// 检查错误处理
		if !strings.Contains(contentStr, "exit /b 1") {
			t.Error("install.ps1 should contain proper error handling with exit codes")
		}

		// 检查用户反馈
		if !strings.Contains(contentStr, "echo") {
			t.Error("install.ps1 should contain user feedback messages")
		}

		// 检查分阶段安装（更新为3阶段）
		phasePatterns := []string{
			"[1/3]", "[2/3]", "[3/3]",
		}
		for _, phase := range phasePatterns {
			if !strings.Contains(contentStr, phase) {
				t.Errorf("install.ps1 missing installation phase: %s", phase)
			}
		}

		// 验证不包含WSL2相关内容
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

// TestREADMEWindowsInstructions 测试README中的Windows安装说明
func TestREADMEWindowsInstructions(t *testing.T) {
	readmePath := filepath.Join("..", "README.md")

	content, err := os.ReadFile(readmePath)
	if err != nil {
		t.Fatalf("Failed to read README.md: %v", err)
	}

	contentStr := string(content)

	// 检查更新的Windows安装说明
	requiredElements := []string{
		"Windows 10/11",
		"curl -o install.ps1",
		"install.ps1",
		"Native Windows installation",
		"administrator",
		"No WSL2 required",
		"runs directly on Windows",
	}

	for _, element := range requiredElements {
		if !strings.Contains(contentStr, element) {
			t.Errorf("README.md missing required Windows instruction element: %s", element)
		} else {
			t.Logf("✓ Found Windows instruction element: %s", element)
		}
	}

	// 验证不再提及WSL2
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

// TestWindowsWorkflowSimulation 模拟Windows原生安装工作流程
func TestWindowsWorkflowSimulation(t *testing.T) {
	t.Run("Simulate native Windows installation workflow", func(t *testing.T) {
		// 这是一个概念性测试，模拟Windows用户的体验流程

		steps := []struct {
			step        string
			description string
			simulation  func() bool
		}{
			{
				step:        "Download install.ps1",
				description: "User downloads install.ps1 from GitHub",
				simulation: func() bool {
					// 模拟：检查install.bat是否可下载
					_, err := os.Stat(filepath.Join("..", "install.ps1"))
					return err == nil
				},
			},
			{
				step:        "Run as administrator",
				description: "User runs install.ps1 with admin privileges",
				simulation: func() bool {
					// 模拟：检查脚本包含管理员检查
					content, err := os.ReadFile(filepath.Join("..", "install.ps1"))
					if err != nil {
						return false
					}
					return strings.Contains(string(content), "net session")
				},
			},
			{
				step:        "Download singctl from GitHub",
				description: "Script downloads singctl Windows binary from GitHub releases",
				simulation: func() bool {
					// 模拟：检查脚本包含GitHub API调用
					content, err := os.ReadFile(filepath.Join("..", "install.ps1"))
					if err != nil {
						return false
					}
					return strings.Contains(string(content), "api.github.com/repos/sixban6/singctl/releases/latest")
				},
			},
			{
				step:        "Install to LOCALAPPDATA",
				description: "Script installs singctl to Windows user directory",
				simulation: func() bool {
					// 模拟：检查脚本使用LOCALAPPDATA路径
					content, err := os.ReadFile(filepath.Join("..", "install.ps1"))
					if err != nil {
						return false
					}
					return strings.Contains(string(content), "%LOCALAPPDATA%\\Programs\\singctl")
				},
			},
			{
				step:        "Create config directory",
				description: "Script creates configuration directory and default config",
				simulation: func() bool {
					// 模拟：检查脚本创建配置目录和文件
					content, err := os.ReadFile(filepath.Join("..", "install.ps1"))
					if err != nil {
						return false
					}
					return strings.Contains(string(content), "singctl.yaml") &&
						strings.Contains(string(content), "%LOCALAPPDATA%\\singctl")
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
	t.Run("Install script consistency", func(t *testing.T) {
		// 验证安装脚本存在且功能一致

		// 检查install.sh (Unix)
		installShPath := filepath.Join("..", "install.sh")
		if _, err := os.Stat(installShPath); err == nil {
			t.Log("✓ Unix install script exists")
		} else {
			t.Error("Unix install script missing")
		}

		// 检查install.bat (Windows原生方式)
		installBatPath := filepath.Join("..", "install.ps1")
		if _, err := os.Stat(installBatPath); err == nil {
			t.Log("✓ Windows batch install script exists")
		} else {
			t.Error("Windows batch install script missing")
		}

		// 验证install.ps1已被删除（不再需要）
		installPs1Path := filepath.Join("..", "install.ps1")
		if _, err := os.Stat(installPs1Path); os.IsNotExist(err) {
			t.Log("✓ install.ps1 correctly removed (no longer needed)")
		} else {
			t.Error("install.ps1 should be removed as it's no longer needed")
		}

		// 验证两个脚本都引用相同的GitHub仓库
		if shContent, err := os.ReadFile(installShPath); err == nil {
			if batContent, err := os.ReadFile(installBatPath); err == nil {
				// install.sh uses GITHUB_REPO variable
				if !strings.Contains(string(shContent), `GITHUB_REPO="sixban6/singctl"`) {
					t.Error("install.sh doesn't reference correct GitHub repo")
				}
				// install.ps1 uses GitHub API
				if !strings.Contains(string(batContent), "api.github.com/repos/sixban6/singctl/releases/latest") {
					t.Error("install.ps1 doesn't reference correct GitHub repo")
				}
				t.Log("✓ Both scripts reference the same GitHub repository")
			}
		}
	})
}

// TestWindowsScriptFiles 测试Windows脚本文件
func TestWindowsScriptFiles(t *testing.T) {
	t.Run("Windows script files validation", func(t *testing.T) {
		// 检查Windows启动脚本
		startScriptPath := filepath.Join("..", "internal", "scripts", "start_singbox_windows.bat")
		if _, err := os.Stat(startScriptPath); err == nil {
			content, err := os.ReadFile(startScriptPath)
			if err != nil {
				t.Fatalf("Failed to read start script: %v", err)
			}

			// 验证启动脚本的关键组件
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

		// 检查Windows停止脚本
		stopScriptPath := filepath.Join("..", "internal", "scripts", "stop_singbox_windows.bat")
		if _, err := os.Stat(stopScriptPath); err == nil {
			content, err := os.ReadFile(stopScriptPath)
			if err != nil {
				t.Fatalf("Failed to read stop script: %v", err)
			}

			// 验证停止脚本的关键组件
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
