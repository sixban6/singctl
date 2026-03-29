package test

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"singctl/internal/cmd"
	"testing"
)

func TestCopyGeneratedConfigToClipboardOnDarwinDefaultPath(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.json")
	clipboardPath := filepath.Join(tempDir, "clipboard.txt")
	configContent := `{"outbounds":[{"type":"direct"}]}`

	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("write config file: %v", err)
	}

	oldCommandRunner := cmd.commandRunner
	oldRuntimeGOOS := cmd.runtimeGOOS
	oldDefaultPath := cmd.defaultSingBoxConfigPath
	t.Cleanup(func() {
		cmd.commandRunner = oldCommandRunner
		cmd.runtimeGOOS = oldRuntimeGOOS
		cmd.defaultSingBoxConfigPath = oldDefaultPath
	})

	cmd.runtimeGOOS = "darwin"
	cmd.defaultSingBoxConfigPath = configPath
	cmd.commandRunner = func(name string, args ...string) *exec.Cmd {
		cmd := exec.Command(os.Args[0], "-test.run=TestClipboardHelperProcess", "--", name)
		cmd.Env = append(os.Environ(),
			"GO_WANT_CLIPBOARD_HELPER=1",
			"GO_CLIPBOARD_CAPTURE_PATH="+clipboardPath,
		)
		return cmd
	}

	copied, err := cmd.copyGeneratedConfigToClipboard(configPath)
	if err != nil {
		t.Fatalf("copyGeneratedConfigToClipboard returned error: %v", err)
	}
	if !copied {
		t.Fatal("expected generated config to be copied on darwin default path")
	}

	got, err := os.ReadFile(clipboardPath)
	if err != nil {
		t.Fatalf("read clipboard capture: %v", err)
	}
	if string(got) != configContent {
		t.Fatalf("unexpected clipboard content: got %q want %q", string(got), configContent)
	}
}

func TestCopyGeneratedConfigToClipboardSkipsUnsupportedCases(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.json")

	if err := os.WriteFile(configPath, []byte(`{"dns":{}}`), 0644); err != nil {
		t.Fatalf("write config file: %v", err)
	}

	oldCommandRunner := cmd.commandRunner
	oldRuntimeGOOS := cmd.runtimeGOOS
	oldDefaultPath := cmd.defaultSingBoxConfigPath
	t.Cleanup(func() {
		cmd.commandRunner = oldCommandRunner
		cmd.runtimeGOOS = oldRuntimeGOOS
		cmd.defaultSingBoxConfigPath = oldDefaultPath
	})

	commandCalled := false
	cmd.commandRunner = func(name string, args ...string) *exec.Cmd {
		commandCalled = true
		return exec.Command("true")
	}

	cmd.runtimeGOOS = "linux"
	cmd.defaultSingBoxConfigPath = configPath
	copied, err := cmd.copyGeneratedConfigToClipboard(configPath)
	if err != nil {
		t.Fatalf("unexpected error on linux: %v", err)
	}
	if copied {
		t.Fatal("expected clipboard copy to be skipped on linux")
	}

	cmd.runtimeGOOS = "darwin"
	cmd.defaultSingBoxConfigPath = filepath.Join(tempDir, "other-config.json")
	copied, err = cmd.copyGeneratedConfigToClipboard(configPath)
	if err != nil {
		t.Fatalf("unexpected error on non-default path: %v", err)
	}
	if copied {
		t.Fatal("expected clipboard copy to be skipped for non-default output path")
	}
	if commandCalled {
		t.Fatal("pbcopy should not be invoked for skipped cases")
	}
}

func TestClipboardHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_CLIPBOARD_HELPER") != "1" {
		return
	}

	if len(os.Args) < 4 || os.Args[3] != "pbcopy" {
		os.Exit(2)
	}

	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		os.Exit(1)
	}

	if err := os.WriteFile(os.Getenv("GO_CLIPBOARD_CAPTURE_PATH"), data, 0644); err != nil {
		os.Exit(1)
	}

	os.Exit(0)
}
