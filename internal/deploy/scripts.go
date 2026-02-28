package deploy

import (
	"embed"
	"fmt"
	"os"
	"os/exec"
)

//go:embed scripts/*.sh
var scriptFiles embed.FS

// runEmbeddedScript is a helper to run a bash script embedded in the binary
func runEmbeddedScript(scriptName string, args ...string) error {
	content, err := scriptFiles.ReadFile("scripts/" + scriptName)
	if err != nil {
		return fmt.Errorf("read embedded script %s failed: %w", scriptName, err)
	}

	tmpFile, err := os.CreateTemp("", scriptName+"-*")
	if err != nil {
		return fmt.Errorf("create temp file for script failed: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	if err := os.WriteFile(tmpFile.Name(), content, 0755); err != nil {
		return fmt.Errorf("write temp script failed: %w", err)
	}

	cmdArgs := append([]string{tmpFile.Name()}, args...)
	cmd := exec.Command("bash", cmdArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("script execution failed (%s): %w", scriptName, err)
	}
	return nil
}
