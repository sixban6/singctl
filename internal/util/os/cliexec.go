package osutil

import (
	"bytes"
	"fmt"
	"os/exec"
)

// RunCommand executes a command, capturing standard output and standard error.
// If the command fails, the Stderr is wrapped into the returned error for better observability.
func RunCommand(name string, arg ...string) error {
	cmd := exec.Command(name, arg...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		errStr := stderr.String()
		if len(errStr) > 500 { // Limit output length to avoid unreadable massive errors
			errStr = errStr[:500] + "..."
		}
		if errStr == "" {
			errStr = "<no stderr output>"
		}
		return fmt.Errorf("command [%s %v] failed: %w, stderr: %s", name, arg, err, errStr)
	}
	return nil
}

// RunCommandWithOutput is like RunCommand but it also returns the stdout.
func RunCommandWithOutput(name string, arg ...string) ([]byte, error) {
	cmd := exec.Command(name, arg...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	out, err := cmd.Output()
	if err != nil {
		errStr := stderr.String()
		if len(errStr) > 500 {
			errStr = errStr[:500] + "..."
		}
		if errStr == "" {
			errStr = "<no stderr output>"
		}
		return nil, fmt.Errorf("command [%s %v] failed: %w, stderr: %s", name, arg, err, errStr)
	}
	return out, nil
}
