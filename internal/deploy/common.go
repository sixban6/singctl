package deploy

import (
	"fmt"
	"os/exec"

	"singctl/internal/logger"
)

// DeployCommon env initializes base environment (UFW, sysctl)
func DeployCommon() error {
	logger.Info("Running common deployment script...")
	if err := runEmbeddedScript("deploy_common.sh"); err != nil {
		return err
	}
	logger.Success("Common deployment script finished.")
	return nil
}

// runCmd wrapper to run command and pipe standard outputs
func runCmd(name string, arg ...string) error {
	cmd := exec.Command(name, arg...)
	// For production, we might want to suppress some outputs, but for transparency we can pipe them.
	// We'll capture output in case of error.
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("command execution failed (%s %v): %v, output: %s", name, arg, err, string(out))
	}
	return nil
}
