package deploy

import (
	"fmt"
	"singctl/internal/logger"
)

// UninstallWarp uninstalls WARP (wireproxy)
func UninstallWarp() error {
	logger.Info("Uninstalling WARP (wireproxy)...")
	if err := runEmbeddedScript("uninstall_warp.sh"); err != nil {
		return fmt.Errorf("warp uninstallation failed: %w", err)
	}
	logger.Success("WARP uninstallation completed.")
	return nil
}

// DeployWarp installs wireproxy using the fscarmen script
func DeployWarp() error {
	logger.Info("Starting WARP (wireproxy) deployment via script...")
	if err := runEmbeddedScript("install_warp.sh"); err != nil {
		return err
	}
	logger.Success("WARP deployment script finished.")
	return nil
}
