package deploy

import (
	"singctl/internal/logger"
)

// DeployWarp installs wireproxy using the fscarmen script
func DeployWarp() error {
	logger.Info("Starting WARP (wireproxy) deployment via script...")
	if err := runEmbeddedScript("install_warp.sh"); err != nil {
		return err
	}
	logger.Success("WARP deployment script finished.")
	return nil
}
