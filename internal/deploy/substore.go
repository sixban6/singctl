package deploy

import (
	"fmt"
	"os"
	"os/exec"
	"singctl/internal/config"
	"strings"

	"singctl/internal/logger"
)

type Substore struct {
	Config *config.Config
	SSKey  string
}

func NewSubstore(cfg *config.Config, ssKey string) *Substore {
	return &Substore{
		Config: cfg, SSKey: ssKey,
	}
}

// DeploySubstore handles Docker installation, password generation, and sub-store container rotation
func (sb *Substore) DeploySubstore() error {
	logger.Info("Starting Sub-Store deployment...")

	// 1. Install Docker if not present
	if _, err := exec.LookPath("docker"); err != nil {
		logger.Info("Docker not found. Installing via get.docker.com...")

		installScript := `curl -fsSL https://get.docker.com | bash -s docker`
		cmd := exec.Command("bash", "-c", installScript)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to install docker: %v, output: %s", err, string(out))
		}
	} else {
		logger.Info("Docker is already installed.")
	}

	// 2. Ensure /etc/sub-store directory exists for volumes
	if err := os.MkdirAll("/etc/sub-store", 0755); err != nil {
		return fmt.Errorf("failed to create /etc/sub-store: %w", err)
	}

	// 3. Generate a new random password
	logger.Info("Generating new random key for Sub-Store...")
	randCmd := exec.Command("sing-box", "generate", "rand", "13", "--hex")
	out, err := randCmd.Output()
	if err != nil {
		return fmt.Errorf("failed to generate random string: %w", err)
	}
	ssKey := strings.TrimSpace(string(out))
	sb.SSKey = ssKey
	// 4. Remove old container if it exists
	logger.Info("Removing old sub-store container (if exists)...")
	_ = runCmd("docker", "rm", "-f", "sub-store")

	// 5. Run new container
	logger.Info("Starting new sub-store container...")
	runArgs := []string{
		"run", "-it", "-d",
		"--restart=always",
		"-e", "SUB_STORE_CRON=50 23 * * *",
		"-e", fmt.Sprintf("SUB_STORE_FRONTEND_BACKEND_PATH=/%s", ssKey),
		"-p", "127.0.0.1:3001:3001",
		"-v", "/etc/sub-store:/opt/app/data",
		"--name", "sub-store",
		"xream/sub-store",
	}

	if err := runCmd("docker", runArgs...); err != nil {
		return fmt.Errorf("failed to run sub-store docker container: %w", err)
	}

	return nil
}

func (sb *Substore) ShowLoginInfo() {
	// 6. Print Admin URL
	logger.Success("Sub-Store deployed successfully!")
	fmt.Println("\n========================================================")
	fmt.Println("🔒 Sub-Store Admin Access URL:")
	fmt.Printf("https://%s:9443/%s\n", sb.Config.Server.SBDomain, sb.SSKey)
	fmt.Println("========================================================")
}

func (sb *Substore) UninstallSubstore() error {
	logger.Info("Uninstalling Sub-Store...")

	// Remove the container
	err := runCmd("docker", "rm", "-f", "sub-store")
	if err != nil {
		logger.Warn("Failed to remove sub-store container (it might not exist): %v", err)
	}

	// Remove the volume directory
	err = runCmd("rm", "-rf", "/etc/sub-store")
	if err != nil {
		return fmt.Errorf("failed to remove /etc/sub-store: %w", err)
	}

	logger.Success("Sub-Store uninstallation completed.")
	return nil
}
