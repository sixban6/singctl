package deploy

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"singctl/internal/logger"
)

// DeploySubstore handles Docker installation, password generation, and sub-store container rotation
func DeploySubstore() error {
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

	// 6. Print Admin URL
	logger.Success("Sub-Store deployed successfully!")
	fmt.Println("\n========================================================")
	fmt.Println("🔒 Sub-Store Admin Access URL:")
	fmt.Printf("https://[YOUR_SB_DOMAIN_HERE]:9443/%s\n", ssKey)
	fmt.Println("========================================================")

	return nil
}
