package deploy

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/logger"
)

type Substore struct {
	Config       *config.Config
	SSKey        string
	substorePath string
}

func NewSubstore(cfg *config.Config, ssKey string) *Substore {
	return &Substore{
		Config: cfg, SSKey: ssKey, substorePath: constant.SubStoreFile,
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
	if err := os.MkdirAll(constant.SubStoreDir, 0755); err != nil {
		return fmt.Errorf("failed to create %s: %w", constant.SubStoreDir, err)
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
		"-v", fmt.Sprintf("%s:/opt/app/data", constant.SubStoreDir),
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
	sbDomain := sb.Config.Server.SBDomain
	logger.Success("Sub-Store deployed successfully!")
	fmt.Println("\n========================================================")
	fmt.Println("🔒 Sub-Store Admin Access URL:")
	fmt.Printf("https://%s?api=https://%s/%s\n", sbDomain, sbDomain, sb.SSKey)
	fmt.Println("========================================================")
}

func UninstallSubstore() error {
	logger.Info("Uninstalling Sub-Store...")

	// Remove the container
	err := runCmd("docker", "rm", "-f", "sub-store")
	if err != nil {
		logger.Warn("Failed to remove sub-store container (it might not exist): %v", err)
	}

	// Remove the volume directory
	err = runCmd("rm", "-rf", constant.SubStoreDir)
	if err != nil {
		return fmt.Errorf("failed to remove %s: %w", constant.SubStoreDir, err)
	}

	logger.Success("Sub-Store uninstallation completed.")
	return nil
}

// UpdateSubstoreConfig updates the sub-store.json file with Hysteria 2 and optionally VLESS+Reality subscriptions.
func (sb *Substore) UpdateSubstoreConfig(sbs *SingBoxServer) error {
	// 1. Backup existing config if it exists
	filePath := sb.substorePath
	if _, err := os.Stat(filePath); err == nil {
		backupPath := filePath + ".bak"
		input, err := os.ReadFile(filePath)
		if err == nil {
			if err := os.WriteFile(backupPath, input, 0644); err == nil {
				logger.Info("Backed up config to %s", backupPath)
			} else {
				logger.Warn("Warning: Failed to create backup: %v", err)
			}
		}
	}

	// 2. Load existing config or create default structure
	var config map[string]interface{}
	data, err := os.ReadFile(filePath)
	if err == nil && len(data) > 0 {
		if err := json.Unmarshal(data, &config); err != nil {
			logger.Warn("Error decoding JSON from %s, starting with empty config.", filePath)
			config = make(map[string]interface{})
		}
	} else {
		logger.Info("File %s not found, initializing new config.", filePath)
		config = make(map[string]interface{})
	}

	// 3. Ensure arrays exist
	var subs []interface{}
	if existingSubs, ok := config["subs"].([]interface{}); ok {
		subs = existingSubs
	}

	var collections []interface{}
	if existingCols, ok := config["collections"].([]interface{}); ok {
		collections = existingCols
	}

	// 4. Add subscriptions
	var addedSubs []string

	hyURI := sbs.ShareLinkHy2
	subs = addOrUpdateSub(subs, "auto_generated_hy2", "Hysteria2 Auto", hyURI, "Auto-generated Hysteria 2 Subscription")
	addedSubs = append(addedSubs, "auto_generated_hy2")

	subs = addOrUpdateSub(subs, "auto_generated_vless", "VLESS Reality Auto", sbs.ShareLinkVless, "Auto-generated VLESS+Reality Subscription")
	addedSubs = append(addedSubs, "auto_generated_vless")

	config["subs"] = subs

	// 5. Update collections
	config["collections"] = addToCollection(collections, addedSubs)

	// 6. Write back to file
	outData, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(filePath, outData, 0644); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	logger.Info("Successfully updated %s", filePath)
	return nil
}

// Helper to add or update a subscription in the sub-store array
func addOrUpdateSub(subs []interface{}, targetName, displayName, contentURI, remark string) []interface{} {
	newSub := map[string]interface{}{
		"name":                  targetName,
		"displayName":           displayName,
		"form":                  "",
		"remark":                remark,
		"mergeSources":          "",
		"ignoreFailedRemoteSub": false,
		"passThroughUA":         false,
		"icon":                  "",
		"isIconColor":           true,
		"process": []interface{}{
			map[string]interface{}{
				"type": "Quick Setting Operator",
				"args": map[string]interface{}{
					"useless":    "DISABLED",
					"udp":        "DEFAULT",
					"scert":      "DEFAULT",
					"tfo":        "DEFAULT",
					"vmess aead": "DEFAULT",
				},
			},
		},
		"source":           "local",
		"url":              "",
		"content":          contentURI,
		"ua":               "",
		"tag":              []interface{}{},
		"subscriptionTags": []interface{}{},
		"display-name":     displayName,
	}

	found := false
	for i, v := range subs {
		if sub, ok := v.(map[string]interface{}); ok {
			if name, ok := sub["name"].(string); ok && name == targetName {
				subs[i] = newSub
				found = true
				logger.Info("Updated existing subscription: %s", targetName)
				break
			}
		}
	}

	if !found {
		subs = append(subs, newSub)
		logger.Info("Added new subscription: %s", targetName)
	}

	return subs
}

// Helper to add the subscription names to the "all" or "Auto" collection
func addToCollection(collections []interface{}, subNames []string) []interface{} {
	targetCollection := "all"
	collectionFound := false

	for _, v := range collections {
		if col, ok := v.(map[string]interface{}); ok {
			if name, ok := col["name"].(string); ok && name == targetCollection {
				var subs []interface{}
				if existingSubs, ok := col["subscriptions"].([]interface{}); ok {
					subs = existingSubs
				}
				for _, subName := range subNames {
					if !containsStr(subs, subName) {
						subs = append(subs, subName)
						logger.Info("Added %s to collection %s", subName, targetCollection)
					}
				}
				col["subscriptions"] = subs
				collectionFound = true
				break
			}
		}
	}

	if !collectionFound {
		autoColName := "Auto"
		autoColFound := false
		for _, v := range collections {
			if col, ok := v.(map[string]interface{}); ok {
				if name, ok := col["name"].(string); ok && name == autoColName {
					var subs []interface{}
					if existingSubs, ok := col["subscriptions"].([]interface{}); ok {
						subs = existingSubs
					}
					for _, subName := range subNames {
						if !containsStr(subs, subName) {
							subs = append(subs, subName)
							logger.Info("Added %s to collection %s", subName, autoColName)
						}
					}
					col["subscriptions"] = subs
					autoColFound = true
					break
				}
			}
		}

		if !autoColFound {
			logger.Info("Creating new collection: %s", autoColName)
			var subs []interface{}
			for _, s := range subNames {
				subs = append(subs, s)
			}
			newCol := map[string]interface{}{
				"name":          autoColName,
				"displayName":   autoColName,
				"subscriptions": subs,
			}
			collections = append(collections, newCol)
		}
	}

	return collections
}

// Helper to check if an array of interface{} contains a specific string
func containsStr(list []interface{}, target string) bool {
	for _, v := range list {
		if s, ok := v.(string); ok && s == target {
			return true
		}
	}
	return false
}
