package deploy

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/logger"
)

type Substore struct {
	Config       *config.Config
	SSKey        string
	SubstorePath string
	substorePath string
	SkipRestart  bool
}

func NewSubstore(cfg *config.Config, ssKey string) *Substore {
	return &Substore{
		Config: cfg, SSKey: ssKey, substorePath: constant.SubStoreFile,
	}
}

func (sb *Substore) getSubstorePath() string {
	if sb.SubstorePath != "" {
		return sb.SubstorePath
	}
	if sb.substorePath != "" {
		return sb.substorePath
	}
	return constant.SubStoreFile
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

	// 3. Obtain existing key or generate a new random key
	keyFile := filepath.Join(constant.SubStoreDir, "key")
	ssKey := sb.SSKey
	if ssKey == "" {
		if data, err := os.ReadFile(keyFile); err == nil && len(strings.TrimSpace(string(data))) > 0 {
			ssKey = strings.TrimSpace(string(data))
			logger.Info("Reusing existing Sub-Store key...")
		} else {
			logger.Info("Generating new random key for Sub-Store...")
			var err error
			ssKey, err = generateHexRandom(13)
			if err != nil {
				return fmt.Errorf("failed to generate random string: %w", err)
			}
		}
	}
	sb.SSKey = ssKey
	_ = os.WriteFile(keyFile, []byte(ssKey), 0600)

	// 4. Remove old container if it exists
	logger.Info("Removing old sub-store container (if exists)...")
	_ = runCmd("docker", "rm", "-f", "sub-store")

	// 5. Run new container
	logger.Info("Starting new sub-store container...")
	corsOrigins := sb.getCorsAllowedOrigins()
	runArgs := []string{
		"run", "-it", "-d",
		"--restart=always",
		"-e", "SUB_STORE_CRON=50 23 * * *",
		"-e", fmt.Sprintf("SUB_STORE_FRONTEND_BACKEND_PATH=/%s", ssKey),
		"-e", fmt.Sprintf("SUB_STORE_CORS_ALLOWED_ORIGINS=%s", corsOrigins),
		"-p", "127.0.0.1:3001:3001",
		"-v", fmt.Sprintf("%s:/opt/app/data", constant.SubStoreDir),
		"--name", "sub-store",
		"xream/sub-store",
	}

	if err := runCmd("docker", runArgs...); err != nil {
		return fmt.Errorf("failed to run sub-store docker container: %w", err)
	}

	// Reload Caddy so its @substore route immediately recognizes the ssKey
	if sb.Config != nil {
		if err := renderCaddyfile(sb.Config); err == nil {
			_ = RestartCaddy()
		}
	}

	return nil
}

func (sb *Substore) getCorsAllowedOrigins() string {
	var origins []string
	seen := make(map[string]bool)

	add := func(origin string) {
		origin = strings.TrimSpace(origin)
		if origin != "" && !seen[origin] {
			seen[origin] = true
			origins = append(origins, origin)
		}
	}

	// 1. Configured server domains
	if sb.Config != nil {
		if domain := strings.TrimSpace(sb.Config.Server.GetSubstoreDomain()); domain != "" {
			add(fmt.Sprintf("https://%s", domain))
			add(fmt.Sprintf("http://%s", domain))
		}
		if domain := strings.TrimSpace(sb.Config.Server.GetNodeDomain()); domain != "" {
			add(fmt.Sprintf("https://%s", domain))
			add(fmt.Sprintf("http://%s", domain))
		}
		if extra := strings.TrimSpace(sb.Config.Server.CorsAllowedOrigins); extra != "" {
			for _, part := range strings.Split(extra, ",") {
				add(part)
			}
		}
	}

	// 2. Official / standard frontend origins
	add("https://sub-store.vercel.app")
	add("http://substore.stash")
	add("https://substore.stash")

	// 3. Local loopback origins
	add("http://127.0.0.1")
	add("http://127.0.0.1:3001")
	add("http://localhost")
	add("http://localhost:3001")

	return strings.Join(origins, ",")
}

// GetSubstoreKey retrieves the existing Sub-Store frontend/backend path key.
// It first checks the persisted key file in /etc/sub-store/key, and if not present,
// inspects the running Docker container's environment variables.
func (sb *Substore) GetSubstoreKey() (string, error) {
	if sb.SSKey != "" {
		return sb.SSKey, nil
	}

	keyFile := filepath.Join(constant.SubStoreDir, "key")
	if data, err := os.ReadFile(keyFile); err == nil {
		key := strings.TrimSpace(string(data))
		if key != "" {
			sb.SSKey = key
			return key, nil
		}
	}

	// Fallback to inspecting Docker container
	if _, err := exec.LookPath("docker"); err == nil {
		out, err := exec.Command("docker", "inspect", "--format", "{{range .Config.Env}}{{println .}}{{end}}", "sub-store").Output()
		if err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "SUB_STORE_FRONTEND_BACKEND_PATH=") {
					raw := strings.TrimPrefix(line, "SUB_STORE_FRONTEND_BACKEND_PATH=")
					key := strings.TrimPrefix(raw, "/")
					if key != "" {
						sb.SSKey = key
						_ = os.WriteFile(keyFile, []byte(key), 0600)
						return key, nil
					}
				}
			}
		}
	}

	return "", fmt.Errorf("sub-store key not found (sub-store may not be deployed or running)")
}

// GetAdminURL returns the complete Sub-Store admin login URL for the self-hosted frontend.
func (sb *Substore) GetAdminURL() (string, error) {
	key, err := sb.GetSubstoreKey()
	if err != nil {
		return "", err
	}
	sbDomain := ""
	if sb.Config != nil {
		sbDomain = sb.Config.Server.GetSubstoreDomain()
	}
	if sbDomain == "" {
		return "", fmt.Errorf("server.substore_domain (or sb_domain) is not configured")
	}
	return fmt.Sprintf("https://%s?api=https://%s/%s", sbDomain, sbDomain, key), nil
}

// GetVercelAdminURL returns the official Sub-Store Web UI URL pointed to this backend.
func (sb *Substore) GetVercelAdminURL() (string, error) {
	key, err := sb.GetSubstoreKey()
	if err != nil {
		return "", err
	}
	sbDomain := ""
	if sb.Config != nil {
		sbDomain = sb.Config.Server.GetSubstoreDomain()
	}
	if sbDomain == "" {
		return "", fmt.Errorf("server.substore_domain (or sb_domain) is not configured")
	}
	return fmt.Sprintf("https://sub-store.vercel.app?api=https://%s/%s", sbDomain, key), nil
}

func (sb *Substore) ShowLoginInfo() {
	adminURL, err := sb.GetAdminURL()
	if err != nil {
		logger.Warn("Failed to get Sub-Store login URL: %v", err)
		return
	}
	vercelURL, _ := sb.GetVercelAdminURL()
	logger.Success("Sub-Store deployed successfully!")
	fmt.Println("\n========================================================")
	fmt.Println("🔒 Sub-Store Admin Access URLs:")
	if vercelURL != "" {
		fmt.Printf("• 官方 Web UI (推荐 / 免 CDN 缓存影响):\n  %s\n", vercelURL)
	}
	fmt.Printf("• 自建独立域名前端 (若遇白屏需在 Cloudflare 清除缓存):\n  %s\n", adminURL)
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
	filePath := sb.getSubstorePath()
	if filePath == "" {
		return fmt.Errorf("sub-store file path is empty")
	}

	if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil {
		return fmt.Errorf("failed to create directory for sub-store config: %w", err)
	}

	// 1. Backup existing config if it exists
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
	subs = addOrUpdateSub(subs, "auto_generated_hy2", "Hysteria2 Auto", hyURI, "Auto-generated Hysteria 2 Subscription", sbs, "hysteria2")
	addedSubs = append(addedSubs, "auto_generated_hy2")

	subs = addOrUpdateSub(subs, "auto_generated_vless", "VLESS Reality Auto", sbs.ShareLinkVless, "Auto-generated VLESS+Reality Subscription", sbs, "vless")
	addedSubs = append(addedSubs, "auto_generated_vless")

	// Clean up deprecated protocols (TUIC, AnyTLS) and deduplicate subscriptions by name
	var cleanedSubs []interface{}
	seenSubNames := make(map[string]bool)
	for _, s := range subs {
		if subObj, ok := s.(map[string]interface{}); ok {
			name, _ := subObj["name"].(string)
			if name == "auto_generated_tuic" || name == "auto_generated_anytls" {
				logger.Info("Removing deprecated subscription: %s", name)
				continue
			}
			if name != "" {
				if seenSubNames[name] {
					logger.Info("Removing duplicate subscription: %s", name)
					continue
				}
				seenSubNames[name] = true
			}
		}
		cleanedSubs = append(cleanedSubs, s)
	}
	subs = cleanedSubs

	config["subs"] = subs

	// 5. Update collections
	collections = addToCollection(collections, addedSubs)
	existingSubNames := make(map[string]bool)
	for _, s := range subs {
		if subObj, ok := s.(map[string]interface{}); ok {
			if name, ok := subObj["name"].(string); ok && name != "" {
				existingSubNames[name] = true
			}
		}
	}
	for _, v := range collections {
		if col, ok := v.(map[string]interface{}); ok {
			if existingSubs, ok := col["subscriptions"].([]interface{}); ok {
				var cleaned []interface{}
				for _, subName := range existingSubs {
					if name, ok := subName.(string); ok && existingSubNames[name] {
						cleaned = append(cleaned, name)
					}
				}
				col["subscriptions"] = cleaned
			}
		}
	}
	config["collections"] = collections

	// 6. Write back to file
	outData, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(filePath, outData, 0644); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	logger.Info("Successfully updated %s", filePath)

	// Restart sub-store container if running to reload the config in memory
	if !sb.SkipRestart {
		if err := sb.RestartSubstore(); err != nil {
			logger.Warn("Failed to restart sub-store container (non-fatal): %v", err)
		}
	}

	return nil
}

// RestartSubstore restarts the sub-store container if it is running in Docker,
// allowing it to reload the updated configuration.
func (sb *Substore) RestartSubstore() error {
	if _, err := exec.LookPath("docker"); err != nil {
		return nil
	}
	out, err := exec.Command("docker", "ps", "-q", "-f", "name=^sub-store$").CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to check sub-store container status: %w", err)
	}
	if strings.TrimSpace(string(out)) == "" {
		return nil
	}
	logger.Info("Restarting sub-store container to apply configuration changes...")
	if err := runCmd("docker", "restart", "-t", "2", "sub-store"); err != nil {
		return fmt.Errorf("failed to restart sub-store container: %w", err)
	}
	logger.Success("Sub-Store container restarted successfully.")
	return nil
}

// Helper to add or update a subscription in the sub-store array
func addOrUpdateSub(subs []interface{}, targetName, displayName, contentURI, remark string, sbs *SingBoxServer, protocol string) []interface{} {
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
				existingContent, _ := sub["content"].(string)
				sub["content"] = mergeNodeContent(existingContent, contentURI, sbs, protocol)
				sub["displayName"] = displayName
				sub["display-name"] = displayName
				subs[i] = sub
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

// removeNodeFromSub removes any node belonging to the current VPS from target subscription.
// If the subscription's content becomes completely empty, it is removed from subs.
func removeNodeFromSub(subs []interface{}, targetName string, sbs *SingBoxServer, protocol string) []interface{} {
	var result []interface{}
	for _, v := range subs {
		if sub, ok := v.(map[string]interface{}); ok {
			if name, ok := sub["name"].(string); ok && name == targetName {
				existingContent, _ := sub["content"].(string)
				updatedContent := removeNodeForCurrentServer(existingContent, sbs, protocol)
				if strings.TrimSpace(updatedContent) == "" {
					logger.Info("Removed empty subscription: %s", targetName)
					continue
				}
				sub["content"] = updatedContent
				result = append(result, sub)
				logger.Info("Removed current server node from %s", targetName)
				continue
			}
		}
		result = append(result, v)
	}
	return result
}

// removeNodeForCurrentServer filters out any node lines belonging to the current VPS.
func removeNodeForCurrentServer(existingContent string, sbs *SingBoxServer, expectedScheme string) string {
	rawLines := strings.Split(strings.ReplaceAll(existingContent, "\r\n", "\n"), "\n")
	var resultLines []string
	for _, rawLine := range rawLines {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}
		if !isNodeForCurrentServer(line, sbs, expectedScheme) {
			resultLines = append(resultLines, line)
		}
	}
	return strings.Join(resultLines, "\n")
}

// mergeNodeContent merges a new node URI into the existing multi-line subscription content.
// It replaces any node belonging to the current VPS while preserving nodes from other VPSs.
// If no existing node belongs to the current VPS, the new URI is appended.
// Duplicate lines are strictly filtered out to prevent identical nodes.
func mergeNodeContent(existingContent, newURI string, sbs *SingBoxServer, expectedScheme string) string {
	newURI = strings.TrimSpace(newURI)
	if newURI == "" {
		return existingContent
	}

	rawLines := strings.Split(strings.ReplaceAll(existingContent, "\r\n", "\n"), "\n")
	var resultLines []string
	replaced := false

	for _, rawLine := range rawLines {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}

		if line == newURI || isNodeForCurrentServer(line, sbs, expectedScheme) {
			if !replaced {
				resultLines = append(resultLines, newURI)
				replaced = true
			}
			// Skip duplicate entries for the current server
		} else {
			resultLines = append(resultLines, line)
		}
	}

	if !replaced {
		resultLines = append(resultLines, newURI)
	}

	// Strictly deduplicate lines so no identical node can ever appear more than once
	var finalLines []string
	seen := make(map[string]bool)
	for _, l := range resultLines {
		if !seen[l] {
			seen[l] = true
			finalLines = append(finalLines, l)
		}
	}

	return strings.Join(finalLines, "\n")
}

// isNodeForCurrentServer checks whether a given node URI corresponds to the current VPS.
func isNodeForCurrentServer(nodeURI string, sbs *SingBoxServer, expectedScheme string) bool {
	nodeURI = strings.TrimSpace(nodeURI)
	if nodeURI == "" || sbs == nil || sbs.cfg == nil {
		return false
	}
	currentDomain := strings.ToLower(strings.TrimSpace(sbs.cfg.Server.GetNodeDomain()))
	if currentDomain == "" {
		return false
	}

	targetTag := ""
	switch expectedScheme {
	case "hysteria2":
		targetTag = sbs.hy2Tag
	case "vless":
		targetTag = sbs.vrTag
	}

	u, err := url.Parse(nodeURI)
	if err == nil {
		if u.Scheme != "" && !strings.EqualFold(u.Scheme, expectedScheme) {
			return false
		}

		uHost := strings.ToLower(u.Hostname())
		if uHost != "" {
			if uHost == currentDomain {
				return true
			}
			// Host differs; check if sni query param matches currentDomain
			sni := strings.ToLower(u.Query().Get("sni"))
			if sni == currentDomain && targetTag != "" && u.Fragment == targetTag {
				return true
			}
		}

		if targetTag != "" && u.Fragment == targetTag {
			return true
		}
	}

	// Fallback string matching if url.Parse fails
	lower := strings.ToLower(nodeURI)
	if expectedScheme != "" && !strings.HasPrefix(lower, expectedScheme+"://") {
		return false
	}
	if strings.Contains(lower, "@"+currentDomain+":") ||
		strings.Contains(lower, "@"+currentDomain+"/") ||
		strings.Contains(lower, "@"+currentDomain+"?") {
		return true
	}
	if targetTag != "" && (strings.HasSuffix(nodeURI, "#"+targetTag) || strings.Contains(nodeURI, "#"+targetTag+"?")) {
		return true
	}

	return false
}

// Helper to add the subscription names to the "all" collection (and clean up legacy "Auto" collection to prevent duplicate shared collections)
func addToCollection(collections []interface{}, subNames []string) []interface{} {
	targetCollection := "all"
	collectionFound := false

	// 1. 查找并更新 "all" 集合，同时清理历史遗留的重复 "Auto" 集合
	var cleanedCols []interface{}
	for _, v := range collections {
		if col, ok := v.(map[string]interface{}); ok {
			name, _ := col["name"].(string)
			if name == "Auto" {
				logger.Info("Removing legacy duplicate collection: Auto")
				continue
			}
			if name == targetCollection {
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
			}
			cleanedCols = append(cleanedCols, col)
		} else {
			cleanedCols = append(cleanedCols, v)
		}
	}
	collections = cleanedCols

	// 2. 全新安装或重新部署找不到 all 时，新建出来的集合名称统一叫 "all"
	if !collectionFound {
		logger.Info("Creating new collection: %s", targetCollection)
		var subs []interface{}
		for _, s := range subNames {
			subs = append(subs, s)
		}
		newCol := map[string]interface{}{
			"name":          targetCollection,
			"displayName":   targetCollection,
			"subscriptions": subs,
		}
		collections = append(collections, newCol)
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
