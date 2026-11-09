package deploy

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/logger"
	"singctl/internal/subhub"
)

type Substore struct {
	Config       *config.Config
	ConfigPath   string
	SSKey        string
	SubstorePath string
	substorePath string
	SkipRestart  bool
}

func NewSubstore(cfg *config.Config, ssKey string) *Substore {
	return &Substore{
		Config:       cfg,
		SSKey:        ssKey,
		substorePath: constant.SubStoreFile,
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

// DeploySubstore initializes the subscription key, installs/starts the native Go SubHub service (singctl-sub),
// and reloads Caddy routes.
func (sb *Substore) DeploySubstore() error {
	logger.Info("Deploying native SubHub subscription aggregation engine...")

	if err := os.MkdirAll(constant.SubStoreDir, 0755); err != nil {
		return fmt.Errorf("failed to create %s: %w", constant.SubStoreDir, err)
	}

	st := subhub.NewStore(constant.SubStoreDir, sb.getSubstorePath())
	ssKey := strings.TrimSpace(sb.SSKey)
	if ssKey != "" {
		if err := os.WriteFile(filepath.Join(constant.SubStoreDir, "key"), []byte(ssKey), 0600); err != nil {
			return fmt.Errorf("failed to persist subscription key: %w", err)
		}
	} else {
		var err error
		ssKey, err = st.EnsureKey()
		if err != nil {
			return fmt.Errorf("failed to initialize subscription key: %w", err)
		}
	}
	sb.SSKey = ssKey

	if err := subhub.InstallService(sb.ConfigPath); err != nil {
		return fmt.Errorf("failed to install singctl-sub service: %w", err)
	}

	// Reload Caddy so its @subhub route immediately recognizes ssKey
	if sb.Config != nil {
		if err := SyncCaddyfile(sb.Config); err != nil {
			logger.Warn("Caddy reload warning after SubHub deploy: %v", err)
		}
	}

	logger.Success("Native SubHub subscription engine deployed on 127.0.0.1:3001.")
	return nil
}

// GetSubstoreKey retrieves the persisted subscription secret path key.
func (sb *Substore) GetSubstoreKey() (string, error) {
	if sb.SSKey != "" {
		return sb.SSKey, nil
	}

	keyFile := filepath.Join(constant.SubStoreDir, "key")
	if data, err := os.ReadFile(keyFile); err == nil {
		if key := strings.TrimSpace(string(data)); key != "" {
			sb.SSKey = key
			return key, nil
		}
	}

	return "", fmt.Errorf("subscription key not found in %s", keyFile)
}

// GetAdminURL returns the built-in SingCtl Server UI URL where subscriptions are managed natively.
func (sb *Substore) GetAdminURL() (string, error) {
	if sb.Config == nil {
		return "", fmt.Errorf("server config is nil")
	}
	domain := sb.Config.Server.GetSubstoreDomain()
	if domain == "" {
		domain = sb.Config.Server.GetNodeDomain()
	}
	adminPath := sb.Config.Server.GetWebAdminPath()
	if domain == "" || adminPath == "" {
		return "", fmt.Errorf("server domain or web_admin.path is not configured")
	}
	return fmt.Sprintf("https://%s%s/", domain, adminPath), nil
}

// GetSubscriptionURL returns the primary aggregated subscription link compatible with all clients.
func (sb *Substore) GetSubscriptionURL() string {
	key, err := sb.GetSubstoreKey()
	sbDomain := ""
	if sb.Config != nil {
		sbDomain = sb.Config.Server.GetSubstoreDomain()
		if sbDomain == "" {
			sbDomain = sb.Config.Server.GetNodeDomain()
		}
	}
	if sbDomain == "" {
		return ""
	}
	if err == nil && key != "" {
		return fmt.Sprintf("https://%s/%s/download/collection/all", sbDomain, key)
	}
	return fmt.Sprintf("https://%s/download/collection/all", sbDomain)
}

func (sb *Substore) ShowLoginInfo() {
	subURL := sb.GetSubscriptionURL()
	adminURL, _ := sb.GetAdminURL()
	logger.Success("SubHub native subscription engine is ready!")
	fmt.Println("\n========================================================")
	fmt.Println("📦 SubHub 聚合订阅中心:")
	if subURL != "" {
		fmt.Printf("• 全平台聚合订阅链接:\n  %s\n", subURL)
	}
	if adminURL != "" {
		fmt.Printf("• 内置管理面板 (添加外部订阅 / 预览配置 / 轮换密钥):\n  %s\n", adminURL)
	}
	fmt.Println("========================================================")
}

func UninstallSubstore() error {
	logger.Info("Uninstalling SubHub subscription service...")
	if err := subhub.UninstallService(true); err != nil {
		return err
	}
	logger.Success("SubHub uninstallation completed.")
	return nil
}

// UpdateSubstoreConfig updates sub-store.json with Hysteria 2 and VLESS+Reality subscriptions.
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
			if err := os.WriteFile(backupPath, input, 0600); err == nil {
				logger.Info("Backed up config to %s", backupPath)
			} else {
				logger.Warn("Warning: Failed to create backup: %v", err)
			}
		}
	}

	// 2. Load existing config or create default structure
	var doc map[string]any
	data, err := os.ReadFile(filePath)
	if err == nil && len(data) > 0 {
		if err := json.Unmarshal(data, &doc); err != nil {
			logger.Warn("Error decoding JSON from %s, starting with empty config.", filePath)
			doc = make(map[string]any)
		}
	} else {
		logger.Info("File %s not found, initializing new config.", filePath)
		doc = make(map[string]any)
	}

	// 3. Ensure arrays exist
	var subs []any
	if existingSubs, ok := doc["subs"].([]any); ok {
		subs = existingSubs
	}

	var collections []any
	if existingCols, ok := doc["collections"].([]any); ok {
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
	var cleanedSubs []any
	seenSubNames := make(map[string]bool)
	for _, s := range subs {
		if subObj, ok := s.(map[string]any); ok {
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

	doc["subs"] = subs

	// 5. Update collections
	collections = AddToCollection(collections, addedSubs)
	existingSubNames := make(map[string]bool)
	for _, s := range subs {
		if subObj, ok := s.(map[string]any); ok {
			if name, ok := subObj["name"].(string); ok && name != "" {
				existingSubNames[name] = true
			}
		}
	}
	for _, v := range collections {
		if col, ok := v.(map[string]any); ok {
			if existingSubs, ok := col["subscriptions"].([]any); ok {
				var cleaned []any
				for _, subName := range existingSubs {
					if name, ok := subName.(string); ok && existingSubNames[name] {
						cleaned = append(cleaned, name)
					}
				}
				col["subscriptions"] = cleaned
			}
		}
	}
	doc["collections"] = collections

	// 6. Write back to file
	outData, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(filePath, outData, 0600); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	logger.Info("Successfully updated %s", filePath)

	// SubHub automatically reloads sub-store.json on mtime change, and RestartSubstore
	// ensures service restarts cleanly if explicitly requested.
	if !sb.SkipRestart {
		if err := sb.RestartSubstore(); err != nil {
			logger.Warn("Failed to restart singctl-sub service (non-fatal): %v", err)
		}
	}

	return nil
}

// RestartSubstore restarts the native singctl-sub daemon if installed.
func (sb *Substore) RestartSubstore() error {
	return subhub.RestartService()
}

// Helper to add or update a subscription in the sub-store array
func addOrUpdateSub(subs []any, targetName, displayName, contentURI, remark string, sbs *SingBoxServer, protocol string) []any {
	newSub := map[string]any{
		"name":                  targetName,
		"displayName":           displayName,
		"form":                  "",
		"remark":                remark,
		"mergeSources":          "",
		"ignoreFailedRemoteSub": false,
		"passThroughUA":         false,
		"icon":                  "",
		"isIconColor":           true,
		"source":                "local",
		"url":                   "",
		"content":               contentURI,
		"ua":                    "",
		"tag":                   []any{},
		"subscriptionTags":      []any{},
		"display-name":          displayName,
	}

	found := false
	for i, v := range subs {
		if sub, ok := v.(map[string]any); ok {
			if name, ok := sub["name"].(string); ok && name == targetName {
				existingContent, _ := sub["content"].(string)
				sub["content"] = MergeNodeContent(existingContent, contentURI, sbs, protocol)
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

// mergeNodeContent merges a new node URI into the existing multi-line subscription content.
// It replaces any node belonging to the current VPS while preserving nodes from other VPSs.
// Duplicate lines are strictly filtered out to prevent identical nodes.
func MergeNodeContent(existingContent, newURI string, sbs *SingBoxServer, expectedScheme string) string {
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
		} else {
			resultLines = append(resultLines, line)
		}
	}

	if !replaced {
		resultLines = append(resultLines, newURI)
	}

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
			sni := strings.ToLower(u.Query().Get("sni"))
			if sni == currentDomain && targetTag != "" && u.Fragment == targetTag {
				return true
			}
		}

		if targetTag != "" && u.Fragment == targetTag {
			return true
		}
	}

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

// addToCollection adds subscription names to the "all" collection and cleans up legacy "Auto" collection.
func AddToCollection(collections []any, subNames []string) []any {
	targetCollection := "all"
	collectionFound := false

	var cleanedCols []any
	for _, v := range collections {
		if col, ok := v.(map[string]any); ok {
			name, _ := col["name"].(string)
			if name == "Auto" {
				logger.Info("Removing legacy duplicate collection: Auto")
				continue
			}
			if name == targetCollection {
				var subs []any
				if existingSubs, ok := col["subscriptions"].([]any); ok {
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

	if !collectionFound {
		logger.Info("Creating new collection: %s", targetCollection)
		subs := make([]any, 0, len(subNames))
		for _, s := range subNames {
			subs = append(subs, s)
		}
		newCol := map[string]any{
			"name":          targetCollection,
			"displayName":   targetCollection,
			"subscriptions": subs,
		}
		collections = append(collections, newCol)
	}

	return collections
}

func containsStr(list []any, target string) bool {
	for _, v := range list {
		if s, ok := v.(string); ok && s == target {
			return true
		}
	}
	return false
}
