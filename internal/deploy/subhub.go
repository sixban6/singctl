package deploy

import (
	"encoding/json"
	"fmt"
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

	logger.Success("Native SubHub subscription engine deployed on %s.", subhub.DefaultListenAddr)
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

func UninstallSubstore() error {
	logger.Info("Uninstalling SubHub subscription service...")
	if err := subhub.UninstallService(true); err != nil {
		return err
	}
	logger.Success("SubHub uninstallation completed.")
	return nil
}

// UpdateSubstoreConfig delegates sub-store.json persistence to subhub.Store's strongly-typed API.
func (sb *Substore) UpdateSubstoreConfig(sbs *SingBoxServer) error {
	filePath := sb.getSubstorePath()
	if filePath == "" {
		return fmt.Errorf("sub-store file path is empty")
	}
	if sbs == nil {
		return fmt.Errorf("sing-box server instance is nil")
	}

	nodeDomain := ""
	if sbs.cfg != nil {
		nodeDomain = sbs.cfg.Server.GetNodeDomain()
	}

	st := subhub.NewStore(filepath.Dir(filePath), filePath)
	if err := st.SyncAutoServerNodes(subhub.SyncServerNodesInput{
		NodeDomain: nodeDomain,
		Hy2URI:     sbs.ShareLinkHy2,
		Hy2Tag:     sbs.hy2Tag,
		VlessURI:   sbs.ShareLinkVless,
		VrTag:      sbs.vrTag,
	}); err != nil {
		return err
	}

	logger.Info("Successfully updated %s", filePath)

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

// MergeNodeContent merges a new node URI into the existing multi-line subscription content,
// delegating to subhub.MergeServerNodeContent for single-source-of-truth behavior.
func MergeNodeContent(existingContent, newURI string, sbs *SingBoxServer, expectedScheme string) string {
	var domain, targetTag string
	if sbs != nil {
		if sbs.cfg != nil {
			domain = sbs.cfg.Server.GetNodeDomain()
		}
		switch expectedScheme {
		case "hysteria2":
			targetTag = sbs.hy2Tag
		case "vless":
			targetTag = sbs.vrTag
		}
	}
	return subhub.MergeServerNodeContent(existingContent, newURI, domain, targetTag, expectedScheme)
}

// AddToCollection preserves backward compatibility for external callers/tests by delegating
// legacy collection normalization to subhub.ReconcileAllCollection.
func AddToCollection(collections []any, subNames []string) []any {
	raw, err := json.Marshal(collections)
	if err != nil {
		return collections
	}
	var typed []struct {
		Name          string   `json:"name"`
		DisplayName   string   `json:"displayName"`
		Subscriptions []string `json:"subscriptions"`
	}
	if err := json.Unmarshal(raw, &typed); err != nil {
		return collections
	}

	var out []any
	foundAll := false
	for _, col := range typed {
		if col.Name == "Auto" {
			continue
		}
		subs := col.Subscriptions
		if col.Name == subhub.DefaultCollectionName {
			foundAll = true
			for _, sn := range subNames {
				has := false
				for _, cur := range subs {
					if cur == sn {
						has = true
						break
					}
				}
				if !has {
					subs = append(subs, sn)
				}
			}
		}
		anySubs := make([]any, len(subs))
		for i, s := range subs {
			anySubs[i] = s
		}
		out = append(out, map[string]any{
			"name":          col.Name,
			"displayName":   col.DisplayName,
			"subscriptions": anySubs,
		})
	}
	if !foundAll {
		anySubs := make([]any, len(subNames))
		for i, s := range subNames {
			anySubs[i] = s
		}
		out = append(out, map[string]any{
			"name":          subhub.DefaultCollectionName,
			"displayName":   subhub.DefaultCollectionName,
			"subscriptions": anySubs,
		})
	}
	return out
}
