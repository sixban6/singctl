package ssh

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// ManagedHost represents a host entry parsed from ~/.ssh/config.
type ManagedHost struct {
	Name         string
	HostName     string
	User         string
	Port         int
	IdentityFile string
}

// LocalConfigManager manages local ~/.ssh/config idempotently.
type LocalConfigManager struct {
	configPath string
}

// NewLocalConfigManager creates a new LocalConfigManager.
func NewLocalConfigManager(customPath string) *LocalConfigManager {
	if customPath == "" {
		home, err := os.UserHomeDir()
		if err == nil {
			customPath = filepath.Join(home, ".ssh", "config")
		} else {
			customPath = filepath.Clean("~/.ssh/config")
		}
	}
	return &LocalConfigManager{configPath: customPath}
}

// GetConfigPath returns the active ~/.ssh/config file path.
func (m *LocalConfigManager) GetConfigPath() string {
	return m.configPath
}

// SyncHosts updates or appends host entries into ~/.ssh/config without altering other entries.
func (m *LocalConfigManager) SyncHosts(hosts []*Host) error {
	if len(hosts) == 0 {
		return nil
	}

	if err := m.ensureDir(); err != nil {
		return err
	}

	content := ""
	if data, err := os.ReadFile(m.configPath); err == nil {
		content = string(data)
		if strings.TrimSpace(content) != "" {
			_ = m.backupFile(content)
		}
	}

	updatedContent := content
	for _, h := range hosts {
		block := m.renderBlock(h)
		pattern := regexp.MustCompile(fmt.Sprintf(`(?s)# === BEGIN SINGCTL MANAGED HOST: %s ===.*?# === END SINGCTL MANAGED HOST: %s ===\n?`,
			regexp.QuoteMeta(h.Name), regexp.QuoteMeta(h.Name)))

		if pattern.MatchString(updatedContent) {
			// In-place replace
			updatedContent = pattern.ReplaceAllString(updatedContent, block)
		} else {
			// Append at the end
			if updatedContent != "" && !strings.HasSuffix(updatedContent, "\n") {
				updatedContent += "\n"
			}
			updatedContent += block
		}
	}

	// Write back with 0600 permissions
	if err := os.WriteFile(m.configPath, []byte(updatedContent), 0600); err != nil {
		return fmt.Errorf("failed to write ~/.ssh/config: %w", err)
	}

	return nil
}

// ListManagedHosts parses and returns all hosts managed by singctl in ~/.ssh/config.
func (m *LocalConfigManager) ListManagedHosts() ([]ManagedHost, error) {
	data, err := os.ReadFile(m.configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read %s: %w", m.configPath, err)
	}

	content := string(data)
	pattern := regexp.MustCompile(`(?s)# === BEGIN SINGCTL MANAGED HOST: ([^\n]+) ===\n(.*?)\n# === END SINGCTL MANAGED HOST: [^\n]+ ===`)
	matches := pattern.FindAllStringSubmatch(content, -1)

	var list []ManagedHost
	for _, m := range matches {
		name := strings.TrimSpace(m[1])
		body := m[2]

		mh := ManagedHost{Name: name}
		for _, line := range strings.Split(body, "\n") {
			trimmed := strings.TrimSpace(line)
			parts := strings.Fields(trimmed)
			if len(parts) >= 2 {
				switch strings.ToLower(parts[0]) {
				case "hostname":
					mh.HostName = parts[1]
				case "user":
					mh.User = parts[1]
				case "port":
					var p int
					_, _ = fmt.Sscanf(parts[1], "%d", &p)
					mh.Port = p
				case "identityfile":
					mh.IdentityFile = parts[1]
				}
			}
		}
		list = append(list, mh)
	}

	return list, nil
}

// CleanManagedHosts removes singctl managed blocks from ~/.ssh/config.
// If targetName is empty, all singctl managed blocks are removed.
func (m *LocalConfigManager) CleanManagedHosts(targetName string) (int, error) {
	data, err := os.ReadFile(m.configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("failed to read %s: %w", m.configPath, err)
	}

	content := string(data)
	var pattern *regexp.Regexp
	if targetName == "" {
		pattern = regexp.MustCompile(`(?s)# === BEGIN SINGCTL MANAGED HOST: [^\n]+ ===\n.*?\n# === END SINGCTL MANAGED HOST: [^\n]+ ===\n?`)
	} else {
		pattern = regexp.MustCompile(fmt.Sprintf(`(?s)# === BEGIN SINGCTL MANAGED HOST: %s ===\n.*?\n# === END SINGCTL MANAGED HOST: %s ===\n?`,
			regexp.QuoteMeta(targetName), regexp.QuoteMeta(targetName)))
	}

	matches := pattern.FindAllString(content, -1)
	count := len(matches)
	if count == 0 {
		return 0, nil
	}

	_ = m.backupFile(content)

	cleaned := pattern.ReplaceAllString(content, "")
	cleaned = strings.TrimSpace(cleaned)
	if cleaned != "" {
		cleaned += "\n"
	}

	if err := os.WriteFile(m.configPath, []byte(cleaned), 0600); err != nil {
		return 0, fmt.Errorf("failed to write cleaned ~/.ssh/config: %w", err)
	}

	return count, nil
}

func (m *LocalConfigManager) renderBlock(h *Host) string {
	return fmt.Sprintf(`# === BEGIN SINGCTL MANAGED HOST: %s ===
Host %s
    HostName %s
    User %s
    Port %d
    IdentityFile %s
    IdentitiesOnly yes
# === END SINGCTL MANAGED HOST: %s ===
`, h.Name, h.Name, h.IP, h.User, h.TargetPort, h.PrivateKey, h.Name)
}

func (m *LocalConfigManager) ensureDir() error {
	dir := filepath.Dir(m.configPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create ~/.ssh directory %s: %w", dir, err)
	}
	return nil
}

func (m *LocalConfigManager) backupFile(content string) error {
	timestamp := time.Now().Format("20060102_150405")
	backupPath := fmt.Sprintf("%s.bak.%s", m.configPath, timestamp)
	return os.WriteFile(backupPath, []byte(content), 0600)
}
