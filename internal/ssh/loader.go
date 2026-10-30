package ssh

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	DefaultConfigFile  = "ssh-init.yaml"
	DefaultUser        = "root"
	DefaultCurrentPort = 22
	DefaultTargetPort  = 2222
	DefaultTimeoutSec  = 15
)

// ExpandPath expands leading `~` to the user's home directory.
func ExpandPath(path string) string {
	if path == "" {
		return ""
	}
	if strings.HasPrefix(path, "~/") || path == "~" {
		home, err := os.UserHomeDir()
		if err == nil {
			if path == "~" {
				return home
			}
			return filepath.Join(home, path[2:])
		}
	}
	return path
}

// ResolveConfigFile finds the target configuration file.
// If configPath is empty, it checks "./ssh-init.yaml" first, falling back to "~/ssh-init.yaml".
func ResolveConfigFile(configPath string) (string, error) {
	if configPath != "" {
		cleanPath := filepath.Clean(configPath)
		if _, err := os.Stat(cleanPath); err != nil {
			return "", fmt.Errorf("configuration file '%s' not found: %w", cleanPath, err)
		}
		return cleanPath, nil
	}

	// 1. Current directory
	if _, err := os.Stat(DefaultConfigFile); err == nil {
		return DefaultConfigFile, nil
	}

	// 2. User home directory fallback
	if home, err := os.UserHomeDir(); err == nil {
		homePath := filepath.Join(home, DefaultConfigFile)
		if _, err := os.Stat(homePath); err == nil {
			return homePath, nil
		}
	}

	return "", fmt.Errorf("configuration file '%s' not found in current directory or user home directory (~).\n💡 Tip: Run 'singctl ssh tpl' to generate a template or specify one using -f <path>", DefaultConfigFile)
}

var envWithDefPattern = regexp.MustCompile(`\$\{([a-zA-Z_][a-zA-Z0-9_]*)(?::-([^}]*))?\}`)

// ExpandEnv expands environment variables, supporting ${VAR:-default} and standard $VAR / ${VAR}.
func ExpandEnv(s string) string {
	expanded := envWithDefPattern.ReplaceAllStringFunc(s, func(match string) string {
		sub := envWithDefPattern.FindStringSubmatch(match)
		if len(sub) >= 2 {
			varName := sub[1]
			defVal := ""
			if len(sub) >= 3 {
				defVal = sub[2]
			}
			if val, ok := os.LookupEnv(varName); ok && val != "" {
				return val
			}
			return defVal
		}
		return match
	})
	return os.ExpandEnv(expanded)
}

// ResolveAliasConfig queries OpenSSH to inspect user, hostname, port, and proxycommand for a ~/.ssh/config alias.
func ResolveAliasConfig(alias string) (user string, host string, port int, proxyCmd string, err error) {
	cmd := exec.Command("ssh", "-G", alias)
	out, err := cmd.Output()
	if err != nil {
		return "", "", 0, "", fmt.Errorf("ssh -G %s failed: %w", alias, err)
	}

	for line := range strings.SplitSeq(string(out), "\n") {
		trimmed := strings.TrimSpace(line)
		parts := strings.Fields(trimmed)
		if len(parts) >= 2 {
			key := strings.ToLower(parts[0])
			val := strings.Join(parts[1:], " ")
			switch key {
			case "user":
				user = val
			case "hostname":
				host = val
			case "port":
				_, _ = fmt.Sscanf(val, "%d", &port)
			case "proxycommand":
				if val != "none" {
					proxyCmd = val
				}
			}
		}
	}
	return user, host, port, proxyCmd, nil
}

// LoadConfig reads, expands environment variables, and parses ssh-init.yaml into resolved Host models.
func LoadConfig(configPath string) (*Config, []*Host, error) {
	resolvedPath, err := ResolveConfigFile(configPath)
	if err != nil {
		return nil, nil, err
	}

	rawBytes, err := os.ReadFile(resolvedPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read %s: %w", resolvedPath, err)
	}

	// Expand environment variables
	expanded := ExpandEnv(string(rawBytes))

	var cfg Config
	if err := yaml.Unmarshal([]byte(expanded), &cfg); err != nil {
		return nil, nil, fmt.Errorf("failed to parse YAML in %s: %w", resolvedPath, err)
	}

	if len(cfg.Hosts) == 0 {
		return nil, nil, fmt.Errorf("no hosts defined in %s", resolvedPath)
	}

	// Apply defaults
	defaults := cfg.Defaults
	if defaults.User == "" {
		defaults.User = DefaultUser
	}
	if defaults.CurrentPort <= 0 {
		defaults.CurrentPort = DefaultCurrentPort
	}
	if defaults.TargetPort <= 0 {
		defaults.TargetPort = DefaultTargetPort
	}
	if defaults.IdentityFile == "" {
		defaults.IdentityFile = "~/.ssh/id_ed25519.pub"
	}
	if defaults.PrivateKey == "" {
		defaults.PrivateKey = "~/.ssh/id_ed25519"
	}
	if defaults.TimeoutSeconds <= 0 {
		defaults.TimeoutSeconds = DefaultTimeoutSec
	}

	defDisablePass := true
	if defaults.DisablePasswordAuth != nil {
		defDisablePass = *defaults.DisablePasswordAuth
	}

	defManageFirewall := true
	if defaults.ManageFirewall != nil {
		defManageFirewall = *defaults.ManageFirewall
	}

	defStrictHostKey := false
	if defaults.StrictHostKeyChecking != nil {
		defStrictHostKey = *defaults.StrictHostKeyChecking
	}

	hosts := make([]*Host, 0, len(cfg.Hosts))
	seenNames := make(map[string]bool)

	for idx, item := range cfg.Hosts {
		alias := strings.TrimSpace(item.Alias)
		isAliasMode := alias != ""

		name := strings.TrimSpace(item.Name)
		if isAliasMode && name == "" {
			name = alias
		}

		if name == "" {
			return nil, nil, fmt.Errorf("hosts[%d]: 'name' (or 'alias') cannot be empty", idx)
		}
		if seenNames[name] {
			return nil, nil, fmt.Errorf("hosts[%d]: duplicate host name '%s'", idx, name)
		}
		seenNames[name] = true

		hostVal := strings.TrimSpace(item.Host)
		if hostVal == "" {
			hostVal = strings.TrimSpace(item.IP)
		}

		user := item.User
		if user == "" {
			user = defaults.User
		}

		curPort := item.CurrentPort
		if curPort <= 0 {
			curPort = defaults.CurrentPort
		}

		// In alias mode, auto-resolve user, host, and port from ~/.ssh/config if not specified
		if isAliasMode {
			resolvedUser, resolvedHost, resolvedPort, _, err := ResolveAliasConfig(alias)
			if err == nil {
				if item.User == "" && resolvedUser != "" {
					user = resolvedUser
				}
				if hostVal == "" && resolvedHost != "" {
					hostVal = resolvedHost
				}
				if item.CurrentPort <= 0 && resolvedPort > 0 {
					curPort = resolvedPort
				}
			}
		}

		if !isAliasMode && hostVal == "" {
			return nil, nil, fmt.Errorf("hosts[%s]: 'host' (or 'ip') cannot be empty", name)
		}

		if curPort < 1 || curPort > 65535 {
			return nil, nil, fmt.Errorf("hosts[%s]: invalid current_port %d", name, curPort)
		}

		targetPort := item.TargetPort
		if targetPort <= 0 {
			if isAliasMode {
				// In alias mode, targetPort matches the active alias port (e.g. 2222)
				targetPort = curPort
			} else {
				targetPort = defaults.TargetPort
			}
		}
		if targetPort < 1 || targetPort > 65535 {
			return nil, nil, fmt.Errorf("hosts[%s]: invalid target_port %d", name, targetPort)
		}

		idFile := item.IdentityFile
		if idFile == "" {
			idFile = defaults.IdentityFile
		}
		idFile = ExpandPath(idFile)

		privKey := item.PrivateKey
		if privKey == "" {
			privKey = defaults.PrivateKey
		}
		privKey = ExpandPath(privKey)

		disablePass := defDisablePass
		if item.DisablePasswordAuth != nil {
			disablePass = *item.DisablePasswordAuth
		}

		manageFw := defManageFirewall
		if item.ManageFirewall != nil {
			manageFw = *item.ManageFirewall
		}

		strictHost := defStrictHostKey
		if item.StrictHostKeyChecking != nil {
			strictHost = *item.StrictHostKeyChecking
		}

		timeoutSec := item.TimeoutSeconds
		if timeoutSec <= 0 {
			timeoutSec = defaults.TimeoutSeconds
		}

		authKey := ExpandPath(item.Auth.Key)
		auth := AuthConfig{
			Password: item.Auth.Password,
			Key:      authKey,
		}

		if !isAliasMode && auth.Password == "" && auth.Key == "" {
			return nil, nil, fmt.Errorf("hosts[%s]: either auth.password or auth.key must be specified", name)
		}

		h := &Host{
			Name:                  name,
			Host:                  hostVal,
			IP:                    hostVal,
			Alias:                 alias,
			IsAliasMode:           isAliasMode,
			User:                  strings.TrimSpace(user),
			CurrentPort:           curPort,
			TargetPort:            targetPort,
			IdentityFile:          idFile,
			PrivateKey:            privKey,
			DisablePasswordAuth:   disablePass,
			ManageFirewall:        manageFw,
			StrictHostKeyChecking: strictHost,
			Timeout:               time.Duration(timeoutSec) * time.Second,
			Auth:                  auth,
		}

		hosts = append(hosts, h)
	}

	return &cfg, hosts, nil
}
