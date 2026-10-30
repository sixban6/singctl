package ssh

import "time"

// Config represents the top-level structure of ssh-init.yaml
type Config struct {
	Version  string     `yaml:"version"`
	Defaults Defaults   `yaml:"defaults"`
	Hosts    []HostItem `yaml:"hosts"`
}

// Defaults contains default parameters for all hosts
type Defaults struct {
	User                   string `yaml:"user"`
	CurrentPort            int    `yaml:"current_port"`
	TargetPort             int    `yaml:"target_port"`
	IdentityFile           string `yaml:"identity_file"`
	PrivateKey             string `yaml:"private_key"`
	DisablePasswordAuth    *bool  `yaml:"disable_password_auth"`
	ManageFirewall         *bool  `yaml:"manage_firewall"`
	StrictHostKeyChecking  *bool  `yaml:"strict_host_key_checking"`
	TimeoutSeconds         int    `yaml:"timeout_seconds"`
}

// AuthConfig defines the authentication method for a host
type AuthConfig struct {
	Password string `yaml:"password"`
	Key      string `yaml:"key"`
}

// HostItem represents a single host configuration from YAML
type HostItem struct {
	Name                  string      `yaml:"name"`
	IP                    string      `yaml:"ip"`
	User                  string      `yaml:"user"`
	CurrentPort           int         `yaml:"current_port"`
	TargetPort            int         `yaml:"target_port"`
	IdentityFile          string      `yaml:"identity_file"`
	PrivateKey            string      `yaml:"private_key"`
	DisablePasswordAuth   *bool       `yaml:"disable_password_auth"`
	ManageFirewall        *bool       `yaml:"manage_firewall"`
	StrictHostKeyChecking *bool       `yaml:"strict_host_key_checking"`
	TimeoutSeconds        int         `yaml:"timeout_seconds"`
	Auth                  AuthConfig  `yaml:"auth"`
}

// Host is the resolved runtime host model after applying defaults and env vars
type Host struct {
	Name                  string
	IP                    string
	User                  string
	CurrentPort           int
	TargetPort            int
	IdentityFile          string // Local public key path (e.g. ~/.ssh/id_ed25519.pub)
	PrivateKey            string // Local private key path (e.g. ~/.ssh/id_ed25519)
	DisablePasswordAuth   bool
	ManageFirewall        bool
	StrictHostKeyChecking bool
	Timeout               time.Duration
	Auth                  AuthConfig
}

// ExecutionStatus represents the execution state of a host
type ExecutionStatus string

const (
	StatusSuccess ExecutionStatus = "SUCCESS"
	StatusWarning ExecutionStatus = "WARNING"
	StatusFailed  ExecutionStatus = "FAILED"
	StatusSkipped ExecutionStatus = "SKIPPED"
)

// HostResult records the execution result and details for a host
type HostResult struct {
	Host               *Host
	Status             ExecutionStatus
	InitialPort        int
	FinalPort          int
	KeyPushed          bool
	KeyVerified        bool
	PasswordDisabled   bool
	FirewallConfigured bool
	ConfigUpdated      bool
	Error              error
	WarningMsg         string
	Duration           time.Duration
}

// TestResult records diagnostic information from `singctl ssh test`
type TestResult struct {
	Host             *Host
	Port22Open       bool
	TargetPortOpen   bool
	KeyAuthWork      bool
	PasswordAuthWork bool
	Details          string
	Error            error
	Duration         time.Duration
}
