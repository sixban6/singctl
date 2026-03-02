package osutil

import (
	"os"
)

// ServiceManager abstracts the operating system's service management logic (e.g. systemctl, init.d).
type ServiceManager interface {
	Start(serviceName string) error
	Stop(serviceName string) error
	Restart(serviceName string) error
	Enable(serviceName string) error
	Disable(serviceName string) error
	DaemonReload() error
	IsRunning(serviceName string) (bool, error)
}

// SystemdManager implements ServiceManager for Linux platforms using systemd
type SystemdManager struct{}

func (s *SystemdManager) Start(serviceName string) error {
	return RunCommand("systemctl", "start", serviceName)
}

func (s *SystemdManager) Stop(serviceName string) error {
	return RunCommand("systemctl", "stop", serviceName)
}

func (s *SystemdManager) Restart(serviceName string) error {
	return RunCommand("systemctl", "restart", serviceName)
}

func (s *SystemdManager) Enable(serviceName string) error {
	return RunCommand("systemctl", "enable", "--now", serviceName)
}

func (s *SystemdManager) Disable(serviceName string) error {
	return RunCommand("systemctl", "disable", "--now", serviceName)
}

func (s *SystemdManager) DaemonReload() error {
	return RunCommand("systemctl", "daemon-reload")
}

func (s *SystemdManager) IsRunning(serviceName string) (bool, error) {
	// systemctl is-active returns 0 if active, non-zero otherwise
	err := RunCommand("systemctl", "is-active", "--quiet", serviceName)
	if err != nil {
		return false, nil // Assume not running, not necessarily an "error"
	}
	return true, nil
}

// GetServiceManager returns the appropriate ServiceManager for the current platform
func GetServiceManager() ServiceManager {
	if IsOpenWrt() {
		return &OpenWrtManager{}
	}
	return &SystemdManager{}
}

// IsOpenWrt checks if the current system is OpenWrt
func IsOpenWrt() bool {
	if _, err := os.Stat("/etc/openwrt_release"); err == nil {
		return true
	}
	if _, err := os.Stat("/etc/openwrt_version"); err == nil {
		return true
	}
	return false
}
