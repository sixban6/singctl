package ssh

import (
	"fmt"
	"slices"
	"strings"
)

const (
	HardeningConfPath = "/etc/ssh/sshd_config.d/00-singctl-hardening.conf"
	MainSshdConfig    = "/etc/ssh/sshd_config"
)

// RemoteSshdInfo contains authoritative runtime parameters queried from remote sshd.
type RemoteSshdInfo struct {
	Ports        []int
	PasswordAuth bool // true if password authentication is permitted
	PubkeyAuth   bool // true if public key authentication is permitted
}

// InspectRemoteSshd queries the remote host's sshd daemon (-T) to get authoritative runtime settings.
func InspectRemoteSshd(executor Executor) (*RemoteSshdInfo, error) {
	cmd := `
sshd_bin="$(command -v sshd || echo '/usr/sbin/sshd')"
if [ -x "$sshd_bin" ]; then
    "$sshd_bin" -T 2>/dev/null | grep -E '^(port|passwordauthentication|pubkeyauthentication) '
fi
`
	out, err := executor.Run(cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to run sshd -T: %w", err)
	}

	info := &RemoteSshdInfo{
		PubkeyAuth: true,
	}

	for line := range strings.SplitSeq(out, "\n") {
		trimmed := strings.TrimSpace(line)
		fields := strings.Fields(trimmed)
		if len(fields) >= 2 {
			key := strings.ToLower(fields[0])
			val := strings.ToLower(fields[1])
			switch key {
			case "port":
				var p int
				if _, err := fmt.Sscanf(val, "%d", &p); err == nil && p > 0 {
					if !slices.Contains(info.Ports, p) {
						info.Ports = append(info.Ports, p)
					}
				}
			case "passwordauthentication":
				info.PasswordAuth = (val == "yes")
			case "pubkeyauthentication":
				info.PubkeyAuth = (val == "yes")
			}
		}
	}

	if len(info.Ports) == 0 {
		return nil, fmt.Errorf("sshd -T returned empty or unrecognized configuration")
	}

	return info, nil
}

// SshdHarden handles sshd configuration file adjustments and daemon reloading.
type SshdHarden struct {
	executor Executor
}

// NewSshdHarden creates a new SshdHarden.
func NewSshdHarden(executor Executor) *SshdHarden {
	return &SshdHarden{executor: executor}
}

// PrepareSshdConfigEnv ensures /etc/ssh/sshd_config.d directory exists and is included in sshd_config.
func (s *SshdHarden) PrepareSshdConfigEnv() error {
	script := `
set -e
mkdir -p /etc/ssh/sshd_config.d

# Clean up legacy 99-singctl-hardening.conf to avoid duplicate drop-ins
rm -f /etc/ssh/sshd_config.d/99-singctl-hardening.conf

# Neutralize known vendor panel backdoor files that force password authentication
rm -f /etc/ssh/sshd_config.d/99-ctrl.conf

if [ -f /etc/ssh/sshd_config ]; then
    if ! grep -Eq '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' /etc/ssh/sshd_config; then
        echo "Include /etc/ssh/sshd_config.d/*.conf" >> /etc/ssh/sshd_config
    fi
    # Neutralize conflicting unmanaged directives in other config files
    for conf in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf; do
        [ -f "${conf}" ] || continue
        [ "${conf}" = "/etc/ssh/sshd_config.d/00-singctl-hardening.conf" ] && continue
        sed -i -E 's/^[[:space:]]*Port[[:space:]]+[0-9]+/# &/g' "${conf}"
        sed -i -E 's/^[[:space:]]*PasswordAuthentication[[:space:]]+yes/# &/g' "${conf}"
        sed -i -E 's/^[[:space:]]*KbdInteractiveAuthentication[[:space:]]+yes/# &/g' "${conf}"
        sed -i -E 's/^[[:space:]]*ChallengeResponseAuthentication[[:space:]]+yes/# &/g' "${conf}"
    done
fi
`
	_, err := s.executor.Run(script)
	return err
}

// EnableDualPort configures sshd to listen on both currentPort and targetPort simultaneously.
func (s *SshdHarden) EnableDualPort(currentPort, targetPort int) error {
	if currentPort <= 0 || targetPort <= 0 {
		return fmt.Errorf("ports must be greater than 0 (current: %d, target: %d)", currentPort, targetPort)
	}

	if err := s.PrepareSshdConfigEnv(); err != nil {
		return fmt.Errorf("prepare sshd config environment failed: %w", err)
	}

	var confContent string
	if currentPort == targetPort {
		confContent = fmt.Sprintf(`Port %d
PubkeyAuthentication yes
`, targetPort)
	} else {
		confContent = fmt.Sprintf(`Port %d
Port %d
PubkeyAuthentication yes
`, currentPort, targetPort)
	}

	cmd := fmt.Sprintf("cat << 'EOF' > %s\n%sEOF\n", HardeningConfPath, confContent)
	if _, err := s.executor.Run(cmd); err != nil {
		return fmt.Errorf("failed to write dual-port configuration: %w", err)
	}

	if err := s.testAndReloadSshd(); err != nil {
		return fmt.Errorf("sshd syntax check or reload failed on dual-port configuration: %w", err)
	}

	return nil
}

// RollbackToPort rolls back configuration to only listen on the specified safe port.
func (s *SshdHarden) RollbackToPort(safePort int) error {
	if safePort <= 0 {
		safePort = 22
	}

	confContent := fmt.Sprintf(`Port %d
PubkeyAuthentication yes
`, safePort)

	cmd := fmt.Sprintf("cat << 'EOF' > %s\n%sEOF\n", HardeningConfPath, confContent)
	if _, err := s.executor.Run(cmd); err != nil {
		return fmt.Errorf("failed to write rollback configuration: %w", err)
	}

	return s.testAndReloadSshd()
}

// FinalizeHardening transitions sshd to listen only on targetPort, and optionally disables password authentication.
func (s *SshdHarden) FinalizeHardening(targetPort int, disablePassword bool) error {
	if targetPort <= 0 {
		return fmt.Errorf("target port must be greater than 0, got %d", targetPort)
	}

	if err := s.PrepareSshdConfigEnv(); err != nil {
		return fmt.Errorf("prepare sshd config environment failed: %w", err)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Port %d\n", targetPort))
	sb.WriteString("PubkeyAuthentication yes\n")

	if disablePassword {
		sb.WriteString("PasswordAuthentication no\n")
		sb.WriteString("KbdInteractiveAuthentication no\n")
		sb.WriteString("ChallengeResponseAuthentication no\n")
	}

	cmd := fmt.Sprintf("cat << 'EOF' > %s\n%sEOF\n", HardeningConfPath, sb.String())
	if _, err := s.executor.Run(cmd); err != nil {
		return fmt.Errorf("failed to write hardened sshd configuration: %w", err)
	}

	if err := s.testAndReloadSshd(); err != nil {
		return fmt.Errorf("sshd syntax check or reload failed during final hardening: %w", err)
	}

	return nil
}

func (s *SshdHarden) testAndReloadSshd() error {
	script := `
set -e
# Test sshd syntax
sshd_bin="$(command -v sshd || echo '/usr/sbin/sshd')"
if [ -x "$sshd_bin" ]; then
    "$sshd_bin" -t
fi

# Reload or restart sshd service
if command -v systemctl >/dev/null 2>&1; then
    systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || systemctl restart sshd
elif command -v service >/dev/null 2>&1; then
    service ssh reload 2>/dev/null || service sshd reload 2>/dev/null || service ssh restart 2>/dev/null || service sshd restart
else
    /etc/init.d/ssh reload 2>/dev/null || /etc/init.d/sshd reload 2>/dev/null || /etc/init.d/ssh restart 2>/dev/null || /etc/init.d/sshd restart
fi
`
	_, err := s.executor.Run(script)
	return err
}
