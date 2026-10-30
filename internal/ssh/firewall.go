package ssh

import (
	"fmt"
	"strings"
)

// FirewallManager handles firewall rules and SELinux port policies on the remote host.
type FirewallManager struct {
	client *Client
}

// NewFirewallManager creates a new FirewallManager.
func NewFirewallManager(client *Client) *FirewallManager {
	return &FirewallManager{client: client}
}

// AllowPort enables incoming TCP traffic on the given port across UFW, Firewalld, and SELinux.
func (f *FirewallManager) AllowPort(port int) error {
	// 1. SELinux configuration (RHEL/CentOS/Rocky/Fedora)
	f.configureSELinux(port)

	// 2. UFW configuration (Ubuntu/Debian)
	f.configureUFW(port, true)

	// 3. Firewalld configuration (RHEL/CentOS/Rocky/Fedora)
	f.configureFirewalld(port, true)

	// 4. Fallback iptables rule if active
	f.configureIPTables(port, true)

	return nil
}

// DisallowPort removes incoming TCP traffic permission on the given port.
func (f *FirewallManager) DisallowPort(port int) error {
	// Remove from UFW
	f.configureUFW(port, false)

	// Remove from Firewalld
	f.configureFirewalld(port, false)

	// Remove from IPTables
	f.configureIPTables(port, false)

	return nil
}

func (f *FirewallManager) configureSELinux(port int) {
	// Check if getenforce is available and active
	out, err := f.client.Run("command -v getenforce >/dev/null 2>&1 && getenforce || true")
	if err != nil {
		return
	}
	status := strings.TrimSpace(out)
	if status != "Enforcing" && status != "Permissive" {
		return
	}

	// SELinux is active. Check if semanage exists.
	cmd := fmt.Sprintf(`
if command -v semanage >/dev/null 2>&1; then
    if ! semanage port -l | grep -w ssh_port_t | grep -qw "%d"; then
        semanage port -a -t ssh_port_t -p tcp %d || semanage port -m -t ssh_port_t -p tcp %d
    fi
fi
`, port, port, port)
	_, _ = f.client.Run(cmd)
}

func (f *FirewallManager) configureUFW(port int, allow bool) {
	checkCmd := "command -v ufw >/dev/null 2>&1 && ufw status | grep -qw active && echo 'active' || true"
	out, err := f.client.Run(checkCmd)
	if err != nil || strings.TrimSpace(out) != "active" {
		return
	}

	if allow {
		_, _ = f.client.Run(fmt.Sprintf("ufw allow %d/tcp comment 'singctl-ssh'", port))
	} else {
		_, _ = f.client.Run(fmt.Sprintf("ufw delete allow %d/tcp", port))
	}
}

func (f *FirewallManager) configureFirewalld(port int, allow bool) {
	checkCmd := "command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state 2>/dev/null || true"
	out, err := f.client.Run(checkCmd)
	if err != nil || strings.TrimSpace(out) != "running" {
		return
	}

	if allow {
		_, _ = f.client.Run(fmt.Sprintf("firewall-cmd --permanent --add-port=%d/tcp && firewall-cmd --reload", port))
	} else {
		_, _ = f.client.Run(fmt.Sprintf("firewall-cmd --permanent --remove-port=%d/tcp 2>/dev/null; firewall-cmd --reload", port))
	}
}

func (f *FirewallManager) configureIPTables(port int, allow bool) {
	// Only touch iptables if iptables command exists and has default DROP policies or established rules
	checkCmd := `
if command -v iptables >/dev/null 2>&1; then
    if iptables -S 2>/dev/null | grep -q -- "-P INPUT DROP"; then
        echo "drop_policy"
    fi
fi
`
	out, err := f.client.Run(checkCmd)
	if err != nil || strings.TrimSpace(out) != "drop_policy" {
		return
	}

	if allow {
		cmd := fmt.Sprintf(`
if ! iptables -C INPUT -p tcp --dport %d -j ACCEPT 2>/dev/null; then
    iptables -I INPUT 1 -p tcp --dport %d -j ACCEPT
fi
`, port, port)
		_, _ = f.client.Run(cmd)
	} else {
		_, _ = f.client.Run(fmt.Sprintf("iptables -D INPUT -p tcp --dport %d -j ACCEPT 2>/dev/null || true", port))
	}
}
