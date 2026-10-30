package ssh

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// Client encapsulates an SSH connection and execution context.
type Client struct {
	client *ssh.Client
	host   *Host
}

// DialHost connects to the target host using either password or key authentication.
func DialHost(h *Host, port int, usePrivateKey bool) (*Client, error) {
	var authMethods []ssh.AuthMethod

	if usePrivateKey {
		keyBytes, err := os.ReadFile(h.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("failed to read private key %s: %w", h.PrivateKey, err)
		}
		signer, err := ssh.ParsePrivateKey(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key %s: %w", h.PrivateKey, err)
		}
		authMethods = append(authMethods, ssh.PublicKeys(signer))
	} else if h.Auth.Key != "" {
		keyBytes, err := os.ReadFile(h.Auth.Key)
		if err != nil {
			return nil, fmt.Errorf("failed to read auth key %s: %w", h.Auth.Key, err)
		}
		signer, err := ssh.ParsePrivateKey(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse auth key %s: %w", h.Auth.Key, err)
		}
		authMethods = append(authMethods, ssh.PublicKeys(signer))
	} else if h.Auth.Password != "" {
		authMethods = append(authMethods, ssh.Password(h.Auth.Password))
	} else {
		return nil, fmt.Errorf("no valid authentication method available for %s", h.Name)
	}

	hostKeyCallback := ssh.InsecureIgnoreHostKey()
	// Note: When StrictHostKeyChecking is false, we ignore host key validation to facilitate automated onboarding.

	sshConfig := &ssh.ClientConfig{
		User:            h.User,
		Auth:            authMethods,
		HostKeyCallback: hostKeyCallback,
		Timeout:         h.Timeout,
	}

	addr := net.JoinHostPort(h.IP, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", addr, h.Timeout)
	if err != nil {
		return nil, fmt.Errorf("TCP dial to %s failed: %w", addr, err)
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, sshConfig)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("SSH handshake with %s failed: %w", addr, err)
	}

	client := ssh.NewClient(sshConn, chans, reqs)
	return &Client{client: client, host: h}, nil
}

// Close closes the underlying SSH connection.
func (c *Client) Close() error {
	if c.client != nil {
		return c.client.Close()
	}
	return nil
}

// Run executes a shell command on the remote host and returns stdout.
// Stderr is captured and included in error if non-zero exit.
func (c *Client) Run(cmd string) (string, error) {
	session, err := c.client.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create SSH session: %w", err)
	}
	defer session.Close()

	var stdoutBuf, stderrBuf bytes.Buffer
	session.Stdout = &stdoutBuf
	session.Stderr = &stderrBuf

	// If non-root user, prepend sudo
	execCmd := cmd
	if c.host.User != "root" && !strings.HasPrefix(strings.TrimSpace(cmd), "sudo") {
		// Use non-interactive sudo
		execCmd = fmt.Sprintf("sudo -n sh -c %s", escapeShellArg(cmd))
	}

	err = session.Run(execCmd)
	stdout := stdoutBuf.String()
	stderr := strings.TrimSpace(stderrBuf.String())

	if err != nil {
		if stderr != "" {
			return stdout, fmt.Errorf("command '%s' failed: %v (stderr: %s)", cmd, err, stderr)
		}
		return stdout, fmt.Errorf("command '%s' failed: %w", cmd, err)
	}

	return stdout, nil
}

// InjectPublicKey appends the content of local public key into remote ~/.ssh/authorized_keys.
func (c *Client) InjectPublicKey(pubKeyPath string) error {
	pubBytes, err := os.ReadFile(pubKeyPath)
	if err != nil {
		return fmt.Errorf("cannot read local public key '%s': %w", pubKeyPath, err)
	}

	pubKeyStr := strings.TrimSpace(string(pubBytes))
	if pubKeyStr == "" {
		return fmt.Errorf("public key file '%s' is empty", pubKeyPath)
	}

	// Remote script ensuring permissions and idempotent append
	remoteScript := fmt.Sprintf(`
set -e
mkdir -p ~/.ssh
chmod 700 ~/.ssh
touch ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys

KEY=%s
if ! grep -q -F "$KEY" ~/.ssh/authorized_keys; then
    printf "%%s\n" "$KEY" >> ~/.ssh/authorized_keys
fi
`, escapeShellArg(pubKeyStr))

	session, err := c.client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()

	var stderrBuf bytes.Buffer
	session.Stderr = &stderrBuf

	if err := session.Run(fmt.Sprintf("sh -c %s", escapeShellArg(remoteScript))); err != nil {
		return fmt.Errorf("failed to inject public key: %v (stderr: %s)", err, strings.TrimSpace(stderrBuf.String()))
	}

	return nil
}

// TestTCPPort checks whether the specified IP and port are reachable via TCP.
func TestTCPPort(ip string, port int, timeout time.Duration) bool {
	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// ProbeKeyLogin tests if public-key authentication succeeds on the specified port.
func ProbeKeyLogin(h *Host, port int, timeout time.Duration) (bool, error) {
	keyBytes, err := os.ReadFile(h.PrivateKey)
	if err != nil {
		return false, fmt.Errorf("read private key %s: %w", h.PrivateKey, err)
	}

	signer, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		return false, fmt.Errorf("parse private key %s: %w", h.PrivateKey, err)
	}

	sshConfig := &ssh.ClientConfig{
		User:            h.User,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         timeout,
	}

	addr := net.JoinHostPort(h.IP, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, sshConfig)
	if err != nil {
		return false, err
	}
	_ = sshConn.Close()
	go ssh.DiscardRequests(reqs)
	for c := range chans {
		_ = c.Reject(ssh.UnknownChannelType, "closing")
	}

	return true, nil
}

// ProbePasswordLogin tests if password authentication succeeds or is accepted on the port.
func ProbePasswordLogin(h *Host, port int, password string, timeout time.Duration) (bool, error) {
	if password == "" {
		password = "invalid_probe_dummy_password_singctl"
	}

	sshConfig := &ssh.ClientConfig{
		User:            h.User,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         timeout,
	}

	addr := net.JoinHostPort(h.IP, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	sshConn, _, _, err := ssh.NewClientConn(conn, addr, sshConfig)
	if err != nil {
		errStr := err.Error()
		// If ssh rejected password, but password auth is enabled, the error contains "ssh: handshake failed: ssh: unable to authenticate"
		// If password auth is disabled on server, it will fail with "none,publickey" supported methods.
		if strings.Contains(errStr, "password") {
			return true, nil // server still accepts/offers password method
		}
		return false, nil
	}
	_ = sshConn.Close()
	return true, nil
}

func escapeShellArg(arg string) string {
	return "'" + strings.ReplaceAll(arg, "'", "'\"'\"'") + "'"
}
