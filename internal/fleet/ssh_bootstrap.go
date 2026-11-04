package fleet

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// DefaultTargetSSHPort is the standard hardened SSH port applied during bare-metal fleet bootstrap.
const DefaultTargetSSHPort = 2222

// EnsureMasterKeypair loads or generates the dedicated Fleet Master Ed25519 SSH keypair (0600)
// at <KeysDir>/master_ed25519 and returns its private key path and authorized_keys public line.
func (s *Store) EnsureMasterKeypair() (privKeyPath string, pubKeyLine string, err error) {
	if err := os.MkdirAll(s.KeysDir, 0700); err != nil {
		return "", "", fmt.Errorf("创建舰队密钥目录失败: %w", err)
	}
	privKeyPath = filepath.Join(s.KeysDir, "master_ed25519")
	pubKeyPath := privKeyPath + ".pub"

	if rawPriv, readErr := os.ReadFile(privKeyPath); readErr == nil && len(bytes.TrimSpace(rawPriv)) > 0 {
		signer, parseErr := ssh.ParsePrivateKey(rawPriv)
		if parseErr != nil {
			return "", "", fmt.Errorf("解析现有主控密钥 %s 失败: %w", privKeyPath, parseErr)
		}
		_ = os.Chmod(privKeyPath, 0600)
		pubLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))) + " singctl-fleet-master"
		_ = os.WriteFile(pubKeyPath, []byte(pubLine+"\n"), 0644)
		return privKeyPath, pubLine, nil
	}

	_, priv, genErr := ed25519.GenerateKey(rand.Reader)
	if genErr != nil {
		return "", "", fmt.Errorf("生成主控 Ed25519 密钥失败: %w", genErr)
	}
	pemBlock, marshalErr := ssh.MarshalPrivateKey(priv, "singctl-fleet-master")
	if marshalErr != nil {
		return "", "", fmt.Errorf("序列化主控私钥失败: %w", marshalErr)
	}
	privPEM := pem.EncodeToMemory(pemBlock)
	if err := os.WriteFile(privKeyPath, privPEM, 0600); err != nil {
		return "", "", fmt.Errorf("写入主控私钥失败: %w", err)
	}
	_ = os.Chmod(privKeyPath, 0600)

	sshPub, pubErr := ssh.NewPublicKey(priv.Public())
	if pubErr != nil {
		return "", "", fmt.Errorf("派生主控公钥失败: %w", pubErr)
	}
	pubKeyLine = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))) + " singctl-fleet-master"
	_ = os.WriteFile(pubKeyPath, []byte(pubKeyLine+"\n"), 0644)

	return privKeyPath, pubKeyLine, nil
}

// CollectMasterAuthorizedKeys combines the Fleet Master public key, any existing admin keys in
// Master's ~/.ssh/authorized_keys (so the operator's personal workstation is not locked out),
// and optional extra public keys, deduplicated by cryptographic key material.
func CollectMasterAuthorizedKeys(masterPubKey, extraKeys string) []string {
	var result []string
	seen := make(map[string]struct{})

	addLine := func(rawLine string) {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			return
		}
		pub, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			return
		}
		wire := string(pub.Marshal())
		if _, exists := seen[wire]; exists {
			return
		}
		seen[wire] = struct{}{}
		formatted := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
		if strings.TrimSpace(comment) != "" {
			formatted += " " + strings.TrimSpace(comment)
		}
		result = append(result, formatted)
	}

	addLine(masterPubKey)

	candidateFiles := []string{"/root/.ssh/authorized_keys"}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		p := filepath.Join(home, ".ssh", "authorized_keys")
		if p != candidateFiles[0] {
			candidateFiles = append(candidateFiles, p)
		}
	}
	for _, p := range candidateFiles {
		if raw, err := os.ReadFile(p); err == nil {
			for line := range strings.SplitSeq(string(raw), "\n") {
				addLine(line)
			}
		}
	}

	for line := range strings.SplitSeq(extraKeys, "\n") {
		addLine(line)
	}

	return result
}

func shouldHardenBootstrapSSH(in BootstrapInput, authType string) bool {
	if authType == AuthSSHAlias {
		return false
	}
	if in.HardenSSH != nil {
		return *in.HardenSSH
	}
	return true
}

// hardenBootstrapSSH performs atomic, lockout-safe SSH hardening on a fresh VPS:
//  1. Injects Master + operator public keys into ~/.ssh/authorized_keys
//  2. Opens targetPort on firewall (UFW / firewalld / SELinux / iptables) and enables dual-port sshd
//  3. Externally verifies passwordless key login from Master on targetPort (auto-rolls back on failure!)
//  4. Closes legacy port 22 and disables password authentication
func (m *Manager) hardenBootstrapSSH(ctx context.Context, initialNode Node, targetPort int, extraKeys string) (Node, error) {
	if targetPort <= 0 || targetPort > 65535 {
		targetPort = DefaultTargetSSHPort
	}
	currentPort := initialNode.Port
	if currentPort <= 0 || currentPort > 65535 {
		currentPort = 22
	}

	masterKeyPath, masterPubLine, err := m.Store.EnsureMasterKeypair()
	if err != nil {
		return Node{}, err
	}
	pubKeys := CollectMasterAuthorizedKeys(masterPubLine, extraKeys)
	if len(pubKeys) == 0 {
		return Node{}, fmt.Errorf("未能生成有效的 SSH 授权公钥")
	}
	keysB64 := base64.StdEncoding.EncodeToString([]byte(strings.Join(pubKeys, "\n") + "\n"))

	var portDirectives string
	if currentPort == targetPort {
		portDirectives = fmt.Sprintf("Port %d", targetPort)
	} else {
		portDirectives = fmt.Sprintf("Port %d\nPort %d", currentPort, targetPort)
	}

	stage1Script := fmt.Sprintf(`
set -e
umask 077
mkdir -p ~/.ssh
chmod 700 ~/.ssh
touch ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys

TMP_KEYS=$(mktemp)
printf '%%s' %q | base64 -d > "$TMP_KEYS"
while IFS= read -r kline || [ -n "$kline" ]; do
  [ -z "$kline" ] && continue
  kbody=$(printf '%%s' "$kline" | awk '{print $1" "$2}')
  if ! grep -Fq "$kbody" ~/.ssh/authorized_keys 2>/dev/null; then
    printf '%%s\n' "$kline" >> ~/.ssh/authorized_keys
  fi
done < "$TMP_KEYS"
rm -f "$TMP_KEYS"
command -v restorecon >/dev/null 2>&1 && restorecon -R -v ~/.ssh >/dev/null 2>&1 || true

# Firewall & SELinux allow target port
TARGET_PORT=%d
MASTER_IP=$(printf '%%s' "${SSH_CLIENT:-}" | awk '{print $1}')

if command -v getenforce >/dev/null 2>&1; then
  SE_STATE=$(getenforce 2>/dev/null || true)
  if [ "$SE_STATE" = "Enforcing" ] || [ "$SE_STATE" = "Permissive" ]; then
    if command -v semanage >/dev/null 2>&1; then
      semanage port -l | grep -w ssh_port_t | grep -qw "$TARGET_PORT" || \
        semanage port -a -t ssh_port_t -p tcp "$TARGET_PORT" 2>/dev/null || \
        semanage port -m -t ssh_port_t -p tcp "$TARGET_PORT" 2>/dev/null || true
    fi
  fi
fi

if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qw active; then
  ufw allow "${TARGET_PORT}/tcp" comment 'singctl-ssh' >/dev/null 2>&1 || true
  if [ -n "$MASTER_IP" ]; then
    ufw insert 1 allow from "$MASTER_IP" to any port "$TARGET_PORT" proto tcp >/dev/null 2>&1 || true
  fi
fi

if command -v firewall-cmd >/dev/null 2>&1 && [ "$(firewall-cmd --state 2>/dev/null || true)" = "running" ]; then
  firewall-cmd --permanent --add-port="${TARGET_PORT}/tcp" >/dev/null 2>&1 || true
  firewall-cmd --reload >/dev/null 2>&1 || true
fi

if command -v iptables >/dev/null 2>&1 && iptables -S 2>/dev/null | grep -q -- "-P INPUT DROP"; then
  iptables -C INPUT -p tcp --dport "$TARGET_PORT" -j ACCEPT 2>/dev/null || \
    iptables -I INPUT 1 -p tcp --dport "$TARGET_PORT" -j ACCEPT 2>/dev/null || true
fi

# Disable systemd ssh.socket override on Ubuntu 22.04+/24.04+ so sshd_config Port takes effect
if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet ssh.socket 2>/dev/null; then
  systemctl disable --now ssh.socket >/dev/null 2>&1 || true
  systemctl enable --now ssh.service >/dev/null 2>&1 || systemctl enable --now ssh >/dev/null 2>&1 || true
fi

mkdir -p /etc/ssh/sshd_config.d
rm -f /etc/ssh/sshd_config.d/99-singctl-hardening.conf /etc/ssh/sshd_config.d/99-ctrl.conf

if [ -f /etc/ssh/sshd_config ]; then
  if ! grep -Eq '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' /etc/ssh/sshd_config; then
    printf '\nInclude /etc/ssh/sshd_config.d/*.conf\n' >> /etc/ssh/sshd_config
  fi
  for conf in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf; do
    [ -f "$conf" ] || continue
    [ "$conf" = "/etc/ssh/sshd_config.d/00-singctl-hardening.conf" ] && continue
    sed -i -E 's/^[[:space:]]*Port[[:space:]]+[0-9]+/# &/g' "$conf"
    sed -i -E 's/^[[:space:]]*PasswordAuthentication[[:space:]]+yes/# &/g' "$conf"
    sed -i -E 's/^[[:space:]]*KbdInteractiveAuthentication[[:space:]]+yes/# &/g' "$conf"
    sed -i -E 's/^[[:space:]]*ChallengeResponseAuthentication[[:space:]]+yes/# &/g' "$conf"
  done
fi

cat << 'EOF' > /etc/ssh/sshd_config.d/00-singctl-hardening.conf
%s
PubkeyAuthentication yes
EOF

SSHD_BIN="$(command -v sshd || echo '/usr/sbin/sshd')"
[ -x "$SSHD_BIN" ] && "$SSHD_BIN" -t

if command -v systemctl >/dev/null 2>&1; then
  systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || systemctl restart sshd
elif command -v service >/dev/null 2>&1; then
  service ssh reload 2>/dev/null || service sshd reload 2>/dev/null || service ssh restart 2>/dev/null || service sshd restart
else
  /etc/init.d/ssh reload 2>/dev/null || /etc/init.d/sshd reload 2>/dev/null || /etc/init.d/ssh restart 2>/dev/null || /etc/init.d/sshd restart
fi
`, keysB64, targetPort, portDirectives)

	runner := m.runner()
	stage1Ctx, cancel1 := context.WithTimeout(ctx, 45*time.Second)
	_, _, err = runner(stage1Ctx, initialNode, stage1Script)
	cancel1()
	if err != nil {
		return Node{}, fmt.Errorf("SSH 免密注入与双端口预备阶段失败: %w", err)
	}

	hardenedNode := initialNode
	hardenedNode.Port = targetPort
	hardenedNode.AuthType = AuthKeyFile
	hardenedNode.KeyPath = masterKeyPath
	hardenedNode.Password = ""
	hardenedNode.HasCredential = true

	// External verification from Master on targetPort using key-only authentication
	var verifyOut string
	var verifyErr error
	for attempt := range 3 {
		if attempt > 0 {
			select {
			case <-time.After(1500 * time.Millisecond):
			case <-ctx.Done():
				return Node{}, ctx.Err()
			}
		}
		vCtx, vCancel := context.WithTimeout(ctx, 12*time.Second)
		verifyOut, _, verifyErr = runner(vCtx, hardenedNode, "echo SINGCTL_FLEET_SSH_VERIFIED")
		vCancel()
		if verifyErr == nil && strings.Contains(verifyOut, "SINGCTL_FLEET_SSH_VERIFIED") {
			break
		}
	}

	if verifyErr != nil || !strings.Contains(verifyOut, "SINGCTL_FLEET_SSH_VERIFIED") {
		// Automatic rollback over initialNode so the machine is never locked out!
		rbScript := fmt.Sprintf(`
cat << 'EOF' > /etc/ssh/sshd_config.d/00-singctl-hardening.conf
Port %d
PubkeyAuthentication yes
PasswordAuthentication yes
EOF
if command -v systemctl >/dev/null 2>&1; then
  systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || systemctl restart sshd || true
fi
`, currentPort)
		rbCtx, rbCancel := context.WithTimeout(context.Background(), 15*time.Second)
		_, _, _ = runner(rbCtx, initialNode, rbScript)
		rbCancel()
		return Node{}, fmt.Errorf(
			"新 SSH 端口 %d 外部免密验证未通过（请检查云厂商安全组/防火墙是否已放行 TCP %d），已自动回滚保留原端口 %d，未锁死服务器: %v",
			targetPort, targetPort, currentPort, verifyErr,
		)
	}

	// Stage 3: Finalize port convergence + disable password authentication over verified hardenedNode
	finalizeScript := fmt.Sprintf(`
set -e
cat << 'EOF' > /etc/ssh/sshd_config.d/00-singctl-hardening.conf
Port %d
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
EOF

SSHD_BIN="$(command -v sshd || echo '/usr/sbin/sshd')"
[ -x "$SSHD_BIN" ] && "$SSHD_BIN" -t

if command -v systemctl >/dev/null 2>&1; then
  systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || systemctl restart sshd
elif command -v service >/dev/null 2>&1; then
  service ssh reload 2>/dev/null || service sshd reload 2>/dev/null || service ssh restart 2>/dev/null || service sshd restart
else
  /etc/init.d/ssh reload 2>/dev/null || /etc/init.d/sshd reload 2>/dev/null || /etc/init.d/ssh restart 2>/dev/null || /etc/init.d/sshd restart
fi

OLD_PORT=%d
TARGET_PORT=%d
if [ "$OLD_PORT" != "$TARGET_PORT" ]; then
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qw active; then
    ufw delete allow "${OLD_PORT}/tcp" >/dev/null 2>&1 || true
    ufw delete allow ssh >/dev/null 2>&1 || true
  fi
  if command -v firewall-cmd >/dev/null 2>&1 && [ "$(firewall-cmd --state 2>/dev/null || true)" = "running" ]; then
    firewall-cmd --permanent --remove-port="${OLD_PORT}/tcp" >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null 2>&1 || true
  fi
fi
`, targetPort, currentPort, targetPort)

	finCtx, finCancel := context.WithTimeout(ctx, 25*time.Second)
	_, _, finErr := runner(finCtx, hardenedNode, finalizeScript)
	finCancel()
	if finErr != nil {
		return Node{}, fmt.Errorf("SSH 最终收口加固失败: %w", finErr)
	}

	return hardenedNode, nil
}
