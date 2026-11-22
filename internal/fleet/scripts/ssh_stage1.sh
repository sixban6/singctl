set -e
KEYS_B64='{{.KeysB64}}'
TARGET_PORT={{.TargetPort}}
umask 077
mkdir -p ~/.ssh
chmod 700 ~/.ssh
touch ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys

TMP_KEYS=$(mktemp)
printf '%s' "$KEYS_B64" | base64 -d > "$TMP_KEYS"
while IFS= read -r kline || [ -n "$kline" ]; do
  [ -z "$kline" ] && continue
  kbody=$(printf '%s' "$kline" | awk '{print $1" "$2}')
  if ! grep -Fq "$kbody" ~/.ssh/authorized_keys 2>/dev/null; then
    printf '%s\n' "$kline" >> ~/.ssh/authorized_keys
  fi
done < "$TMP_KEYS"
rm -f "$TMP_KEYS"
command -v restorecon >/dev/null 2>&1 && restorecon -R -v ~/.ssh >/dev/null 2>&1 || true

# Firewall & SELinux allow target port
MASTER_IP=$(printf '%s' "${SSH_CLIENT:-}" | awk '{print $1}')

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
    ufw delete deny from "$MASTER_IP" to any port "$TARGET_PORT" >/dev/null 2>&1 || true
    ufw delete deny from "$MASTER_IP" >/dev/null 2>&1 || true
    ufw insert 1 allow from "$MASTER_IP" to any port "$TARGET_PORT" proto tcp >/dev/null 2>&1 || true
  fi
fi

if command -v nft >/dev/null 2>&1 && nft list table inet security >/dev/null 2>&1; then
  nft delete element inet security protected_ports { 1080 } >/dev/null 2>&1 || true
  nft delete element inet security protected_ports { "$TARGET_PORT" } >/dev/null 2>&1 || true
  if [ -n "$MASTER_IP" ]; then
    nft add element inet security whitelist_ip { "$MASTER_IP" } >/dev/null 2>&1 || true
    nft delete element inet security blocklist_ip4 { "$MASTER_IP" } >/dev/null 2>&1 || true
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
    sed -i -E 's/^[[:space:]]*PermitRootLogin[[:space:]]+yes/# &/g' "$conf"
    sed -i -E 's/^[[:space:]]*X11Forwarding[[:space:]]+yes/# &/g' "$conf"
    sed -i -E 's/^[[:space:]]*PasswordAuthentication[[:space:]]+yes/# &/g' "$conf"
    sed -i -E 's/^[[:space:]]*KbdInteractiveAuthentication[[:space:]]+yes/# &/g' "$conf"
    sed -i -E 's/^[[:space:]]*ChallengeResponseAuthentication[[:space:]]+yes/# &/g' "$conf"
  done
fi

cat << 'EOF' > /etc/ssh/sshd_config.d/00-singctl-hardening.conf
{{.PortDirectives}}
PubkeyAuthentication yes
EOF

LOCAL_SSH_PORT=$(printf '%s' "${SSH_CONNECTION:-}" | awk '{print $4}')
if [ -n "$LOCAL_SSH_PORT" ] && ! grep -Eq "^[[:space:]]*Port[[:space:]]+${LOCAL_SSH_PORT}([[:space:]]|$)" /etc/ssh/sshd_config.d/00-singctl-hardening.conf 2>/dev/null; then
  TMP_SSHD_CONF=$(mktemp)
  printf 'Port %s\n' "$LOCAL_SSH_PORT" > "$TMP_SSHD_CONF"
  cat /etc/ssh/sshd_config.d/00-singctl-hardening.conf >> "$TMP_SSHD_CONF"
  cat "$TMP_SSHD_CONF" > /etc/ssh/sshd_config.d/00-singctl-hardening.conf
  rm -f "$TMP_SSHD_CONF"
fi
[ -n "$LOCAL_SSH_PORT" ] && printf 'SINGCTL_LOCAL_SSH_PORT=%s\n' "$LOCAL_SSH_PORT" || true

SSHD_BIN="$(command -v sshd || echo '/usr/sbin/sshd')"
[ -x "$SSHD_BIN" ] && "$SSHD_BIN" -t

if command -v systemctl >/dev/null 2>&1; then
  systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || systemctl restart sshd
elif command -v service >/dev/null 2>&1; then
  service ssh reload 2>/dev/null || service sshd reload 2>/dev/null || service ssh restart 2>/dev/null || service sshd restart
else
  /etc/init.d/ssh reload 2>/dev/null || /etc/init.d/sshd reload 2>/dev/null || /etc/init.d/ssh restart 2>/dev/null || /etc/init.d/sshd restart
fi
