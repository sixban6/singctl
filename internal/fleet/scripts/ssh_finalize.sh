set -e
OLD_PORT={{.OldPort}}
TARGET_PORT={{.TargetPort}}
cat << 'EOF' > /etc/ssh/sshd_config.d/00-singctl-hardening.conf
{{.FinalPortDirectives}}
PermitRootLogin prohibit-password
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
X11Forwarding no
MaxAuthTries 3
ClientAliveInterval 60
ClientAliveCountMax 3
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
