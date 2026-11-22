cat << 'EOF' > /etc/ssh/sshd_config.d/00-singctl-hardening.conf
{{.RBPortDirectives}}
PubkeyAuthentication yes
PasswordAuthentication yes
EOF
if command -v systemctl >/dev/null 2>&1; then
  systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || systemctl restart sshd || true
fi
