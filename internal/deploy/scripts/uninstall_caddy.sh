#!/bin/bash
set -e

echo "Starting Caddy uninstallation..."

# Stop and disable caddy service
systemctl stop caddy 2>/dev/null || true
systemctl disable caddy 2>/dev/null || true
rm -f /etc/systemd/system/caddy.service
systemctl daemon-reload 2>/dev/null || true

# Backup existing SSL certificates before removal to prevent rate-limiting on reinstall
if [ -d "/var/lib/caddy/.local/share/caddy/certificates" ]; then
    mkdir -p /var/lib/singctl/caddy_certs_backup
    cp -a /var/lib/caddy/.local/share/caddy/certificates/* /var/lib/singctl/caddy_certs_backup/ 2>/dev/null || true
fi

# Clean up any legacy APT/dpkg Caddy book-keeping if present
apt-mark unhold caddy 2>/dev/null || true
apt-get remove -y caddy 2>/dev/null || true
rm -f /etc/apt/sources.list.d/caddy-stable.list
rm -f /usr/share/keyrings/caddy-stable-archive-keyring.gpg
rm -f /var/lib/apt/lists/*caddy* 2>/dev/null || true
apt-get update -qq 2>/dev/null || true

# Remove Caddy configuration directory and binary
rm -rf /etc/caddy
rm -f /usr/bin/caddy /usr/local/bin/caddy
# Remove generic webroot marker created by singctl
rm -f /var/www/html/index.html

echo "Caddy uninstallation completed successfully."
