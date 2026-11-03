#!/bin/bash
set -e

echo "Starting Caddy uninstallation..."

# Stop and disable caddy service
systemctl stop caddy || true
systemctl disable caddy || true

# Unhold caddy if held before removing
apt-mark unhold caddy || true

# Backup existing SSL certificates before package removal to prevent rate-limiting on reinstall
if [ -d "/var/lib/caddy/.local/share/caddy/certificates" ]; then
    mkdir -p /var/lib/singctl/caddy_certs_backup
    cp -a /var/lib/caddy/.local/share/caddy/certificates/* /var/lib/singctl/caddy_certs_backup/ 2>/dev/null || true
fi

# Remove caddy package (use remove instead of purge to avoid wiping valid ACME state)
apt-get remove -y caddy || true
apt-get autoremove -y || true

# Remove Caddy APT sources and keys
rm -f /etc/apt/sources.list.d/caddy-stable.list
rm -f /usr/share/keyrings/caddy-stable-archive-keyring.gpg
apt-get update || true

# Remove Caddy configuration directory and lingering binary
rm -rf /etc/caddy
rm -f /usr/bin/caddy
# Remove generic webroot marker created by singctl
rm -f /var/www/html/index.html

# Unhold caddy again to ensure it is completely unlocked in APT
apt-mark unhold caddy || true

echo "Caddy uninstallation completed successfully."
