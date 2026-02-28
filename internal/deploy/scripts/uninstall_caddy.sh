#!/bin/bash
set -e

echo "Starting Caddy uninstallation..."

# Stop and disable caddy service
systemctl stop caddy || true
systemctl disable caddy || true

# Purge caddy package
apt-get purge -y caddy || true
apt-get autoremove -y || true

# Remove Caddy APT sources and keys
rm -f /etc/apt/sources.list.d/caddy-stable.list
rm -f /usr/share/keyrings/caddy-stable-archive-keyring.gpg
apt-get update || true

# Remove Caddy configuration directory
rm -rf /etc/caddy
# Remove generic webroot marker created by singctl
rm -f /var/www/html/index.html

echo "Caddy uninstallation completed successfully."
