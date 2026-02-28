#!/bin/bash
set -e

apt-get update
apt-get install -y debian-keyring debian-archive-keyring apt-transport-https curl

# Add Caddy repository
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor --batch --yes -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list
chmod o+r /usr/share/keyrings/caddy-stable-archive-keyring.gpg
chmod o+r /etc/apt/sources.list.d/caddy-stable.list

apt-get update
apt-get install -y caddy

# Add plugins only if not already present
if ! caddy list-modules | grep -q "dns.providers.cloudflare"; then
    caddy add-package github.com/caddy-dns/cloudflare
fi

if ! caddy list-modules | grep -q "layer4"; then
    caddy add-package github.com/mholt/caddy-l4
fi