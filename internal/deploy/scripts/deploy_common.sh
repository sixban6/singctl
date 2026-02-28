#!/bin/bash
set -e

echo "Starting Common deployment (UFW, Sysctl BBR)..."

# 1. Install UFW if not present
if ! command -v ufw &> /dev/null; then
    apt-get update
    apt-get install -y ufw
fi

# 2. Configure UFW Rules
for port in 22 2222 443 8443 52021; do
    echo "Allowing port $port..."
    ufw allow "$port" || true
done

echo "Enabling UFW..."
ufw --force enable || true

# 3. Configure sysctl (BBR and FQ)
echo "Configuring sysctl (TCP BBR and FQ)..."

sysctl_set() {
    local key=$1
    local value=$2
    if grep -q "^$key" /etc/sysctl.conf; then
        sed -i "s/^${key}.*/${key}=${value}/" /etc/sysctl.conf
    else
        echo "${key}=${value}" >> /etc/sysctl.conf
    fi
}

sysctl_set "net.core.default_qdisc" "fq"
sysctl_set "net.ipv4.tcp_congestion_control" "bbr"

echo "Applying sysctl changes..."
sysctl -p || true

echo "Common deployment completed successfully."
