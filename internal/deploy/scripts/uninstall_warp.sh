#!/bin/bash
set -e
set -o pipefail

echo "Starting WARP (wireproxy) uninstallation..."

curl -fsSLO https://gitlab.com/fscarmen/warp/-/raw/main/menu.sh
chmod +x menu.sh

export L=C
if echo "y" | bash ./menu.sh u; then
    echo "WARP (wireproxy) uninstalled successfully via script."
else
    echo "WARP uninstallation script returned an error, proceeding with manual cleanup..."
    systemctl stop wireproxy || true
    systemctl disable wireproxy || true
    rm -f /etc/systemd/system/wireproxy.service
    systemctl daemon-reload || true
    rm -f /usr/local/bin/wireproxy
    rm -rf /etc/wireproxy
    echo "Manual cleanup completed."
fi

rm -f menu.sh
