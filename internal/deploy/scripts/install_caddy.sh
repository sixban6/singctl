#!/bin/bash
set -e

# 1. Check if Caddy with both required modules is already present
if command -v caddy >/dev/null 2>&1; then
    if caddy list-modules 2>/dev/null | grep -q "dns.providers.cloudflare" && caddy list-modules 2>/dev/null | grep -q "layer4"; then
        echo "Caddy with cloudflare and layer4 modules is already installed."
        exit 0
    fi
fi

# 2. Try downloading prebuilt custom Caddy binary to prevent OOM on low-spec VPS
ARCH="$(uname -m)"
case "${ARCH}" in
    x86_64) CADDY_ARCH="amd64" ;;
    aarch64|arm64) CADDY_ARCH="arm64" ;;
    *) CADDY_ARCH="" ;;
esac

PREBUILT_SUCCESS=false
if [ -n "${CADDY_ARCH}" ]; then
    CADDY_TAR="caddy-custom-linux-${CADDY_ARCH}.tar.gz"
    DOWNLOAD_URL="https://github.com/sixban6/singctl/releases/latest/download/${CADDY_TAR}"
    if [ -n "${MIRROR_URL}" ]; then
        DOWNLOAD_URL="${MIRROR_URL}/${DOWNLOAD_URL}"
    fi

    echo "Attempting to download prebuilt Caddy binary (${CADDY_ARCH}) from ${DOWNLOAD_URL}..."
    TMP_DIR="$(mktemp -d)"
    if curl -fsSL --connect-timeout 10 -o "${TMP_DIR}/${CADDY_TAR}" "${DOWNLOAD_URL}" 2>/dev/null; then
        if tar -xzf "${TMP_DIR}/${CADDY_TAR}" -C "${TMP_DIR}" caddy 2>/dev/null || tar -xzf "${TMP_DIR}/${CADDY_TAR}" -C "${TMP_DIR}" 2>/dev/null; then
            if [ -f "${TMP_DIR}/caddy" ]; then
                # Ensure base caddy package is installed for systemd and user setup
                apt-get update
                apt-get install -y debian-keyring debian-archive-keyring apt-transport-https curl
                curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor --batch --yes -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg 2>/dev/null || true
                curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list 2>/dev/null || true
                chmod o+r /usr/share/keyrings/caddy-stable-archive-keyring.gpg 2>/dev/null || true
                chmod o+r /etc/apt/sources.list.d/caddy-stable.list 2>/dev/null || true
                apt-get update
                apt-mark unhold caddy || true
                apt-get install -y caddy

                cp "${TMP_DIR}/caddy" /usr/bin/caddy
                chmod 0755 /usr/bin/caddy
                apt-mark hold caddy
                echo "Prebuilt Caddy with Cloudflare & layer4 installed successfully."
                PREBUILT_SUCCESS=true
            fi
        fi
    fi
    rm -rf "${TMP_DIR}"
fi

# 3. Fallback to apt install + caddy add-package if prebuilt download was not used
if [ "${PREBUILT_SUCCESS}" != "true" ]; then
    echo "Falling back to package manager and dynamic caddy module compilation..."
    apt-get update
    apt-get install -y debian-keyring debian-archive-keyring apt-transport-https curl

    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor --batch --yes -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list
    chmod o+r /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    chmod o+r /etc/apt/sources.list.d/caddy-stable.list

    apt-get update
    apt-mark unhold caddy || true
    apt-get install -y caddy

    if ! caddy list-modules 2>/dev/null | grep -q "dns.providers.cloudflare"; then
        caddy add-package github.com/caddy-dns/cloudflare
    fi

    if ! caddy list-modules 2>/dev/null | grep -q "layer4"; then
        caddy add-package github.com/mholt/caddy-l4
    fi

    apt-mark hold caddy
fi
