#!/bin/bash
set -e

setup_caddy_runtime() {
    groupadd --system caddy 2>/dev/null || true
    if ! id -u caddy >/dev/null 2>&1; then
        useradd --system \
            --gid caddy \
            --create-home \
            --home-dir /var/lib/caddy \
            --shell /usr/sbin/nologin \
            --comment "Caddy web server" \
            caddy 2>/dev/null || true
    fi

    mkdir -p /etc/caddy
    mkdir -p /var/lib/caddy
    chown -R caddy:caddy /var/lib/caddy 2>/dev/null || true

    # Remove symlink if previously masked by dpkg postrm
    if [ -L /etc/systemd/system/caddy.service ]; then
        rm -f /etc/systemd/system/caddy.service
    fi

    cat > /etc/systemd/system/caddy.service << 'EOF'
[Unit]
Description=Caddy (Custom build with Cloudflare DNS & Layer4, managed by singctl)
Documentation=https://caddyserver.com/docs/
After=network.target network-online.target
Requires=network-online.target

[Service]
Type=notify
User=caddy
Group=caddy
ExecStart=/usr/bin/caddy run --environ --config /etc/caddy/Caddyfile
ExecReload=/usr/bin/caddy reload --config /etc/caddy/Caddyfile --force
TimeoutStopSec=5s
LimitNOFILE=1048576
PrivateTmp=true
ProtectSystem=full
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload 2>/dev/null || true
    systemctl enable caddy 2>/dev/null || true
}

# 1. Check if Caddy with both required modules is already present
if command -v caddy >/dev/null 2>&1; then
    if caddy list-modules 2>/dev/null | grep -q "dns.providers.cloudflare" && caddy list-modules 2>/dev/null | grep -q "layer4"; then
        setup_caddy_runtime
        echo "Caddy with cloudflare and layer4 modules is already installed."
        exit 0
    fi
fi

if ! command -v curl >/dev/null 2>&1; then
    apt-get update -qq
    apt-get install -y curl ca-certificates tar
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
        DOWNLOAD_URL="${MIRROR_URL%/}/${DOWNLOAD_URL}"
    fi

    echo "Attempting to download prebuilt Caddy binary (${CADDY_ARCH}) from ${DOWNLOAD_URL}..."
    TMP_DIR="$(mktemp -d)"
    if curl -fsSL --connect-timeout 15 -o "${TMP_DIR}/${CADDY_TAR}" "${DOWNLOAD_URL}" 2>/dev/null; then
        if tar -xzf "${TMP_DIR}/${CADDY_TAR}" -C "${TMP_DIR}" caddy 2>/dev/null || tar -xzf "${TMP_DIR}/${CADDY_TAR}" -C "${TMP_DIR}" 2>/dev/null; then
            if [ -f "${TMP_DIR}/caddy" ]; then
                setup_caddy_runtime
                systemctl stop caddy 2>/dev/null || true
                install -m 0755 "${TMP_DIR}/caddy" /usr/bin/caddy
                echo "Prebuilt Caddy with Cloudflare & layer4 installed successfully (standalone, no APT repo)."
                PREBUILT_SUCCESS=true
            fi
        fi
    fi
    rm -rf "${TMP_DIR}"
fi

# 3. Fallback to official Caddy custom build API (still standalone, never registering in APT/dpkg)
if [ "${PREBUILT_SUCCESS}" != "true" ]; then
    if [ -z "${CADDY_ARCH}" ]; then
        echo "Unsupported CPU architecture for custom Caddy build: ${ARCH}" >&2
        exit 1
    fi
    echo "Falling back to official Caddy build server for cloudflare + layer4..."
    TMP_BIN="$(mktemp)"
    API_URL="https://caddyserver.com/api/download?os=linux&arch=${CADDY_ARCH}&p=github.com/caddy-dns/cloudflare&p=github.com/mholt/caddy-l4"
    curl -fsSL --connect-timeout 20 --max-time 300 -o "${TMP_BIN}" "${API_URL}"
    chmod 0755 "${TMP_BIN}"
    if ! "${TMP_BIN}" list-modules 2>/dev/null | grep -q "dns.providers.cloudflare" || ! "${TMP_BIN}" list-modules 2>/dev/null | grep -q "layer4"; then
        rm -f "${TMP_BIN}"
        echo "Downloaded Caddy binary is missing required modules." >&2
        exit 1
    fi
    setup_caddy_runtime
    systemctl stop caddy 2>/dev/null || true
    install -m 0755 "${TMP_BIN}" /usr/bin/caddy
    rm -f "${TMP_BIN}"
fi

# 4. Restore certificates if backup exists and target directory is empty
if [ -d "/var/lib/singctl/caddy_certs_backup" ]; then
    mkdir -p /var/lib/caddy/.local/share/caddy/certificates
    cp -rn /var/lib/singctl/caddy_certs_backup/* /var/lib/caddy/.local/share/caddy/certificates/ 2>/dev/null || true
    chown -R caddy:caddy /var/lib/caddy 2>/dev/null || true
fi

# 5. Ensure /etc/singctl/mtls ca.crt is readable by caddy user while private keys remain 0600 root:root
if [ -d "/etc/singctl" ]; then
    chmod a+x /etc/singctl 2>/dev/null || true
fi
if [ -d "/etc/singctl/mtls" ]; then
    chown root:caddy /etc/singctl/mtls 2>/dev/null || true
    chmod 710 /etc/singctl/mtls 2>/dev/null || true
    if [ -f "/etc/singctl/mtls/ca.crt" ]; then
        chown root:caddy /etc/singctl/mtls/ca.crt 2>/dev/null || true
        chmod 640 /etc/singctl/mtls/ca.crt 2>/dev/null || true
    fi
    for f in client.p12 client.crt client.key; do
        if [ -f "/etc/singctl/mtls/${f}" ]; then
            chown root:root "/etc/singctl/mtls/${f}" 2>/dev/null || true
            chmod 600 "/etc/singctl/mtls/${f}" 2>/dev/null || true
        fi
    done
fi
rm -rf /etc/caddy/mtls 2>/dev/null || true
