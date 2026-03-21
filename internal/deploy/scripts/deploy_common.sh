#!/bin/bash
set -e
set -o pipefail

echo "Starting Common deployment (Firewall, Sysctl BBR, SSH hardening)..."

SSH_PORT="2222"

detect_os() {
    if [ -f /etc/openwrt_release ] || [ -f /etc/openwrt_version ]; then
        echo "openwrt"
        return
    fi

    if [ -f /etc/os-release ]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        case "${ID:-}" in
            ubuntu|debian)
                echo "${ID}"
                return
                ;;
        esac
    fi

    echo "unknown"
}

configure_firewall_debian_like() {
    echo "Configuring firewall via UFW (Debian/Ubuntu)..."

    if ! command -v ufw >/dev/null 2>&1; then
        apt-get update
        apt-get install -y ufw
    fi

    # Remove legacy SSH 22 allow rules if present.
    ufw --force delete allow 22 >/dev/null 2>&1 || true

    for port in "${SSH_PORT}" 443; do
        echo "Allowing port ${port}..."
        ufw allow "${port}" || true
    done

    echo "Enabling UFW..."
    ufw --force enable || true
}

ensure_openwrt_allow_rule() {
    local name="$1"
    local port="$2"
    local proto="$3"

    if uci show firewall | grep -q "name='${name}'"; then
        return 0
    fi

    local section
    section="$(uci add firewall rule)"
    uci -q set "firewall.${section}.name=${name}"
    uci -q set "firewall.${section}.src=wan"
    uci -q set "firewall.${section}.dest_port=${port}"
    uci -q set "firewall.${section}.proto=${proto}"
    uci -q set "firewall.${section}.target=ACCEPT"
}

configure_firewall_openwrt() {
    echo "Configuring firewall via UCI (OpenWrt)..."
    command -v uci >/dev/null 2>&1

    # Remove legacy allow rule for SSH 22 if it exists.
    local old_sections
    old_sections="$(uci show firewall | awk -F= '/name='\''Allow-SSH-22'\''/ {print $1}' | sed 's/\.name$//')"
    if [ -n "${old_sections}" ]; then
        local s
        for s in ${old_sections}; do
            uci -q delete "${s}" || true
        done
    fi

    ensure_openwrt_allow_rule "Allow-SSH-${SSH_PORT}" "${SSH_PORT}" "tcp"
    ensure_openwrt_allow_rule "Allow-HTTPS-443" "443" "tcp udp"

    uci -q commit firewall
    if [ -x /etc/init.d/firewall ]; then
        /etc/init.d/firewall restart
    fi
}

configure_firewall() {
    local os_name="$1"
    case "${os_name}" in
        ubuntu|debian)
            configure_firewall_debian_like
            ;;
        openwrt)
            configure_firewall_openwrt
            ;;
        *)
            echo "WARN: unsupported OS for firewall setup: ${os_name}, skipping firewall config."
            ;;
    esac
}

sysctl_set() {
    local key="$1"
    local value="$2"

    touch /etc/sysctl.conf
    if grep -q "^${key}" /etc/sysctl.conf; then
        sed -i "s/^${key}.*/${key}=${value}/" /etc/sysctl.conf
    else
        echo "${key}=${value}" >> /etc/sysctl.conf
    fi
}

configure_sysctl() {
    echo "Configuring sysctl (TCP BBR and FQ)..."
    sysctl_set "net.core.default_qdisc" "fq"
    sysctl_set "net.ipv4.tcp_congestion_control" "bbr"

    echo "Applying sysctl changes..."
    sysctl -p || true
}

has_authorized_key_openwrt() {
    [ -s /etc/dropbear/authorized_keys ] || [ -s /root/.ssh/authorized_keys ]
}

has_authorized_key_openssh() {
    if [ -s /root/.ssh/authorized_keys ]; then
        return 0
    fi

    if [ -n "${SUDO_USER:-}" ] && [ "${SUDO_USER}" != "root" ]; then
        local user_home
        user_home="$(getent passwd "${SUDO_USER}" | cut -d: -f6 || true)"
        if [ -n "${user_home}" ] && [ -s "${user_home}/.ssh/authorized_keys" ]; then
            return 0
        fi
    fi

    return 1
}

configure_ssh_openwrt() {
    echo "Configuring SSH for OpenWrt (dropbear)..."

    if ! has_authorized_key_openwrt; then
        echo "ERROR: no authorized key found, refuse to disable password authentication."
        return 1
    fi

    local sections
    sections="$(uci show dropbear | awk -F= '/=dropbear$/ {print $1}' | sed 's/^dropbear\.//')"
    if [ -z "${sections}" ]; then
        sections="@dropbear[0]"
    fi

    local sec
    for sec in ${sections}; do
        uci -q set "dropbear.${sec}.Port=${SSH_PORT}"
        uci -q set "dropbear.${sec}.PasswordAuth=off"
        uci -q set "dropbear.${sec}.RootPasswordAuth=off"
    done

    uci -q commit dropbear
    /etc/init.d/dropbear restart
}

configure_ssh_debian_like() {
    echo "Configuring SSH for Debian/Ubuntu (OpenSSH)..."

    if ! has_authorized_key_openssh; then
        echo "ERROR: no authorized key found for root/current sudo user, refuse to disable password authentication."
        return 1
    fi

    mkdir -p /etc/ssh/sshd_config.d

    if ! grep -Eq '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' /etc/ssh/sshd_config; then
        echo "Include /etc/ssh/sshd_config.d/*.conf" >> /etc/ssh/sshd_config
    fi

    # Make sure old active Port directives do not keep SSH on 22.
    # Port is multi-value in sshd, so we neutralize previous Port lines first.
    local conf
    for conf in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf; do
        [ -f "${conf}" ] || continue
        [ "${conf}" = "/etc/ssh/sshd_config.d/99-singctl-hardening.conf" ] && continue
        sed -i -E 's/^[[:space:]]*Port[[:space:]]+[0-9]+/# &/g' "${conf}"
    done

    cat > /etc/ssh/sshd_config.d/99-singctl-hardening.conf <<EOF
Port ${SSH_PORT}
PasswordAuthentication no
PubkeyAuthentication yes
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
EOF

    local sshd_bin
    sshd_bin="$(command -v sshd || true)"
    if [ -z "${sshd_bin}" ]; then
        sshd_bin="/usr/sbin/sshd"
    fi

    "${sshd_bin}" -t

    if command -v systemctl >/dev/null 2>&1; then
        systemctl restart ssh || systemctl restart sshd
    else
        service ssh restart || /etc/init.d/ssh restart || /etc/init.d/sshd restart
    fi
}

harden_ssh_access() {
    local os_name="$1"
    case "${os_name}" in
        openwrt)
            configure_ssh_openwrt
            ;;
        ubuntu|debian)
            configure_ssh_debian_like
            ;;
        *)
            echo "WARN: unsupported OS for SSH hardening: ${os_name}, skipping SSH hardening."
            ;;
    esac
}

verify_ssh_settings() {
    local os_name="$1"
    echo "Verifying SSH settings..."

    case "${os_name}" in
        openwrt)
            uci show dropbear | grep -E "Port=|PasswordAuth=|RootPasswordAuth=" || true
            ;;
        ubuntu|debian)
            local sshd_bin
            sshd_bin="$(command -v sshd || true)"
            if [ -z "${sshd_bin}" ]; then
                sshd_bin="/usr/sbin/sshd"
            fi
            "${sshd_bin}" -T | grep -E "port|passwordauthentication|pubkeyauthentication" || true
            ;;
    esac
}

OS_NAME="$(detect_os)"
echo "Detected OS: ${OS_NAME}"

configure_firewall "${OS_NAME}"
configure_sysctl
echo "Hardening SSH access..."
harden_ssh_access "${OS_NAME}"
verify_ssh_settings "${OS_NAME}"

echo "Common deployment completed successfully."
