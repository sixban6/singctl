set -e
REPO_URL='{{.RepoURL}}'
if ! command -v singctl >/dev/null 2>&1; then
  ARCH=$(uname -m)
  case "$ARCH" in
    x86_64|amd64) PKG="singctl-linux-amd64.tar.gz" ;;
    aarch64|arm64) PKG="singctl-linux-arm64.tar.gz" ;;
    *) echo "Unsupported arch: $ARCH" >&2; exit 1 ;;
  esac
  TMPD=$(mktemp -d)
  curl -fsSL "${REPO_URL}/releases/latest/download/checksums.txt" -o "${TMPD}/checksums.txt" || true
  curl -fsSL "${REPO_URL}/releases/latest/download/${PKG}" -o "${TMPD}/${PKG}"
  if [ -s "${TMPD}/checksums.txt" ] && command -v sha256sum >/dev/null 2>&1; then
    EXPECTED=$(grep "  ${PKG}$" "${TMPD}/checksums.txt" | awk '{print $1}')
    ACTUAL=$(sha256sum "${TMPD}/${PKG}" | awk '{print $1}')
    if [ -n "$EXPECTED" ] && [ "$EXPECTED" != "$ACTUAL" ]; then
      rm -rf "${TMPD}"
      echo "SHA256 verification failed for ${PKG}" >&2
      exit 1
    fi
  fi
  tar -xzf "${TMPD}/${PKG}" -C "${TMPD}"
  BIN=$(find "${TMPD}" -type f -name singctl | head -n1)
  install -m 0755 "$BIN" /usr/local/bin/singctl
  rm -rf "${TMPD}"
else
  singctl update self >/dev/null 2>&1 || true
fi
mkdir -p /etc/singctl
printf '%s' '{{.CfgB64}}' | base64 -d > /etc/singctl/singctl.yaml
chmod 600 /etc/singctl/singctl.yaml
{{.InstallEnvPrefix}}singctl sr install >/dev/null 2>&1
if command -v systemctl >/dev/null 2>&1; then
  for _i in $(seq 1 30); do
    if systemctl is-active --quiet caddy && systemctl is-active --quiet sing-box; then
      break
    fi
    if systemctl is-active --quiet caddy && ! systemctl is-active --quiet sing-box; then
      if find /var/lib/caddy/.local/share/caddy/certificates -name "*.crt" 2>/dev/null | grep -q .; then
        systemctl restart sing-box >/dev/null 2>&1 || true
      fi
    fi
    sleep 2
  done
  if ! systemctl is-active --quiet caddy; then
    echo "Caddy gateway failed to start after install" >&2
    exit 1
  fi
fi
