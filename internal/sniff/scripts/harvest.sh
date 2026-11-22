export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"
echo "===SINGCTL_TRUSTED==="
if command -v curl >/dev/null 2>&1 && [ -f /etc/sing-box/config.json ]; then
  SECRET=$(sed -n 's/.*"secret"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' /etc/sing-box/config.json | head -n 1)
  if [ -n "$SECRET" ]; then
    curl -fsS -m 1 -H "Authorization: Bearer $SECRET" "http://${TELEMETRY_ADDR}/connections" 2>/dev/null || true
  else
    curl -fsS -m 1 "http://${TELEMETRY_ADDR}/connections" 2>/dev/null || true
  fi
fi
echo ""
echo "===SINGCTL_NFT==="
if command -v nft >/dev/null 2>&1; then
  nft list set inet security blocklist_ip4 2>/dev/null || true
fi
echo "===SINGCTL_F2B==="
if command -v fail2ban-client >/dev/null 2>&1; then
  fail2ban-client status sshd 2>/dev/null || true
  fail2ban-client status recidive 2>/dev/null || true
fi
if [ -r /var/log/fail2ban.log ]; then
  tail -c 32768 /var/log/fail2ban.log 2>/dev/null | grep -E "Found |Ban " || true
fi
echo "===SINGCTL_KERN==="
for f in /var/log/kern.log /var/log/syslog /var/log/messages; do
  if [ -r "$f" ]; then
    tail -c 32768 "$f" 2>/dev/null | grep "\[NFT\]" || true
    break
  fi
done
echo "===SINGCTL_SS==="
if command -v ss >/dev/null 2>&1; then
  ss -tan 2>/dev/null || true
fi
