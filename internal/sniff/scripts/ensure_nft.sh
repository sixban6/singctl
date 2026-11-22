if ! nft list table inet security >/dev/null 2>&1; then
  modprobe nf_tables 2>/dev/null || /sbin/modprobe nf_tables 2>/dev/null || true
  if [ -f /etc/sing-box/sec_block.nft ] && nft -c -f /etc/sing-box/sec_block.nft >/dev/null 2>&1; then
    nft -f /etc/sing-box/sec_block.nft >/dev/null 2>&1 || true
  fi
  if ! nft list table inet security >/dev/null 2>&1; then
    nft -f - <<'SINGCTL_NFT_EOF'
table inet security {
    set blocklist_ip4_forever {
        type ipv4_addr
        flags interval
        auto-merge
        size 65535
    }
    set blocklist_ip4 {
        type ipv4_addr
        flags dynamic,timeout
        size 65535
        timeout 7d
    }
    set blocklist_ip6 {
        type ipv6_addr
        flags dynamic,timeout
        size 65535
        timeout 7d
    }
    set whitelist_ip {
        type ipv4_addr
        flags interval
        auto-merge
        elements = { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10 }
    }
    chain input {
        type filter hook input priority 0; policy accept;
        ct state established,related counter accept
        iifname "lo" counter accept
        iifname "tailscale0" counter accept
        iifname "wg*" counter accept
        iifname "tun*" counter accept
        ip saddr @whitelist_ip counter accept
        ip saddr @blocklist_ip4_forever log prefix "[NFT] Ban Forever IPv4 (listed): " counter drop
        ip saddr @blocklist_ip4 log prefix "[NFT] Blocked IPv4 (listed): " counter drop
        ip6 saddr @blocklist_ip6 log prefix "[NFT] Blocked IPv6 (listed): " counter drop
    }
}
SINGCTL_NFT_EOF
  fi
  MASTER_IP=$(printf '%s' "${SSH_CLIENT:-}" | awk '{print $1}')
  if [ -n "$MASTER_IP" ]; then
    nft add element inet security whitelist_ip "{ $MASTER_IP }" 2>/dev/null || true
  fi
fi
