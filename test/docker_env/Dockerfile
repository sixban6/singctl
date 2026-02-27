FROM golang:1.25-alpine

RUN apk add --no-cache curl wget iproute2 iptables ethtool procps bash

# Fake lsmod that outputs ip_tunnel (causes false positive with old code)
RUN echo '#!/bin/sh' > /usr/bin/lsmod && \
    echo 'echo "Module                  Size  Used by"' >> /usr/bin/lsmod && \
    echo 'echo "ip_tunnel              32768  1"' >> /usr/bin/lsmod && \
    echo 'echo "tunnel4                16384  1 ip_tunnel"' >> /usr/bin/lsmod && \
    echo 'echo "pppoe                  20480  0"' >> /usr/bin/lsmod && \
    chmod +x /usr/bin/lsmod

# Fake uci command
RUN echo '#!/bin/sh' > /usr/bin/uci && \
    echo 'if [ "$1" = "get" ] && [ "$2" = "network.lan.ipaddr" ]; then echo "192.168.1.1"; exit 0; fi' >> /usr/bin/uci && \
    echo 'if [ "$1" = "get" ] && [ "$2" = "network.lan.netmask" ]; then echo "255.255.255.0"; exit 0; fi' >> /usr/bin/uci && \
    echo 'if [ "$1" = "show" ]; then echo ""; exit 0; fi' >> /usr/bin/uci && \
    echo 'exit 0' >> /usr/bin/uci && \
    chmod +x /usr/bin/uci

# Fake /etc/init.d environment
RUN mkdir -p /etc/init.d /usr/sbin /etc/tailscale /var/run/tailscale /var/lib/tailscale

# Fake openwrt detection files
RUN echo 'ImmortalWrt 23.05.1' > /etc/openwrt_release

# The Go source will be mounted at /app
WORKDIR /app
