// 文件职责：定义防火墙 nftables 安全表、最小黑名单表及 systemd/OpenWrt 自启脚本的具名 text/template 渲染器。
package firewall

import (
	"bytes"
	"strconv"
	"strings"
	"text/template"
)

type nftSecurityTemplateData struct {
	ForeverV4       []string
	BanTimeoutDays  int
	WhitelistV4     []string
	WhitelistV6     []string
	ProtectedPorts  []int
	PingLimitPerSec int
	EnableHoneypot  bool
}

var nftTemplateFuncs = template.FuncMap{
	"joinStr": strings.Join,
	"joinForever": func(items []string) string {
		return strings.Join(items, ",\n          ")
	},
	"joinPorts": func(ports []int) string {
		strs := make([]string, len(ports))
		for i, p := range ports {
			strs[i] = strconv.Itoa(p)
		}
		return strings.Join(strs, ",\n            ")
	},
}

var securityNFTTemplate = template.Must(template.New("security_nft").Funcs(nftTemplateFuncs).Parse(`#!/usr/sbin/nft -f

table inet security {

    set blocklist_ip4_forever {
        type ipv4_addr
        flags interval
        auto-merge
        size 65535
        elements = {
          {{joinForever .ForeverV4}}
        }
    }

    set blocklist_ip4 {
        type ipv4_addr
        flags dynamic,timeout
        size 65535
        timeout {{.BanTimeoutDays}}d
    }

    set blocklist_ip6 {
        type ipv6_addr
        flags dynamic,timeout
        size 65535
        timeout {{.BanTimeoutDays}}d
    }

    set whitelist_ip {
        type ipv4_addr
        flags interval
        auto-merge
        elements = { {{joinStr .WhitelistV4 ", "}} }
    }

    set whitelist_ip6 {
        type ipv6_addr
        flags interval
        auto-merge{{if .WhitelistV6}}
        elements = { {{joinStr .WhitelistV6 ", "}} }{{end}}
    }
{{if .EnableHoneypot}}
    set protected_ports {
        type inet_service
        flags interval
        elements = {
            {{joinPorts .ProtectedPorts}}
        }
    }
{{end}}
    chain input {
        type filter hook input priority 0; policy accept;

        # 优先处理已建立的连接，提高性能
        ct state established,related counter accept

        # 允许回环接口和常见虚拟网络接口的流量
        iifname "lo" counter accept
        iifname "tailscale0" counter accept
        iifname "wg*" counter accept
        iifname "tun*" counter accept
        iifname "docker0" counter accept

        # 限制 ICMP (Ping) 频率
        ip protocol icmp icmp type echo-request limit rate {{.PingLimitPerSec}}/second counter accept
        ip6 nexthdr icmpv6 icmpv6 type echo-request limit rate {{.PingLimitPerSec}}/second counter accept

        # 允许来自白名单 IP 的所有连接
        ip saddr @whitelist_ip counter accept
        ip6 saddr @whitelist_ip6 counter accept

        ip saddr @blocklist_ip4_forever log prefix "[NFT] Ban Forever IPv4 (listed): " counter drop

        # 记录并丢弃来自 IPv4 黑名单的连接
        ip saddr @blocklist_ip4 \
            log prefix "[NFT] Blocked IPv4 (listed): " \
            counter drop

        # 记录并丢弃来自 IPv6 黑名单的连接
        ip6 saddr @blocklist_ip6 \
            log prefix "[NFT] Blocked IPv6 (listed): " \
            counter drop{{if .EnableHoneypot}}

        # 记录并处理 IPv4 受保护端口的连接尝试 (TCP & UDP)
        meta l4proto tcp tcp dport @protected_ports \
            log prefix "[NFT] Blocked IPv4 TCP: " \
            add @blocklist_ip4 { ip saddr limit rate 5/minute } \
            counter drop
        meta l4proto udp udp dport @protected_ports \
            log prefix "[NFT] Blocked IPv4 UDP: " \
            add @blocklist_ip4 { ip saddr limit rate 5/minute } \
            counter drop

        # 记录并处理 IPv6 受保护端口的连接尝试 (TCP & UDP)
        meta l4proto tcp tcp dport @protected_ports \
            log prefix "[NFT] Blocked IPv6 TCP: " \
            add @blocklist_ip6 { ip6 saddr limit rate 5/minute } \
            counter drop
        meta l4proto udp udp dport @protected_ports \
            log prefix "[NFT] Blocked IPv6 UDP: " \
            add @blocklist_ip6 { ip6 saddr limit rate 5/minute } \
            counter drop{{end}}
    }

}
`))

var minimalBlocklistNFTTemplate = template.Must(template.New("minimal_blocklist_nft").Funcs(nftTemplateFuncs).Parse(`table inet security {
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
        elements = { {{joinStr .WhitelistV4 ", "}} }
    }
    set whitelist_ip6 {
        type ipv6_addr
        flags interval
        auto-merge
    }
    chain input {
        type filter hook input priority 0; policy accept;
        ct state established,related counter accept
        iifname "lo" counter accept
        iifname "tailscale0" counter accept
        iifname "wg*" counter accept
        iifname "tun*" counter accept
        ip saddr @whitelist_ip counter accept
        ip6 saddr @whitelist_ip6 counter accept
        ip saddr @blocklist_ip4_forever log prefix "[NFT] Ban Forever IPv4 (listed): " counter drop
        ip saddr @blocklist_ip4 log prefix "[NFT] Blocked IPv4 (listed): " counter drop
        ip6 saddr @blocklist_ip6 log prefix "[NFT] Blocked IPv6 (listed): " counter drop
    }
}
`))

var firewallSystemdUnitTemplate = template.Must(template.New("firewall_systemd_unit").Parse(`[Unit]
Description=Singctl Security NFTables Rules
# 确保在网络、内核模块加载及主流防火墙就绪后加载，避免早期 Netlink 未初始化或规则被冲刷
After=network.target systemd-modules-load.service nftables.service firewalld.service ufw.service

[Service]
Type=oneshot
ExecStartPre=-/bin/sh -c 'modprobe nf_tables 2>/dev/null || /sbin/modprobe nf_tables 2>/dev/null || true'
ExecStart=/bin/sh -c 'i=0; while [ "$i" -lt 5 ]; do /usr/sbin/nft -f "{{.ScriptPath}}" && exit 0; modprobe nf_tables 2>/dev/null || /sbin/modprobe nf_tables 2>/dev/null || true; sleep 1; i=$((i + 1)); done; exec /usr/sbin/nft -f "{{.ScriptPath}}"'
ExecStop=-/usr/sbin/nft delete table inet security
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
`))

var firewallOpenWrtInitTemplate = template.Must(template.New("firewall_openwrt_init").Parse(`#!/bin/sh /etc/rc.common

START=99
STOP=10

start() {
	echo "Loading singctl security firewall rules..."
	modprobe nf_tables 2>/dev/null || true
	/usr/sbin/nft -f {{.ScriptPath}}
}

stop() {
	echo "Removing singctl security firewall rules..."
	/usr/sbin/nft delete table inet security 2>/dev/null || true
}
`))

func renderTemplateString(tmpl *template.Template, data any) string {
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return ""
	}
	return buf.String()
}

func renderSecurityNFT(data nftSecurityTemplateData) string {
	return renderTemplateString(securityNFTTemplate, data)
}

// BuildMinimalBlocklistNFT 生成零端口拦截的最小安全黑名单表（仅包含私网/Tailscale 白名单、已建立连接放行与黑名单集合丢包）。
// 供从未执行过 `singctl fw enable` 的主机在触发「一键拉黑」时按需初始化，彻底杜绝任何 SSH 端口误封锁死风险。
func BuildMinimalBlocklistNFT() string {
	return renderTemplateString(minimalBlocklistNFTTemplate, struct {
		WhitelistV4 []string
	}{
		WhitelistV4: defaultWhitelistV4,
	})
}

// BuildFirewallSystemdUnit 生成带 nf_tables 内核模块预加载与开机 Netlink 重试机制的 systemd 单元。
// 解决部分 KVM/Debian VPS 开机早期 nf_tables 模块尚未注册 Netlink 时 `nft -f` 报
// "Unable to initialize Netlink socket: Protocol not supported" 退出导致丢表的问题。
func BuildFirewallSystemdUnit(scriptPath string) string {
	return renderTemplateString(firewallSystemdUnitTemplate, struct {
		ScriptPath string
	}{
		ScriptPath: scriptPath,
	})
}

func renderOpenWrtInitScript(scriptPath string) string {
	return renderTemplateString(firewallOpenWrtInitTemplate, struct {
		ScriptPath string
	}{
		ScriptPath: scriptPath,
	})
}
