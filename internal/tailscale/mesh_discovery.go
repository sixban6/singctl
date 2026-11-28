// 文件职责：提供跨拓扑 Tailscale 本机内网/VLAN/下级静态路由网段自动发现与 `tailscale set` 在线无断流同步能力。
package tailscale

import (
	"cmp"
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"singctl/internal/config"
)

const (
	LocalNetPrimaryLAN       = "primary_lan"
	LocalNetVLAN             = "vlan"
	LocalNetDownstreamSubnet = "downstream_subnet"
	LocalNetCustom           = "custom"
)

// VLANHint 描述从宿主机 VLAN 控制器注入的已配置分段元数据（避免 tailscale 包反向依赖 vlan 包）。
type VLANHint struct {
	ID            string
	DisplayName   string
	CIDR          string
	VLANID        int
	SSID          string
	IsPrimaryLAN  bool
	OnlineClients int
}

// LocalNetwork 描述本机自动探测到可参与 Tailscale 组网的本地内网或下级路由子网。
type LocalNetwork struct {
	CIDR            string        `json:"cidr"`
	Kind            string        `json:"kind"`
	Label           string        `json:"label"`
	Interface       string        `json:"interface,omitempty"`
	ViaGateway      string        `json:"viaGateway,omitempty"`
	SSID            string        `json:"ssid,omitempty"`
	VLANID          int           `json:"vlanId,omitempty"`
	OnlineClients   int           `json:"onlineClients,omitempty"`
	Selected         bool          `json:"selected"`
	Approved         bool          `json:"approved"`
	ACLStatus        string        `json:"aclStatus,omitempty"`
	ACLMatchedRanges []string      `json:"aclMatchedRanges,omitempty"`
	Scope            string        `json:"scope,omitempty"`
	SelectedDevices []string      `json:"selectedDevices,omitempty"`
	Devices         []LocalDevice `json:"devices,omitempty"`
	NATHint         string        `json:"natHint,omitempty"`
}

// DiscoverOptions 封装本地网络及单机设备发现所需的显式上下文（支持纯内存单测注入）。
type DiscoverOptions struct {
	PrimaryLANCIDR        string
	ConfiguredSubnets     string
	LiveAdvertisedSubnets string
	ExplicitEmptySubnets  bool
	SelfLANIP             string
	LocalRules            []config.TailscaleLocalSubnetRule
	DeviceNicknames       map[string]string
	VLANHints             []VLANHint
	RouteOutput           string
	LeaseText             string
	NeighText             string
	StaticHostIPs         map[string]bool
	ConntrackText         string
}

// SyncLiveMeshOptions 控制运行中 tailscaled 的在线子网广播与对端路由接收热同步。
type SyncLiveMeshOptions struct {
	BinPath           string
	SubnetsCSV        string
	AcceptRoutes      bool
	IsOpenWrt         bool
	AdvertiseExitNode *bool
	Runner            CmdRunner
}

// DiscoverLocalNetworks 综合主 LAN、VLAN 分段及内核 main 表下级静态路由，去重输出标准化的本地内网清单。
func DiscoverLocalNetworks(ctx context.Context, opts DiscoverOptions) []LocalNetwork {
	selectedSource := strings.TrimSpace(opts.ConfiguredSubnets)
	if selectedSource == "" {
		selectedSource = strings.TrimSpace(opts.LiveAdvertisedSubnets)
	}
	selectedSet, selectedOrder := parseSubnetSelection(selectedSource)
	approvedSet, _ := parseSubnetSelection(opts.LiveAdvertisedSubnets)
	defaultPrimaryIfEmpty := selectedSource == "" && !opts.ExplicitEmptySubnets

	ruleByCIDR := make(map[string]config.TailscaleLocalSubnetRule, len(opts.LocalRules))
	for _, r := range opts.LocalRules {
		if pfx, err := netip.ParsePrefix(strings.TrimSpace(r.CIDR)); err == nil {
			ruleByCIDR[pfx.Masked().String()] = r
		}
	}

	hintByCIDR := make(map[string]VLANHint, len(opts.VLANHints))
	var vlanNonPrimary []VLANHint
	var primaryHint *VLANHint
	for _, h := range opts.VLANHints {
		c, ok := normalizePrivateCIDR(h.CIDR, true)
		if !ok {
			continue
		}
		hCopy := h
		hCopy.CIDR = c
		hintByCIDR[c] = hCopy
		if h.IsPrimaryLAN && primaryHint == nil {
			primaryHint = &hCopy
		} else {
			vlanNonPrimary = append(vlanNonPrimary, hCopy)
		}
	}

	var result []LocalNetwork
	idxByCIDR := make(map[string]int)

	addOrMerge := func(entry LocalNetwork) {
		if entry.CIDR == "" {
			return
		}
		if idx, exists := idxByCIDR[entry.CIDR]; exists {
			cur := &result[idx]
			if cur.Interface == "" {
				cur.Interface = entry.Interface
			}
			if cur.ViaGateway == "" {
				cur.ViaGateway = entry.ViaGateway
				cur.NATHint = entry.NATHint
			}
			if cur.SSID == "" {
				cur.SSID = entry.SSID
			}
			if cur.VLANID == 0 {
				cur.VLANID = entry.VLANID
			}
			if cur.OnlineClients == 0 {
				cur.OnlineClients = entry.OnlineClients
			}
			cur.Approved = cur.Approved || approvedSet[entry.CIDR]
			return
		}
		entry.Selected = selectedSet[entry.CIDR] || (entry.Kind == LocalNetPrimaryLAN && defaultPrimaryIfEmpty)
		entry.Approved = approvedSet[entry.CIDR]
		if rule, hasRule := ruleByCIDR[entry.CIDR]; hasRule {
			if normScope, ok := config.NormalizeTailscaleSubnetScope(rule.Scope); ok {
				entry.Scope = normScope
			} else {
				entry.Scope = config.TailscaleScopeAll
			}
			for _, ip := range rule.Devices {
				if parsed, err := netip.ParseAddr(strings.TrimSpace(ip)); err == nil {
					entry.SelectedDevices = append(entry.SelectedDevices, parsed.Unmap().String())
				}
			}
		} else {
			entry.Scope = config.TailscaleScopeAll
		}
		idxByCIDR[entry.CIDR] = len(result)
		result = append(result, entry)
	}

	primaryCIDR, hasPrimary := normalizePrivateCIDR(opts.PrimaryLANCIDR, false)
	if !hasPrimary && primaryHint != nil {
		primaryCIDR = primaryHint.CIDR
		hasPrimary = true
	}
	if hasPrimary {
		item := LocalNetwork{
			CIDR:  primaryCIDR,
			Kind:  LocalNetPrimaryLAN,
			Label: "本机主网段 (LAN)",
		}
		if h, ok := hintByCIDR[primaryCIDR]; ok {
			item.Label = cmp.Or(strings.TrimSpace(h.DisplayName), item.Label)
			item.SSID = strings.TrimSpace(h.SSID)
			item.VLANID = h.VLANID
			item.OnlineClients = h.OnlineClients
		} else if primaryHint != nil && primaryHint.CIDR == primaryCIDR {
			item.Label = cmp.Or(strings.TrimSpace(primaryHint.DisplayName), item.Label)
			item.SSID = strings.TrimSpace(primaryHint.SSID)
			item.VLANID = primaryHint.VLANID
			item.OnlineClients = primaryHint.OnlineClients
		}
		addOrMerge(item)
	}

	for _, vh := range vlanNonPrimary {
		addOrMerge(LocalNetwork{
			CIDR:          vh.CIDR,
			Kind:          LocalNetVLAN,
			Label:         cmp.Or(strings.TrimSpace(vh.DisplayName), fmt.Sprintf("VLAN %d", vh.VLANID), "VLAN 分段"),
			SSID:          strings.TrimSpace(vh.SSID),
			VLANID:        vh.VLANID,
			OnlineClients: vh.OnlineClients,
		})
	}

	routeText := strings.TrimSpace(opts.RouteOutput)
	if routeText == "" && runtime.GOOS == "linux" {
		rCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		if out, err := exec.CommandContext(rCtx, "ip", "-o", "-4", "route", "show", "table", "main").Output(); err == nil {
			routeText = string(out)
		}
		cancel()
	}
	for _, rn := range parseMainTableLocalRoutes(routeText, hasPrimary || len(idxByCIDR) > 0) {
		addOrMerge(rn)
	}

	for _, customCIDR := range selectedOrder {
		if _, exists := idxByCIDR[customCIDR]; !exists {
			addOrMerge(LocalNetwork{
				CIDR:     customCIDR,
				Kind:     LocalNetCustom,
				Label:    "手动通告网段",
				Selected: true,
			})
		}
	}

	populateNetworkDevices(ctx, result, opts)
	return result
}

// SyncLiveTailscaleMesh 在无需重启 tailscaled 的前提下，通过 `tailscale set` 热更新广播子网与路由接收策略。
func SyncLiveTailscaleMesh(ctx context.Context, opts SyncLiveMeshOptions) error {
	run := opts.Runner
	if run == nil {
		run = defaultCmdRunner
	}
	bin := cmp.Or(strings.TrimSpace(opts.BinPath), FindInstalledTailscaleBin(), "tailscale")
	subnets := strings.TrimSpace(opts.SubnetsCSV)

	args := []string{
		"set",
		"--advertise-routes=" + subnets,
		fmt.Sprintf("--accept-routes=%t", opts.AcceptRoutes),
	}
	if subnets != "" {
		args = append(args, "--snat-subnet-routes=false")
	}
	if opts.IsOpenWrt {
		args = append(args, "--netfilter-mode=off")
	}
	if opts.AdvertiseExitNode != nil {
		args = append(args, fmt.Sprintf("--advertise-exit-node=%t", *opts.AdvertiseExitNode))
	}

	out, err := run(ctx, "", bin, args...)
	if err != nil {
		return fmt.Errorf("tailscale set 同步组网路由失败: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func parseSubnetSelection(rawCSV string) (map[string]bool, []string) {
	selected := make(map[string]bool)
	var order []string
	for part := range strings.SplitSeq(rawCSV, ",") {
		p := strings.TrimSpace(part)
		if p == "" || p == "0.0.0.0/0" || p == "::/0" {
			continue
		}
		pfx, err := netip.ParsePrefix(p)
		if err != nil {
			continue
		}
		norm := netip.PrefixFrom(pfx.Addr().Unmap(), pfx.Bits()).Masked().String()
		if !selected[norm] {
			selected[norm] = true
			order = append(order, norm)
		}
	}
	return selected, order
}

func normalizePrivateCIDR(raw string, allow16 bool) (string, bool) {
	s := strings.TrimSpace(raw)
	if s == "" || !strings.Contains(s, "/") {
		return "", false
	}
	pfx, err := netip.ParsePrefix(s)
	if err != nil {
		return "", false
	}
	addr := pfx.Addr().Unmap()
	if !addr.Is4() {
		return "", false
	}
	pfx = netip.PrefixFrom(addr, pfx.Bits()).Masked()
	if pfx.Bits() < 16 || pfx.Bits() > 30 || !isRFC1918V4(pfx.Addr()) {
		return "", false
	}
	if !allow16 && isWideSummaryRFC1918(pfx) {
		return "", false
	}
	return pfx.String(), true
}

func isRFC1918V4(addr netip.Addr) bool {
	if !addr.IsValid() || !addr.Is4() {
		return false
	}
	b := addr.As4()
	return b[0] == 10 || (b[0] == 172 && b[1]&0xf0 == 16) || (b[0] == 192 && b[1] == 168)
}

func isWideSummaryRFC1918(pfx netip.Prefix) bool {
	if !pfx.Addr().Is4() {
		return false
	}
	b := pfx.Addr().As4()
	return (b[0] == 10 && pfx.Bits() <= 8) ||
		(b[0] == 172 && b[1] == 16 && pfx.Bits() <= 12) ||
		(b[0] == 192 && b[1] == 168 && b[2] == 0 && pfx.Bits() <= 16)
}

func isExcludedRouteDev(dev string) bool {
	d := strings.ToLower(strings.TrimSpace(dev))
	if d == "" || d == "lo" {
		return true
	}
	for _, prefix := range []string{"tailscale", "tun", "tap", "utun", "wg", "docker", "veth", "ppp", "wan", "cni", "flannel", "podman"} {
		if strings.HasPrefix(d, prefix) {
			return true
		}
	}
	return false
}

func parseMainTableLocalRoutes(routeText string, hasPrimaryOrVLAN bool) []LocalNetwork {
	var out []LocalNetwork
	for line := range strings.SplitSeq(routeText, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) == 0 || fields[0] == "default" {
			continue
		}
		var dev, via, scope string
		for i := 1; i+1 < len(fields); i++ {
			switch fields[i] {
			case "dev":
				dev = fields[i+1]
			case "via":
				via = fields[i+1]
			case "scope":
				scope = fields[i+1]
			}
		}
		if isExcludedRouteDev(dev) {
			continue
		}
		// 保留直接挂接子网(scope link)，排除 192.168.0.0/16 等汇总黑洞/静态大块路由。
		cidr, ok := normalizePrivateCIDR(fields[0], via == "" && scope == "link")
		if !ok {
			continue
		}

		if via != "" {
			gwAddr, err := netip.ParseAddr(via)
			if err != nil || !isRFC1918V4(gwAddr.Unmap()) {
				continue
			}
			gw := gwAddr.Unmap().String()
			out = append(out, LocalNetwork{
				CIDR:       cidr,
				Kind:       LocalNetDownstreamSubnet,
				Label:      "下级路由子网",
				Interface:  dev,
				ViaGateway: gw,
				NATHint:    fmt.Sprintf("经下级路由 %s 转发（请确认下级路由未对内网做二次 NAT 隔离）", gw),
			})
			continue
		}

		if strings.HasPrefix(strings.ToLower(dev), "docker") || (strings.HasPrefix(strings.ToLower(dev), "br-") && dev != "br-lan") {
			// 非 UCI VLAN 记录且未知的独立网桥仅在非容器网段下保留为接口网段。
			if strings.HasPrefix(cidr, "172.") {
				continue
			}
		}
		kind := LocalNetVLAN
		label := fmt.Sprintf("接口直连网段 (%s)", cmp.Or(dev, "lan"))
		if !hasPrimaryOrVLAN && len(out) == 0 {
			kind = LocalNetPrimaryLAN
			label = "本机主网段 (LAN)"
		}
		out = append(out, LocalNetwork{
			CIDR:      cidr,
			Kind:      kind,
			Label:     label,
			Interface: dev,
		})
	}
	return out
}
