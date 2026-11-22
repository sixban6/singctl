package config

import (
	"maps"
	"slices"
)

func cloneBoolPtr(p *bool) *bool {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

func cloneAnySlice(src []any) []any {
	if src == nil {
		return nil
	}
	dst := make([]any, len(src))
	for i, v := range src {
		dst[i] = cloneAnyValue(v)
	}
	return dst
}

func cloneAnyMap(src map[string]any) map[string]any {
	if src == nil {
		return nil
	}
	dst := make(map[string]any, len(src))
	for k, v := range src {
		dst[k] = cloneAnyValue(v)
	}
	return dst
}

func cloneAnyMapSlice(src []map[string]any) []map[string]any {
	if src == nil {
		return nil
	}
	dst := make([]map[string]any, len(src))
	for i, m := range src {
		dst[i] = cloneAnyMap(m)
	}
	return dst
}

func cloneAnyValue(v any) any {
	switch val := v.(type) {
	case map[string]any:
		return cloneAnyMap(val)
	case []any:
		return cloneAnySlice(val)
	case []string:
		return slices.Clone(val)
	case []int:
		return slices.Clone(val)
	case []bool:
		return slices.Clone(val)
	case map[string]string:
		return maps.Clone(val)
	default:
		return val
	}
}

func cloneWarpRoutingConfig(w WarpRoutingConfig) WarpRoutingConfig {
	out := WarpRoutingConfig{
		Mode:          w.Mode,
		WarpDomains:   slices.Clone(w.WarpDomains),
		WarpCIDRs:     slices.Clone(w.WarpCIDRs),
		DirectDomains: slices.Clone(w.DirectDomains),
		DirectCIDRs:   slices.Clone(w.DirectCIDRs),
	}
	if w.Presets != nil {
		out.Presets = maps.Clone(w.Presets)
	}
	return out
}

// Clone 返回 Config 的完整深拷贝，隔离所有切片、映射及指针字段，确保调用方写入不影响原快照。
func (c *Config) Clone() *Config {
	if c == nil {
		return nil
	}

	out := *c

	if c.Subs != nil {
		out.Subs = make([]Subscription, len(c.Subs))
		for i, sub := range c.Subs {
			out.Subs[i] = sub
			out.Subs[i].Rename = slices.Clone(sub.Rename)
		}
	}

	out.DNS.Enabled = cloneBoolPtr(c.DNS.Enabled)
	out.DNS.Upstreams = slices.Clone(c.DNS.Upstreams)
	out.DNS.Whitelist = slices.Clone(c.DNS.Whitelist)
	out.DNS.Rewrites = slices.Clone(c.DNS.Rewrites)
	out.DNS.DisabledAdRuleSets = slices.Clone(c.DNS.DisabledAdRuleSets)
	out.DNS.SmartDNSFilters = slices.Clone(c.DNS.SmartDNSFilters)

	out.Tailscale.P2PAssist.PayloadFilter = cloneBoolPtr(c.Tailscale.P2PAssist.PayloadFilter)
	if c.Tailscale.P2PAssist.Peers != nil {
		peers := make([]TailscaleP2PPeerConfig, len(c.Tailscale.P2PAssist.Peers))
		for i, peer := range c.Tailscale.P2PAssist.Peers {
			peers[i] = peer
			peers[i].AllowedLANTargets = slices.Clone(peer.AllowedLANTargets)
		}
		out.Tailscale.P2PAssist.Peers = peers
	}

	out.Server.WarpRouting = cloneWarpRoutingConfig(c.Server.WarpRouting)

	out.Watchdog.PreserveManualConfig = cloneBoolPtr(c.Watchdog.PreserveManualConfig)
	out.Watchdog.Failover.Enabled = cloneBoolPtr(c.Watchdog.Failover.Enabled)
	out.Watchdog.Failover.Groups = slices.Clone(c.Watchdog.Failover.Groups)
	out.Watchdog.Failover.ProbeURLs = slices.Clone(c.Watchdog.Failover.ProbeURLs)

	out.Firewall.Whitelist = slices.Clone(c.Firewall.Whitelist)
	out.Firewall.ExtraForeverBan = slices.Clone(c.Firewall.ExtraForeverBan)
	out.Firewall.ProtectedPorts = slices.Clone(c.Firewall.ProtectedPorts)

	out.Audit.Whitelist = slices.Clone(c.Audit.Whitelist)
	out.Audit.PCDNBlock = cloneBoolPtr(c.Audit.PCDNBlock)
	out.Audit.Throttles = slices.Clone(c.Audit.Throttles)

	out.CustomRules.Block = slices.Clone(c.CustomRules.Block)
	if c.CustomRules.Outbounds != nil {
		obs := make([]OutboundRule, len(c.CustomRules.Outbounds))
		for i, ob := range c.CustomRules.Outbounds {
			obs[i] = ob
			obs[i].Outbounds = slices.Clone(ob.Outbounds)
			obs[i].InterruptExistConnections = cloneBoolPtr(ob.InterruptExistConnections)
		}
		out.CustomRules.Outbounds = obs
	}
	out.CustomRules.Route = cloneAnyMapSlice(c.CustomRules.Route)
	out.CustomRules.DNS = cloneAnyMapSlice(c.CustomRules.DNS)

	out.TrafficRouting = c.TrafficRouting.Clone()

	return &out
}
