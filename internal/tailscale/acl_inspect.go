// 文件职责：解析 Tailscale NetMap PacketFilter 并评估本地通告子网是否已被云端 ACL 放行。
package tailscale

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

const (
	// ACLStatusAllowed 表示云端 ACL PacketFilter 已完整放行目标子网的全部端口。
	ACLStatusAllowed = "allowed"
	// ACLStatusPartial 表示云端 ACL 仅放行目标子网内的部分主机或受限端口。
	ACLStatusPartial = "partial"
	// ACLStatusBlocked 表示云端 ACL PacketFilter 中未匹配任何允许目标子网入站的规则。
	ACLStatusBlocked = "blocked"

	maxACLMatchedHints = 6
)

// PacketFilterDst 表示单条 Tailscale PacketFilter 规则允许的目的网段与端口范围。
type PacketFilterDst struct {
	Prefix    netip.Prefix
	PortFirst uint16
	PortLast  uint16
}

// PacketFilterRule 表示解析后的单条 Tailscale PacketFilter 放行规则。
type PacketFilterRule struct {
	SrcCount int
	Dsts     []PacketFilterDst
}

// PacketFilterSnapshot 保存从 NetMap 解析出的云端 ACL 包过滤规则快照。
type PacketFilterSnapshot struct {
	Loaded bool
	Rules  []PacketFilterRule
}

// SubnetACLResult 描述单个本地通告子网在云端 ACL 下的匹配结论。
type SubnetACLResult struct {
	Status        string
	MatchedRanges []string
}

// CloudACLSummary 汇总所有已启用且已获批子网的云端 ACL 检查结果。
type CloudACLSummary struct {
	Checked        bool     `json:"checked"`
	BlockedSubnets []string `json:"blockedSubnets,omitempty"`
	PartialSubnets []string `json:"partialSubnets,omitempty"`
}

func hasNonNullJSON(raw json.RawMessage) bool {
	s := bytes.TrimSpace(raw)
	return len(s) > 0 && !bytes.Equal(s, []byte("null"))
}

func parseFilterPrefixes(raw string) []netip.Prefix {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil
	}
	if s == "*" {
		return []netip.Prefix{
			netip.MustParsePrefix("0.0.0.0/0"),
			netip.MustParsePrefix("::/0"),
		}
	}
	if pfx, err := netip.ParsePrefix(s); err == nil {
		addr := pfx.Addr()
		bits := pfx.Bits()
		if addr.Is4In6() && bits >= 96 {
			addr = addr.Unmap()
			bits -= 96
		}
		return []netip.Prefix{netip.PrefixFrom(addr, bits).Masked()}
	}
	if addr, err := netip.ParseAddr(s); err == nil {
		u := addr.Unmap()
		return []netip.Prefix{netip.PrefixFrom(u, u.BitLen())}
	}
	return nil
}

// ParseNetmapPacketFilter 从 `tailscale debug netmap` JSON 字节中解析 PacketFilter 或回退的 PacketFilterRules。
func ParseNetmapPacketFilter(raw []byte) *PacketFilterSnapshot {
	if len(bytes.TrimSpace(raw)) == 0 {
		return &PacketFilterSnapshot{}
	}
	var top struct {
		PacketFilter      json.RawMessage `json:"PacketFilter"`
		PacketFilterRules json.RawMessage `json:"PacketFilterRules"`
	}
	if json.Unmarshal(raw, &top) != nil {
		return &PacketFilterSnapshot{}
	}

	if hasNonNullJSON(top.PacketFilter) {
		var rawRules []struct {
			Srcs []string `json:"Srcs"`
			Dsts []struct {
				Net   string `json:"Net"`
				Ports struct {
					First uint16 `json:"First"`
					Last  uint16 `json:"Last"`
				} `json:"Ports"`
			} `json:"Dsts"`
		}
		if json.Unmarshal(top.PacketFilter, &rawRules) != nil {
			return &PacketFilterSnapshot{}
		}
		rules := make([]PacketFilterRule, 0, len(rawRules))
		for _, rr := range rawRules {
			rule := PacketFilterRule{SrcCount: len(rr.Srcs)}
			for _, dst := range rr.Dsts {
				for _, pfx := range parseFilterPrefixes(dst.Net) {
					rule.Dsts = append(rule.Dsts, PacketFilterDst{
						Prefix:    pfx,
						PortFirst: dst.Ports.First,
						PortLast:  dst.Ports.Last,
					})
				}
			}
			rules = append(rules, rule)
		}
		return &PacketFilterSnapshot{Loaded: true, Rules: rules}
	}

	if hasNonNullJSON(top.PacketFilterRules) {
		var rawLegacy []struct {
			SrcIPs   []string `json:"SrcIPs"`
			DstPorts []struct {
				IP    string `json:"IP"`
				Ports struct {
					First uint16 `json:"First"`
					Last  uint16 `json:"Last"`
				} `json:"Ports"`
			} `json:"DstPorts"`
		}
		if json.Unmarshal(top.PacketFilterRules, &rawLegacy) != nil {
			return &PacketFilterSnapshot{}
		}
		rules := make([]PacketFilterRule, 0, len(rawLegacy))
		for _, rl := range rawLegacy {
			rule := PacketFilterRule{SrcCount: len(rl.SrcIPs)}
			for _, dst := range rl.DstPorts {
				for _, pfx := range parseFilterPrefixes(dst.IP) {
					rule.Dsts = append(rule.Dsts, PacketFilterDst{
						Prefix:    pfx,
						PortFirst: dst.Ports.First,
						PortLast:  dst.Ports.Last,
					})
				}
			}
			rules = append(rules, rule)
		}
		return &PacketFilterSnapshot{Loaded: true, Rules: rules}
	}

	return &PacketFilterSnapshot{}
}

func formatPortRange(first, last uint16) string {
	if first == last {
		return strconv.Itoa(int(first))
	}
	return fmt.Sprintf("%d-%d", first, last)
}

// EvaluateSubnetACL 评估指定本地子网 CIDR 在云端 PacketFilter 快照中的放行状态。
func EvaluateSubnetACL(snap *PacketFilterSnapshot, cidr string) SubnetACLResult {
	if snap == nil || !snap.Loaded {
		return SubnetACLResult{}
	}
	pfx, err := netip.ParsePrefix(strings.TrimSpace(cidr))
	if err != nil {
		return SubnetACLResult{}
	}
	target := netip.PrefixFrom(pfx.Addr().Unmap(), pfx.Bits()).Masked()

	var matched []string
	seenHints := make(map[string]struct{})
	addHint := func(h string) {
		if len(matched) >= maxACLMatchedHints {
			return
		}
		if _, dup := seenHints[h]; dup {
			return
		}
		seenHints[h] = struct{}{}
		matched = append(matched, h)
	}

	for _, rule := range snap.Rules {
		if rule.SrcCount <= 0 {
			continue
		}
		for _, dst := range rule.Dsts {
			if !dst.Prefix.IsValid() || dst.Prefix.Addr().Is4() != target.Addr().Is4() {
				continue
			}
			isAllPorts := dst.PortFirst == 0 && (dst.PortLast == 65535 || dst.PortLast == 0)

			// 完全覆盖目标网段（本网段或更大超网，如 0.0.0.0/0、192.168.0.0/16）
			if dst.Prefix.Bits() <= target.Bits() && dst.Prefix.Contains(target.Addr()) {
				if isAllPorts {
					return SubnetACLResult{Status: ACLStatusAllowed}
				}
				addHint(target.String() + ":" + formatPortRange(dst.PortFirst, dst.PortLast))
				continue
			}

			// 目标网段内的子集授权（如放行个别 /32 主机或小块子网）
			if dst.Prefix.Bits() > target.Bits() && target.Contains(dst.Prefix.Addr()) {
				if isAllPorts {
					addHint(dst.Prefix.String())
				} else {
					addHint(dst.Prefix.String() + ":" + formatPortRange(dst.PortFirst, dst.PortLast))
				}
			}
		}
	}

	if len(matched) > 0 {
		return SubnetACLResult{
			Status:        ACLStatusPartial,
			MatchedRanges: matched,
		}
	}
	return SubnetACLResult{Status: ACLStatusBlocked}
}

// AnnotateLocalNetworksACL 批量为本地发现网段列表标注云端 ACL 放行状态。
func AnnotateLocalNetworksACL(nets []LocalNetwork, snap *PacketFilterSnapshot) {
	if snap == nil || !snap.Loaded {
		return
	}
	for i := range nets {
		res := EvaluateSubnetACL(snap, nets[i].CIDR)
		nets[i].ACLStatus = res.Status
		nets[i].ACLMatchedRanges = res.MatchedRanges
	}
}

// SummarizeCloudACL 汇总所有已启用且后台已批准子网中被云端 ACL 拦截或部分放行的网段。
func SummarizeCloudACL(nets []LocalNetwork, snap *PacketFilterSnapshot) CloudACLSummary {
	if snap == nil || !snap.Loaded {
		return CloudACLSummary{}
	}
	sum := CloudACLSummary{Checked: true}
	for _, n := range nets {
		if !n.Selected || !n.Approved {
			continue
		}
		switch n.ACLStatus {
		case ACLStatusBlocked:
			sum.BlockedSubnets = append(sum.BlockedSubnets, n.CIDR)
		case ACLStatusPartial:
			sum.PartialSubnets = append(sum.PartialSubnets, n.CIDR)
		}
	}
	return sum
}
