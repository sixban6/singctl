// 文件职责：覆盖 Tailscale NetMap PacketFilter 解析、子网云端 ACL 放行评估与状态摘要单元测试。
package tailscale_test

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"singctl/internal/tailscale"
)

func TestParseNetmapPacketFilter_And_EvaluateSubnetACL(t *testing.T) {
	manyHostDsts := make([]string, 0, 10)
	for i := 10; i < 20; i++ {
		manyHostDsts = append(manyHostDsts, fmt.Sprintf(`{"Net": "192.168.27.%d/32", "Ports": {"First": 0, "Last": 65535}}`, i))
	}

	tests := []struct {
		name              string
		rawJSON           []byte
		cidr              string
		wantLoaded        bool
		wantStatus        string
		wantMatched       []string
		wantMatchedMaxLen int
	}{
		{
			name: "default open ACL allows RFC1918 subnet",
			rawJSON: []byte(`{
				"PacketFilter": [{
					"Caps": [],
					"Srcs": ["0.0.0.0/0"],
					"Dsts": [{"Net": "0.0.0.0/0", "Ports": {"First": 0, "Last": 65535}}]
				}]
			}`),
			cidr:       "192.168.27.0/24",
			wantLoaded: true,
			wantStatus: tailscale.ACLStatusAllowed,
		},
		{
			name: "exact subnet match allows full access",
			rawJSON: []byte(`{
				"PacketFilter": [{
					"Srcs": ["100.64.0.10/32"],
					"Dsts": [{"Net": "192.168.27.0/24", "Ports": {"First": 0, "Last": 65535}}]
				}]
			}`),
			cidr:       "192.168.27.0/24",
			wantLoaded: true,
			wantStatus: tailscale.ACLStatusAllowed,
		},
		{
			name: "supernet match allows child subnet",
			rawJSON: []byte(`{
				"PacketFilter": [{
					"Srcs": ["100.64.0.10/32"],
					"Dsts": [{"Net": "192.168.0.0/16", "Ports": {"First": 0, "Last": 65535}}]
				}]
			}`),
			cidr:       "192.168.27.0/24",
			wantLoaded: true,
			wantStatus: tailscale.ACLStatusAllowed,
		},
		{
			name: "real-world autogroup internet plus other subnets blocks 27.0/24",
			rawJSON: []byte(`{
				"PacketFilter": [{
					"Caps": [],
					"Srcs": ["100.64.0.11/32"],
					"Dsts": [
						{"Net": "100.64.0.10/32", "Ports": {"First": 0, "Last": 65535}},
						{"Net": "192.168.31.0/24", "Ports": {"First": 0, "Last": 65535}},
						{"Net": "192.168.55.0/24", "Ports": {"First": 0, "Last": 65535}},
						{"Net": "0.0.0.0/5", "Ports": {"First": 0, "Last": 65535}},
						{"Net": "192.169.0.0/16", "Ports": {"First": 0, "Last": 65535}}
					]
				}]
			}`),
			cidr:       "192.168.27.0/24",
			wantLoaded: true,
			wantStatus: tailscale.ACLStatusBlocked,
		},
		{
			name: "real-world autogroup internet plus other subnets blocks 29.0/24",
			rawJSON: []byte(`{
				"PacketFilter": [{
					"Srcs": ["100.64.0.11/32"],
					"Dsts": [
						{"Net": "192.168.31.0/24", "Ports": {"First": 0, "Last": 65535}},
						{"Net": "192.168.55.0/24", "Ports": {"First": 0, "Last": 65535}},
						{"Net": "0.0.0.0/5", "Ports": {"First": 0, "Last": 65535}}
					]
				}]
			}`),
			cidr:       "192.168.29.0/24",
			wantLoaded: true,
			wantStatus: tailscale.ACLStatusBlocked,
		},
		{
			name: "real-world autogroup internet plus other subnets allows 31.0/24",
			rawJSON: []byte(`{
				"PacketFilter": [{
					"Srcs": ["100.64.0.11/32"],
					"Dsts": [
						{"Net": "192.168.31.0/24", "Ports": {"First": 0, "Last": 65535}},
						{"Net": "192.168.55.0/24", "Ports": {"First": 0, "Last": 65535}},
						{"Net": "0.0.0.0/5", "Ports": {"First": 0, "Last": 65535}}
					]
				}]
			}`),
			cidr:       "192.168.31.0/24",
			wantLoaded: true,
			wantStatus: tailscale.ACLStatusAllowed,
		},
		{
			name: "partial single-host /32 match returns partial with host hint",
			rawJSON: []byte(`{
				"PacketFilter": [{
					"Srcs": ["100.64.0.11/32"],
					"Dsts": [{"Net": "192.168.27.143/32", "Ports": {"First": 0, "Last": 65535}}]
				}]
			}`),
			cidr:        "192.168.27.0/24",
			wantLoaded:  true,
			wantStatus:  tailscale.ACLStatusPartial,
			wantMatched: []string{"192.168.27.143/32"},
		},
		{
			name: "partial port-restricted full subnet returns partial with port hints",
			rawJSON: []byte(`{
				"PacketFilter": [{
					"Srcs": ["100.64.0.11/32"],
					"Dsts": [
						{"Net": "192.168.27.0/24", "Ports": {"First": 22, "Last": 22}},
						{"Net": "192.168.27.0/24", "Ports": {"First": 443, "Last": 443}}
					]
				}]
			}`),
			cidr:        "192.168.27.0/24",
			wantLoaded:  true,
			wantStatus:  tailscale.ACLStatusPartial,
			wantMatched: []string{"192.168.27.0/24:22", "192.168.27.0/24:443"},
		},
		{
			name: "partial host plus restricted port returns host:port hint",
			rawJSON: []byte(`{
				"PacketFilter": [{
					"Srcs": ["100.64.0.11/32"],
					"Dsts": [{"Net": "192.168.27.143/32", "Ports": {"First": 22, "Last": 22}}]
				}]
			}`),
			cidr:        "192.168.27.0/24",
			wantLoaded:  true,
			wantStatus:  tailscale.ACLStatusPartial,
			wantMatched: []string{"192.168.27.143/32:22"},
		},
		{
			name: "rule with empty Srcs is ignored and subnet is blocked",
			rawJSON: []byte(`{
				"PacketFilter": [{
					"Srcs": [],
					"Dsts": [{"Net": "192.168.27.0/24", "Ports": {"First": 0, "Last": 65535}}]
				}]
			}`),
			cidr:       "192.168.27.0/24",
			wantLoaded: true,
			wantStatus: tailscale.ACLStatusBlocked,
		},
		{
			name:       "explicit empty PacketFilter array means Loaded=true and blocked",
			rawJSON:    []byte(`{"PacketFilter": []}`),
			cidr:       "192.168.27.0/24",
			wantLoaded: true,
			wantStatus: tailscale.ACLStatusBlocked,
		},
		{
			name:       "missing PacketFilter key yields Loaded=false and empty status",
			rawJSON:    []byte(`{"SelfNode": {"StableID": "nSelf"}}`),
			cidr:       "192.168.27.0/24",
			wantLoaded: false,
			wantStatus: "",
		},
		{
			name:       "null PacketFilter yields Loaded=false and empty status",
			rawJSON:    []byte(`{"PacketFilter": null}`),
			cidr:       "192.168.27.0/24",
			wantLoaded: false,
			wantStatus: "",
		},
		{
			name:       "malformed JSON yields Loaded=false and empty status",
			rawJSON:    []byte(`{invalid`),
			cidr:       "192.168.27.0/24",
			wantLoaded: false,
			wantStatus: "",
		},
		{
			name: "fallback PacketFilterRules wildcard allows subnet",
			rawJSON: []byte(`{
				"PacketFilterRules": [{
					"SrcIPs": ["*"],
					"DstPorts": [{"IP": "*", "Ports": {"First": 0, "Last": 65535}}]
				}]
			}`),
			cidr:       "192.168.27.0/24",
			wantLoaded: true,
			wantStatus: tailscale.ACLStatusAllowed,
		},
		{
			name: "fallback PacketFilterRules exact subnet allows subnet",
			rawJSON: []byte(`{
				"PacketFilter": null,
				"PacketFilterRules": [{
					"SrcIPs": ["100.64.0.11"],
					"DstPorts": [{"IP": "192.168.27.0/24", "Ports": {"First": 0, "Last": 65535}}]
				}]
			}`),
			cidr:       "192.168.27.0/24",
			wantLoaded: true,
			wantStatus: tailscale.ACLStatusAllowed,
		},
		{
			name: "fallback PacketFilterRules single IP + port returns partial",
			rawJSON: []byte(`{
				"PacketFilterRules": [{
					"SrcIPs": ["100.64.0.11"],
					"DstPorts": [{"IP": "192.168.27.143", "Ports": {"First": 22, "Last": 22}}]
				}]
			}`),
			cidr:        "192.168.27.0/24",
			wantLoaded:  true,
			wantStatus:  tailscale.ACLStatusPartial,
			wantMatched: []string{"192.168.27.143/32:22"},
		},
		{
			name: "IPv6 subnet does not false-match IPv4 0.0.0.0/0",
			rawJSON: []byte(`{
				"PacketFilter": [{
					"Srcs": ["*"],
					"Dsts": [{"Net": "0.0.0.0/0", "Ports": {"First": 0, "Last": 65535}}]
				}]
			}`),
			cidr:       "fd00:1234::/64",
			wantLoaded: true,
			wantStatus: tailscale.ACLStatusBlocked,
		},
		{
			name: "IPv6 subnet matches ::/0",
			rawJSON: []byte(`{
				"PacketFilter": [{
					"Srcs": ["*"],
					"Dsts": [{"Net": "::/0", "Ports": {"First": 0, "Last": 65535}}]
				}]
			}`),
			cidr:       "fd00:1234::/64",
			wantLoaded: true,
			wantStatus: tailscale.ACLStatusAllowed,
		},
		{
			name: "invalid CIDR returns empty status",
			rawJSON: []byte(`{
				"PacketFilter": [{
					"Srcs": ["0.0.0.0/0"],
					"Dsts": [{"Net": "0.0.0.0/0", "Ports": {"First": 0, "Last": 65535}}]
				}]
			}`),
			cidr:       "192.168.27.0/24;id",
			wantLoaded: true,
			wantStatus: "",
		},
		{
			name: "empty CIDR returns empty status",
			rawJSON: []byte(`{
				"PacketFilter": [{
					"Srcs": ["0.0.0.0/0"],
					"Dsts": [{"Net": "0.0.0.0/0", "Ports": {"First": 0, "Last": 65535}}]
				}]
			}`),
			cidr:       "",
			wantLoaded: true,
			wantStatus: "",
		},
		{
			name: "large number of partial /32 matches caps MatchedRanges at 6",
			rawJSON: []byte(fmt.Sprintf(`{
				"PacketFilter": [{
					"Srcs": ["100.64.0.11/32"],
					"Dsts": [%s]
				}]
			}`, strings.Join(manyHostDsts, ","))),
			cidr:              "192.168.27.0/24",
			wantLoaded:        true,
			wantStatus:        tailscale.ACLStatusPartial,
			wantMatchedMaxLen: 6,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			snap := tailscale.ParseNetmapPacketFilter(tc.rawJSON)
			if snap == nil {
				t.Fatalf("ParseNetmapPacketFilter returned nil")
			}
			if snap.Loaded != tc.wantLoaded {
				t.Fatalf("Loaded = %v, want %v", snap.Loaded, tc.wantLoaded)
			}
			res := tailscale.EvaluateSubnetACL(snap, tc.cidr)
			if res.Status != tc.wantStatus {
				t.Fatalf("Status = %q, want %q (matched=%v)", res.Status, tc.wantStatus, res.MatchedRanges)
			}
			if tc.wantMatched != nil && !reflect.DeepEqual(res.MatchedRanges, tc.wantMatched) {
				t.Fatalf("MatchedRanges = %v, want %v", res.MatchedRanges, tc.wantMatched)
			}
			if tc.wantMatchedMaxLen > 0 && len(res.MatchedRanges) != tc.wantMatchedMaxLen {
				t.Fatalf("len(MatchedRanges) = %d (%v), want %d", len(res.MatchedRanges), res.MatchedRanges, tc.wantMatchedMaxLen)
			}
		})
	}

	if res := tailscale.EvaluateSubnetACL(nil, "192.168.27.0/24"); res.Status != "" {
		t.Fatalf("expected empty status for nil snapshot, got %+v", res)
	}
}

func TestAnnotateLocalNetworksACL_And_SummarizeCloudACL(t *testing.T) {
	rawNetmap := []byte(`{
		"PacketFilter": [{
			"Srcs": ["100.64.0.11/32"],
			"Dsts": [
				{"Net": "192.168.31.0/24", "Ports": {"First": 0, "Last": 65535}},
				{"Net": "192.168.28.10/32", "Ports": {"First": 22, "Last": 22}}
			]
		}]
	}`)
	snap := tailscale.ParseNetmapPacketFilter(rawNetmap)

	nets := []tailscale.LocalNetwork{
		{CIDR: "192.168.27.0/24", Selected: true, Approved: true},
		{CIDR: "192.168.29.0/24", Selected: true, Approved: false}, // not yet approved: not in blockedSubnets
		{CIDR: "192.168.28.0/24", Selected: true, Approved: true},
		{CIDR: "192.168.31.0/24", Selected: true, Approved: true},
		{CIDR: "192.168.99.0/24", Selected: false, Approved: false},
	}

	tailscale.AnnotateLocalNetworksACL(nets, snap)
	if nets[0].ACLStatus != tailscale.ACLStatusBlocked {
		t.Fatalf("nets[0].ACLStatus = %q, want blocked", nets[0].ACLStatus)
	}
	if nets[2].ACLStatus != tailscale.ACLStatusPartial || len(nets[2].ACLMatchedRanges) != 1 || nets[2].ACLMatchedRanges[0] != "192.168.28.10/32:22" {
		t.Fatalf("nets[2] partial mismatch: %+v", nets[2])
	}
	if nets[3].ACLStatus != tailscale.ACLStatusAllowed {
		t.Fatalf("nets[3].ACLStatus = %q, want allowed", nets[3].ACLStatus)
	}

	summary := tailscale.SummarizeCloudACL(nets, snap)
	if !summary.Checked {
		t.Fatalf("expected Checked=true")
	}
	if !reflect.DeepEqual(summary.BlockedSubnets, []string{"192.168.27.0/24"}) {
		t.Fatalf("BlockedSubnets = %v, want [192.168.27.0/24]", summary.BlockedSubnets)
	}
	if !reflect.DeepEqual(summary.PartialSubnets, []string{"192.168.28.0/24"}) {
		t.Fatalf("PartialSubnets = %v, want [192.168.28.0/24]", summary.PartialSubnets)
	}

	// Nil / unloaded snapshot -> Checked=false, empty slices, no mutations.
	unloadedNets := []tailscale.LocalNetwork{{CIDR: "192.168.27.0/24", Selected: true, Approved: true}}
	tailscale.AnnotateLocalNetworksACL(unloadedNets, nil)
	if unloadedNets[0].ACLStatus != "" {
		t.Fatalf("expected empty ACLStatus for nil snap, got %q", unloadedNets[0].ACLStatus)
	}
	emptySummary := tailscale.SummarizeCloudACL(unloadedNets, &tailscale.PacketFilterSnapshot{Loaded: false})
	if emptySummary.Checked || len(emptySummary.BlockedSubnets) != 0 || len(emptySummary.PartialSubnets) != 0 {
		t.Fatalf("expected unchecked summary, got %+v", emptySummary)
	}
}

func TestUnixLocalAPIClient_NetMap_ParsesPacketFilter(t *testing.T) {
	ctx := t.Context()

	t.Run("parses PacketFilter when present", func(t *testing.T) {
		client := &tailscale.UnixLocalAPIClient{
			NetMapRunner: func(ctx context.Context, binPath string) ([]byte, error) {
				return []byte(`{
					"SelfNode": {"Endpoints": ["203.0.113.1:41641"]},
					"Peers": [],
					"PacketFilter": [{
						"Srcs": ["100.64.0.2/32"],
						"Dsts": [{"Net": "192.168.31.0/24", "Ports": {"First": 0, "Last": 65535}}]
					}]
				}`), nil
			},
		}
		nm, err := client.NetMap(ctx)
		if err != nil {
			t.Fatalf("NetMap failed: %v", err)
		}
		if nm.PacketFilter == nil || !nm.PacketFilter.Loaded {
			t.Fatalf("expected Loaded PacketFilter, got %+v", nm.PacketFilter)
		}
		if got := tailscale.EvaluateSubnetACL(nm.PacketFilter, "192.168.31.0/24").Status; got != tailscale.ACLStatusAllowed {
			t.Fatalf("31.0/24 status = %q, want allowed", got)
		}
		if got := tailscale.EvaluateSubnetACL(nm.PacketFilter, "192.168.27.0/24").Status; got != tailscale.ACLStatusBlocked {
			t.Fatalf("27.0/24 status = %q, want blocked", got)
		}
	})

	t.Run("preserves Loaded=false when PacketFilter absent", func(t *testing.T) {
		client := &tailscale.UnixLocalAPIClient{
			NetMapRunner: func(ctx context.Context, binPath string) ([]byte, error) {
				return []byte(`{"SelfNode": {"Endpoints": ["203.0.113.1:41641"]}, "Peers": []}`), nil
			},
		}
		nm, err := client.NetMap(ctx)
		if err != nil {
			t.Fatalf("NetMap failed: %v", err)
		}
		if nm.PacketFilter != nil && nm.PacketFilter.Loaded {
			t.Fatalf("expected Loaded=false when PacketFilter omitted, got %+v", nm.PacketFilter)
		}
	})
}
