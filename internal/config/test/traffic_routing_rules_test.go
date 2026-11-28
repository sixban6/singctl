// 文件职责：覆盖 TrafficCustomRule 归一化校验、幂等 Upsert/Remove 与深拷贝单测。
package config_test

import (
	"testing"

	"singctl/internal/config"
)

func TestNormalizeTrafficCustomRule(t *testing.T) {
	tests := []struct {
		name      string
		in        config.TrafficCustomRule
		want      config.TrafficCustomRule
		wantError bool
	}{
		{
			name: "domain suffix strips scheme wildcard port and path",
			in: config.TrafficCustomRule{
				Target:    "https://*.Api.Example.com:443/v1/test.",
				MatchType: config.TrafficMatchDomainSuffix,
				Outbound:  "#VPS",
			},
			want: config.TrafficCustomRule{
				Target:    "api.example.com",
				MatchType: config.TrafficMatchDomainSuffix,
				Outbound:  "#VPS",
			},
		},
		{
			name: "exact domain preserves domain match type and lowercases",
			in: config.TrafficCustomRule{
				Target:    "API.Example.com.",
				MatchType: config.TrafficMatchDomain,
				Outbound:  "Proxy",
			},
			want: config.TrafficCustomRule{
				Target:    "api.example.com",
				MatchType: config.TrafficMatchDomain,
				Outbound:  "Proxy",
			},
		},
		{
			name: "bare ipv4 auto normalizes to /32 ip_cidr",
			in: config.TrafficCustomRule{
				Target:   "198.51.100.20",
				Outbound: "DIRECT",
			},
			want: config.TrafficCustomRule{
				Target:    "198.51.100.20/32",
				MatchType: config.TrafficMatchIPCIDR,
				Outbound:  config.TrafficOutboundDirect,
			},
		},
		{
			name: "ipv4 cidr gets masked cleanly",
			in: config.TrafficCustomRule{
				Target:    "198.51.100.5/24",
				MatchType: config.TrafficMatchIPCIDR,
				Outbound:  "🇭🇰 香港",
			},
			want: config.TrafficCustomRule{
				Target:    "198.51.100.0/24",
				MatchType: config.TrafficMatchIPCIDR,
				Outbound:  "🇭🇰 香港",
			},
		},
		{
			name: "ipv6 normalizes to /128 ip_cidr",
			in: config.TrafficCustomRule{
				Target:   "2001:db8::1",
				Outbound: "direct",
			},
			want: config.TrafficCustomRule{
				Target:    "2001:db8::1/128",
				MatchType: config.TrafficMatchIPCIDR,
				Outbound:  config.TrafficOutboundDirect,
			},
		},
		{
			name: "optional single sourceIp normalized",
			in: config.TrafficCustomRule{
				Target:    "example.com",
				MatchType: config.TrafficMatchDomainSuffix,
				Outbound:  "#VPS",
				SourceIP:  "192.168.1.50/32",
			},
			want: config.TrafficCustomRule{
				Target:    "example.com",
				MatchType: config.TrafficMatchDomainSuffix,
				Outbound:  "#VPS",
				SourceIP:  "192.168.1.50",
			},
		},
		{
			name: "rejects empty target",
			in: config.TrafficCustomRule{
				Target:   "",
				Outbound: "#VPS",
			},
			wantError: true,
		},
		{
			name: "rejects empty outbound",
			in: config.TrafficCustomRule{
				Target:   "example.com",
				Outbound: "   ",
			},
			wantError: true,
		},
		{
			name: "rejects shell injection in target",
			in: config.TrafficCustomRule{
				Target:   "example.com;rm -rf /",
				Outbound: "#VPS",
			},
			wantError: true,
		},
		{
			name: "rejects ip_cidr match type with domain target",
			in: config.TrafficCustomRule{
				Target:    "example.com",
				MatchType: config.TrafficMatchIPCIDR,
				Outbound:  "#VPS",
			},
			wantError: true,
		},
		{
			name: "rejects domain match type with ip target",
			in: config.TrafficCustomRule{
				Target:    "198.51.100.20",
				MatchType: config.TrafficMatchDomain,
				Outbound:  "#VPS",
			},
			wantError: true,
		},
		{
			name: "rejects invalid sourceIp",
			in: config.TrafficCustomRule{
				Target:   "example.com",
				Outbound: "#VPS",
				SourceIP: "not-an-ip",
			},
			wantError: true,
		},
		{
			name: "rejects control char in outbound",
			in: config.TrafficCustomRule{
				Target:   "example.com",
				Outbound: "bad\noutbound",
			},
			wantError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := config.NormalizeTrafficCustomRule(tc.in)
			if tc.wantError {
				if err == nil {
					t.Fatalf("expected error, got %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Target != tc.want.Target || got.MatchType != tc.want.MatchType ||
				got.Outbound != tc.want.Outbound || got.SourceIP != tc.want.SourceIP {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestTrafficRoutingConfig_UpsertRemoveCloneAndEmpty(t *testing.T) {
	var tr config.TrafficRoutingConfig
	if !tr.IsEmpty() {
		t.Fatalf("expected empty TrafficRoutingConfig initially")
	}

	r1, err := tr.UpsertRule(config.TrafficCustomRule{
		Target:    "api.example.com",
		MatchType: config.TrafficMatchDomainSuffix,
		Outbound:  "#VPS",
	})
	if err != nil {
		t.Fatalf("UpsertRule r1 failed: %v", err)
	}
	if r1.Target != "api.example.com" || r1.Outbound != "#VPS" || r1.CreatedAt == "" {
		t.Fatalf("unexpected r1: %+v", r1)
	}
	if tr.IsEmpty() {
		t.Fatalf("expected IsEmpty() == false after UpsertRule")
	}

	// Second upsert with same identity updates in place rather than appending duplicate.
	_, err = tr.UpsertRule(config.TrafficCustomRule{
		Target:    "API.Example.com",
		MatchType: config.TrafficMatchDomainSuffix,
		Outbound:  "DIRECT",
	})
	if err != nil {
		t.Fatalf("UpsertRule update failed: %v", err)
	}
	if len(tr.Rules) != 1 || tr.Rules[0].Outbound != config.TrafficOutboundDirect {
		t.Fatalf("expected 1 updated rule with direct, got %+v", tr.Rules)
	}

	// Same target with different sourceIp coexists cleanly.
	_, err = tr.UpsertRule(config.TrafficCustomRule{
		Target:    "api.example.com",
		MatchType: config.TrafficMatchDomainSuffix,
		Outbound:  "#VPS",
		SourceIP:  "192.168.1.50",
	})
	if err != nil {
		t.Fatalf("UpsertRule scoped failed: %v", err)
	}
	if len(tr.Rules) != 2 {
		t.Fatalf("expected 2 coexisting rules, got %+v", tr.Rules)
	}

	// Clone independence
	cloned := tr.Clone()
	cloned.Rules[0].Outbound = "Mutated"
	if tr.Rules[0].Outbound == "Mutated" {
		t.Fatalf("Clone mutated original Rules slice")
	}

	// Remove rules
	if tr.RemoveRule("missing.example.com", config.TrafficMatchDomainSuffix, "") {
		t.Fatalf("expected false when removing absent rule")
	}
	if !tr.RemoveRule("api.example.com", config.TrafficMatchDomainSuffix, "") {
		t.Fatalf("expected true removing global rule")
	}
	if len(tr.Rules) != 1 || tr.Rules[0].SourceIP != "192.168.1.50" {
		t.Fatalf("expected scoped rule to remain, got %+v", tr.Rules)
	}
	if !tr.RemoveRule("api.example.com", config.TrafficMatchDomainSuffix, "192.168.1.50") {
		t.Fatalf("expected true removing scoped rule")
	}
	if !tr.IsEmpty() {
		t.Fatalf("expected IsEmpty() == true after removing all rules, got %+v", tr.Rules)
	}
}
