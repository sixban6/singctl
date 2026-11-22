// 文件职责：定义 sing-box DNS 与 Route 配置段、规则集及嵌套规则结构体的强类型模型与 Extra 无损编解码器。
package sboption

import (
	"bytes"
	"encoding/json"
)

// DNSOptions 描述 sing-box dns 配置段。
type DNSOptions struct {
	Servers          []DNSServer                `json:"servers,omitzero"`
	Rules            []DNSRule                  `json:"rules,omitzero"`
	Final            string                     `json:"final,omitempty"`
	Strategy         string                     `json:"strategy,omitempty"`
	ClientSubnet     string                     `json:"client_subnet,omitempty"`
	DisableCache     *bool                      `json:"disable_cache,omitempty"`
	DisableExpire    *bool                      `json:"disable_expire,omitempty"`
	IndependentCache *bool                      `json:"independent_cache,omitempty"`
	Optimistic       *bool                      `json:"optimistic,omitempty"`
	Extra            map[string]json.RawMessage `json:"-"`
}

var knownDNSKeys = map[string]bool{
	"servers": true, "rules": true, "final": true, "strategy": true, "client_subnet": true,
	"disable_cache": true, "disable_expire": true, "independent_cache": true, "optimistic": true,
}

func (o *DNSOptions) UnmarshalJSON(data []byte) error {
	type plain DNSOptions
	*o = DNSOptions{}
	return unmarshalEnvelope(data, (*plain)(o), knownDNSKeys, &o.Extra)
}

func (o DNSOptions) MarshalJSON() ([]byte, error) {
	type plain DNSOptions
	return marshalEnvelope(plain(o), knownDNSKeys, o.Extra)
}

// DNSServer 描述单个 DNS 上游解析服务器。
type DNSServer struct {
	Tag        string                     `json:"tag,omitempty"`
	Type       string                     `json:"type,omitempty"`
	Server     string                     `json:"server,omitempty"`
	ServerPort int                        `json:"server_port,omitempty"`
	Path       string                     `json:"path,omitempty"`
	Address    string                     `json:"address,omitempty"`
	Detour     string                     `json:"detour,omitempty"`
	Extra      map[string]json.RawMessage `json:"-"`
}

var knownDNSServerKeys = map[string]bool{
	"tag": true, "type": true, "server": true, "server_port": true, "path": true, "address": true, "detour": true,
}

func (s *DNSServer) UnmarshalJSON(data []byte) error {
	type plain DNSServer
	*s = DNSServer{}
	return unmarshalEnvelope(data, (*plain)(s), knownDNSServerKeys, &s.Extra)
}

func (s DNSServer) MarshalJSON() ([]byte, error) {
	type plain DNSServer
	return marshalEnvelope(plain(s), knownDNSServerKeys, s.Extra)
}

// DNSRule 描述单条 sing-box DNS 路由/拦截/预定义响应规则。
type DNSRule struct {
	Type          string                     `json:"type,omitempty"`
	Mode          string                     `json:"mode,omitempty"`
	Rules         []DNSRule                  `json:"rules,omitzero"`
	Action        string                     `json:"action,omitempty"`
	Server        string                     `json:"server,omitempty"`
	ClashMode     string                     `json:"clash_mode,omitempty"`
	ClientSubnet  string                     `json:"client_subnet,omitempty"`
	Rcode         string                     `json:"rcode,omitempty"`
	Answer        Listable[string]           `json:"answer,omitzero"`
	Strategy      string                     `json:"strategy,omitempty"`
	Invert        *bool                      `json:"invert,omitempty"`
	DisableCache  *bool                      `json:"disable_cache,omitempty"`
	RewriteTTL    *uint32                    `json:"rewrite_ttl,omitempty"`
	RuleSet       Listable[string]           `json:"rule_set,omitzero"`
	Domain        Listable[string]           `json:"domain,omitzero"`
	DomainSuffix  Listable[string]           `json:"domain_suffix,omitzero"`
	DomainKeyword Listable[string]           `json:"domain_keyword,omitzero"`
	DomainRegex   Listable[string]           `json:"domain_regex,omitzero"`
	SourceIPCIDR  Listable[string]           `json:"source_ip_cidr,omitzero"`
	QueryType     Listable[string]           `json:"query_type,omitzero"`
	Extra         map[string]json.RawMessage `json:"-"`
}

var knownDNSRuleKeys = map[string]bool{
	"type": true, "mode": true, "rules": true, "action": true, "server": true,
	"clash_mode": true, "client_subnet": true, "rcode": true, "answer": true, "strategy": true,
	"invert": true, "disable_cache": true, "rewrite_ttl": true, "rule_set": true, "domain": true,
	"domain_suffix": true, "domain_keyword": true, "domain_regex": true,
	"source_ip_cidr": true, "query_type": true,
}

func (r *DNSRule) UnmarshalJSON(data []byte) error {
	type plain DNSRule
	*r = DNSRule{}
	return unmarshalEnvelope(data, (*plain)(r), knownDNSRuleKeys, &r.Extra)
}

func (r DNSRule) MarshalJSON() ([]byte, error) {
	type plain DNSRule
	return marshalEnvelope(plain(r), knownDNSRuleKeys, r.Extra)
}

// Clone 深拷贝 DNSRule（零 JSON 往返）。
func (r DNSRule) Clone() DNSRule {
	cp := r
	if len(r.Rules) > 0 {
		cp.Rules = make([]DNSRule, len(r.Rules))
		for i := range r.Rules {
			cp.Rules[i] = r.Rules[i].Clone()
		}
	}
	if r.Invert != nil {
		cp.Invert = new(*r.Invert)
	}
	if r.DisableCache != nil {
		cp.DisableCache = new(*r.DisableCache)
	}
	if r.RewriteTTL != nil {
		cp.RewriteTTL = new(*r.RewriteTTL)
	}
	cp.Answer = r.Answer.Clone()
	cp.RuleSet = r.RuleSet.Clone()
	cp.Domain = r.Domain.Clone()
	cp.DomainSuffix = r.DomainSuffix.Clone()
	cp.DomainKeyword = r.DomainKeyword.Clone()
	cp.DomainRegex = r.DomainRegex.Clone()
	cp.SourceIPCIDR = r.SourceIPCIDR.Clone()
	cp.QueryType = r.QueryType.Clone()
	cp.Extra = CloneRawMap(r.Extra)
	return cp
}

// ParseDNSRuleMap 将任意规则字典转换为强类型 DNSRule。
func ParseDNSRuleMap(m map[string]any) (DNSRule, error) {
	b, err := json.Marshal(m)
	if err != nil {
		return DNSRule{}, err
	}
	var r DNSRule
	if err := json.Unmarshal(b, &r); err != nil {
		return DNSRule{}, err
	}
	return r, nil
}

// RouteOptions 描述 sing-box route 配置段。
type RouteOptions struct {
	Rules                 []RouteRule                `json:"rules,omitzero"`
	RuleSet               []RuleSet                  `json:"rule_set,omitzero"`
	Final                 string                     `json:"final,omitempty"`
	AutoDetectInterface   *bool                      `json:"auto_detect_interface,omitempty"`
	DefaultMark           int                        `json:"default_mark,omitempty"`
	DefaultHTTPClient     string                     `json:"default_http_client,omitempty"`
	DefaultDomainResolver json.RawMessage            `json:"default_domain_resolver,omitempty"`
	Extra                 map[string]json.RawMessage `json:"-"`
}

var knownRouteKeys = map[string]bool{
	"rules": true, "rule_set": true, "final": true, "auto_detect_interface": true,
	"default_mark": true, "default_http_client": true, "default_domain_resolver": true,
}

func (r *RouteOptions) UnmarshalJSON(data []byte) error {
	type plain RouteOptions
	*r = RouteOptions{}
	return unmarshalEnvelope(data, (*plain)(r), knownRouteKeys, &r.Extra)
}

func (r RouteOptions) MarshalJSON() ([]byte, error) {
	type plain RouteOptions
	return marshalEnvelope(plain(r), knownRouteKeys, r.Extra)
}

// RuleSet 描述 remote / local / inline 规则集声明。
type RuleSet struct {
	Tag            string                     `json:"tag,omitempty"`
	Type           string                     `json:"type,omitempty"`
	Format         string                     `json:"format,omitempty"`
	URL            string                     `json:"url,omitempty"`
	Path           string                     `json:"path,omitempty"`
	DownloadDetour string                     `json:"download_detour,omitempty"`
	HTTPClient     string                     `json:"http_client,omitempty"`
	UpdateInterval string                     `json:"update_interval,omitempty"`
	Rules          json.RawMessage            `json:"rules,omitempty"`
	Extra          map[string]json.RawMessage `json:"-"`
}

var knownRuleSetKeys = map[string]bool{
	"tag": true, "type": true, "format": true, "url": true, "path": true,
	"download_detour": true, "http_client": true, "update_interval": true, "rules": true,
}

func (rs *RuleSet) UnmarshalJSON(data []byte) error {
	type plain RuleSet
	*rs = RuleSet{}
	return unmarshalEnvelope(data, (*plain)(rs), knownRuleSetKeys, &rs.Extra)
}

func (rs RuleSet) MarshalJSON() ([]byte, error) {
	type plain RuleSet
	return marshalEnvelope(plain(rs), knownRuleSetKeys, rs.Extra)
}

// Clone 深拷贝 RuleSet。
func (rs RuleSet) Clone() RuleSet {
	cp := rs
	cp.Rules = bytes.Clone(rs.Rules)
	cp.Extra = CloneRawMap(rs.Extra)
	return cp
}

// RouteRule 描述单条或逻辑嵌套的 sing-box 路由规则。
type RouteRule struct {
	Type          string                     `json:"type,omitempty"`
	Mode          string                     `json:"mode,omitempty"`
	Rules         []RouteRule                `json:"rules,omitzero"`
	Action        string                     `json:"action,omitempty"`
	Outbound      string                     `json:"outbound,omitempty"`
	ClashMode     string                     `json:"clash_mode,omitempty"`
	Invert        *bool                      `json:"invert,omitempty"`
	IPIsPrivate   *bool                      `json:"ip_is_private,omitempty"`
	Network       Listable[string]           `json:"network,omitzero"`
	Protocol      Listable[string]           `json:"protocol,omitzero"`
	Port          Listable[uint16]           `json:"port,omitzero"`
	PortRange     Listable[string]           `json:"port_range,omitzero"`
	RuleSet       Listable[string]           `json:"rule_set,omitzero"`
	Domain        Listable[string]           `json:"domain,omitzero"`
	DomainSuffix  Listable[string]           `json:"domain_suffix,omitzero"`
	DomainKeyword Listable[string]           `json:"domain_keyword,omitzero"`
	DomainRegex   Listable[string]           `json:"domain_regex,omitzero"`
	IPCIDR        Listable[string]           `json:"ip_cidr,omitzero"`
	SourceIPCIDR  Listable[string]           `json:"source_ip_cidr,omitzero"`
	Extra         map[string]json.RawMessage `json:"-"`
}

var knownRouteRuleKeys = map[string]bool{
	"type": true, "mode": true, "rules": true, "action": true, "outbound": true,
	"clash_mode": true, "invert": true, "ip_is_private": true, "network": true, "protocol": true,
	"port": true, "port_range": true, "rule_set": true, "domain": true,
	"domain_suffix": true, "domain_keyword": true, "domain_regex": true,
	"ip_cidr": true, "source_ip_cidr": true,
}

func (r *RouteRule) UnmarshalJSON(data []byte) error {
	type plain RouteRule
	*r = RouteRule{}
	return unmarshalEnvelope(data, (*plain)(r), knownRouteRuleKeys, &r.Extra)
}

func (r RouteRule) MarshalJSON() ([]byte, error) {
	type plain RouteRule
	return marshalEnvelope(plain(r), knownRouteRuleKeys, r.Extra)
}

// Clone 深拷贝 RouteRule（零 JSON 往返）。
func (r RouteRule) Clone() RouteRule {
	cp := r
	if len(r.Rules) > 0 {
		cp.Rules = make([]RouteRule, len(r.Rules))
		for i := range r.Rules {
			cp.Rules[i] = r.Rules[i].Clone()
		}
	}
	if r.Invert != nil {
		cp.Invert = new(*r.Invert)
	}
	if r.IPIsPrivate != nil {
		cp.IPIsPrivate = new(*r.IPIsPrivate)
	}
	cp.Network = r.Network.Clone()
	cp.Protocol = r.Protocol.Clone()
	cp.Port = r.Port.Clone()
	cp.PortRange = r.PortRange.Clone()
	cp.RuleSet = r.RuleSet.Clone()
	cp.Domain = r.Domain.Clone()
	cp.DomainSuffix = r.DomainSuffix.Clone()
	cp.DomainKeyword = r.DomainKeyword.Clone()
	cp.DomainRegex = r.DomainRegex.Clone()
	cp.IPCIDR = r.IPCIDR.Clone()
	cp.SourceIPCIDR = r.SourceIPCIDR.Clone()
	cp.Extra = CloneRawMap(r.Extra)
	return cp
}

// ParseRouteRuleMap 将任意规则字典转换为强类型 RouteRule。
func ParseRouteRuleMap(m map[string]any) (RouteRule, error) {
	b, err := json.Marshal(m)
	if err != nil {
		return RouteRule{}, err
	}
	var r RouteRule
	if err := json.Unmarshal(b, &r); err != nil {
		return RouteRule{}, err
	}
	return r, nil
}
