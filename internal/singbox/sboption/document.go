// 文件职责：定义 sing-box 顶层 Document 与 Log/Inbound/Outbound/Experimental/Service 强类型骨架及 Extra 无损信封编解码器。
package sboption

import (
	"encoding/json"
	"slices"
)

// Document 表示一份完整的 sing-box 配置文档，核心编译骨架字段强类型可见，
// 其余未知顶层键（如 ntp、certificate）保存在 Extra 中实现 100% 无损往返。
type Document struct {
	Log          *LogOptions                `json:"log,omitempty"`
	DNS          *DNSOptions                `json:"dns,omitempty"`
	Inbounds     []Inbound                  `json:"inbounds,omitzero"`
	Outbounds    []Outbound                 `json:"outbounds,omitzero"`
	Endpoints    []Endpoint                 `json:"endpoints,omitzero"`
	Route        *RouteOptions              `json:"route,omitempty"`
	Experimental *ExperimentalOptions       `json:"experimental,omitempty"`
	Services     []Service                  `json:"services,omitzero"`
	HTTPClients  []HTTPClient               `json:"http_clients,omitzero"`
	Extra        map[string]json.RawMessage `json:"-"`
}

var knownDocumentKeys = map[string]bool{
	"log": true, "dns": true, "inbounds": true, "outbounds": true,
	"endpoints": true, "route": true, "experimental": true, "services": true, "http_clients": true,
}

func (d *Document) UnmarshalJSON(data []byte) error {
	type plain Document
	*d = Document{}
	return unmarshalEnvelope(data, (*plain)(d), knownDocumentKeys, &d.Extra)
}

func (d Document) MarshalJSON() ([]byte, error) {
	type plain Document
	return marshalEnvelope(plain(d), knownDocumentKeys, d.Extra)
}

// ParseDocument 解析 JSON 字节流为保真 Document。
func ParseDocument(raw []byte) (*Document, error) {
	var doc Document
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	return &doc, nil
}

// MarshalCompact 输出紧凑 JSON 字符串。
func (d *Document) MarshalCompact() (string, error) {
	if d == nil {
		return "{}", nil
	}
	b, err := json.Marshal(d)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// MarshalPretty 输出 2 空格缩进的 JSON 字符串。
func (d *Document) MarshalPretty() (string, error) {
	if d == nil {
		return "{}", nil
	}
	b, err := json.Marshal(d)
	if err != nil {
		return "", err
	}
	return PrettyBytes(b)
}

// LogOptions 描述 sing-box log 配置段。
type LogOptions struct {
	Disabled  *bool                      `json:"disabled,omitempty"`
	Level     string                     `json:"level,omitempty"`
	Output    string                     `json:"output,omitempty"`
	Timestamp *bool                      `json:"timestamp,omitempty"`
	Extra     map[string]json.RawMessage `json:"-"`
}

var knownLogKeys = map[string]bool{"disabled": true, "level": true, "output": true, "timestamp": true}

func (o *LogOptions) UnmarshalJSON(data []byte) error {
	type plain LogOptions
	*o = LogOptions{}
	return unmarshalEnvelope(data, (*plain)(o), knownLogKeys, &o.Extra)
}

func (o LogOptions) MarshalJSON() ([]byte, error) {
	type plain LogOptions
	return marshalEnvelope(plain(o), knownLogKeys, o.Extra)
}

// Inbound 描述 sing-box 入站监听骨架（含服务端 TLS/Reality 结构化配置），其余字段保存在 Extra 中。
type Inbound struct {
	Type       string                     `json:"type,omitempty"`
	Tag        string                     `json:"tag,omitempty"`
	Listen     string                     `json:"listen,omitempty"`
	ListenPort int                        `json:"listen_port,omitempty"`
	TLS        *InboundTLSOptions         `json:"tls,omitempty"`
	Extra      map[string]json.RawMessage `json:"-"`
}

var knownInboundKeys = map[string]bool{
	"type": true, "tag": true, "listen": true, "listen_port": true, "tls": true,
}

func (ib *Inbound) UnmarshalJSON(data []byte) error {
	type plain Inbound
	*ib = Inbound{}
	return unmarshalEnvelope(data, (*plain)(ib), knownInboundKeys, &ib.Extra)
}

func (ib Inbound) MarshalJSON() ([]byte, error) {
	type plain Inbound
	return marshalEnvelope(plain(ib), knownInboundKeys, ib.Extra)
}

// InboundTLSOptions 描述入站 TLS 与 Reality 配置骨架。
type InboundTLSOptions struct {
	Enabled         *bool                      `json:"enabled,omitempty"`
	ServerName      string                     `json:"server_name,omitempty"`
	ALPN            Listable[string]           `json:"alpn,omitzero"`
	CertificatePath string                     `json:"certificate_path,omitempty"`
	KeyPath         string                     `json:"key_path,omitempty"`
	Reality         *RealityOptions            `json:"reality,omitempty"`
	Extra           map[string]json.RawMessage `json:"-"`
}

var knownInboundTLSKeys = map[string]bool{
	"enabled": true, "server_name": true, "alpn": true,
	"certificate_path": true, "key_path": true, "reality": true,
}

func (t *InboundTLSOptions) UnmarshalJSON(data []byte) error {
	type plain InboundTLSOptions
	*t = InboundTLSOptions{}
	return unmarshalEnvelope(data, (*plain)(t), knownInboundTLSKeys, &t.Extra)
}

func (t InboundTLSOptions) MarshalJSON() ([]byte, error) {
	type plain InboundTLSOptions
	return marshalEnvelope(plain(t), knownInboundTLSKeys, t.Extra)
}

// RealityOptions 描述服务端 VLESS Reality TLS 子配置。
type RealityOptions struct {
	Enabled    *bool                      `json:"enabled,omitempty"`
	Handshake  *RealityHandshake          `json:"handshake,omitempty"`
	PrivateKey string                     `json:"private_key,omitempty"`
	ShortID    Listable[string]           `json:"short_id,omitzero"`
	Extra      map[string]json.RawMessage `json:"-"`
}

var knownRealityKeys = map[string]bool{
	"enabled": true, "handshake": true, "private_key": true, "short_id": true,
}

func (r *RealityOptions) UnmarshalJSON(data []byte) error {
	type plain RealityOptions
	*r = RealityOptions{}
	return unmarshalEnvelope(data, (*plain)(r), knownRealityKeys, &r.Extra)
}

func (r RealityOptions) MarshalJSON() ([]byte, error) {
	type plain RealityOptions
	return marshalEnvelope(plain(r), knownRealityKeys, r.Extra)
}

// RealityHandshake 描述 Reality 偷取目标握手端点。
type RealityHandshake struct {
	Server     string                     `json:"server,omitempty"`
	ServerPort int                        `json:"server_port,omitempty"`
	Extra      map[string]json.RawMessage `json:"-"`
}

var knownRealityHandshakeKeys = map[string]bool{"server": true, "server_port": true}

func (h *RealityHandshake) UnmarshalJSON(data []byte) error {
	type plain RealityHandshake
	*h = RealityHandshake{}
	return unmarshalEnvelope(data, (*plain)(h), knownRealityHandshakeKeys, &h.Extra)
}

func (h RealityHandshake) MarshalJSON() ([]byte, error) {
	type plain RealityHandshake
	return marshalEnvelope(plain(h), knownRealityHandshakeKeys, h.Extra)
}

// Outbound 描述策略组（selector/urltest）或底层代理节点出站骨架，协议私有字段保存在 Extra 中。
type Outbound struct {
	Type                      string                     `json:"type,omitempty"`
	Tag                       string                     `json:"tag,omitempty"`
	Server                    string                     `json:"server,omitempty"`
	ServerPort                int                        `json:"server_port,omitempty"`
	Outbounds                 []string                   `json:"outbounds,omitzero"`
	Default                   string                     `json:"default,omitempty"`
	URL                       string                     `json:"url,omitempty"`
	Interval                  string                     `json:"interval,omitempty"`
	Tolerance                 int                        `json:"tolerance,omitempty"`
	InterruptExistConnections *bool                      `json:"interrupt_exist_connections,omitempty"`
	Extra                     map[string]json.RawMessage `json:"-"`
}

var knownOutboundKeys = map[string]bool{
	"type": true, "tag": true, "server": true, "server_port": true, "outbounds": true,
	"default": true, "url": true, "interval": true, "tolerance": true, "interrupt_exist_connections": true,
}

func (o *Outbound) UnmarshalJSON(data []byte) error {
	type plain Outbound
	*o = Outbound{}
	return unmarshalEnvelope(data, (*plain)(o), knownOutboundKeys, &o.Extra)
}

func (o Outbound) MarshalJSON() ([]byte, error) {
	type plain Outbound
	return marshalEnvelope(plain(o), knownOutboundKeys, o.Extra)
}

// Clone 深拷贝 Outbound（零 JSON 往返）。
func (o Outbound) Clone() Outbound {
	cp := o
	if o.Outbounds != nil {
		cp.Outbounds = slices.Clone(o.Outbounds)
	}
	if o.InterruptExistConnections != nil {
		cp.InterruptExistConnections = new(*o.InterruptExistConnections)
	}
	cp.Extra = CloneRawMap(o.Extra)
	return cp
}

// Endpoint 描述 sing-box endpoints（如 Tailscale/WireGuard）条目骨架。
type Endpoint struct {
	Type  string                     `json:"type,omitempty"`
	Tag   string                     `json:"tag,omitempty"`
	Extra map[string]json.RawMessage `json:"-"`
}

var knownEndpointKeys = map[string]bool{"type": true, "tag": true}

func (e *Endpoint) UnmarshalJSON(data []byte) error {
	type plain Endpoint
	*e = Endpoint{}
	return unmarshalEnvelope(data, (*plain)(e), knownEndpointKeys, &e.Extra)
}

func (e Endpoint) MarshalJSON() ([]byte, error) {
	type plain Endpoint
	return marshalEnvelope(plain(e), knownEndpointKeys, e.Extra)
}

// ExperimentalOptions 描述 sing-box experimental 配置段。
type ExperimentalOptions struct {
	ClashAPI  *ClashAPIOptions           `json:"clash_api,omitempty"`
	CacheFile *CacheFileOptions          `json:"cache_file,omitempty"`
	Extra     map[string]json.RawMessage `json:"-"`
}

var knownExperimentalKeys = map[string]bool{"clash_api": true, "cache_file": true}

func (e *ExperimentalOptions) UnmarshalJSON(data []byte) error {
	type plain ExperimentalOptions
	*e = ExperimentalOptions{}
	return unmarshalEnvelope(data, (*plain)(e), knownExperimentalKeys, &e.Extra)
}

func (e ExperimentalOptions) MarshalJSON() ([]byte, error) {
	type plain ExperimentalOptions
	return marshalEnvelope(plain(e), knownExperimentalKeys, e.Extra)
}

// ClashAPIOptions 描述 experimental.clash_api 配置段。
type ClashAPIOptions struct {
	ExternalController       string                     `json:"external_controller,omitempty"`
	ExternalUI               string                     `json:"external_ui,omitempty"`
	ExternalUIDownloadURL    string                     `json:"external_ui_download_url,omitempty"`
	ExternalUIDownloadDetour string                     `json:"external_ui_download_detour,omitempty"`
	Secret                   string                     `json:"secret,omitempty"`
	DefaultMode              string                     `json:"default_mode,omitempty"`
	Extra                    map[string]json.RawMessage `json:"-"`
}

var knownClashAPIKeys = map[string]bool{
	"external_controller": true, "external_ui": true,
	"external_ui_download_url": true, "external_ui_download_detour": true,
	"secret": true, "default_mode": true,
}

func (c *ClashAPIOptions) UnmarshalJSON(data []byte) error {
	type plain ClashAPIOptions
	*c = ClashAPIOptions{}
	return unmarshalEnvelope(data, (*plain)(c), knownClashAPIKeys, &c.Extra)
}

func (c ClashAPIOptions) MarshalJSON() ([]byte, error) {
	type plain ClashAPIOptions
	return marshalEnvelope(plain(c), knownClashAPIKeys, c.Extra)
}

// CacheFileOptions 描述 experimental.cache_file 配置段。
type CacheFileOptions struct {
	Enabled     *bool                      `json:"enabled,omitempty"`
	Path        string                     `json:"path,omitempty"`
	CacheID     string                     `json:"cache_id,omitempty"`
	StoreFakeIP *bool                      `json:"store_fakeip,omitempty"`
	StoreRDRC   *bool                      `json:"store_rdrc,omitempty"`
	StoreDNS    *bool                      `json:"store_dns,omitempty"`
	Extra       map[string]json.RawMessage `json:"-"`
}

var knownCacheFileKeys = map[string]bool{
	"enabled": true, "path": true, "cache_id": true,
	"store_fakeip": true, "store_rdrc": true, "store_dns": true,
}

func (c *CacheFileOptions) UnmarshalJSON(data []byte) error {
	type plain CacheFileOptions
	*c = CacheFileOptions{}
	return unmarshalEnvelope(data, (*plain)(c), knownCacheFileKeys, &c.Extra)
}

func (c CacheFileOptions) MarshalJSON() ([]byte, error) {
	type plain CacheFileOptions
	return marshalEnvelope(plain(c), knownCacheFileKeys, c.Extra)
}

// Service 描述 sing-box 1.14+ services 条目骨架。
type Service struct {
	Type      string                     `json:"type,omitempty"`
	Tag       string                     `json:"tag,omitempty"`
	Listen    string                     `json:"listen,omitempty"`
	Secret    string                     `json:"secret,omitempty"`
	Dashboard json.RawMessage            `json:"dashboard,omitempty"`
	Extra     map[string]json.RawMessage `json:"-"`
}

var knownServiceKeys = map[string]bool{"type": true, "tag": true, "listen": true, "secret": true, "dashboard": true}

func (s *Service) UnmarshalJSON(data []byte) error {
	type plain Service
	*s = Service{}
	return unmarshalEnvelope(data, (*plain)(s), knownServiceKeys, &s.Extra)
}

func (s Service) MarshalJSON() ([]byte, error) {
	type plain Service
	return marshalEnvelope(plain(s), knownServiceKeys, s.Extra)
}

// HTTPClient 描述 sing-box 1.14+ http_clients 条目骨架。
type HTTPClient struct {
	Tag    string                     `json:"tag,omitempty"`
	Detour string                     `json:"detour,omitempty"`
	Extra  map[string]json.RawMessage `json:"-"`
}

var knownHTTPClientKeys = map[string]bool{"tag": true, "detour": true}

func (h *HTTPClient) UnmarshalJSON(data []byte) error {
	type plain HTTPClient
	*h = HTTPClient{}
	return unmarshalEnvelope(data, (*plain)(h), knownHTTPClientKeys, &h.Extra)
}

func (h HTTPClient) MarshalJSON() ([]byte, error) {
	type plain HTTPClient
	return marshalEnvelope(plain(h), knownHTTPClientKeys, h.Extra)
}
