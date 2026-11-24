// 文件职责：定义 OpenWrt VLAN 网络分段与安全隔离的纯领域数据模型、场景预设与变更预览契约。
package vlan

const (
	DriverDSA         = "dsa"
	DriverSwconfig    = "swconfig"
	DriverSoftRouter  = "softrouter"
	DriverUnsupported = "unsupported"

	PortModeOff    = "off"
	PortModeAccess = "access"
	PortModeTrunk  = "trunk"

	ProxyModeFollow = "follow"
	ProxyModeDirect = "direct"

	IPv6Off    = "off"
	IPv6Relay  = "relay"
	IPv6Server = "server"

	PresetIoT   = "iot"
	PresetWiFi  = "wifi"
	PresetGuest = "guest"
	PresetWired = "wired"
)

// PortInfo 描述路由器单个物理网口的链路状态与当前 VLAN 分配情况。
type PortInfo struct {
	Name              string   `json:"name"`
	Label             string   `json:"label"`
	SwitchPort        string   `json:"switchPort,omitempty"`
	IsWAN             bool     `json:"isWan"`
	IsMgmt            bool     `json:"isMgmt"`
	LinkUp            bool     `json:"linkUp"`
	SpeedMbps         int      `json:"speedMbps"`
	UntaggedSegmentID string   `json:"untaggedSegmentId,omitempty"`
	TaggedSegmentIDs  []string `json:"taggedSegmentIds,omitempty"`
}

// RadioInfo 描述宿主机探测到的物理无线射频（2.4G / 5G / 6G）。
type RadioInfo struct {
	Name       string `json:"name"`
	Band       string `json:"band"`
	BandLabel  string `json:"bandLabel"`
	Phy        string `json:"phy,omitempty"`
	DriverType string `json:"driverType,omitempty"`
}

// WirelessSSIDInfo 描述宿主机现有无线 SSID 绑定信息（密码永不回传明文）。
type WirelessSSIDInfo struct {
	Section            string `json:"section"`
	Device             string `json:"device"`
	Band               string `json:"band"`
	SSID               string `json:"ssid"`
	Network            string `json:"network"`
	Encryption         string `json:"encryption"`
	Isolate            bool   `json:"isolate"`
	Disabled           bool   `json:"disabled"`
	ManagedBySingCtl   bool   `json:"managedBySingCtl"`
	PasswordConfigured bool   `json:"passwordConfigured"`
}

// WirelessSpec 描述 VLAN 分段关联的无线 SSID 配置。
type WirelessSpec struct {
	Enabled            bool   `json:"enabled"`
	Section            string `json:"section,omitempty"`
	Radio              string `json:"radio,omitempty"`
	Band               string `json:"band,omitempty"`
	SSID               string `json:"ssid,omitempty"`
	Password           string `json:"password,omitempty"`
	PasswordConfigured bool   `json:"passwordConfigured,omitempty"`
	Encryption         string `json:"encryption,omitempty"` // "psk2" | "sae-mixed"
	Isolate            bool   `json:"isolate"`
}

// SecurityPolicy 描述单个 VLAN 分段的跨网访问隔离与发现策略。
type SecurityPolicy struct {
	AllowWAN         bool     `json:"allowWan"`
	BlockRouterMgmt  bool     `json:"blockRouterMgmt"`
	BlockUpstreamLAN bool     `json:"blockUpstreamLan"`
	AllowFromMainLAN bool     `json:"allowFromMainLan"`
	AllowForwardTo   []string `json:"allowForwardTo,omitempty"`
	TrustedSourceIPs []string `json:"trustedSourceIps,omitempty"`
	AllowMDNS        bool     `json:"allowMdns"`
}

// RelationBadge 描述人类可读的跨网访问关系徽标（用于前端“看图即懂”展示）。
type RelationBadge struct {
	Tone string `json:"tone"` // "ok" | "warn" | "danger" | "neutral" | "accent"
	Text string `json:"text"`
}

// Segment 描述一条完整的网络分段（包含主网 lan 与所有自定义/托管 VLAN）。
type Segment struct {
	ID               string            `json:"id"`
	DisplayName      string            `json:"displayName"`
	Preset           string            `json:"preset,omitempty"`
	VLANID           int               `json:"vlanId"`
	Device           string            `json:"device"`
	IPAddr           string            `json:"ipAddr"`
	Netmask          string            `json:"netmask"`
	CIDR             string            `json:"cidr"`
	DHCPStart        int               `json:"dhcpStart"`
	DHCPLimit        int               `json:"dhcpLimit"`
	LeaseTime        string            `json:"leaseTime"`
	IPv6Mode         string            `json:"ipv6Mode"`
	ProxyMode        string            `json:"proxyMode"`
	IsPrimaryLAN     bool              `json:"isPrimaryLan"`
	IsCallerMgmt     bool              `json:"isCallerMgmt"`
	ManagedBySingCtl bool              `json:"managedBySingCtl"`
	OnlineClients    int               `json:"onlineClients"`
	Ports            map[string]string `json:"ports,omitempty"`
	Wireless         *WirelessSpec     `json:"wireless,omitempty"`
	Policy           SecurityPolicy    `json:"policy"`
	Relations        []RelationBadge   `json:"relations,omitempty"`
}

// PresetTemplate 描述面向普通用户的零术语场景预设模板。
type PresetTemplate struct {
	ID              string         `json:"id"`
	Title           string         `json:"title"`
	Tagline         string         `json:"tagline"`
	RecommendedName string         `json:"recommendedName"`
	SuggestedID     string         `json:"suggestedId"`
	SuggestedVLANID int            `json:"suggestedVlanId"`
	SuggestedIPAddr string         `json:"suggestedIpAddr"`
	DefaultIPv6Mode string         `json:"defaultIpv6Mode"`
	DefaultProxy    string         `json:"defaultProxyMode"`
	DefaultWireless WirelessSpec   `json:"defaultWireless"`
	DefaultPolicy   SecurityPolicy `json:"defaultPolicy"`
}

// Overview 汇总宿主机 VLAN 硬件拓扑、物理网口、无线射频、现有网段及推荐预设。
type Overview struct {
	Supported         bool               `json:"supported"`
	UnsupportedReason string             `json:"unsupportedReason,omitempty"`
	Driver            string             `json:"driver"`
	DriverLabel       string             `json:"driverLabel"`
	BoardModel        string             `json:"boardModel,omitempty"`
	WANDevice         string             `json:"wanDevice,omitempty"`
	WANIP             string             `json:"wanIp,omitempty"`
	WANSubnet         string             `json:"wanSubnet,omitempty"`
	CallerIP          string             `json:"callerIp,omitempty"`
	CallerSegmentID   string             `json:"callerSegmentId,omitempty"`
	CallerPort        string             `json:"callerPort,omitempty"`
	Ports             []PortInfo         `json:"ports"`
	Radios            []RadioInfo        `json:"radios"`
	ExistingSSIDs     []WirelessSSIDInfo `json:"existingSsids"`
	Segments          []Segment          `json:"segments"`
	Presets           []PresetTemplate   `json:"presets"`
	Warnings          []string           `json:"warnings,omitempty"`
}

// SaveSegmentRequest 描述新建或更新单个 VLAN 分段的完整输入契约。
type SaveSegmentRequest struct {
	ID              string            `json:"id"`
	DisplayName     string            `json:"displayName,omitempty"`
	Preset          string            `json:"preset,omitempty"`
	VLANID          int               `json:"vlanId"`
	IPAddr          string            `json:"ipAddr"`
	Netmask         string            `json:"netmask,omitempty"`
	DHCPStart       int               `json:"dhcpStart,omitempty"`
	DHCPLimit       int               `json:"dhcpLimit,omitempty"`
	LeaseTime       string            `json:"leaseTime,omitempty"`
	IPv6Mode        string            `json:"ipv6Mode,omitempty"`
	ProxyMode       string            `json:"proxyMode,omitempty"`
	Ports           map[string]string `json:"ports,omitempty"`
	Wireless        *WirelessSpec     `json:"wireless,omitempty"`
	Policy          SecurityPolicy    `json:"policy"`
	AllowModifyMgmt bool              `json:"allowModifyMgmt,omitempty"`
	TTLSec          int               `json:"ttlSec,omitempty"`
}

// PreviewResult 描述 Dry-Run 校验、人话变更摘要与底层 UCI 预览指令。
type PreviewResult struct {
	Valid             bool     `json:"valid"`
	Errors            []string `json:"errors,omitempty"`
	Warnings          []string `json:"warnings,omitempty"`
	PlainSummary      []string `json:"plainSummary,omitempty"`
	UCICommands       []string `json:"uciCommands,omitempty"`
	ProxyBypassCIDRs  []string `json:"proxyBypassCidrs,omitempty"`
	UpstreamRouteHint string   `json:"upstreamRouteHint,omitempty"`
}

// ApplyResult 描述 VLAN 变更应用后的执行结果与 Safe Commit 令牌信息。
type ApplyResult struct {
	OK                bool     `json:"ok"`
	SegmentID         string   `json:"segmentId"`
	PlainSummary      []string `json:"plainSummary,omitempty"`
	UCICommands       []string `json:"uciCommands,omitempty"`
	Warnings          []string `json:"warnings,omitempty"`
	UpstreamRouteHint string   `json:"upstreamRouteHint,omitempty"`
	SafeCommitToken   string   `json:"safeCommitToken,omitempty"`
	SafeCommitTTLSec  int      `json:"safeCommitTtlSec,omitempty"`
}
