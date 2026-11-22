// 文件职责：定义浏览器安全 DNS（DoH）旁路检测领域模型与显式依赖注入契约。
package dohprobe

import (
	"context"
	"time"

	"singctl/internal/netdiag"
	"singctl/internal/singbox/clashapi"
)

// ClashConn 表示浏览器安全 DNS 检测所需的一条网关活跃连接摘要。
type ClashConn struct {
	ID        string
	Upload    int64
	Download  int64
	Start     string
	SourceIP  string
	DestIP    string
	DestPort  string
	Host      string
	SniffHost string
	Network   string
	Rule      string
	Chains    []string
}

// EDNSSample 描述浏览器侧单次随机子域探测命中的递归 DNS 出口画像。
type EDNSSample struct {
	DNSIP       string `json:"dnsIp"`
	Country     string `json:"country,omitempty"`
	CountryCode string `json:"countryCode,omitempty"`
	ISP         string `json:"isp,omitempty"`
}

// CheckRequest 描述两阶段（begin / finish）浏览器 DoH 旁路检测请求载荷。
type CheckRequest struct {
	Phase                 string       `json:"phase,omitempty"`
	ProbeID               string       `json:"probeId,omitempty"`
	BrowserSamples        []EDNSSample `json:"browserSamples"`
	BrowserProbeAttempted int          `json:"browserProbeAttempted"`
	BrowserProbeFailed    int          `json:"browserProbeFailed"`
}

// EndpointMatch 描述网关连接表中匹配到的公共 DoH/DoT 活跃连接特征。
type EndpointMatch struct {
	Provider string `json:"provider"`
	Host     string `json:"host,omitempty"`
	DestIP   string `json:"destIp,omitempty"`
	DestPort string `json:"destPort,omitempty"`
	SourceIP string `json:"sourceIp,omitempty"`
	Network  string `json:"network,omitempty"`
	Rule     string `json:"rule,omitempty"`
}

// CheckResponse 描述浏览器 DoH 旁路检测完整诊断结果。
type CheckResponse struct {
	Status            string                      `json:"status"`
	Confidence        string                      `json:"confidence"`
	ProbeID           string                      `json:"probeId,omitempty"`
	IdleLeftoverCount int                         `json:"idleLeftoverCount,omitempty"`
	ClientIP          string                      `json:"clientIp,omitempty"`
	IsLANClient       bool                        `json:"isLanClient"`
	ViaTailscale      bool                        `json:"viaTailscale"`
	DetectedProvider  string                      `json:"detectedProvider,omitempty"`
	MatchedEndpoints  []EndpointMatch             `json:"matchedEndpoints,omitempty"`
	GatewayResolver   *netdiag.DNSResolverProfile `json:"gatewayResolver,omitempty"`
	BrowserResolvers  []EDNSSample                `json:"browserResolvers,omitempty"`
	Signals           []string                    `json:"signals,omitempty"`
	Summary           string                      `json:"summary"`
	Recommendation    string                      `json:"recommendation,omitempty"`
	CheckedAt         string                      `json:"checkedAt"`
}

// Deps 显式注入浏览器 DoH 旁路检测器的运行态依赖（严禁反向依赖控制面或守护进程包）。
type Deps struct {
	ClientIP          string
	PeerIPsForMAC     func(ctx context.Context, clientIP string) []string
	SingBoxRunning    func() bool
	ClashClient       *clashapi.Client
	ClashConnections  func(ctx context.Context) ([]ClashConn, error)
	GatewayEDNSProber func(ctx context.Context) (*netdiag.DNSResolverProfile, error)
	Now               func() time.Time
}

// ClashConnsFromSnapshot 将 clashapi.ConnectionsSnapshot 转换为领域连接摘要切片。
func ClashConnsFromSnapshot(snap clashapi.ConnectionsSnapshot) []ClashConn {
	out := make([]ClashConn, 0, len(snap.Connections))
	for _, c := range snap.Connections {
		out = append(out, ClashConn{
			ID:        c.ID,
			Upload:    c.Upload,
			Download:  c.Download,
			Start:     c.Start,
			SourceIP:  c.Metadata.SourceIP,
			DestIP:    c.Metadata.DestinationIP,
			DestPort:  c.Metadata.DestinationPort,
			Host:      c.Metadata.Host,
			SniffHost: c.Metadata.SniffHost,
			Network:   c.Metadata.Network,
			Rule:      c.Rule,
			Chains:    c.Chains,
		})
	}
	return out
}
