// 文件职责：提供 tailscaled Unix Socket LocalAPI 连接池客户端、NetMap 解析与公网候选端点安全过滤。
package tailscale

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"time"

	"singctl/internal/config"
)

const (
	DefaultTailscaledSocket = "/var/run/tailscale/tailscaled.sock"
	maxCandidateIPsPerFam   = 4
)

var (
	cgnatPrefix      = netip.MustParsePrefix("100.64.0.0/10")
	thisNetPrefix    = netip.MustParsePrefix("0.0.0.0/8")
	ietfProtoPrefix  = netip.MustParsePrefix("192.0.0.0/24")
	reservedV4Prefix = netip.MustParsePrefix("240.0.0.0/4")
	nat64Prefix      = netip.MustParsePrefix("64:ff9b::/96")
	discardV6Prefix  = netip.MustParsePrefix("100::/64")
)

// PeerStatus 描述 Tailscale LocalAPI 返回的节点快照。
type PeerStatus struct {
	ID            string    `json:"id"`
	HostName      string    `json:"hostName"`
	DNSName       string    `json:"dnsName"`
	ShortName     string    `json:"shortName"`
	TailscaleIPs  []string  `json:"tailscaleIPs"`
	PrimaryRoutes []string  `json:"primaryRoutes,omitempty"`
	Online        bool      `json:"online"`
	Active        bool      `json:"active"`
	CurAddr       string    `json:"curAddr,omitempty"`
	Relay         string    `json:"relay,omitempty"`
	Addrs         []string  `json:"addrs,omitempty"`
	RxBytes       int64     `json:"rxBytes"`
	TxBytes       int64     `json:"txBytes"`
	LastHandshake time.Time `json:"lastHandshake,omitzero"`
}

// StatusSnapshot 描述 Tailscale Daemon 当前状态与所有对端节点。
type StatusSnapshot struct {
	BackendState string       `json:"backendState"`
	Self         PeerStatus   `json:"self"`
	Peers        []PeerStatus `json:"peers"`
}

// NetMapSnapshot 描述 `tailscale debug netmap` 提取出的候选公网端口映射与云端 ACL 过滤规则快照。
type NetMapSnapshot struct {
	SelfEndpoints []string
	PeerEndpoints map[string][]string
	PacketFilter  *PacketFilterSnapshot
}

// PingResult 描述 LocalAPI DISCO ping 响应。
type PingResult struct {
	IP             string  `json:"IP"`
	Endpoint       string  `json:"Endpoint"`
	DERPRegionCode string  `json:"DERPRegionCode"`
	LatencySeconds float64 `json:"LatencySeconds"`
	Err            string  `json:"Err"`
}

// LocalAPIClient 抽象 Tailscale 后端观测与 DISCO 唤醒操作。
type LocalAPIClient interface {
	Status(ctx context.Context) (*StatusSnapshot, error)
	NetMap(ctx context.Context) (*NetMapSnapshot, error)
	PingDisco(ctx context.Context, peerTSIP string) (*PingResult, error)
}

// UnixLocalAPIClient 通过 Unix socket 直连 tailscaled LocalAPI，并在需要候选公网端点时调用 netmap。
type UnixLocalAPIClient struct {
	SocketPath   string
	TailscaleBin string
	NetMapRunner func(ctx context.Context, binPath string) ([]byte, error)

	clientOnce sync.Once
	httpClient *http.Client
}

var defaultUnixLocalAPIClient = &UnixLocalAPIClient{}

// DefaultLocalAPIClient 返回复用连接池的默认 tailscaled LocalAPI 客户端，避免高频轮询泄漏 Unix Socket。
func DefaultLocalAPIClient() LocalAPIClient {
	return defaultUnixLocalAPIClient
}

func (c *UnixLocalAPIClient) socketPath() string {
	return cmp.Or(strings.TrimSpace(c.SocketPath), DefaultTailscaledSocket)
}

// HTTPClient 返回复用的 Unix Socket HTTP 客户端实例。
func (c *UnixLocalAPIClient) HTTPClient() *http.Client {
	return c.client()
}

func (c *UnixLocalAPIClient) client() *http.Client {
	c.clientOnce.Do(func() {
		sock := c.socketPath()
		tr := &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "unix", sock)
			},
			MaxIdleConns:        4,
			MaxIdleConnsPerHost: 2,
			IdleConnTimeout:     30 * time.Second,
		}
		c.httpClient = &http.Client{
			Transport: tr,
			Timeout:   8 * time.Second,
		}
	})
	return c.httpClient
}

func resolveTailscaleBin(explicit string) string {
	if s := strings.TrimSpace(explicit); s != "" {
		return s
	}
	for _, candidate := range []string{"/usr/sbin/tailscale", "/usr/bin/tailscale", "/usr/local/bin/tailscale"} {
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	if p, err := exec.LookPath("tailscale"); err == nil {
		return p
	}
	return "tailscale"
}

type rawLocalPeer struct {
	ID            string    `json:"ID"`
	HostName      string    `json:"HostName"`
	DNSName       string    `json:"DNSName"`
	TailscaleIPs  []string  `json:"TailscaleIPs"`
	PrimaryRoutes []string  `json:"PrimaryRoutes"`
	Online        bool      `json:"Online"`
	Active        bool      `json:"Active"`
	CurAddr       string    `json:"CurAddr"`
	Relay         string    `json:"Relay"`
	Addrs         []string  `json:"Addrs"`
	RxBytes       int64     `json:"RxBytes"`
	TxBytes       int64     `json:"TxBytes"`
	LastHandshake time.Time `json:"LastHandshake"`
}

func toPeerStatus(r rawLocalPeer) PeerStatus {
	dns := strings.TrimSuffix(strings.TrimSpace(r.DNSName), ".")
	short := dns
	if idx := strings.IndexByte(dns, '.'); idx > 0 {
		short = dns[:idx]
	}
	short = cmp.Or(short, strings.TrimSpace(r.HostName), strings.TrimSpace(r.ID))
	return PeerStatus{
		ID:            strings.TrimSpace(r.ID),
		HostName:      strings.TrimSpace(r.HostName),
		DNSName:       dns,
		ShortName:     short,
		TailscaleIPs:  slices.Clone(r.TailscaleIPs),
		PrimaryRoutes: slices.Clone(r.PrimaryRoutes),
		Online:        r.Online,
		Active:        r.Active,
		CurAddr:       strings.TrimSpace(r.CurAddr),
		Relay:         strings.TrimSpace(r.Relay),
		Addrs:         slices.Clone(r.Addrs),
		RxBytes:       r.RxBytes,
		TxBytes:       r.TxBytes,
		LastHandshake: r.LastHandshake,
	}
}

func (c *UnixLocalAPIClient) Status(ctx context.Context) (*StatusSnapshot, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://local-tailscaled.sock/localapi/v0/status", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("localapi status: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, fmt.Errorf("read localapi status: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("localapi status http %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var raw struct {
		BackendState string                  `json:"BackendState"`
		Self         rawLocalPeer            `json:"Self"`
		Peer         map[string]rawLocalPeer `json:"Peer"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("decode localapi status: %w", err)
	}

	peers := make([]PeerStatus, 0, len(raw.Peer))
	for _, p := range raw.Peer {
		peers = append(peers, toPeerStatus(p))
	}
	slices.SortFunc(peers, func(a, b PeerStatus) int {
		if c := cmp.Compare(a.ShortName, b.ShortName); c != 0 {
			return c
		}
		return cmp.Compare(a.ID, b.ID)
	})

	return &StatusSnapshot{
		BackendState: strings.TrimSpace(raw.BackendState),
		Self:         toPeerStatus(raw.Self),
		Peers:        peers,
	}, nil
}

func (c *UnixLocalAPIClient) NetMap(ctx context.Context) (*NetMapSnapshot, error) {
	bin := resolveTailscaleBin(c.TailscaleBin)
	var rawBytes []byte
	var err error
	if c.NetMapRunner != nil {
		rawBytes, err = c.NetMapRunner(ctx, bin)
	} else {
		nmCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		rawBytes, err = exec.CommandContext(nmCtx, bin, "debug", "netmap").Output()
	}
	if err != nil {
		return nil, fmt.Errorf("tailscale debug netmap: %w", err)
	}

	var decoded struct {
		SelfNode struct {
			Endpoints []string `json:"Endpoints"`
		} `json:"SelfNode"`
		Peers []struct {
			StableID  string   `json:"StableID"`
			Endpoints []string `json:"Endpoints"`
		} `json:"Peers"`
	}
	if err := json.Unmarshal(rawBytes, &decoded); err != nil {
		return nil, fmt.Errorf("decode netmap: %w", err)
	}

	snap := &NetMapSnapshot{
		SelfEndpoints: slices.Clone(decoded.SelfNode.Endpoints),
		PeerEndpoints: make(map[string][]string, len(decoded.Peers)),
		PacketFilter:  ParseNetmapPacketFilter(rawBytes),
	}
	for _, p := range decoded.Peers {
		id := strings.TrimSpace(p.StableID)
		if id == "" || len(p.Endpoints) == 0 {
			continue
		}
		snap.PeerEndpoints[id] = slices.Clone(p.Endpoints)
	}
	return snap, nil
}

func (c *UnixLocalAPIClient) PingDisco(ctx context.Context, peerTSIP string) (*PingResult, error) {
	q := url.Values{}
	q.Set("ip", strings.TrimSpace(peerTSIP))
	q.Set("type", "disco")
	u := "http://local-tailscaled.sock/localapi/v0/ping?" + q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("localapi ping: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read localapi ping: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("localapi ping http %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var res PingResult
	if err := json.Unmarshal(body, &res); err != nil {
		return nil, fmt.Errorf("decode localapi ping: %w", err)
	}
	return &res, nil
}

func parseEndpointAddr(raw string) (netip.Addr, bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return netip.Addr{}, false
	}
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr().Unmap(), true
	}
	if addr, err := netip.ParseAddr(s); err == nil {
		return addr.Unmap(), true
	}
	return netip.Addr{}, false
}

func isSafePublicCandidate(addr netip.Addr) bool {
	if !addr.IsValid() || !addr.IsGlobalUnicast() {
		return false
	}
	if addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsMulticast() || addr.IsUnspecified() {
		return false
	}
	if addr.Is4() {
		if cgnatPrefix.Contains(addr) || thisNetPrefix.Contains(addr) || ietfProtoPrefix.Contains(addr) || reservedV4Prefix.Contains(addr) {
			return false
		}
		return true
	}
	if nat64Prefix.Contains(addr) || discardV6Prefix.Contains(addr) {
		return false
	}
	return true
}

// FilterPublicCandidateIPs 严格过滤仅保留全局单播公网 IPv4/IPv6，排除私网、CGNAT、回环、链路本地、ULA 及本机自身公网 IP，
// 并对双栈各去重上限截断为 4 个候选地址，防止恶意或污染端点扩大开放面。
func FilterPublicCandidateIPs(endpoints []string, selfIPs []netip.Addr) (v4 []netip.Addr, v6 []netip.Addr) {
	selfSet := make(map[netip.Addr]struct{}, len(selfIPs))
	for _, ip := range selfIPs {
		if u := ip.Unmap(); u.IsValid() {
			selfSet[u] = struct{}{}
		}
	}

	seen := make(map[netip.Addr]struct{}, len(endpoints))
	for _, ep := range endpoints {
		addr, ok := parseEndpointAddr(ep)
		if !ok || !isSafePublicCandidate(addr) {
			continue
		}
		if _, isSelf := selfSet[addr]; isSelf {
			continue
		}
		if _, dup := seen[addr]; dup {
			continue
		}
		seen[addr] = struct{}{}
		if addr.Is4() {
			if len(v4) < maxCandidateIPsPerFam {
				v4 = append(v4, addr)
			}
		} else if addr.Is6() {
			if len(v6) < maxCandidateIPsPerFam {
				v6 = append(v6, addr)
			}
		}
	}
	return v4, v6
}

// ExtractSelfIPs 汇总本机在 Tailscale 状态、NetMap 及本地网卡上的全部 IP，用于在打洞前排除自身公网地址。
func ExtractSelfIPs(status *StatusSnapshot, netmap *NetMapSnapshot, ifaceAddrs []netip.Addr) []netip.Addr {
	var out []netip.Addr
	seen := make(map[netip.Addr]struct{})
	addAddr := func(a netip.Addr) {
		a = a.Unmap()
		if !a.IsValid() {
			return
		}
		if _, ok := seen[a]; ok {
			return
		}
		seen[a] = struct{}{}
		out = append(out, a)
	}
	for _, a := range ifaceAddrs {
		addAddr(a)
	}
	if status != nil {
		for _, raw := range status.Self.Addrs {
			if a, ok := parseEndpointAddr(raw); ok {
				addAddr(a)
			}
		}
	}
	if netmap != nil {
		for _, raw := range netmap.SelfEndpoints {
			if a, ok := parseEndpointAddr(raw); ok {
				addAddr(a)
			}
		}
	}
	return out
}

// HostInterfaceAddrs 读取宿主机当前所有网卡的 IP 地址（用于排除本机 WAN IP）。
func HostInterfaceAddrs() []netip.Addr {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []netip.Addr
	for _, raw := range addrs {
		var ip net.IP
		switch v := raw.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip == nil {
			continue
		}
		if parsed, ok := netip.AddrFromSlice(ip); ok {
			out = append(out, parsed.Unmap())
		}
	}
	return out
}

// MatchConfiguredPeer 按 ID > TailscaleIP > Name(ShortName/DNSName/HostName) 精确匹配配置项与在线节点，
// 永不匹配本机 Self，避免重名 OpenWrt 设备（如均叫 ImmortalWrt）发生误匹配。
func MatchConfiguredPeer(rule config.TailscaleP2PPeerConfig, peers []PeerStatus, selfID string) (*PeerStatus, bool) {
	ruleID := strings.TrimSpace(rule.ID)
	ruleIP := strings.TrimSpace(rule.TailscaleIP)
	ruleName := strings.TrimSuffix(strings.TrimSpace(rule.Name), ".")

	isSelf := func(p PeerStatus) bool {
		return selfID != "" && p.ID == selfID
	}

	if ruleID != "" {
		for i := range peers {
			if !isSelf(peers[i]) && peers[i].ID == ruleID {
				cp := peers[i]
				return &cp, true
			}
		}
	}
	if ruleIP != "" {
		for i := range peers {
			if isSelf(peers[i]) {
				continue
			}
			if slices.Contains(peers[i].TailscaleIPs, ruleIP) {
				cp := peers[i]
				return &cp, true
			}
		}
	}
	if ruleName != "" {
		for i := range peers {
			if isSelf(peers[i]) {
				continue
			}
			p := peers[i]
			if strings.EqualFold(p.ShortName, ruleName) ||
				strings.EqualFold(strings.TrimSuffix(p.DNSName, "."), ruleName) ||
				strings.EqualFold(p.HostName, ruleName) ||
				strings.EqualFold(p.ID, ruleName) {
				cp := peers[i]
				return &cp, true
			}
		}
	}
	return nil, false
}
