// 文件职责：采集本地回环 Clash API 遥测快照、远端目标聚合脱敏、存量长连接精准踢断及配置文件热注入。
package telemetry

import (
	"cmp"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"singctl/internal/common/fsx"
	"singctl/internal/common/sysinfo"
	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/singbox/clashapi"
)

const (
	DefaultControllerAddr = "127.0.0.1:9099"
	secretFileName        = ".telemetry_secret"
	maxHistoryPoints      = 30
	maxTopDomains         = 8
)

// RatePoint represents a single throughput sample for sparkline rendering.
type RatePoint struct {
	Time    string `json:"time"`
	UpBps   int64  `json:"upBps"`
	DownBps int64  `json:"downBps"`
}

// ProtocolBreakdown summarizes traffic and connections per inbound protocol.
type ProtocolBreakdown struct {
	Hy2Connections     int   `json:"hy2Connections"`
	Hy2Bytes           int64 `json:"hy2Bytes"`
	RealityConnections int   `json:"realityConnections"`
	RealityBytes       int64 `json:"realityBytes"`
	OtherConnections   int   `json:"otherConnections"`
	OtherBytes         int64 `json:"otherBytes"`
}

// OutboundBreakdown summarizes split-routing traffic between Direct and WARP.
type OutboundBreakdown struct {
	DirectConnections int   `json:"directConnections"`
	DirectBytes       int64 `json:"directBytes"`
	WarpConnections   int   `json:"warpConnections"`
	WarpBytes         int64 `json:"warpBytes"`
	OtherConnections  int   `json:"otherConnections"`
	OtherBytes        int64 `json:"otherBytes"`
}

// DomainStat summarizes active traffic grouped by destination host.
type DomainStat struct {
	Domain      string `json:"domain"`
	Protocol    string `json:"protocol"`
	Outbound    string `json:"outbound"`
	Rule        string `json:"rule,omitempty"`
	Connections int    `json:"connections"`
	Bytes       int64  `json:"bytes"`
}

// ActiveDestinationGroup 汇总远端目标站点（域名或目标 IP）的实时活跃连接详情，不包含客户端来源 IP。
type ActiveDestinationGroup struct {
	Target        string `json:"target"`
	RootDomain    string `json:"rootDomain"`
	IsIP          bool   `json:"isIP"`
	Protocol      string `json:"protocol"`
	Outbound      string `json:"outbound"` // "WARP" | "Direct"
	Rule          string `json:"rule,omitempty"`
	Connections   int    `json:"connections"`
	UploadBytes   int64  `json:"uploadBytes"`
	DownloadBytes int64  `json:"downloadBytes"`
	TotalBytes    int64  `json:"totalBytes"`
}

// Snapshot represents a point-in-time server telemetry reading.
type Snapshot struct {
	Enabled           bool              `json:"enabled"`
	Reachable         bool              `json:"reachable"`
	ControllerAddr    string            `json:"controllerAddr,omitempty"`
	Timestamp         string            `json:"timestamp"`
	UpBps             int64             `json:"upBps"`
	DownBps           int64             `json:"downBps"`
	UploadTotal       int64             `json:"uploadTotal"`
	DownloadTotal     int64             `json:"downloadTotal"`
	MemoryBytes       int64             `json:"memoryBytes,omitempty"`
	ActiveConnections int               `json:"activeConnections"`
	Protocols         ProtocolBreakdown `json:"protocols"`
	Outbounds         OutboundBreakdown `json:"outbounds"`
	TopDomains        []DomainStat      `json:"topDomains"`
	History           []RatePoint       `json:"history"`
	ActiveClientIPs   []string          `json:"-"`
	Message           string            `json:"message,omitempty"`
}

// EnsureSecret loads or generates a 32-char hex secret in <configDir>/.telemetry_secret.
func EnsureSecret(configDir string) (string, error) {
	configDir = cmp.Or(strings.TrimSpace(configDir), constant.SingBoxConfigDir)
	if configDir == "" {
		return generateRandomHex(16)
	}
	secretPath := filepath.Join(configDir, secretFileName)
	if raw, err := os.ReadFile(secretPath); err == nil {
		s := strings.TrimSpace(string(raw))
		if len(s) >= 16 {
			_ = os.Chmod(secretPath, 0600)
			return s, nil
		}
	}
	sec, err := generateRandomHex(16)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(configDir, 0755); err == nil {
		_ = fsx.WriteAtomic0600(secretPath, []byte(sec+"\n"))
	}
	return sec, nil
}

func generateRandomHex(nBytes int) (string, error) {
	buf := make([]byte, nBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// ResolveConfig inspects sing-box config.json for experimental.clash_api.
func ResolveConfig(singboxConfigPath string) (addr string, secret string, enabled bool) {
	singboxConfigPath = cmp.Or(strings.TrimSpace(singboxConfigPath), constant.SingBoxConfigFile)
	raw, err := os.ReadFile(singboxConfigPath)
	if err != nil {
		return "", "", false
	}
	var parsed struct {
		Experimental struct {
			ClashAPI struct {
				ExternalController string `json:"external_controller"`
				Secret             string `json:"secret"`
			} `json:"clash_api"`
		} `json:"experimental"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return "", "", false
	}
	ctrl := strings.TrimSpace(parsed.Experimental.ClashAPI.ExternalController)
	if ctrl == "" {
		return "", "", false
	}
	return ctrl, strings.TrimSpace(parsed.Experimental.ClashAPI.Secret), true
}

func (c *Collector) resolveConfigSnapshot() (string, string, bool) {
	cfgPath := ""
	if c != nil {
		cfgPath = c.ConfigPath
	}
	cfgPath = cmp.Or(strings.TrimSpace(cfgPath), constant.SingBoxConfigFile)
	info, err := os.Stat(cfgPath)
	if err != nil {
		if c != nil {
			c.cfgMu.Lock()
			c.cachedCfgValid = false
			c.cfgMu.Unlock()
		}
		return "", "", false
	}

	statKey := configStatKey{
		path:    cfgPath,
		size:    info.Size(),
		modNano: info.ModTime().UnixNano(),
	}
	if c != nil {
		c.cfgMu.RLock()
		if c.cachedCfgValid && c.cachedCfgKey == statKey {
			addr, sec, en := c.cachedAddr, c.cachedSecret, c.cachedEnabled
			c.cfgMu.RUnlock()
			return addr, sec, en
		}
		c.cfgMu.RUnlock()

		c.cfgMu.Lock()
		defer c.cfgMu.Unlock()
		if c.cachedCfgValid && c.cachedCfgKey == statKey {
			return c.cachedAddr, c.cachedSecret, c.cachedEnabled
		}
		c.cfgDiskReads.Add(1)
		addr, sec, en := ResolveConfig(cfgPath)
		c.cachedCfgKey = statKey
		c.cachedAddr = addr
		c.cachedSecret = sec
		c.cachedEnabled = en
		c.cachedCfgValid = true
		return addr, sec, en
	}
	return ResolveConfig(cfgPath)
}

// ConfigDiskReads 返回自创建以来实际读取并解析磁盘配置文件的次数。
func (c *Collector) ConfigDiskReads() int64 {
	if c == nil {
		return 0
	}
	return c.cfgDiskReads.Load()
}

// EnsureConfigTelemetry non-destructively injects loopback clash_api telemetry into an existing sing-box config.json.
func EnsureConfigTelemetry(singboxConfigPath string) (changed bool, addr string, secret string, err error) {
	singboxConfigPath = cmp.Or(strings.TrimSpace(singboxConfigPath), constant.SingBoxConfigFile)
	raw, err := os.ReadFile(singboxConfigPath)
	if err != nil {
		return false, "", "", fmt.Errorf("读取 sing-box 配置失败: %w", err)
	}

	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return false, "", "", fmt.Errorf("解析 sing-box 配置失败: %w", err)
	}
	if doc == nil {
		return false, "", "", errors.New("sing-box 配置内容为空")
	}

	exp, _ := doc["experimental"].(map[string]any)
	if exp == nil {
		exp = make(map[string]any)
	}
	clashAPI, _ := exp["clash_api"].(map[string]any)
	if clashAPI != nil {
		existingAddr, _ := clashAPI["external_controller"].(string)
		existingSec, _ := clashAPI["secret"].(string)
		if isLoopbackAddr(existingAddr) && strings.TrimSpace(existingSec) != "" {
			return false, strings.TrimSpace(existingAddr), strings.TrimSpace(existingSec), nil
		}
	}

	sec, err := EnsureSecret(filepath.Dir(singboxConfigPath))
	if err != nil {
		return false, "", "", err
	}

	exp["clash_api"] = map[string]any{
		"external_controller": DefaultControllerAddr,
		"secret":              sec,
	}
	doc["experimental"] = exp

	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return false, "", "", err
	}

	mode := os.FileMode(0600)
	if st, statErr := os.Stat(singboxConfigPath); statErr == nil {
		mode = st.Mode().Perm()
	}
	if err := fsx.WriteAtomic(singboxConfigPath, out, mode); err != nil {
		return false, "", "", err
	}
	return true, DefaultControllerAddr, sec, nil
}

func isLoopbackAddr(addr string) bool {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return false
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

type configStatKey struct {
	path    string
	size    int64
	modNano int64
}

// Collector samples sing-box Clash API endpoints on loopback and maintains short-term rate history.
type Collector struct {
	ConfigPath string
	HTTPClient *http.Client

	clashMu     sync.Mutex
	clashClient *clashapi.Client
	clashBound  *http.Client

	mu          sync.Mutex
	lastSample  time.Time
	lastUpTotal int64
	lastDnTotal int64
	lastUpBps   int64
	lastDnBps   int64
	history     []RatePoint

	// 配置文件 stat 指纹缓存：1.5s SSE 遥测期间文件未变更时 0 磁盘读取与 JSON 解析开销
	cfgMu          sync.RWMutex
	cachedCfgKey   configStatKey
	cachedAddr     string
	cachedSecret   string
	cachedEnabled  bool
	cachedCfgValid bool
	cfgDiskReads   atomic.Int64
}

// NewCollector creates a Collector bound to singboxConfigPath (defaults to constant.SingBoxConfigFile).
func NewCollector(singboxConfigPath string) *Collector {
	return &Collector{
		ConfigPath: singboxConfigPath,
		clashClient: clashapi.NewClient(clashapi.Options{
			ConfigPath:     singboxConfigPath,
			RequestTimeout: 1500 * time.Millisecond,
		}),
	}
}

func (c *Collector) clash() *clashapi.Client {
	if c == nil {
		return clashapi.NewClient(clashapi.Options{RequestTimeout: 1500 * time.Millisecond})
	}
	c.clashMu.Lock()
	defer c.clashMu.Unlock()
	if c.HTTPClient != nil {
		if c.clashClient == nil || c.clashBound != c.HTTPClient {
			c.clashClient = clashapi.NewClient(clashapi.Options{
				ConfigPath:     c.ConfigPath,
				RequestTimeout: 1500 * time.Millisecond,
				HTTPClient:     c.HTTPClient,
			})
			c.clashBound = c.HTTPClient
		}
		return c.clashClient
	}
	if c.clashClient == nil || c.clashBound != nil {
		c.clashClient = clashapi.NewClient(clashapi.Options{
			ConfigPath:     c.ConfigPath,
			RequestTimeout: 1500 * time.Millisecond,
		})
		c.clashBound = nil
	}
	return c.clashClient
}

// Collect queries the local sing-box controller and returns an enriched Snapshot.
func (c *Collector) Collect(ctx context.Context) Snapshot {
	now := time.Now()
	snap := Snapshot{
		Timestamp:  now.Format(time.RFC3339),
		TopDomains: []DomainStat{},
		History:    []RatePoint{},
	}

	addr, secret, enabled := c.resolveConfigSnapshot()
	snap.Enabled = enabled
	snap.ControllerAddr = addr
	if !enabled {
		snap.Message = "当前 sing-box 配置尚未开启本地流量遥测 (" + DefaultControllerAddr + ")"
		return snap
	}
	if !isLoopbackAddr(addr) {
		snap.Message = "遥测地址非本地回环，已拒绝连接以保护安全"
		return snap
	}

	payload, msgErr := c.fetchConnections(ctx, addr, secret)
	if msgErr != nil {
		snap.Message = msgErr.Error()
		return snap
	}

	snap.Reachable = true
	snap.UploadTotal = payload.UploadTotal
	snap.DownloadTotal = payload.DownloadTotal
	snap.MemoryBytes = payload.Memory
	snap.ActiveConnections = len(payload.Connections)

	snap.UpBps, snap.DownBps, snap.History = c.recordRateSample(now, payload.UploadTotal, payload.DownloadTotal)
	c.populateSnapshotBreakdowns(&snap, payload.Connections)
	return snap
}

func (c *Collector) recordRateSample(now time.Time, uploadTotal, downloadTotal int64) (int64, int64, []RatePoint) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var upBps, dnBps int64
	if !c.lastSample.IsZero() {
		dt := now.Sub(c.lastSample).Seconds()
		if dt >= 0.25 {
			dUp := uploadTotal - c.lastUpTotal
			dDn := downloadTotal - c.lastDnTotal
			if dUp >= 0 && dDn >= 0 {
				upBps = int64(float64(dUp) / dt)
				dnBps = int64(float64(dDn) / dt)
			}
			c.lastSample = now
			c.lastUpTotal = uploadTotal
			c.lastDnTotal = downloadTotal
			c.lastUpBps = upBps
			c.lastDnBps = dnBps

			c.history = append(c.history, RatePoint{
				Time:    now.Format("15:04:05"),
				UpBps:   upBps,
				DownBps: dnBps,
			})
			if len(c.history) > maxHistoryPoints {
				c.history = c.history[len(c.history)-maxHistoryPoints:]
			}
		} else {
			upBps = c.lastUpBps
			dnBps = c.lastDnBps
		}
	} else {
		c.lastSample = now
		c.lastUpTotal = uploadTotal
		c.lastDnTotal = downloadTotal
		c.history = append(c.history, RatePoint{
			Time:    now.Format("15:04:05"),
			UpBps:   0,
			DownBps: 0,
		})
	}
	return upBps, dnBps, slices.Clone(c.history)
}

func (c *Collector) populateSnapshotBreakdowns(snap *Snapshot, conns []clashapi.Connection) {
	domainMap := make(map[string]*DomainStat, min(len(conns), 64))
	clientIPSet := make(map[string]struct{}, 8)
	for i := range conns {
		conn := &conns[i]
		if srcIP := strings.TrimSpace(conn.Metadata.SourceIP); srcIP != "" {
			clientIPSet[srcIP] = struct{}{}
		}
		totalConnBytes := conn.Upload + conn.Download
		proto := classifyProtocol(conn.Metadata.Type)
		switch proto {
		case "Hysteria2":
			snap.Protocols.Hy2Connections++
			snap.Protocols.Hy2Bytes += totalConnBytes
		case "Reality":
			snap.Protocols.RealityConnections++
			snap.Protocols.RealityBytes += totalConnBytes
		default:
			snap.Protocols.OtherConnections++
			snap.Protocols.OtherBytes += totalConnBytes
		}

		outLabel := classifyOutbound(conn.Chains)
		switch outLabel {
		case "Direct":
			snap.Outbounds.DirectConnections++
			snap.Outbounds.DirectBytes += totalConnBytes
		case "WARP":
			snap.Outbounds.WarpConnections++
			snap.Outbounds.WarpBytes += totalConnBytes
		default:
			snap.Outbounds.OtherConnections++
			snap.Outbounds.OtherBytes += totalConnBytes
		}

		target := cmp.Or(strings.TrimSpace(conn.Metadata.Host), strings.TrimSpace(conn.Metadata.DestinationIP), "unknown")
		if existing, ok := domainMap[target]; ok {
			existing.Connections++
			existing.Bytes += totalConnBytes
		} else {
			domainMap[target] = &DomainStat{
				Domain:      target,
				Protocol:    proto,
				Outbound:    outLabel,
				Rule:        conn.Rule,
				Connections: 1,
				Bytes:       totalConnBytes,
			}
		}
	}

	domains := make([]DomainStat, 0, len(domainMap))
	for _, d := range domainMap {
		domains = append(domains, *d)
	}
	slices.SortFunc(domains, func(a, b DomainStat) int {
		if a.Bytes != b.Bytes {
			return cmp.Compare(b.Bytes, a.Bytes)
		}
		return cmp.Compare(b.Connections, a.Connections)
	})
	if len(domains) > maxTopDomains {
		domains = domains[:maxTopDomains]
	}
	snap.TopDomains = domains
	if len(clientIPSet) > 0 {
		snap.ActiveClientIPs = make([]string, 0, len(clientIPSet))
		for ip := range clientIPSet {
			snap.ActiveClientIPs = append(snap.ActiveClientIPs, ip)
		}
	}
}

func (c *Collector) fetchConnections(ctx context.Context, addr, secret string) (clashapi.ConnectionsSnapshot, error) {
	snap, err := c.clash().ConnectionsAt(ctx, "http://"+addr, secret)
	if err == nil {
		return snap, nil
	}
	var se *clashapi.StatusError
	if errors.As(err, &se) {
		return clashapi.ConnectionsSnapshot{}, fmt.Errorf("sing-box 遥测接口返回 HTTP %d", se.StatusCode)
	}
	var de *clashapi.DecodeError
	if errors.As(err, &de) {
		return clashapi.ConnectionsSnapshot{}, errors.New("解析遥测数据失败")
	}
	return clashapi.ConnectionsSnapshot{}, errors.New("无法连接 sing-box 遥测接口，请确认 sing-box 正在运行")
}

// GetActiveDestinations 查询本地 127.0.0.1:9099 遥测接口并返回按远端目标聚合的活跃连接列表（零客户端隐私 IP 暴露）。
func (c *Collector) GetActiveDestinations(ctx context.Context, query, outboundFilter string) ([]ActiveDestinationGroup, error) {
	addr, secret, enabled := c.resolveConfigSnapshot()
	if !enabled {
		return []ActiveDestinationGroup{}, errors.New("当前 sing-box 配置尚未开启本地流量遥测 (" + DefaultControllerAddr + ")")
	}
	if !isLoopbackAddr(addr) {
		return []ActiveDestinationGroup{}, errors.New("遥测地址非本地回环，已拒绝连接以保护安全")
	}

	payload, err := c.fetchConnections(ctx, addr, secret)
	if err != nil {
		return []ActiveDestinationGroup{}, err
	}

	q := strings.ToLower(strings.TrimSpace(query))
	obFilter := strings.ToUpper(strings.TrimSpace(outboundFilter))
	if obFilter == "DC" {
		obFilter = "DIRECT"
	}

	groupMap := make(map[string]*ActiveDestinationGroup)
	for _, conn := range payload.Connections {
		host := strings.TrimSpace(conn.Metadata.Host)
		dstIP := strings.TrimSpace(conn.Metadata.DestinationIP)
		target := cmp.Or(host, dstIP, "unknown")
		if target == "unknown" {
			continue
		}
		outLabel := classifyOutbound(conn.Chains)
		if obFilter != "" && obFilter != "ALL" && !strings.EqualFold(outLabel, obFilter) {
			continue
		}
		root := config.ExtractRootDomain(target)
		if q != "" &&
			!strings.Contains(strings.ToLower(target), q) &&
			!strings.Contains(strings.ToLower(root), q) &&
			!strings.Contains(strings.ToLower(dstIP), q) &&
			!strings.Contains(strings.ToLower(conn.Rule), q) {
			continue
		}

		_, parseErr := netip.ParseAddr(target)
		isIP := host == "" || parseErr == nil
		proto := classifyProtocol(conn.Metadata.Type)
		key := target + "|" + outLabel

		if existing, ok := groupMap[key]; ok {
			existing.Connections++
			existing.UploadBytes += conn.Upload
			existing.DownloadBytes += conn.Download
			existing.TotalBytes += conn.Upload + conn.Download
			if existing.Rule == "" && conn.Rule != "" {
				existing.Rule = conn.Rule
			}
		} else {
			groupMap[key] = &ActiveDestinationGroup{
				Target:        target,
				RootDomain:    cmp.Or(root, target),
				IsIP:          isIP,
				Protocol:      proto,
				Outbound:      outLabel,
				Rule:          conn.Rule,
				Connections:   1,
				UploadBytes:   conn.Upload,
				DownloadBytes: conn.Download,
				TotalBytes:    conn.Upload + conn.Download,
			}
		}
	}

	items := make([]ActiveDestinationGroup, 0, len(groupMap))
	for _, g := range groupMap {
		items = append(items, *g)
	}
	slices.SortFunc(items, func(a, b ActiveDestinationGroup) int {
		if a.TotalBytes != b.TotalBytes {
			return cmp.Compare(b.TotalBytes, a.TotalBytes)
		}
		if a.Connections != b.Connections {
			return cmp.Compare(b.Connections, a.Connections)
		}
		return strings.Compare(a.Target, b.Target)
	})
	if len(items) > 100 {
		items = items[:100]
	}
	return items, nil
}

// EvictMismatchedConnections 遍历当前活跃连接，对满足 matchFn 的存量长连接逐条调用 DELETE /connections/{id} 踢断。
func (c *Collector) EvictMismatchedConnections(ctx context.Context, matchFn func(host, dstIP, rule, currentOutbound string) bool) (int, error) {
	if matchFn == nil {
		return 0, nil
	}
	addr, secret, enabled := c.resolveConfigSnapshot()
	if !enabled || !isLoopbackAddr(addr) {
		return 0, nil
	}
	payload, err := c.fetchConnections(ctx, addr, secret)
	if err != nil {
		return 0, err
	}

	evicted := 0
	baseURL := "http://" + addr
	clashCli := c.clash()
	for _, conn := range payload.Connections {
		if conn.ID == "" {
			continue
		}
		host := strings.TrimSpace(conn.Metadata.Host)
		dstIP := strings.TrimSpace(conn.Metadata.DestinationIP)
		outLabel := classifyOutbound(conn.Chains)
		if !matchFn(host, dstIP, conn.Rule, outLabel) {
			continue
		}

		delCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		if err := clashCli.CloseConnectionAt(delCtx, baseURL, secret, conn.ID); err == nil {
			evicted++
		}
		cancel()
	}
	return evicted, nil
}

func classifyProtocol(metaType string) string {
	lower := strings.ToLower(metaType)
	switch {
	case strings.Contains(lower, "hysteria"):
		return "Hysteria2"
	case strings.Contains(lower, "vless") || strings.Contains(lower, "reality"):
		return "Reality"
	default:
		return "Other"
	}
}

func classifyOutbound(chains []string) string {
	for _, ch := range chains {
		upper := strings.ToUpper(strings.TrimSpace(ch))
		switch {
		case strings.Contains(upper, "WARP"):
			return "WARP"
		case upper == "DC" || strings.Contains(upper, "DIRECT"):
			return "Direct"
		}
	}
	return "Direct"
}

// FormatRate formats bytes/sec into human-readable Mbps or Kbps/B/s (delegated to common/sysinfo).
func FormatRate(bps int64) string {
	return sysinfo.FormatRate(bps)
}

// FormatBytes formats cumulative byte counts into human-readable units (delegated to common/sysinfo).
func FormatBytes(b int64) string {
	return sysinfo.FormatBytes(b)
}
