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
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"singctl/internal/constant"
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
	Sniffing          any               `json:"sniffing,omitempty"`
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
		_ = os.WriteFile(secretPath, []byte(sec+"\n"), 0600)
		_ = os.Chmod(secretPath, 0600)
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
	tmp := singboxConfigPath + ".tmp"
	if err := os.WriteFile(tmp, out, mode); err != nil {
		return false, "", "", err
	}
	if err := os.Rename(tmp, singboxConfigPath); err != nil {
		_ = os.Remove(tmp)
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

// Collector samples sing-box Clash API endpoints on loopback and maintains short-term rate history.
type Collector struct {
	ConfigPath string
	HTTPClient *http.Client

	mu          sync.Mutex
	lastSample  time.Time
	lastUpTotal int64
	lastDnTotal int64
	lastUpBps   int64
	lastDnBps   int64
	history     []RatePoint
}

// NewCollector creates a Collector bound to singboxConfigPath (defaults to constant.SingBoxConfigFile).
func NewCollector(singboxConfigPath string) *Collector {
	return &Collector{
		ConfigPath: singboxConfigPath,
		HTTPClient: &http.Client{
			Timeout: 1500 * time.Millisecond,
		},
	}
}

type clashConnectionsResp struct {
	DownloadTotal int64             `json:"downloadTotal"`
	UploadTotal   int64             `json:"uploadTotal"`
	Memory        int64             `json:"memory"`
	Connections   []clashConnection `json:"connections"`
}

type clashConnection struct {
	ID       string   `json:"id"`
	Upload   int64    `json:"upload"`
	Download int64    `json:"download"`
	Start    string   `json:"start"`
	Chains   []string `json:"chains"`
	Rule     string   `json:"rule"`
	Metadata struct {
		Network         string `json:"network"`
		Type            string `json:"type"`
		SourceIP        string `json:"sourceIP"`
		Host            string `json:"host"`
		DestinationIP   string `json:"destinationIP"`
		DestinationPort string `json:"destinationPort"`
	} `json:"metadata"`
}

// Collect queries the local sing-box controller and returns an enriched Snapshot.
func (c *Collector) Collect(ctx context.Context) Snapshot {
	now := time.Now()
	snap := Snapshot{
		Timestamp:  now.Format(time.RFC3339),
		TopDomains: []DomainStat{},
		History:    []RatePoint{},
	}

	addr, secret, enabled := ResolveConfig(c.ConfigPath)
	snap.Enabled = enabled
	snap.ControllerAddr = addr
	if !enabled {
		snap.Message = "当前 sing-box 配置尚未开启本地流量遥测 (127.0.0.1:9099)"
		return snap
	}
	if !isLoopbackAddr(addr) {
		snap.Message = "遥测地址非本地回环，已拒绝连接以保护安全"
		return snap
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("http://%s/connections", addr), nil)
	if err != nil {
		snap.Message = err.Error()
		return snap
	}
	if secret != "" {
		req.Header.Set("Authorization", "Bearer "+secret)
	}

	client := c.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 1500 * time.Millisecond}
	}
	resp, err := client.Do(req)
	if err != nil {
		snap.Message = "无法连接 sing-box 遥测接口，请确认 sing-box 正在运行"
		return snap
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		snap.Message = fmt.Sprintf("sing-box 遥测接口返回 HTTP %d", resp.StatusCode)
		return snap
	}

	var payload clashConnectionsResp
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		snap.Message = "解析遥测数据失败"
		return snap
	}

	snap.Reachable = true
	snap.UploadTotal = payload.UploadTotal
	snap.DownloadTotal = payload.DownloadTotal
	snap.MemoryBytes = payload.Memory
	snap.ActiveConnections = len(payload.Connections)

	c.mu.Lock()
	var upBps, dnBps int64
	if !c.lastSample.IsZero() {
		dt := now.Sub(c.lastSample).Seconds()
		if dt >= 0.25 {
			dUp := payload.UploadTotal - c.lastUpTotal
			dDn := payload.DownloadTotal - c.lastDnTotal
			if dUp >= 0 && dDn >= 0 {
				upBps = int64(float64(dUp) / dt)
				dnBps = int64(float64(dDn) / dt)
			}
			c.lastSample = now
			c.lastUpTotal = payload.UploadTotal
			c.lastDnTotal = payload.DownloadTotal
			c.lastUpBps = upBps
			c.lastDnBps = dnBps

			pt := RatePoint{
				Time:    now.Format("15:04:05"),
				UpBps:   upBps,
				DownBps: dnBps,
			}
			c.history = append(c.history, pt)
			if len(c.history) > maxHistoryPoints {
				c.history = c.history[len(c.history)-maxHistoryPoints:]
			}
		} else {
			// Guard against burst calls < 250ms apart: reuse previous instantaneous rate
			upBps = c.lastUpBps
			dnBps = c.lastDnBps
		}
	} else {
		c.lastSample = now
		c.lastUpTotal = payload.UploadTotal
		c.lastDnTotal = payload.DownloadTotal
		c.history = append(c.history, RatePoint{
			Time:    now.Format("15:04:05"),
			UpBps:   0,
			DownBps: 0,
		})
	}
	historyCopy := slices.Clone(c.history)
	c.mu.Unlock()

	snap.UpBps = upBps
	snap.DownBps = dnBps
	snap.History = historyCopy

	domainMap := make(map[string]*DomainStat)
	clientIPSet := make(map[string]struct{})
	for _, conn := range payload.Connections {
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
			if a.Bytes > b.Bytes {
				return -1
			}
			return 1
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
	return snap
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

// FormatRate formats bytes/sec into human-readable Mbps or Kbps/B/s.
func FormatRate(bps int64) string {
	bits := float64(bps) * 8
	switch {
	case bits >= 1_000_000_000:
		return fmt.Sprintf("%.2f Gbps", bits/1_000_000_000)
	case bits >= 1_000_000:
		return fmt.Sprintf("%.2f Mbps", bits/1_000_000)
	case bits >= 1_000:
		return fmt.Sprintf("%.1f Kbps", bits/1_000)
	default:
		return fmt.Sprintf("%d bps", int64(bits))
	}
}

// FormatBytes formats cumulative byte counts into human-readable units.
func FormatBytes(b int64) string {
	const (
		KB = 1024
		MB = 1024 * KB
		GB = 1024 * MB
		TB = 1024 * GB
	)
	switch {
	case b >= TB:
		return fmt.Sprintf("%.2f TB", float64(b)/float64(TB))
	case b >= GB:
		return fmt.Sprintf("%.2f GB", float64(b)/float64(GB))
	case b >= MB:
		return fmt.Sprintf("%.1f MB", float64(b)/float64(MB))
	case b >= KB:
		return fmt.Sprintf("%.1f KB", float64(b)/float64(KB))
	default:
		return fmt.Sprintf("%d B", b)
	}
}
