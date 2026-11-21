// 文件职责：负责 Clash /connections API 连接抓包、流量增量摄取（Ingest）、时序变异系数计算与流列表多维排序。
package audit

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
)

// clashConnectionsResponse 对应 sing-box Clash API GET /connections 响应结构。
type clashConnectionsResponse struct {
	DownloadTotal int64             `json:"downloadTotal"`
	UploadTotal   int64             `json:"uploadTotal"`
	Connections   []clashConnection `json:"connections"`
}

type clashConnection struct {
	ID          string   `json:"id"`
	Upload      int64    `json:"upload"`
	Download    int64    `json:"download"`
	Start       string   `json:"start"`
	Chains      []string `json:"chains"`
	Rule        string   `json:"rule"`
	RulePayload string   `json:"rulePayload"`
	Metadata    struct {
		Network         string `json:"network"`
		Type            string `json:"type"`
		SourceIP        string `json:"sourceIP"`
		DestinationIP   string `json:"destinationIP"`
		SourcePort      string `json:"sourcePort"`
		DestinationPort string `json:"destinationPort"`
		Host            string `json:"host"`
		SniffHost       string `json:"sniffHost,omitempty"`
	} `json:"metadata"`
}

func (c *Collector) fetchConnectionsLocked(ctx context.Context) (*clashConnectionsResponse, string, error) {
	var lastErr error
	for _, ep := range c.endpoints {
		u := strings.TrimRight(ep, "/") + "/connections"
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			lastErr = err
			continue
		}
		if c.secret != "" {
			req.Header.Set("Authorization", "Bearer "+c.secret)
		}
		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			lastErr = fmt.Errorf("clash api %s returned %d", ep, resp.StatusCode)
			continue
		}
		var parsed clashConnectionsResponse
		decErr := json.NewDecoder(resp.Body).Decode(&parsed)
		resp.Body.Close()
		if decErr != nil {
			lastErr = decErr
			continue
		}
		return &parsed, ep, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no clash api endpoints available")
	}
	return nil, "", lastErr
}

func (c *Collector) ingestConnectionsLocked(
	state *persistedAuditState,
	conns []clashConnection,
	devDir map[string]lanDeviceInfo,
	selfIPs map[string]bool,
	activeByKey map[string][]string,
	engine *NonlinearEngine,
	now time.Time,
) bool {
	nowUnix := now.Unix()
	hour := now.Hour()
	isNight := hour >= 1 && hour <= 5
	mutated := false

	for _, conn := range conns {
		rawSrc := cmp.Or(strings.TrimSpace(conn.Metadata.SourceIP), "127.0.0.1")
		srcIP := normalizeSourceDeviceIP(rawSrc, selfIPs, devDir)
		network := strings.ToLower(cmp.Or(strings.TrimSpace(conn.Metadata.Network), "tcp"))
		destPort, _ := strconv.Atoi(strings.TrimSpace(conn.Metadata.DestinationPort))
		rawHost, destIP, target, isDirectIP := resolveConnTarget(conn)
		if target == "" {
			continue
		}
		if len(conn.Chains) > 0 && strings.EqualFold(conn.Chains[0], "block") {
			continue
		}
		if engine != nil && engine.IsBlocked(srcIP, target) {
			continue
		}

		// 计算该连接自上次采样以来的增量字节（支持长连接持续累加且不丢历史）
		var deltaUp, deltaDown int64
		isNewConn := false
		if prev, seen := state.ConnCursors[conn.ID]; seen {
			if conn.Upload >= prev.Upload {
				deltaUp = conn.Upload - prev.Upload
			} else {
				deltaUp = conn.Upload
			}
			if conn.Download >= prev.Download {
				deltaDown = conn.Download - prev.Download
			} else {
				deltaDown = conn.Download
			}
		} else {
			isNewConn = true
			deltaUp = conn.Upload
			deltaDown = conn.Download
		}
		state.ConnCursors[conn.ID] = connByteCursor{
			Upload:   conn.Upload,
			Download: conn.Download,
			SeenUnix: nowUnix,
		}

		key := srcIP + "|" + target + "|" + network
		activeByKey[key] = append(activeByKey[key], conn.ID)

		entry, exists := state.Flows[key]
		if !exists {
			entry = &persistedFlowEntry{
				Key:           key,
				DeviceIP:      srcIP,
				Target:        target,
				RawHost:       rawHost,
				DestIP:        destIP,
				DestPort:      destPort,
				IsDirectIP:    isDirectIP,
				Network:       network,
				FirstSeenUnix: nowUnix,
			}
			state.Flows[key] = entry
			mutated = true
		}

		if isNewConn || deltaUp > 0 || deltaDown > 0 {
			mutated = true
		}

		entry.LastSeenUnix = nowUnix
		entry.UploadBytes += deltaUp
		entry.DownloadBytes += deltaDown
		if entry.RawHost == "" && rawHost != "" {
			entry.RawHost = rawHost
			mutated = true
		}
		if destPort > 0 && entry.DestPort != destPort {
			entry.DestPort = destPort
			mutated = true
		}
		if destIP != "" && entry.DestIP != destIP {
			entry.DestIP = destIP
			mutated = true
		}
		if len(conn.Chains) > 0 {
			if entry.Outbound != conn.Chains[0] {
				entry.Outbound = conn.Chains[0]
				mutated = true
			}
			chains := make([]string, 0, len(conn.Chains))
			for i := len(conn.Chains) - 1; i >= 0; i-- {
				hop := strings.TrimSpace(conn.Chains[i])
				if hop != "" && !slices.Contains(chains, hop) {
					chains = append(chains, hop)
				}
			}
			if len(chains) > 0 && !slices.Equal(entry.Chains, chains) {
				entry.Chains = chains
				mutated = true
			}
		}
		if conn.Rule != "" {
			newRule := conn.Rule
			if conn.RulePayload != "" {
				newRule = conn.Rule + "(" + conn.RulePayload + ")"
			}
			if entry.Rule != newRule {
				entry.Rule = newRule
				mutated = true
			}
		}
		if devInfo, ok := devDir[srcIP]; ok {
			if entry.DeviceName != devInfo.Name || entry.DeviceMAC != devInfo.MAC {
				entry.DeviceName = devInfo.Name
				entry.DeviceMAC = devInfo.MAC
				mutated = true
			}
		}

		if isNewConn {
			entry.ConnCount++
			if isNight && deltaUp > 0 {
				entry.NightHits++
			}
			connStartUnix := nowUnix
			if parsedStart, err := time.Parse(time.RFC3339Nano, conn.Start); err == nil {
				connStartUnix = parsedStart.Unix()
			}
			entry.ArrivalsUnix = append(entry.ArrivalsUnix, connStartUnix)
			if len(entry.ArrivalsUnix) > maxArrivalSamples {
				entry.ArrivalsUnix = entry.ArrivalsUnix[len(entry.ArrivalsUnix)-maxArrivalSamples:]
			}
		}
	}
	return mutated
}

// computeIntervalCV 计算建连时间序列的间隔变异系数 CV = sigma / mu。
func computeIntervalCV(arrivals []int64) float64 {
	if len(arrivals) < 4 {
		return 0
	}
	sorted := slices.Clone(arrivals)
	slices.Sort(sorted)

	intervals := make([]float64, 0, len(sorted)-1)
	for i := 1; i < len(sorted); i++ {
		diff := float64(sorted[i] - sorted[i-1])
		if diff >= 0.5 { // 忽略同一毫秒并发建连簇，聚焦周期性间隔
			intervals = append(intervals, diff)
		}
	}
	if len(intervals) < 3 {
		return 0
	}

	var sum float64
	for _, iv := range intervals {
		sum += iv
	}
	mean := sum / float64(len(intervals))
	if mean <= 0.1 {
		return 0
	}

	var sqDiffSum float64
	for _, iv := range intervals {
		d := iv - mean
		sqDiffSum += d * d
	}
	stdDev := math.Sqrt(sqDiffSum / float64(len(intervals)))
	cv := stdDev / mean
	return math.Round(cv*1000) / 1000
}
func enforcementActiveRank(s EnforcementState) int {
	switch s {
	case EnforcementBlocked:
		return 1
	case EnforcementWhitelisted:
		return 0
	default: // EnforcementObserved 或未填充态优先排在待处置前列
		return 2
	}
}

func flowActiveBucket(f FlowRecord) int {
	if f.ActiveConns > 0 {
		return 1
	}
	return 0
}

func compareRiskHierarchy(a, b FlowRecord) int {
	if s := cmp.Compare(enforcementActiveRank(b.State), enforcementActiveRank(a.State)); s != 0 {
		return s
	}
	if t := cmp.Compare(b.Threat.SeverityRank(), a.Threat.SeverityRank()); t != 0 {
		return t
	}
	if r := cmp.Compare(b.RiskScore, a.RiskScore); r != 0 {
		return r
	}
	if ac := cmp.Compare(b.ActiveConns, a.ActiveConns); ac != 0 {
		return ac
	}
	return cmp.Compare(b.UploadBytes, a.UploadBytes)
}

// SortFlows 对审计流记录按指定字段（默认 "active": 活跃优先+风险评分，或 "risk" | "upload" | "download" | "ratio"）执行稳定排序。
func SortFlows(flows []FlowRecord, sortBy string, asc bool) {
	key := strings.ToLower(strings.TrimSpace(sortBy))
	slices.SortFunc(flows, func(a, b FlowRecord) int {
		var c int
		switch key {
		case "upload":
			c = cmp.Compare(b.UploadBytes, a.UploadBytes)
			if asc {
				c = -c
			}
			if c != 0 {
				return c
			}
			if r := cmp.Compare(b.RiskScore, a.RiskScore); r != 0 {
				return r
			}
			return cmp.Compare(b.DownloadBytes, a.DownloadBytes)
		case "download":
			c = cmp.Compare(b.DownloadBytes, a.DownloadBytes)
			if asc {
				c = -c
			}
			if c != 0 {
				return c
			}
			if r := cmp.Compare(b.RiskScore, a.RiskScore); r != 0 {
				return r
			}
			return cmp.Compare(b.UploadBytes, a.UploadBytes)
		case "ratio":
			c = cmp.Compare(b.UploadRatio, a.UploadRatio)
			if asc {
				c = -c
			}
			if c != 0 {
				return c
			}
			if u := cmp.Compare(b.UploadBytes, a.UploadBytes); u != 0 {
				return u
			}
			return cmp.Compare(b.RiskScore, a.RiskScore)
		case "risk":
			c = compareRiskHierarchy(a, b)
			if asc {
				c = -c
			}
			return c
		default: // "" 或 "active"：活跃置顶 -> 组内按风险评分层级降序
			if act := cmp.Compare(flowActiveBucket(b), flowActiveBucket(a)); act != 0 {
				c = act
			} else {
				c = compareRiskHierarchy(a, b)
			}
			if asc {
				c = -c
			}
			return c
		}
	})
}

// isValidAuditDomain 校验嗅探出的字符串是否为合法 FQDN 域名（拒绝类似 "Mijia Cloud" 的 TLS 证书 Subject CN 非域名文本）。
func isValidAuditDomain(s string) bool {
	s = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
	if s == "" || len(s) > 253 || net.ParseIP(s) != nil {
		return false
	}
	if !strings.Contains(s, ".") {
		return false
	}
	lastLabel := ""
	for label := range strings.SplitSeq(s, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := range len(label) {
			ch := label[i]
			isAlphaNum := (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9')
			if !isAlphaNum && ch != '-' && ch != '_' {
				return false
			}
		}
		lastLabel = label
	}
	if len(lastLabel) < 2 || strings.Contains(lastLabel, "_") {
		return false
	}
	allDigits := true
	for i := range len(lastLabel) {
		if lastLabel[i] < '0' || lastLabel[i] > '9' {
			allDigits = false
			break
		}
	}
	return !allDigits
}

// resolveConnTarget 从 Clash API 单条连接元数据提取规范化目标域名/IP（供采集与连接断开共享）。
func resolveConnTarget(conn clashConnection) (rawHost, destIP, target string, isDirectIP bool) {
	rawHost = cmp.Or(strings.TrimSpace(conn.Metadata.SniffHost), strings.TrimSpace(conn.Metadata.Host))
	destIP = strings.TrimSpace(conn.Metadata.DestinationIP)
	target = strings.TrimSuffix(strings.ToLower(rawHost), ".")
	if h, _, err := net.SplitHostPort(target); err == nil && h != "" {
		target = strings.TrimSuffix(h, ".")
	}
	if target == "" || net.ParseIP(target) != nil {
		isDirectIP = true
		target = cmp.Or(destIP, target)
	} else if !isValidAuditDomain(target) {
		isDirectIP = true
		target = destIP
	}
	return rawHost, destIP, target, isDirectIP
}
