// 文件职责：负责 Clash /connections API 连接抓包、流量增量摄取（Ingest）、时序变异系数计算与流列表多维排序。
package audit

import (
	"cmp"
	"context"
	"fmt"
	"math"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"

	"singctl/internal/singbox/clashapi"
)

// clashConnectionsResponse 与 clashConnection 直接复用统一 clashapi 数据模型。
type clashConnectionsResponse = clashapi.ConnectionsSnapshot
type clashConnection = clashapi.Connection

func (c *Collector) fetchConnectionsLocked(ctx context.Context) (*clashConnectionsResponse, string, error) {
	cli := c.clashClient
	if cli == nil {
		cli = clashapi.NewClient(clashapi.Options{RequestTimeout: 2500 * time.Millisecond})
	}
	var lastErr error
	for _, ep := range c.endpoints {
		parsed, err := fetchEndpointConnections(ctx, cli, ep, c.secret)
		if err != nil {
			lastErr = err
			continue
		}
		return parsed, ep, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no clash api endpoints available")
	}
	return nil, "", lastErr
}

func fetchEndpointConnections(ctx context.Context, client *clashapi.Client, endpoint, secret string) (*clashConnectionsResponse, error) {
	snap, err := client.ConnectionsAt(ctx, endpoint, secret)
	if err != nil {
		return nil, err
	}
	return &snap, nil
}

func computeConnByteDelta(cursors map[string]connByteCursor, conn clashConnection, nowUnix int64) (deltaUp, deltaDown int64, isNew bool) {
	prev, seen := cursors[conn.ID]
	cursors[conn.ID] = connByteCursor{
		Upload:   conn.Upload,
		Download: conn.Download,
		SeenUnix: nowUnix,
	}
	if !seen {
		return conn.Upload, conn.Download, true
	}
	deltaUp = conn.Upload
	if conn.Upload >= prev.Upload {
		deltaUp = conn.Upload - prev.Upload
	}
	deltaDown = conn.Download
	if conn.Download >= prev.Download {
		deltaDown = conn.Download - prev.Download
	}
	return deltaUp, deltaDown, false
}

func dedupReverseChains(raw []string) []string {
	chains := make([]string, 0, len(raw))
	for i := len(raw) - 1; i >= 0; i-- {
		hop := strings.TrimSpace(raw[i])
		if hop != "" && !slices.Contains(chains, hop) {
			chains = append(chains, hop)
		}
	}
	return chains
}

func updateFlowEntryMetadata(
	entry *persistedFlowEntry,
	conn clashConnection,
	rawHost, destIP string,
	destPort int,
	devDir map[string]lanDeviceInfo,
	srcIP string,
) bool {
	mutated := false
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
		if chains := dedupReverseChains(conn.Chains); len(chains) > 0 && !slices.Equal(entry.Chains, chains) {
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
	if devInfo, ok := devDir[srcIP]; ok && (entry.DeviceName != devInfo.Name || entry.DeviceMAC != devInfo.MAC) {
		entry.DeviceName = devInfo.Name
		entry.DeviceMAC = devInfo.MAC
		mutated = true
	}
	return mutated
}

func recordNewConnArrival(entry *persistedFlowEntry, connStart string, nowUnix int64, isNight bool, deltaUp int64) {
	entry.ConnCount++
	if isNight && deltaUp > 0 {
		entry.NightHits++
	}
	connStartUnix := nowUnix
	if parsedStart, err := time.Parse(time.RFC3339Nano, connStart); err == nil {
		connStartUnix = parsedStart.Unix()
	}
	entry.ArrivalsUnix = append(entry.ArrivalsUnix, connStartUnix)
	if len(entry.ArrivalsUnix) > maxArrivalSamples {
		entry.ArrivalsUnix = entry.ArrivalsUnix[len(entry.ArrivalsUnix)-maxArrivalSamples:]
	}
}

const (
	liveRateMinSampleSec    = 0.5
	liveRateMaxSampleSec    = 120.0
	maxValidConnStartAge    = 30 * 24 * 3600
	maxActiveDetailsPerFlow = 8
)

func buildActiveConnDetail(conn clashConnection, upBps, downBps float64, now time.Time) ActiveConnDetail {
	rule := strings.TrimSpace(conn.Rule)
	if rule != "" && strings.TrimSpace(conn.RulePayload) != "" {
		rule = rule + "(" + strings.TrimSpace(conn.RulePayload) + ")"
	}
	var durSec int64
	var startLabel string
	if st, ok := parseConnStartTime(conn.Start); ok {
		startLabel = st.In(now.Location()).Format("15:04:05")
		if d := int64(now.Sub(st).Seconds()); d > 0 {
			durSec = d
		}
	}
	return ActiveConnDetail{
		ID:          conn.ID,
		SourcePort:  strings.TrimSpace(conn.Metadata.SourcePort),
		DestIP:      strings.TrimSpace(conn.Metadata.DestinationIP),
		DestPort:    strings.TrimSpace(conn.Metadata.DestinationPort),
		InboundType: strings.TrimSpace(conn.Metadata.Type),
		Rule:        rule,
		Chains:      dedupReverseChains(conn.Chains),
		Upload:      conn.Upload,
		Download:    conn.Download,
		UploadBps:   math.Round(upBps*10) / 10,
		DownloadBps: math.Round(downBps*10) / 10,
		Start:       startLabel,
		DurationSec: durSec,
	}
}

func parseConnStartTime(raw string) (time.Time, bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return time.Time{}, false
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t, true
	}
	return time.Time{}, false
}

func computeConnLiveRate(
	prev connRateCursor,
	hadPrev bool,
	lastPollAt time.Time,
	conn clashConnection,
	now time.Time,
) (upBps, downBps float64) {
	if hadPrev {
		dt := now.Sub(prev.SampleAt).Seconds()
		if dt < liveRateMinSampleSec || dt > liveRateMaxSampleSec {
			return 0, 0
		}
		if conn.Upload > prev.Upload {
			upBps = float64(conn.Upload-prev.Upload) / dt
		}
		if conn.Download > prev.Download {
			downBps = float64(conn.Download-prev.Download) / dt
		}
		return upBps, downBps
	}

	if lastPollAt.IsZero() {
		return 0, 0
	}
	connStart, ok := parseConnStartTime(conn.Start)
	if !ok || !connStart.After(lastPollAt) || connStart.After(now) {
		return 0, 0
	}
	dt := max(1.0, now.Sub(connStart).Seconds())
	if conn.Upload > 0 {
		upBps = float64(conn.Upload) / dt
	}
	if conn.Download > 0 {
		downBps = float64(conn.Download) / dt
	}
	return upBps, downBps
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

	pollDeltaSec := now.Sub(c.lastPollAt).Seconds()
	debounceRapidPoll := !c.lastPollAt.IsZero() && pollDeltaSec >= 0 && pollDeltaSec < liveRateMinSampleSec

	var nextCursors map[string]connRateCursor
	var nextRates map[string]flowLiveRate
	nextDetails := make(map[string][]ActiveConnDetail, len(conns))
	if !debounceRapidPoll {
		nextCursors = make(map[string]connRateCursor, len(conns))
		nextRates = make(map[string]flowLiveRate, len(conns))
	}

	profileSamples := make([]profileConnDelta, 0, len(conns))

	for _, conn := range conns {
		flowKey, changed, pSample, hasSample := ingestSingleConnection(state, conn, devDir, selfIPs, activeByKey, engine, nowUnix, isNight)
		if changed {
			mutated = true
		}
		if hasSample {
			profileSamples = append(profileSamples, pSample)
		}
		if flowKey == "" {
			continue
		}
		var upBps, downBps float64
		if !debounceRapidPoll {
			prev, hadPrev := c.connRateCursors[conn.ID]
			upBps, downBps = computeConnLiveRate(prev, hadPrev, c.lastPollAt, conn, now)
			if upBps > 0 || downBps > 0 {
				cur := nextRates[flowKey]
				cur.upBps += upBps
				cur.downBps += downBps
				nextRates[flowKey] = cur
			}
			nextCursors[conn.ID] = connRateCursor{
				Upload:   conn.Upload,
				Download: conn.Download,
				SampleAt: now,
			}
		}
		nextDetails[flowKey] = append(nextDetails[flowKey], buildActiveConnDetail(conn, upBps, downBps, now))
	}

	for key, list := range nextDetails {
		if len(list) > 1 {
			slices.SortFunc(list, func(a, b ActiveConnDetail) int {
				if c := cmp.Compare(b.UploadBps+b.DownloadBps, a.UploadBps+a.DownloadBps); c != 0 {
					return c
				}
				return cmp.Compare(b.Upload+b.Download, a.Upload+a.Download)
			})
		}
		if len(list) > maxActiveDetailsPerFlow {
			nextDetails[key] = list[:maxActiveDetailsPerFlow]
		}
	}
	c.flowActiveDetails = nextDetails

	if debounceRapidPoll {
		if len(c.flowLiveRates) > 0 {
			retained := make(map[string]flowLiveRate, len(activeByKey))
			for key := range activeByKey {
				if r, ok := c.flowLiveRates[key]; ok {
					retained[key] = r
				}
			}
			c.flowLiveRates = retained
		}
	} else {
		c.connRateCursors = nextCursors
		c.flowLiveRates = nextRates
		c.lastPollAt = now
	}
	if len(profileSamples) > 0 && c.recordProfileSamplesLocked(state, profileSamples, devDir, now) {
		mutated = true
	}
	return mutated
}

func ingestSingleConnection(
	state *persistedAuditState,
	conn clashConnection,
	devDir map[string]lanDeviceInfo,
	selfIPs map[string]bool,
	activeByKey map[string][]string,
	engine *NonlinearEngine,
	nowUnix int64,
	isNight bool,
) (string, bool, profileConnDelta, bool) {
	rawSrc := cmp.Or(strings.TrimSpace(conn.Metadata.SourceIP), "127.0.0.1")
	srcIP := normalizeSourceDeviceIP(rawSrc, selfIPs, devDir)
	rawHost, destIP, target, isDirectIP := resolveConnTarget(conn)
	if target == "" {
		return "", false, profileConnDelta{}, false
	}
	if len(conn.Chains) > 0 && strings.EqualFold(conn.Chains[0], "block") {
		return "", false, profileConnDelta{}, false
	}
	if engine != nil && engine.IsBlocked(srcIP, target) {
		return "", false, profileConnDelta{}, false
	}

	network := strings.ToLower(cmp.Or(strings.TrimSpace(conn.Metadata.Network), "tcp"))
	destPort, _ := strconv.Atoi(strings.TrimSpace(conn.Metadata.DestinationPort))
	deltaUp, deltaDown, isNewConn := computeConnByteDelta(state.ConnCursors, conn, nowUnix)

	key := srcIP + "|" + target + "|" + network
	activeByKey[key] = append(activeByKey[key], conn.ID)

	firstSeenCandidate := nowUnix
	if connStart, ok := parseConnStartTime(conn.Start); ok {
		startUnix := connStart.Unix()
		if startUnix > 0 && startUnix < nowUnix && nowUnix-startUnix <= maxValidConnStartAge {
			firstSeenCandidate = startUnix
		}
	}

	mutated := isNewConn || deltaUp > 0 || deltaDown > 0
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
			FirstSeenUnix: firstSeenCandidate,
		}
		state.Flows[key] = entry
		mutated = true
	} else if firstSeenCandidate < entry.FirstSeenUnix {
		entry.FirstSeenUnix = firstSeenCandidate
		mutated = true
	}

	entry.LastSeenUnix = nowUnix
	entry.UploadBytes += deltaUp
	entry.DownloadBytes += deltaDown
	if updateFlowEntryMetadata(entry, conn, rawHost, destIP, destPort, devDir, srcIP) {
		mutated = true
	}
	if isNewConn {
		recordNewConnArrival(entry, conn.Start, nowUnix, isNight, deltaUp)
	}
	outbound := ""
	if len(conn.Chains) > 0 {
		outbound = conn.Chains[0]
	}
	ruleStr := strings.TrimSpace(conn.Rule)
	if ruleStr != "" && strings.TrimSpace(conn.RulePayload) != "" {
		ruleStr = ruleStr + "(" + strings.TrimSpace(conn.RulePayload) + ")"
	}
	sample := profileConnDelta{
		DeviceIP:     srcIP,
		DeviceName:   entry.DeviceName,
		DeviceMAC:    entry.DeviceMAC,
		Target:       target,
		RawHost:      rawHost,
		DestIP:       destIP,
		Rule:         cmp.Or(entry.Rule, ruleStr),
		Outbound:     cmp.Or(entry.Outbound, outbound),
		DeltaUp:      deltaUp,
		DeltaDown:    deltaDown,
		IsNewConn:    isNewConn,
		ArrivalCount: len(entry.ArrivalsUnix),
		IntervalCV:   computeIntervalCV(entry.ArrivalsUnix),
	}
	return key, mutated, sample, deltaUp > 0 || deltaDown > 0 || isNewConn
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
		if diff >= 0.5 {
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
	return math.Round((stdDev/mean)*1000) / 1000
}

func enforcementActiveRank(s EnforcementState) int {
	switch s {
	case EnforcementBlocked:
		return 1
	case EnforcementWhitelisted:
		return 0
	default:
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

func applySortDirection(c int, asc bool) int {
	if asc {
		return -c
	}
	return c
}

func compareFlowsBySortKey(a, b FlowRecord, key string, asc bool) int {
	switch key {
	case "latest":
		if c := applySortDirection(cmp.Compare(b.LastSeenUnix, a.LastSeenUnix), asc); c != 0 {
			return c
		}
		if ac := cmp.Compare(b.ActiveConns, a.ActiveConns); ac != 0 {
			return ac
		}
		return cmp.Compare(b.RiskScore, a.RiskScore)
	case "live_up":
		if c := applySortDirection(cmp.Compare(b.CurrentUploadBps, a.CurrentUploadBps), asc); c != 0 {
			return c
		}
		if u := applySortDirection(cmp.Compare(b.UploadBytes, a.UploadBytes), asc); u != 0 {
			return u
		}
		return cmp.Compare(b.RiskScore, a.RiskScore)
	case "live_down":
		if c := applySortDirection(cmp.Compare(b.CurrentDownloadBps, a.CurrentDownloadBps), asc); c != 0 {
			return c
		}
		if d := applySortDirection(cmp.Compare(b.DownloadBytes, a.DownloadBytes), asc); d != 0 {
			return d
		}
		return cmp.Compare(b.RiskScore, a.RiskScore)
	case "upload":
		if c := applySortDirection(cmp.Compare(b.UploadBytes, a.UploadBytes), asc); c != 0 {
			return c
		}
		if r := cmp.Compare(b.RiskScore, a.RiskScore); r != 0 {
			return r
		}
		return cmp.Compare(b.DownloadBytes, a.DownloadBytes)
	case "download":
		if c := applySortDirection(cmp.Compare(b.DownloadBytes, a.DownloadBytes), asc); c != 0 {
			return c
		}
		if r := cmp.Compare(b.RiskScore, a.RiskScore); r != 0 {
			return r
		}
		return cmp.Compare(b.UploadBytes, a.UploadBytes)
	case "ratio":
		if c := applySortDirection(cmp.Compare(b.UploadRatio, a.UploadRatio), asc); c != 0 {
			return c
		}
		if u := cmp.Compare(b.UploadBytes, a.UploadBytes); u != 0 {
			return u
		}
		return cmp.Compare(b.RiskScore, a.RiskScore)
	case "risk":
		return applySortDirection(compareRiskHierarchy(a, b), asc)
	default:
		if act := cmp.Compare(flowActiveBucket(b), flowActiveBucket(a)); act != 0 {
			return applySortDirection(act, asc)
		}
		return applySortDirection(compareRiskHierarchy(a, b), asc)
	}
}

// SortFlows 对审计流记录按指定字段（默认 "active": 活跃优先+风险评分，或 "risk" | "upload" | "download" | "ratio"）执行稳定排序。
func SortFlows(flows []FlowRecord, sortBy string, asc bool) {
	key := strings.ToLower(strings.TrimSpace(sortBy))
	slices.SortFunc(flows, func(a, b FlowRecord) int {
		return compareFlowsBySortKey(a, b, key, asc)
	})
}

func isValidDNSLabel(label string) bool {
	if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for i := range len(label) {
		ch := label[i]
		isAlphaNum := (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9')
		if !isAlphaNum && ch != '-' && ch != '_' {
			return false
		}
	}
	return true
}

// isValidAuditDomain 校验嗅探出的字符串是否为合法 FQDN 域名（拒绝类似 "Mijia Cloud" 的 TLS 证书 Subject CN 非域名文本）。
func isValidAuditDomain(s string) bool {
	s = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
	if s == "" || len(s) > 253 || !strings.Contains(s, ".") || net.ParseIP(s) != nil {
		return false
	}
	lastLabel := ""
	for label := range strings.SplitSeq(s, ".") {
		if !isValidDNSLabel(label) {
			return false
		}
		lastLabel = label
	}
	if len(lastLabel) < 2 || strings.Contains(lastLabel, "_") {
		return false
	}
	for i := range len(lastLabel) {
		if lastLabel[i] < '0' || lastLabel[i] > '9' {
			return true
		}
	}
	return false
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
		return rawHost, destIP, cmp.Or(destIP, target), true
	}
	if !isValidAuditDomain(target) {
		return rawHost, destIP, destIP, true
	}
	return rawHost, destIP, target, false
}
