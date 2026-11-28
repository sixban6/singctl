// 文件职责：负责设备审计增量状态（/tmp snapshots）加载与内存池落盘，以及 Clash 活跃连接强制断开控制。
package audit

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"singctl/internal/singbox"
	"singctl/internal/singbox/clashapi"
)

const (
	maxPersistedFlows       = 1500
	maxTrackedConnDeltas    = 3000
	maxArrivalSamples       = 16
	flowIdleTTLSeconds      = 86400 // 超过 24 小时无流量活动的陈旧流自动淘汰
	currentAuditStateSchema = 2
)

// defaultStatePath 返回设备审计增量快照文件的默认路径（位于 /tmp 内存盘，绝不磨损 OpenWrt 闪存）。
func defaultStatePath() string {
	return filepath.Join(os.TempDir(), "singctl-audit-state.json")
}

// persistedFlowEntry 保存单条聚合流的历史累计统计与建连时间序列（用于计算变异系数 CV）。
type persistedFlowEntry struct {
	Key           string   `json:"key"`
	DeviceIP      string   `json:"deviceIp"`
	DeviceName    string   `json:"deviceName,omitempty"`
	DeviceMAC     string   `json:"deviceMac,omitempty"`
	Target        string   `json:"target"`
	RawHost       string   `json:"rawHost,omitempty"`
	DestIP        string   `json:"destIp,omitempty"`
	DestPort      int      `json:"destPort"`
	IsDirectIP    bool     `json:"isDirectIp"`
	Network       string   `json:"network"`
	Outbound      string   `json:"outbound"`
	Chains        []string `json:"chains,omitempty"`
	Rule          string   `json:"rule,omitempty"`
	UploadBytes   int64    `json:"uploadBytes"`
	DownloadBytes int64    `json:"downloadBytes"`
	ConnCount     int      `json:"connCount"`
	FirstSeenUnix int64    `json:"firstSeenUnix"`
	LastSeenUnix  int64    `json:"lastSeenUnix"`
	NightHits     int      `json:"nightHits"`
	ArrivalsUnix  []int64  `json:"arrivalsUnix,omitempty"`
}

type connByteCursor struct {
	Upload   int64 `json:"up"`
	Download int64 `json:"down"`
	SeenUnix int64 `json:"ts"`
}

type persistedAuditState struct {
	SchemaVersion int                                `json:"schemaVersion,omitempty"`
	UpdatedUnix   int64                              `json:"updatedUnix"`
	Flows         map[string]*persistedFlowEntry     `json:"flows"`
	ConnCursors   map[string]connByteCursor          `json:"connCursors"`
	Profiles      map[string]*persistedDeviceProfile `json:"profiles,omitempty"`
}

func purgeExpiredFlows(flows map[string]*persistedFlowEntry, nowUnix int64) bool {
	if nowUnix <= 0 {
		return false
	}
	before := len(flows)
	maps.DeleteFunc(flows, func(_ string, e *persistedFlowEntry) bool {
		return e == nil || (e.LastSeenUnix > 0 && nowUnix-e.LastSeenUnix > flowIdleTTLSeconds)
	})
	return len(flows) != before
}

func migrateLegacyStateV2(st *persistedAuditState) {
	migrated := make(map[string]*persistedFlowEntry, len(st.Flows))
	for _, e := range st.Flows {
		if e == nil {
			continue
		}
		e.NightHits = 0
		if !e.IsDirectIP && net.ParseIP(e.Target) == nil && !isValidAuditDomain(e.Target) {
			e.RawHost = cmp.Or(e.RawHost, e.Target)
			if net.ParseIP(e.DestIP) == nil {
				continue
			}
			e.Target = e.DestIP
			e.IsDirectIP = true
			e.Key = e.DeviceIP + "|" + e.Target + "|" + e.Network
		}
		prev, exists := migrated[e.Key]
		if !exists {
			migrated[e.Key] = e
			continue
		}
		prev.UploadBytes += e.UploadBytes
		prev.DownloadBytes += e.DownloadBytes
		prev.ConnCount += e.ConnCount
		if e.FirstSeenUnix > 0 && (prev.FirstSeenUnix == 0 || e.FirstSeenUnix < prev.FirstSeenUnix) {
			prev.FirstSeenUnix = e.FirstSeenUnix
		}
		prev.LastSeenUnix = max(prev.LastSeenUnix, e.LastSeenUnix)
		prev.RawHost = cmp.Or(prev.RawHost, e.RawHost)
	}
	st.Flows = migrated
	st.SchemaVersion = currentAuditStateSchema
}

func (c *Collector) loadStateLocked(nowUnix int64) *persistedAuditState {
	if c.statePath != "" {
		fp := auditFileFingerprint(c.statePath)
		if c.cachedState != nil && c.cachedStateFp == fp {
			if purgeExpiredFlows(c.cachedState.Flows, nowUnix) {
				c.stateDirty = true
			}
			return c.cachedState
		}
	}

	st := &persistedAuditState{
		SchemaVersion: currentAuditStateSchema,
		Flows:         make(map[string]*persistedFlowEntry),
		ConnCursors:   make(map[string]connByteCursor),
	}
	if c.statePath == "" {
		return st
	}
	raw, err := os.ReadFile(c.statePath)
	if err != nil {
		c.cachedState = st
		c.cachedStateFp = auditFileFingerprint(c.statePath)
		return st
	}
	st.SchemaVersion = 0
	_ = json.Unmarshal(raw, st)
	if st.Flows == nil {
		st.Flows = make(map[string]*persistedFlowEntry)
	}
	if st.ConnCursors == nil {
		st.ConnCursors = make(map[string]connByteCursor)
	}
	if st.SchemaVersion < currentAuditStateSchema {
		migrateLegacyStateV2(st)
	}
	purgeExpiredFlows(st.Flows, nowUnix)
	c.cachedState = st
	c.cachedStateFp = auditFileFingerprint(c.statePath)
	return st
}

var auditStateBufPool = sync.Pool{
	New: func() any {
		return bytes.NewBuffer(make([]byte, 0, 16<<10))
	},
}

func writeStateFileAtomically(statePath string, payload []byte) {
	tmpFile, err := os.CreateTemp(filepath.Dir(statePath), ".singctl-audit-state-*.tmp")
	if err != nil {
		return
	}
	tmpPath := tmpFile.Name()
	_, writeErr := tmpFile.Write(payload)
	chmodErr := tmpFile.Chmod(0600)
	closeErr := tmpFile.Close()
	if writeErr != nil || chmodErr != nil || closeErr != nil {
		_ = os.Remove(tmpPath)
		return
	}
	if os.Rename(tmpPath, statePath) != nil {
		_ = os.Remove(tmpPath)
	}
}

func (c *Collector) saveStateLocked(st *persistedAuditState, activeByKey map[string][]string, now time.Time) {
	if c.statePath == "" || st == nil {
		return
	}
	nowUnix := now.Unix()
	st.SchemaVersion = currentAuditStateSchema
	st.UpdatedUnix = nowUnix

	purgeExpiredFlows(st.Flows, nowUnix)
	c.enforceBoundsLocked(st, activeByKey, c.cachedMergedLANDevs, c.cachedSelfIPs, c.resolveEngineLocked(), nowUnix)

	buf := auditStateBufPool.Get().(*bytes.Buffer)
	buf.Reset()
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(false)
	err := enc.Encode(st)
	if err == nil {
		writeStateFileAtomically(c.statePath, buf.Bytes())
	}
	if buf.Cap() <= 2<<20 {
		auditStateBufPool.Put(buf)
	}
	if err != nil {
		return
	}
	c.cachedState = st
	c.cachedStateFp = auditFileFingerprint(c.statePath)
	c.stateDirty = false
	c.lastSavedUnix = nowUnix
}

// CloseConnectionsRequest 描述 WebUI 临时断开活跃连接的筛选条件。
type CloseConnectionsRequest struct {
	All         bool     `json:"all,omitempty"`
	ConnIDs     []string `json:"connIds,omitempty"`
	DeviceIP    string   `json:"deviceIp,omitempty"`
	Target      string   `json:"target,omitempty"`
	MatchSuffix bool     `json:"matchSuffix,omitempty"`
	Network     string   `json:"network,omitempty"`
}

// CloseConnectionsResult 返回本次踢断活跃连接的结果统计。
type CloseConnectionsResult struct {
	Closed int  `json:"closed"`
	All    bool `json:"all"`
}

func closeAllEndpointConns(ctx context.Context, client *clashapi.Client, baseURL, secret string) error {
	return client.CloseAllConnectionsAt(ctx, baseURL, secret)
}

func connMatchesCloseFilter(
	conn clashConnection,
	selfIPs map[string]bool,
	devDir map[string]lanDeviceInfo,
	wantDev, wantNet, wantTarget string,
	wantPrefix *netip.Prefix,
	matchSuffix bool,
) bool {
	if conn.ID == "" {
		return false
	}
	connSrc := normalizeSourceDeviceIP(strings.TrimSpace(conn.Metadata.SourceIP), selfIPs, devDir)
	if wantDev != "" && connSrc != wantDev {
		return false
	}
	connNet := strings.ToLower(cmp.Or(strings.TrimSpace(conn.Metadata.Network), "tcp"))
	if wantNet != "" && connNet != wantNet {
		return false
	}
	if wantTarget == "" && wantPrefix == nil {
		return true
	}
	_, destIP, connTarget, _ := resolveConnTarget(conn)
	if wantPrefix != nil {
		if addr, err := netip.ParseAddr(strings.TrimSpace(destIP)); err == nil && wantPrefix.Contains(addr.Unmap()) {
			return true
		}
	}
	if strings.EqualFold(connTarget, wantTarget) || destIP == wantTarget {
		return true
	}
	if matchSuffix && wantTarget != "" && connTarget != "" {
		lowerConn := strings.ToLower(strings.TrimSuffix(connTarget, "."))
		if strings.HasSuffix(lowerConn, "."+wantTarget) {
			return true
		}
	}
	return false
}

func (c *Collector) resolveMatchingConnIDs(
	ctx context.Context,
	client *clashapi.Client,
	baseURL, secret string,
	req CloseConnectionsRequest,
) (targetIDs []string, reachable bool, err error) {
	for _, id := range req.ConnIDs {
		if cleanID := strings.TrimSpace(id); cleanID != "" && !slices.Contains(targetIDs, cleanID) {
			targetIDs = append(targetIDs, cleanID)
		}
	}

	wantTarget := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(req.Target)), ".")
	wantDev := strings.TrimSpace(req.DeviceIP)
	wantNet := strings.ToLower(strings.TrimSpace(req.Network))
	var wantPrefix *netip.Prefix
	if strings.Contains(wantTarget, "/") {
		if pfx, err := netip.ParsePrefix(wantTarget); err == nil {
			normPfx := netip.PrefixFrom(pfx.Addr().Unmap(), pfx.Bits()).Masked()
			wantPrefix = &normPfx
		}
	}
	if wantTarget == "" && wantPrefix == nil && wantDev == "" && len(targetIDs) > 0 {
		return targetIDs, false, nil
	}

	parsed, fetchErr := fetchEndpointConnections(ctx, client, baseURL, secret)
	if fetchErr != nil {
		return targetIDs, false, fetchErr
	}

	selfIPs := collectLocalInterfaceIPs()
	c.mu.Lock()
	devDir := c.resolveLANDevicesLocked()
	c.mu.Unlock()
	for _, conn := range parsed.Connections {
		if connMatchesCloseFilter(conn, selfIPs, devDir, wantDev, wantNet, wantTarget, wantPrefix, req.MatchSuffix) && !slices.Contains(targetIDs, conn.ID) {
			targetIDs = append(targetIDs, conn.ID)
		}
	}
	return targetIDs, true, nil
}

func deleteEndpointConnIDs(ctx context.Context, client *clashapi.Client, baseURL, secret string, targetIDs []string) (closed int, anyValid bool, lastErr error) {
	for _, id := range targetIDs {
		err := client.CloseConnectionAt(ctx, baseURL, secret, id)
		if err == nil {
			anyValid = true
			closed++
			continue
		}
		var stErr *clashapi.StatusError
		if errors.As(err, &stErr) && stErr.StatusCode == http.StatusNotFound {
			anyValid = true
			continue
		}
		lastErr = err
	}
	return closed, anyValid, lastErr
}

// CloseConnections 通过 sing-box Clash API 临时断开指定（或全部）活跃连接，触发客户端重新握手选路。
func (c *Collector) CloseConnections(ctx context.Context, req CloseConnectionsRequest) (CloseConnectionsResult, error) {
	c.mu.Lock()
	if !c.customEndpoints {
		c.endpoints = singbox.ClashAPIEndpoints()
		c.secret = singbox.ClashAPISecret()
	}
	endpoints := slices.Clone(c.endpoints)
	secret := c.secret
	client := c.clashClient
	c.mu.Unlock()

	if len(endpoints) == 0 {
		endpoints = []string{"http://127.0.0.1:9090"}
	}
	if client == nil {
		client = clashapi.NewClient(clashapi.Options{RequestTimeout: 2500 * time.Millisecond})
	}

	var lastErr error
	for _, ep := range endpoints {
		baseURL := strings.TrimRight(strings.TrimSpace(ep), "/")
		if baseURL == "" {
			continue
		}
		if req.All {
			if err := closeAllEndpointConns(ctx, client, baseURL, secret); err == nil {
				return CloseConnectionsResult{All: true}, nil
			} else {
				lastErr = err
			}
			continue
		}

		targetIDs, reachable, listErr := c.resolveMatchingConnIDs(ctx, client, baseURL, secret, req)
		if listErr != nil {
			lastErr = listErr
		}
		if !reachable && listErr != nil {
			continue
		}
		closed, anyValid, delErr := deleteEndpointConnIDs(ctx, client, baseURL, secret, targetIDs)
		if delErr != nil {
			lastErr = delErr
		}
		if reachable || anyValid {
			return CloseConnectionsResult{Closed: closed}, nil
		}
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("未找到可达的 sing-box Clash API 控制端口")
	}
	return CloseConnectionsResult{}, lastErr
}
