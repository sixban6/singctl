// 文件职责：负责设备审计增量状态（/tmp snapshots）加载与内存池落盘，以及 Clash 活跃连接强制断开控制。
package audit

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"singctl/internal/singbox"
	"slices"
	"strings"
	"sync"
	"time"
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
	SchemaVersion int                            `json:"schemaVersion,omitempty"`
	UpdatedUnix   int64                          `json:"updatedUnix"`
	Flows         map[string]*persistedFlowEntry `json:"flows"`
	ConnCursors   map[string]connByteCursor      `json:"connCursors"`
}

func (c *Collector) loadStateLocked(nowUnix int64) *persistedAuditState {
	if c.statePath != "" {
		fp := auditFileFingerprint(c.statePath)
		if c.cachedState != nil && c.cachedStateFp == fp {
			if nowUnix > 0 {
				before := len(c.cachedState.Flows)
				maps.DeleteFunc(c.cachedState.Flows, func(_ string, e *persistedFlowEntry) bool {
					return e == nil || (e.LastSeenUnix > 0 && nowUnix-e.LastSeenUnix > flowIdleTTLSeconds)
				})
				if len(c.cachedState.Flows) != before {
					c.stateDirty = true
				}
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

	// Schema v2 一次性平滑自愈迁移：
	// 1) 清零旧版 OpenWrt UTC 时区回退导致的白天误记 NightHits（保留累计上下行流量）
	// 2) 将旧快照中因证书 CN 嗅探混入的非法非域名 Target（如 "mijia cloud"）回退并归并至真实 DestIP
	if st.SchemaVersion < currentAuditStateSchema {
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
			if prev, exists := migrated[e.Key]; exists {
				prev.UploadBytes += e.UploadBytes
				prev.DownloadBytes += e.DownloadBytes
				prev.ConnCount += e.ConnCount
				if e.FirstSeenUnix > 0 && (prev.FirstSeenUnix == 0 || e.FirstSeenUnix < prev.FirstSeenUnix) {
					prev.FirstSeenUnix = e.FirstSeenUnix
				}
				if e.LastSeenUnix > prev.LastSeenUnix {
					prev.LastSeenUnix = e.LastSeenUnix
				}
				prev.RawHost = cmp.Or(prev.RawHost, e.RawHost)
			} else {
				migrated[e.Key] = e
			}
		}
		st.Flows = migrated
		st.SchemaVersion = currentAuditStateSchema
	}

	// 24 小时滑动窗口：淘汰超过 24 小时无活动的陈旧流记录，避免跨日长尾连接无限累积
	if nowUnix > 0 {
		maps.DeleteFunc(st.Flows, func(_ string, e *persistedFlowEntry) bool {
			return e == nil || (e.LastSeenUnix > 0 && nowUnix-e.LastSeenUnix > flowIdleTTLSeconds)
		})
	}
	c.cachedState = st
	c.cachedStateFp = auditFileFingerprint(c.statePath)
	return st
}

var auditStateBufPool = sync.Pool{
	New: func() any {
		return bytes.NewBuffer(make([]byte, 0, 16<<10))
	},
}

func (c *Collector) saveStateLocked(st *persistedAuditState, activeByKey map[string][]string, now time.Time) {
	if c.statePath == "" || st == nil {
		return
	}
	nowUnix := now.Unix()
	st.SchemaVersion = currentAuditStateSchema
	st.UpdatedUnix = nowUnix

	// 修剪过期连接游标 (超过 2 小时未活动或超出容量上限)
	if len(st.ConnCursors) > maxTrackedConnDeltas {
		maps.DeleteFunc(st.ConnCursors, func(_ string, cur connByteCursor) bool {
			return nowUnix-cur.SeenUnix > 7200
		})
	}

	// 淘汰超过 24 小时未活跃的陈旧流
	maps.DeleteFunc(st.Flows, func(_ string, e *persistedFlowEntry) bool {
		return e == nil || (e.LastSeenUnix > 0 && nowUnix-e.LastSeenUnix > flowIdleTTLSeconds)
	})

	// 修剪聚合流桶 (最多保留 maxPersistedFlows 条记录，优先保护当前活跃连接，恒定内存 < 1MB)
	if len(st.Flows) > maxPersistedFlows {
		entries := make([]*persistedFlowEntry, 0, len(st.Flows))
		for _, e := range st.Flows {
			entries = append(entries, e)
		}
		slices.SortFunc(entries, func(a, b *persistedFlowEntry) int {
			aAct, bAct := 0, 0
			if len(activeByKey[a.Key]) > 0 {
				aAct = 1
			}
			if len(activeByKey[b.Key]) > 0 {
				bAct = 1
			}
			if c := cmp.Compare(bAct, aAct); c != 0 {
				return c
			}
			if c := cmp.Compare(b.UploadBytes, a.UploadBytes); c != 0 {
				return c
			}
			return cmp.Compare(b.LastSeenUnix, a.LastSeenUnix)
		})
		trimmed := make(map[string]*persistedFlowEntry, maxPersistedFlows)
		for _, e := range entries[:maxPersistedFlows] {
			trimmed[e.Key] = e
		}
		st.Flows = trimmed
	}

	buf := auditStateBufPool.Get().(*bytes.Buffer)
	buf.Reset()
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(false)
	err := enc.Encode(st)
	if err == nil {
		if tmpFile, crErr := os.CreateTemp(filepath.Dir(c.statePath), ".singctl-audit-state-*.tmp"); crErr == nil {
			tmpPath := tmpFile.Name()
			_, writeErr := tmpFile.Write(buf.Bytes())
			chmodErr := tmpFile.Chmod(0600)
			closeErr := tmpFile.Close()
			if writeErr == nil && chmodErr == nil && closeErr == nil {
				if os.Rename(tmpPath, c.statePath) != nil {
					_ = os.Remove(tmpPath)
				}
			} else {
				_ = os.Remove(tmpPath)
			}
		}
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
	All      bool     `json:"all,omitempty"`
	ConnIDs  []string `json:"connIds,omitempty"`
	DeviceIP string   `json:"deviceIp,omitempty"`
	Target   string   `json:"target,omitempty"`
	Network  string   `json:"network,omitempty"`
}

// CloseConnectionsResult 返回本次踢断活跃连接的结果统计。
type CloseConnectionsResult struct {
	Closed int  `json:"closed"`
	All    bool `json:"all"`
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
	client := c.httpClient
	c.mu.Unlock()

	if len(endpoints) == 0 {
		endpoints = []string{"http://127.0.0.1:9090"}
	}
	if client == nil {
		client = &http.Client{Timeout: 2500 * time.Millisecond}
	}

	var lastErr error
	for _, ep := range endpoints {
		baseURL := strings.TrimRight(strings.TrimSpace(ep), "/")
		if baseURL == "" {
			continue
		}

		if req.All {
			delReq, err := http.NewRequestWithContext(ctx, http.MethodDelete, baseURL+"/connections", nil)
			if err != nil {
				lastErr = err
				continue
			}
			if secret != "" {
				delReq.Header.Set("Authorization", "Bearer "+secret)
			}
			resp, err := client.Do(delReq)
			if err != nil {
				lastErr = err
				continue
			}
			resp.Body.Close()
			if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusOK {
				return CloseConnectionsResult{All: true}, nil
			}
			lastErr = fmt.Errorf("Clash API 返回状态 %d", resp.StatusCode)
			continue
		}

		// 收集显式传入的连接 ID，并补充拉取一次活跃连接表以捕捉刚新建的同目标连接
		targetIDs := make([]string, 0, len(req.ConnIDs))
		for _, id := range req.ConnIDs {
			cleanID := strings.TrimSpace(id)
			if cleanID != "" && !slices.Contains(targetIDs, cleanID) {
				targetIDs = append(targetIDs, cleanID)
			}
		}

		wantTarget := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(req.Target)), ".")
		wantDev := strings.TrimSpace(req.DeviceIP)
		wantNet := strings.ToLower(strings.TrimSpace(req.Network))
		reachable := false

		if wantTarget != "" || wantDev != "" || len(targetIDs) == 0 {
			getReq, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/connections", nil)
			if err == nil {
				if secret != "" {
					getReq.Header.Set("Authorization", "Bearer "+secret)
				}
				getResp, err := client.Do(getReq)
				if err != nil {
					lastErr = err
					continue
				}
				if getResp.StatusCode == http.StatusOK {
					reachable = true
					var parsed clashConnectionsResponse
					if decErr := json.NewDecoder(getResp.Body).Decode(&parsed); decErr == nil {
						selfIPs := collectLocalInterfaceIPs()
						devDir := c.resolveLANDevicesLocked()
						for _, conn := range parsed.Connections {
							connSrc := normalizeSourceDeviceIP(strings.TrimSpace(conn.Metadata.SourceIP), selfIPs, devDir)
							_, destIP, connTarget, _ := resolveConnTarget(conn)
							connNet := strings.ToLower(cmp.Or(strings.TrimSpace(conn.Metadata.Network), "tcp"))
							if wantDev != "" && connSrc != wantDev {
								continue
							}
							if wantNet != "" && connNet != wantNet {
								continue
							}
							if wantTarget != "" && !strings.EqualFold(connTarget, wantTarget) && destIP != wantTarget {
								continue
							}
							if conn.ID != "" && !slices.Contains(targetIDs, conn.ID) {
								targetIDs = append(targetIDs, conn.ID)
							}
						}
					}
				} else {
					lastErr = fmt.Errorf("Clash API /connections 返回状态 %d", getResp.StatusCode)
				}
				getResp.Body.Close()
				if !reachable && len(targetIDs) == 0 {
					continue
				}
			}
		}

		closed := 0
		anySucceeded := reachable
		for _, id := range targetIDs {
			delReq, err := http.NewRequestWithContext(ctx, http.MethodDelete, baseURL+"/connections/"+url.PathEscape(id), nil)
			if err != nil {
				lastErr = err
				continue
			}
			if secret != "" {
				delReq.Header.Set("Authorization", "Bearer "+secret)
			}
			delResp, err := client.Do(delReq)
			if err != nil {
				lastErr = err
				continue
			}
			delResp.Body.Close()
			anySucceeded = true
			if delResp.StatusCode == http.StatusNoContent || delResp.StatusCode == http.StatusOK {
				closed++
			}
		}
		if anySucceeded {
			return CloseConnectionsResult{Closed: closed}, nil
		}
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("未找到可达的 sing-box Clash API 控制端口")
	}
	return CloseConnectionsResult{}, lastErr
}
