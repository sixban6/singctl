// 文件职责：实现 /api/sb/traffic 按需低开销实时速率采样器及 Clash /connections 流式摘要解码。
package webui

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"time"
)

func (s *Server) handleSbTrafficGet(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	s.trafficMu.Lock()
	s.trafficLastReqAt = now
	if !s.trafficSampledAt.IsZero() && now.Sub(s.trafficSampledAt) < trafficCacheFreshWindow {
		snap := s.trafficState
		if snap.Running && !s.trafficRunning {
			s.startTrafficSamplerLocked()
		}
		s.trafficMu.Unlock()
		writeJSON(w, http.StatusOK, snap)
		return
	}
	s.trafficMu.Unlock()

	snap := s.sampleClashTrafficOnce(r.Context())

	s.trafficMu.Lock()
	s.trafficLastReqAt = time.Now()
	s.trafficState = snap
	s.trafficSampledAt = time.Now()
	if snap.Running && !s.trafficRunning {
		s.startTrafficSamplerLocked()
	}
	s.trafficMu.Unlock()

	writeJSON(w, http.StatusOK, snap)
}

func (s *Server) sampleClashTrafficOnce(parentCtx context.Context) sbTrafficResponse {
	ctx, cancel := context.WithTimeout(parentCtx, 2200*time.Millisecond)
	defer cancel()

	base, secret, err := s.clashEndpointAndSecret(ctx)
	if err != nil {
		return sbTrafficResponse{
			Running: false,
			Error:   err.Error(),
		}
	}

	s.trafficMu.Lock()
	skipMem := time.Now().Before(s.trafficMemUnsupportedUntil)
	s.trafficMu.Unlock()

	var (
		connUp, connDown int64
		connCount        int
		connOK           bool
		rateUp, rateDown int64
		tickOK           bool
		memInuse         int64
		memOK            bool
		wg               sync.WaitGroup
	)

	// 1. 活跃连接总数与累计流量
	wg.Go(func() {
		connUp, connDown, connCount, connOK = fetchClashConnections(ctx, base, secret)
	})

	// 2. 瞬时上下行速率（Clash /traffic 为流式 NDJSON，读取首条后立即释放连接）
	wg.Go(func() {
		tickCtx, tickCancel := context.WithTimeout(ctx, 1400*time.Millisecond)
		defer tickCancel()
		var tick struct {
			Up   int64 `json:"up"`
			Down int64 `json:"down"`
		}
		if readFirstClashStreamObject(tickCtx, base+"/traffic", secret, &tick) {
			rateUp = tick.Up
			rateDown = tick.Down
			tickOK = true
		}
	})

	// 3. sing-box 内核内存占用（若内核不支持 /memory 则冷却退避，避免阻塞采样）
	if !skipMem {
		wg.Go(func() {
			memCtx, memCancel := context.WithTimeout(ctx, 250*time.Millisecond)
			defer memCancel()
			var mem struct {
				Inuse int64 `json:"inuse"`
			}
			if readFirstClashStreamObject(memCtx, base+"/memory", secret, &mem) {
				memInuse = mem.Inuse
				memOK = true
			}
		})
	}

	wg.Wait()

	if connOK && !skipMem {
		s.trafficMu.Lock()
		if memOK {
			s.trafficMemUnsupportedUntil = time.Time{}
		} else {
			s.trafficMemUnsupportedUntil = time.Now().Add(trafficMemRetryCooldown)
		}
		s.trafficMu.Unlock()
	}

	if !connOK && !tickOK {
		s.invalidateClashCache()
		return sbTrafficResponse{
			Running: false,
			Error:   errClashUnreachable.Error(),
		}
	}

	return sbTrafficResponse{
		Running:       true,
		Up:            rateUp,
		Down:          rateDown,
		UploadTotal:   connUp,
		DownloadTotal: connDown,
		Connections:   connCount,
		Memory:        memInuse,
	}
}

func (s *Server) startTrafficSamplerLocked() {
	if s.trafficRunning {
		return
	}
	s.trafficRunning = true
	go s.runTrafficSampler()
}

func (s *Server) runTrafficSampler() {
	streamCtx, streamCancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	defer func() {
		streamCancel()
		wg.Wait()
		s.trafficMu.Lock()
		s.trafficRunning = false
		s.trafficMu.Unlock()
	}()

	// 后台持续读取 Clash /traffic 流式 NDJSON 推送实时速率
	wg.Go(func() {
		consecutiveFail := 0
		for streamCtx.Err() == nil {
			probeCtx, probeCancel := context.WithTimeout(streamCtx, 1500*time.Millisecond)
			base, secret, err := s.clashEndpointAndSecret(probeCtx)
			probeCancel()
			if err != nil {
				consecutiveFail++
				if consecutiveFail >= 2 {
					return
				}
				select {
				case <-streamCtx.Done():
					return
				case <-time.After(time.Second):
					continue
				}
			}

			req, reqErr := http.NewRequestWithContext(streamCtx, http.MethodGet, base+"/traffic", nil)
			if reqErr != nil {
				return
			}
			if secret != "" {
				req.Header.Set("Authorization", "Bearer "+secret)
			}
			resp, doErr := sharedClashStreamClient.Do(req)
			if doErr != nil || resp.StatusCode != http.StatusOK {
				if resp != nil {
					_ = resp.Body.Close()
				}
				consecutiveFail++
				if consecutiveFail >= 2 {
					return
				}
				select {
				case <-streamCtx.Done():
					return
				case <-time.After(time.Second):
					continue
				}
			}
			consecutiveFail = 0
			dec := json.NewDecoder(resp.Body)
			for streamCtx.Err() == nil {
				var tick struct {
					Up   int64 `json:"up"`
					Down int64 `json:"down"`
				}
				if dec.Decode(&tick) != nil {
					break
				}
				s.trafficMu.Lock()
				s.trafficState.Running = true
				s.trafficState.Up = tick.Up
				s.trafficState.Down = tick.Down
				s.trafficSampledAt = time.Now()
				s.trafficMu.Unlock()
			}
			_ = resp.Body.Close()
			select {
			case <-streamCtx.Done():
				return
			case <-time.After(time.Second):
			}
		}
	})

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	consecutiveConnFail := 0
	tickCount := 0
	for range ticker.C {
		s.trafficMu.Lock()
		idle := time.Since(s.trafficLastReqAt) > trafficIdleStopWindow
		skipMem := time.Now().Before(s.trafficMemUnsupportedUntil)
		s.trafficMu.Unlock()
		if idle {
			return
		}

		tickCount++
		ctx, cancel := context.WithTimeout(streamCtx, 1500*time.Millisecond)
		base, secret, err := s.clashEndpointAndSecret(ctx)
		if err != nil {
			cancel()
			consecutiveConnFail++
			if consecutiveConnFail >= 2 {
				s.trafficMu.Lock()
				s.trafficState = sbTrafficResponse{Running: false, Error: err.Error()}
				s.trafficSampledAt = time.Now()
				s.trafficMu.Unlock()
				return
			}
			continue
		}

		connUp, connDown, connCount, connOK := fetchClashConnections(ctx, base, secret)
		if !connOK {
			cancel()
			consecutiveConnFail++
			if consecutiveConnFail >= 2 {
				s.invalidateClashCache()
				s.trafficMu.Lock()
				s.trafficState = sbTrafficResponse{Running: false, Error: errClashUnreachable.Error()}
				s.trafficSampledAt = time.Now()
				s.trafficMu.Unlock()
				return
			}
			continue
		}
		consecutiveConnFail = 0

		var memInuse int64
		var hasMemUpdate bool
		if !skipMem && tickCount%5 == 0 {
			memCtx, memCancel := context.WithTimeout(ctx, 250*time.Millisecond)
			var mem struct {
				Inuse int64 `json:"inuse"`
			}
			if readFirstClashStreamObject(memCtx, base+"/memory", secret, &mem) {
				memInuse = mem.Inuse
				hasMemUpdate = true
			} else {
				s.trafficMu.Lock()
				s.trafficMemUnsupportedUntil = time.Now().Add(trafficMemRetryCooldown)
				s.trafficMu.Unlock()
			}
			memCancel()
		}
		cancel()

		s.trafficMu.Lock()
		s.trafficState.Running = true
		s.trafficState.Error = ""
		s.trafficState.UploadTotal = connUp
		s.trafficState.DownloadTotal = connDown
		s.trafficState.Connections = connCount
		if hasMemUpdate {
			s.trafficState.Memory = memInuse
		}
		s.trafficSampledAt = time.Now()
		s.trafficMu.Unlock()
	}
}

func fetchClashConnections(ctx context.Context, base, secret string) (upTotal, downTotal int64, count int, ok bool) {
	reqCtx, cancel := context.WithTimeout(ctx, 1200*time.Millisecond)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, base+"/connections", nil)
	if err != nil {
		return 0, 0, 0, false
	}
	if secret != "" {
		req.Header.Set("Authorization", "Bearer "+secret)
	}
	resp, err := sharedClashStreamClient.Do(req)
	if err != nil {
		return 0, 0, 0, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return 0, 0, 0, false
	}
	return decodeClashConnectionsSummary(io.LimitReader(resp.Body, 16<<20))
}

// decodeClashConnectionsSummary 流式统计 Clash /connections 中的累计上下行字节数与连接数组长度。
// 性能优化原理：此前反序列化为 `Connections []any` 会为每秒数千条活跃连接的字段分配大量 map/slice 堆对象；
// 本函数通过 json.Decoder + 复用同一块 json.RawMessage 缓冲区扫描数组元素，只统计数量与核心整数字段，
// 在保持 100% 标准库 JSON 校验准确性的前提下将热点分配降至接近零。
func decodeClashConnectionsSummary(r io.Reader) (upTotal, downTotal int64, count int, ok bool) {
	dec := json.NewDecoder(r)
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return 0, 0, 0, false
	}

	var scratch json.RawMessage
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return 0, 0, 0, false
		}
		key, isStr := keyTok.(string)
		if !isStr {
			return 0, 0, 0, false
		}
		switch key {
		case "uploadTotal":
			if err := dec.Decode(&upTotal); err != nil {
				return 0, 0, 0, false
			}
		case "downloadTotal":
			if err := dec.Decode(&downTotal); err != nil {
				return 0, 0, 0, false
			}
		case "connections":
			arrTok, err := dec.Token()
			if err != nil {
				return 0, 0, 0, false
			}
			if arrTok == nil {
				continue
			}
			if arrTok != json.Delim('[') {
				return 0, 0, 0, false
			}
			for dec.More() {
				scratch = scratch[:0]
				if err := dec.Decode(&scratch); err != nil {
					return 0, 0, 0, false
				}
				count++
			}
			endArr, err := dec.Token()
			if err != nil || endArr != json.Delim(']') {
				return 0, 0, 0, false
			}
		default:
			scratch = scratch[:0]
			if err := dec.Decode(&scratch); err != nil {
				return 0, 0, 0, false
			}
		}
	}

	endObj, err := dec.Token()
	if err != nil || endObj != json.Delim('}') {
		return 0, 0, 0, false
	}
	if _, err := dec.Token(); err != io.EOF {
		return 0, 0, 0, false
	}
	return upTotal, downTotal, count, true
}

func readFirstClashStreamObject(ctx context.Context, fullURL, secret string, dst any) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
	if err != nil {
		return false
	}
	if secret != "" {
		req.Header.Set("Authorization", "Bearer "+secret)
	}
	resp, err := sharedClashStreamClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 64*1024)).Decode(dst) == nil
}
