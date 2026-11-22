// 文件职责：实现 /api/sb/traffic 按需低开销实时速率采样器，流式解码与连接采样全部委托 clashapi。
package webui

import (
	"context"
	"net/http"
	"sync"
	"time"

	"singctl/internal/singbox/clashapi"
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

func (s *Server) sampleClashTrafficOnce(parentCtx context.Context) SbTrafficResponse {
	ctx, cancel := context.WithTimeout(parentCtx, 2200*time.Millisecond)
	defer cancel()

	base, secret, err := s.clashEndpointAndSecret(ctx)
	if err != nil {
		return SbTrafficResponse{
			Running: false,
			Error:   err.Error(),
		}
	}

	s.trafficMu.Lock()
	skipMem := time.Now().Before(s.trafficMemUnsupportedUntil)
	s.trafficMu.Unlock()

	cli := s.clashClient()
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

	wg.Go(func() {
		connUp, connDown, connCount, connOK = cli.ConnectionsSummaryAt(ctx, base, secret)
	})

	wg.Go(func() {
		tickCtx, tickCancel := context.WithTimeout(ctx, 1400*time.Millisecond)
		defer tickCancel()
		var tick struct {
			Up   int64 `json:"up"`
			Down int64 `json:"down"`
		}
		if cli.ReadFirstStreamObjectAt(tickCtx, base, secret, "/traffic", &tick) {
			rateUp = tick.Up
			rateDown = tick.Down
			tickOK = true
		}
	})

	if !skipMem {
		wg.Go(func() {
			memCtx, memCancel := context.WithTimeout(ctx, 250*time.Millisecond)
			defer memCancel()
			var mem struct {
				Inuse int64 `json:"inuse"`
			}
			if cli.ReadFirstStreamObjectAt(memCtx, base, secret, "/memory", &mem) {
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
		return SbTrafficResponse{
			Running: false,
			Error:   clashapi.ErrUnreachable.Error(),
		}
	}

	return SbTrafficResponse{
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

	cli := s.clashClient()

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

			gotAny := false
			streamErr := cli.StreamTrafficAt(streamCtx, base, secret, func(up, down int64) {
				gotAny = true
				s.trafficMu.Lock()
				s.trafficState.Running = true
				s.trafficState.Up = up
				s.trafficState.Down = down
				s.trafficSampledAt = time.Now()
				s.trafficMu.Unlock()
			})
			if streamErr != nil && !gotAny {
				consecutiveFail++
				if consecutiveFail >= 2 {
					return
				}
			} else {
				consecutiveFail = 0
			}
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
				s.trafficState = SbTrafficResponse{Running: false, Error: err.Error()}
				s.trafficSampledAt = time.Now()
				s.trafficMu.Unlock()
				return
			}
			continue
		}

		connUp, connDown, connCount, connOK := cli.ConnectionsSummaryAt(ctx, base, secret)
		if !connOK {
			cancel()
			consecutiveConnFail++
			if consecutiveConnFail >= 2 {
				s.invalidateClashCache()
				s.trafficMu.Lock()
				s.trafficState = SbTrafficResponse{Running: false, Error: clashapi.ErrUnreachable.Error()}
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
			if cli.ReadFirstStreamObjectAt(memCtx, base, secret, "/memory", &mem) {
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
