package daemon

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"singctl/internal/config"
)

func TestGroupFailoverState_WANGate_Failover_And_AutoFailback(t *testing.T) {
	var (
		mu         sync.Mutex
		currentNow = "node-primary"
		primaryUp  = false
		wanAlive   = false
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/proxies":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"proxies": map[string]any{
					"Proxy": map[string]any{
						"type": "Selector",
						"now":  currentNow,
						"all":  []string{"剩余流量: 100GB", "node-primary", "node-slow", "node-fast"},
					},
					"node-primary": map[string]any{"type": "VLESS"},
					"node-slow":    map[string]any{"type": "Hysteria2"},
					"node-fast":    map[string]any{"type": "VLESS"},
				},
			})
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/delay"):
			parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/proxies/"), "/")
			node := parts[0]
			switch node {
			case "node-primary":
				if !primaryUp {
					http.Error(w, `{"message":"timeout"}`, http.StatusGatewayTimeout)
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"delay": 95})
			case "node-slow":
				_ = json.NewEncoder(w).Encode(map[string]any{"delay": 380})
			case "node-fast":
				_ = json.NewEncoder(w).Encode(map[string]any{"delay": 110})
			default:
				http.Error(w, `{"message":"dead"}`, http.StatusGatewayTimeout)
			}
		case r.Method == http.MethodPut && r.URL.Path == "/proxies/Proxy":
			var body struct {
				Name string `json:"name"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			currentNow = body.Name
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	clock := time.Date(2026, 5, 1, 12, 0, 0, 0, time.Local)
	st := NewGroupFailoverState()
	enabled := true
	st.ApplyConfig(config.WatchdogFailoverConfig{
		Enabled:            &enabled,
		Groups:             []string{"Proxy"},
		ProbeTimeoutMs:     800,
		ConfirmRetries:     -1, // immediate switch without retry sleep
		FailbackCooldown:   60,
		MaxFailbackDelayMs: 300,
		ProbeURLs:          []string{"https://www.gstatic.com/generate_204"},
	})
	st.NowFn = func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return clock
	}
	st.EnableWANGate = true
	st.CheckWANFn = func(context.Context) bool {
		mu.Lock()
		defer mu.Unlock()
		return wanAlive
	}

	ctx := t.Context()
	endpoints := []string{srv.URL}

	// 1. When local WAN is down, WAN gate must block false-positive failover!
	st.Patrol(ctx, endpoints, "")
	mu.Lock()
	gotAfterWANDown := currentNow
	mu.Unlock()
	if gotAfterWANDown != "node-primary" || len(st.ActiveSnapshot()) != 0 {
		t.Fatalf("WAN gate failed: switched to %q despite WAN outage", gotAfterWANDown)
	}

	// 2. WAN comes back up while node-primary is dead -> must pick lowest-latency healthy backup ("node-fast", skipping placeholder)
	mu.Lock()
	wanAlive = true
	mu.Unlock()
	st.Patrol(ctx, endpoints, "")

	mu.Lock()
	gotAfterFailover := currentNow
	mu.Unlock()
	if gotAfterFailover != "node-fast" {
		t.Fatalf("expected failover to pick lowest-latency 'node-fast', got %q", gotAfterFailover)
	}
	snap := st.ActiveSnapshot()
	if len(snap) != 1 || snap[0].Origin != "node-primary" || snap[0].Current != "node-fast" {
		t.Fatalf("unexpected ActiveSnapshot: %+v", snap)
	}

	// 3. Verify RestoreSnapshot into a fresh state machine
	restored := NewGroupFailoverState()
	restored.ApplyConfig(config.WatchdogFailoverConfig{
		Enabled:            &enabled,
		Groups:             []string{"Proxy"},
		ProbeTimeoutMs:     800,
		ConfirmRetries:     -1,
		FailbackCooldown:   60,
		MaxFailbackDelayMs: 300,
		ProbeURLs:          []string{"https://www.gstatic.com/generate_204"},
	})
	restored.NowFn = st.NowFn
	restored.CheckWANFn = st.CheckWANFn
	restored.RestoreSnapshot(snap)

	// 4. Primary recovers after cooldown (2 consecutive healthy patrols required when cooldown > 0)
	mu.Lock()
	primaryUp = true
	clock = clock.Add(2 * time.Minute)
	mu.Unlock()

	restored.Patrol(ctx, endpoints, "")
	restored.Patrol(ctx, endpoints, "")

	mu.Lock()
	gotAfterFailback := currentNow
	mu.Unlock()
	if gotAfterFailback != "node-primary" || len(restored.ActiveSnapshot()) != 0 {
		t.Fatalf("expected automatic failback to 'node-primary', got %q (active=%+v)", gotAfterFailback, restored.ActiveSnapshot())
	}
}
