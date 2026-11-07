package daemon

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestGroupFailover_AutoSwitchAndAutoRestore(t *testing.T) {
	var mu sync.Mutex
	autoAlive := false
	vpsAlive := true
	gameNow := "#Auto"
	vpsNow := "sec_los_hy2"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		path := r.URL.Path

		if r.Method == http.MethodGet && path == "/proxies" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"proxies": map[string]any{
					"Game": map[string]any{
						"type": "Selector",
						"now":  gameNow,
						"all":  []string{"#Auto", "#VPS", "#Nodes"},
					},
					"#VPS": map[string]any{
						"type": "Selector",
						"now":  vpsNow,
						"all":  []string{"sec_los_hy2", "sec_sg1_hy2"},
					},
				},
			})
			return
		}

		if r.Method == http.MethodGet && strings.HasSuffix(path, "/delay") {
			switch {
			case strings.Contains(path, "/%23Auto/delay") || strings.Contains(path, "/#Auto/delay"):
				if autoAlive {
					_ = json.NewEncoder(w).Encode(map[string]int{"delay": 85})
				} else {
					w.WriteHeader(http.StatusGatewayTimeout)
					_ = json.NewEncoder(w).Encode(map[string]string{"message": "Timeout"})
				}
			case strings.Contains(path, "/%23VPS/delay") || strings.Contains(path, "/#VPS/delay") || strings.Contains(path, "/sec_los_hy2/delay"):
				if vpsAlive {
					_ = json.NewEncoder(w).Encode(map[string]int{"delay": 240})
				} else {
					w.WriteHeader(http.StatusGatewayTimeout)
				}
			default:
				_ = json.NewEncoder(w).Encode(map[string]int{"delay": 300})
			}
			return
		}

		if r.Method == http.MethodPut && strings.HasPrefix(path, "/proxies/") {
			var body struct {
				Name string `json:"name"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if strings.HasSuffix(path, "/Game") {
				gameNow = body.Name
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	state := NewGroupFailoverState()
	state.probeURLs = []string{"http://example.com/generate_204"}
	state.probeTimeout = 500 * time.Millisecond

	// 1. 当 #Auto 全挂时，Patrol 应自动将 Game 切换至 #VPS
	state.Patrol(t.Context(), []string{srv.URL}, "")
	mu.Lock()
	if gameNow != "#VPS" {
		t.Fatalf("expected Game to auto-failover from dead #Auto to #VPS, got %s", gameNow)
	}
	mu.Unlock()

	// 2. 当 #Auto 恢复正常后，Patrol 应自动将 Game 切回 #Auto
	mu.Lock()
	autoAlive = true
	mu.Unlock()

	state.Patrol(t.Context(), []string{srv.URL}, "")
	mu.Lock()
	if gameNow != "#Auto" {
		t.Fatalf("expected Game to auto-restore back to #Auto once recovered, got %s", gameNow)
	}
	mu.Unlock()
}
