package serverweb

import (
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestIPLimiter_RecordFailureNeverClearsActiveBanAfterWindow(t *testing.T) {
	dir := t.TempDir()
	persistPath := filepath.Join(dir, "bans.json")

	// Short 25ms failure window, long 5s ban duration
	lim := NewIPLimiter(2, 25*time.Millisecond, 5*time.Second, persistPath)
	defer lim.Close()

	ip := "198.51.100.99"
	banned, _, _ := lim.RecordFailure(ip)
	if banned {
		t.Fatal("first failure should not ban yet")
	}
	banned, _, _ = lim.RecordFailure(ip)
	if !banned {
		t.Fatal("second failure should trigger ban")
	}

	// Wait longer than failure window (40ms > 25ms) while 5s ban is STILL active
	time.Sleep(40 * time.Millisecond)

	// An attacker probing again after the 25ms failure window must NOT reset BannedUntil to zero!
	_, _, _ = lim.RecordFailure(ip)
	if rem, stillBanned := lim.CheckBan(ip); !stillBanned || rem <= 0 {
		t.Fatalf("active ban was prematurely wiped by RecordFailure after window elapsed! stillBanned=%v rem=%v", stillBanned, rem)
	}
}

func TestIPLimiter_ConcurrentAndXRealIPTrustBoundary(t *testing.T) {
	// External peer spoofing X-Real-IP must NOT be trusted
	extReq := httptest.NewRequest("GET", "/login", nil)
	extReq.RemoteAddr = "203.0.113.50:41234"
	extReq.Header.Set("X-Real-IP", "127.0.0.1")
	extReq.Header.Set("X-Forwarded-For", "127.0.0.1")
	if got := GetClientIP(extReq); got != "203.0.113.50" {
		t.Fatalf("GetClientIP trusted spoofed X-Real-IP from non-loopback peer: got %q", got)
	}

	// Local Caddy reverse proxy on 127.0.0.1 setting X-Real-IP IS trusted
	localReq := httptest.NewRequest("GET", "/login", nil)
	localReq.RemoteAddr = "127.0.0.1:51234"
	localReq.Header.Set("X-Real-IP", "198.51.100.77")
	if got := GetClientIP(localReq); got != "198.51.100.77" {
		t.Fatalf("GetClientIP failed to extract Caddy X-Real-IP: got %q", got)
	}

	dir := t.TempDir()
	persistPath := filepath.Join(dir, "bans_race.json")
	lim := NewIPLimiter(3, time.Minute, 10*time.Minute, persistPath)

	var wg sync.WaitGroup
	for g := range 12 {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			ip := fmt.Sprintf("198.51.100.%d", 10+id)
			for range 5 {
				lim.RecordFailure(ip)
				_, _ = lim.CheckBan(ip)
				_ = lim.ListBans()
			}
			if id%3 == 0 {
				lim.RecordSuccess(ip)
			}
		}(g)
	}
	wg.Wait()
	lim.Close()

	if st, err := os.Stat(persistPath); err == nil && st.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 on persisted bans.json, got %04o", st.Mode().Perm())
	}

	// Reload from persisted 0600 file
	reloaded := NewIPLimiter(3, time.Minute, 10*time.Minute, persistPath)
	defer reloaded.Close()
	if len(reloaded.ListBans()) == 0 {
		t.Fatal("expected active bans to survive persistence reload")
	}
	reloaded.Unban("all")
	if len(reloaded.ListBans()) != 0 {
		t.Fatal("expected Unban('all') to clear all bans")
	}
}
