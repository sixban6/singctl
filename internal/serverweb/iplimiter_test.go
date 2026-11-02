package serverweb

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestGetClientIP(t *testing.T) {
	// 1. CF-Connecting-IP
	{
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("CF-Connecting-IP", "104.28.1.1")
		req.RemoteAddr = "127.0.0.1:12345"
		if ip := GetClientIP(req); ip != "104.28.1.1" {
			t.Fatalf("expected 104.28.1.1 from CF-Connecting-IP, got %s", ip)
		}
	}

	// 2. X-Real-IP
	{
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-Real-IP", "203.0.113.195")
		req.RemoteAddr = "127.0.0.1:12345"
		if ip := GetClientIP(req); ip != "203.0.113.195" {
			t.Fatalf("expected 203.0.113.195 from X-Real-IP, got %s", ip)
		}
	}

	// 3. X-Forwarded-For (multiple IPs)
	{
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-Forwarded-For", "198.51.100.42, 172.68.1.1")
		req.RemoteAddr = "127.0.0.1:12345"
		if ip := GetClientIP(req); ip != "198.51.100.42" {
			t.Fatalf("expected 198.51.100.42 from X-Forwarded-For, got %s", ip)
		}
	}

	// 4. RemoteAddr
	{
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "192.0.2.1:54321"
		if ip := GetClientIP(req); ip != "192.0.2.1" {
			t.Fatalf("expected 192.0.2.1 from RemoteAddr, got %s", ip)
		}
	}
}

func TestIPLimiter_BanAfterThreeFails(t *testing.T) {
	limiter := NewIPLimiter(3, 1*time.Minute, 15*time.Minute)
	defer limiter.Close()

	testIP := "198.51.100.99"

	// 尝试 1
	banned, _, fails := limiter.RecordFailure(testIP)
	if banned || fails != 1 {
		t.Fatalf("expected fails=1, banned=false, got fails=%d, banned=%v", fails, banned)
	}
	if _, isBanned := limiter.CheckBan(testIP); isBanned {
		t.Fatalf("should not be banned after 1 fail")
	}

	// 尝试 2
	banned, _, fails = limiter.RecordFailure(testIP)
	if banned || fails != 2 {
		t.Fatalf("expected fails=2, banned=false, got fails=%d, banned=%v", fails, banned)
	}

	// 尝试 3 -> 触发封禁
	banned, rem, fails := limiter.RecordFailure(testIP)
	if !banned || fails != 3 {
		t.Fatalf("expected fails=3, banned=true, got fails=%d, banned=%v", fails, banned)
	}
	if rem <= 0 {
		t.Fatalf("expected positive remaining time, got %v", rem)
	}

	// 再次检查 CheckBan
	remCheck, isBanned := limiter.CheckBan(testIP)
	if !isBanned || remCheck <= 0 {
		t.Fatalf("expected isBanned=true, got %v (%v)", isBanned, remCheck)
	}

	// 解封单个 IP
	limiter.Unban(testIP)
	if _, isBanned := limiter.CheckBan(testIP); isBanned {
		t.Fatalf("expected IP to be unbanned")
	}
}

func TestIPLimiter_SuccessResetsCounter(t *testing.T) {
	limiter := NewIPLimiter(3, 1*time.Minute, 15*time.Minute)
	defer limiter.Close()

	testIP := "198.51.100.100"

	// 尝试 2 次失败
	limiter.RecordFailure(testIP)
	limiter.RecordFailure(testIP)

	// 成功登录
	limiter.RecordSuccess(testIP)

	// 再失败 1 次，应该重新从 1 开始计次
	banned, _, fails := limiter.RecordFailure(testIP)
	if banned || fails != 1 {
		t.Fatalf("expected fails=1 after reset, got %d (banned=%v)", fails, banned)
	}
}

func TestIPLimiter_LocalhostWhitelisted(t *testing.T) {
	limiter := NewIPLimiter(3, 1*time.Minute, 15*time.Minute)
	defer limiter.Close()

	for i := 0; i < 10; i++ {
		banned, _, fails := limiter.RecordFailure("127.0.0.1")
		if banned || fails != 0 {
			t.Fatalf("localhost 127.0.0.1 should never be recorded or banned")
		}
	}
	if _, isBanned := limiter.CheckBan("127.0.0.1"); isBanned {
		t.Fatalf("localhost 127.0.0.1 should never be banned")
	}
}
