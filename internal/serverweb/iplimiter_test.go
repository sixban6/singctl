package serverweb

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGetClientIP(t *testing.T) {
	t.Run("loopback trusts X-Real-IP", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-Real-IP", "203.0.113.195")
		req.Header.Set("X-Forwarded-For", "127.0.0.1")
		req.Header.Set("CF-Connecting-IP", "127.0.0.1")
		req.RemoteAddr = "127.0.0.1:12345"
		if ip := GetClientIP(req); ip != "203.0.113.195" {
			t.Fatalf("expected 203.0.113.195 from X-Real-IP, got %s", ip)
		}
	})

	t.Run("spoofed forwarding headers are ignored", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("CF-Connecting-IP", "104.28.1.1")
		req.Header.Set("X-Real-IP", "127.0.0.1")
		req.Header.Set("X-Forwarded-For", "127.0.0.1, 198.51.100.42")
		req.RemoteAddr = "203.0.113.9:54321"
		if ip := GetClientIP(req); ip != "203.0.113.9" {
			t.Fatalf("expected remote address 203.0.113.9, got %s", ip)
		}
	})

	t.Run("invalid X-Real-IP falls back to loopback", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-Real-IP", "not-an-ip")
		req.RemoteAddr = "127.0.0.1:12345"
		if ip := GetClientIP(req); ip != "127.0.0.1" {
			t.Fatalf("expected 127.0.0.1, got %s", ip)
		}
	})
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

func TestIPLimiter_FilePersistence(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "bans.json")

	l1 := NewIPLimiter(3, 10*time.Minute, 15*time.Minute, filePath)
	testIP := "198.51.100.77"

	// 触发封禁
	l1.RecordFailure(testIP)
	l1.RecordFailure(testIP)
	banned, _, _ := l1.RecordFailure(testIP)
	if !banned {
		t.Fatal("expected IP to be banned")
	}
	l1.Close()

	// 验证文件权限为 0600
	st, err := os.Stat(filePath)
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}
	if perm := st.Mode().Perm(); perm != 0600 {
		t.Fatalf("expected ban file perm 0600, got %o", perm)
	}

	// 模拟服务重启：创建新实例 l2 读取相同的小文件
	l2 := NewIPLimiter(3, 10*time.Minute, 15*time.Minute, filePath)
	defer l2.Close()

	rem, isBanned := l2.CheckBan(testIP)
	if !isBanned || rem <= 0 {
		t.Fatalf("expected banned IP to persist after restart, got isBanned=%v, rem=%v", isBanned, rem)
	}

	bans := l2.ListBans()
	if _, exists := bans[testIP]; !exists {
		t.Fatalf("expected %s in ListBans after restart", testIP)
	}

	// 解封并验证持久化
	l2.Unban(testIP)
	if _, isBanned := l2.CheckBan(testIP); isBanned {
		t.Fatal("expected unbanned")
	}

	// 再次重启验证解封已持久化
	l3 := NewIPLimiter(3, 10*time.Minute, 15*time.Minute, filePath)
	defer l3.Close()
	if _, isBanned := l3.CheckBan(testIP); isBanned {
		t.Fatal("expected unban state to persist across restart")
	}
}
