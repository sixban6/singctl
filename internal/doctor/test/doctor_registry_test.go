// 文件职责：测试声明式体检注册表（Registry）与可注入探针依赖（Deps）的服务端/客户端全链路离线体检、评分计算与并发安全。
package doctor_test

import (
	"context"
	"errors"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"

	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/doctor"
	"singctl/internal/subhub"
)

func TestDoctorRegistry_CustomRegistrationOrderAndIsolation(t *testing.T) {
	reg := doctor.NewRegistry()
	reg.Register(
		doctor.Check{
			ID:    "srv-1",
			Scope: doctor.ScopeServer,
			Run: func(context.Context, *config.Config, doctor.Deps) []doctor.DoctorItem {
				return []doctor.DoctorItem{{Name: "S1", Category: "system", Status: "ok", Summary: "ok"}}
			},
		},
		doctor.Check{
			ID:    "cli-1",
			Scope: doctor.ScopeClient,
			Run: func(context.Context, *config.Config, doctor.Deps) []doctor.DoctorItem {
				return []doctor.DoctorItem{{Name: "C1", Category: "network", Status: "warn", Summary: "warn"}}
			},
		},
		doctor.Check{
			ID:    "srv-2",
			Scope: doctor.ScopeServer,
			Run: func(context.Context, *config.Config, doctor.Deps) []doctor.DoctorItem {
				return []doctor.DoctorItem{{Name: "S2", Category: "security", Status: "fail", Summary: "fail"}}
			},
		},
	)

	srvRep := reg.RunScope(t.Context(), doctor.ScopeServer, nil, doctor.Deps{}, "healthy")
	if len(srvRep.Items) != 2 || srvRep.Items[0].Name != "S1" || srvRep.Items[1].Name != "S2" {
		t.Fatalf("unexpected server items order/filtering: %+v", srvRep.Items)
	}
	if srvRep.Score != 80 {
		t.Fatalf("expected score 80 (1 fail = -20), got %d", srvRep.Score)
	}

	cliRep := reg.RunScope(t.Context(), doctor.ScopeClient, nil, doctor.Deps{}, "healthy")
	if len(cliRep.Items) != 1 || cliRep.Items[0].Name != "C1" || cliRep.Score != 95 {
		t.Fatalf("unexpected client report: %+v", cliRep)
	}
}

func TestRunServerAndClientDoctorWithDeps_OfflineDeterministic(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	files := map[string][]byte{
		"/etc/os-release": []byte("PRETTY_NAME=\"Debian GNU/Linux 12\"\n"),
		"/proc/sys/net/ipv4/tcp_congestion_control": []byte("bbr\n"),
		constant.SingBoxConfigFile:                  []byte(`{"inbounds":[{"type":"hysteria2","tls":{"certificate_path":"/var/lib/caddy/node.example.com.crt"}}]}`),
	}

	healthyDeps := doctor.Deps{
		GOOS:   "linux",
		GOARCH: "amd64",
		NumCPU: 4,
		Now:    func() time.Time { return now },
		ReadFile: func(p string) ([]byte, error) {
			if b, ok := files[p]; ok {
				return b, nil
			}
			return nil, os.ErrNotExist
		},
		FileExists: func(p string) bool {
			_, ok := files[p]
			return ok || p == "/etc/caddy/Caddyfile"
		},
		FileNonEmpty: func(p string) bool {
			b, ok := files[p]
			return ok && len(b) > 0
		},
		DialTCP: func(addr string, _ time.Duration) error {
			return nil
		},
		HTTPGetStatus: func(url string, _ time.Duration) (int, time.Duration, error) {
			if url == "http://"+subhub.DefaultListenAddr+"/healthz" || url == "https://cp.cloudflare.com/generate_204" {
				return http.StatusOK, 8 * time.Millisecond, nil
			}
			return 0, 0, errors.New("unexpected url: " + url)
		},
		ProbeServerTLS: func(domain string, port int) (doctor.TLSPeerInfo, error) {
			return doctor.TLSPeerInfo{
				NotAfter:   now.Add(60 * 24 * time.Hour),
				TLSVersion: "1.3",
			}, nil
		},
		ProbeRealitySNI: func(sni string) (time.Duration, string, error) {
			return 6 * time.Millisecond, "1.3", nil
		},
		LookupValidCaddyCert: func(domain string) (string, string) {
			return "/var/lib/caddy/node.example.com.crt", "/var/lib/caddy/node.example.com.key"
		},
		IsServiceActive: func(name string) bool {
			return true
		},
		CheckMediaUnlock: func() *doctor.MediaUnlockReport {
			return &doctor.MediaUnlockReport{
				Direct: doctor.ExitProfile{
					Available: true,
					ExitIP:    "198.51.100.10",
					ExitLoc:   "LAX",
					OpenAI:    doctor.ServiceUnlockStatus{Status: "unlocked", Region: "US"},
					Netflix:   doctor.ServiceUnlockStatus{Status: "unlocked"},
				},
				WARP: doctor.ExitProfile{
					Available: true,
					ExitIP:    "198.51.100.20",
					ExitLoc:   "SJC",
					OpenAI:    doctor.ServiceUnlockStatus{Status: "unlocked", Region: "US"},
					Netflix:   doctor.ServiceUnlockStatus{Status: "partially_unlocked"},
				},
			}
		},
	}

	srvCfg := &config.Config{
		Server: config.ServerConfig{
			NodeDomain: "node.example.com",
			Sni:        "www.example.com",
			WebAdmin:   config.WebAdminConfig{Port: 8092, Path: "/sr/panel"},
		},
	}
	if !doctor.IsServerEnvironmentWithDeps(srvCfg, healthyDeps) {
		t.Fatal("expected IsServerEnvironmentWithDeps=true when /etc/caddy/Caddyfile exists")
	}

	srvRep := doctor.RunServerDoctorWithDeps(t.Context(), srvCfg, healthyDeps)
	if srvRep.Score != 100 {
		t.Fatalf("expected 100 score for healthy server deps, got %d (%+v)", srvRep.Score, srvRep.Items)
	}

	// Degraded server scenario: expired TLS cert + local self-signed Hy2 cert + offline services
	degradedDeps := healthyDeps
	degradedDeps.ReadFile = func(p string) ([]byte, error) {
		if p == constant.SingBoxConfigFile {
			return []byte(`{"inbounds":[{"type":"hysteria2","tls":{"certificate_path":"/var/lib/caddy/certificates/local/node.crt"}}]}`), nil
		}
		if p == "/proc/sys/net/ipv4/tcp_congestion_control" {
			return []byte("cubic\n"), nil
		}
		return healthyDeps.ReadFile(p)
	}
	degradedDeps.ProbeServerTLS = func(string, int) (doctor.TLSPeerInfo, error) {
		return doctor.TLSPeerInfo{NotAfter: now.Add(-24 * time.Hour), TLSVersion: "1.3"}, nil
	}
	degradedDeps.IsServiceActive = func(string) bool { return false }
	degradedRep := doctor.RunServerDoctorWithDeps(t.Context(), srvCfg, degradedDeps)
	if degradedRep.Score >= 60 {
		t.Fatalf("expected degraded server score < 60, got %d", degradedRep.Score)
	}

	// Client doctor scenario (healthy vs missing subscription)
	cliCfg := &config.Config{
		Subs: []config.Subscription{{Name: "main", URL: "https://sub.example.com/api/v1"}},
	}
	cliRep := doctor.RunClientDoctorWithDeps(t.Context(), cliCfg, healthyDeps)
	if cliRep.Score != 100 {
		t.Fatalf("expected 100 score for healthy client deps, got %d (%+v)", cliRep.Score, cliRep.Items)
	}
	cliEmptyRep := doctor.RunClientDoctorWithDeps(t.Context(), &config.Config{}, healthyDeps)
	if cliEmptyRep.Score >= 100 {
		t.Fatalf("expected warning score < 100 when client subs empty, got %d", cliEmptyRep.Score)
	}

	// Concurrent execution under -race
	var wg sync.WaitGroup
	for range 6 {
		wg.Go(func() {
			_ = doctor.RunServerDoctorWithDeps(t.Context(), srvCfg, healthyDeps)
			_ = doctor.RunClientDoctorWithDeps(t.Context(), cliCfg, healthyDeps)
		})
	}
	wg.Wait()
}
