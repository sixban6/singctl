// 文件职责：验证流媒体与 AI 解锁探测（RunExitDiagnostics）、画像摘要格式化、环境识别与报告评分汇总。
package doctor_test

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"singctl/internal/config"
	"singctl/internal/doctor"
)

type mockUnlockTransport struct {
	mode string // "unlocked", "originals_and_blocked", "captcha"
}

func (m mockUnlockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	mkResp := func(code int, body string) *http.Response {
		return &http.Response{
			StatusCode: code,
			Status:     http.StatusText(code),
			Body:       io.NopCloser(strings.NewReader(body)),
			Header:     make(http.Header),
		}
	}
	u := req.URL.String()
	switch {
	case strings.Contains(u, "cdn-cgi/trace") && strings.Contains(u, "chatgpt.com"):
		if m.mode == "originals_and_blocked" {
			return mkResp(403, "error code: 1020"), nil
		}
		return mkResp(200, "ip=198.51.100.10\nloc=US\n"), nil
	case strings.Contains(u, "cdn-cgi/trace"):
		return mkResp(200, "ip=198.51.100.10\nloc=US\n"), nil
	case strings.Contains(u, "netflix.com/title/81280792"):
		if m.mode == "unlocked" {
			return mkResp(200, "ok"), nil
		}
		return mkResp(404, "not available"), nil
	case strings.Contains(u, "netflix.com/title/80018499"):
		if m.mode == "originals_and_blocked" {
			return mkResp(200, "originals ok"), nil
		}
		return mkResp(403, "blocked"), nil
	case strings.Contains(u, "youtube.com/premium"):
		if m.mode == "originals_and_blocked" {
			return mkResp(200, "Premium is not available in your country"), nil
		}
		return mkResp(200, "YouTube Premium"), nil
	case strings.Contains(u, "disneyplus.com"):
		if m.mode == "originals_and_blocked" {
			return mkResp(403, "forbidden"), nil
		}
		return mkResp(200, "Disney+"), nil
	case strings.Contains(u, "google.com/search"):
		if m.mode == "captcha" {
			return mkResp(429, "detected unusual traffic"), nil
		}
		return mkResp(200, "search results"), nil
	default:
		return mkResp(200, ""), nil
	}
}

func TestMediaUnlockDiagnostics_And_ReportFormatting(t *testing.T) {
	fullClient := &http.Client{Transport: mockUnlockTransport{mode: "unlocked"}}
	p1 := doctor.RunExitDiagnostics("direct", fullClient, false)
	if p1.ExitIP != "198.51.100.10" || p1.ExitLoc != "US" {
		t.Fatalf("unexpected exit IP/loc: %+v", p1)
	}
	if p1.OpenAI.Status != "unlocked" || p1.Netflix.Status != "unlocked" || p1.YouTube.Status != "unlocked" || p1.Disney.Status != "unlocked" || p1.Google.Status != "unlocked" {
		t.Fatalf("expected all unlocked in mode=unlocked, got %+v", p1)
	}

	restrictedClient := &http.Client{Transport: mockUnlockTransport{mode: "originals_and_blocked"}}
	p2 := doctor.RunExitDiagnostics("warp", restrictedClient, true)
	if p2.OpenAI.Status != "locked" || p2.Netflix.Status != "partially_unlocked" || p2.YouTube.Status != "locked" || p2.Disney.Status != "locked" {
		t.Fatalf("unexpected restricted statuses: %+v", p2)
	}

	captchaClient := &http.Client{Transport: mockUnlockTransport{mode: "captcha"}}
	p3 := doctor.RunExitDiagnostics("direct", captchaClient, false)
	if p3.Google.Status != "warn" {
		t.Fatalf("expected Google captcha warn, got %+v", p3.Google)
	}

	summary := doctor.FormatProfileSummary(&p2)
	if summary == "" {
		t.Fatal("expected non-empty profile summary")
	}

	if doctor.IsServerEnvironment(&config.Config{Server: config.ServerConfig{NodeDomain: "node.example.com"}}) {
		t.Fatal("template placeholder node.example.com should not trigger server environment")
	}
	srvCfg := &config.Config{Server: config.ServerConfig{NodeDomain: "us1.example.com"}}
	if !doctor.IsServerEnvironment(srvCfg) {
		t.Fatal("expected server config with us1.example.com to be recognized as server environment")
	}

	rep := &doctor.DoctorReport{
		Items: []doctor.DoctorItem{
			{Category: "system", Name: "BBR", Status: "ok", Summary: "fq+bbr"},
			{Category: "network", Name: "Google", Status: "warn", Summary: "captcha", Detail: "enable WARP"},
		},
	}
	doctor.FinalizeReport(rep, "all good")
	if rep.Score <= 0 || rep.Score >= 100 {
		t.Fatalf("expected partial score with 1 warn, got %+v", rep)
	}
	doctor.PrintDoctorReport(rep)
}
