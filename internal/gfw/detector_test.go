package gfw

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestDetector_ModelScoring(t *testing.T) {
	tests := []struct {
		score int
		level RiskLevel
	}{
		{0, RiskLevelClean},
		{15, RiskLevelClean},
		{20, RiskLevelClean},
		{25, RiskLevelLow},
		{50, RiskLevelLow},
		{55, RiskLevelHigh},
		{75, RiskLevelHigh},
		{80, RiskLevelCritical},
		{100, RiskLevelCritical},
	}

	for _, tt := range tests {
		rep := &Report{TotalScore: tt.score}
		switch {
		case tt.score <= 20:
			rep.RiskLevel = RiskLevelClean
		case tt.score <= 50:
			rep.RiskLevel = RiskLevelLow
		case tt.score <= 75:
			rep.RiskLevel = RiskLevelHigh
		default:
			rep.RiskLevel = RiskLevelCritical
		}

		if rep.RiskLevel != tt.level {
			t.Errorf("score %d: expected level %v, got %v", tt.score, tt.level, rep.RiskLevel)
		}
	}
}

func TestDetector_MockServer(t *testing.T) {
	// 启动一个模拟的标准 HTTP/HTTPS 服务
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Caddy")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<!DOCTYPE html><html><body><h1>Welcome to My Blog</h1></body></html>"))
	}))
	defer ts.Close()

	host, portStr, err := net.SplitHostPort(ts.Listener.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort failed: %v", err)
	}
	port, _ := strconv.Atoi(portStr)

	opts := ProbeOptions{
		IP:      host,
		Ports:   []int{port},
		Timeout: 2 * time.Second,
	}

	detector := NewDetector(opts)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	report, err := detector.Run(ctx)
	if err != nil {
		t.Fatalf("detector.Run failed: %v", err)
	}

	if report.TotalScore < 0 || report.TotalScore > 100 {
		t.Errorf("expected score 0-100, got %d", report.TotalScore)
	}

	var buf bytes.Buffer
	if err := PrintReport(&buf, report, false); err != nil {
		t.Fatalf("PrintReport failed: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "GFW 主动探测模拟与风险评估报告") {
		t.Errorf("output missing header: %s", out)
	}
	if !strings.Contains(out, "GFW 判定风险总评分") {
		t.Errorf("output missing total score: %s", out)
	}

	var jsonBuf bytes.Buffer
	if err := PrintJSONReport(&jsonBuf, report); err != nil {
		t.Fatalf("PrintJSONReport failed: %v", err)
	}
	if !strings.Contains(jsonBuf.String(), `"total_score":`) {
		t.Errorf("json report invalid: %s", jsonBuf.String())
	}
}
