package cmd

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"singctl/internal/config"
	"singctl/internal/deploy"
)

func TestShowUnifiedServerPanel(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			NodeDomain:     "node.example.com",
			SubstoreDomain: "sub.example.com",
			CFDNSKey:       "dummy_token",
			WebAdmin: config.WebAdminConfig{
				Enabled:  true,
				Port:     8092,
				Path:     "/sr/abcdef1234567890abcdef12",
				Username: "admin",
				Password: "TestPassword123",
			},
		},
	}

	sbs := &deploy.SingBoxServer{
		ShareLinkHy2:   "hysteria2://test-hy2-link",
		ShareLinkVless: "vless://test-vless-link",
	}

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	showUnifiedServerPanel(cfg, sbs, nil, "📌 SingCtl 服务端核心配置与连接信息")

	_ = w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	output := buf.String()

	// 1. Verify header title
	if !strings.Contains(output, "📌 SingCtl 服务端核心配置与连接信息") {
		t.Errorf("missing header title in output:\n%s", output)
	}

	// 2. Verify WebAdmin credentials & URL
	if !strings.Contains(output, "专属管理控制台 (核心 Web 后台入口)") {
		t.Errorf("missing WebAdmin panel header in output:\n%s", output)
	}
	if !strings.Contains(output, "https://sub.example.com/sr/abcdef1234567890abcdef12/") {
		t.Errorf("missing WebAdmin access URL in output:\n%s", output)
	}
	if !strings.Contains(output, "admin") || !strings.Contains(output, "TestPassword123") {
		t.Errorf("missing username or password in output:\n%s", output)
	}

	// 3. Verify node links
	if !strings.Contains(output, "hysteria2://test-hy2-link") || !strings.Contains(output, "vless://test-vless-link") {
		t.Errorf("missing node share links in output:\n%s", output)
	}

	// 4. Verify subscription URL
	if !strings.Contains(output, "https://sub.example.com/api/substore/download/singctl") {
		t.Errorf("missing subscription download URL in output:\n%s", output)
	}

	// 5. Verify maintenance commands
	if !strings.Contains(output, "singctl doctor") || !strings.Contains(output, "singctl sr info") {
		t.Errorf("missing maintenance commands in output:\n%s", output)
	}
}
