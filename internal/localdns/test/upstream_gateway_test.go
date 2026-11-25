// 文件职责：测试二级级联路由在 SmartDNS 引擎与 sing-box 应急兜底中的上级私网网关 DNS 协同预设、探测与零环路落盘。
package localdns_test

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"singctl/internal/adguard"
	"singctl/internal/config"
	"singctl/internal/localdns"
	"singctl/internal/platform/servicemgr"
	"singctl/internal/singbox"
)

func TestUpstreamGateway_SmartDNSPresetSetUpstreamsAndSingBoxFallback(t *testing.T) {
	dir := t.TempDir()
	sdBin := filepath.Join(dir, "smartdns")
	if err := os.WriteFile(sdBin, []byte("#!/bin/sh\n"), 0755); err != nil {
		t.Fatal(err)
	}
	sdConf := filepath.Join(dir, "smartdns.conf")
	cfgPath := filepath.Join(dir, "singctl.yaml")
	sbPath := filepath.Join(dir, "config.json")

	// Mock local UDP DNS server to test ProbeSingleUpstream("udp://...")
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 512)
		for {
			n, addr, rErr := pc.ReadFrom(buf)
			if rErr != nil {
				return
			}
			if n < 12 {
				continue
			}
			resp := make([]byte, 0, n+16)
			resp = append(resp, buf[0], buf[1], 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00)
			resp = append(resp, buf[12:n]...)
			resp = append(resp, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 203, 0, 113, 8)
			_, _ = pc.WriteTo(resp, addr)
		}
	}()

	probeItem := adguard.ProbeSingleUpstream(t.Context(), "udp://"+pc.LocalAddr().String(), "qq.com", 2*time.Second)
	if !probeItem.Healthy || probeItem.Resolved != "203.0.113.8" {
		t.Fatalf("expected UDP upstream probe healthy with 203.0.113.8, got %+v", probeItem)
	}

	// DescribeUpstream recognizes gateway UDP upstream; AdGuard validator still rejects it
	meta := adguard.DescribeUpstream("udp://192.168.1.1:53")
	if meta.Protocol != "Gateway" || !strings.Contains(meta.Name, "上级") {
		t.Fatalf("unexpected DescribeUpstream for gateway UDP: %+v", meta)
	}
	if _, _, _, err := adguard.NormalizeAndValidateUpstream("udp://192.168.1.1:53"); err == nil {
		t.Fatal("AdGuard Home NormalizeAndValidateUpstream must still reject plain UDP private IP")
	}

	// SmartDNSEngine Overview exposes clickable gateway preset when UpstreamGatewayIP is private
	cfg := &config.Config{
		Gateway: config.GatewayConfig{WorkMode: config.WorkModeAudit},
		DNS:     config.ClientDNSConfig{Engine: "smartdns", DNSPort: 5354},
	}
	mockMgr := servicemgr.NewMock()
	reg := localdns.NewRegistry(cfg, localdns.EngineDeps{
		ConfigPath:         cfgPath,
		SingBoxConfigPath:  sbPath,
		SmartDNSBinPath:    sdBin,
		SmartDNSConfigFile: sdConf,
		ServiceMgr:         mockMgr,
		SkipProbeForTest:   true,
		UpstreamGatewayIP:  "192.168.1.1",
		ProbeDNSFunc:       func(string, time.Duration) error { return nil },
	})

	ov := reg.Overview(context.Background())
	if ov.UpstreamGatewayIP != "192.168.1.1" {
		t.Fatalf("expected Overview.UpstreamGatewayIP=192.168.1.1, got %q", ov.UpstreamGatewayIP)
	}
	foundGwPreset := false
	for _, p := range ov.UpstreamPresets {
		if p.Address == "udp://192.168.1.1:53" && p.Protocol == "Gateway" {
			foundGwPreset = true
		}
	}
	if !foundGwPreset {
		t.Fatalf("expected gateway preset in Overview.UpstreamPresets, got %+v", ov.UpstreamPresets)
	}

	// SetUpstreams accepts udp://192.168.1.1:53 and writes decimal -set-mark 524288 (0x80000) to smartdns.conf
	res, err := reg.ActiveEngine().SetUpstreams(t.Context(), []string{"udp://192.168.1.1:53"}, "fastest_ip", false)
	if err != nil {
		t.Fatalf("SmartDNSEngine.SetUpstreams(udp://192.168.1.1:53) failed: %v", err)
	}
	if len(res.Upstreams) != 1 || res.Upstreams[0].Address != "udp://192.168.1.1:53" {
		t.Fatalf("unexpected SetUpstreams result: %+v", res.Upstreams)
	}
	confBytes, err := os.ReadFile(sdConf)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(confBytes), "server 192.168.1.1:53 -set-mark 524288") {
		t.Fatalf("expected decimal -set-mark 524288 in smartdns.conf:\n%s", string(confBytes))
	}
	if strings.Contains(string(confBytes), "-set-mark 0x") {
		t.Fatalf("smartdns.conf must not render hex -set-mark:\n%s", string(confBytes))
	}

	// sing-box fallback dns_local MUST reject private IP 192.168.1.1 (side-router ping-pong loop risk) and fall back to safe public unicast UDP 53!
	sbBase := `{"dns":{"servers":[{"tag":"dns_local","type":"udp","server":"127.0.0.1","server_port":5354}],"final":"dns_local"},"route":{"rules":[]}}`
	patched, changed, err := singbox.PatchDNSLocalJSONWithFallback(sbBase, false, 5354, "192.168.1.1")
	if err != nil || !changed {
		t.Fatalf("PatchDNSLocalJSONWithFallback failed: changed=%v err=%v", changed, err)
	}
	if strings.Contains(patched, `"server": "192.168.1.1"`) || !strings.Contains(patched, `"type": "udp"`) || !strings.Contains(patched, `"server_port": 53`) || strings.Contains(patched, "223.5.5.5") {
		t.Fatalf("expected private gateway IP rejected and dns_local fallen back to safe public UDP 53, got:\n%s", patched)
	}
}
