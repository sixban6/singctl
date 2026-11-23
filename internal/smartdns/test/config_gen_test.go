// 文件职责：验证 SmartDNS 配置生成、上游指令防注入校验、策略映射、低内存参数与 0600 落盘。
package smartdns_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"singctl/internal/smartdns"
)

func TestDefaultUpstreamsAndNormalizeMode(t *testing.T) {
	defaults := smartdns.DefaultUpstreams()
	want := []string{
		"https://223.5.5.5/dns-query",
		"https://1.12.12.12/dns-query",
		"tls://223.6.6.6:853",
		"tls://120.53.53.53:853",
	}
	if len(defaults) != len(want) {
		t.Fatalf("DefaultUpstreams len = %d, want %d: %v", len(defaults), len(want), defaults)
	}
	for i := range want {
		if defaults[i] != want[i] {
			t.Errorf("DefaultUpstreams[%d] = %q, want %q", i, defaults[i], want[i])
		}
	}

	modeCases := []struct {
		in   string
		want string
	}{
		{"", "fastest_ip"},
		{"fastest_ip", "fastest_ip"},
		{"FASTEST_ADDR", "fastest_ip"},
		{"parallel", "parallel"},
		{"load_balance", "load_balance"},
		{"unknown-mode", "fastest_ip"},
	}
	for _, tc := range modeCases {
		if got := smartdns.NormalizeUpstreamMode(tc.in); got != tc.want {
			t.Errorf("NormalizeUpstreamMode(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestFormatUpstreamDirective_ValidAndInjectionPayloads(t *testing.T) {
	validCases := []struct {
		raw  string
		want string
	}{
		{"https://223.5.5.5/dns-query", "server-https https://223.5.5.5/dns-query"},
		{"https://1.12.12.12/dns-query", "server-https https://1.12.12.12/dns-query"},
		{"https://192.0.2.1", "server-https https://192.0.2.1/dns-query"},
		{"https://192.0.2.1:8443/custom", "server-https https://192.0.2.1:8443/custom"},
		{"tls://223.6.6.6:853", "server-tls 223.6.6.6:853"},
		{"tls://120.53.53.53:853", "server-tls 120.53.53.53:853"},
		{"tls://198.51.100.2", "server-tls 198.51.100.2:853"},
		{"quic://198.51.100.3:853", "server-quic 198.51.100.3:853"},
		{"quic://198.51.100.4", "server-quic 198.51.100.4:853"},
		{"h3://203.0.113.5/dns-query", "server-https https://203.0.113.5/dns-query"},
		{"tls://[2001:db8::1]:853", "server-tls [2001:db8::1]:853"},
		{"tls://dot.onedns.net", "server-tls dot.onedns.net:853"},
		{"https://doh.onedns.net", "server-https https://doh.onedns.net/dns-query"},
		{"quic://dns.example.com", "server-quic dns.example.com:853"},
	}
	for _, tc := range validCases {
		got, err := smartdns.FormatUpstreamDirective(tc.raw)
		if err != nil {
			t.Errorf("FormatUpstreamDirective(%q) unexpected err: %v", tc.raw, err)
			continue
		}
		if got != tc.want {
			t.Errorf("FormatUpstreamDirective(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}

	invalidPayloads := []string{
		"",
		"   ",
		"# comment",
		"192.0.2.1",
		"udp://192.0.2.1:53",
		"tcp://192.0.2.1:53",
		"http://192.0.2.1/dns-query",
		"https://192.0.2.1:53/dns-query",
		"tls://127.0.0.1:853",
		"tls://0.0.0.0:853",
		"https://192.168.1.1/dns-query",
		"https://192.0.2.1/dns-query\nbind 0.0.0.0:53",
		"https://192.0.2.1/dns-query\r\nserver 198.51.100.1",
		"https://192.0.2.1/dns-query -group evil",
		"tls://192.0.2.1:853\t-proxy p",
		"https://192.0.2.1/dns-query;cat /etc/passwd",
		"https://192.0.2.1/dns-query\x00extra",
		"tls://192.0.2.1:99999",
		"https://",
		"tls://localhost",
		"tls://router.lan",
		"https://nas.local/dns-query",
		"tls://dns.home.arpa",
		"tls://999.999.999.999",
	}
	for _, bad := range invalidPayloads {
		if got, err := smartdns.FormatUpstreamDirective(bad); err == nil {
			t.Errorf("FormatUpstreamDirective(%q) expected error, got %q", bad, got)
		}
	}
}

func TestBuildConfig_StrategiesLowMemoryAndSecurity(t *testing.T) {
	rulesDir := "/etc/singctl/smartdns-rules.d"
	auditLog := "/tmp/singctl-smartdns-audit.log"
	logFile := "/tmp/singctl-smartdns.log"

	t.Run("default_fastest_ip_standard_memory", func(t *testing.T) {
		cfg, err := smartdns.BuildConfig(smartdns.ConfigInput{}, rulesDir, auditLog, logFile)
		if err != nil {
			t.Fatalf("BuildConfig failed: %v", err)
		}
		mustContain := []string{
			"bind 127.0.0.1:5353",
			"server-https https://223.5.5.5/dns-query",
			"server-https https://1.12.12.12/dns-query",
			"server-tls 223.6.6.6:853",
			"server-tls 120.53.53.53:853",
			"speed-check-mode ping,tcp:80,tcp:443",
			"response-mode fastest-ip",
			"cache-size 8192",
			"cache-persist no",
			"serve-expired yes",
			"prefetch-domain yes",
			"log-level warn",
			"log-file " + logFile,
			"log-size 64k",
			"log-num 1",
			"audit-enable yes",
			"audit-SOA yes",
			"audit-file " + auditLog,
			"audit-size 128k",
			"audit-num 1",
			"address /localhost/127.0.0.1",
			"conf-file " + filepath.Join(rulesDir, "whitelist.conf"),
			"conf-file " + filepath.Join(rulesDir, "rewrites.conf"),
			"conf-file " + filepath.Join(rulesDir, "audit_block.conf"),
		}
		for _, kw := range mustContain {
			if !strings.Contains(cfg, kw) {
				t.Errorf("config missing %q\n--- config ---\n%s", kw, cfg)
			}
		}
		if strings.Contains(cfg, "0.0.0.0:53") {
			t.Errorf("config must never bind 0.0.0.0:53")
		}
		if strings.Contains(cfg, "force-AAAA-SOA") {
			t.Errorf("force-AAAA-SOA should not be present when BlockAAAA is false")
		}
		if strings.Contains(cfg, "adblock.conf") {
			t.Errorf("adblock.conf should not be included when EnabledFilters is empty")
		}
		if strings.Contains(cfg, "-bootstrap-dns") {
			t.Errorf("-bootstrap-dns should not be emitted when all upstreams are pure IPs")
		}
	})

	t.Run("domain_upstream_adds_encrypted_bootstrap_dns", func(t *testing.T) {
		cfg, err := smartdns.BuildConfig(smartdns.ConfigInput{
			Upstreams: []string{
				"https://223.5.5.5/dns-query",
				"tls://dot.onedns.net",
			},
		}, rulesDir, auditLog, logFile)
		if err != nil {
			t.Fatalf("BuildConfig failed: %v", err)
		}
		for _, kw := range []string{
			"server-https https://223.5.5.5/dns-query -bootstrap-dns",
			"server-tls 1.12.12.12:853 -bootstrap-dns",
			"server-tls dot.onedns.net:853",
		} {
			if !strings.Contains(cfg, kw) {
				t.Errorf("config missing %q\n--- config ---\n%s", kw, cfg)
			}
		}
	})

	t.Run("parallel_low_memory_block_aaaa_and_adblock", func(t *testing.T) {
		cfg, err := smartdns.BuildConfig(smartdns.ConfigInput{
			DNSPort:        5355,
			UpstreamMode:   "parallel",
			IsLowMemory:    true,
			BlockAAAA:      true,
			EnabledFilters: []string{"https://example.com/list.conf"},
		}, rulesDir, auditLog, logFile)
		if err != nil {
			t.Fatalf("BuildConfig failed: %v", err)
		}
		for _, kw := range []string{
			"bind 127.0.0.1:5355",
			"speed-check-mode ping,tcp:80,tcp:443",
			"response-mode first-ping",
			"cache-size 2048",
			"force-AAAA-SOA yes",
			"conf-file " + filepath.Join(rulesDir, "adblock.conf"),
		} {
			if !strings.Contains(cfg, kw) {
				t.Errorf("config missing %q\n%s", kw, cfg)
			}
		}
	})

	t.Run("load_balance_and_protection_paused_omits_adblock", func(t *testing.T) {
		cfg, err := smartdns.BuildConfig(smartdns.ConfigInput{
			UpstreamMode:     "load_balance",
			EnabledFilters:   []string{"https://example.com/list.conf"},
			ProtectionPaused: true,
		}, rulesDir, auditLog, logFile)
		if err != nil {
			t.Fatalf("BuildConfig failed: %v", err)
		}
		if !strings.Contains(cfg, "speed-check-mode none") || !strings.Contains(cfg, "response-mode fastest-response") {
			t.Errorf("expected load_balance directives, got:\n%s", cfg)
		}
		if strings.Contains(cfg, "adblock.conf") {
			t.Errorf("adblock.conf must be omitted when ProtectionPaused=true")
		}
	})

	t.Run("rejects_port_53_and_invalid_ports_and_path_injection", func(t *testing.T) {
		if _, err := smartdns.BuildConfig(smartdns.ConfigInput{DNSPort: 53}, rulesDir, auditLog, logFile); err == nil {
			t.Error("expected port 53 rejected")
		}
		if _, err := smartdns.BuildConfig(smartdns.ConfigInput{DNSPort: 70000}, rulesDir, auditLog, logFile); err == nil {
			t.Error("expected port 70000 rejected")
		}
		if _, err := smartdns.BuildConfig(smartdns.ConfigInput{}, "/tmp/evil\nbind 0.0.0.0:53", auditLog, logFile); err == nil {
			t.Error("expected newline injection in rulesDir rejected")
		}
		if _, err := smartdns.BuildConfig(smartdns.ConfigInput{}, rulesDir, "/tmp/audit\nevil", logFile); err == nil {
			t.Error("expected newline injection in auditLogPath rejected")
		}
	})
}

func TestWriteConfig_Permissions0600AndDir0700(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "confdir")
	cfgPath := filepath.Join(dir, "smartdns.conf")

	content, err := smartdns.BuildConfig(smartdns.ConfigInput{}, filepath.Join(dir, "rules.d"), filepath.Join(dir, "audit.log"), filepath.Join(dir, "smartdns.log"))
	if err != nil {
		t.Fatal(err)
	}
	if err := smartdns.WriteConfig(cfgPath, content); err != nil {
		t.Fatalf("WriteConfig failed: %v", err)
	}

	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := dirInfo.Mode().Perm(); perm != 0700 {
		t.Errorf("config dir perm = %04o, want 0700", perm)
	}
	fileInfo, err := os.Stat(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fileInfo.Mode().Perm(); perm != 0600 {
		t.Errorf("config file perm = %04o, want 0600", perm)
	}
	got, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != content {
		t.Errorf("written content mismatch")
	}
}
