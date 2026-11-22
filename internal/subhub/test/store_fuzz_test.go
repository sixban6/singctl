// 文件职责：覆盖 SubHub 远程订阅 SSRF 过滤、多字节 UTF-8 UA 截断与解析器 Fuzz 安全测试。
package subhub_test

import (
	"testing"
	"unicode/utf8"

	"singctl/internal/subhub"
)

func TestShortUALabel_PreservesValidUTF8OnMultiByteInput(t *testing.T) {
	ua := "自定义客户端订阅拉取代理标识测试版本1.0"
	got := subhub.ShortUALabel(ua)
	if !utf8.ValidString(got) {
		t.Fatalf("ShortUALabel produced invalid UTF-8 string: %q", got)
	}
}

func TestValidateRemoteURL_BlocksLocalhostVariantsAndNonPublicIPs(t *testing.T) {
	s := &subhub.Store{AllowLoopbackRemote: false}
	blocked := []string{
		"",
		"ftp://example.com/sub",
		"file:///etc/passwd",
		"http://localhost/sub",
		"http://localhost./sub",
		"http://sub.localhost/sub",
		"http://sub.localhost./sub",
		"http://127.0.0.1:8080/sub",
		"http://[::1]/sub",
		"http://[::ffff:127.0.0.1]/sub",
		"http://10.0.0.1/sub",
		"http://192.168.1.1/sub",
		"http://169.254.169.254/latest/meta-data/",
		"http://100.100.100.100/sub",
	}
	for _, u := range blocked {
		if err := s.ValidateRemoteURL(u); err == nil {
			t.Errorf("expected ValidateRemoteURL(%q) to be blocked, got nil", u)
		}
	}

	allowed := []string{
		"https://example.com/api/v1/client/subscribe?token=test",
		"https://203.0.113.10:8443/sub",
	}
	for _, u := range allowed {
		if err := s.ValidateRemoteURL(u); err != nil {
			t.Errorf("expected ValidateRemoteURL(%q) to pass, got %v", u, err)
		}
	}
}

func FuzzSubHubParsers(f *testing.F) {
	f.Add([]byte("vless://11111111-1111-1111-1111-111111111111@example.com:443?security=reality&sni=example.com&pbk=testkey#US-Node\n"))
	f.Add([]byte("ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@example.com:8388#中文节点\n"))
	f.Add([]byte(`{"outbounds":[{"type":"hysteria2","tag":"hy2","server":"example.com","server_port":443,"password":"secret"}]}`))
	f.Add([]byte("proxies:\n  - name: jp1\n    type: trojan\n    server: example.com\n    port: 443\n    password: test\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		ctx := t.Context()
		_, _ = subhub.ParseRawSubscriptionPayload(ctx, data)
		_ = subhub.NormalizeShareURI(string(data))
		_, _ = subhub.DecodeBase64Flexible(string(data))
		label := subhub.ShortUALabel(string(data))
		if utf8.Valid(data) && !utf8.ValidString(label) {
			t.Fatalf("ShortUALabel corrupted valid UTF-8 input %q -> %q", string(data), label)
		}
	})
}
