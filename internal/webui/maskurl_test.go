package webui

import "testing"

func TestMaskURL(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"标准订阅链接", "https://sub.example.com/api/v1/client/subscribe?token=abcdef123456", "https://******"},
		{"带端口的链接", "http://provider.io:8443/token/xyz?flag=1", "http://******"},
		{"畸形链接", "not-a-url", "https://******"},
		{"空链接", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := maskURL(tc.in); got != tc.want {
				t.Fatalf("maskURL(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
