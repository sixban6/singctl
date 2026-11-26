// 文件职责：验证上游光猫 IP 校验、WAN 路由/PPPoE 桥接/旁路由形态识别、OpenWrt 桥接免插线接口托管及防跨站/闲置自动休眠反向代理。
package gateway_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"singctl/internal/config"
	"singctl/internal/gateway"
	"singctl/internal/platform/servicemgr"
)

func TestValidateModemIP(t *testing.T) {
	validCases := []struct {
		raw  string
		want string
	}{
		{"", ""},
		{"  192.168.3.1  ", "192.168.3.1"},
		{"192.168.100.1", "192.168.100.1"},
		{"10.0.0.1", "10.0.0.1"},
		{"172.16.1.1", "172.16.1.1"},
	}
	for _, tc := range validCases {
		got, err := gateway.ValidateModemIP(tc.raw, "192.168.55.1", "192.168.55.88")
		if err != nil {
			t.Fatalf("ValidateModemIP(%q) unexpected err: %v", tc.raw, err)
		}
		if got != tc.want {
			t.Fatalf("ValidateModemIP(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}

	invalidCases := []string{
		"127.0.0.1",
		"100.64.0.1",
		"203.0.113.1",
		"169.254.1.1",
		"224.0.0.1",
		"255.255.255.255",
		"192.168.55.1",
		"192.168.55.88",
		"192.168.3.1;reboot",
		"not-an-ip",
		"2001:db8::1",
	}
	for _, bad := range invalidCases {
		if _, err := gateway.ValidateModemIP(bad, "192.168.55.1", "192.168.55.88"); err == nil {
			t.Fatalf("expected ValidateModemIP(%q) to fail, got nil", bad)
		}
	}
}

func TestProbeModemStatus_TopologiesAndVendorFingerprints(t *testing.T) {
	t.Run("main_router_dhcp_double_nat_huawei", func(t *testing.T) {
		topo := gateway.TopologyInfo{
			LANIP:                 "192.168.55.1",
			LANCIDR:               "192.168.55.0/24",
			LANIface:              "br-lan",
			CurrentGatewayIP:      "192.168.3.1",
			SuggestedMainRouterIP: "192.168.3.1",
		}
		deps := gateway.ModemDeps{
			IsOpenWrt:  func() bool { return true },
			HasCommand: func(name string) bool { return name == "ifstatus" || name == "uci" },
			RunCmd: func(_ context.Context, name string, args ...string) ([]byte, error) {
				cmd := name + " " + strings.Join(args, " ")
				switch cmd {
				case "ifstatus wan":
					return []byte(`{"up":true,"proto":"dhcp","device":"eth0.2","l3_device":"eth0.2","ipv4-address":[{"address":"192.168.3.181","mask":24}],"route":[{"target":"0.0.0.0","mask":0,"nexthop":"192.168.3.1"}]}`), nil
				case "uci -q get network.wan.proto":
					return []byte("dhcp\n"), nil
				case "uci -q get network.wan.device":
					return []byte("eth0.2\n"), nil
				}
				return nil, os.ErrNotExist
			},
			HTTPProbe: func(_ context.Context, scheme, ip string, port int) (int, http.Header, string, int, error) {
				if scheme == "http" && ip == "192.168.3.1" && port == 80 {
					return http.StatusOK, http.Header{"X-Frame-Options": []string{"SAMEORIGIN"}}, `<html><script>xmlHttp.open("GET", "/api/system/routerstatus", true);</script></html>`, 2, nil
				}
				return 0, nil, "", 0, os.ErrNotExist
			},
		}

		st := gateway.ProbeModemStatus(t.Context(), config.GatewayConfig{Mode: "main"}, topo, deps)
		if !st.Supported || st.AccessMode != gateway.ModemAccessRouterNAT || st.WANExitType != gateway.WANExitPrivate {
			t.Fatalf("unexpected router_nat probe: %+v", st)
		}
		if st.EffectiveModemIP != "192.168.3.1" || !st.Online || st.Port != 80 || st.Scheme != "http" {
			t.Fatalf("expected 192.168.3.1 online on http:80, got %+v", st)
		}
		if !strings.Contains(st.VendorHint, "华为家用路由器") || st.DeviceKind != gateway.DeviceKindRouter || st.DoubleNATHint == "" || st.BridgeHelperCapable {
			t.Fatalf("expected huawei home router hint & router kind, doubleNatHint & non-bridge state, got %+v", st)
		}
	})

	t.Run("main_router_pppoe_bridge_cgnat_and_subnet_conflict", func(t *testing.T) {
		topo := gateway.TopologyInfo{
			LANIP:    "192.168.1.1",
			LANCIDR:  "192.168.1.0/24",
			LANIface: "br-lan",
		}
		deps := gateway.ModemDeps{
			IsOpenWrt:  func() bool { return true },
			HasCommand: func(name string) bool { return name == "ifstatus" || name == "uci" },
			LocalSubnets: func() []netip.Prefix {
				return []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}
			},
			RunCmd: func(_ context.Context, name string, args ...string) ([]byte, error) {
				cmd := name + " " + strings.Join(args, " ")
				switch cmd {
				case "ifstatus wan":
					return []byte(`{"up":true,"proto":"pppoe","device":"eth0.2","l3_device":"pppoe-wan","ipv4-address":[{"address":"100.64.10.5","mask":32}]}`), nil
				case "uci -q get network.wan.proto":
					return []byte("pppoe\n"), nil
				case "uci -q get network.wan.device":
					return []byte("eth0.2\n"), nil
				}
				return nil, os.ErrNotExist
			},
			HTTPProbe: func(context.Context, string, string, int) (int, http.Header, string, int, error) {
				return 0, nil, "", 0, os.ErrNotExist
			},
		}

		st := gateway.ProbeModemStatus(t.Context(), config.GatewayConfig{Mode: "main", ModemIP: "192.168.1.1"}, topo, deps)
		if st.AccessMode != gateway.ModemAccessPPPoEBridge || st.WANExitType != gateway.WANExitCGNAT || !st.BridgeHelperCapable {
			t.Fatalf("unexpected pppoe_bridge probe: %+v", st)
		}
		if st.SubnetConflict == "" {
			t.Fatalf("expected SubnetConflict warning when modem=192.168.1.1 overlaps LAN 192.168.1.0/24, got %+v", st)
		}
	})

	t.Run("side_router_discovers_upstream_modem_skipping_own_lan", func(t *testing.T) {
		topo := gateway.TopologyInfo{
			LANIP:                 "192.168.55.88",
			LANCIDR:               "192.168.55.0/24",
			LANIface:              "eth0",
			CurrentGatewayIP:      "192.168.55.1",
			SuggestedMainRouterIP: "192.168.55.1",
		}
		deps := gateway.ModemDeps{
			IsOpenWrt:  func() bool { return true },
			HasCommand: func(name string) bool { return name == "uci" },
			RunCmd:     func(context.Context, string, ...string) ([]byte, error) { return nil, os.ErrNotExist },
			HTTPProbe: func(_ context.Context, scheme, ip string, port int) (int, http.Header, string, int, error) {
				if ip == "192.168.55.1" {
					t.Fatalf("side router probe must skip mainRouterIP %s", ip)
				}
				if scheme == "http" && ip == "192.168.3.1" && port == 80 {
					return http.StatusOK, http.Header{}, `<title>ZXHN F663N</title>`, 3, nil
				}
				return 0, nil, "", 0, os.ErrNotExist
			},
		}

		st := gateway.ProbeModemStatus(t.Context(), config.GatewayConfig{Mode: "side", MainRouterIP: "192.168.55.1"}, topo, deps)
		if st.AccessMode != gateway.ModemAccessSideViaMain || st.EffectiveModemIP != "192.168.3.1" || !st.Online {
			t.Fatalf("unexpected side_via_main probe: %+v", st)
		}
		if !strings.Contains(st.VendorHint, "中兴") {
			t.Fatalf("expected ZTE vendor hint, got %q", st.VendorHint)
		}
	})
}

func TestApplyModemBridgeHelper_EnableDisableAndConflictGuard(t *testing.T) {
	topoConflict := gateway.TopologyInfo{LANIP: "192.168.1.1", LANCIDR: "192.168.1.0/24"}
	conflictDeps := gateway.ModemDeps{
		IsOpenWrt:  func() bool { return true },
		HasCommand: func(name string) bool { return name == "uci" || name == "ifstatus" },
		LocalSubnets: func() []netip.Prefix {
			return []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}
		},
		RunCmd: func(_ context.Context, name string, args ...string) ([]byte, error) {
			if name == "uci" && strings.Join(args, " ") == "-q get network.wan.proto" {
				return []byte("pppoe\n"), nil
			}
			if name == "uci" && strings.Join(args, " ") == "-q get network.wan.device" {
				return []byte("eth0.2\n"), nil
			}
			return nil, os.ErrNotExist
		},
	}
	if _, err := gateway.ApplyModemBridgeHelper(t.Context(), true, "192.168.1.1", topoConflict, conflictDeps); err == nil {
		t.Fatal("expected subnet conflict error when modem 192.168.1.1 overlaps LAN 192.168.1.0/24")
	}

	var cmds []string
	var wanNets []string
	mockMgr := servicemgr.NewMock()
	topoOK := gateway.TopologyInfo{LANIP: "192.168.55.1", LANCIDR: "192.168.55.0/24"}
	deps := gateway.ModemDeps{
		IsOpenWrt:  func() bool { return true },
		HasCommand: func(name string) bool { return name == "uci" || name == "ifstatus" || name == "ifup" || name == "ifdown" || name == "fw4" },
		LocalSubnets: func() []netip.Prefix {
			return []netip.Prefix{netip.MustParsePrefix("192.168.55.0/24")}
		},
		ServiceMgr: mockMgr,
		RunCmd: func(_ context.Context, name string, args ...string) ([]byte, error) {
			cmd := name + " " + strings.Join(args, " ")
			cmds = append(cmds, cmd)
			switch cmd {
			case "uci -q get network.wan.proto":
				return []byte("pppoe\n"), nil
			case "uci -q get network.wan.device":
				return []byte("eth0.2\n"), nil
			case "uci -q get firewall.@zone[1].name":
				return []byte("wan\n"), nil
			case "uci -q get firewall.@zone[1].network":
				if len(wanNets) == 0 {
					return []byte("wan wan6\n"), nil
				}
				return []byte(strings.Join(wanNets, " ") + "\n"), nil
			case "uci add_list firewall.@zone[1].network=singctl_modem":
				if len(wanNets) == 0 {
					wanNets = []string{"wan", "wan6"}
				}
				wanNets = append(wanNets, gateway.ModemBridgeUCISection)
			case "uci del_list firewall.@zone[1].network=singctl_modem":
				wanNets = []string{"wan", "wan6"}
			}
			return []byte("ok\n"), nil
		},
	}

	if _, err := gateway.ApplyModemBridgeHelper(t.Context(), true, "192.168.100.1", topoOK, deps); err != nil {
		t.Fatalf("ApplyModemBridgeHelper(enable) failed: %v", err)
	}
	for _, want := range []string{
		"uci set network.singctl_modem.device=eth0.2",
		"uci set network.singctl_modem.ipaddr=192.168.100.254",
		"uci set network.singctl_modem.defaultroute=0",
		"uci set network.singctl_modem.peerdns=0",
		"uci add_list firewall.@zone[1].network=singctl_modem",
		"ifup singctl_modem",
		"fw4 reload",
	} {
		if !slices.Contains(cmds, want) {
			t.Fatalf("missing expected command %q in %v", want, cmds)
		}
	}

	cmds = nil
	if _, err := gateway.ApplyModemBridgeHelper(t.Context(), false, "", topoOK, deps); err != nil {
		t.Fatalf("ApplyModemBridgeHelper(disable) failed: %v", err)
	}
	for _, want := range []string{
		"ifdown singctl_modem",
		"uci -q delete network.singctl_modem",
		"uci -q del_list firewall.@zone[1].network=singctl_modem",
		"fw4 reload",
	} {
		if !slices.Contains(cmds, want) {
			t.Fatalf("missing expected teardown command %q in %v", want, cmds)
		}
	}
}

func TestModemProxyManager_SecurityHeadersCSRFAndIdleSleep(t *testing.T) {
	var seenOrigin, seenReferer, seenCookie string
	upstreamModem := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenOrigin = r.Header.Get("Origin")
		seenReferer = r.Header.Get("Referer")
		seenCookie = r.Header.Get("Cookie")
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'self'; script-src 'self'")
		http.SetCookie(w, &http.Cookie{Name: "SID", Value: "modem-sid-1", Path: "/", Secure: true})
		if r.URL.Path == "/api/system/routerstatus" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"guide":true}`))
			return
		}
		_, _ = w.Write([]byte(`<html>ok</html>`))
	}))
	defer upstreamModem.Close()

	u, err := url.Parse(upstreamModem.URL)
	if err != nil {
		t.Fatal(err)
	}
	port := 0
	for _, r := range u.Port() {
		port = port*10 + int(r-'0')
	}

	authed := false
	mgr := gateway.NewModemProxyManager(gateway.ModemProxyOptions{
		IdleTimeout:                120 * time.Millisecond,
		AllowLoopbackTargetForTest: true,
		Authorizer:                 func(*http.Request) bool { return authed },
	})
	defer func() { _ = mgr.Close() }()

	sess, err := mgr.Open(gateway.ModemProxyTarget{Scheme: "http", IP: u.Hostname(), Port: port}, 0)
	if err != nil {
		t.Fatalf("Open modem proxy failed: %v", err)
	}
	if !sess.Running || sess.Port == 0 || sess.Ticket == "" {
		t.Fatalf("unexpected open session: %+v", sess)
	}

	baseURL := "http://127.0.0.1:" + strings.TrimSpace(url.PathEscape(strings.ReplaceAll(time.Duration(sess.Port).String(), "ns", "")))
	_ = baseURL
	noRedirectCli := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	proxyBase := "http://" + (&url.URL{Host: "127.0.0.1:" + itoa(sess.Port)}).Host

	// 1. Unauthenticated request without ticket fails with 401.
	unauthResp, err := noRedirectCli.Get(proxyBase + "/")
	if err != nil {
		t.Fatal(err)
	}
	_ = unauthResp.Body.Close()
	if unauthResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unauthenticated proxy request, got %d", unauthResp.StatusCode)
	}

	// 1b. Public WAN RemoteAddr must be rejected with 403 Forbidden; Tailscale CGNAT reaches 401 auth gate.
	pubReq := httptest.NewRequest(http.MethodGet, "/", nil)
	pubReq.RemoteAddr = "203.0.113.9:12345"
	pubRec := httptest.NewRecorder()
	mgr.ServeHTTP(pubRec, pubReq)
	if pubRec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for public RemoteAddr, got %d", pubRec.Code)
	}
	tsReq := httptest.NewRequest(http.MethodGet, "/", nil)
	tsReq.RemoteAddr = "100.64.0.5:4321"
	tsRec := httptest.NewRecorder()
	mgr.ServeHTTP(tsRec, tsReq)
	if tsRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected Tailscale RemoteAddr to pass IP filter and reach 401 auth, got %d", tsRec.Code)
	}

	// 2. Ticket exchange redirects to "/" and issues HttpOnly auth cookie.
	ticketResp, err := noRedirectCli.Get(proxyBase + "/?_sc_modem_ticket=" + url.QueryEscape(sess.Ticket))
	if err != nil {
		t.Fatal(err)
	}
	_ = ticketResp.Body.Close()
	if ticketResp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302 redirect after ticket exchange, got %d", ticketResp.StatusCode)
	}
	cookies := ticketResp.Cookies()
	if len(cookies) == 0 {
		t.Fatal("expected modem proxy auth cookie after ticket exchange")
	}

	// 3. Authenticated request strips X-Frame-Options & frame-ancestors, rewrites CSRF headers, and scrubs singctl_session cookie.
	req, _ := http.NewRequest(http.MethodGet, proxyBase+"/api/system/routerstatus", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	req.AddCookie(&http.Cookie{Name: "singctl_session", Value: "secret-singctl-tok"})
	req.AddCookie(&http.Cookie{Name: "SID", Value: "modem-sid-1"})
	req.Header.Set("Origin", "http://192.168.55.1:8090")
	req.Header.Set("Referer", "http://192.168.55.1:8090/net/modem")

	apiResp, err := noRedirectCli.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = apiResp.Body.Close()
	if apiResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on proxied /api/system/routerstatus, got %d", apiResp.StatusCode)
	}
	if apiResp.Header.Get("X-Frame-Options") != "" {
		t.Fatalf("expected X-Frame-Options stripped, got %q", apiResp.Header.Get("X-Frame-Options"))
	}
	if strings.Contains(strings.ToLower(apiResp.Header.Get("Content-Security-Policy")), "frame-ancestors") {
		t.Fatalf("expected frame-ancestors stripped from CSP, got %q", apiResp.Header.Get("Content-Security-Policy"))
	}
	if seenOrigin != upstreamModem.URL || !strings.HasPrefix(seenReferer, upstreamModem.URL) {
		t.Fatalf("expected Origin & Referer rewritten to %s, got origin=%q referer=%q", upstreamModem.URL, seenOrigin, seenReferer)
	}
	if strings.Contains(seenCookie, "singctl_session") || !strings.Contains(seenCookie, "SID=modem-sid-1") {
		t.Fatalf("expected singctl_session scrubbed and SID preserved, got Cookie=%q", seenCookie)
	}

	// 4. Wait past IdleTimeout and confirm proxy listener auto-sleeps.
	deadline := time.Now().Add(800 * time.Millisecond)
	for time.Now().Before(deadline) {
		if !mgr.Status().Running {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if mgr.Status().Running {
		t.Fatalf("expected modem proxy to auto-sleep after idle timeout, still running: %+v", mgr.Status())
	}
}

func TestClassifyGatewayEndpoint_ModemVsRouter(t *testing.T) {
	cases := []struct {
		name     string
		headers  http.Header
		body     string
		wantKind string
		wantHint string
	}{
		{
			name:     "huawei_home_router_session_r3",
			headers:  http.Header{"Set-Cookie": []string{"SessionID_R3=abc; path=/; HttpOnly"}},
			body:     `<html><script>xmlHttp.open("GET", "/api/system/routerstatus", true);</script></html>`,
			wantKind: gateway.DeviceKindRouter,
			wantHint: "华为家用路由器",
		},
		{
			name:     "openwrt_plain_luci_router",
			headers:  http.Header{},
			body:     `<title>OpenWrt - LuCI</title><form action="/cgi-bin/luci"></form>`,
			wantKind: gateway.DeviceKindRouter,
			wantHint: "OpenWrt",
		},
		{
			name:     "xiaomi_router",
			headers:  http.Header{},
			body:     `<title>MiWiFi 管理</title>`,
			wantKind: gateway.DeviceKindRouter,
			wantHint: "小米",
		},
		{
			name:     "telecom_tianyi_luci_modem",
			headers:  http.Header{},
			body:     `<title>中国电信智能网关</title><img src="/luci-static/resources/image/logo_tianyi.png"><input type="hidden" name="username" value="telecomadmin"><script>window.localStorage.setItem("hasPots", 1);</script>`,
			wantKind: gateway.DeviceKindModem,
			wantHint: "电信",
		},
		{
			name:     "telecom_boa_8080_superadmin",
			headers:  http.Header{"Server": []string{"Boa/0.93.15"}},
			body:     `<form action=/boaform/admin/formLogin method=POST><input onclick="location.href='/usereg.asp'"></form>`,
			wantKind: gateway.DeviceKindModem,
			wantHint: "电信",
		},
		{
			name:     "huawei_optixstar_ont",
			headers:  http.Header{},
			body:     `<title>OptiXstar HN8145X6</title><script>fetch("/asp/GetRandCount.asp")</script>`,
			wantKind: gateway.DeviceKindModem,
			wantHint: "华为",
		},
		{
			name:     "zte_zxhn_ont",
			headers:  http.Header{},
			body:     `<title>ZXHN F7607P</title>`,
			wantKind: gateway.DeviceKindModem,
			wantHint: "中兴",
		},
		{
			name:     "fiberhome_ont",
			headers:  http.Header{},
			body:     `<title>烽火智能网关 HG6143D</title>`,
			wantKind: gateway.DeviceKindModem,
			wantHint: "烽火",
		},
		{
			name:     "cmcc_ont",
			headers:  http.Header{},
			body:     `<div>中国移动宽带网关</div><input value="CMCCAdmin">`,
			wantKind: gateway.DeviceKindModem,
			wantHint: "移动",
		},
		{
			name:     "unicom_ont",
			headers:  http.Header{},
			body:     `<div>中国联通</div><input value="CUAdmin">`,
			wantKind: gateway.DeviceKindModem,
			wantHint: "联通",
		},
		{
			name:    "huawei_home_router_with_mobile_ua_zte_regex_and_hex_cookie",
			headers: http.Header{"Set-Cookie": []string{"SessionID_R3=045cf663f460hg8145deadbeef; path=/; HttpOnly"}, "Content-Type": []string{"text/html"}},
			body: `<html><script>
xmlHttp.open("GET", "/api/system/routerstatus", true);
xmlHttp.setRequestHeader("Content-Type", "javascript/json");
var ismobile = /mobile|netfront|yas\-|your|zeto|zte\-/i.test(useragent.substr(0,4));
window.location.href = "/html/smallguide.html";
</script></html>`,
			wantKind: gateway.DeviceKindRouter,
			wantHint: "华为家用路由器",
		},
		{
			name:     "zte_title_f460_ont",
			headers:  http.Header{},
			body:     `<title>ZTE F460 GPON</title>`,
			wantKind: gateway.DeviceKindModem,
			wantHint: "中兴",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kind, hint := gateway.ClassifyGatewayEndpoint(tc.headers, tc.body)
			if kind != tc.wantKind {
				t.Fatalf("ClassifyGatewayEndpoint kind = %q, want %q (hint=%q)", kind, tc.wantKind, hint)
			}
			if tc.wantHint != "" && !strings.Contains(hint, tc.wantHint) {
				t.Fatalf("ClassifyGatewayEndpoint hint = %q, want substring %q", hint, tc.wantHint)
			}
		})
	}
}

func TestParseTraceroutePrivateHopsAndTripleNATModemSelection(t *testing.T) {
	rawTrace := `traceroute to 223.5.5.5 (223.5.5.5), 5 hops max, 46 byte packets
 1  192.168.3.1  3.087 ms  0.403 ms  0.441 ms
 2  192.168.1.1  1.141 ms  1.386 ms  1.242 ms
 3  *  *  *
 4  203.0.113.9  4.637 ms
 5  192.168.99.1  8.751 ms
`
	hops := gateway.ParseTraceroutePrivateHops(rawTrace)
	wantHops := []string{"192.168.3.1", "192.168.1.1"}
	if !slices.Equal(hops, wantHops) {
		t.Fatalf("ParseTraceroutePrivateHops = %v, want %v", hops, wantHops)
	}

	topo := gateway.TopologyInfo{
		LANIP:            "192.168.55.1",
		LANCIDR:          "192.168.55.0/24",
		LANIface:         "br-lan",
		CurrentGatewayIP: "192.168.3.1",
	}
	deps := gateway.ModemDeps{
		IsOpenWrt:  func() bool { return true },
		HasCommand: func(name string) bool { return name == "ifstatus" || name == "uci" || name == "traceroute" },
		TraceHops:  func(context.Context) []string { return []string{"192.168.3.1", "192.168.1.1"} },
		RunCmd: func(_ context.Context, name string, args ...string) ([]byte, error) {
			cmd := name + " " + strings.Join(args, " ")
			switch cmd {
			case "ifstatus wan":
				return []byte(`{"up":true,"proto":"dhcp","device":"eth0.2","l3_device":"eth0.2","ipv4-address":[{"address":"192.168.3.181","mask":24}],"route":[{"target":"0.0.0.0","mask":0,"nexthop":"192.168.3.1"}]}`), nil
			case "uci -q get network.wan.proto":
				return []byte("dhcp\n"), nil
			case "uci -q get network.wan.device":
				return []byte("eth0.2\n"), nil
			}
			return nil, os.ErrNotExist
		},
		HTTPProbe: func(_ context.Context, scheme, ip string, port int) (int, http.Header, string, int, error) {
			if scheme == "http" && ip == "192.168.3.1" && port == 80 {
				return http.StatusOK, http.Header{"Set-Cookie": []string{"SessionID_R3=test; path=/"}}, `<html><script>xmlHttp.open("GET","/api/system/routerstatus",true);</script></html>`, 1, nil
			}
			if scheme == "http" && ip == "192.168.1.1" && port == 80 {
				return http.StatusOK, http.Header{"X-Frame-Options": []string{"SAMEORIGIN"}}, `<html><title>中国电信智能网关</title><input value="telecomadmin"><script>localStorage.setItem("hasPots", 1)</script></html>`, 2, nil
			}
			if scheme == "http" && ip == "192.168.1.1" && port == 8080 {
				return http.StatusOK, http.Header{"Server": []string{"Boa/0.93.15"}}, `<form action=/boaform/admin/formLogin method=POST></form>`, 2, nil
			}
			return 0, nil, "", 0, os.ErrNotExist
		},
	}

	st := gateway.ProbeModemStatus(t.Context(), config.GatewayConfig{Mode: "main"}, topo, deps)
	if st.EffectiveModemIP != "192.168.1.1" || st.DeviceKind != gateway.DeviceKindModem {
		t.Fatalf("expected auto-probe to skip intermediate router 192.168.3.1 and pick modem 192.168.1.1, got %+v", st)
	}
	if st.AdminPort != 8080 || st.NATLayers != 3 {
		t.Fatalf("expected AdminPort=8080 and NATLayers=3, got %+v", st)
	}
	if len(st.UpstreamHops) != 2 || st.UpstreamHops[0].IP != "192.168.3.1" || st.UpstreamHops[0].DeviceKind != gateway.DeviceKindRouter || st.UpstreamHops[1].IP != "192.168.1.1" || st.UpstreamHops[1].DeviceKind != gateway.DeviceKindModem {
		t.Fatalf("unexpected UpstreamHops chain: %+v", st.UpstreamHops)
	}
	if !strings.Contains(st.DoubleNATHint, "三层 NAT") {
		t.Fatalf("expected 3-layer NAT hint in DoubleNATHint, got %q", st.DoubleNATHint)
	}
}

func TestModemVault_SaveLoadClearPermissionsAndConcurrency(t *testing.T) {
	dir := t.TempDir()
	vaultPath := gateway.ModemVaultPath(filepath.Join(dir, "singctl.yaml"))
	if filepath.Base(vaultPath) != "modem-auth.json" || filepath.Dir(vaultPath) != dir {
		t.Fatalf("unexpected ModemVaultPath: %q", vaultPath)
	}

	// Empty vault returns unsaved summaries.
	empty := gateway.LoadModemCredentialsSummary(vaultPath)
	if empty.Super.Saved || empty.User.Saved {
		t.Fatalf("expected empty vault initially, got %+v", empty)
	}

	// Validation errors: invalid slot, initial empty password, control chars, oversized value.
	now := time.Unix(1732600000, 0).UTC()
	if _, err := gateway.SaveModemCredentialSlot(vaultPath, "admin", "u", "p", false, now); err == nil {
		t.Fatal("expected error for invalid slot name")
	}
	if _, err := gateway.SaveModemCredentialSlot(vaultPath, "super", "telecomadmin", "", false, now); err == nil {
		t.Fatal("expected error when saving new slot with empty password")
	}
	if _, err := gateway.SaveModemCredentialSlot(vaultPath, "super", "telecom\nadmin", "secret", false, now); err == nil {
		t.Fatal("expected error for control char in username")
	}
	if _, err := gateway.SaveModemCredentialSlot(vaultPath, "super", "telecomadmin", strings.Repeat("x", 129), false, now); err == nil {
		t.Fatal("expected error for oversized password > 128 chars")
	}

	// Save superadmin & user slots cleanly, check 0600 permissions and redacted JSON.
	sum, err := gateway.SaveModemCredentialSlot(vaultPath, "super", "telecomadmin", "Sup3r!Pass", false, now)
	if err != nil {
		t.Fatalf("SaveModemCredentialSlot(super) failed: %v", err)
	}
	if !sum.Super.Saved || sum.Super.Username != "telecomadmin" {
		t.Fatalf("unexpected summary after save: %+v", sum)
	}
	info, err := os.Stat(vaultPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("expected vault mode 0600, got %04o", info.Mode().Perm())
	}

	// Update username without passing password -> preserves existing password.
	sum, err = gateway.SaveModemCredentialSlot(vaultPath, "super", "telecomadmin2", "", false, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("SaveModemCredentialSlot(preserve password) failed: %v", err)
	}
	u, p, err := gateway.ReadModemCredentialSecret(vaultPath, "super")
	if err != nil || u != "telecomadmin2" || p != "Sup3r!Pass" {
		t.Fatalf("ReadModemCredentialSecret mismatch: u=%q p=%q err=%v", u, p, err)
	}

	// Summary JSON must never contain secret passwords.
	summaryJSON, _ := json.Marshal(sum)
	if strings.Contains(string(summaryJSON), "Sup3r!Pass") {
		t.Fatalf("summary JSON leaked password: %s", summaryJSON)
	}

	// Concurrent reads/writes under -race.
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			_, _ = gateway.SaveModemCredentialSlot(vaultPath, "user", "useradmin", "UserPass#"+itoa(i), false, now)
			_ = gateway.LoadModemCredentialsSummary(vaultPath)
		})
	}
	wg.Wait()

	// Clear slot wipes stored credentials cleanly.
	sum, err = gateway.SaveModemCredentialSlot(vaultPath, "super", "", "", true, now.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("clearSlot failed: %v", err)
	}
	if sum.Super.Saved || sum.Super.Username != "" {
		t.Fatalf("expected super slot cleared, got %+v", sum.Super)
	}
	if _, _, err := gateway.ReadModemCredentialSecret(vaultPath, "super"); err == nil {
		t.Fatal("expected error reading cleared super slot")
	}
}

func TestModemProxyManager_FramebusterRewriteAndASCIIAutofillInjection(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login.js":
			w.Header().Set("Content-Type", "application/javascript")
			_, _ = w.Write([]byte(`if (window != top) top.location.href = "/cgi-bin/luci";`))
		default:
			w.Header().Set("Content-Type", "text/html; charset=gbk")
			_, _ = w.Write([]byte(`<html><head><title>Modem</title><script>if (window.top != window.self) { window.top.location.href = "/admin/login.asp"; }</script></head><body><form id="login_form"><input id="login_username"><input id="login_password" type="password"></form></body></html>`))
		}
	}))
	defer upstream.Close()

	u, _ := url.Parse(upstream.URL)
	port := 0
	for _, r := range u.Port() {
		port = port*10 + int(r-'0')
	}

	mgr := gateway.NewModemProxyManager(gateway.ModemProxyOptions{
		IdleTimeout:                time.Second,
		AllowLoopbackTargetForTest: true,
		Authorizer:                 func(*http.Request) bool { return true },
	})
	defer func() { _ = mgr.Close() }()

	sess, err := mgr.Open(gateway.ModemProxyTarget{Scheme: "http", IP: u.Hostname(), Port: port}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if sess.AutofillNonce == "" {
		t.Fatalf("expected non-empty AutofillNonce in session: %+v", sess)
	}

	proxyBase := "http://127.0.0.1:" + itoa(sess.Port)
	htmlResp, err := http.Get(proxyBase + "/admin/login.asp")
	if err != nil {
		t.Fatal(err)
	}
	defer htmlResp.Body.Close()
	rawHTML, _ := io.ReadAll(htmlResp.Body)
	htmlStr := string(rawHTML)
	if strings.Contains(htmlStr, "window.top != window.self") {
		t.Fatalf("expected HTML framebuster neutralized, got %s", htmlStr)
	}
	marker := `<script data-sc-modem-helper="1">`
	idx := strings.Index(htmlStr, marker)
	if idx < 0 || !strings.Contains(htmlStr[idx:], sess.AutofillNonce) || !strings.Contains(htmlStr[idx:], "captcha_required") {
		t.Fatalf("expected injected helper script with nonce & captcha guard, got %s", htmlStr)
	}
	for _, b := range rawHTML[idx:] {
		if b >= 128 {
			t.Fatalf("injected helper script must be pure 7-bit ASCII for GBK compatibility, found byte 0x%02x", b)
		}
	}

	jsResp, err := http.Get(proxyBase + "/login.js")
	if err != nil {
		t.Fatal(err)
	}
	defer jsResp.Body.Close()
	rawJS, _ := io.ReadAll(jsResp.Body)
	if strings.Contains(string(rawJS), "window != top") {
		t.Fatalf("expected JS framebuster neutralized, got %s", string(rawJS))
	}
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var buf [16]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}
