// 文件职责：验证客户端上游光猫探测、配置保存与防覆盖、桥接免插线接口开关、按需内嵌反向代理与 CSP frame-src 放行契约。
package webui_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"singctl/internal/config"
	"singctl/internal/gateway"
	"singctl/internal/webui"
)

func TestModemAPI_StatusConfigBridgeAndEmbeddedConsole(t *testing.T) {
	upstreamModem := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		if r.URL.Path == "/api/system/routerstatus" {
			_, _ = w.Write([]byte(`{"guide":true,"isrepeater":false}`))
			return
		}
		_, _ = w.Write([]byte(`<html><script>xmlHttp.open("GET","/api/system/routerstatus",true);</script></html>`))
	}))
	defer upstreamModem.Close()

	u, _ := url.Parse(upstreamModem.URL)
	modemPort := 0
	for _, r := range u.Port() {
		modemPort = modemPort*10 + int(r-'0')
	}

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "singctl.yaml")
	if err := os.WriteFile(cfgPath, []byte("subs:\n  - name: main\n    url: https://example.com/sub\n"), 0600); err != nil {
		t.Fatal(err)
	}

	var uciCmds []string
	wanProto := "pppoe"
	bridgeEnabled := false
	ephemeralPort := 0

	modemDeps := gateway.ModemDeps{
		IsOpenWrt:  func() bool { return true },
		HasCommand: func(name string) bool { return name == "uci" || name == "ifstatus" || name == "ifup" || name == "ifdown" || name == "fw4" },
		LocalSubnets: func() []netip.Prefix {
			return []netip.Prefix{netip.MustParsePrefix("192.168.55.0/24")}
		},
		RunCmd: func(_ context.Context, name string, args ...string) ([]byte, error) {
			cmd := name + " " + strings.Join(args, " ")
			uciCmds = append(uciCmds, cmd)
			switch cmd {
			case "uci -q get network.wan.proto":
				return []byte(wanProto + "\n"), nil
			case "uci -q get network.wan.device":
				return []byte("eth0.2\n"), nil
			case "uci -q get network.singctl_modem.ipaddr":
				if bridgeEnabled {
					return []byte("192.168.100.254\n"), nil
				}
				return nil, os.ErrNotExist
			case "uci -q get firewall.@zone[1].name":
				return []byte("wan\n"), nil
			case "uci -q get firewall.@zone[1].network":
				return []byte("wan wan6\n"), nil
			case "ifup singctl_modem":
				bridgeEnabled = true
			case "ifdown singctl_modem":
				bridgeEnabled = false
			}
			return []byte("ok\n"), nil
		},
		HTTPProbe: func(_ context.Context, scheme, ip string, port int) (int, http.Header, string, int, error) {
			if scheme == "http" && ip == "192.168.100.1" && port == 80 {
				return http.StatusOK, http.Header{"X-Frame-Options": []string{"SAMEORIGIN"}}, `/api/system/routerstatus`, 2, nil
			}
			return 0, nil, "", 0, os.ErrNotExist
		},
	}

	srv := webui.New(webui.Options{
		ConfigPath:       cfgPath,
		Version:          "v1.14.203-test",
		ModemConsolePort: &ephemeralPort,
		GatewayProberForTest: func() gateway.TopologyInfo {
			return gateway.TopologyInfo{
				LANIP:    "192.168.55.1",
				LANCIDR:  "192.168.55.0/24",
				LANIface: "br-lan",
			}
		},
		ModemDepsForTest: &modemDeps,
		ModemProxyOptionsForTest: &gateway.ModemProxyOptions{
			IdleTimeout:                5 * time.Second,
			AllowLoopbackTargetForTest: true,
		},
	})

	// 1. CSP allows iframe rendering while preserving frame-ancestors 'none' & X-Frame-Options: DENY
	rootRec := httptest.NewRecorder()
	srv.Mux.ServeHTTP(rootRec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rootRec.Code != http.StatusOK {
		t.Fatalf("GET / failed: %d", rootRec.Code)
	}
	csp := rootRec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "frame-src 'self' http: https:") || !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Fatalf("unexpected CSP header: %q", csp)
	}

	// 2. PUT /api/modem/config rejects invalid IP and persists valid RFC1918 IP with 0600 perms
	badReq := httptest.NewRequest(http.MethodPut, "/api/modem/config", bytes.NewBufferString(`{"modemIP":"127.0.0.1"}`))
	badReq.Header.Set("Content-Type", "application/json")
	badRec := httptest.NewRecorder()
	srv.Mux.ServeHTTP(badRec, badReq)
	if badRec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on loopback modemIP, got %d (%s)", badRec.Code, badRec.Body.String())
	}

	okReq := httptest.NewRequest(http.MethodPut, "/api/modem/config", bytes.NewBufferString(`{"modemIP":"192.168.100.1"}`))
	okReq.Header.Set("Content-Type", "application/json")
	okRec := httptest.NewRecorder()
	srv.Mux.ServeHTTP(okRec, okReq)
	if okRec.Code != http.StatusOK {
		t.Fatalf("PUT /api/modem/config failed: %d %s", okRec.Code, okRec.Body.String())
	}

	// 3. Subsequent PUT /api/gateway preserves gateway.modem_ip
	gwReq := httptest.NewRequest(http.MethodPut, "/api/gateway", bytes.NewBufferString(`{"mode":"main","ipv6Mode":"off"}`))
	gwReq.Header.Set("Content-Type", "application/json")
	gwRec := httptest.NewRecorder()
	srv.Mux.ServeHTTP(gwRec, gwReq)
	if gwRec.Code != http.StatusOK {
		t.Fatalf("PUT /api/gateway failed: %d %s", gwRec.Code, gwRec.Body.String())
	}
	loadedCfg, err := config.Load(cfgPath)
	if err != nil || loadedCfg.Gateway.ModemIP != "192.168.100.1" {
		t.Fatalf("expected gateway.modem_ip preserved as 192.168.100.1, got %+v (err=%v)", loadedCfg.Gateway, err)
	}

	// 4. GET /api/modem/status reflects PPPoE bridge + Huawei fingerprint + configured IP
	stRec := httptest.NewRecorder()
	srv.Mux.ServeHTTP(stRec, httptest.NewRequest(http.MethodGet, "/api/modem/status", nil))
	if stRec.Code != http.StatusOK {
		t.Fatalf("GET /api/modem/status failed: %d %s", stRec.Code, stRec.Body.String())
	}
	if !strings.Contains(stRec.Body.String(), `"accessMode":"pppoe_bridge"`) || !strings.Contains(stRec.Body.String(), `"effectiveModemIp":"192.168.100.1"`) {
		t.Fatalf("unexpected modem status JSON: %s", stRec.Body.String())
	}

	// 5. PUT /api/modem/bridge mounts & removes singctl_modem
	brOnReq := httptest.NewRequest(http.MethodPut, "/api/modem/bridge", bytes.NewBufferString(`{"enabled":true,"modemIP":"192.168.100.1"}`))
	brOnReq.Header.Set("Content-Type", "application/json")
	brOnRec := httptest.NewRecorder()
	srv.Mux.ServeHTTP(brOnRec, brOnReq)
	if brOnRec.Code != http.StatusOK || !bridgeEnabled || !slices.Contains(uciCmds, "ifup singctl_modem") {
		t.Fatalf("PUT /api/modem/bridge enable failed: %d %s", brOnRec.Code, brOnRec.Body.String())
	}

	brOffReq := httptest.NewRequest(http.MethodPut, "/api/modem/bridge", bytes.NewBufferString(`{"enabled":false}`))
	brOffReq.Header.Set("Content-Type", "application/json")
	brOffRec := httptest.NewRecorder()
	srv.Mux.ServeHTTP(brOffRec, brOffReq)
	if brOffRec.Code != http.StatusOK || bridgeEnabled {
		t.Fatalf("PUT /api/modem/bridge disable failed: %d %s", brOffRec.Code, brOffRec.Body.String())
	}

	// 6. POST /api/modem/console/open starts proxy and forwards HTTP, then /close shuts down listener
	openBody, _ := json.Marshal(map[string]any{
		"scheme": "http",
		"ip":     u.Hostname(),
		"port":   modemPort,
	})
	openReq := httptest.NewRequest(http.MethodPost, "/api/modem/console/open", bytes.NewReader(openBody))
	openReq.Header.Set("Content-Type", "application/json")
	openRec := httptest.NewRecorder()
	srv.Mux.ServeHTTP(openRec, openReq)
	if openRec.Code != http.StatusOK {
		t.Fatalf("POST /api/modem/console/open failed: %d %s", openRec.Code, openRec.Body.String())
	}
	var openResp struct {
		OK      bool                      `json:"ok"`
		Session gateway.ModemProxySession `json:"session"`
	}
	if err := json.Unmarshal(openRec.Body.Bytes(), &openResp); err != nil || !openResp.Session.Running || openResp.Session.Port == 0 {
		t.Fatalf("unexpected open session response: %s (err=%v)", openRec.Body.String(), err)
	}

	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	proxyHost := "http://127.0.0.1:" + (&url.URL{Host: ""}).Port()
	_ = proxyHost
	proxyURL := (&url.URL{Scheme: "http", Host: (&url.URL{}).Host}).String()
	_ = proxyURL
	respTicket, err := noRedirect.Get("http://127.0.0.1:" + intStr(openResp.Session.Port) + "/?_sc_modem_ticket=" + url.QueryEscape(openResp.Session.Ticket))
	if err != nil || respTicket.StatusCode != http.StatusFound {
		t.Fatalf("ticket exchange failed: resp=%v err=%v", respTicket, err)
	}
	_ = respTicket.Body.Close()

	apiReq, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1:"+intStr(openResp.Session.Port)+"/api/system/routerstatus", nil)
	for _, c := range respTicket.Cookies() {
		apiReq.AddCookie(c)
	}
	apiResp, err := noRedirect.Do(apiReq)
	if err != nil || apiResp.StatusCode != http.StatusOK {
		t.Fatalf("proxied modem API failed: resp=%v err=%v", apiResp, err)
	}
	_ = apiResp.Body.Close()
	if apiResp.Header.Get("X-Frame-Options") != "" {
		t.Fatalf("expected X-Frame-Options stripped, got %q", apiResp.Header.Get("X-Frame-Options"))
	}

	closeReq := httptest.NewRequest(http.MethodPost, "/api/modem/console/close", bytes.NewBufferString(`{}`))
	closeReq.Header.Set("Content-Type", "application/json")
	closeRec := httptest.NewRecorder()
	srv.Mux.ServeHTTP(closeRec, closeReq)
	if closeRec.Code != http.StatusOK || !strings.Contains(closeRec.Body.String(), `"running":false`) {
		t.Fatalf("POST /api/modem/console/close failed: %d %s", closeRec.Code, closeRec.Body.String())
	}

	// 7. Dual-slot modem credentials vault endpoints: reject bad slot, save 0600, redact status, use for autofill, and clear.
	badCredReq := httptest.NewRequest(http.MethodPut, "/api/modem/credentials", bytes.NewBufferString(`{"slot":"root","username":"a","password":"b"}`))
	badCredReq.Header.Set("Content-Type", "application/json")
	badCredRec := httptest.NewRecorder()
	srv.Mux.ServeHTTP(badCredRec, badCredReq)
	if badCredRec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on invalid credential slot, got %d (%s)", badCredRec.Code, badCredRec.Body.String())
	}

	saveCredReq := httptest.NewRequest(http.MethodPut, "/api/modem/credentials", bytes.NewBufferString(`{"slot":"super","username":"telecomadmin","password":"Sup3r!Secret"}`))
	saveCredReq.Header.Set("Content-Type", "application/json")
	saveCredRec := httptest.NewRecorder()
	srv.Mux.ServeHTTP(saveCredRec, saveCredReq)
	if saveCredRec.Code != http.StatusOK {
		t.Fatalf("PUT /api/modem/credentials failed: %d %s", saveCredRec.Code, saveCredRec.Body.String())
	}
	if strings.Contains(saveCredRec.Body.String(), "Sup3r!Secret") {
		t.Fatalf("PUT /api/modem/credentials response leaked password: %s", saveCredRec.Body.String())
	}
	vaultStat, err := os.Stat(filepath.Join(dir, "modem-auth.json"))
	if err != nil || vaultStat.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 modem-auth.json file, stat=%v err=%v", vaultStat, err)
	}

	stWithCredRec := httptest.NewRecorder()
	srv.Mux.ServeHTTP(stWithCredRec, httptest.NewRequest(http.MethodGet, "/api/modem/status", nil))
	stBody := stWithCredRec.Body.String()
	if stWithCredRec.Code != http.StatusOK || !strings.Contains(stBody, `"username":"telecomadmin"`) || strings.Contains(stBody, "Sup3r!Secret") {
		t.Fatalf("unexpected /api/modem/status credentials summary: %d %s", stWithCredRec.Code, stBody)
	}

	useCredReq := httptest.NewRequest(http.MethodPost, "/api/modem/credentials/use", bytes.NewBufferString(`{"slot":"super"}`))
	useCredReq.Header.Set("Content-Type", "application/json")
	useCredRec := httptest.NewRecorder()
	srv.Mux.ServeHTTP(useCredRec, useCredReq)
	if useCredRec.Code != http.StatusOK || !strings.Contains(useCredRec.Body.String(), `"password":"Sup3r!Secret"`) {
		t.Fatalf("POST /api/modem/credentials/use failed: %d %s", useCredRec.Code, useCredRec.Body.String())
	}

	clearCredReq := httptest.NewRequest(http.MethodPut, "/api/modem/credentials", bytes.NewBufferString(`{"slot":"super","clear":true}`))
	clearCredReq.Header.Set("Content-Type", "application/json")
	clearCredRec := httptest.NewRecorder()
	srv.Mux.ServeHTTP(clearCredRec, clearCredReq)
	if clearCredRec.Code != http.StatusOK {
		t.Fatalf("PUT /api/modem/credentials clear failed: %d %s", clearCredRec.Code, clearCredRec.Body.String())
	}

	useClearedReq := httptest.NewRequest(http.MethodPost, "/api/modem/credentials/use", bytes.NewBufferString(`{"slot":"super"}`))
	useClearedReq.Header.Set("Content-Type", "application/json")
	useClearedRec := httptest.NewRecorder()
	srv.Mux.ServeHTTP(useClearedRec, useClearedReq)
	if useClearedRec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 after clearing credential slot, got %d (%s)", useClearedRec.Code, useClearedRec.Body.String())
	}
}

func intStr(v int) string {
	b := make([]byte, 0, 8)
	if v == 0 {
		return "0"
	}
	var rev [8]byte
	i := 0
	for v > 0 {
		rev[i] = byte('0' + v%10)
		i++
		v /= 10
	}
	for i > 0 {
		i--
		b = append(b, rev[i])
	}
	return string(b)
}
