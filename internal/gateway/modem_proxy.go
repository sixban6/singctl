// 文件职责：提供按需启动、15 分钟闲置自动休眠且带会话鉴权与防跨站头重写的上游光猫反向代理隧道。
package gateway

import (
	"bytes"
	"cmp"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultModemProxyIdleTimeout = 15 * time.Minute
	modemTicketQueryParam        = "_sc_modem_ticket"
	modemAuthCookieName          = "singctl_modem_auth"
	ticketTTL                    = 2 * time.Minute
	maxModemProxyRewriteBytes    = 512 * 1024
)

var (
	frameBusterRe       = regexp.MustCompile(`\b(?:(?:window\.)?(?:top|self|parent)|window)\s*!==?\s*(?:(?:window\.)?(?:top|self|parent)|window)\b`)
	frameLocationBuster = regexp.MustCompile(`\b(?:window\.)?(?:top|parent)\.location(?:\.href)?\s*!==?\s*(?:window\.)?(?:self|window)\.location(?:\.href)?\b`)
	bodyCloseTagRe      = regexp.MustCompile(`(?i)</body>`)
)

// ModemProxyTarget 描述目标光猫控制台端点。
type ModemProxyTarget struct {
	Scheme string `json:"scheme"`
	IP     string `json:"ip"`
	Port   int    `json:"port"`
}

// ModemProxySession 描述一次已激活的内嵌控制台反向代理会话。
type ModemProxySession struct {
	Running       bool   `json:"running"`
	Port          int    `json:"port"`
	Ticket        string `json:"ticket"`
	Target        string `json:"target"`
	ExpiresInSec  int    `json:"expiresInSec"`
	AutofillNonce string `json:"autofillNonce,omitempty"`
}

// ModemProxyStatus 描述反向代理监听状态。
type ModemProxyStatus struct {
	Running bool   `json:"running"`
	Port    int    `json:"port"`
	Target  string `json:"target"`
	IdleSec int    `json:"idleSec"`
}

// ModemProxyOptions 配置按需光猫反向代理管理器的安全策略与可测替身。
type ModemProxyOptions struct {
	IdleTimeout                time.Duration
	Authorizer                 func(*http.Request) bool
	AllowLoopbackTargetForTest bool
	Transport                  http.RoundTripper
	NowFunc                    func() time.Time
}

// ModemProxyManager 管理按需启停与闲置自动休眠的光猫管理面板反向代理服务。
type ModemProxyManager struct {
	opts ModemProxyOptions

	mu            sync.Mutex
	listener      net.Listener
	srv           *http.Server
	port          int
	target        ModemProxyTarget
	autofillNonce string
	tickets       map[string]time.Time
	cookieTokens  map[string]time.Time
	stopReaper    context.CancelFunc

	lastActivityUnix atomic.Int64
}

// NewModemProxyManager 创建光猫内嵌控制台反向代理管理器。
func NewModemProxyManager(opts ModemProxyOptions) *ModemProxyManager {
	if opts.IdleTimeout <= 0 {
		opts.IdleTimeout = defaultModemProxyIdleTimeout
	}
	if opts.NowFunc == nil {
		opts.NowFunc = time.Now
	}
	return &ModemProxyManager{
		opts:         opts,
		tickets:      make(map[string]time.Time),
		cookieTokens: make(map[string]time.Time),
	}
}

func (m *ModemProxyManager) validateTarget(raw ModemProxyTarget) (ModemProxyTarget, error) {
	scheme := strings.ToLower(strings.TrimSpace(raw.Scheme))
	if scheme == "" {
		scheme = "http"
	}
	if scheme != "http" && scheme != "https" {
		return ModemProxyTarget{}, fmt.Errorf("不支持的光猫访问协议 %q", raw.Scheme)
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(raw.IP))
	if err != nil || !addr.Is4() {
		return ModemProxyTarget{}, fmt.Errorf("无效的光猫 IPv4 地址 %q", raw.IP)
	}
	if addr.IsUnspecified() || addr.IsMulticast() || addr.String() == "255.255.255.255" {
		return ModemProxyTarget{}, fmt.Errorf("不允许代理到非单播地址 %q", raw.IP)
	}
	if !m.opts.AllowLoopbackTargetForTest && (!isRFC1918Private(addr) || addr.IsLoopback()) {
		return ModemProxyTarget{}, fmt.Errorf("仅允许反向代理到局域网私网光猫 IP (%s)", addr.String())
	}

	port := raw.Port
	if port <= 0 || port > 65535 {
		if scheme == "https" {
			port = 443
		} else {
			port = 80
		}
	}
	return ModemProxyTarget{Scheme: scheme, IP: addr.String(), Port: port}, nil
}

func formatTargetBaseURL(t ModemProxyTarget) string {
	return fmt.Sprintf("%s://%s:%d", t.Scheme, t.IP, t.Port)
}

func randomSecretToken(numBytes int) (string, error) {
	buf := make([]byte, numBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func listenModemProxyPort(preferredPort int) (net.Listener, int, error) {
	tryBind := func(port int) (net.Listener, int, error) {
		addr := fmt.Sprintf(":%d", port)
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			ln, err = net.Listen("tcp4", "0.0.0.0"+addr)
		}
		if err != nil {
			return nil, 0, err
		}
		tcpAddr, ok := ln.Addr().(*net.TCPAddr)
		if !ok {
			return ln, port, nil
		}
		return ln, tcpAddr.Port, nil
	}

	if preferredPort > 0 {
		for offset := range 9 {
			if ln, actual, err := tryBind(preferredPort + offset); err == nil {
				return ln, actual, nil
			}
		}
	}
	return tryBind(0)
}

// Open 按需开启或切换目标光猫并绑定监听端口，返回一次性登录换 Cookie 票据。
func (m *ModemProxyManager) Open(target ModemProxyTarget, preferredPort int) (ModemProxySession, error) {
	norm, err := m.validateTarget(target)
	if err != nil {
		return ModemProxySession{}, err
	}
	ticket, err := randomSecretToken(24)
	if err != nil {
		return ModemProxySession{}, err
	}

	now := m.opts.NowFunc()
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.listener == nil {
		portToBind := preferredPort
		if portToBind < 0 {
			portToBind = DefaultModemConsolePort
		}
		ln, actualPort, lErr := listenModemProxyPort(portToBind)
		if lErr != nil {
			return ModemProxySession{}, fmt.Errorf("绑定光猫控制台端口失败: %w", lErr)
		}
		srv := &http.Server{
			Handler:           m,
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       90 * time.Second,
		}
		reaperCtx, cancelReaper := context.WithCancel(context.Background())
		m.listener = ln
		m.srv = srv
		m.port = actualPort
		m.stopReaper = cancelReaper

		go func() {
			_ = srv.Serve(ln)
		}()
		go m.runIdleReaper(reaperCtx)
	}

	m.target = norm
	if m.autofillNonce == "" {
		nonce, nErr := randomSecretToken(16)
		if nErr != nil {
			return ModemProxySession{}, nErr
		}
		m.autofillNonce = nonce
	}
	nonce := m.autofillNonce
	m.pruneExpiredLocked(now)
	m.tickets[ticket] = now.Add(ticketTTL)
	m.lastActivityUnix.Store(now.UnixNano())

	return ModemProxySession{
		Running:       true,
		Port:          m.port,
		Ticket:        ticket,
		Target:        formatTargetBaseURL(norm),
		ExpiresInSec:  int(m.opts.IdleTimeout.Seconds()),
		AutofillNonce: nonce,
	}, nil
}

// Status 返回当前光猫反向代理监听与闲置时长状态。
func (m *ModemProxyManager) Status() ModemProxyStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.listener == nil {
		return ModemProxyStatus{}
	}
	lastUnix := m.lastActivityUnix.Load()
	idleSec := 0
	if lastUnix > 0 {
		elapsed := m.opts.NowFunc().Sub(time.Unix(0, lastUnix))
		if elapsed > 0 {
			idleSec = int(elapsed.Seconds())
		}
	}
	return ModemProxyStatus{
		Running: true,
		Port:    m.port,
		Target:  formatTargetBaseURL(m.target),
		IdleSec: idleSec,
	}
}

// Close 立即停止反向代理监听并清空临时票据会话。
func (m *ModemProxyManager) Close() error {
	m.mu.Lock()
	cancel := m.stopReaper
	srv := m.srv
	ln := m.listener
	m.stopReaper = nil
	m.srv = nil
	m.listener = nil
	m.port = 0
	m.autofillNonce = ""
	clear(m.tickets)
	clear(m.cookieTokens)
	m.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if srv != nil {
		shutCtx, shutCancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = srv.Shutdown(shutCtx)
		shutCancel()
	}
	if ln != nil {
		_ = ln.Close()
	}
	return nil
}

func (m *ModemProxyManager) pruneExpiredLocked(now time.Time) {
	for tok, exp := range m.tickets {
		if now.After(exp) {
			delete(m.tickets, tok)
		}
	}
	for tok, exp := range m.cookieTokens {
		if now.After(exp) {
			delete(m.cookieTokens, tok)
		}
	}
}

func (m *ModemProxyManager) runIdleReaper(ctx context.Context) {
	interval := m.opts.IdleTimeout / 3
	if interval < 20*time.Millisecond {
		interval = 20 * time.Millisecond
	}
	if interval > 30*time.Second {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			lastUnix := m.lastActivityUnix.Load()
			if lastUnix == 0 {
				continue
			}
			if m.opts.NowFunc().Sub(time.Unix(0, lastUnix)) >= m.opts.IdleTimeout {
				_ = m.Close()
				return
			}
		}
	}
}

func isAllowedProxyRemote(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(strings.TrimSpace(remoteAddr))
	if err != nil {
		host = strings.TrimSpace(remoteAddr)
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	if addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() {
		return true
	}
	return addr.Is4() && cgnatIPv4Prefix.Contains(addr)
}

func (m *ModemProxyManager) issueOrValidateAuth(w http.ResponseWriter, r *http.Request) (handledRedirect bool, authorized bool) {
	now := m.opts.NowFunc()
	q := r.URL.Query()
	ticket := strings.TrimSpace(q.Get(modemTicketQueryParam))

	if ticket != "" {
		m.mu.Lock()
		m.pruneExpiredLocked(now)
		exp, ok := m.tickets[ticket]
		if ok && !now.After(exp) {
			delete(m.tickets, ticket)
			sessTok, err := randomSecretToken(24)
			if err == nil {
				m.cookieTokens[sessTok] = now.Add(maxCookieLife(m.opts.IdleTimeout))
				m.mu.Unlock()
				http.SetCookie(w, &http.Cookie{
					Name:     modemAuthCookieName,
					Value:    sessTok,
					Path:     "/",
					HttpOnly: true,
					SameSite: http.SameSiteLaxMode,
				})
				q.Del(modemTicketQueryParam)
				cleanPath := r.URL.Path
				if cleanPath == "" {
					cleanPath = "/"
				}
				if enc := q.Encode(); enc != "" {
					cleanPath += "?" + enc
				}
				http.Redirect(w, r, cleanPath, http.StatusFound)
				return true, true
			}
		}
		m.mu.Unlock()
		return false, false
	}

	if c, err := r.Cookie(modemAuthCookieName); err == nil && c.Value != "" {
		m.mu.Lock()
		m.pruneExpiredLocked(now)
		for tok, exp := range m.cookieTokens {
			if !now.After(exp) && subtle.ConstantTimeCompare([]byte(c.Value), []byte(tok)) == 1 {
				m.cookieTokens[tok] = now.Add(maxCookieLife(m.opts.IdleTimeout))
				m.mu.Unlock()
				return false, true
			}
		}
		m.mu.Unlock()
	}

	if m.opts.Authorizer != nil && m.opts.Authorizer(r) {
		return false, true
	}
	return false, false
}

func maxCookieLife(idle time.Duration) time.Duration {
	if idle > 12*time.Hour {
		return idle
	}
	return 12 * time.Hour
}

func scrubModemCookies(r *http.Request) {
	rawCookies := r.Cookies()
	if len(rawCookies) == 0 {
		return
	}
	r.Header.Del("Cookie")
	var kept []string
	for _, c := range rawCookies {
		if c.Name == "singctl_session" || c.Name == modemAuthCookieName {
			continue
		}
		kept = append(kept, c.Name+"="+c.Value)
	}
	if len(kept) > 0 {
		r.Header.Set("Cookie", strings.Join(kept, "; "))
	}
}

func stripFrameAncestorsCSP(csp string) string {
	if strings.TrimSpace(csp) == "" {
		return ""
	}
	parts := strings.Split(csp, ";")
	var kept []string
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		lower := strings.ToLower(trimmed)
		if strings.HasPrefix(lower, "frame-ancestors") {
			continue
		}
		kept = append(kept, trimmed)
	}
	return strings.Join(kept, "; ")
}

func sanitizeSetCookieHeader(raw string) string {
	parts := strings.Split(raw, ";")
	var kept []string
	for i, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		if i > 0 {
			lower := strings.ToLower(trimmed)
			if lower == "secure" || strings.HasPrefix(lower, "domain=") {
				continue
			}
		}
		kept = append(kept, trimmed)
	}
	return strings.Join(kept, "; ")
}

// ServeHTTP 实现 http.Handler，执行来源白名单、会话鉴权并反向代理光猫请求。
func (m *ModemProxyManager) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !isAllowedProxyRemote(r.RemoteAddr) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	redirected, ok := m.issueOrValidateAuth(w, r)
	if redirected {
		return
	}
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	m.mu.Lock()
	target := m.target
	m.mu.Unlock()
	if target.IP == "" {
		http.Error(w, "modem proxy target not configured", http.StatusServiceUnavailable)
		return
	}

	m.lastActivityUnix.Store(m.opts.NowFunc().UnixNano())

	targetURL, err := url.Parse(formatTargetBaseURL(target))
	if err != nil {
		http.Error(w, "invalid target", http.StatusBadGateway)
		return
	}

	tr := m.opts.Transport
	if tr == nil {
		tr = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	rp := &httputil.ReverseProxy{
		Transport: tr,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(targetURL)
			pr.Out.Host = targetURL.Host
			if pr.In.Header.Get("Origin") != "" {
				pr.Out.Header.Set("Origin", targetURL.Scheme+"://"+targetURL.Host)
			}
			if ref := pr.In.Header.Get("Referer"); ref != "" {
				if refURL, rErr := url.Parse(ref); rErr == nil {
					refURL.Scheme = targetURL.Scheme
					refURL.Host = targetURL.Host
					pr.Out.Header.Set("Referer", refURL.String())
				} else {
					pr.Out.Header.Set("Referer", targetURL.Scheme+"://"+targetURL.Host+"/")
				}
			}
			scrubModemCookies(pr.Out)
			pr.Out.Header.Del("Accept-Encoding")
		},
		ModifyResponse: func(resp *http.Response) error {
			resp.Header.Del("X-Frame-Options")
			for _, cspHdr := range []string{"Content-Security-Policy", "Content-Security-Policy-Report-Only"} {
				if v := resp.Header.Get(cspHdr); v != "" {
					cleaned := stripFrameAncestorsCSP(v)
					if cleaned == "" {
						resp.Header.Del(cspHdr)
					} else {
						resp.Header.Set(cspHdr, cleaned)
					}
				}
			}
			if rawCookies := resp.Header.Values("Set-Cookie"); len(rawCookies) > 0 {
				resp.Header.Del("Set-Cookie")
				for _, sc := range rawCookies {
					if cleaned := sanitizeSetCookieHeader(sc); cleaned != "" {
						resp.Header.Add("Set-Cookie", cleaned)
					}
				}
			}
			if loc := resp.Header.Get("Location"); loc != "" {
				if locURL, lErr := url.Parse(loc); lErr == nil && locURL.IsAbs() && locURL.Hostname() == target.IP {
					if strings.EqualFold(locURL.Scheme, "https") && target.Scheme == "http" {
						newPort := 443
						if pStr := locURL.Port(); pStr != "" {
							if pNum, pErr := strconv.Atoi(pStr); pErr == nil && pNum > 0 {
								newPort = pNum
							}
						}
						m.mu.Lock()
						m.target.Scheme = "https"
						m.target.Port = newPort
						m.mu.Unlock()
					}
					rel := cmp.Or(locURL.EscapedPath(), "/")
					if locURL.RawQuery != "" {
						rel += "?" + locURL.RawQuery
					}
					if locURL.Fragment != "" {
						rel += "#" + locURL.Fragment
					}
					resp.Header.Set("Location", rel)
				}
			}
			if resp.Request == nil || resp.Request.Method != http.MethodHead {
				m.mu.Lock()
				nonce := m.autofillNonce
				m.mu.Unlock()
				if err := rewriteModemProxyResponse(resp, nonce); err != nil {
					return err
				}
			}
			return nil
		},
		ErrorHandler: func(rw http.ResponseWriter, _ *http.Request, pErr error) {
			http.Error(rw, fmt.Sprintf("光猫反向代理连接失败 (%s): %v", formatTargetBaseURL(target), pErr), http.StatusBadGateway)
		},
	}

	rp.ServeHTTP(w, r)
}

type readCloser struct {
	io.Reader
	io.Closer
}

func rewriteModemProxyResponse(resp *http.Response, nonce string) error {
	if resp == nil || resp.Body == nil || resp.StatusCode == http.StatusNotModified {
		return nil
	}
	if strings.TrimSpace(resp.Header.Get("Content-Encoding")) != "" {
		return nil
	}
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	isHTML := strings.Contains(ct, "text/html") || strings.Contains(ct, "application/xhtml")
	isJS := strings.Contains(ct, "javascript") || strings.Contains(ct, "ecmascript")
	if !isHTML && !isJS {
		return nil
	}

	origBody := resp.Body
	buf, err := io.ReadAll(io.LimitReader(origBody, maxModemProxyRewriteBytes+1))
	if err != nil {
		return err
	}
	if len(buf) > maxModemProxyRewriteBytes {
		resp.Body = readCloser{Reader: io.MultiReader(bytes.NewReader(buf), origBody), Closer: origBody}
		return nil
	}
	_ = origBody.Close()

	// Neutralize common JS framebusters while preserving byte encodings such as GBK outside helper tail.
	rewritten := frameLocationBuster.ReplaceAll(buf, []byte("false"))
	rewritten = frameBusterRe.ReplaceAll(rewritten, []byte("false"))

	if isHTML && nonce != "" {
		helper := []byte(buildModemAutofillScript(nonce))
		if loc := bodyCloseTagRe.FindIndex(rewritten); loc != nil {
			out := make([]byte, 0, len(rewritten)+len(helper))
			out = append(out, rewritten[:loc[0]]...)
			out = append(out, helper...)
			out = append(out, rewritten[loc[0]:]...)
			rewritten = out
		} else {
			rewritten = append(rewritten, helper...)
		}
	}

	resp.Body = io.NopCloser(bytes.NewReader(rewritten))
	resp.ContentLength = int64(len(rewritten))
	resp.Header.Set("Content-Length", strconv.Itoa(len(rewritten)))
	resp.Header.Del("Transfer-Encoding")
	resp.Header.Del("ETag")
	return nil
}

func buildModemAutofillScript(nonce string) string {
	// Pure 7-bit ASCII script so ISO-8859-1/GBK modem pages never corrupt scripts or DOM text.
	return `<script data-sc-modem-helper="1">(function(){var NONCE="` + nonce + `";if(window.__scModemHelperInstalled){return;}window.__scModemHelperInstalled=true;function isVis(el){if(!el||el.disabled){return false;}var s=window.getComputedStyle?getComputedStyle(el):null;if(s&&(s.display==="none"||s.visibility==="hidden")){return false;}return el.offsetParent!==null||(el.getClientRects&&el.getClientRects().length>0);}function findField(sels){for(var i=0;i<sels.length;i++){var list=document.querySelectorAll(sels[i]);for(var j=0;j<list.length;j++){if(isVis(list[j])){return list[j];}}}for(var i=0;i<sels.length;i++){var el=document.querySelector(sels[i]);if(el&&!el.disabled){return el;}}return null;}function setVal(el,val){if(!el){return;}try{var proto=window.HTMLInputElement&&window.HTMLInputElement.prototype;var desc=proto&&Object.getOwnPropertyDescriptor(proto,"value");if(desc&&desc.set){desc.set.call(el,val);}else{el.value=val;}}catch(e){el.value=val;}try{el.dispatchEvent(new Event("input",{bubbles:true}));}catch(e){}try{el.dispatchEvent(new Event("change",{bubbles:true}));}catch(e){}}function reply(status){try{if(window.parent&&window.parent!==window){window.parent.postMessage({type:"sc_modem_autofill_ack",nonce:NONCE,status:status},"*");}}catch(e){}}function tryFill(u,p,autoSubmit,attempt){var pEl=findField(["#psd1","#psd2","#login_password","#txt_Password","#Frm_Password","#password","#passwd","#user_password","input[type='password']"]);var uEl=findField(["#username1","#username2","#login_username","#txt_Username","#Frm_Username","#username","#user_name","input[name='username']","input[name='Username']","input[type='text']"]);if(!pEl){if(attempt<12){setTimeout(function(){tryFill(u,p,autoSubmit,attempt+1);},220);return;}reply("not_found");return;}if(uEl){setVal(uEl,u);}setVal(pEl,p);var capEl=findField(["input[name*='captcha' i]","input[id*='captcha' i]","input[name*='verif' i]","input[id*='verif' i]","input[name*='checkcode' i]","input[id*='checkcode' i]","input[name*='authcode' i]","input[id*='authcode' i]","input[name*='randcode' i]","input[id*='randcode' i]","input[name*='yzm' i]","input[id*='yzm' i]"]);if(capEl){try{capEl.focus();}catch(e){}reply("captcha_required");return;}if(autoSubmit){if(typeof window.on_submit==="function"&&(document.getElementById("psd1")||document.getElementById("psd2"))){try{window.on_submit();reply("submitted");return;}catch(e){}}if(typeof window.SubmitForm==="function"){try{window.SubmitForm();reply("submitted");return;}catch(e){}}var btn=findField(["#LoginId","#login_submit","#btnLogin","#submit","#loginBtn","button[type='submit']","input[type='submit']","input[type='button'][onclick*='submit' i]"]);if(btn){try{btn.click();reply("submitted");return;}catch(e){}}if(pEl.form){try{if(typeof pEl.form.onsubmit==="function"&&pEl.form.onsubmit()===false){reply("filled");return;}pEl.form.submit();reply("submitted");return;}catch(e){}}}reply("filled");}window.addEventListener("message",function(ev){var d=ev&&ev.data;if(!d||d.type!=="sc_modem_autofill"||d.nonce!==NONCE){return;}tryFill(String(d.username||""),String(d.password||""),Boolean(d.autoSubmit),0);});})();</script>`
}
