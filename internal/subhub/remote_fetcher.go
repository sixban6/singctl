// 文件职责：负责 SubHub 远程订阅源的安全拉取（SSRF 过滤 + Redirect 复验）、UA/出口代理（Direct / WARP）自适应重试以及本地缓存持久化。
//
// 架构设计原则：
//   - 安全纵深防御（Defense in Depth）：不仅在 URL 解析阶段拒绝内网/CGNAT/回环地址，还在 net.Dialer.Control 连接瞬间复核解析后的真实 IP，并限制最大响应体积（8MiB）。
//   - 降级弹性：远程拉取失败时若允许使用陈旧缓存且缓存存在有效节点，则优雅降级避免订阅刷新雪崩；缓存文件采用 WriteAtomic0600 落盘。
package subhub

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"singctl/internal/util/file"
)

type remoteFetchJob struct {
	name       string
	url        string
	uaStrategy string
	proxyMode  string
}

func normalizeProxyMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "direct":
		return "direct"
	case "warp":
		return "warp"
	default:
		return "auto"
	}
}

func subFetchOptions(sub map[string]any) (uaStrategy string, proxyMode string) {
	ua, _ := sub["userAgent"].(string)
	ua = strings.TrimSpace(ua)
	if ua == "" {
		if legacyUA, _ := sub["ua"].(string); strings.TrimSpace(legacyUA) != "" {
			// Ignore legacy browser User-Agents that trigger anti-bot HTTP 418/403 blocks
			if !strings.Contains(strings.ToLower(legacyUA), "mozilla/") {
				ua = strings.TrimSpace(legacyUA)
			}
		}
	}
	if ua == "" {
		ua = "auto"
	}
	pm, _ := sub["proxyMode"].(string)
	return ua, normalizeProxyMode(pm)
}

// WarmupUncachedSources fetches any enabled remote subscription sources that lack a valid cached payload,
// skipping URLs attempted within the last 60 seconds so dashboard loads never stall repeatedly on dead links.
func (s *Store) WarmupUncachedSources(ctx context.Context) {
	s.mu.Lock()
	doc, err := s.readDocLocked()
	var jobs []remoteFetchJob
	if err == nil {
		s.reloadRemoteCacheLocked()
		rawSubs, _ := doc["subs"].([]any)
		now := time.Now()
		for _, entry := range rawSubs {
			sub, ok := entry.(map[string]any)
			if !ok || !subEnabled(sub) {
				continue
			}
			srcType, _ := sub["source"].(string)
			rawURL, _ := sub["url"].(string)
			rawURL = strings.TrimSpace(rawURL)
			if rawURL == "" || (srcType != "" && srcType != "remote") {
				continue
			}
			if cached, ok := s.remoteCache[rawURL]; ok && cached.Body != "" {
				nodes, uris := ParseRawSubscriptionPayload(ctx, []byte(cached.Body))
				if len(nodes) > 0 || len(uris) > 0 {
					continue
				}
			}
			if lastTry, ok := s.lastAttempt[rawURL]; ok && now.Sub(lastTry) < 60*time.Second {
				continue
			}
			ua, pm := subFetchOptions(sub)
			n, _ := sub["name"].(string)
			jobs = append(jobs, remoteFetchJob{name: n, url: rawURL, uaStrategy: ua, proxyMode: pm})
		}
	}
	s.mu.Unlock()

	if len(jobs) == 0 {
		return
	}

	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for _, job := range jobs {
		wg.Add(1)
		go func(j remoteFetchJob) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			_, _ = s.fetchRemoteAdaptive(ctx, j.url, j.uaStrategy, j.proxyMode, true)
		}(job)
	}
	wg.Wait()
}

// RefreshSources force-refreshes a specific named remote source (or all enabled remote sources when targetName is empty)
// and returns the updated source list.
func (s *Store) RefreshSources(ctx context.Context, targetName string) ([]SourceItem, error) {
	targetName = strings.TrimSpace(targetName)

	s.mu.Lock()
	doc, err := s.readDocLocked()
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}

	rawSubs, _ := doc["subs"].([]any)
	var jobs []remoteFetchJob
	for _, entry := range rawSubs {
		sub, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		n, _ := sub["name"].(string)
		if targetName != "" && n != targetName {
			continue
		}
		if targetName == "" && !subEnabled(sub) {
			continue
		}
		srcType, _ := sub["source"].(string)
		rawURL, _ := sub["url"].(string)
		rawURL = strings.TrimSpace(rawURL)
		if rawURL == "" || (srcType != "" && srcType != "remote") {
			continue
		}
		ua, pm := subFetchOptions(sub)
		jobs = append(jobs, remoteFetchJob{name: n, url: rawURL, uaStrategy: ua, proxyMode: pm})
	}

	if targetName != "" && len(jobs) == 0 {
		return nil, fmt.Errorf("未找到可刷新的远程订阅源 %q", targetName)
	}

	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	var errMu sync.Mutex
	var errs []error
	for _, job := range jobs {
		wg.Add(1)
		go func(j remoteFetchJob) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				errMu.Lock()
				errs = append(errs, ctx.Err())
				errMu.Unlock()
				return
			}
			if _, fErr := s.fetchRemoteAdaptive(ctx, j.url, j.uaStrategy, j.proxyMode, true); fErr != nil {
				errMu.Lock()
				errs = append(errs, fmt.Errorf("%s: %w", j.name, fErr))
				errMu.Unlock()
			}
		}(job)
	}
	wg.Wait()

	items, listErr := s.ListSources()
	if listErr != nil {
		return nil, listErr
	}
	if targetName != "" && len(errs) > 0 {
		return items, errs[0]
	}
	return items, errors.Join(errs...)
}

func (s *Store) existingSubFetchOptions(name string) (string, string) {
	if name == "" {
		return "auto", "auto"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	doc, err := s.readDocLocked()
	if err != nil {
		return "auto", "auto"
	}
	rawSubs, _ := doc["subs"].([]any)
	for _, entry := range rawSubs {
		if m, ok := entry.(map[string]any); ok {
			if n, _ := m["name"].(string); n == name {
				return subFetchOptions(m)
			}
		}
	}
	return "auto", "auto"
}

func (s *Store) validateRemoteURL(rawURL string) error {
	if rawURL == "" {
		return errors.New("远程订阅 URL 不能为空")
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("无效的订阅 URL: %w", err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return errors.New("远程订阅仅支持 http:// 或 https:// 协议")
	}
	host := strings.TrimSpace(u.Hostname())
	if host == "" {
		return errors.New("远程订阅 URL 缺少主机名")
	}
	if !s.AllowLoopbackRemote {
		cleanHost := strings.TrimSuffix(strings.ToLower(host), ".")
		if cleanHost == "localhost" || strings.HasSuffix(cleanHost, ".localhost") {
			return errors.New("安全策略禁止拉取本机回环地址 (localhost)")
		}
		if addr, err := netip.ParseAddr(host); err == nil && isBlockedRemoteAddr(addr) {
			return fmt.Errorf("安全策略禁止拉取私网或回环地址 (%s)", host)
		}
	}
	return nil
}

func isBlockedRemoteAddr(addr netip.Addr) bool {
	addr = addr.Unmap()
	if addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsMulticast() || addr.IsUnspecified() {
		return true
	}
	// Block CGNAT / Tailscale 100.64.0.0/10
	if cgnat, err := netip.ParsePrefix("100.64.0.0/10"); err == nil && cgnat.Contains(addr) {
		return true
	}
	return false
}

func (s *Store) newSafeHTTPClient() *http.Client {
	timeout := cmp.Or(s.HTTPTimeout, 12*time.Second)
	dialer := &net.Dialer{
		Timeout:   8 * time.Second,
		KeepAlive: 15 * time.Second,
	}
	if !s.AllowLoopbackRemote {
		dialer.Control = func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			addr, err := netip.ParseAddr(host)
			if err != nil {
				return err
			}
			if isBlockedRemoteAddr(addr) {
				return fmt.Errorf("blocked SSRF connection to non-public IP %s", addr)
			}
			return nil
		}
	}

	transport := &http.Transport{
		DialContext:           dialer.DialContext,
		TLSHandshakeTimeout:   8 * time.Second,
		ResponseHeaderTimeout: timeout,
		MaxIdleConns:          10,
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			return s.validateRemoteURL(req.URL.String())
		},
	}
}

func (s *Store) newWarpHTTPClient() *http.Client {
	timeout := cmp.Or(s.HTTPTimeout, 12*time.Second)
	warpAddr := cmp.Or(strings.TrimSpace(s.WarpProxyAddr), DefaultWarpProxyAddr)
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			return dialSOCKS5Context(ctx, warpAddr, addr, s.AllowLoopbackRemote)
		},
		TLSHandshakeTimeout:   8 * time.Second,
		ResponseHeaderTimeout: timeout,
		MaxIdleConns:          4,
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			return s.validateRemoteURL(req.URL.String())
		},
	}
}

func buildUACandidates(strategy, lastWinningUA string) []string {
	raw := strings.TrimSpace(strategy)
	switch strings.ToLower(raw) {
	case "", "auto":
		var out []string
		if w := strings.TrimSpace(lastWinningUA); w != "" && !strings.HasPrefix(strings.ToLower(w), "singctl-subhub/") {
			out = append(out, w)
		}
		for _, preset := range []string{UAV2rayNG, UAShadowrocket, UAClashMeta, UASingBox} {
			if !slices.Contains(out, preset) {
				out = append(out, preset)
			}
		}
		return out
	case "v2rayng":
		return []string{UAV2rayNG}
	case "shadowrocket":
		return []string{UAShadowrocket}
	case "clash", "clashmeta", "clash.meta", "mihomo":
		return []string{UAClashMeta}
	case "singbox", "sing-box", "sfa", "sfi":
		return []string{UASingBox}
	default:
		return []string{raw}
	}
}

func shortUALabel(ua string) string {
	lower := strings.ToLower(ua)
	switch {
	case strings.Contains(lower, "v2rayng"):
		return "v2rayNG"
	case strings.Contains(lower, "shadowrocket"):
		return "Shadowrocket"
	case strings.Contains(lower, "clash") || strings.Contains(lower, "mihomo"):
		return "Clash.Meta"
	case strings.Contains(lower, "sing-box") || strings.Contains(lower, "sfa/") || strings.Contains(lower, "sfi/"):
		return "Sing-box"
	default:
		runes := []rune(ua)
		if len(runes) > 28 {
			return string(runes[:28]) + "..."
		}
		return ua
	}
}

func (s *Store) buildEgressChannels(proxyMode, lastUsedProxy string) ([]string, error) {
	warpAddr := cmp.Or(strings.TrimSpace(s.WarpProxyAddr), DefaultWarpProxyAddr)
	switch normalizeProxyMode(proxyMode) {
	case "direct":
		return []string{"direct"}, nil
	case "warp":
		if !isTCPPortListening(warpAddr, 400*time.Millisecond) {
			return nil, fmt.Errorf("本机 WARP SOCKS5 通道 (%s) 未运行或不可达", warpAddr)
		}
		return []string{"warp"}, nil
	default:
		warpReady := isTCPPortListening(warpAddr, 300*time.Millisecond)
		if !warpReady {
			return []string{"direct"}, nil
		}
		if lastUsedProxy == "warp" {
			return []string{"warp", "direct"}, nil
		}
		return []string{"direct", "warp"}, nil
	}
}

func (s *Store) fetchRemoteAdaptive(ctx context.Context, rawURL, uaStrategy, proxyMode string, forceRefresh bool) (string, error) {
	if err := s.validateRemoteURL(rawURL); err != nil {
		return "", err
	}

	ttl := cmp.Or(s.CacheTTL, 10*time.Minute)
	s.mu.Lock()
	s.reloadRemoteCacheLocked()
	cached, hasCached := s.remoteCache[rawURL]
	s.mu.Unlock()

	if !forceRefresh && hasCached && cached.Body != "" && time.Since(cached.FetchedAt) < ttl {
		nodes, uris := ParseRawSubscriptionPayload(ctx, []byte(cached.Body))
		if len(nodes) > 0 || len(uris) > 0 {
			return cached.Body, nil
		}
	}

	channels, chanErr := s.buildEgressChannels(proxyMode, cached.UsedProxy)
	if chanErr != nil {
		s.recordRemoteFailure(rawURL, cached, hasCached, chanErr.Error())
		if !forceRefresh && hasCached && cached.Body != "" {
			return cached.Body, nil
		}
		return "", chanErr
	}

	uaCandidates := buildUACandidates(uaStrategy, cached.EffectiveUA)
	perAttemptTimeout := min(cmp.Or(s.HTTPTimeout, 12*time.Second), 8*time.Second)

	var lastErr error
	for _, channel := range channels {
		var client *http.Client
		if channel == "warp" {
			client = s.newWarpHTTPClient()
		} else {
			client = s.newSafeHTTPClient()
		}

		for _, ua := range uaCandidates {
			if ctx.Err() != nil {
				lastErr = ctx.Err()
				break
			}

			reqCtx, cancel := context.WithTimeout(ctx, perAttemptTimeout)
			req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, rawURL, nil)
			if err != nil {
				cancel()
				lastErr = err
				break
			}
			req.Header.Set("User-Agent", ua)
			req.Header.Set("Accept", "*/*")

			resp, err := client.Do(req)
			if err != nil {
				cancel()
				lastErr = fmt.Errorf("[%s/%s] %w", channel, shortUALabel(ua), err)
				// 传输层或握手失败说明当前出口通道不通，更换 UA 无法恢复，直接切换下一个出口通道
				break
			}

			rawBytes, readErr := io.ReadAll(io.LimitReader(resp.Body, maxRemoteSubBytes))
			_ = resp.Body.Close()
			cancel()

			if resp.StatusCode != http.StatusOK {
				lastErr = fmt.Errorf("HTTP %d (%s / %s)", resp.StatusCode, channel, shortUALabel(ua))
				continue
			}
			if readErr != nil {
				lastErr = fmt.Errorf("[%s/%s] %w", channel, shortUALabel(ua), readErr)
				continue
			}

			body := strings.TrimSpace(string(rawBytes))
			if body == "" {
				lastErr = fmt.Errorf("响应内容为空 (%s / %s)", channel, shortUALabel(ua))
				continue
			}

			nodes, uris := ParseRawSubscriptionPayload(ctx, []byte(body))
			if len(nodes) == 0 && len(uris) == 0 {
				lastErr = fmt.Errorf("HTTP 200 但未解析出有效节点 (%s / %s，疑似反爬拦截或空订阅)", channel, shortUALabel(ua))
				continue
			}

			s.mu.Lock()
			s.lastAttempt[rawURL] = time.Now()
			s.remoteCache[rawURL] = remoteCacheEntry{
				URL:         rawURL,
				Body:        body,
				FetchedAt:   time.Now(),
				EffectiveUA: ua,
				UsedProxy:   channel,
				LastError:   "",
			}
			s.saveRemoteCacheLocked()
			s.mu.Unlock()
			return body, nil
		}
		if ctx.Err() != nil {
			break
		}
	}

	if lastErr == nil {
		lastErr = errors.New("远程订阅拉取失败")
	}
	s.recordRemoteFailure(rawURL, cached, hasCached, lastErr.Error())

	if !forceRefresh && hasCached && cached.Body != "" {
		nodes, uris := ParseRawSubscriptionPayload(ctx, []byte(cached.Body))
		if len(nodes) > 0 || len(uris) > 0 {
			return cached.Body, nil
		}
	}
	return "", lastErr
}

func (s *Store) recordRemoteFailure(rawURL string, prev remoteCacheEntry, hasPrev bool, errMsg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastAttempt[rawURL] = time.Now()
	entry := remoteCacheEntry{
		URL:       rawURL,
		LastError: errMsg,
	}
	if hasPrev {
		entry.Body = prev.Body
		entry.FetchedAt = prev.FetchedAt
		entry.EffectiveUA = prev.EffectiveUA
		entry.UsedProxy = prev.UsedProxy
	}
	s.remoteCache[rawURL] = entry
	s.saveRemoteCacheLocked()
}

func (s *Store) loadRemoteCacheFromDisk() {
	s.reloadRemoteCacheLocked()
}

func (s *Store) reloadRemoteCacheLocked() {
	p := s.remoteCachePath()
	st, err := os.Stat(p)
	if err != nil {
		return
	}
	if !s.remoteCacheMtime.IsZero() && st.ModTime().Equal(s.remoteCacheMtime) {
		return
	}
	raw, err := os.ReadFile(p)
	if err != nil || len(raw) == 0 {
		return
	}
	var entries map[string]remoteCacheEntry
	if err := json.Unmarshal(raw, &entries); err == nil && entries != nil {
		s.remoteCache = entries
		s.remoteCacheMtime = st.ModTime()
	}
}

func (s *Store) saveRemoteCacheLocked() {
	if s.DataDir == "" {
		return
	}
	_ = os.MkdirAll(s.DataDir, 0700)
	p := s.remoteCachePath()
	b, err := json.Marshal(s.remoteCache)
	if err != nil {
		return
	}
	if err := file.WriteAtomic0600(p, b); err == nil {
		if st, stErr := os.Stat(p); stErr == nil {
			s.remoteCacheMtime = st.ModTime()
		}
	}
}
