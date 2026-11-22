// 文件职责：提供 Clash API 节点延迟测速、SSRF 安全探测地址校验、DNS 探活与出站链路解析。
package clashapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ValidateProbeURL 校验延迟测速目标 URL，拦截内网/回环/链路本地/认证凭据等 SSRF 风险地址。
func ValidateProbeURL(raw string) error {
	parsed, err := url.ParseRequestURI(raw)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return errors.New("测速 URL 必须为合法的 http/https 地址")
	}
	if parsed.User != nil {
		return errors.New("测速 URL 不允许包含认证凭据")
	}
	host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(parsed.Hostname()), "."))
	if host == "" {
		return errors.New("测速 URL 缺少合法主机名")
	}
	if host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") {
		return errors.New("出于安全策略禁止测速本机或内网保留域名")
	}
	if ip := net.ParseIP(host); ip != nil && isBlockedProbeIP(ip) {
		return errors.New("出于安全策略禁止测速回环、内网或链路本地 IP 地址")
	}
	return nil
}

func isBlockedProbeIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		if ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 {
			return true
		}
		if ip4[0] == 0 || (ip4[0] == 198 && (ip4[1] == 18 || ip4[1] == 19)) {
			return true
		}
	}
	return false
}

// ProbeDelayAt 对单个代理节点执行延迟探测（GET /proxies/{target}/delay），成功返回正整数毫秒数。
func (c *Client) ProbeDelayAt(ctx context.Context, baseURL, secret, target, testURL string, timeoutMs int) (int, error) {
	base := NormalizeBaseURL(baseURL)
	if base == "" {
		return 0, ErrUnreachable
	}
	if strings.TrimSpace(testURL) == "" {
		testURL = DefaultDelayProbeURL
	}
	if timeoutMs <= 0 {
		timeoutMs = DefaultDelayTimeoutMs
	}
	reqURL := fmt.Sprintf("%s/proxies/%s/delay?url=%s&timeout=%d",
		base,
		url.PathEscape(target),
		url.QueryEscape(testURL),
		timeoutMs,
	)
	reqCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutMs+700)*time.Millisecond)
	defer cancel()

	code, raw, err := doJSONRequest(reqCtx, c.streamingClient(), http.MethodGet, reqURL, secret, nil)
	if err != nil {
		return 0, err
	}
	if code != http.StatusOK {
		return 0, &StatusError{StatusCode: code, Body: strings.TrimSpace(string(raw))}
	}
	var res struct {
		Delay int `json:"delay"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return 0, &DecodeError{Cause: err}
	}
	if res.Delay <= 0 {
		return 0, errors.New("non-positive delay")
	}
	return res.Delay, nil
}

// ProbeDelaysBatchAt 使用有界并发工作池批量探测多个节点的延迟（不可达节点记为 0）。
func (c *Client) ProbeDelaysBatchAt(ctx context.Context, baseURL, secret string, targets []string, testURL string, timeoutMs, concurrency int) map[string]int {
	delays := make(map[string]int, len(targets))
	if len(targets) == 0 {
		return delays
	}
	if concurrency <= 0 {
		concurrency = DefaultDelayConcurrency
	}
	workers := min(concurrency, len(targets))
	jobs := make(chan string, len(targets))
	for _, t := range targets {
		jobs <- t
	}
	close(jobs)

	var mu sync.Mutex
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			for targetName := range jobs {
				if ctx.Err() != nil {
					return
				}
				d, err := c.ProbeDelayAt(ctx, baseURL, secret, targetName, testURL, timeoutMs)
				if err != nil || d <= 0 {
					d = 0
				}
				mu.Lock()
				delays[targetName] = d
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	return delays
}

type dnsQueryResponse struct {
	Status int `json:"Status"`
	Answer []struct {
		Name string `json:"Name"`
		Type int    `json:"Type"`
		TTL  int    `json:"TTL"`
		Data string `json:"data"`
	} `json:"Answer"`
}

// QueryDNSAcross 对候选 Clash API 端点依次发起内部 DNS A 记录探测并返回耗时毫秒与诊断详情。
func (c *Client) QueryDNSAcross(ctx context.Context, endpoints []string, secret string, domains []string) (ok bool, latencyMs int, detail string) {
	if len(domains) == 0 {
		domains = []string{"cn.bing.com", "www.google.com"}
	}
	var lastErr string

	for _, rawBase := range endpoints {
		base := NormalizeBaseURL(rawBase)
		if base == "" {
			continue
		}
		for _, domain := range domains {
			reqURL := fmt.Sprintf("%s/dns/query?name=%s&type=A", base, url.QueryEscape(domain))
			qCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			req, err := http.NewRequestWithContext(qCtx, http.MethodGet, reqURL, nil)
			if err != nil {
				cancel()
				lastErr = fmt.Sprintf("%s: %v", domain, err)
				continue
			}
			if secret != "" {
				req.Header.Set("Authorization", "Bearer "+secret)
			}

			t0 := time.Now()
			resp, err := c.streamingClient().Do(req)
			if err != nil {
				cancel()
				lastErr = fmt.Sprintf("%s: %v", domain, err)
				continue
			}

			if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
				_ = resp.Body.Close()
				cancel()
				lastErr = fmt.Sprintf("%s: clash API auth rejected (HTTP %d)", domain, resp.StatusCode)
				continue
			}

			var dnsResp dnsQueryResponse
			decErr := json.NewDecoder(resp.Body).Decode(&dnsResp)
			_ = resp.Body.Close()
			cancel()
			if decErr != nil {
				lastErr = fmt.Sprintf("%s: failed to decode response: %v", domain, decErr)
				continue
			}

			for _, answer := range dnsResp.Answer {
				if answer.Type == 1 && answer.Data != "" {
					ms := max(1, int(time.Since(t0).Milliseconds()))
					return true, ms, fmt.Sprintf("DNS 正常: %s → %s (%dms)", domain, answer.Data, ms)
				}
			}
			lastErr = fmt.Sprintf("%s: no A record in response (status=%d, answers=%d)", domain, dnsResp.Status, len(dnsResp.Answer))
		}
	}

	return false, 0, fmt.Sprintf("sing-box DNS handler may be stuck: %s (tried %v)", lastErr, endpoints)
}

// IsProxyGroupType 判断 Clash 条目类型是否为策略组（Selector / URLTest / Fallback / LoadBalance）。
func IsProxyGroupType(typ string) bool {
	switch strings.ToLower(strings.TrimSpace(typ)) {
	case "selector", "urltest", "fallback", "loadbalance":
		return true
	default:
		return false
	}
}

// CanonicalGroupType 将策略组类型归一化为标准大小写形式。
func CanonicalGroupType(typ string) string {
	switch strings.ToLower(strings.TrimSpace(typ)) {
	case "selector":
		return "Selector"
	case "urltest":
		return "URLTest"
	case "fallback":
		return "Fallback"
	case "loadbalance":
		return "LoadBalance"
	default:
		return typ
	}
}

// LatestProxyDelay 提取节点最近一次测速延迟及是否已有历史记录。
func LatestProxyDelay(item ProxyItem) (int, bool) {
	if len(item.History) == 0 {
		return 0, false
	}
	last := item.History[len(item.History)-1]
	if last.Delay > 0 {
		return last.Delay, true
	}
	return 0, true
}

// ResolveOutboundChain 沿策略组的 Now 引用链向下解析最终落地的叶子节点及有效延迟（带环路保护）。
func ResolveOutboundChain(proxies map[string]ProxyItem, initialNow string) (chain []string, leaf string, delay int) {
	cur := strings.TrimSpace(initialNow)
	if cur == "" {
		return nil, "", 0
	}
	seen := make(map[string]bool, 8)
	for range 8 {
		if cur == "" || seen[cur] {
			break
		}
		seen[cur] = true
		chain = append(chain, cur)

		item, ok := proxies[cur]
		if !ok || !IsProxyGroupType(item.Type) {
			leaf = cur
			break
		}
		next := strings.TrimSpace(item.Now)
		if next == "" {
			leaf = cur
			break
		}
		cur = next
	}
	if leaf == "" && len(chain) > 0 {
		leaf = chain[len(chain)-1]
	}
	if leaf != "" {
		if d, ok := LatestProxyDelay(proxies[leaf]); ok && d > 0 {
			delay = d
		}
	}
	if delay == 0 {
		for i := len(chain) - 1; i >= 0; i-- {
			if d, ok := LatestProxyDelay(proxies[chain[i]]); ok && d > 0 {
				delay = d
				break
			}
		}
	}
	return chain, leaf, delay
}
