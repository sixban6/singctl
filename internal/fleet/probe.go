package fleet

import (
	"cmp"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DefaultPatrolInterval is the default low-frequency background HTTPS probe cadence.
const DefaultPatrolInterval = 3 * time.Minute

// ProbeResult captures the outcome of a zero-SSH-log HTTPS :443 health check on a worker node.
type ProbeResult struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Online       bool   `json:"online"`
	Skipped      bool   `json:"skipped,omitempty"`
	LatencyMs    int    `json:"latencyMs"`
	HTTPStatus   int    `json:"httpStatus,omitempty"`
	CertDaysLeft int    `json:"certDaysLeft,omitempty"`
	ProbeStatus  string `json:"probeStatus"` // "https_ok" | "cert_expiring" | "tls_ip_ok" | "unreachable" | "skipped"
	CheckedAt    string `json:"checkedAt"`
	Message      string `json:"message"`
}

// HTTPSProberFunc probes a fleet node's public :443 HTTPS gateway without opening an SSH session.
type HTTPSProberFunc func(ctx context.Context, node Node) ProbeResult

// DefaultHTTPSProber performs a lightweight TCP + TLS handshake + HTTP HEAD check against the node's :443 camouflage gateway.
func DefaultHTTPSProber(ctx context.Context, node Node) ProbeResult {
	nowStr := time.Now().Format(time.RFC3339)
	sniHost := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(node.Domain)), ".")
	rawHost := strings.TrimSpace(node.Host)

	targetPort := 443
	if node.NodePort > 0 && node.NodePort <= 65535 {
		targetPort = node.NodePort
	}
	dialAddr := ""
	if h, p, err := net.SplitHostPort(rawHost); err == nil && h != "" && p != "" {
		dialAddr = net.JoinHostPort(h, p)
		if pNum, pErr := strconv.Atoi(p); pErr == nil && pNum > 0 && pNum <= 65535 {
			targetPort = pNum
		}
		if sniHost == "" && net.ParseIP(h) == nil {
			sniHost = strings.ToLower(h)
		}
	} else {
		dialHost := rawHost
		if dialHost == "" || (node.AuthType == AuthSSHAlias && net.ParseIP(dialHost) == nil) {
			dialHost = sniHost
		}
		if dialHost == "" {
			return ProbeResult{
				ID:          node.ID,
				Name:        node.Name,
				Skipped:     true,
				ProbeStatus: "skipped",
				CheckedAt:   nowStr,
				Message:     "未记录节点域名或公网 IP，跳过 HTTPS 探活（执行一次同步后自动补齐）",
			}
		}
		if sniHost == "" && net.ParseIP(dialHost) == nil {
			sniHost = strings.ToLower(dialHost)
		}
		dialAddr = net.JoinHostPort(dialHost, strconv.Itoa(targetPort))
	}

	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	if sniHost != "" {
		tlsCfg.ServerName = sniHost
	} else {
		// 纯 IP 未绑定域名场景允许验证 Caddy 兜底自签 TLS 握手连通性
		tlsCfg.InsecureSkipVerify = true //nolint:gosec
	}

	dialer := &net.Dialer{Timeout: 3500 * time.Millisecond}
	tr := &http.Transport{
		DisableKeepAlives:     true,
		TLSHandshakeTimeout:   3500 * time.Millisecond,
		ResponseHeaderTimeout: 3500 * time.Millisecond,
		TLSClientConfig:       tlsCfg,
		DialContext: func(dCtx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(dCtx, network, dialAddr)
		},
	}
	defer tr.CloseIdleConnections()

	client := &http.Client{
		Transport: tr,
		Timeout:   5 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	reqHost := cmp.Or(sniHost, rawHost)
	reqURL := "https://" + reqHost + "/"
	req, err := http.NewRequestWithContext(probeCtx, http.MethodHead, reqURL, nil)
	if err != nil {
		return ProbeResult{
			ID:          node.ID,
			Name:        node.Name,
			Online:      false,
			ProbeStatus: "unreachable",
			CheckedAt:   nowStr,
			Message:     "构造 HTTPS 探针失败: " + err.Error(),
		}
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36")

	start := time.Now()
	resp, err := client.Do(req)
	rtt := int(time.Since(start).Milliseconds())
	if rtt <= 0 {
		rtt = 1
	}
	if err != nil {
		return ProbeResult{
			ID:          node.ID,
			Name:        node.Name,
			Online:      false,
			LatencyMs:   rtt,
			ProbeStatus: "unreachable",
			CheckedAt:   nowStr,
			Message:     fmt.Sprintf("HTTPS :%d 探活失败: %s", targetPort, truncateLine(err.Error(), 120)),
		}
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
	_ = resp.Body.Close()

	certDays := 0
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		leaf := resp.TLS.PeerCertificates[0]
		certDays = max(0, int(time.Until(leaf.NotAfter).Hours()/24))
	}

	if resp.StatusCode >= 500 {
		return ProbeResult{
			ID:           node.ID,
			Name:         node.Name,
			Online:       false,
			LatencyMs:    rtt,
			HTTPStatus:   resp.StatusCode,
			CertDaysLeft: certDays,
			ProbeStatus:  "unreachable",
			CheckedAt:    nowStr,
			Message:      fmt.Sprintf("网关返回异常状态 HTTP %d (%d ms)", resp.StatusCode, rtt),
		}
	}

	statusTag := "https_ok"
	msg := fmt.Sprintf("HTTPS :%d 正常 (%d ms)", targetPort, rtt)
	if sniHost == "" {
		statusTag = "tls_ip_ok"
	} else if certDays > 0 && certDays <= 7 {
		statusTag = "cert_expiring"
		msg = fmt.Sprintf("HTTPS 在线 (%d ms)，TLS 证书仅剩 %d 天", rtt, certDays)
	} else if certDays > 0 {
		msg = fmt.Sprintf("HTTPS :%d 正常 (%d ms，证书余 %d 天)", targetPort, rtt, certDays)
	}

	return ProbeResult{
		ID:           node.ID,
		Name:         node.Name,
		Online:       true,
		LatencyMs:    rtt,
		HTTPStatus:   resp.StatusCode,
		CertDaysLeft: certDays,
		ProbeStatus:  statusTag,
		CheckedAt:    nowStr,
		Message:      msg,
	}
}

func (m *Manager) httpProber() HTTPSProberFunc {
	if m.HTTPProber != nil {
		return m.HTTPProber
	}
	return DefaultHTTPSProber
}

func (m *Manager) probeSingleNode(ctx context.Context, node Node) ProbeResult {
	prober := m.httpProber()
	res := prober(ctx, node)
	if res.Skipped {
		return res
	}
	_, _ = m.Store.UpdateRuntimeState(node.ID, func(n *Node) {
		n.Online = res.Online
		n.LastProbeAt = res.CheckedAt
		n.ProbeStatus = res.ProbeStatus
		if res.LatencyMs > 0 {
			n.LatencyMs = res.LatencyMs
		}
		if res.CertDaysLeft > 0 {
			n.CertDaysLeft = res.CertDaysLeft
		}
		if res.Online {
			n.LastError = ""
		} else {
			n.LastError = res.Message
		}
	})
	return res
}

func (m *Manager) probeNodeActionObj(ctx context.Context, node Node) NodeActionResult {
	res := m.probeSingleNode(ctx, node)
	if res.Skipped {
		return NodeActionResult{
			ID:      node.ID,
			Name:    node.Name,
			Success: true,
			Message: res.Message,
		}
	}
	return NodeActionResult{
		ID:        node.ID,
		Name:      node.Name,
		Success:   res.Online,
		LatencyMs: res.LatencyMs,
		Message:   res.Message,
	}
}

// ProbeNodes runs concurrent zero-SSH-log HTTPS :443 probes across targetIDs (or all enabled nodes if empty).
func (m *Manager) ProbeNodes(ctx context.Context, targetIDs []string) ([]ProbeResult, error) {
	if m == nil || m.Store == nil {
		return nil, nil
	}
	m.probeMu.Lock()
	defer m.probeMu.Unlock()

	nodes, err := m.Store.List()
	if err != nil {
		return nil, err
	}

	var selected []Node
	if len(targetIDs) == 0 {
		for _, n := range nodes {
			if n.Enabled {
				selected = append(selected, n)
			}
		}
	} else {
		want := make(map[string]bool, len(targetIDs))
		for _, id := range targetIDs {
			want[strings.TrimSpace(id)] = true
		}
		for _, n := range nodes {
			if want[n.ID] {
				selected = append(selected, n)
			}
		}
	}

	if len(selected) == 0 {
		return []ProbeResult{}, nil
	}

	results := make([]ProbeResult, len(selected))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)

	for i, n := range selected {
		wg.Add(1)
		go func(idx int, node Node) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[idx] = m.probeSingleNode(ctx, node)
		}(i, n)
	}
	wg.Wait()
	return results, nil
}

// StartBackgroundPatrol launches a single low-frequency background HTTPS patrol loop tied to ctx.
// It produces zero sshd logs on workers and exits immediately when ctx is cancelled.
func (m *Manager) StartBackgroundPatrol(ctx context.Context, interval time.Duration) {
	if m == nil || m.Store == nil {
		return
	}
	if !m.patrolStarted.CompareAndSwap(false, true) {
		return
	}
	if interval <= 0 {
		interval = DefaultPatrolInterval
	}

	go func() {
		defer m.patrolStarted.Store(false)

		// Initial warmup probe shortly after WebUI startup
		warmupDelay := min(3*time.Second, interval)
		warmup := time.NewTimer(warmupDelay)
		select {
		case <-ctx.Done():
			warmup.Stop()
			return
		case <-warmup.C:
			pCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			_, _ = m.ProbeNodes(pCtx, nil)
			cancel()
		}

		for {
			maxJitter := min(10*time.Second, max(time.Millisecond, interval/5))
			jitter := time.Duration(rand.Int64N(int64(maxJitter)))
			timer := time.NewTimer(interval + jitter)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
				pCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
				_, _ = m.ProbeNodes(pCtx, nil)
				cancel()
			}
		}
	}()
}
