// 文件职责：定义统一 Clash API 客户端模型、实例级 Keep-Alive 连接池与端点密钥指纹缓存。
package clashapi

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"singctl/internal/constant"
	"singctl/internal/singbox"
)

const (
	// DefaultDelayProbeURL 为节点延迟测速默认探测地址。
	DefaultDelayProbeURL = "https://www.gstatic.com/generate_204"
	// DefaultDelayTimeoutMs 为节点延迟测速默认超时毫秒数。
	DefaultDelayTimeoutMs = 3500
	// DefaultDelayConcurrency 为批量并发测速默认工作协程上限。
	DefaultDelayConcurrency = 6

	endpointCacheTTL = 30 * time.Second
)

// ErrUnreachable 表示本地 sing-box Clash API 控制接口不可达。
var ErrUnreachable = errors.New("sing-box 控制接口当前不可达，请确认核心已启动")

// StatusError 表示 Clash API 返回了非预期的 HTTP 状态码。
type StatusError struct {
	StatusCode int
	Body       string
}

func (e *StatusError) Error() string {
	if e.Body != "" {
		return fmt.Sprintf("HTTP %d: %s", e.StatusCode, e.Body)
	}
	return fmt.Sprintf("HTTP %d", e.StatusCode)
}

// DecodeError 表示 Clash API 响应 JSON 解码失败。
type DecodeError struct {
	Cause error
}

func (e *DecodeError) Error() string {
	return fmt.Sprintf("decode clash response: %v", e.Cause)
}

func (e *DecodeError) Unwrap() error {
	return e.Cause
}

// HistoryEntry 描述 Clash 节点历史延迟记录项。
type HistoryEntry struct {
	Time  string `json:"time,omitempty"`
	Delay int    `json:"delay"`
}

// ProxyItem 描述 Clash /proxies 返回的单个出站或策略组条目。
type ProxyItem struct {
	Type    string         `json:"type"`
	Now     string         `json:"now,omitempty"`
	All     []string       `json:"all,omitempty"`
	History []HistoryEntry `json:"history,omitempty"`
	UDP     bool           `json:"udp,omitempty"`
}

// ConnectionMetadata 描述 Clash /connections 中单条活跃连接的五元组与嗅探元数据。
type ConnectionMetadata struct {
	Network         string `json:"network"`
	Type            string `json:"type"`
	SourceIP        string `json:"sourceIP"`
	DestinationIP   string `json:"destinationIP"`
	SourcePort      string `json:"sourcePort,omitempty"`
	DestinationPort string `json:"destinationPort"`
	Host            string `json:"host"`
	SniffHost       string `json:"sniffHost"`
}

// Connection 描述 Clash /connections 中的单条活跃连接。
type Connection struct {
	ID          string             `json:"id"`
	Upload      int64              `json:"upload"`
	Download    int64              `json:"download"`
	Start       string             `json:"start"`
	Chains      []string           `json:"chains"`
	Rule        string             `json:"rule"`
	RulePayload string             `json:"rulePayload,omitempty"`
	Metadata    ConnectionMetadata `json:"metadata"`
}

// ConnectionsSnapshot 描述 Clash /connections 的完整快照。
type ConnectionsSnapshot struct {
	DownloadTotal int64        `json:"downloadTotal"`
	UploadTotal   int64        `json:"uploadTotal"`
	Memory        int64        `json:"memory"`
	Connections   []Connection `json:"connections"`
}

// Options 配置统一 Clash API 客户端实例。
type Options struct {
	ConfigPath     string
	Endpoints      []string
	Secret         string
	RequestTimeout time.Duration
	HTTPClient     *http.Client
}

// Client 提供带实例级 HTTP Keep-Alive 连接池的 Clash 控制面客户端。
type Client struct {
	opts         Options
	httpClient   *http.Client
	streamClient *http.Client

	mu          sync.Mutex
	fingerprint string
	endpoint    string
	secret      string
	cachedAt    time.Time
}

// NewClient 创建实例级隔离连接池的 Clash API 客户端。
func NewClient(opts Options) *Client {
	reqTimeout := cmp.Or(opts.RequestTimeout, 3*time.Second)
	if opts.HTTPClient != nil {
		streamCli := *opts.HTTPClient
		streamCli.Timeout = 0
		return &Client{
			opts:         opts,
			httpClient:   opts.HTTPClient,
			streamClient: &streamCli,
		}
	}
	transport := &http.Transport{
		Proxy:               nil,
		MaxIdleConns:        16,
		MaxIdleConnsPerHost: 8,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  true,
	}
	return &Client{
		opts:         opts,
		httpClient:   &http.Client{Transport: transport, Timeout: reqTimeout},
		streamClient: &http.Client{Transport: transport},
	}
}

// NormalizeBaseURL 将 host:port 或 URL 规范化为不带尾斜杠的 http(s)://host:port。
func NormalizeBaseURL(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return ""
	}
	scheme := "http"
	rest := addr
	if strings.HasPrefix(strings.ToLower(addr), "http://") {
		rest = addr[len("http://"):]
	} else if strings.HasPrefix(strings.ToLower(addr), "https://") {
		scheme = "https"
		rest = addr[len("https://"):]
	}
	rest = strings.TrimRight(strings.TrimSpace(rest), "/")
	if rest == "" {
		return ""
	}
	host, port, err := net.SplitHostPort(rest)
	if err != nil {
		host, port = rest, "9090"
	}
	host = strings.Trim(host, "[]")
	switch host {
	case "", "0.0.0.0", "::":
		host = "127.0.0.1"
	}
	return scheme + "://" + net.JoinHostPort(host, port)
}

func sbConfigFingerprint(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return "missing"
	}
	return fmt.Sprintf("%d:%d", info.Size(), info.ModTime().UnixNano())
}

// InvalidateCache 清空已缓存的 Clash API 端点与密钥。
func (c *Client) InvalidateCache() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.endpoint = ""
	c.secret = ""
	c.cachedAt = time.Time{}
	c.mu.Unlock()
}

func (c *Client) configPath() string {
	if c == nil {
		return constant.SingBoxConfigFile
	}
	return cmp.Or(strings.TrimSpace(c.opts.ConfigPath), constant.SingBoxConfigFile)
}

// ResolveEndpoint 探测并缓存可达的 Clash API 基础地址与 Bearer 密钥。
func (c *Client) ResolveEndpoint(ctx context.Context) (string, string, error) {
	sbPath := c.configPath()
	fp := sbConfigFingerprint(sbPath)
	if len(c.opts.Endpoints) > 0 {
		fp = "static:" + strings.Join(c.opts.Endpoints, ",") + ":" + c.opts.Secret
	}

	c.mu.Lock()
	if c.endpoint != "" && c.fingerprint == fp && time.Since(c.cachedAt) < endpointCacheTTL {
		ep, sec := c.endpoint, c.secret
		c.mu.Unlock()
		return ep, sec, nil
	}
	c.mu.Unlock()

	endpoints := c.opts.Endpoints
	secret := c.opts.Secret
	if len(endpoints) == 0 {
		endpoints = singbox.ClashAPIEndpointsForConfig(sbPath)
		secret = singbox.ClashAPISecretForConfig(sbPath)
	}

	for _, rawBase := range endpoints {
		base := NormalizeBaseURL(rawBase)
		if base == "" {
			continue
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/version", nil)
		if err != nil {
			continue
		}
		if secret != "" {
			req.Header.Set("Authorization", "Bearer "+secret)
		}
		resp, err := c.reqClient().Do(req)
		if err != nil {
			continue
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			c.mu.Lock()
			c.fingerprint = fp
			c.endpoint = base
			c.secret = secret
			c.cachedAt = time.Now()
			c.mu.Unlock()
			return base, secret, nil
		}
	}

	c.InvalidateCache()
	return "", "", ErrUnreachable
}

func (c *Client) reqClient() *http.Client {
	if c != nil && c.httpClient != nil {
		return c.httpClient
	}
	return http.DefaultClient
}

func (c *Client) streamingClient() *http.Client {
	if c != nil && c.streamClient != nil {
		return c.streamClient
	}
	return c.reqClient()
}

func doJSONRequest(ctx context.Context, client *http.Client, method, fullURL, secret string, payload any) (int, []byte, error) {
	var bodyReader io.Reader
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			return 0, nil, err
		}
		bodyReader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, fullURL, bodyReader)
	if err != nil {
		return 0, nil, err
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if secret != "" {
		req.Header.Set("Authorization", "Bearer "+secret)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, data, nil
}

// ProxiesAt 请求指定 Clash 端点的 /proxies 字典。
func (c *Client) ProxiesAt(ctx context.Context, baseURL, secret string) (map[string]ProxyItem, error) {
	base := NormalizeBaseURL(baseURL)
	if base == "" {
		return nil, ErrUnreachable
	}
	code, raw, err := doJSONRequest(ctx, c.reqClient(), http.MethodGet, base+"/proxies", secret, nil)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, &StatusError{StatusCode: code, Body: strings.TrimSpace(string(raw))}
	}
	var doc struct {
		Proxies map[string]ProxyItem `json:"proxies"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, &DecodeError{Cause: err}
	}
	return doc.Proxies, nil
}

// ResolveProxiesAcross 依次尝试候选端点列表，返回首个成功响应的非空策略字典及其基础地址。
func (c *Client) ResolveProxiesAcross(ctx context.Context, endpoints []string, secret string) (string, map[string]ProxyItem, error) {
	var lastErr error
	for _, rawBase := range endpoints {
		base := NormalizeBaseURL(rawBase)
		if base == "" {
			continue
		}
		proxies, err := c.ProxiesAt(ctx, base, secret)
		if err != nil {
			lastErr = err
			continue
		}
		if len(proxies) > 0 {
			return base, proxies, nil
		}
		lastErr = errors.New("empty proxies document")
	}
	if lastErr == nil {
		lastErr = errors.New("no clash api endpoints reachable")
	}
	return "", nil, lastErr
}

// ModeAt 查询指定 Clash 端点的当前运行模式（rule / global / direct）。
func (c *Client) ModeAt(ctx context.Context, baseURL, secret string) (string, error) {
	base := NormalizeBaseURL(baseURL)
	if base == "" {
		return "", ErrUnreachable
	}
	code, raw, err := doJSONRequest(ctx, c.reqClient(), http.MethodGet, base+"/configs", secret, nil)
	if err != nil {
		return "", err
	}
	if code != http.StatusOK {
		return "", &StatusError{StatusCode: code, Body: strings.TrimSpace(string(raw))}
	}
	var doc struct {
		Mode string `json:"mode"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return "", &DecodeError{Cause: err}
	}
	return cmp.Or(strings.ToLower(strings.TrimSpace(doc.Mode)), "rule"), nil
}

// PatchModeAt 切换指定 Clash 端点的运行模式（PATCH /configs）。
func (c *Client) PatchModeAt(ctx context.Context, baseURL, secret, mode string) error {
	base := NormalizeBaseURL(baseURL)
	if base == "" {
		return ErrUnreachable
	}
	code, raw, err := doJSONRequest(ctx, c.reqClient(), http.MethodPatch, base+"/configs", secret, map[string]string{"mode": mode})
	if err != nil {
		return err
	}
	if code < 200 || code >= 300 {
		return &StatusError{StatusCode: code, Body: strings.TrimSpace(string(raw))}
	}
	return nil
}

// SwitchSelectorAt 切换指定 Selector 策略组的当前选中节点（PUT /proxies/{group}）。
func (c *Client) SwitchSelectorAt(ctx context.Context, baseURL, secret, group, target string) error {
	base := NormalizeBaseURL(baseURL)
	if base == "" {
		return ErrUnreachable
	}
	putURL := fmt.Sprintf("%s/proxies/%s", base, url.PathEscape(group))
	code, raw, err := doJSONRequest(ctx, c.reqClient(), http.MethodPut, putURL, secret, map[string]string{"name": target})
	if err != nil {
		return err
	}
	if code < 200 || code >= 300 {
		return &StatusError{StatusCode: code, Body: strings.TrimSpace(string(raw))}
	}
	return nil
}
