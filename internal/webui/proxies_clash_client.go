// 文件职责：维护本地 Clash 控制面（/proxies /configs /connections）复用的 HTTP 连接池、端点密钥缓存与请求封装。
package webui

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"singctl/internal/singbox"
	"strings"
	"time"
)

const (
	defaultClashDelayURL     = "https://www.gstatic.com/generate_204"
	defaultClashDelayTimeout = 3500
	maxClashDelayConcurrency = 6
)

var (
	errClashUnreachable = errors.New("sing-box 控制接口当前不可达，请确认核心已启动")

	// 共享本地回环 HTTP 连接池：
	// 127.0.0.1 控制面接口（Clash API /traffic /connections /proxies）高频每秒调用，
	// 复用 Keep-Alive TCP 连接并关闭无意义的回环 gzip，避免每次轮询重复三次握手与 TIME_WAIT 堆积。
	sharedClashTransport = &http.Transport{
		Proxy:               nil,
		MaxIdleConns:        16,
		MaxIdleConnsPerHost: 8,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  true,
	}
	sharedClashHTTPClient   = &http.Client{Transport: sharedClashTransport, Timeout: 3 * time.Second}
	sharedClashStreamClient = &http.Client{Transport: sharedClashTransport}
)

type sbProxyHistoryEntry struct {
	Time  string `json:"time,omitempty"`
	Delay int    `json:"delay"`
}

type sbProxyRawItem struct {
	Type    string                `json:"type"`
	Now     string                `json:"now,omitempty"`
	All     []string              `json:"all,omitempty"`
	History []sbProxyHistoryEntry `json:"history,omitempty"`
	UDP     bool                  `json:"udp,omitempty"`
}

type sbClashProxiesResp struct {
	Proxies map[string]sbProxyRawItem `json:"proxies"`
}

type sbClashConfigsResp struct {
	Mode string `json:"mode"`
}

// SbProxyNodeMeta 描述单个出站节点的实时元信息与最新测速结果。
type SbProxyNodeMeta struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	Delay  int    `json:"delay"`
	Tested bool   `json:"tested,omitempty"`
	UDP    bool   `json:"udp,omitempty"`
}

// SbProxyGroup 描述一个策略组（Selector / URLTest / Fallback）的完整视图与关联业务分流信息。
type SbProxyGroup struct {
	Name          string   `json:"name"`
	Type          string   `json:"type"`
	CanSelect     bool     `json:"canSelect"`
	Now           string   `json:"now,omitempty"`
	ResolvedChain []string `json:"resolvedChain,omitempty"`
	ResolvedNode  string   `json:"resolvedNode,omitempty"`
	ResolvedDelay int      `json:"resolvedDelay,omitempty"`
	All           []string `json:"all"`
	UsedBy        []string `json:"usedBy,omitempty"`
	UsedByCount   int      `json:"usedByCount,omitempty"`
	FailedOver    bool     `json:"failedOver,omitempty"`
	FailoverFrom  string   `json:"failoverFrom,omitempty"`
	FailoverSince string   `json:"failoverSince,omitempty"`
}

// SbProxiesSnapshot 供原生 sing-box 节点控制页面使用的策略组全景快照。
type SbProxiesSnapshot struct {
	Running      bool                       `json:"running"`
	Mode         string                     `json:"mode"`
	PrimaryGroup string                     `json:"primaryGroup,omitempty"`
	PrimaryNode  string                     `json:"primaryNode,omitempty"`
	PrimaryDelay int                        `json:"primaryDelay,omitempty"`
	Groups       []SbProxyGroup             `json:"groups"`
	Nodes        map[string]SbProxyNodeMeta `json:"nodes"`
	Error        string                     `json:"error,omitempty"`
}

type sbProxySwitchRequest struct {
	Group  string `json:"group"`
	Target string `json:"target"`
}

type sbProxyDelayRequest struct {
	Group     string `json:"group,omitempty"`
	Node      string `json:"node,omitempty"`
	URL       string `json:"url,omitempty"`
	TimeoutMs int    `json:"timeoutMs,omitempty"`
}

type sbModeRequest struct {
	Mode string `json:"mode"`
}

type sbTrafficResponse struct {
	Running       bool   `json:"running"`
	Up            int64  `json:"up"`
	Down          int64  `json:"down"`
	UploadTotal   int64  `json:"uploadTotal"`
	DownloadTotal int64  `json:"downloadTotal"`
	Connections   int    `json:"connections"`
	Memory        int64  `json:"memory"`
	Error         string `json:"error,omitempty"`
}

func sbConfigFingerprint(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return "missing"
	}
	return fmt.Sprintf("%d:%d", info.Size(), info.ModTime().UnixNano())
}

func (s *Server) invalidateClashCache() {
	s.clashMu.Lock()
	s.clashEndpoint = ""
	s.clashSecret = ""
	s.clashCachedAt = time.Time{}
	s.clashMu.Unlock()
}

func (s *Server) clashEndpointAndSecret(ctx context.Context) (string, string, error) {
	sbPath := s.sbConfigPath()
	fp := sbConfigFingerprint(sbPath)

	s.clashMu.Lock()
	if s.clashEndpoint != "" && s.clashFingerprint == fp && time.Since(s.clashCachedAt) < 30*time.Second {
		ep, sec := s.clashEndpoint, s.clashSecret
		s.clashMu.Unlock()
		return ep, sec, nil
	}
	s.clashMu.Unlock()

	endpoints := singbox.ClashAPIEndpointsForConfig(sbPath)
	secret := singbox.ClashAPISecretForConfig(sbPath)

	for _, base := range endpoints {
		base = strings.TrimRight(strings.TrimSpace(base), "/")
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
		resp, err := sharedClashHTTPClient.Do(req)
		if err != nil {
			continue
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			s.clashMu.Lock()
			s.clashFingerprint = fp
			s.clashEndpoint = base
			s.clashSecret = secret
			s.clashCachedAt = time.Now()
			s.clashMu.Unlock()
			return base, secret, nil
		}
	}

	s.invalidateClashCache()
	return "", "", errClashUnreachable
}

func doClashRequest(ctx context.Context, client *http.Client, method, fullURL, secret string, payload any) (int, []byte, error) {
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
