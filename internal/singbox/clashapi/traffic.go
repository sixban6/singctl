// 文件职责：提供 Clash API 活跃连接读取、连接精准踢断、零分配流式连接摘要解码与 NDJSON 实时流量采样。
package clashapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ConnectionsAt 获取指定 Clash 端点当前的完整活跃连接快照（GET /connections）。
func (c *Client) ConnectionsAt(ctx context.Context, baseURL, secret string) (ConnectionsSnapshot, error) {
	base := NormalizeBaseURL(baseURL)
	if base == "" {
		return ConnectionsSnapshot{}, ErrUnreachable
	}
	code, raw, err := doJSONRequest(ctx, c.reqClient(), http.MethodGet, base+"/connections", secret, nil)
	if err != nil {
		return ConnectionsSnapshot{}, err
	}
	if code != http.StatusOK {
		return ConnectionsSnapshot{}, &StatusError{StatusCode: code, Body: strings.TrimSpace(string(raw))}
	}
	var snap ConnectionsSnapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		return ConnectionsSnapshot{}, &DecodeError{Cause: err}
	}
	return snap, nil
}

// CloseConnectionAt 关闭单条指定 ID 的活跃连接（DELETE /connections/{id}）。
func (c *Client) CloseConnectionAt(ctx context.Context, baseURL, secret, connID string) error {
	base := NormalizeBaseURL(baseURL)
	if base == "" {
		return ErrUnreachable
	}
	if strings.TrimSpace(connID) == "" {
		return errors.New("connection id is empty")
	}
	delURL := fmt.Sprintf("%s/connections/%s", base, url.PathEscape(connID))
	code, raw, err := doJSONRequest(ctx, c.reqClient(), http.MethodDelete, delURL, secret, nil)
	if err != nil {
		return err
	}
	if code < 200 || code >= 300 {
		return &StatusError{StatusCode: code, Body: strings.TrimSpace(string(raw))}
	}
	return nil
}

// CloseAllConnectionsAt 关闭指定 Clash 端点上的全部活跃连接（DELETE /connections）。
func (c *Client) CloseAllConnectionsAt(ctx context.Context, baseURL, secret string) error {
	base := NormalizeBaseURL(baseURL)
	if base == "" {
		return ErrUnreachable
	}
	code, raw, err := doJSONRequest(ctx, c.reqClient(), http.MethodDelete, base+"/connections", secret, nil)
	if err != nil {
		return err
	}
	if code < 200 || code >= 300 {
		return &StatusError{StatusCode: code, Body: strings.TrimSpace(string(raw))}
	}
	return nil
}

// ConnectionsSummaryAt 流式获取活跃连接累计上下行字节数与连接总数。
func (c *Client) ConnectionsSummaryAt(ctx context.Context, baseURL, secret string) (upTotal, downTotal int64, count int, ok bool) {
	base := NormalizeBaseURL(baseURL)
	if base == "" {
		return 0, 0, 0, false
	}
	reqCtx, cancel := context.WithTimeout(ctx, 1200*time.Millisecond)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, base+"/connections", nil)
	if err != nil {
		return 0, 0, 0, false
	}
	if secret != "" {
		req.Header.Set("Authorization", "Bearer "+secret)
	}
	resp, err := c.streamingClient().Do(req)
	if err != nil {
		return 0, 0, 0, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return 0, 0, 0, false
	}
	return DecodeConnectionsSummary(io.LimitReader(resp.Body, 16<<20))
}

// DecodeConnectionsSummary 流式解码 /connections 响应中的累计流量与活跃连接条数，避免反序列化大数组产生堆分配。
func DecodeConnectionsSummary(r io.Reader) (upTotal, downTotal int64, count int, ok bool) {
	dec := json.NewDecoder(r)
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return 0, 0, 0, false
	}

	var scratch json.RawMessage
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return 0, 0, 0, false
		}
		key, isStr := keyTok.(string)
		if !isStr {
			return 0, 0, 0, false
		}
		switch key {
		case "uploadTotal":
			if err := dec.Decode(&upTotal); err != nil {
				return 0, 0, 0, false
			}
		case "downloadTotal":
			if err := dec.Decode(&downTotal); err != nil {
				return 0, 0, 0, false
			}
		case "connections":
			arrTok, err := dec.Token()
			if err != nil {
				return 0, 0, 0, false
			}
			if arrTok == nil {
				continue
			}
			if arrTok != json.Delim('[') {
				return 0, 0, 0, false
			}
			for dec.More() {
				scratch = scratch[:0]
				if err := dec.Decode(&scratch); err != nil {
					return 0, 0, 0, false
				}
				count++
			}
			endArr, err := dec.Token()
			if err != nil || endArr != json.Delim(']') {
				return 0, 0, 0, false
			}
		default:
			scratch = scratch[:0]
			if err := dec.Decode(&scratch); err != nil {
				return 0, 0, 0, false
			}
		}
	}

	endObj, err := dec.Token()
	if err != nil || endObj != json.Delim('}') {
		return 0, 0, 0, false
	}
	if _, err := dec.Token(); err != io.EOF {
		return 0, 0, 0, false
	}
	return upTotal, downTotal, count, true
}

// ReadFirstStreamObjectAt 读取流式端点（如 /traffic 或 /memory）的首条 JSON 对象后立即关闭连接。
func (c *Client) ReadFirstStreamObjectAt(ctx context.Context, baseURL, secret, path string, dst any) bool {
	base := NormalizeBaseURL(baseURL)
	if base == "" {
		return false
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
	if err != nil {
		return false
	}
	if secret != "" {
		req.Header.Set("Authorization", "Bearer "+secret)
	}
	resp, err := c.streamingClient().Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 64*1024)).Decode(dst) == nil
}

// StreamTrafficAt 持续流式读取 /traffic NDJSON 并在每条采样到达时回调 onTick，直至 ctx 取消或连接断开。
func (c *Client) StreamTrafficAt(ctx context.Context, baseURL, secret string, onTick func(up, down int64)) error {
	base := NormalizeBaseURL(baseURL)
	if base == "" {
		return ErrUnreachable
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/traffic", nil)
	if err != nil {
		return err
	}
	if secret != "" {
		req.Header.Set("Authorization", "Bearer "+secret)
	}
	resp, err := c.streamingClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return &StatusError{StatusCode: resp.StatusCode, Body: strings.TrimSpace(string(raw))}
	}

	dec := json.NewDecoder(resp.Body)
	for ctx.Err() == nil {
		var tick struct {
			Up   int64 `json:"up"`
			Down int64 `json:"down"`
		}
		if err := dec.Decode(&tick); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if onTick != nil {
			onTick(tick.Up, tick.Down)
		}
	}
	return ctx.Err()
}
