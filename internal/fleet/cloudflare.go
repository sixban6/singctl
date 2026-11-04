package fleet

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
	"strings"
	"time"
)

const defaultCloudflareAPIBase = "https://api.cloudflare.com/client/v4"

// CloudflareDNSClient manages automatic DNS A/AAAA provisioning and cleanup for Fleet nodes.
type CloudflareDNSClient struct {
	BaseURL    string
	HTTPClient *http.Client
}

// NewCloudflareDNSClient creates a Cloudflare DNS API v4 client.
func NewCloudflareDNSClient() *CloudflareDNSClient {
	return &CloudflareDNSClient{
		BaseURL: defaultCloudflareAPIBase,
		HTTPClient: &http.Client{
			Timeout: 12 * time.Second,
		},
	}
}

type cfZone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type cfDNSRecord struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	Proxied bool   `json:"proxied"`
	TTL     int    `json:"ttl"`
}

type cfEnvelope[T any] struct {
	Success bool `json:"success"`
	Errors  []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
	Result T `json:"result"`
}

func (c *CloudflareDNSClient) baseURL() string {
	return strings.TrimRight(cmp.Or(strings.TrimSpace(c.BaseURL), defaultCloudflareAPIBase), "/")
}

func (c *CloudflareDNSClient) client() *http.Client {
	if c != nil && c.HTTPClient != nil {
		return c.HTTPClient
	}
	return &http.Client{Timeout: 12 * time.Second}
}

func (c *CloudflareDNSClient) doJSON(ctx context.Context, token, method, path string, reqBody any, out any) error {
	var bodyReader io.Reader
	if reqBody != nil {
		b, err := json.Marshal(reqBody)
		if err != nil {
			return err
		}
		bodyReader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL()+path, bodyReader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(token))
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client().Do(req)
	if err != nil {
		return fmt.Errorf("请求 Cloudflare API 失败: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("读取 Cloudflare 响应失败: %w", err)
	}
	if out == nil {
		if resp.StatusCode >= 400 {
			return fmt.Errorf("Cloudflare API 返回 HTTP %d", resp.StatusCode)
		}
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("解析 Cloudflare 响应失败 (HTTP %d): %w", resp.StatusCode, err)
	}
	return nil
}

// ListActiveZones returns active Cloudflare zones accessible by token.
func (c *CloudflareDNSClient) ListActiveZones(ctx context.Context, token string) ([]cfZone, error) {
	if strings.TrimSpace(token) == "" {
		return nil, errors.New("Cloudflare API Token 为空")
	}
	var env cfEnvelope[[]cfZone]
	if err := c.doJSON(ctx, token, http.MethodGet, "/zones?status=active&per_page=50", nil, &env); err != nil {
		return nil, err
	}
	if !env.Success {
		if len(env.Errors) > 0 {
			return nil, fmt.Errorf("Cloudflare Zone 查询失败: %s", env.Errors[0].Message)
		}
		return nil, errors.New("Cloudflare Zone 查询失败（请确认 Token 具备 Zone.DNS 权限）")
	}
	return env.Result, nil
}

// FindZone locates the best matching Cloudflare zone for domainHint.
// If strictMatch is false and domainHint does not match any zone, falls back when exactly one zone exists.
func (c *CloudflareDNSClient) FindZone(ctx context.Context, token, domainHint string, strictMatch bool) (*cfZone, error) {
	zones, err := c.ListActiveZones(ctx, token)
	if err != nil {
		return nil, err
	}
	if len(zones) == 0 {
		return nil, errors.New("当前 Cloudflare Token 名下未找到任何活跃域名 Zone")
	}

	hint := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domainHint)), ".")
	var best *cfZone
	for i := range zones {
		zn := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(zones[i].Name)), ".")
		if zn == "" {
			continue
		}
		if hint == zn || strings.HasSuffix(hint, "."+zn) {
			if best == nil || len(zn) > len(best.Name) {
				cp := zones[i]
				cp.Name = zn
				best = &cp
			}
		}
	}
	if best != nil {
		return best, nil
	}
	if !strictMatch && len(zones) == 1 {
		cp := zones[0]
		cp.Name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(cp.Name)), ".")
		return &cp, nil
	}
	if strictMatch {
		return nil, fmt.Errorf("域名 %q 不属于当前 Cloudflare Token 可管理的任何 Zone", domainHint)
	}
	return nil, fmt.Errorf("无法从主控域名 %q 自动匹配 Cloudflare 根域名，请显式指定 --domain", domainHint)
}

func resolveTargetRecordIP(host string) (ipStr string, recType string, err error) {
	h := strings.TrimSpace(host)
	if parsed := net.ParseIP(h); parsed != nil {
		if parsed.To4() != nil {
			return parsed.String(), "A", nil
		}
		return parsed.String(), "AAAA", nil
	}
	ips, lErr := net.LookupIP(h)
	if lErr != nil || len(ips) == 0 {
		return "", "", fmt.Errorf("无法解析主机地址 %q 的公网 IP: %v", h, lErr)
	}
	for _, ip := range ips {
		if ip.To4() != nil {
			return ip.String(), "A", nil
		}
	}
	return ips[0].String(), "AAAA", nil
}

func (c *CloudflareDNSClient) listRecordsByName(ctx context.Context, token, zoneID, fqdn string) ([]cfDNSRecord, error) {
	q := url.Values{}
	q.Set("name", strings.ToLower(strings.TrimSpace(fqdn)))
	q.Set("per_page", "20")
	var env cfEnvelope[[]cfDNSRecord]
	if err := c.doJSON(ctx, token, http.MethodGet, "/zones/"+zoneID+"/dns_records?"+q.Encode(), nil, &env); err != nil {
		return nil, err
	}
	if !env.Success {
		if len(env.Errors) > 0 {
			return nil, fmt.Errorf("查询 DNS 记录失败: %s", env.Errors[0].Message)
		}
		return nil, errors.New("查询 Cloudflare DNS 记录失败")
	}
	return env.Result, nil
}

func (c *CloudflareDNSClient) createOrUpdateRecord(ctx context.Context, token, zoneID string, existingID string, recType, fqdn, ipStr string) error {
	payload := map[string]any{
		"type":    recType,
		"name":    fqdn,
		"content": ipStr,
		"ttl":     60,
		"proxied": false, // 强制灰云仅 DNS，杜绝套小黄云导致 Reality / Hysteria2 握手失败
		"comment": "Managed by SingCtl Fleet",
	}
	var env cfEnvelope[cfDNSRecord]
	method := http.MethodPost
	path := "/zones/" + zoneID + "/dns_records"
	if existingID != "" {
		method = http.MethodPut
		path = "/zones/" + zoneID + "/dns_records/" + existingID
	}
	if err := c.doJSON(ctx, token, method, path, payload, &env); err != nil {
		return err
	}
	if !env.Success {
		if len(env.Errors) > 0 {
			return fmt.Errorf("写入 DNS 记录 [%s -> %s] 失败: %s", fqdn, ipStr, env.Errors[0].Message)
		}
		return fmt.Errorf("写入 DNS 记录 [%s -> %s] 失败", fqdn, ipStr)
	}
	return nil
}

// ProvisionNodeDNS automatically allocates (if explicitDomain is empty) and provisions a grey-cloud A/AAAA record.
// When auto-deriving, it never overwrites existing DNS records pointing to a different IP.
func (c *CloudflareDNSClient) ProvisionNodeDNS(
	ctx context.Context,
	token string,
	masterDomain string,
	nodeID string,
	explicitDomain string,
	targetHost string,
) (finalDomain string, autoManaged bool, err error) {
	ipStr, recType, err := resolveTargetRecordIP(targetHost)
	if err != nil {
		return "", false, err
	}

	explicit := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(explicitDomain)), ".")
	if explicit != "" {
		zone, zErr := c.FindZone(ctx, token, explicit, true)
		if zErr != nil {
			// 若用户显式传了不属于当前 CF 账号的外部域名（极少见），只要已提前手动解析则不阻断，交给后续 Caddy 验证
			return explicit, false, zErr
		}
		records, rErr := c.listRecordsByName(ctx, token, zone.ID, explicit)
		if rErr != nil {
			return "", false, rErr
		}
		var sameTypeRec *cfDNSRecord
		for i := range records {
			if strings.EqualFold(records[i].Type, "CNAME") {
				return "", false, fmt.Errorf("域名 %s 已存在 CNAME 记录 (%s)，拒绝覆盖，请换用其他子域名", explicit, records[i].Content)
			}
			if strings.EqualFold(records[i].Type, recType) {
				sameTypeRec = &records[i]
				break
			}
		}
		existingID := ""
		if sameTypeRec != nil {
			if strings.TrimSpace(sameTypeRec.Content) == ipStr && !sameTypeRec.Proxied {
				return explicit, true, nil
			}
			existingID = sameTypeRec.ID
		}
		if err := c.createOrUpdateRecord(ctx, token, zone.ID, existingID, recType, explicit, ipStr); err != nil {
			return "", false, err
		}
		return explicit, true, nil
	}

	// 自动推导子域名：绝不覆盖指向其他 IP 的既有记录
	zone, err := c.FindZone(ctx, token, masterDomain, false)
	if err != nil {
		return "", false, err
	}

	cleanID := strings.ToLower(strings.TrimSpace(nodeID))
	if cleanID == "" {
		cleanID = "node"
	}
	candidates := []string{
		fmt.Sprintf("%s.%s", cleanID, zone.Name),
		fmt.Sprintf("fl-%s.%s", cleanID, zone.Name),
	}
	for i := 2; i <= 9; i++ {
		candidates = append(candidates, fmt.Sprintf("%s%d.%s", cleanID, i, zone.Name))
	}

	for _, cand := range candidates {
		if strings.EqualFold(cand, strings.TrimSpace(masterDomain)) {
			continue
		}
		records, rErr := c.listRecordsByName(ctx, token, zone.ID, cand)
		if rErr != nil {
			return "", false, rErr
		}
		if len(records) == 0 {
			if err := c.createOrUpdateRecord(ctx, token, zone.ID, "", recType, cand, ipStr); err != nil {
				return "", false, err
			}
			return cand, true, nil
		}

		// 若同名记录已存在，仅当全部现存地址记录都指向当前这台新机 IP 时才直接复用（并自动修正小黄云为灰云）
		conflict := false
		var matchID string
		var needsDeproxy bool
		for _, r := range records {
			rt := strings.ToUpper(r.Type)
			if rt == "A" || rt == "AAAA" || rt == "CNAME" {
				if rt != recType || strings.TrimSpace(r.Content) != ipStr {
					conflict = true
					break
				}
				matchID = r.ID
				if r.Proxied {
					needsDeproxy = true
				}
			}
		}
		if conflict {
			continue
		}
		if matchID != "" {
			if needsDeproxy {
				if err := c.createOrUpdateRecord(ctx, token, zone.ID, matchID, recType, cand, ipStr); err != nil {
					return "", false, err
				}
			}
			return cand, true, nil
		}
		if err := c.createOrUpdateRecord(ctx, token, zone.ID, "", recType, cand, ipStr); err != nil {
			return "", false, err
		}
		return cand, true, nil
	}

	return "", false, fmt.Errorf("在根域名 %s 下未能找到空闲子域名，请使用 --domain 手动指定", zone.Name)
}

// DeleteNodeDNSIfMatching removes the A/AAAA DNS record for domain ONLY if its content matches expectedHostIP.
func (c *CloudflareDNSClient) DeleteNodeDNSIfMatching(ctx context.Context, token, domain, expectedHost string) (bool, error) {
	fqdn := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if fqdn == "" || strings.TrimSpace(token) == "" || strings.TrimSpace(expectedHost) == "" {
		return false, nil
	}
	ipStr, _, err := resolveTargetRecordIP(expectedHost)
	if err != nil {
		return false, err
	}
	zone, err := c.FindZone(ctx, token, fqdn, true)
	if err != nil {
		return false, err
	}
	records, err := c.listRecordsByName(ctx, token, zone.ID, fqdn)
	if err != nil {
		return false, err
	}
	deletedAny := false
	for _, r := range records {
		rt := strings.ToUpper(r.Type)
		if (rt == "A" || rt == "AAAA") && strings.TrimSpace(r.Content) == ipStr {
			var env cfEnvelope[map[string]any]
			if dErr := c.doJSON(ctx, token, http.MethodDelete, "/zones/"+zone.ID+"/dns_records/"+r.ID, nil, &env); dErr != nil {
				return deletedAny, dErr
			}
			deletedAny = true
		}
	}
	return deletedAny, nil
}
