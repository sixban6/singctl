package serverweb

import (
	"cmp"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"singctl/internal/config"
)

// CertHealth 单个域名的 TLS 证书健康度与剩余有效期详情
type CertHealth struct {
	Domain        string `json:"domain"`
	Role          string `json:"role"` // "节点域名" | "订阅/面板域名" | "节点与订阅合一"
	Status        string `json:"status"` // "healthy" | "expiring" | "expired" | "missing"
	Issuer        string `json:"issuer,omitempty"`
	NotAfter      string `json:"notAfter,omitempty"`
	DaysRemaining int    `json:"daysRemaining"`
	Source        string `json:"source,omitempty"` // "caddy-disk" | "local-tls"
	Message       string `json:"message,omitempty"`
}

type certCacheState struct {
	mu        sync.Mutex
	expiresAt time.Time
	key       string
	items     []CertHealth
}

var globalCertCache certCacheState

// InspectServerCerts 检查当前服务端配置的节点域名与订阅域名 TLS 证书健康状态（带 3 分钟内存缓存）
func InspectServerCerts(cfg *config.Config, forceRefresh bool) []CertHealth {
	if cfg == nil {
		return []CertHealth{}
	}
	nodeDomain := strings.TrimSpace(cfg.Server.GetNodeDomain())
	subDomain := strings.TrimSpace(cfg.Server.GetSubstoreDomain())
	if nodeDomain == "" && subDomain == "" {
		return []CertHealth{}
	}

	cacheKey := nodeDomain + "|" + subDomain
	now := time.Now()

	if !forceRefresh {
		globalCertCache.mu.Lock()
		if globalCertCache.key == cacheKey && now.Before(globalCertCache.expiresAt) {
			cached := slices.Clone(globalCertCache.items)
			globalCertCache.mu.Unlock()
			return cached
		}
		globalCertCache.mu.Unlock()
	}

	type domainTarget struct {
		domain string
		role   string
	}
	var targets []domainTarget
	if nodeDomain != "" && subDomain != "" && strings.EqualFold(nodeDomain, subDomain) {
		targets = append(targets, domainTarget{domain: nodeDomain, role: "节点与面板域名"})
	} else {
		if subDomain != "" {
			targets = append(targets, domainTarget{domain: subDomain, role: "订阅与面板域名"})
		}
		if nodeDomain != "" {
			targets = append(targets, domainTarget{domain: nodeDomain, role: "代理节点域名"})
		}
	}

	diskCerts := scanCaddyCertFiles()
	out := make([]CertHealth, 0, len(targets))
	for _, tgt := range targets {
		out = append(out, inspectSingleDomainCert(tgt.domain, tgt.role, diskCerts))
	}

	globalCertCache.mu.Lock()
	globalCertCache.key = cacheKey
	globalCertCache.items = slices.Clone(out)
	globalCertCache.expiresAt = time.Now().Add(3 * time.Minute)
	globalCertCache.mu.Unlock()

	return out
}

func inspectSingleDomainCert(domain, role string, diskCerts map[string]*x509.Certificate) CertHealth {
	lower := strings.ToLower(strings.TrimSpace(domain))
	var leaf *x509.Certificate
	source := ""

	if cert, ok := diskCerts[lower]; ok && cert != nil {
		leaf = cert
		source = "caddy-disk"
	} else {
		// 支持通配符匹配 *.example.com
		if _, rest, ok := strings.Cut(lower, "."); ok && rest != "" {
			if cert, ok := diskCerts["*."+rest]; ok && cert != nil {
				leaf = cert
				source = "caddy-disk"
			}
		}
	}

	if leaf == nil {
		if probed := probeLocalLoopbackCert(lower); probed != nil {
			leaf = probed
			source = "local-tls"
		}
	}

	if leaf == nil {
		return CertHealth{
			Domain:        domain,
			Role:          role,
			Status:        "missing",
			DaysRemaining: 0,
			Message:       "暂未读取到本地 ACME 证书（可能仍在签发中或非本机终止 TLS）",
		}
	}

	return summarizeX509Cert(domain, role, source, leaf, time.Now())
}

func summarizeX509Cert(domain, role, source string, leaf *x509.Certificate, now time.Time) CertHealth {
	rem := leaf.NotAfter.Sub(now)
	days := int(rem.Hours() / 24)
	issuer := cmp.Or(
		firstOrEmpty(leaf.Issuer.Organization),
		leaf.Issuer.CommonName,
		"ACME CA",
	)
	notAfterStr := leaf.NotAfter.Local().Format("2006-01-02 15:04")

	status := "healthy"
	msg := fmt.Sprintf("证书正常，剩余 %d 天", max(days, 0))
	switch {
	case now.After(leaf.NotAfter):
		status = "expired"
		msg = fmt.Sprintf("证书已于 %s 过期，请检查 Cloudflare DNS Token 与 Caddy 日志", notAfterStr)
	case rem < 14*24*time.Hour:
		status = "expiring"
		msg = fmt.Sprintf("证书剩余不足 %d 天，请关注 Caddy 自动续签状态", max(days, 1))
	}

	return CertHealth{
		Domain:        domain,
		Role:          role,
		Status:        status,
		Issuer:        issuer,
		NotAfter:      notAfterStr,
		DaysRemaining: days,
		Source:        source,
		Message:       msg,
	}
}

func firstOrEmpty(items []string) string {
	if len(items) > 0 {
		return strings.TrimSpace(items[0])
	}
	return ""
}

func scanCaddyCertFiles() map[string]*x509.Certificate {
	roots := []string{
		"/var/lib/caddy/.local/share/caddy/certificates",
		"/root/.local/share/caddy/certificates",
		"/etc/caddy/certificates",
	}
	res := make(map[string]*x509.Certificate)
	for _, root := range roots {
		st, err := os.Stat(root)
		if err != nil || !st.IsDir() {
			continue
		}
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil || d.IsDir() || !strings.HasSuffix(strings.ToLower(d.Name()), ".crt") {
				return nil
			}
			cert := parseLeafCertFile(path)
			if cert == nil {
				return nil
			}
			for _, dnsName := range cert.DNSNames {
				key := strings.ToLower(strings.TrimSpace(dnsName))
				if key == "" {
					continue
				}
				if existing, ok := res[key]; !ok || cert.NotAfter.After(existing.NotAfter) {
					res[key] = cert
				}
			}
			if cn := strings.ToLower(strings.TrimSpace(cert.Subject.CommonName)); cn != "" {
				if existing, ok := res[cn]; !ok || cert.NotAfter.After(existing.NotAfter) {
					res[cn] = cert
				}
			}
			return nil
		})
	}
	return res
}

func parseLeafCertFile(path string) *x509.Certificate {
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) == 0 {
		return nil
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil
	}
	return cert
}

func probeLocalLoopbackCert(domain string) *x509.Certificate {
	dialer := &net.Dialer{Timeout: 600 * time.Millisecond}
	conn, err := tls.DialWithDialer(dialer, "tcp", "127.0.0.1:443", &tls.Config{
		ServerName:         domain,
		InsecureSkipVerify: true, // 仅用于本机回环读取 Caddy 实际挂载的叶子证书元数据
	})
	if err != nil {
		return nil
	}
	defer conn.Close()
	state := conn.ConnectionState()
	for _, cert := range state.PeerCertificates {
		if !cert.IsCA {
			return cert
		}
	}
	if len(state.PeerCertificates) > 0 {
		return state.PeerCertificates[0]
	}
	return nil
}

func (s *Server) handleInspectCerts(w http.ResponseWriter, r *http.Request) {
	cfg, _ := config.Load(s.opts.ConfigPath)
	force := r.URL.Query().Get("refresh") == "1" || r.URL.Query().Get("refresh") == "true"
	certs := InspectServerCerts(cfg, force)
	writeJSON(w, http.StatusOK, map[string]any{
		"certs": certs,
	})
}
