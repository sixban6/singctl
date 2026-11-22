// 文件职责：检测服务端 Caddy ACME 磁盘证书与本机回环 TLS 叶子证书健康度与剩余有效期（零全局可变缓存）。
package deploy

import (
	"cmp"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"singctl/internal/config"
)

// CertHealth 单个域名的 TLS 证书健康度与剩余有效期详情。
type CertHealth struct {
	Domain        string `json:"domain"`
	Role          string `json:"role"`   // "代理节点域名" | "订阅与面板域名" | "节点与面板域名"
	Status        string `json:"status"` // "healthy" | "expiring" | "expired" | "missing"
	Issuer        string `json:"issuer,omitempty"`
	NotAfter      string `json:"notAfter,omitempty"`
	DaysRemaining int    `json:"daysRemaining"`
	Source        string `json:"source,omitempty"` // "caddy-disk" | "local-tls"
	Message       string `json:"message,omitempty"`
}

// InspectCertOptions 允许调用方或测试显式注入证书扫描目录、回环地址与基准时钟。
type InspectCertOptions struct {
	CertRoots    []string
	LoopbackAddr string
	DisableTLS   bool
	Now          time.Time
}

var defaultCaddyCertRoots = []string{
	"/var/lib/caddy/.local/share/caddy/certificates",
	"/root/.local/share/caddy/certificates",
	"/etc/caddy/certificates",
}

// InspectServerCerts 检查当前服务端配置的节点域名与订阅域名 TLS 证书健康状态（无包级可变缓存，缓存策略由控制面按需托管）。
func InspectServerCerts(cfg *config.Config) []CertHealth {
	return InspectServerCertsWithOptions(cfg, InspectCertOptions{})
}

// InspectServerCertsWithOptions 使用显式选项检查服务端域名 TLS 证书健康状态。
func InspectServerCertsWithOptions(cfg *config.Config, opts InspectCertOptions) []CertHealth {
	if cfg == nil {
		return []CertHealth{}
	}
	nodeDomain := strings.TrimSpace(cfg.Server.GetNodeDomain())
	subDomain := strings.TrimSpace(cfg.Server.GetSubstoreDomain())
	if nodeDomain == "" && subDomain == "" {
		return []CertHealth{}
	}

	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	roots := opts.CertRoots
	if len(roots) == 0 {
		roots = defaultCaddyCertRoots
	}
	loopbackAddr := cmp.Or(strings.TrimSpace(opts.LoopbackAddr), "127.0.0.1:443")

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

	diskCerts := scanCaddyCertFiles(roots)
	out := make([]CertHealth, 0, len(targets))
	for _, tgt := range targets {
		out = append(out, inspectSingleDomainCert(tgt.domain, tgt.role, diskCerts, loopbackAddr, opts.DisableTLS, now))
	}
	return out
}

func inspectSingleDomainCert(domain, role string, diskCerts map[string]*x509.Certificate, loopbackAddr string, disableTLS bool, now time.Time) CertHealth {
	lower := strings.ToLower(strings.TrimSpace(domain))
	var leaf *x509.Certificate
	source := ""

	if cert, ok := diskCerts[lower]; ok && cert != nil {
		leaf = cert
		source = "caddy-disk"
	} else if _, rest, ok := strings.Cut(lower, "."); ok && rest != "" {
		if cert, ok := diskCerts["*."+rest]; ok && cert != nil {
			leaf = cert
			source = "caddy-disk"
		}
	}

	if leaf == nil && !disableTLS {
		if probed := probeLocalLoopbackCert(lower, loopbackAddr); probed != nil {
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

	return SummarizeX509Cert(domain, role, source, leaf, now)
}

// SummarizeX509Cert 汇总单张 X.509 叶子证书的健康等级、签发方与剩余天数。
func SummarizeX509Cert(domain, role, source string, leaf *x509.Certificate, now time.Time) CertHealth {
	rem := leaf.NotAfter.Sub(now)
	days := int(rem.Hours() / 24)
	issuer := cmp.Or(
		firstNonEmptyCertOrg(leaf.Issuer.Organization),
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

func firstNonEmptyCertOrg(items []string) string {
	if len(items) > 0 {
		return strings.TrimSpace(items[0])
	}
	return ""
}

func scanCaddyCertFiles(roots []string) map[string]*x509.Certificate {
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

func probeLocalLoopbackCert(domain, loopbackAddr string) *x509.Certificate {
	dialer := &net.Dialer{Timeout: 600 * time.Millisecond}
	conn, err := tls.DialWithDialer(dialer, "tcp", loopbackAddr, &tls.Config{
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
