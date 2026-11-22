// 文件职责：覆盖服务端证书检视器（certs_inspect.go）的磁盘 PEM 扫描、通配符匹配、过期分级与无全局缓存隔离单测。
package deploy_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"singctl/internal/config"
	"singctl/internal/deploy"
)

func writeSelfSignedCertPEM(t *testing.T, path string, dnsNames []string, notAfter time.Time) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: dnsNames[0]},
		Issuer:       pkix.Name{Organization: []string{"Let's Encrypt"}},
		NotBefore:    notAfter.Add(-30 * 24 * time.Hour),
		NotAfter:     notAfter,
		DNSNames:     dnsNames,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestInspectServerCerts_StatesWildcardAndNoGlobalCacheLeak(t *testing.T) {
	now := time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC)
	mkLeaf := func(notAfter time.Time) *x509.Certificate {
		return &x509.Certificate{
			Issuer:   pkix.Name{Organization: []string{"Let's Encrypt"}},
			NotAfter: notAfter,
		}
	}

	if h := deploy.SummarizeX509Cert("node.example.com", "代理节点域名", "caddy-disk", mkLeaf(now.Add(65*24*time.Hour)), now); h.Status != "healthy" || h.DaysRemaining != 65 {
		t.Fatalf("unexpected healthy summary: %+v", h)
	}
	if ex := deploy.SummarizeX509Cert("node.example.com", "代理节点域名", "caddy-disk", mkLeaf(now.Add(5*24*time.Hour)), now); ex.Status != "expiring" || ex.DaysRemaining != 5 {
		t.Fatalf("unexpected expiring summary: %+v", ex)
	}
	if dead := deploy.SummarizeX509Cert("node.example.com", "代理节点域名", "caddy-disk", mkLeaf(now.Add(-24*time.Hour)), now); dead.Status != "expired" {
		t.Fatalf("unexpected expired summary: %+v", dead)
	}

	// Nil/empty config returns empty slice safely
	if got := deploy.InspectServerCerts(nil); len(got) != 0 {
		t.Fatalf("expected empty slice for nil config, got %+v", got)
	}

	certRoot := t.TempDir()
	certFile := filepath.Join(certRoot, "wildcard", "example.crt")
	writeSelfSignedCertPEM(t, certFile, []string{"*.example.com"}, now.Add(40*24*time.Hour))

	cfg := &config.Config{
		Server: config.ServerConfig{
			NodeDomain:     "us1.example.com",
			SubstoreDomain: "missing.other.example",
		},
	}
	opts := deploy.InspectCertOptions{
		CertRoots:  []string{certRoot},
		DisableTLS: true,
		Now:        now,
	}
	items := deploy.InspectServerCertsWithOptions(cfg, opts)
	if len(items) != 2 {
		t.Fatalf("expected 2 cert results (substore + node), got %+v", items)
	}
	if items[0].Domain != "missing.other.example" || items[0].Status != "missing" {
		t.Fatalf("expected missing cert for substore, got %+v", items[0])
	}
	if items[1].Domain != "us1.example.com" || items[1].Status != "healthy" || items[1].Source != "caddy-disk" {
		t.Fatalf("expected wildcard match healthy for us1.example.com, got %+v", items[1])
	}

	// Overwrite cert on disk to expired -> immediate reflection proves zero global mutable cert cache!
	writeSelfSignedCertPEM(t, certFile, []string{"*.example.com"}, now.Add(-2*time.Hour))
	itemsAfter := deploy.InspectServerCertsWithOptions(cfg, opts)
	if itemsAfter[1].Status != "expired" {
		t.Fatalf("expected immediate expired state without global cache staleness, got %+v", itemsAfter[1])
	}
}
