package gfw

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestDetector_ModelScoring(t *testing.T) {
	tests := []struct {
		score int
		level RiskLevel
	}{
		{0, RiskLevelClean},
		{15, RiskLevelClean},
		{20, RiskLevelClean},
		{25, RiskLevelLow},
		{50, RiskLevelLow},
		{55, RiskLevelHigh},
		{75, RiskLevelHigh},
		{80, RiskLevelCritical},
		{100, RiskLevelCritical},
	}

	for _, tt := range tests {
		rep := &Report{TotalScore: tt.score}
		switch {
		case tt.score <= 20:
			rep.RiskLevel = RiskLevelClean
		case tt.score <= 50:
			rep.RiskLevel = RiskLevelLow
		case tt.score <= 75:
			rep.RiskLevel = RiskLevelHigh
		default:
			rep.RiskLevel = RiskLevelCritical
		}

		if rep.RiskLevel != tt.level {
			t.Errorf("score %d: expected level %v, got %v", tt.score, tt.level, rep.RiskLevel)
		}
	}
}

func TestDetector_MockServer(t *testing.T) {
	// 启动一个模拟的标准 HTTP/HTTPS 服务
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Caddy")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<!DOCTYPE html><html><body><h1>Welcome to My Blog</h1></body></html>"))
	}))
	defer ts.Close()

	host, portStr, err := net.SplitHostPort(ts.Listener.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort failed: %v", err)
	}
	port, _ := strconv.Atoi(portStr)

	opts := ProbeOptions{
		IP:      host,
		Ports:   []int{port},
		Timeout: 2 * time.Second,
	}

	detector := NewDetector(opts)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	report, err := detector.Run(ctx)
	if err != nil {
		t.Fatalf("detector.Run failed: %v", err)
	}

	if report.TotalScore < 0 || report.TotalScore > 100 {
		t.Errorf("expected score 0-100, got %d", report.TotalScore)
	}

	var buf bytes.Buffer
	if err := PrintReport(&buf, report, false); err != nil {
		t.Fatalf("PrintReport failed: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "广域网主动探测模拟与抗压风险评估报告") {
		t.Errorf("output missing header: %s", out)
	}
	if !strings.Contains(out, "判定风险总评分") {
		t.Errorf("output missing total score: %s", out)
	}

	var jsonBuf bytes.Buffer
	if err := PrintJSONReport(&jsonBuf, report); err != nil {
		t.Fatalf("PrintJSONReport failed: %v", err)
	}
	if !strings.Contains(jsonBuf.String(), `"total_score":`) {
		t.Errorf("json report invalid: %s", jsonBuf.String())
	}
}

func TestProbeOptions_PortResolution(t *testing.T) {
	// Empty ports -> default 80 and 443
	o1 := ProbeOptions{}
	if o1.GetHTTPPort() != 80 || o1.GetHTTPSPort() != 443 {
		t.Errorf("o1: expected 80 and 443, got %d and %d", o1.GetHTTPPort(), o1.GetHTTPSPort())
	}

	// 1 port provided -> both use that port
	o2 := ProbeOptions{Ports: []int{8443}}
	if o2.GetHTTPPort() != 8443 || o2.GetHTTPSPort() != 8443 {
		t.Errorf("o2: expected 8443 and 8443, got %d and %d", o2.GetHTTPPort(), o2.GetHTTPSPort())
	}

	// 2 ports provided -> 0 is HTTP, 1 is HTTPS
	o3 := ProbeOptions{Ports: []int{8080, 8443}}
	if o3.GetHTTPPort() != 8080 || o3.GetHTTPSPort() != 8443 {
		t.Errorf("o3: expected 8080 and 8443, got %d and %d", o3.GetHTTPPort(), o3.GetHTTPSPort())
	}
}

func TestDetector_ContextCancel(t *testing.T) {
	opts := ProbeOptions{
		IP:      "127.0.0.1",
		Timeout: 5 * time.Second,
	}
	d := NewDetector(opts)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := d.Run(ctx)
	if err == nil {
		t.Errorf("expected error on canceled context, got nil")
	}
}

func generateTestCert(t *testing.T, cn, issuerCN string, dnsNames []string, notBefore, notAfter time.Time) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: issuerCN, Organization: []string{issuerCN}},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     dnsNames,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, leafTmpl, caTmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	parsed, err := x509.ParseCertificate(derBytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
		Leaf:        parsed,
	}, parsed
}

func TestTLS_OnDemandCertOracleDetected(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	// 模拟开启了 Caddy tls internal on_demand 的服务端：对任意随机 SNI 现场签发同名自签证书
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				tlsConn := tls.Server(c, &tls.Config{
					GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
						sni := chi.ServerName
						if sni == "" {
							sni = "localhost"
						}
						cert, _ := generateTestCert(t, sni, "Caddy Local Authority - 2026 ECC Root", []string{sni}, time.Now().Add(-10*time.Second), time.Now().Add(12*time.Hour))
						return &cert, nil
					},
				})
				_ = tlsConn.Handshake()
			}(conn)
		}
	}()

	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)

	cat := probeTLS(t.Context(), ProbeOptions{
		IP:      "127.0.0.1",
		Ports:   []int{port},
		SNI:     "swdist.apple.com",
		Timeout: 2 * time.Second,
	})

	if len(cat.Items) < 2 {
		t.Fatalf("expected TLS check items, got %d", len(cat.Items))
	}
	// Item 0: 随机 SNI 必须捕获动态签发神谕 (Score == 10, Passed == false)
	if cat.Items[0].Passed || cat.Items[0].Score < 10 {
		t.Errorf("expected Random SNI on-demand oracle to fail with score 10, got passed=%v score=%d details=%s",
			cat.Items[0].Passed, cat.Items[0].Score, cat.Items[0].Details)
	}
	// Item 1: 目标 SNI 落入自签假证书必须被 CA 信任链校验拦截 (Score == 10, Passed == false)
	if cat.Items[1].Passed || cat.Items[1].Score < 10 {
		t.Errorf("expected Target SNI fake self-signed cert to fail with score 10, got passed=%v score=%d details=%s",
			cat.Items[1].Passed, cat.Items[1].Score, cat.Items[1].Details)
	}
}

func TestQUICv1PacketRoundTripAndCertExtraction(t *testing.T) {
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("resolve udp: %v", err)
	}
	serverConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer serverConn.Close()

	tlsCert, _ := generateTestCert(t, "node.example.com", "Caddy Local Authority", []string{"node.example.com"}, time.Now().Add(-1*time.Hour), time.Now().Add(12*time.Hour))

	// 启动一个使用标准库 tls.QUICServer 的最小 RFC 9001 模拟服务端
	go func() {
		buf := make([]byte, 4096)
		n, clientAddr, err := serverConn.ReadFromUDP(buf)
		if err != nil || n < 20 {
			return
		}
		datagram := buf[:n]
		// 解析客户端 DCID 派生 Initial Keys
		dcidLen := int(datagram[5])
		clientDCID := datagram[6 : 6+dcidLen]
		cInitKeys, _ := deriveQUICInitialKeys(clientDCID, true)
		sInitKeys, _ := deriveQUICInitialKeys(clientDCID, false)

		_, _, pktSCID, plain, _, uErr := unpackQUICLongHeaderPacket(datagram, cInitKeys, nil)
		if uErr != nil {
			return
		}
		chunks, _, fErr := extractQUICFrames(plain)
		if fErr != nil || len(chunks) == 0 {
			return
		}

		qsrv := tls.QUICServer(&tls.QUICConfig{
			TLSConfig: &tls.Config{
				Certificates: []tls.Certificate{tlsCert},
				NextProtos:   []string{"h3"},
				MinVersion:   tls.VersionTLS13,
			},
		})
		defer qsrv.Close()
		qsrv.SetTransportParameters(buildClientTransportParameters([]byte("srv-scid")))
		_ = qsrv.Start(context.Background())
		_ = qsrv.HandleData(tls.QUICEncryptionLevelInitial, chunks[0].data)

		var (
			srvInitCrypto []byte
			srvHsCrypto   []byte
			srvHsKeys     *quicKeys
		)
		for {
			ev := qsrv.NextEvent()
			if ev.Kind == tls.QUICNoEvent {
				break
			}
			switch ev.Kind {
			case tls.QUICSetWriteSecret:
				if ev.Level == tls.QUICEncryptionLevelHandshake {
					hk := deriveHandshakeKeysForSuite(ev.Suite, ev.Data)
					srvHsKeys = &hk
				}
			case tls.QUICWriteData:
				if ev.Level == tls.QUICEncryptionLevelInitial {
					srvInitCrypto = append(srvInitCrypto, ev.Data...)
				} else if ev.Level == tls.QUICEncryptionLevelHandshake {
					srvHsCrypto = append(srvHsCrypto, ev.Data...)
				}
			}
		}

		// 发送 Server Initial + Server Handshake
		var initFrame []byte
		initFrame = append(initFrame, 0x06, 0x00)
		initFrame = appendQUICVarint(initFrame, uint64(len(srvInitCrypto)))
		initFrame = append(initFrame, srvInitCrypto...)
		pktInit, _ := packQUICLongHeaderPacket(0x00, pktSCID, []byte("srv-scid"), 1, initFrame, sInitKeys, 0)

		var hsFrame []byte
		hsFrame = append(hsFrame, 0x06, 0x00)
		hsFrame = appendQUICVarint(hsFrame, uint64(len(srvHsCrypto)))
		hsFrame = append(hsFrame, srvHsCrypto...)
		pktHs, _ := packQUICLongHeaderPacket(0x02, pktSCID, []byte("srv-scid"), 1, hsFrame, *srvHsKeys, 0)

		combined := append(pktInit, pktHs...)
		_, _ = serverConn.WriteToUDP(combined, clientAddr)
	}()

	port := serverConn.LocalAddr().(*net.UDPAddr).Port
	certs, alpn, err := probeQUICv1Certificates(t.Context(), "127.0.0.1", port, "node.example.com", 2*time.Second)
	if err != nil {
		t.Fatalf("probeQUICv1Certificates failed: %v", err)
	}
	if len(certs) == 0 {
		t.Fatalf("expected non-empty QUIC certificates")
	}
	if certs[0].Subject.CommonName != "node.example.com" {
		t.Errorf("expected CN=node.example.com, got %s (alpn=%s)", certs[0].Subject.CommonName, alpn)
	}
	if !isSelfSignedOrInternalCA(certs[0]) {
		t.Errorf("expected Caddy Local Authority cert to be flagged as internal CA")
	}
}
