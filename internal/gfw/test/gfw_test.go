// 文件职责：针对 GFW 主动探测模拟器的离线纯内存表驱动单元测试（覆盖 QUIC v1 加解密、帧重组、TLS 证书判定、报告格式化与并发安全）。
package gfw_test

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
	"strings"
	"sync"
	"testing"
	"time"

	"singctl/internal/gfw"
)

func generateTestCertDER(t *testing.T, cn, issuerCN string, selfSigned bool, notAfter time.Time) (*x509.Certificate, []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	subj := pkix.Name{CommonName: cn}
	issuer := pkix.Name{CommonName: issuerCN, Organization: []string{"Test Public CA"}}
	if selfSigned {
		issuer = subj
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1001),
		Subject:      subj,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		DNSNames:     []string{cn},
	}
	parent := tmpl
	parentKey := priv
	if !selfSigned {
		caKey, kErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if kErr != nil {
			t.Fatal(kErr)
		}
		parent = &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               issuer,
			NotBefore:             time.Now().Add(-2 * time.Hour),
			NotAfter:              notAfter.Add(24 * time.Hour),
			IsCA:                  true,
			BasicConstraintsValid: true,
		}
		parentKey = caKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &priv.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return parsed, der
}

func buildTLS13CertMessage(certDERs ...[]byte) []byte {
	var list []byte
	for _, der := range certDERs {
		cLen := len(der)
		list = append(list, byte(cLen>>16), byte(cLen>>8), byte(cLen))
		list = append(list, der...)
		list = append(list, 0x00, 0x00) // empty extensions
	}
	var body []byte
	body = append(body, 0x00) // empty request_context
	lLen := len(list)
	body = append(body, byte(lLen>>16), byte(lLen>>8), byte(lLen))
	body = append(body, list...)

	var msg []byte
	msg = append(msg, 11) // Certificate Handshake Type
	mLen := len(body)
	msg = append(msg, byte(mLen>>16), byte(mLen>>8), byte(mLen))
	msg = append(msg, body...)
	return msg
}

func TestProbeOptions_PortDefaultsAndOverrides(t *testing.T) {
	tests := []struct {
		name      string
		ports     []int
		wantHTTP  int
		wantHTTPS int
	}{
		{name: "empty defaults", ports: nil, wantHTTP: 80, wantHTTPS: 443},
		{name: "single custom port", ports: []int{8443}, wantHTTP: 8443, wantHTTPS: 8443},
		{name: "dual ports", ports: []int{8080, 9443}, wantHTTP: 8080, wantHTTPS: 9443},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			opt := gfw.ProbeOptions{Ports: tc.ports}
			if got := opt.GetHTTPPort(); got != tc.wantHTTP {
				t.Fatalf("GetHTTPPort() = %d, want %d", got, tc.wantHTTP)
			}
			if got := opt.GetHTTPSPort(); got != tc.wantHTTPS {
				t.Fatalf("GetHTTPSPort() = %d, want %d", got, tc.wantHTTPS)
			}
		})
	}
}

func TestQUICVarint_RoundTripAndTruncatedBoundaries(t *testing.T) {
	values := []uint64{0, 1, 63, 64, 16383, 16384, 1073741823, 1073741824, (1 << 62) - 1}
	for _, v := range values {
		enc := gfw.AppendQUICVarint(nil, v)
		got, n := gfw.ReadQUICVarint(enc)
		if n != len(enc) || got != v {
			t.Fatalf("varint roundtrip(%d): got=(%d, %d), enc=%x", v, got, n, enc)
		}
		// Truncated buffer must return n=0 safely
		if len(enc) > 1 {
			if _, shortN := gfw.ReadQUICVarint(enc[:len(enc)-1]); shortN != 0 {
				t.Fatalf("expected truncated varint(%d) to return n=0, got %d", v, shortN)
			}
		}
	}
	if _, n := gfw.ReadQUICVarint(nil); n != 0 {
		t.Fatalf("expected empty slice ReadQUICVarint to return n=0, got %d", n)
	}
}

func TestQUICPacketPackUnpackAndFrames_RoundTripAndTamperGuards(t *testing.T) {
	dcid := []byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}
	scid := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}

	tp := gfw.BuildClientTransportParameters(scid)
	if !bytes.Contains(tp, scid) {
		t.Fatalf("expected client transport parameters to embed SCID")
	}

	cKeys, err := gfw.DeriveQUICInitialKeys(dcid, true)
	if err != nil {
		t.Fatal(err)
	}
	hsSecret := bytes.Repeat([]byte{0x42}, 48)
	hsKeys128 := gfw.DeriveHandshakeKeysForSuite(tls.TLS_AES_128_GCM_SHA256, hsSecret[:32])
	hsKeys256 := gfw.DeriveHandshakeKeysForSuite(tls.TLS_AES_256_GCM_SHA384, hsSecret)
	if hsKeys128.KeyLen() != 16 || hsKeys256.KeyLen() != 32 {
		t.Fatalf("unexpected handshake key lengths: %d / %d", hsKeys128.KeyLen(), hsKeys256.KeyLen())
	}

	// Build CRYPTO frame + PING frame inside Initial packet
	hello := []byte("client-hello-payload-for-offline-quic-test")
	var frames []byte
	frames = append(frames, 0x01) // PING
	frames = append(frames, 0x06) // CRYPTO
	frames = gfw.AppendQUICVarint(frames, 0)
	frames = gfw.AppendQUICVarint(frames, uint64(len(hello)))
	frames = append(frames, hello...)

	pkt, err := gfw.PackQUICLongHeaderPacket(0x00, dcid, scid, 1, frames, cKeys, 1200)
	if err != nil {
		t.Fatalf("PackQUICLongHeaderPacket failed: %v", err)
	}
	if len(pkt) < 1200 {
		t.Fatalf("expected Initial packet padded to >= 1200 bytes, got %d", len(pkt))
	}

	pktType, gotDCID, gotSCID, plain, consumed, err := gfw.UnpackQUICLongHeaderPacket(pkt, cKeys, nil)
	if err != nil {
		t.Fatalf("UnpackQUICLongHeaderPacket failed: %v", err)
	}
	if pktType != 0x00 || consumed != len(pkt) || !bytes.Equal(gotDCID, dcid) || !bytes.Equal(gotSCID, scid) {
		t.Fatalf("unexpected unpacked header: type=%d consumed=%d", pktType, consumed)
	}

	chunks, closeReason, err := gfw.ExtractQUICFrames(plain)
	if err != nil || closeReason != "" || len(chunks) != 1 || !bytes.Equal(chunks[0].Data, hello) {
		t.Fatalf("unexpected ExtractQUICFrames: chunks=%d reason=%q err=%v", len(chunks), closeReason, err)
	}

	// Handshake packet round-trip + missing handshake keys error
	hsPkt, err := gfw.PackQUICLongHeaderPacket(0x02, dcid, scid, 5, frames, hsKeys256, 200)
	if err != nil {
		t.Fatalf("PackQUICLongHeaderPacket(Handshake) failed: %v", err)
	}
	if _, _, _, _, _, err := gfw.UnpackQUICLongHeaderPacket(hsPkt, cKeys, nil); err == nil {
		t.Fatal("expected error when unpacking Handshake packet without hsKeys")
	}
	if _, _, _, hsPlain, _, err := gfw.UnpackQUICLongHeaderPacket(hsPkt, cKeys, &hsKeys256); err != nil || len(hsPlain) == 0 {
		t.Fatalf("expected valid Handshake packet unpack, err=%v", err)
	}

	// Tampered ciphertext and malformed boundaries
	tampered := bytes.Clone(pkt)
	tampered[len(tampered)-5] ^= 0xff
	if _, _, _, _, _, err := gfw.UnpackQUICLongHeaderPacket(tampered, cKeys, nil); err == nil {
		t.Fatal("expected GCM auth failure on tampered QUIC packet")
	}
	if _, _, _, _, _, err := gfw.UnpackQUICLongHeaderPacket([]byte{0x00, 1, 2}, cKeys, nil); err == nil {
		t.Fatal("expected short datagram error")
	}
	if _, _, _, _, _, err := gfw.UnpackQUICLongHeaderPacket([]byte{0x40, 1, 2, 3, 4, 5, 6, 7, 8}, cKeys, nil); err == nil {
		t.Fatal("expected short header rejection")
	}

	// CONNECTION_CLOSE frame (0x1c) and truncated CRYPTO frame
	closePayload := []byte{0x1c, 0x0a, 0x06, 0x04, 'b', 'a', 'd', '!'}
	_, reason, err := gfw.ExtractQUICFrames(closePayload)
	if err != nil || !strings.Contains(reason, "bad!") {
		t.Fatalf("expected CONNECTION_CLOSE reason containing 'bad!', got reason=%q err=%v", reason, err)
	}
	if _, _, err := gfw.ExtractQUICFrames([]byte{0x06, 0x00, 0x20, 'x'}); err == nil {
		t.Fatal("expected error on truncated CRYPTO frame")
	}
}

func TestCryptoReassembler_And_TLS13CertStreamParser(t *testing.T) {
	_, der := generateTestCertDER(t, "node.example.com", "Let's Encrypt E5", false, time.Now().Add(60*24*time.Hour))
	eeMsg := []byte{8, 0, 0, 2, 0x00, 0x00} // EncryptedExtensions (type 8, len 2)
	certMsg := buildTLS13CertMessage(der)
	fullStream := append(eeMsg, certMsg...)

	// Out-of-order push into CryptoReassembler
	r := gfw.NewCryptoReassembler()
	mid := len(fullStream) / 2
	r.Push(uint64(mid), fullStream[mid:])
	if got := r.PopContiguous(); got != nil {
		t.Fatalf("expected nil contiguous pop before offset 0 arrives, got %d bytes", len(got))
	}
	// Oversized offset beyond 256KiB cap must be ignored safely
	r.Push(300000, []byte("ignored"))

	r.Push(0, fullStream[:mid])
	contig := r.PopContiguous()
	if !bytes.Equal(contig, fullStream) {
		t.Fatalf("expected reassembled stream len=%d, got %d", len(fullStream), len(contig))
	}

	certs, complete := gfw.ParseTLS13CertificateMsgFromStream(r.AllSeen())
	if !complete || len(certs) != 1 || certs[0].Subject.CommonName != "node.example.com" {
		t.Fatalf("unexpected parsed certs: complete=%v len=%d", complete, len(certs))
	}

	// Partial stream containing full leaf cert + truncated second cert -> complete=false, leaf returned
	twoCertStream := buildTLS13CertMessage(der, der)
	partial := twoCertStream[:len(twoCertStream)-10]
	pCerts, pComplete := gfw.ParseTLS13CertificateMsgFromStream(partial)
	if pComplete || len(pCerts) != 1 {
		t.Fatalf("expected partial stream to return 1 cert and complete=false, got len=%d complete=%v", len(pCerts), pComplete)
	}
}

func TestCertHeuristics_Formatter_And_DetectorValidation(t *testing.T) {
	pubCert, _ := generateTestCertDER(t, "node.example.com", "R11", false, time.Now().Add(30*24*time.Hour))
	selfCert, _ := generateTestCertDER(t, "node.example.com", "node.example.com", true, time.Now().Add(30*24*time.Hour))
	caddyLocal, _ := generateTestCertDER(t, "node.example.com", "Caddy Local Authority - 2026 ECC Root", false, time.Now().Add(30*24*time.Hour))

	if gfw.IsSelfSignedOrInternalCA(pubCert) {
		t.Fatal("expected public CA cert to not be flagged as internal/self-signed")
	}
	if !gfw.IsSelfSignedOrInternalCA(selfCert) || !gfw.IsSelfSignedOrInternalCA(caddyLocal) || !gfw.IsSelfSignedOrInternalCA(nil) {
		t.Fatal("expected self-signed, Caddy Local, and nil certs to be flagged")
	}
	if got := gfw.CertIssuerDisplay(pubCert); got != "R11" {
		t.Fatalf("CertIssuerDisplay() = %q, want R11", got)
	}
	if !gfw.IsStandardRejectPayload([]byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28}) {
		t.Fatal("expected TLS Alert (0x15) to be recognized as standard reject payload")
	}
	if !gfw.IsStandardRejectPayload([]byte("HTTP/1.1 400 Bad Request\r\n\r\n")) {
		t.Fatal("expected HTTP 400 to be recognized as standard reject payload")
	}
	if gfw.IsStandardRejectPayload([]byte{0x88, 0x99, 0xaa, 0xbb}) {
		t.Fatal("expected random binary echo to NOT be recognized as standard reject payload")
	}

	// Detector input validation & canceled context
	detEmpty := gfw.NewDetector(gfw.ProbeOptions{})
	if _, err := detEmpty.Run(t.Context()); err == nil {
		t.Fatal("expected error when TargetIP is empty")
	}
	cancelCtx, cancel := context.WithCancel(t.Context())
	cancel()
	detCanceled := gfw.NewDetector(gfw.ProbeOptions{IP: "127.0.0.1", Ports: []int{1}, Timeout: 20 * time.Millisecond})
	if _, err := detCanceled.Run(cancelCtx); err == nil {
		t.Fatal("expected error when context is pre-canceled")
	}

	// Formatter output (text + JSON) + concurrent safety
	sampleReport := &gfw.Report{
		TargetIP:        "192.0.2.10",
		TargetSNI:       "www.example.com",
		TargetDomain:    "node.example.com",
		ScanTime:        time.Now(),
		TotalScore:      12,
		RiskLevel:       gfw.RiskLevelClean,
		Categories:      []gfw.Category{{Name: "TLS", Score: 12, MaxScore: 35, Items: []gfw.CheckItem{{Name: "Alert", Score: 12, MaxScore: 12, Passed: false, Details: "missing alert"}}}},
		Findings:        []string{"[+12分] Alert: missing alert"},
		Recommendations: []string{"• [Alert] enable standard alert"},
	}

	var wg sync.WaitGroup
	for range 6 {
		wg.Go(func() {
			var textBuf, jsonBuf bytes.Buffer
			if err := gfw.PrintReport(&textBuf, sampleReport, true); err != nil || !strings.Contains(textBuf.String(), "192.0.2.10") {
				t.Errorf("PrintReport failed: %v", err)
			}
			if err := gfw.PrintJSONReport(&jsonBuf, sampleReport); err != nil || !strings.Contains(jsonBuf.String(), `"target_ip": "192.0.2.10"`) {
				t.Errorf("PrintJSONReport failed: %v", err)
			}
		})
	}
	wg.Wait()
}
