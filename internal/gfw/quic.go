package gfw

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"hash"
	"net"
	"strings"
	"time"
)

// probeQUIC 探测 UDP / QUIC 协议画像（满分 15 分 - 针对 Hysteria2 / HTTP3）
func probeQUIC(ctx context.Context, opts ProbeOptions) Category {
	cat := Category{
		Name:     "UDP / QUIC (Hysteria2) 协议探测",
		MaxScore: 15,
		Items:    make([]CheckItem, 0, 2),
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	httpsPort := opts.GetHTTPSPort()

	// 1. 畸形 QUIC 版本协商与随机高熵防反射探测 (MaxScore: 5)
	itemQUICBase := CheckItem{
		Name:        fmt.Sprintf("UDP %d QUIC 版本协商与防反射基准探测", httpsPort),
		Description: fmt.Sprintf("向 UDP %d 发送保留版本 (0x1a2a3a4a) 与 64B 高熵包，检验 RFC 9000 规范性", httpsPort),
		MaxScore:    5,
	}

	quicResponsive, isAbnormal, vnDetails := testQUICInitialPacket(ctx, opts.IP, httpsPort, timeout)
	udpEcho, udpMsg := testUDPEntropy(ctx, opts.IP, httpsPort, 1200*time.Millisecond)

	if !quicResponsive {
		itemQUICBase.Score = 0
		itemQUICBase.Passed = true
		itemQUICBase.Details = vnDetails
	} else if isAbnormal {
		itemQUICBase.Score = 5
		itemQUICBase.Passed = false
		itemQUICBase.Details = vnDetails
		itemQUICBase.Mitigation = "检查 UDP/QUIC 端口暴露情况，确保采用符合 RFC 9000 的标准 QUIC 协议栈。"
	} else if udpEcho {
		itemQUICBase.Score = 4
		itemQUICBase.Passed = false
		itemQUICBase.Details = udpMsg
		itemQUICBase.Mitigation = "确保 UDP 端口静默丢弃短于 1200 字节的未格式化随机 UDP 报文，防止反射放大与特征暴露。"
	} else {
		itemQUICBase.Score = 0
		itemQUICBase.Passed = true
		itemQUICBase.Details = fmt.Sprintf("%s；且对 64B 随机高熵包静默丢弃。", vnDetails)
	}
	cat.Items = append(cat.Items, itemQUICBase)

	// 2. 真实 QUIC v1 (ALPN: h3) 加密握手与 TCP/UDP 双栈证书脑裂比对 (MaxScore: 10)
	itemQUICHandshake := CheckItem{
		Name:        fmt.Sprintf("UDP %d 真实 QUIC v1 (h3) 握手与双栈证书一致性", httpsPort),
		Description: "发起 RFC 9001 QUIC v1 Initial (ALPN: h3) 真实 TLS 1.3 握手，校验 UDP 证书真伪并与 TCP 443 比对是否脑裂",
		MaxScore:    10,
	}

	if !quicResponsive {
		itemQUICHandshake.Score = 0
		itemQUICHandshake.Passed = true
		itemQUICHandshake.Details = fmt.Sprintf("UDP %d 未开启 QUIC 服务，无需执行 H3 证书脑裂比对。", httpsPort)
	} else {
		targetSNI := opts.Domain
		if targetSNI == "" {
			targetSNI = opts.SNI
		}
		pass, score, details, mitigation := testQUICv1HandshakeAndSplitBrain(ctx, opts.IP, httpsPort, targetSNI, timeout)
		itemQUICHandshake.Passed = pass
		itemQUICHandshake.Score = score
		itemQUICHandshake.Details = details
		itemQUICHandshake.Mitigation = mitigation
	}
	cat.Items = append(cat.Items, itemQUICHandshake)

	for _, it := range cat.Items {
		cat.Score += it.Score
	}
	if cat.Score > cat.MaxScore {
		cat.Score = cat.MaxScore
	}

	return cat
}

// testQUICv1HandshakeAndSplitBrain 执行真实 QUIC v1 (0x00000001) TLS 1.3 握手并与 TCP 证书比对
func testQUICv1HandshakeAndSplitBrain(ctx context.Context, ip string, port int, serverName string, timeout time.Duration) (bool, int, string, string) {
	sni := serverName
	if sni == "" {
		sni = "localhost"
	}

	quicCerts, quicALPN, quicErr := ProbeQUICv1Certificates(ctx, ip, port, sni, timeout)
	if quicErr != nil {
		return false, 10, fmt.Sprintf("UDP %d 响应了 QUIC 版本协商，但真实 QUIC v1 (h3, SNI=%s) 加密握手失败: %v！极可能是 Hysteria2 证书缺失或失效！",
			port, sni, quicErr), "检查 /etc/sing-box/config.json 中 HYSTERIA2 的 certificate_path 是否指向有效的 Let's Encrypt/ZeroSSL 证书并重启 sing-box。"
	}

	if len(quicCerts) == 0 {
		return false, 10, fmt.Sprintf("UDP %d 完成 QUIC Initial 响应但未返回任何服务端证书 (SNI=%s)", port, sni),
			"检查 Hysteria2 TLS 证书与私钥配置完整性。"
	}

	udpLeaf := quicCerts[0]
	udpIssuer := certIssuerDisplay(udpLeaf)

	// 1. 若用户提供了域名，或者即便未提供域名也检查是否暴露了 Caddy Local Authority 自签/过期证书
	if IsSelfSignedOrInternalCA(udpLeaf) {
		return false, 10, fmt.Sprintf("UDP %d (QUIC/H3) 暴露了内部自签证书 (CN: %s, Issuer: %s)！客户端在 insecure=0 下将无法连接且极易被主动探测识别！",
			port, udpLeaf.Subject.CommonName, udpIssuer), "严禁在 Hysteria2 中使用 Caddy local 自签证书，请将其修正为 ACME 公共 CA 证书路径。"
	}
	if time.Now().After(udpLeaf.NotAfter) {
		return false, 10, fmt.Sprintf("UDP %d (QUIC/H3) 证书已于 %s 过期 (CN: %s)！说明证书续期后未重载 sing-box！",
			port, udpLeaf.NotAfter.Format("2006-01-02"), udpLeaf.Subject.CommonName), "重启或重载 sing-box 服务以加载 Caddy 续签后的最新证书。"
	}

	// 2. TCP 443 vs UDP 443 双栈证书脑裂比对 (Cross-Transport Split-Brain Check)
	tcpSNI := serverName
	if tcpSNI == "" && udpLeaf.Subject.CommonName != "" {
		tcpSNI = udpLeaf.Subject.CommonName
	}
	chainForVerify := quicCerts
	if tcpCerts, tcpErr := probeTLSCertificate(ctx, ip, port, tcpSNI, timeout); tcpErr == nil && len(tcpCerts) > 0 {
		tcpLeaf := tcpCerts[0]
		udpSum := sha256.Sum256(udpLeaf.Raw)
		tcpSum := sha256.Sum256(tcpLeaf.Raw)
		if udpSum != tcpSum {
			return false, 10, fmt.Sprintf("检测到 TCP %d 与 UDP %d 双栈证书脑裂不一致！(TCP CN=%s [Issuer: %s] vs UDP CN=%s [Issuer: %s])，直接暴露独立 UDP 代理后端！",
					port, port, tcpLeaf.Subject.CommonName, certIssuerDisplay(tcpLeaf), udpLeaf.Subject.CommonName, udpIssuer),
				"确保 Hysteria2 与 Caddy HTTPS 共用同一张最新 ACME 证书文件，并在 Caddy 续期后自动同步重载 sing-box。"
		}
		if len(chainForVerify) == 1 && len(tcpCerts) > 1 {
			chainForVerify = append(chainForVerify, tcpCerts[1:]...)
		}
	}

	if serverName != "" && net.ParseIP(serverName) == nil {
		if caOK, caReason := verifyCertificateChain(chainForVerify, serverName); !caOK {
			return false, 10, fmt.Sprintf("UDP %d (QUIC/H3) 证书未通过 CA 信任链校验 (%s, CN: %s, Issuer: %s)",
				port, caReason, udpLeaf.Subject.CommonName, udpIssuer), "确保 Hysteria2 证书域名与节点业务域名 (--domain) 完全一致且由公共 CA 签发。"
		}
	}

	return true, 0, fmt.Sprintf("UDP %d 真实 QUIC v1 (ALPN: %s) 握手通过，证书链有效且与 TCP %d 双栈完全一致 (CN: %s, Issuer: %s)。",
		port, cmpOrString(quicALPN, "h3"), port, udpLeaf.Subject.CommonName, udpIssuer), ""
}

func cmpOrString(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// ── 纯标准库 RFC 9000 / RFC 9001 QUIC v1 握手探针实现（零第三方依赖） ──

var quicV1InitialSalt = []byte{
	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
	0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
	0xcc, 0xbb, 0x7f, 0x0a,
}

type QuicKeys struct {
	key []byte
	iv  []byte
	hp  []byte
}

func DeriveQUICInitialKeys(dcid []byte, isClient bool) (QuicKeys, error) {
	initialSecret := hkdfExtract(sha256.New, dcid, quicV1InitialSalt)
	label := "server in"
	if isClient {
		label = "client in"
	}
	secret := hkdfExpandLabel(sha256.New, initialSecret, label, nil, 32)
	return deriveQUICKeysFromSecret(sha256.New, secret, 16), nil
}

func deriveQUICKeysFromSecret(hashFn func() hash.Hash, secret []byte, keyLen int) QuicKeys {
	return QuicKeys{
		key: hkdfExpandLabel(hashFn, secret, "quic key", nil, keyLen),
		iv:  hkdfExpandLabel(hashFn, secret, "quic iv", nil, 12),
		hp:  hkdfExpandLabel(hashFn, secret, "quic hp", nil, 16),
	}
}

func hkdfExtract(hashFn func() hash.Hash, secret, salt []byte) []byte {
	mac := hmac.New(hashFn, salt)
	mac.Write(secret)
	return mac.Sum(nil)
}

func hkdfExpandLabel(hashFn func() hash.Hash, secret []byte, label string, context []byte, length int) []byte {
	fullLabel := "tls13 " + label
	hkdfLabel := make([]byte, 0, 2+1+len(fullLabel)+1+len(context))
	hkdfLabel = append(hkdfLabel, byte(length>>8), byte(length))
	hkdfLabel = append(hkdfLabel, byte(len(fullLabel)))
	hkdfLabel = append(hkdfLabel, []byte(fullLabel)...)
	hkdfLabel = append(hkdfLabel, byte(len(context)))
	hkdfLabel = append(hkdfLabel, context...)

	var out []byte
	var prev []byte
	counter := byte(1)
	for len(out) < length {
		mac := hmac.New(hashFn, secret)
		mac.Write(prev)
		mac.Write(hkdfLabel)
		mac.Write([]byte{counter})
		prev = mac.Sum(nil)
		out = append(out, prev...)
		counter++
	}
	return out[:length]
}

// probeQUICv1Certificates 使用标准库 crypto/tls.QUICClient 发起 QUIC v1 握手并提取服务端 X.509 证书链
func ProbeQUICv1Certificates(ctx context.Context, ip string, port int, serverName string, timeout time.Duration) ([]*x509.Certificate, string, error) {
	raddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(ip, fmt.Sprintf("%d", port)))
	if err != nil {
		return nil, "", err
	}

	var d net.Dialer
	connRaw, err := d.DialContext(ctx, "udp", raddr.String())
	if err != nil {
		return nil, "", err
	}
	defer connRaw.Close()
	_ = connRaw.SetDeadline(time.Now().Add(timeout))

	dcid := make([]byte, 8)
	scid := make([]byte, 8)
	_, _ = rand.Read(dcid)
	_, _ = rand.Read(scid)

	qconn := tls.QUICClient(&tls.QUICConfig{
		TLSConfig: &tls.Config{
			ServerName:         serverName,
			NextProtos:         []string{"h3"},
			MinVersion:         tls.VersionTLS13,
			CurvePreferences:   []tls.CurveID{tls.X25519, tls.CurveP256},
			InsecureSkipVerify: true,
		},
	})
	defer qconn.Close()

	qconn.SetTransportParameters(BuildClientTransportParameters(scid))
	if err := qconn.Start(ctx); err != nil {
		return nil, "", err
	}

	var clientHello []byte
	for {
		ev := qconn.NextEvent()
		if ev.Kind == tls.QUICNoEvent {
			break
		}
		if ev.Kind == tls.QUICWriteData && ev.Level == tls.QUICEncryptionLevelInitial {
			clientHello = append(clientHello, ev.Data...)
		}
	}
	if len(clientHello) == 0 {
		return nil, "", fmt.Errorf("empty QUIC ClientHello")
	}

	cKeys, err := DeriveQUICInitialKeys(dcid, true)
	if err != nil {
		return nil, "", err
	}
	sInitKeys, err := DeriveQUICInitialKeys(dcid, false)
	if err != nil {
		return nil, "", err
	}

	// 封装 CRYPTO 帧 (0x06 + offset(0) + varint(len) + clientHello)
	cryptoFrame := make([]byte, 0, 4+len(clientHello))
	cryptoFrame = append(cryptoFrame, 0x06, 0x00)
	cryptoFrame = AppendQUICVarint(cryptoFrame, uint64(len(clientHello)))
	cryptoFrame = append(cryptoFrame, clientHello...)

	initialPkt, err := PackQUICLongHeaderPacket(0x00, dcid, scid, 1, cryptoFrame, cKeys, 1200)
	if err != nil {
		return nil, "", err
	}
	if _, err := connRaw.Write(initialPkt); err != nil {
		return nil, "", err
	}

	var (
		hsKeys        *QuicKeys
		serverSCID    []byte
		initStream    = newCryptoReassembler()
		hsStream      = newCryptoReassembler()
		receivedCerts []*x509.Certificate
		negotiated    string
		sentAck       bool
	)

	recvBuf := make([]byte, 65535)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		n, rErr := connRaw.Read(recvBuf)
		if rErr != nil {
			if len(receivedCerts) > 0 {
				return receivedCerts, negotiated, nil
			}
			return nil, "", rErr
		}

		datagram := recvBuf[:n]
		for len(datagram) > 0 {
			pktType, pktDCID, pktSCID, plainPayload, consumed, uErr := UnpackQUICLongHeaderPacket(datagram, sInitKeys, hsKeys)
			if consumed <= 0 {
				break
			}
			datagram = datagram[consumed:]
			if uErr != nil {
				continue
			}
			_ = pktDCID
			if len(pktSCID) > 0 && len(serverSCID) == 0 {
				serverSCID = append([]byte(nil), pktSCID...)
			}

			// 解析帧列表中的 CRYPTO (0x06) 或 CONNECTION_CLOSE (0x1c)
			cryptoChunks, closeReason, fErr := ExtractQUICFrames(plainPayload)
			if closeReason != "" {
				return nil, "", fmt.Errorf("server closed QUIC connection: %s", closeReason)
			}
			if fErr != nil {
				continue
			}

			for _, ch := range cryptoChunks {
				if pktType == 0x00 { // Initial
					initStream.push(ch.offset, ch.Data)
				} else if pktType == 0x02 { // Handshake
					hsStream.push(ch.offset, ch.Data)
				}
			}

			if avail := initStream.popContiguous(); len(avail) > 0 {
				if err := qconn.HandleData(tls.QUICEncryptionLevelInitial, avail); err != nil {
					return nil, "", fmt.Errorf("initial TLS error: %w", err)
				}
			}

			// 处理 QUICClient 事件（重点捕获 Handshake Read Secret）
			for {
				ev := qconn.NextEvent()
				if ev.Kind == tls.QUICNoEvent {
					break
				}
				switch ev.Kind {
				case tls.QUICSetReadSecret:
					if ev.Level == tls.QUICEncryptionLevelHandshake {
						hk := DeriveHandshakeKeysForSuite(ev.Suite, ev.Data)
						hsKeys = &hk
					}
				case tls.QUICHandshakeDone:
					st := qconn.ConnectionState()
					return st.PeerCertificates, st.NegotiatedProtocol, nil
				}
			}

			if hsKeys != nil {
				if avail := hsStream.popContiguous(); len(avail) > 0 {
					_ = qconn.HandleData(tls.QUICEncryptionLevelHandshake, avail)
					for {
						ev := qconn.NextEvent()
						if ev.Kind == tls.QUICNoEvent {
							break
						}
						if ev.Kind == tls.QUICHandshakeDone {
							st := qconn.ConnectionState()
							return st.PeerCertificates, st.NegotiatedProtocol, nil
						}
					}
					st := qconn.ConnectionState()
					if len(st.PeerCertificates) > 0 {
						return st.PeerCertificates, st.NegotiatedProtocol, nil
					}
					certs, complete := parseTLS13CertificateMsgFromStream(hsStream.allSeen())
					if len(certs) > 0 {
						receivedCerts = certs
						negotiated = cmpOrString(st.NegotiatedProtocol, "h3")
						if complete {
							return receivedCerts, negotiated, nil
						}
						// 已拿到叶子证书但中间证书链仍在后续 UDP 分片途中，缩短等待窗口收齐后续包
						_ = connRaw.SetDeadline(time.Now().Add(400 * time.Millisecond))
					}
				}
			}
		}

		// 若收到了 Server Initial 但证书较大被 RFC 9000 3x 防放大限制截断，回发一个 1200B 客户端 Initial ACK 解锁后续 Handshake 包
		if !sentAck && len(serverSCID) > 0 {
			sentAck = true
			// ACK Frame (0x02): Largest Acknowledged=0, ACK Delay=0, ACK Range Count=0, First ACK Range=0
			ackFrame := []byte{0x02, 0x00, 0x00, 0x00, 0x00}
			sKeysForNewDCID := cKeys
			if ackPkt, aErr := PackQUICLongHeaderPacket(0x00, serverSCID, scid, 2, ackFrame, sKeysForNewDCID, 1200); aErr == nil {
				_, _ = connRaw.Write(ackPkt)
			}
		}
	}

	if certs, _ := parseTLS13CertificateMsgFromStream(hsStream.allSeen()); len(certs) > 0 {
		return certs, cmpOrString(negotiated, "h3"), nil
	}
	return nil, "", fmt.Errorf("QUIC handshake timed out waiting for server Certificate")
}

func DeriveHandshakeKeysForSuite(suite uint16, secret []byte) QuicKeys {
	if suite == tls.TLS_AES_256_GCM_SHA384 {
		return deriveQUICKeysFromSecret(sha512.New384, secret, 32)
	}
	return deriveQUICKeysFromSecret(sha256.New, secret, 16)
}

func BuildClientTransportParameters(scid []byte) []byte {
	var b []byte
	// max_idle_timeout (0x01) = 10000ms
	b = appendTPVarint(b, 0x01, 10000)
	// initial_max_data (0x04) = 1048576
	b = appendTPVarint(b, 0x04, 1048576)
	// initial_max_stream_data_bidi_local (0x05) = 524288
	b = appendTPVarint(b, 0x05, 524288)
	// initial_max_stream_data_bidi_remote (0x06) = 524288
	b = appendTPVarint(b, 0x06, 524288)
	// initial_max_stream_data_uni (0x07) = 524288
	b = appendTPVarint(b, 0x07, 524288)
	// initial_max_streams_bidi (0x08) = 100
	b = appendTPVarint(b, 0x08, 100)
	// initial_max_streams_uni (0x09) = 100
	b = appendTPVarint(b, 0x09, 100)
	// initial_source_connection_id (0x0f) = scid
	b = AppendQUICVarint(b, 0x0f)
	b = AppendQUICVarint(b, uint64(len(scid)))
	b = append(b, scid...)
	return b
}

func appendTPVarint(b []byte, id uint64, val uint64) []byte {
	var valBuf []byte
	valBuf = AppendQUICVarint(valBuf, val)
	b = AppendQUICVarint(b, id)
	b = AppendQUICVarint(b, uint64(len(valBuf)))
	b = append(b, valBuf...)
	return b
}

func AppendQUICVarint(b []byte, v uint64) []byte {
	switch {
	case v <= 63:
		return append(b, byte(v))
	case v <= 16383:
		return append(b, byte(0x40|(v>>8)), byte(v))
	case v <= 1073741823:
		return append(b, byte(0x80|(v>>24)), byte(v>>16), byte(v>>8), byte(v))
	default:
		return append(b, byte(0xc0|(v>>56)), byte(v>>48), byte(v>>40), byte(v>>32), byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	}
}

func readQUICVarint(b []byte) (uint64, int) {
	if len(b) == 0 {
		return 0, 0
	}
	prefix := b[0] >> 6
	length := 1 << prefix
	if len(b) < length {
		return 0, 0
	}
	val := uint64(b[0] & 0x3f)
	for i := 1; i < length; i++ {
		val = (val << 8) | uint64(b[i])
	}
	return val, length
}

func PackQUICLongHeaderPacket(pktType byte, dcid, scid []byte, pktNum uint32, payload []byte, keys QuicKeys, minTotalSize int) ([]byte, error) {
	// Long Header: 1(fixed=1)|1(long=1)|2(type)|2(reserved=0)|2(pnLen=1 -> 2 bytes PN)
	firstByte := byte(0xc0 | ((pktType & 0x03) << 4) | 0x01)
	var hdr []byte
	hdr = append(hdr, firstByte)
	hdr = append(hdr, 0x00, 0x00, 0x00, 0x01) // QUIC v1
	hdr = append(hdr, byte(len(dcid)))
	hdr = append(hdr, dcid...)
	hdr = append(hdr, byte(len(scid)))
	hdr = append(hdr, scid...)
	if pktType == 0x00 {
		// Initial packet includes Token Length (0)
		hdr = append(hdr, 0x00)
	}

	// 计算需填充的 PADDING (0x00) 长度以达到 1200 字节
	pnBytes := []byte{byte(pktNum >> 8), byte(pktNum)}
	overhead := len(hdr) + 2 + len(pnBytes) + 16 // 2 bytes for Length varint, 16 bytes for GCM tag
	if len(payload)+overhead < minTotalSize {
		padLen := minTotalSize - (len(payload) + overhead)
		padding := make([]byte, padLen)
		payload = append(payload, padding...)
	}

	remLen := len(pnBytes) + len(payload) + 16
	// Always encode Length as 2-byte varint (0x4000 | remLen)
	hdr = append(hdr, byte(0x40|(remLen>>8)), byte(remLen))
	pnOffset := len(hdr)
	hdr = append(hdr, pnBytes...)

	block, err := aes.NewCipher(keys.key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, len(keys.iv))
	copy(nonce, keys.iv)
	binary.BigEndian.PutUint64(nonce[len(nonce)-8:], binary.BigEndian.Uint64(nonce[len(nonce)-8:])^uint64(pktNum))

	ciphertext := aead.Seal(nil, nonce, payload, hdr)
	pkt := append(hdr, ciphertext...)

	// Header Protection (RFC 9001 Section 5.4.1)
	hpBlock, err := aes.NewCipher(keys.hp)
	if err != nil {
		return nil, err
	}
	sampleOffset := pnOffset + 4
	if sampleOffset+16 > len(pkt) {
		return nil, fmt.Errorf("packet too short for header protection sample")
	}
	var mask [16]byte
	hpBlock.Encrypt(mask[:], pkt[sampleOffset:sampleOffset+16])
	pkt[0] ^= mask[0] & 0x0f
	for i := range 2 {
		pkt[pnOffset+i] ^= mask[1+i]
	}

	return pkt, nil
}

func UnpackQUICLongHeaderPacket(datagram []byte, initKeys QuicKeys, hsKeys *QuicKeys) (byte, []byte, []byte, []byte, int, error) {
	if len(datagram) < 7 {
		return 0, nil, nil, nil, len(datagram), fmt.Errorf("short datagram")
	}
	if (datagram[0] & 0x80) == 0 {
		// Short header packet (1-RTT), skip rest of datagram
		return 0, nil, nil, nil, len(datagram), fmt.Errorf("short header")
	}

	pktType := (datagram[0] & 0x30) >> 4
	idx := 5 // skip first byte + 4-byte version
	dcidLen := int(datagram[idx])
	idx++
	if idx+dcidLen >= len(datagram) {
		return 0, nil, nil, nil, len(datagram), fmt.Errorf("invalid dcid")
	}
	dcid := datagram[idx : idx+dcidLen]
	idx += dcidLen

	scidLen := int(datagram[idx])
	idx++
	if idx+scidLen >= len(datagram) {
		return 0, nil, nil, nil, len(datagram), fmt.Errorf("invalid scid")
	}
	scid := datagram[idx : idx+scidLen]
	idx += scidLen

	if pktType == 0x00 {
		tokLen, n := readQUICVarint(datagram[idx:])
		if n == 0 || idx+n+int(tokLen) >= len(datagram) {
			return 0, nil, nil, nil, len(datagram), fmt.Errorf("invalid token")
		}
		idx += n + int(tokLen)
	}

	remLen, n := readQUICVarint(datagram[idx:])
	if n == 0 {
		return 0, nil, nil, nil, len(datagram), fmt.Errorf("invalid length")
	}
	idx += n
	pnOffset := idx
	totalPktLen := pnOffset + int(remLen)
	if totalPktLen > len(datagram) {
		return 0, nil, nil, nil, len(datagram), fmt.Errorf("truncated packet")
	}

	var keys QuicKeys
	switch pktType {
	case 0x00:
		keys = initKeys
	case 0x02:
		if hsKeys == nil {
			return pktType, dcid, scid, nil, totalPktLen, fmt.Errorf("missing handshake keys")
		}
		keys = *hsKeys
	default:
		return pktType, dcid, scid, nil, totalPktLen, fmt.Errorf("unsupported long packet type %d", pktType)
	}

	pktCopy := make([]byte, totalPktLen)
	copy(pktCopy, datagram[:totalPktLen])

	sampleOffset := pnOffset + 4
	if sampleOffset+16 > len(pktCopy) {
		return pktType, dcid, scid, nil, totalPktLen, fmt.Errorf("short sample")
	}
	hpBlock, err := aes.NewCipher(keys.hp)
	if err != nil {
		return pktType, dcid, scid, nil, totalPktLen, err
	}
	var mask [16]byte
	hpBlock.Encrypt(mask[:], pktCopy[sampleOffset:sampleOffset+16])
	pktCopy[0] ^= mask[0] & 0x0f
	pnLen := int(pktCopy[0]&0x03) + 1
	var pktNum uint64
	for i := range pnLen {
		pktCopy[pnOffset+i] ^= mask[1+i]
		pktNum = (pktNum << 8) | uint64(pktCopy[pnOffset+i])
	}

	hdr := pktCopy[:pnOffset+pnLen]
	ciphertext := pktCopy[pnOffset+pnLen:]

	block, err := aes.NewCipher(keys.key)
	if err != nil {
		return pktType, dcid, scid, nil, totalPktLen, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return pktType, dcid, scid, nil, totalPktLen, err
	}

	nonce := make([]byte, len(keys.iv))
	copy(nonce, keys.iv)
	binary.BigEndian.PutUint64(nonce[len(nonce)-8:], binary.BigEndian.Uint64(nonce[len(nonce)-8:])^pktNum)

	plain, err := aead.Open(nil, nonce, ciphertext, hdr)
	if err != nil {
		return pktType, dcid, scid, nil, totalPktLen, err
	}

	return pktType, dcid, scid, plain, totalPktLen, nil
}

type CryptoChunk struct {
	offset uint64
	Data   []byte
}

func ExtractQUICFrames(plain []byte) ([]CryptoChunk, string, error) {
	var chunks []CryptoChunk
	idx := 0
	for idx < len(plain) {
		frameType, n := readQUICVarint(plain[idx:])
		if n == 0 {
			break
		}
		idx += n
		switch frameType {
		case 0x00, 0x01: // PADDING or PING
			continue
		case 0x02, 0x03: // ACK
			_, n1 := readQUICVarint(plain[idx:])
			idx += n1
			_, n2 := readQUICVarint(plain[idx:])
			idx += n2
			rngCount, n3 := readQUICVarint(plain[idx:])
			idx += n3
			_, n4 := readQUICVarint(plain[idx:])
			idx += n4
			for range rngCount {
				_, ng := readQUICVarint(plain[idx:])
				idx += ng
				_, na := readQUICVarint(plain[idx:])
				idx += na
			}
			if frameType == 0x03 {
				for range 3 {
					_, ne := readQUICVarint(plain[idx:])
					idx += ne
				}
			}
		case 0x06: // CRYPTO
			offset, n1 := readQUICVarint(plain[idx:])
			idx += n1
			length, n2 := readQUICVarint(plain[idx:])
			idx += n2
			if n1 == 0 || n2 == 0 || idx+int(length) > len(plain) {
				return chunks, "", fmt.Errorf("invalid CRYPTO frame")
			}
			chunks = append(chunks, CryptoChunk{
				offset: offset,
				Data:   plain[idx : idx+int(length)],
			})
			idx += int(length)
		case 0x1c, 0x1d: // CONNECTION_CLOSE
			errCode, n1 := readQUICVarint(plain[idx:])
			idx += n1
			if frameType == 0x1c {
				_, nf := readQUICVarint(plain[idx:])
				idx += nf
			}
			rLen, n2 := readQUICVarint(plain[idx:])
			idx += n2
			reason := ""
			if idx+int(rLen) <= len(plain) {
				reason = string(plain[idx : idx+int(rLen)])
			}
			return chunks, fmt.Sprintf("error_code=0x%x (%s)", errCode, reason), nil
		default:
			// 其他未知帧提前结束解析当前包
			return chunks, "", nil
		}
	}
	return chunks, "", nil
}

type cryptoReassembler struct {
	buf      []byte
	received []bool
	readOff  int
}

func newCryptoReassembler() *cryptoReassembler {
	return &cryptoReassembler{}
}

func (r *cryptoReassembler) push(offset uint64, data []byte) {
	end := int(offset) + len(data)
	if end > 262144 {
		return
	}
	if end > len(r.buf) {
		newBuf := make([]byte, end)
		copy(newBuf, r.buf)
		r.buf = newBuf
		newRec := make([]bool, end)
		copy(newRec, r.received)
		r.received = newRec
	}
	copy(r.buf[int(offset):end], data)
	for i := int(offset); i < end; i++ {
		r.received[i] = true
	}
}

func (r *cryptoReassembler) popContiguous() []byte {
	start := r.readOff
	for r.readOff < len(r.received) && r.received[r.readOff] {
		r.readOff++
	}
	if r.readOff == start {
		return nil
	}
	return r.buf[start:r.readOff]
}

func (r *cryptoReassembler) allSeen() []byte {
	return r.buf[:r.readOff]
}

// parseTLS13CertificateMsgFromStream 直接从重组后的 TLS 1.3 Handshake 流中提取 Certificate 消息 (MsgType == 11)。
// 返回解析到的证书列表以及整个 Certificate 消息是否已完整到达。
func parseTLS13CertificateMsgFromStream(stream []byte) ([]*x509.Certificate, bool) {
	idx := 0
	for idx+4 <= len(stream) {
		msgType := stream[idx]
		msgLen := int(stream[idx+1])<<16 | int(stream[idx+2])<<8 | int(stream[idx+3])
		idx += 4
		if msgType != 11 {
			if idx+msgLen > len(stream) {
				break
			}
			idx += msgLen
			continue
		}

		complete := idx+msgLen <= len(stream)
		endMsg := idx + msgLen
		if endMsg > len(stream) {
			endMsg = len(stream)
		}
		body := stream[idx:endMsg]
		if len(body) < 4 {
			break
		}
		ctxLen := int(body[0])
		if 1+ctxLen+3 > len(body) {
			break
		}
		p := 1 + ctxLen
		listLen := int(body[p])<<16 | int(body[p+1])<<8 | int(body[p+2])
		p += 3
		end := p + listLen
		if end > len(body) {
			end = len(body)
			complete = false
		}
		var certs []*x509.Certificate
		for p+3 <= end {
			cLen := int(body[p])<<16 | int(body[p+1])<<8 | int(body[p+2])
			p += 3
			if p+cLen > end {
				complete = false
				break
			}
			if cert, err := x509.ParseCertificate(body[p : p+cLen]); err == nil {
				certs = append(certs, cert)
			}
			p += cLen
			if p+2 > end {
				break
			}
			extLen := int(body[p])<<8 | int(body[p+1])
			p += 2 + extLen
		}
		if len(certs) > 0 {
			return certs, complete
		}
		break
	}
	return nil, false
}

// testQUICInitialPacket 构造并发送测试 QUIC Initial 数据包 (保留版本 0x1a2a3a4a)
func testQUICInitialPacket(ctx context.Context, ip string, port int, timeout time.Duration) (bool, bool, string) {
	raddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(ip, fmt.Sprintf("%d", port)))
	if err != nil {
		return false, false, fmt.Sprintf("解析 UDP 地址失败: %v", err)
	}

	var d net.Dialer
	connRaw, err := d.DialContext(ctx, "udp", raddr.String())
	if err != nil {
		return false, false, fmt.Sprintf("创建 UDP Socket 失败: %v", err)
	}
	defer connRaw.Close()

	conn, ok := connRaw.(*net.UDPConn)
	if !ok {
		return false, false, "非 UDP 套接字"
	}

	_ = conn.SetDeadline(time.Now().Add(timeout))

	quicProbe := []byte{
		0xc0,                   // Long Header (Initial)
		0x1a, 0x2a, 0x3a, 0x4a, // Unsupported reserved version for negotiation testing
		0x08, // DCID Length: 8
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x08, // SCID Length: 8
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
	}
	padding := make([]byte, 1200-len(quicProbe))
	_, _ = rand.Read(padding)
	packet := append(quicProbe, padding...)

	if _, err := conn.Write(packet); err != nil {
		return false, false, fmt.Sprintf("发送 QUIC 探测包失败: %v", err)
	}

	recvBuf := make([]byte, 1500)
	n, _, err := conn.ReadFrom(recvBuf)
	if err != nil {
		return false, false, fmt.Sprintf("UDP %d 未响应 QUIC 报文 (目标未开启 HTTP/3 或防火墙过滤了 UDP，未暴露特征)", port)
	}

	if n > 0 {
		if n >= 5 && bytes.Equal(recvBuf[1:5], []byte{0x00, 0x00, 0x00, 0x00}) {
			return true, false, fmt.Sprintf("UDP %d 返回了标准 RFC 9000 QUIC 版本协商报文 (%d 字节)", port, n)
		}
		return true, true, fmt.Sprintf("UDP %d 响应了非标准数据包 (%d 字节，首字节: 0x%02x)，可能存在非标 QUIC 代理特征！", port, n, recvBuf[0])
	}

	return false, false, "未收到响应"
}

func testUDPEntropy(ctx context.Context, ip string, port int, timeout time.Duration) (bool, string) {
	raddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(ip, fmt.Sprintf("%d", port)))
	if err != nil {
		return false, "UDP 地址解析失败"
	}

	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", raddr.String())
	if err != nil {
		return false, "UDP 连接失败"
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	buf := make([]byte, 64)
	_, _ = rand.Read(buf)
	if len(buf) > 0 {
		buf[0] &= 0x3f // 确保首字节非 Long Header，模拟纯随机短包
	}
	_, _ = conn.Write(buf)

	recv := make([]byte, 512)
	n, err := conn.Read(recv)
	if err != nil {
		return false, fmt.Sprintf("UDP %d 静默丢弃随机高熵包（符合防反射放大规范）", port)
	}

	return true, fmt.Sprintf("UDP %d 对 64B 随机未识别包返回了异常响应 (%d 字节，首字节: 0x%02x)", port, n, recv[0])
}

// Keep unused import guard if strings is used for formatting
var _ = strings.TrimSpace
