// 文件职责：纯标准库 RFC 9000 / RFC 9001 QUIC v1 密钥派生、Long Header 加解密、帧编解码与分片重组实现。
package gfw

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"hash"
)

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

// KeyLen 返回当前 QUIC AEAD 对称密钥字节长度。
func (k QuicKeys) KeyLen() int {
	return len(k.key)
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

func DeriveHandshakeKeysForSuite(suite uint16, secret []byte) QuicKeys {
	if suite == tls.TLS_AES_256_GCM_SHA384 {
		return deriveQUICKeysFromSecret(sha512.New384, secret, 32)
	}
	return deriveQUICKeysFromSecret(sha256.New, secret, 16)
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

func BuildClientTransportParameters(scid []byte) []byte {
	var b []byte
	b = appendTPVarint(b, 0x01, 10000)   // max_idle_timeout = 10000ms
	b = appendTPVarint(b, 0x04, 1048576) // initial_max_data = 1048576
	b = appendTPVarint(b, 0x05, 524288)  // initial_max_stream_data_bidi_local
	b = appendTPVarint(b, 0x06, 524288)  // initial_max_stream_data_bidi_remote
	b = appendTPVarint(b, 0x07, 524288)  // initial_max_stream_data_uni
	b = appendTPVarint(b, 0x08, 100)     // initial_max_streams_bidi
	b = appendTPVarint(b, 0x09, 100)     // initial_max_streams_uni
	b = AppendQUICVarint(b, 0x0f)        // initial_source_connection_id
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

func ReadQUICVarint(b []byte) (uint64, int) {
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
	firstByte := byte(0xc0 | ((pktType & 0x03) << 4) | 0x01)
	var hdr []byte
	hdr = append(hdr, firstByte)
	hdr = append(hdr, 0x00, 0x00, 0x00, 0x01) // QUIC v1
	hdr = append(hdr, byte(len(dcid)))
	hdr = append(hdr, dcid...)
	hdr = append(hdr, byte(len(scid)))
	hdr = append(hdr, scid...)
	if pktType == 0x00 {
		hdr = append(hdr, 0x00)
	}

	pnBytes := []byte{byte(pktNum >> 8), byte(pktNum)}
	overhead := len(hdr) + 2 + len(pnBytes) + 16
	if len(payload)+overhead < minTotalSize {
		padLen := minTotalSize - (len(payload) + overhead)
		padding := make([]byte, padLen)
		payload = append(payload, padding...)
	}

	remLen := len(pnBytes) + len(payload) + 16
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
		return 0, nil, nil, nil, len(datagram), fmt.Errorf("short header")
	}

	pktType := (datagram[0] & 0x30) >> 4
	idx := 5
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
		tokLen, n := ReadQUICVarint(datagram[idx:])
		if n == 0 || idx+n+int(tokLen) >= len(datagram) {
			return 0, nil, nil, nil, len(datagram), fmt.Errorf("invalid token")
		}
		idx += n + int(tokLen)
	}

	remLen, n := ReadQUICVarint(datagram[idx:])
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
		frameType, n := ReadQUICVarint(plain[idx:])
		if n == 0 {
			break
		}
		idx += n
		switch frameType {
		case 0x00, 0x01: // PADDING or PING
			continue
		case 0x02, 0x03: // ACK
			_, n1 := ReadQUICVarint(plain[idx:])
			idx += n1
			_, n2 := ReadQUICVarint(plain[idx:])
			idx += n2
			rngCount, n3 := ReadQUICVarint(plain[idx:])
			idx += n3
			_, n4 := ReadQUICVarint(plain[idx:])
			idx += n4
			for range rngCount {
				_, ng := ReadQUICVarint(plain[idx:])
				idx += ng
				_, na := ReadQUICVarint(plain[idx:])
				idx += na
			}
			if frameType == 0x03 {
				for range 3 {
					_, ne := ReadQUICVarint(plain[idx:])
					idx += ne
				}
			}
		case 0x06: // CRYPTO
			offset, n1 := ReadQUICVarint(plain[idx:])
			idx += n1
			length, n2 := ReadQUICVarint(plain[idx:])
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
			errCode, n1 := ReadQUICVarint(plain[idx:])
			idx += n1
			if frameType == 0x1c {
				_, nf := ReadQUICVarint(plain[idx:])
				idx += nf
			}
			rLen, n2 := ReadQUICVarint(plain[idx:])
			idx += n2
			reason := ""
			if idx+int(rLen) <= len(plain) {
				reason = string(plain[idx : idx+int(rLen)])
			}
			return chunks, fmt.Sprintf("error_code=0x%x (%s)", errCode, reason), nil
		default:
			return chunks, "", nil
		}
	}
	return chunks, "", nil
}

// CryptoReassembler 按偏移量安全重组可能乱序到达的 QUIC CRYPTO 字节流。
type CryptoReassembler struct {
	buf      []byte
	received []bool
	readOff  int
}

// NewCryptoReassembler 创建空的 QUIC CRYPTO 流重组器。
func NewCryptoReassembler() *CryptoReassembler {
	return &CryptoReassembler{}
}

// Push 将单段 CRYPTO 数据帧按偏移量写入重组缓冲区（超过 256KiB 上限自动丢弃防内存耗尽）。
func (r *CryptoReassembler) Push(offset uint64, data []byte) {
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

// PopContiguous 弹出从当前读游标起始的新增连续字节段。
func (r *CryptoReassembler) PopContiguous() []byte {
	start := r.readOff
	for r.readOff < len(r.received) && r.received[r.readOff] {
		r.readOff++
	}
	if r.readOff == start {
		return nil
	}
	return r.buf[start:r.readOff]
}

// AllSeen 返回从流起点至今已连续重组完成的全部字节切片。
func (r *CryptoReassembler) AllSeen() []byte {
	return r.buf[:r.readOff]
}

// ParseTLS13CertificateMsgFromStream 直接从重组后的 TLS 1.3 Handshake 流中提取 Certificate 消息 (MsgType == 11)。
func ParseTLS13CertificateMsgFromStream(stream []byte) ([]*x509.Certificate, bool) {
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
		endMsg := min(idx+msgLen, len(stream))
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
