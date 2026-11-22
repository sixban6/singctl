// 文件职责：提供客户端与服务端共享的 PBKDF2-HMAC-SHA256 + AES-256-GCM 加密灾备快照信封编解码原语。
package cryptobak

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

const (
	// DefaultPBKDF2Iterations 为 OWASP 推荐的 PBKDF2-HMAC-SHA256 迭代次数。
	DefaultPBKDF2Iterations = 210000
	minPBKDF2Iterations     = 10000
	maxPBKDF2Iterations     = 2000000
	// MinPassphraseLen 为灾备快照口令最短字符长度。
	MinPassphraseLen = 8
)

// Envelope 为加密灾备快照的标准外层 JSON 信封（零明文隐私暴露，100% 兼容现有前后端备份文件）。
type Envelope struct {
	Format     string `json:"format"`
	CreatedAt  string `json:"createdAt"`
	KDF        string `json:"kdf"`
	Iterations int    `json:"iterations"`
	Salt       string `json:"salt"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

// Encrypt 使用 PBKDF2-HMAC-SHA256 派生 256-bit 密钥并以 AES-256-GCM（绑定 format 作为 AAD）加密任意可序列化载荷。
func Encrypt[T any](format, passphrase string, payload T) ([]byte, error) {
	if format == "" {
		return nil, errors.New("backup format identifier must not be empty")
	}
	if len(passphrase) < MinPassphraseLen {
		return nil, errors.New("加密口令长度至少需要 8 位字符")
	}
	plain, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("序列化备份数据失败: %w", err)
	}

	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	key, err := pbkdf2.Key(sha256.New, passphrase, salt, DefaultPBKDF2Iterations, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nil, nonce, plain, []byte(format))

	env := Envelope{
		Format:     format,
		CreatedAt:  time.Now().UTC().Format(time.RFC3339),
		KDF:        "PBKDF2-HMAC-SHA256",
		Iterations: DefaultPBKDF2Iterations,
		Salt:       base64.StdEncoding.EncodeToString(salt),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}
	return json.MarshalIndent(env, "", "  ")
}

// Decrypt 校验信封格式、KDF 安全边界与 AES-256-GCM 认证标签（含 format AAD），解密还原强类型载荷。
func Decrypt[T any](expectedFormat, passphrase string, rawEnvelope []byte) (*T, error) {
	if len(passphrase) < MinPassphraseLen {
		return nil, errors.New("解密口令长度至少需要 8 位字符")
	}
	var env Envelope
	if err := json.Unmarshal(rawEnvelope, &env); err != nil {
		return nil, errors.New("无效的加密快照文件格式")
	}
	if env.Format != expectedFormat {
		return nil, fmt.Errorf("不支持的备份文件版本: %s", env.Format)
	}
	if env.Iterations < minPBKDF2Iterations || env.Iterations > maxPBKDF2Iterations {
		return nil, errors.New("备份文件 KDF 参数超出安全范围")
	}
	salt, err := base64.StdEncoding.DecodeString(env.Salt)
	if err != nil || len(salt) < 8 {
		return nil, errors.New("备份文件 Salt 损坏")
	}
	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil {
		return nil, errors.New("备份文件 Nonce 损坏")
	}
	ciphertext, err := base64.StdEncoding.DecodeString(env.Ciphertext)
	if err != nil {
		return nil, errors.New("备份文件密文损坏")
	}

	key, err := pbkdf2.Key(sha256.New, passphrase, salt, env.Iterations, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, errors.New("备份文件 Nonce 长度非法")
	}
	plain, err := gcm.Open(nil, nonce, ciphertext, []byte(expectedFormat))
	if err != nil {
		return nil, errors.New("解密失败：口令不正确或快照文件已被篡改")
	}

	var payload T
	if err := json.Unmarshal(plain, &payload); err != nil {
		return nil, errors.New("备份内层结构损坏")
	}
	return &payload, nil
}
