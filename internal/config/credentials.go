// 文件职责：负责服务端/网关面板的密码哈希（bcrypt）、常量时间校验、高熵随机 Token/管理路径与随机密码生成。
//
// 架构设计原则：
//   - 单一职责原则（SRP）：将密码学与高熵随机生成从配置结构体中剥离，避免 config.go 混杂安全原语与 YAML 结构。
//   - 密码学无偏采样：cryptoRandInt 使用拒绝采样避免模偏差（modulo bias），确保随机口令每位字符均匀分布。
package config

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// IsHashedPassword 判断密码字段是否已经采用 bcrypt 哈希存储
func IsHashedPassword(secret string) bool {
	trimmed := strings.TrimSpace(secret)
	return strings.HasPrefix(trimmed, "$2a$") ||
		strings.HasPrefix(trimmed, "$2b$") ||
		strings.HasPrefix(trimmed, "$2y$")
}

// HashPassword 使用 bcrypt 对明文密码进行单向哈希；若已是哈希值则原样返回。
func HashPassword(plain string) (string, error) {
	trimmed := strings.TrimSpace(plain)
	if trimmed == "" {
		return "", fmt.Errorf("password cannot be empty")
	}
	if IsHashedPassword(trimmed) {
		return trimmed, nil
	}
	hashed, err := bcrypt.GenerateFromPassword([]byte(trimmed), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}
	return string(hashed), nil
}

// VerifyPassword 同时兼容校验 bcrypt 哈希密码与初始明文密码（常量时间比对）。
func VerifyPassword(stored, candidate string) bool {
	stored = strings.TrimSpace(stored)
	if stored == "" || candidate == "" {
		return false
	}
	if IsHashedPassword(stored) {
		return bcrypt.CompareHashAndPassword([]byte(stored), []byte(candidate)) == nil
	}
	return subtle.ConstantTimeCompare([]byte(stored), []byte(candidate)) == 1
}

// DeriveGatewayToken 基于随机管理路径派生 Caddy -> ServerWeb 内部网关鉴权令牌。
func DeriveGatewayToken(adminPath string) string {
	p := strings.TrimSpace(adminPath)
	if p == "" {
		return ""
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	p = strings.TrimSuffix(p, "/")
	if p == "" {
		return ""
	}
	mac := hmac.New(sha256.New, []byte("singctl-caddy-gateway-v1"))
	_, _ = mac.Write([]byte(p))
	return hex.EncodeToString(mac.Sum(nil))
}

// GenerateAdminToken 生成 16 位包含数字、大写字母与小写字母的高熵安全 Token
func GenerateAdminToken(length int) string {
	if length < 16 {
		length = 16
	}
	const upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	const lower = "abcdefghijklmnopqrstuvwxyz"
	const digits = "0123456789"
	const all = upper + lower + digits

	buf := make([]byte, length)
	buf[0] = upper[cryptoRandInt(len(upper))]
	buf[1] = lower[cryptoRandInt(len(lower))]
	buf[2] = digits[cryptoRandInt(len(digits))]

	for i := 3; i < length; i++ {
		buf[i] = all[cryptoRandInt(len(all))]
	}
	for i := length - 1; i > 0; i-- {
		j := cryptoRandInt(i + 1)
		buf[i], buf[j] = buf[j], buf[i]
	}
	return string(buf)
}

// GenerateRandomAdminPath 生成 /sr/ 加上 24 位包含大小写字母和数字的高熵路径，例如 /sr/3aB9kLmN2pQrSt8XWk9Lp2Zx
func GenerateRandomAdminPath() string {
	return "/sr/" + GenerateAdminToken(24)
}

// GenerateSecurePassword 生成包含大写字母、小写字母和数字的随机密码。length 小于 8 时按 8 位生成。
func GenerateSecurePassword(length int) string {
	if length < 8 {
		length = 8
	}
	const upper = "ABCDEFGHJKLMNPQRSTUVWXYZ"
	const lower = "abcdefghijkmnopqrstuvwxyz"
	const digits = "23456789"
	const all = upper + lower + digits

	buf := make([]byte, length)
	buf[0] = upper[cryptoRandInt(len(upper))]
	buf[1] = lower[cryptoRandInt(len(lower))]
	buf[2] = digits[cryptoRandInt(len(digits))]

	for i := 3; i < length; i++ {
		buf[i] = all[cryptoRandInt(len(all))]
	}
	for i := length - 1; i > 0; i-- {
		j := cryptoRandInt(i + 1)
		buf[i], buf[j] = buf[j], buf[i]
	}
	return string(buf)
}

func cryptoRandInt(n int) int {
	if n <= 0 {
		return 0
	}
	b := make([]byte, 1)
	for {
		_, _ = rand.Read(b)
		val := int(b[0])
		// 拒绝采样：丢弃会导致余数倾斜的尾部区间，保证 [0, n) 绝对均匀
		if val < 256-(256%n) {
			return val % n
		}
	}
}
