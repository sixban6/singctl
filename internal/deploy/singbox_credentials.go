// 文件职责：负责服务端 sing-box 凭据生成/读取、分享链接组装与 Reality 握手端口结构化改写。
package deploy

import (
	"cmp"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/logger"
	"singctl/internal/singbox/sboption"
)

// InspectExistingShareLinks 以纯本地只读方式读取已部署的 sing-box 凭据并组装分享链接（零外网探测、零证书轮询等待、零随机伪造密钥）。
func InspectExistingShareLinks(cfg *config.Config, configFile string) (hy2Link, vlessLink string, hy2Port, vlessPort int) {
	if cfg == nil {
		return "", "", 443, 443
	}
	sbs := &SingBoxServer{
		cfg:        cfg,
		ConfigFile: configFile,
	}
	tagPrefix := cmp.Or(cfg.Server.FastNodeTag(), "node")
	sbs.hy2Tag = fmt.Sprintf("sec_%s_hy2", tagPrefix)
	sbs.vrTag = fmt.Sprintf("sec_%s_vr", tagPrefix)
	_ = sbs.LoadExistingCredentials()
	return sbs.ShareLinkHy2, sbs.ShareLinkVless, sbs.Hy2Port(), sbs.VlessPort()
}

func (sbs *SingBoxServer) updateShareLinks() {
	nodeDomain := sbs.cfg.Server.GetNodeDomain()
	hy2Port := sbs.Hy2Port()
	vlessPort := sbs.VlessPort()
	sbs.ShareLinkHy2 = fmt.Sprintf("hysteria2://%s@%s:%d/?sni=%s&alpn=h3&insecure=0#%s", sbs.hyUUID, nodeDomain, hy2Port, nodeDomain, sbs.hy2Tag)
	sbs.ShareLinkVless = fmt.Sprintf("vless://%s@%s:%d?type=tcp&encryption=none&security=reality&pbk=%s&fp=chrome&sni=%s&sid=%s&flow=xtls-rprx-vision#%s", sbs.hyUUID, nodeDomain, vlessPort, sbs.publicKey, sbs.cfg.Server.Sni, sbs.shortID, sbs.vrTag)
}

func (sbs *SingBoxServer) initVRParams() error {
	if sbs.hyUUID != "" {
		if sbs.publicKey == "" && sbs.privateKey != "" {
			pub, err := deriveRealityPublicKey(sbs.privateKey)
			if err != nil {
				return fmt.Errorf("failed to derive reality public key from existing private key: %w", err)
			}
			sbs.publicKey = pub
		}
		return nil
	}

	logger.Info("Generating new UUID for Hysteria2 and VLESS...")
	uuid, err := generateUUIDv4()
	if err != nil {
		return fmt.Errorf("failed to generate uuid: %w", err)
	}
	sbs.hyUUID = uuid

	logger.Info("Generating VLESS Reality Keypair...")
	privateKey, publicKey, err := generateRealityKeypair()
	if err != nil {
		return fmt.Errorf("failed to generate reality keypair locally: %w", err)
	}
	sbs.privateKey = privateKey
	sbs.publicKey = publicKey

	logger.Info("Generating VLESS Reality Short ID...")
	shortID, err := generateHexRandom(8)
	if err != nil {
		return fmt.Errorf("failed to generate short id: %w", err)
	}
	sbs.shortID = shortID
	return nil
}

func generateUUIDv4() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

func generateRealityKeypair() (privateKey string, publicKey string, err error) {
	curve := ecdh.X25519()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	privateKey = base64.RawURLEncoding.EncodeToString(priv.Bytes())
	publicKey = base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes())
	return privateKey, publicKey, nil
}

func deriveRealityPublicKey(privateKey string) (string, error) {
	privBytes, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(privateKey))
	if err != nil {
		return "", err
	}
	curve := ecdh.X25519()
	priv, err := curve.NewPrivateKey(privBytes)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes()), nil
}

func generateHexRandom(byteLen int) (string, error) {
	b := make([]byte, byteLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// SetRealityHandshakePort 通过强类型结构化模型修改 Reality 入站握手端口，避免依赖模板缩进空格。
func SetRealityHandshakePort(rawJSON string, port int) (string, error) {
	doc, err := sboption.ParseDocument([]byte(rawJSON))
	if err != nil {
		return "", err
	}
	for i := range doc.Inbounds {
		ib := &doc.Inbounds[i]
		if ib.TLS != nil && ib.TLS.Reality != nil && ib.TLS.Reality.Handshake != nil {
			ib.TLS.Reality.Handshake.ServerPort = port
		}
	}
	return doc.MarshalPretty()
}

func setRealityHandshakePort(rawJSON string, port int) (string, error) {
	return SetRealityHandshakePort(rawJSON, port)
}

func (sbs *SingBoxServer) getConfigFile() string {
	if sbs.ConfigFile != "" {
		return sbs.ConfigFile
	}
	return constant.SingBoxConfigFile
}

// LoadExistingCredentials reads the deployed sing-box config and populates
// sbs with the existing uuid, private_key and short_id, and updates share links.
func (sbs *SingBoxServer) LoadExistingCredentials() error {
	configFile := sbs.getConfigFile()
	data, err := os.ReadFile(configFile)
	if err != nil {
		return fmt.Errorf("read existing config: %w", err)
	}

	var raw struct {
		Inbounds []struct {
			Type  string `json:"type"`
			Users []struct {
				UUID string `json:"uuid"`
			} `json:"users"`
			TLS struct {
				ServerName string `json:"server_name"`
				Reality    struct {
					PrivateKey string   `json:"private_key"`
					ShortID    []string `json:"short_id"`
				} `json:"reality"`
			} `json:"tls"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("parse existing config: %w", err)
	}

	for _, inbound := range raw.Inbounds {
		if len(inbound.Users) > 0 && inbound.Users[0].UUID != "" {
			sbs.hyUUID = inbound.Users[0].UUID
			if inbound.TLS.ServerName != "" && sbs.cfg != nil && sbs.cfg.Server.Sni == "" {
				sbs.cfg.Server.Sni = inbound.TLS.ServerName
			}
			sbs.privateKey = inbound.TLS.Reality.PrivateKey
			if sbs.privateKey != "" {
				pub, err := deriveRealityPublicKey(sbs.privateKey)
				if err != nil {
					return fmt.Errorf("derive public key from existing private key: %w", err)
				}
				sbs.publicKey = pub
			}
			if len(inbound.TLS.Reality.ShortID) > 0 {
				sbs.shortID = inbound.TLS.Reality.ShortID[0]
			}
			sbs.updateShareLinks()
			logger.Info("Loaded existing credentials from %s", configFile)
			return nil
		}
	}
	return fmt.Errorf("no credentials found in existing sing-box config")
}
