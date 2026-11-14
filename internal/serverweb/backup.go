package serverweb

import (
	"cmp"
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
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"singctl/internal/config"
	"singctl/internal/deploy"
	"singctl/internal/logger"

	"gopkg.in/yaml.v3"
)

const (
	backupFormatVersion = "SINGCTL-BAK-V1"
	backupPBKDF2Iter    = 210000
	maxBackupUploadSize = 4 * 1024 * 1024 // 4 MiB
)

// EncryptedBackupEnvelope 加密灾备快照外层信封（无任何明文隐私）
type EncryptedBackupEnvelope struct {
	Format     string `json:"format"`
	CreatedAt  string `json:"createdAt"`
	KDF        string `json:"kdf"`
	Iterations int    `json:"iterations"`
	Salt       string `json:"salt"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

type backupPayload struct {
	Version       string            `json:"version"`
	ExportedAt    string            `json:"exportedAt"`
	SingctlYAML   string            `json:"singctlYaml,omitempty"`
	FleetYAML     string            `json:"fleetYaml,omitempty"`
	FleetKeys     map[string][]byte `json:"fleetKeys,omitempty"`
	SubStoreJSON  string            `json:"subStoreJson,omitempty"`
	SubStoreKey   string            `json:"subStoreKey,omitempty"`
	MasterSSHPriv []byte            `json:"masterSshPriv,omitempty"`
	MasterSSHPub  []byte            `json:"masterSshPub,omitempty"`
	MtlsFiles     map[string][]byte `json:"mtlsFiles,omitzero"`
}

// EncryptBackupBundle 使用 PBKDF2-HMAC-SHA256 + AES-256-GCM 在内存中加密备份载荷
func EncryptBackupBundle(passphrase string, payload backupPayload) ([]byte, error) {
	if len(passphrase) < 8 {
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
	key, err := pbkdf2.Key(sha256.New, passphrase, salt, backupPBKDF2Iter, 32)
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
	ciphertext := gcm.Seal(nil, nonce, plain, []byte(backupFormatVersion))

	env := EncryptedBackupEnvelope{
		Format:     backupFormatVersion,
		CreatedAt:  time.Now().UTC().Format(time.RFC3339),
		KDF:        "PBKDF2-HMAC-SHA256",
		Iterations: backupPBKDF2Iter,
		Salt:       base64.StdEncoding.EncodeToString(salt),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}
	return json.MarshalIndent(env, "", "  ")
}

// DecryptBackupBundle 在内存中校验并解密灾备快照（口令错误或篡改将立即被 GCM 认证拦截）
func DecryptBackupBundle(passphrase string, rawEnvelope []byte) (*backupPayload, error) {
	if len(passphrase) < 8 {
		return nil, errors.New("解密口令长度至少需要 8 位字符")
	}
	var env EncryptedBackupEnvelope
	if err := json.Unmarshal(rawEnvelope, &env); err != nil {
		return nil, errors.New("无效的加密快照文件格式")
	}
	if env.Format != backupFormatVersion {
		return nil, fmt.Errorf("不支持的备份文件版本: %s", env.Format)
	}
	iters := env.Iterations
	if iters < 10000 || iters > 2000000 {
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

	key, err := pbkdf2.Key(sha256.New, passphrase, salt, iters, 32)
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
	plain, err := gcm.Open(nil, nonce, ciphertext, []byte(backupFormatVersion))
	if err != nil {
		return nil, errors.New("解密失败：口令不正确或快照文件已被篡改")
	}

	var payload backupPayload
	if err := json.Unmarshal(plain, &payload); err != nil {
		return nil, errors.New("备份内层结构损坏")
	}
	return &payload, nil
}

func (s *Server) buildBackupPayload() backupPayload {
	p := backupPayload{
		Version:    cmp.Or(s.opts.Version, "1.0"),
		ExportedAt: time.Now().Format(time.RFC3339),
		FleetKeys:  make(map[string][]byte),
	}

	if s.opts.ConfigPath != "" {
		if raw, err := os.ReadFile(s.opts.ConfigPath); err == nil {
			p.SingctlYAML = string(raw)
		}
		cfgDir := filepath.Dir(s.opts.ConfigPath)
		if priv, err := os.ReadFile(filepath.Join(cfgDir, "master_ed25519")); err == nil {
			p.MasterSSHPriv = priv
		}
		if pub, err := os.ReadFile(filepath.Join(cfgDir, "master_ed25519.pub")); err == nil {
			p.MasterSSHPub = pub
		}
	}

	if s.fleet != nil && s.fleet.Store != nil {
		if s.fleet.Store.FilePath != "" {
			if raw, err := os.ReadFile(s.fleet.Store.FilePath); err == nil {
				p.FleetYAML = string(raw)
			}
		}
		if s.fleet.Store.KeysDir != "" {
			if entries, err := os.ReadDir(s.fleet.Store.KeysDir); err == nil {
				for _, ent := range entries {
					if ent.IsDir() {
						continue
					}
					base := filepath.Base(ent.Name())
					if base == "" || strings.HasPrefix(base, ".") {
						continue
					}
					if kData, rErr := os.ReadFile(filepath.Join(s.fleet.Store.KeysDir, base)); rErr == nil {
						p.FleetKeys[base] = kData
					}
				}
			}
		}
	}

	if s.subStore != nil {
		if s.subStore.FilePath != "" {
			if raw, err := os.ReadFile(s.subStore.FilePath); err == nil {
				p.SubStoreJSON = string(raw)
			}
		}
		if key, err := s.subStore.GetKey(); err == nil && key != "" {
			p.SubStoreKey = key
		}
	}

	if mtlsBundle := deploy.LoadMtlsBundleFromVault(); len(mtlsBundle) > 0 {
		p.MtlsFiles = mtlsBundle
	}

	return p
}

func (s *Server) handleBackupExport(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Passphrase string `json:"passphrase"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "无效的请求格式")
		return
	}
	passphrase := strings.TrimSpace(body.Passphrase)
	if len(passphrase) < 8 {
		writeJSONError(w, http.StatusBadRequest, "为保障密钥安全，备份加密口令长度至少需要 8 位字符")
		return
	}

	payload := s.buildBackupPayload()
	if payload.SingctlYAML == "" && payload.FleetYAML == "" && payload.SubStoreJSON == "" {
		writeJSONError(w, http.StatusNotFound, "当前无可导出的主控配置或舰队数据")
		return
	}

	encryptedBytes, err := EncryptBackupBundle(passphrase, payload)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "生成加密快照失败: "+err.Error())
		return
	}

	filename := fmt.Sprintf("singctl-master-backup-%s.enc.json", time.Now().Format("20060102-150405"))
	s.recordAudit(r, fmt.Sprintf("导出主控与舰队 AES-256-GCM 加密灾备快照 (含私钥=%d 把)", len(payload.FleetKeys)))
	writeJSON(w, http.StatusOK, map[string]any{
		"message":       "加密灾备快照已在内存生成，请妥善保管快照文件与解密口令",
		"filename":      filename,
		"data":          string(encryptedBytes),
		"hasSingctlCfg": payload.SingctlYAML != "",
		"hasFleet":      payload.FleetYAML != "",
		"fleetKeyCount": len(payload.FleetKeys),
		"hasSubStore":   payload.SubStoreJSON != "",
	})
}

func (s *Server) handleBackupRestore(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Passphrase string `json:"passphrase"`
		Data       string `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxBackupUploadSize)).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "无效的请求或备份文件超过 4MB 上限")
		return
	}
	passphrase := strings.TrimSpace(body.Passphrase)
	rawData := strings.TrimSpace(body.Data)
	if len(passphrase) < 8 || rawData == "" {
		writeJSONError(w, http.StatusBadRequest, "请提供完整的加密快照内容与至少 8 位解密口令")
		return
	}

	payload, err := DecryptBackupBundle(passphrase, []byte(rawData))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	// 写入前严格校验 YAML / JSON 合法性，防止损坏数据落盘
	if payload.SingctlYAML != "" {
		var checkMap map[string]any
		if err := yaml.Unmarshal([]byte(payload.SingctlYAML), &checkMap); err != nil {
			writeJSONError(w, http.StatusBadRequest, "快照中的 singctl.yaml 格式非法: "+err.Error())
			return
		}
	}
	if payload.FleetYAML != "" {
		var checkFleet map[string]any
		if err := yaml.Unmarshal([]byte(payload.FleetYAML), &checkFleet); err != nil {
			writeJSONError(w, http.StatusBadRequest, "快照中的 fleet.yaml 格式非法: "+err.Error())
			return
		}
	}
	if payload.SubStoreJSON != "" {
		var checkSub json.RawMessage
		if err := json.Unmarshal([]byte(payload.SubStoreJSON), &checkSub); err != nil {
			writeJSONError(w, http.StatusBadRequest, "快照中的 SubHub 订阅数据格式非法: "+err.Error())
			return
		}
	}

	var restoredItems []string

	// 0. 若快照包含 Web 终端 mTLS 证书，优先恢复至持久化 0700/0600 主库，确保后续 SyncCaddyfile 可立即投射 ca.crt
	if len(payload.MtlsFiles) > 0 {
		if mErr := deploy.SaveMtlsBundleToVault(payload.MtlsFiles); mErr != nil {
			writeJSONError(w, http.StatusInternalServerError, "恢复 Web 终端 mTLS 证书失败: "+mErr.Error())
			return
		}
		_, _, _ = deploy.EnsureCaddyMtlsTrustPool("")
		restoredItems = append(restoredItems, "Web终端mTLS证书")
	}

	// 1. 恢复 singctl.yaml 与主控 SSH 密钥 (强制 0700 目录 + 0600 文件)
	if payload.SingctlYAML != "" && s.opts.ConfigPath != "" {
		if old, rErr := os.ReadFile(s.opts.ConfigPath); rErr == nil {
			_ = WriteConfigBackup(s.opts.ConfigPath, old)
		}
		if err := writeSecretFile0600(s.opts.ConfigPath, []byte(payload.SingctlYAML)); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "恢复 singctl.yaml 失败: "+err.Error())
			return
		}
		restoredItems = append(restoredItems, "主控配置")

		cfgDir := filepath.Dir(s.opts.ConfigPath)
		if len(payload.MasterSSHPriv) > 0 {
			_ = writeSecretFile0600(filepath.Join(cfgDir, "master_ed25519"), payload.MasterSSHPriv)
		}
		if len(payload.MasterSSHPub) > 0 {
			_ = writeSecretFile0600(filepath.Join(cfgDir, "master_ed25519.pub"), payload.MasterSSHPub)
		}
		if cfg, lErr := config.Load(s.opts.ConfigPath); lErr == nil && cfg != nil {
			if deploy.UpgradeLegacyMtlsConfig(cfg) {
				_ = config.Save(s.opts.ConfigPath, cfg)
			}
			s.mu.Lock()
			s.opts.Username = cmp.Or(cfg.Server.GetWebAdminUsername(), s.opts.Username)
			if p := cfg.Server.GetWebAdminPassword(); p != "" {
				s.opts.Password = p
			}
			s.gatewayToken = config.DeriveGatewayToken(cfg.Server.GetWebAdminPath())
			s.mu.Unlock()
			if cErr := deploy.SyncCaddyfile(cfg); cErr != nil {
				logger.Warn("灾备恢复后同步 Caddyfile 提示: %v", cErr)
			}
		}
	}

	// 2. 恢复舰队 SSH 密钥与 fleet.yaml (强制文件名净化防目录穿越 + 0600)
	if s.fleet != nil && s.fleet.Store != nil {
		if len(payload.FleetKeys) > 0 && s.fleet.Store.KeysDir != "" {
			_ = os.MkdirAll(s.fleet.Store.KeysDir, 0700)
			_ = os.Chmod(s.fleet.Store.KeysDir, 0700)
			for rawName, kBytes := range payload.FleetKeys {
				safeName, err := sanitizeFleetKeyFilename(rawName)
				if err != nil {
					continue
				}
				_ = writeSecretFile0600(filepath.Join(s.fleet.Store.KeysDir, safeName), kBytes)
			}
		}
		if payload.FleetYAML != "" && s.fleet.Store.FilePath != "" {
			rewrittenFleet := rewriteRestoredFleetKeyPaths(payload.FleetYAML, s.fleet.Store.KeysDir, payload.FleetKeys)
			if old, rErr := os.ReadFile(s.fleet.Store.FilePath); rErr == nil {
				_ = WriteConfigBackup(s.fleet.Store.FilePath, old)
			}
			if err := writeSecretFile0600(s.fleet.Store.FilePath, []byte(rewrittenFleet)); err != nil {
				writeJSONError(w, http.StatusInternalServerError, "恢复 fleet.yaml 失败: "+err.Error())
				return
			}
			restoredItems = append(restoredItems, fmt.Sprintf("舰队清单与密钥(%d)", len(payload.FleetKeys)))
		}
	}

	// 3. 恢复 SubHub 聚合订阅源与访问密钥
	if s.subStore != nil {
		if payload.SubStoreJSON != "" && s.subStore.FilePath != "" {
			if old, rErr := os.ReadFile(s.subStore.FilePath); rErr == nil {
				_ = WriteConfigBackup(s.subStore.FilePath, old)
			}
			if err := writeSecretFile0600(s.subStore.FilePath, []byte(payload.SubStoreJSON)); err != nil {
				writeJSONError(w, http.StatusInternalServerError, "恢复 SubHub 订阅配置失败: "+err.Error())
				return
			}
			restoredItems = append(restoredItems, "聚合订阅池")
		}
		if strings.TrimSpace(payload.SubStoreKey) != "" && s.subStore.DataDir != "" {
			_ = writeSecretFile0600(filepath.Join(s.subStore.DataDir, "key"), []byte(strings.TrimSpace(payload.SubStoreKey)+"\n"))
			if cfg, lErr := config.Load(s.opts.ConfigPath); lErr == nil && cfg != nil {
				_ = deploy.SyncCaddyfile(cfg)
			}
		}
	}

	summary := strings.Join(restoredItems, "、")
	if summary == "" {
		summary = "无变更项"
	}
	s.recordAudit(r, fmt.Sprintf("从加密灾备快照成功恢复 [%s]", summary))
	writeJSON(w, http.StatusOK, map[string]any{
		"message":       fmt.Sprintf("加密灾备快照已成功恢复：%s", summary),
		"restoredItems": restoredItems,
	})
}

func sanitizeFleetKeyFilename(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || trimmed == "." || trimmed == ".." || strings.Contains(trimmed, "..") || strings.ContainsAny(trimmed, `/\`) {
		return "", errors.New("invalid fleet key filename")
	}
	base := filepath.Base(trimmed)
	if base != trimmed || base == "" || base == "." || base == ".." {
		return "", errors.New("invalid fleet key filename")
	}
	return base, nil
}

func writeSecretFile0600(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	tmp := fmt.Sprintf("%s.%d.tmp", path, time.Now().UnixNano())
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	_ = os.Chmod(tmp, 0600)
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		if wErr := os.WriteFile(path, data, 0600); wErr != nil {
			return wErr
		}
	}
	return os.Chmod(path, 0600)
}

// rewriteRestoredFleetKeyPaths 若新机配置目录不同，将受管 fleet_keys 路径自动对齐到当前 KeysDir
func rewriteRestoredFleetKeyPaths(rawFleetYAML, targetKeysDir string, bundledKeys map[string][]byte) string {
	if targetKeysDir == "" || len(bundledKeys) == 0 {
		return rawFleetYAML
	}
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(rawFleetYAML), &doc); err != nil {
		return rawFleetYAML
	}
	nodesRaw, ok := doc["nodes"].([]any)
	if !ok {
		return rawFleetYAML
	}
	changed := false
	for _, item := range nodesRaw {
		nodeMap, ok := item.(map[string]any)
		if !ok {
			continue
		}
		kp, _ := nodeMap["key_path"].(string)
		if kp == "" {
			continue
		}
		base := filepath.Base(kp)
		if _, exists := bundledKeys[base]; exists {
			newPath := filepath.Join(targetKeysDir, base)
			if newPath != kp {
				nodeMap["key_path"] = newPath
				changed = true
			}
		}
	}
	if !changed {
		return rawFleetYAML
	}
	out, err := yaml.Marshal(doc)
	if err != nil {
		return rawFleetYAML
	}
	return string(out)
}
