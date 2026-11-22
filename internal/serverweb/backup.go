// 文件职责：提供主控配置、舰队清单/密钥与 mTLS 证书保险库的加密灾备快照导出与 0600 原子恢复接口（底层加解密委托 common/cryptobak，路径净化委托 fleet）。
package serverweb

import (
	"cmp"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"singctl/internal/common/cryptobak"
	"singctl/internal/common/fsx"
	"singctl/internal/common/httpx"
	"singctl/internal/config"
	"singctl/internal/deploy"
	"singctl/internal/fleet"
	"singctl/internal/logger"

	"gopkg.in/yaml.v3"
)

const (
	backupFormatVersion = "SINGCTL-BAK-V1"
	maxBackupUploadSize = httpx.DefaultMaxBodyBytes
)

// EncryptedBackupEnvelope 加密灾备快照外层信封（复用 common/cryptobak.Envelope）。
type EncryptedBackupEnvelope = cryptobak.Envelope

// BackupPayload 描述服务端全量灾备快照明文载荷结构。
type BackupPayload struct {
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

// EncryptBackupBundle 使用 PBKDF2-HMAC-SHA256 + AES-256-GCM 在内存中加密备份载荷。
func EncryptBackupBundle(passphrase string, payload BackupPayload) ([]byte, error) {
	return cryptobak.Encrypt(backupFormatVersion, passphrase, payload)
}

// DecryptBackupBundle 在内存中校验并解密灾备快照（口令错误或篡改将立即被 GCM 认证拦截）。
func DecryptBackupBundle(passphrase string, rawEnvelope []byte) (*BackupPayload, error) {
	return cryptobak.Decrypt[BackupPayload](backupFormatVersion, passphrase, rawEnvelope)
}

// BuildBackupPayload 收集主控配置、舰队清单与密钥、SubHub 聚合源及 mTLS 保险库构建待加密快照。
func (s *Server) BuildBackupPayload() BackupPayload {
	p := BackupPayload{
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
	type reqBody struct {
		Passphrase string `json:"passphrase"`
	}
	body, ok := decodeBodyJSON[reqBody](w, r, 4096, false, "无效的请求格式")
	if !ok {
		return
	}
	passphrase := strings.TrimSpace(body.Passphrase)
	if len(passphrase) < 8 {
		writeJSONError(w, http.StatusBadRequest, "为保障密钥安全，备份加密口令长度至少需要 8 位字符")
		return
	}

	payload := s.BuildBackupPayload()
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
	type reqBody struct {
		Passphrase string `json:"passphrase"`
		Data       string `json:"data"`
	}
	body, ok := decodeBodyJSON[reqBody](w, r, maxBackupUploadSize, false, "无效的请求或备份文件超过 4MB 上限")
	if !ok {
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

	if len(payload.MtlsFiles) > 0 {
		if mErr := deploy.SaveMtlsBundleToVault(payload.MtlsFiles); mErr != nil {
			writeJSONError(w, http.StatusInternalServerError, "恢复 Web 终端 mTLS 证书失败: "+mErr.Error())
			return
		}
		_, _, _ = deploy.EnsureCaddyMtlsTrustPool("")
		restoredItems = append(restoredItems, "Web终端mTLS证书")
	}

	if payload.SingctlYAML != "" && s.opts.ConfigPath != "" {
		if old, rErr := os.ReadFile(s.opts.ConfigPath); rErr == nil {
			_ = WriteConfigBackup(s.opts.ConfigPath, old)
		}
		if err := fsx.WriteAtomic0600(s.opts.ConfigPath, []byte(payload.SingctlYAML)); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "恢复 singctl.yaml 失败: "+err.Error())
			return
		}
		restoredItems = append(restoredItems, "主控配置")

		cfgDir := filepath.Dir(s.opts.ConfigPath)
		if len(payload.MasterSSHPriv) > 0 {
			_ = fsx.WriteAtomic0600(filepath.Join(cfgDir, "master_ed25519"), payload.MasterSSHPriv)
		}
		if len(payload.MasterSSHPub) > 0 {
			_ = fsx.WriteAtomic0600(filepath.Join(cfgDir, "master_ed25519.pub"), payload.MasterSSHPub)
		}
		s.InvalidateConfigCache()
		if cfg, lErr := s.loadMutableConfig(); lErr == nil && cfg != nil {
			if deploy.UpgradeLegacyMtlsConfig(cfg) {
				_ = s.saveConfig(cfg)
			} else {
				s.updateConfigCache(cfg)
			}
			s.mu.Lock()
			s.opts.Username = cmp.Or(cfg.Server.GetWebAdminUsername(), s.opts.Username)
			if p := cfg.Server.GetWebAdminPassword(); p != "" {
				s.opts.Password = p
			}
			s.gatewayToken = config.DeriveGatewayToken(cfg.Server.GetWebAdminPath())
			s.mu.Unlock()
			s.invalidateStatusCaches()
			if cErr := deploy.SyncCaddyfile(cfg); cErr != nil {
				logger.Warn("灾备恢复后同步 Caddyfile 提示: %v", cErr)
			}
		}
	}

	if s.fleet != nil && s.fleet.Store != nil {
		if len(payload.FleetKeys) > 0 && s.fleet.Store.KeysDir != "" {
			_ = os.MkdirAll(s.fleet.Store.KeysDir, 0700)
			_ = os.Chmod(s.fleet.Store.KeysDir, 0700)
			for rawName, kBytes := range payload.FleetKeys {
				safeName, err := fleet.SanitizeKeyFilename(rawName)
				if err != nil {
					continue
				}
				_ = fsx.WriteAtomic0600(filepath.Join(s.fleet.Store.KeysDir, safeName), kBytes)
			}
		}
		if payload.FleetYAML != "" && s.fleet.Store.FilePath != "" {
			rewrittenFleet := fleet.RewriteRestoredKeyPaths(payload.FleetYAML, s.fleet.Store.KeysDir, payload.FleetKeys)
			if old, rErr := os.ReadFile(s.fleet.Store.FilePath); rErr == nil {
				_ = WriteConfigBackup(s.fleet.Store.FilePath, old)
			}
			if err := fsx.WriteAtomic0600(s.fleet.Store.FilePath, []byte(rewrittenFleet)); err != nil {
				writeJSONError(w, http.StatusInternalServerError, "恢复 fleet.yaml 失败: "+err.Error())
				return
			}
			restoredItems = append(restoredItems, fmt.Sprintf("舰队清单与密钥(%d)", len(payload.FleetKeys)))
		}
	}

	if s.subStore != nil {
		if payload.SubStoreJSON != "" && s.subStore.FilePath != "" {
			if old, rErr := os.ReadFile(s.subStore.FilePath); rErr == nil {
				_ = WriteConfigBackup(s.subStore.FilePath, old)
			}
			if err := fsx.WriteAtomic0600(s.subStore.FilePath, []byte(payload.SubStoreJSON)); err != nil {
				writeJSONError(w, http.StatusInternalServerError, "恢复 SubHub 订阅配置失败: "+err.Error())
				return
			}
			restoredItems = append(restoredItems, "聚合订阅池")
		}
		if strings.TrimSpace(payload.SubStoreKey) != "" && s.subStore.DataDir != "" {
			_ = fsx.WriteAtomic0600(filepath.Join(s.subStore.DataDir, "key"), []byte(strings.TrimSpace(payload.SubStoreKey)+"\n"))
			if cfg := s.readConfigOrNil(); cfg != nil {
				_ = deploy.SyncCaddyfile(cfg)
			}
		}
	}

	summary := cmp.Or(strings.Join(restoredItems, "、"), "无变更项")
	s.recordAudit(r, fmt.Sprintf("从加密灾备快照成功恢复 [%s]", summary))
	writeJSON(w, http.StatusOK, map[string]any{
		"message":       fmt.Sprintf("加密灾备快照已成功恢复：%s", summary),
		"restoredItems": restoredItems,
	})
}
