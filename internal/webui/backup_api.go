// 文件职责：提供客户端网关配置加密灾备包导出与原子恢复（含失败自动回滚）接口。
package webui

import (
	"cmp"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"singctl/internal/common/cryptobak"
	"singctl/internal/common/fsx"
	"singctl/internal/config"
	"singctl/internal/daemon"
	"singctl/internal/logger"
	"singctl/internal/singbox"

	"gopkg.in/yaml.v3"
)

const (
	clientBackupFormatVersion = "SINGCTL-CLIENT-BAK-V1"
	maxClientBackupUploadSize = 4 * 1024 * 1024 // 4 MiB
)

// ClientBackupEnvelope 为客户端网关加密灾备快照外层信封（复用 common/cryptobak.Envelope）。
type ClientBackupEnvelope = cryptobak.Envelope

// ClientBackupPayload 保存网关可迁出的完整核心配置状态。
type ClientBackupPayload struct {
	Version           string `json:"version"`
	ExportedAt        string `json:"exportedAt"`
	SingctlYAML       string `json:"singctlYaml,omitempty"`
	GroupsYAML        string `json:"groupsYaml,omitempty"`
	AdGuardYAML       string `json:"adguardYaml,omitempty"`
	SingBoxConfigJSON string `json:"singboxConfigJson,omitempty"`
}

// EncryptClientBackupBundle 使用 PBKDF2-HMAC-SHA256 + AES-256-GCM 加密网关备份载荷。
func EncryptClientBackupBundle(passphrase string, payload ClientBackupPayload) ([]byte, error) {
	return cryptobak.Encrypt(clientBackupFormatVersion, passphrase, payload)
}

// DecryptClientBackupBundle 在内存中校验并解密网关灾备快照。
func DecryptClientBackupBundle(passphrase string, rawEnvelope []byte) (*ClientBackupPayload, error) {
	return cryptobak.Decrypt[ClientBackupPayload](clientBackupFormatVersion, passphrase, rawEnvelope)
}

func (s *Server) handleClientBackupExport(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Passphrase string `json:"passphrase"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "无效的请求格式")
		return
	}
	passphrase := strings.TrimSpace(body.Passphrase)
	if len(passphrase) < 8 {
		writeJSONError(w, http.StatusBadRequest, "为保障订阅与凭据安全，加密口令长度至少需要 8 位字符")
		return
	}

	s.cfgMu.Lock()
	cfgPath := configPathFor(s)
	gPath := config.GroupsPathForConfig(cfgPath)
	aghPath := s.adguardConfigFilePath()
	sbPath := s.sbConfigPath()

	payload := ClientBackupPayload{
		Version:    cmp.Or(s.opts.Version, "1.0"),
		ExportedAt: time.Now().Format(time.RFC3339),
	}
	if raw, err := os.ReadFile(cfgPath); err == nil {
		payload.SingctlYAML = string(raw)
	}
	if raw, err := os.ReadFile(gPath); err == nil {
		payload.GroupsYAML = string(raw)
	}
	if aghPath != "" {
		if raw, err := os.ReadFile(aghPath); err == nil {
			payload.AdGuardYAML = string(raw)
		}
	}
	if sbPath != "" {
		if raw, err := os.ReadFile(sbPath); err == nil {
			payload.SingBoxConfigJSON = string(raw)
		}
	}
	s.cfgMu.Unlock()

	if payload.SingctlYAML == "" && payload.GroupsYAML == "" && payload.AdGuardYAML == "" && payload.SingBoxConfigJSON == "" {
		writeJSONError(w, http.StatusNotFound, "当前无可导出的网关配置数据")
		return
	}

	encryptedBytes, err := EncryptClientBackupBundle(passphrase, payload)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "生成加密快照失败: "+err.Error())
		return
	}

	filename := fmt.Sprintf("singctl-client-backup-%s.enc.json", time.Now().Format("20060102-150405"))
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"message":  "网关加密备份快照已生成，请妥善保管文件与解密口令",
		"filename": filename,
		"data":     string(encryptedBytes),
		"summary": map[string]any{
			"hasSingctlCfg": payload.SingctlYAML != "",
			"hasGroups":     payload.GroupsYAML != "",
			"hasAdGuard":    payload.AdGuardYAML != "",
			"hasSingBox":    payload.SingBoxConfigJSON != "",
		},
	})
}

func validateClientBackupPayload(p *ClientBackupPayload) error {
	if p.SingctlYAML != "" {
		var checkMap map[string]any
		if err := yaml.Unmarshal([]byte(p.SingctlYAML), &checkMap); err != nil {
			return fmt.Errorf("快照中的 singctl.yaml 格式非法: %w", err)
		}
		var checkCfg config.Config
		if err := yaml.Unmarshal([]byte(p.SingctlYAML), &checkCfg); err != nil {
			return fmt.Errorf("快照中的 singctl.yaml 结构非法: %w", err)
		}
	}
	if p.GroupsYAML != "" {
		if _, err := config.ParseGroupsYAML([]byte(p.GroupsYAML)); err != nil {
			return fmt.Errorf("快照中的 groups.yaml 校验失败: %w", err)
		}
	}
	if p.AdGuardYAML != "" {
		var checkMap map[string]any
		if err := yaml.Unmarshal([]byte(p.AdGuardYAML), &checkMap); err != nil {
			return fmt.Errorf("快照中的 AdGuardHome.yaml 格式非法: %w", err)
		}
	}
	if p.SingBoxConfigJSON != "" {
		var checkObj map[string]any
		if err := json.Unmarshal([]byte(p.SingBoxConfigJSON), &checkObj); err != nil {
			return fmt.Errorf("快照中的 sing-box config.json 格式非法: %w", err)
		}
	}
	return nil
}

func (s *Server) handleClientBackupRestore(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Passphrase string `json:"passphrase"`
		Data       string `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxClientBackupUploadSize)).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "无效的请求或备份文件超过 4MB 上限")
		return
	}
	passphrase := strings.TrimSpace(body.Passphrase)
	rawData := strings.TrimSpace(body.Data)
	if len(passphrase) < 8 || rawData == "" {
		writeJSONError(w, http.StatusBadRequest, "请提供完整的加密快照内容与至少 8 位解密口令")
		return
	}

	payload, err := DecryptClientBackupBundle(passphrase, []byte(rawData))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := validateClientBackupPayload(payload); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()

	cfgPath := configPathFor(s)
	gPath := config.GroupsPathForConfig(cfgPath)
	aghPath := s.adguardConfigFilePath()
	sbPath := s.sbConfigPath()

	var restoredItems []string

	// 1. 恢复主配置 singctl.yaml (先备份现有文件再 0600 原子写入)
	if payload.SingctlYAML != "" && cfgPath != "" {
		if err := backupConfig(cfgPath); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "备份现有 singctl.yaml 失败: "+err.Error())
			return
		}
		if err := fsx.WriteAtomic0600(cfgPath, []byte(payload.SingctlYAML)); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "写入 singctl.yaml 失败: "+err.Error())
			return
		}
		s.invalidateConfigStore()
		restoredItems = append(restoredItems, "主配置 (singctl.yaml)")
	}

	// 2. 恢复声明式策略组配置 groups.yaml
	if payload.GroupsYAML != "" && gPath != "" {
		if err := backupConfig(gPath); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "备份现有 groups.yaml 失败: "+err.Error())
			return
		}
		if _, err := config.SaveGroupsFile(gPath, []byte(payload.GroupsYAML)); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "写入 groups.yaml 失败: "+err.Error())
			return
		}
		restoredItems = append(restoredItems, "分组编排 (groups.yaml)")
	}

	loadedCfg, cfgErr := s.loadConfigSnapshot()
	if cfgErr != nil || loadedCfg == nil {
		loadedCfg = &config.Config{}
		loadedCfg.SetSourcePath(cfgPath)
	}

	// 3. 恢复本地防劫持 DNS 配置 AdGuardHome.yaml
	if payload.AdGuardYAML != "" && aghPath != "" {
		if err := os.MkdirAll(filepath.Dir(aghPath), 0755); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "创建 AdGuard 配置目录失败: "+err.Error())
			return
		}
		if err := backupConfig(aghPath); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "备份现有 AdGuardHome.yaml 失败: "+err.Error())
			return
		}
		if err := fsx.WriteAtomic0600(aghPath, []byte(payload.AdGuardYAML)); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "写入 AdGuardHome.yaml 失败: "+err.Error())
			return
		}
		if !s.opts.SkipAdGuardProbeForTest {
			if info, statErr := os.Stat(s.adguardBinPath()); statErr == nil && !info.IsDir() {
				if rErr := s.newAdGuardManager(loadedCfg).Restart(); rErr != nil {
					logger.Warn("恢复备份后重启 AdGuard Home 提示: %v", rErr)
				}
			}
		}
		restoredItems = append(restoredItems, "AdGuard Home")
	}

	// 4. 恢复或无损重编译应用 sing-box config.json
	if sbPath != "" {
		existingSB, sbReadErr := os.ReadFile(sbPath)
		hasLiveSB := sbReadErr == nil && strings.TrimSpace(string(existingSB)) != ""
		if hasLiveSB {
			gc, _, _ := config.LoadGroupsFile(gPath)
			recompiled, _, compErr := singbox.RecompileLiveConfigWithGroups(string(existingSB), loadedCfg, gc, "")
			if compErr != nil {
				writeJSONError(w, http.StatusBadRequest, "使用恢复策略重编译 sing-box 配置失败: "+compErr.Error())
				return
			}
			if applyErr := singbox.ApplyLiveSingBoxConfig(r.Context(), sbPath, s.sbWorkConfigPath(), recompiled, "backup-restore"); applyErr != nil {
				writeJSONError(w, http.StatusBadRequest, "sing-box 校验或热重载失败: "+applyErr.Error())
				return
			}
			if baseRaw, bErr := singbox.LoadBaseSnapshot(sbPath); bErr == nil && strings.TrimSpace(baseRaw) != "" {
				if updatedBase, _, uErr := singbox.RecompileLiveConfigWithGroups(baseRaw, loadedCfg, gc, ""); uErr == nil {
					_ = singbox.SaveBaseSnapshot(sbPath, updatedBase)
				}
			}
			restoredItems = append(restoredItems, "sing-box 策略热重载")
		} else if payload.SingBoxConfigJSON != "" {
			if err := os.MkdirAll(filepath.Dir(sbPath), 0755); err != nil {
				writeJSONError(w, http.StatusInternalServerError, "创建 sing-box 配置目录失败: "+err.Error())
				return
			}
			if err := singbox.ValidateAndReplaceSingBoxConfig(r.Context(), sbPath, payload.SingBoxConfigJSON, ".restore.tmp"); err != nil {
				writeJSONError(w, http.StatusBadRequest, "快照中的 sing-box 配置校验失败: "+err.Error())
				return
			}
			restoredItems = append(restoredItems, "sing-box 配置")
		}
	}

	s.invalidateIOSCache()
	_ = daemon.NotifyReload()

	summary := strings.Join(restoredItems, "、")
	if summary == "" {
		summary = "无变更项"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"message":       fmt.Sprintf("已成功从加密快照恢复：%s", summary),
		"restoredItems": restoredItems,
	})
}
