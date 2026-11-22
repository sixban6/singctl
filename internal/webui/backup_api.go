// 文件职责：提供客户端网关配置 V2 加密灾备包导出、跨硬件智能自适配与全事务原子回滚恢复接口。
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
	"singctl/internal/common/sysinfo"
	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/daemon"
	"singctl/internal/logger"
	"singctl/internal/singbox"

	"gopkg.in/yaml.v3"
)

const (
	clientBackupFormatVersion = "SINGCTL-CLIENT-BAK-V2"
	maxClientBackupUploadSize = 16 * 1024 * 1024 // 16 MiB
)

// ClientBackupEnvelope 为客户端网关加密灾备快照外层信封（复用 common/cryptobak.Envelope）。
type ClientBackupEnvelope = cryptobak.Envelope

// ClientBackupPayload 保存网关可迁出的完整核心配置、三路合并基线与离线规则集归档。
type ClientBackupPayload struct {
	Version           string `json:"version"`
	ExportedAt        string `json:"exportedAt"`
	SingctlYAML       string `json:"singctlYaml,omitempty"`
	GroupsYAML        string `json:"groupsYaml,omitempty"`
	AdGuardYAML       string `json:"adguardYaml,omitempty"`
	SmartDNSConf      string `json:"smartdnsConf,omitempty"`
	SingBoxConfigJSON string `json:"singboxConfigJson,omitempty"`
	SingBoxBaseJSON   string `json:"singboxBaseJson,omitempty"`
	RuleSetsTarGz     []byte `json:"ruleSetsTarGz,omitempty"`
	RuleSetCount      int    `json:"ruleSetCount,omitempty"`
}

// EncryptClientBackupBundle 使用 PBKDF2-HMAC-SHA256 + AES-256-GCM 加密网关 V2 备份载荷。
func EncryptClientBackupBundle(passphrase string, payload ClientBackupPayload) ([]byte, error) {
	return cryptobak.Encrypt(clientBackupFormatVersion, passphrase, payload)
}

// DecryptClientBackupBundle 在内存中校验 V2 信封并解密网关灾备快照（拒绝非 V2 旧包）。
func DecryptClientBackupBundle(passphrase string, rawEnvelope []byte) (*ClientBackupPayload, error) {
	return cryptobak.Decrypt[ClientBackupPayload](clientBackupFormatVersion, passphrase, rawEnvelope)
}

func (s *Server) handleClientBackupExport(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Passphrase      string `json:"passphrase"`
		IncludeRuleSets *bool  `json:"includeRuleSets,omitempty"`
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
	includeRuleSets := true
	if body.IncludeRuleSets != nil {
		includeRuleSets = *body.IncludeRuleSets
	}

	s.cfgMu.Lock()
	cfgPath := configPathFor(s)
	gPath := config.GroupsPathForConfig(cfgPath)
	aghPath := s.adguardConfigFilePath()
	smartDNSPath := s.smartDNSConfigFilePath()
	sbPath := s.sbConfigPath()
	rsDir := s.ruleSetCacheDir()

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
	if smartDNSPath != "" {
		if raw, err := os.ReadFile(smartDNSPath); err == nil {
			payload.SmartDNSConf = string(raw)
		}
	}
	if sbPath != "" {
		if raw, err := os.ReadFile(sbPath); err == nil {
			payload.SingBoxConfigJSON = string(raw)
		}
		if baseRaw, err := singbox.LoadBaseSnapshot(sbPath); err == nil && strings.TrimSpace(baseRaw) != "" {
			payload.SingBoxBaseJSON = baseRaw
		}
	}
	var packErr error
	if includeRuleSets {
		payload.RuleSetsTarGz, payload.RuleSetCount, packErr = packRuleSetsTarGz(rsDir)
	}
	s.cfgMu.Unlock()

	if packErr != nil {
		writeJSONError(w, http.StatusInternalServerError, "打包离线规则集失败: "+packErr.Error())
		return
	}
	if payload.SingctlYAML == "" && payload.GroupsYAML == "" && payload.AdGuardYAML == "" && payload.SmartDNSConf == "" &&
		payload.SingBoxConfigJSON == "" && payload.SingBoxBaseJSON == "" && len(payload.RuleSetsTarGz) == 0 {
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
		"message":  "网关 V2 加密备份快照已生成，请妥善保管文件与解密口令",
		"filename": filename,
		"data":     string(encryptedBytes),
		"summary": map[string]any{
			"hasSingctlCfg":  payload.SingctlYAML != "",
			"hasGroups":      payload.GroupsYAML != "",
			"hasAdGuard":     payload.AdGuardYAML != "",
			"hasSmartDNS":    payload.SmartDNSConf != "",
			"hasSingBox":     payload.SingBoxConfigJSON != "",
			"hasSingBoxBase": payload.SingBoxBaseJSON != "",
			"ruleSetCount":   payload.RuleSetCount,
		},
	})
}

func validateClientBackupPayload(p *ClientBackupPayload) ([]ruleSetArchiveEntry, error) {
	if p.SingctlYAML != "" {
		var checkMap map[string]any
		if err := yaml.Unmarshal([]byte(p.SingctlYAML), &checkMap); err != nil {
			return nil, fmt.Errorf("快照中的 singctl.yaml 格式非法: %w", err)
		}
		var checkCfg config.Config
		if err := yaml.Unmarshal([]byte(p.SingctlYAML), &checkCfg); err != nil {
			return nil, fmt.Errorf("快照中的 singctl.yaml 结构非法: %w", err)
		}
	}
	if p.GroupsYAML != "" {
		if _, err := config.ParseGroupsYAML([]byte(p.GroupsYAML)); err != nil {
			return nil, fmt.Errorf("快照中的 groups.yaml 校验失败: %w", err)
		}
	}
	if p.AdGuardYAML != "" {
		var checkMap map[string]any
		if err := yaml.Unmarshal([]byte(p.AdGuardYAML), &checkMap); err != nil {
			return nil, fmt.Errorf("快照中的 AdGuardHome.yaml 格式非法: %w", err)
		}
	}
	if p.SmartDNSConf != "" && strings.ContainsRune(p.SmartDNSConf, '\x00') {
		return nil, fmt.Errorf("快照中的 smartdns.conf 包含非法空字节")
	}
	if p.SingBoxConfigJSON != "" {
		var checkObj map[string]any
		if err := json.Unmarshal([]byte(p.SingBoxConfigJSON), &checkObj); err != nil {
			return nil, fmt.Errorf("快照中的 sing-box config.json 格式非法: %w", err)
		}
	}
	if p.SingBoxBaseJSON != "" {
		var checkBase map[string]any
		if err := json.Unmarshal([]byte(p.SingBoxBaseJSON), &checkBase); err != nil {
			return nil, fmt.Errorf("快照中的 .config.json.singctl-base 格式非法: %w", err)
		}
	}
	rsEntries, err := parseAndValidateRuleSetsTarGz(p.RuleSetsTarGz)
	if err != nil {
		return nil, err
	}
	return rsEntries, nil
}

func (s *Server) hostTotalRAMBytes() uint64 {
	if s != nil && s.opts.AdGuardMemInfoForTest != nil {
		return s.opts.AdGuardMemInfoForTest().TotalBytes
	}
	return sysinfo.TotalRAMBytes()
}

func (s *Server) isTargetLowMemory(cfg *config.Config) bool {
	if cfg != nil {
		if norm, ok := config.NormalizeLowMemoryMode(string(cfg.LowMemory)); ok {
			switch norm {
			case config.LowMemoryOn:
				return true
			case config.LowMemoryOff:
				return false
			}
		}
	}
	if s != nil && s.opts.LowMemoryMode != nil {
		return *s.opts.LowMemoryMode
	}
	return cfg.EffectiveLowMemory(s.hostTotalRAMBytes())
}

func (s *Server) hasAdGuardBinary() bool {
	binPath := s.adguardBinPath()
	if binPath == "" {
		return false
	}
	info, err := os.Stat(binPath)
	return err == nil && !info.IsDir()
}

func (s *Server) hasSmartDNSBinary() bool {
	binPath := s.smartDNSBinPath()
	if binPath == "" {
		return false
	}
	info, err := os.Stat(binPath)
	return err == nil && !info.IsDir()
}

func (s *Server) previewTargetConfig(singctlYAML string) *config.Config {
	if strings.TrimSpace(singctlYAML) != "" {
		var cfg config.Config
		if err := yaml.Unmarshal([]byte(singctlYAML), &cfg); err == nil {
			return &cfg
		}
	}
	if snap, err := s.loadConfigSnapshot(); err == nil && snap != nil {
		return snap
	}
	return &config.Config{}
}

func (s *Server) handleClientBackupRestore(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Passphrase string `json:"passphrase"`
		Data       string `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxClientBackupUploadSize)).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "无效的请求或备份文件超过 16MB 上限")
		return
	}
	passphrase := strings.TrimSpace(body.Passphrase)
	rawData := strings.TrimSpace(body.Data)
	if len(passphrase) < 8 || rawData == "" {
		writeJSONError(w, http.StatusBadRequest, "请提供完整的加密快照内容与至少 8 位解密口令")
		return
	}

	// 前置全量解密与校验（动磁盘前完成全部 YAML/JSON/BaseJSON/tar.gz 安全校验）
	payload, err := DecryptClientBackupBundle(passphrase, []byte(rawData))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	rsEntries, err := validateClientBackupPayload(payload)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()

	cfgPath := configPathFor(s)
	gPath := config.GroupsPathForConfig(cfgPath)
	aghPath := s.adguardConfigFilePath()
	smartDNSPath := s.smartDNSConfigFilePath()
	sbPath := s.sbConfigPath()
	sbWorkPath := s.sbWorkConfigPath()
	rsDir := s.ruleSetCacheDir()

	// 启动全事务原子回滚栈：后续任意步骤失败均完整回滚所有已写文件与规则集目录并刷新 cfgStore
	tx := newRestoreTransaction(s)
	defer tx.rollbackIfNeeded()

	restoredItems := []string{}
	adaptations := []string{}

	previewCfg := s.previewTargetConfig(payload.SingctlYAML)
	targetLowMem := s.isTargetLowMemory(previewCfg)

	// 1. 先将离线规则集原子落盘至 rule_sets 目录（低内存目标跳过巨型 geosite-ad2.srs 节省闪存）
	restoredRuleSetCount, skippedHeavyRS, writtenRS, rsErr := applyRuleSetEntriesToDir(tx, rsDir, rsEntries, targetLowMem)
	if rsErr != nil {
		writeJSONError(w, http.StatusInternalServerError, rsErr.Error())
		return
	}
	if restoredRuleSetCount > 0 {
		restoredItems = append(restoredItems, fmt.Sprintf("离线规则集 (%d 项)", restoredRuleSetCount))
	}

	// 2. 原子写入 singctl.yaml (0600)、groups.yaml、AdGuardHome.yaml (0600)、.config.json.singctl-base (0600)
	if payload.SingctlYAML != "" && cfgPath != "" {
		if err := tx.snapshotFile(cfgPath); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "快照现有 singctl.yaml 失败: "+err.Error())
			return
		}
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

	if payload.GroupsYAML != "" && gPath != "" {
		if err := tx.snapshotFile(gPath); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "快照现有 groups.yaml 失败: "+err.Error())
			return
		}
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
	targetLowMem = s.isTargetLowMemory(loadedCfg)

	adguardRestored := false
	if payload.AdGuardYAML != "" && aghPath != "" {
		if err := tx.ensureDir(filepath.Dir(aghPath)); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "创建 AdGuard 配置目录失败: "+err.Error())
			return
		}
		if err := tx.snapshotFile(aghPath); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "快照现有 AdGuardHome.yaml 失败: "+err.Error())
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
		adguardRestored = true
		restoredItems = append(restoredItems, "AdGuard Home")
	}

	smartDNSRestored := false
	if payload.SmartDNSConf != "" && smartDNSPath != "" {
		if err := tx.ensureDir(filepath.Dir(smartDNSPath)); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "创建 SmartDNS 配置目录失败: "+err.Error())
			return
		}
		if err := tx.snapshotFile(smartDNSPath); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "快照现有 smartdns.conf 失败: "+err.Error())
			return
		}
		if err := backupConfig(smartDNSPath); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "备份现有 smartdns.conf 失败: "+err.Error())
			return
		}
		if err := fsx.WriteAtomic0600(smartDNSPath, []byte(payload.SmartDNSConf)); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "写入 smartdns.conf 失败: "+err.Error())
			return
		}
		smartDNSRestored = true
		restoredItems = append(restoredItems, "SmartDNS")
	}

	if payload.SingBoxBaseJSON != "" && sbPath != "" {
		basePath := singbox.BaseSnapshotPath(sbPath)
		if err := tx.ensureDir(filepath.Dir(basePath)); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "创建 sing-box 基线目录失败: "+err.Error())
			return
		}
		if err := tx.snapshotFile(basePath); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "快照现有 .singctl-base 失败: "+err.Error())
			return
		}
		if err := singbox.SaveBaseSnapshot(sbPath, payload.SingBoxBaseJSON); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "写入 .config.json.singctl-base 失败: "+err.Error())
			return
		}
		restoredItems = append(restoredItems, "三路合并基线 (.singctl-base)")
	}

	// 3. 跨硬件智能自适配并校验应用 sing-box config.json（备份优先，仅在缺失时回退本地旧 config.json）
	didPruneAd2InConfig := false
	if sbPath != "" {
		existingSB, sbReadErr := os.ReadFile(sbPath)
		hasLiveSB := sbReadErr == nil && strings.TrimSpace(string(existingSB)) != ""
		targetJSON := strings.TrimSpace(payload.SingBoxConfigJSON)
		if targetJSON == "" && hasLiveSB {
			targetJSON = string(existingSB)
		}

		if targetJSON != "" {
			if hasLiveSB && strings.TrimSpace(payload.SingBoxConfigJSON) != "" {
				targetJSON = preserveLiveClashSecret(string(existingSB), targetJSON)
			}

			hasSmartDNSUsable := s.hasSmartDNSBinary() && (loadedCfg.DNS.GetEngine() == constant.DNSEngineSmartDNS || payload.SmartDNSConf != "")
			noExternalDNS := !s.hasAdGuardBinary() && !hasSmartDNSUsable
			adaptedJSON, didFallbackDoH, didPruneAd2, adaptErr := adaptSingBoxJSONForTarget(
				targetJSON, rsDir, writtenRS, noExternalDNS, targetLowMem,
			)
			if adaptErr != nil {
				writeJSONError(w, http.StatusBadRequest, adaptErr.Error())
				return
			}
			didPruneAd2InConfig = didPruneAd2
			if didFallbackDoH {
				adaptations = append(adaptations, "目标机未安装可用的外部本地 DNS 引擎（AdGuard Home / SmartDNS），已自动将 dns_local 安全回退为 sing-box 内置纯 IP 加密 DoH (223.5.5.5，已关闭乐观缓存)")
			}
			if didPruneAd2 {
				if skippedHeavyRS {
					adaptations = append(adaptations, "目标机处于低内存模式，已自动剥离重型广告规则集 geosite-ad2 并跳过落盘以节省内存与闪存")
				} else {
					adaptations = append(adaptations, "目标机处于低内存模式，已自动剥离重型广告规则集 geosite-ad2 以节省内存")
				}
			}

			gc, _, _ := config.LoadGroupsFile(gPath)
			recompiled, _, compErr := singbox.RecompileLiveConfigWithGroups(adaptedJSON, loadedCfg, gc, "")
			if compErr != nil {
				writeJSONError(w, http.StatusBadRequest, "使用恢复策略重编译 sing-box 配置失败: "+compErr.Error())
				return
			}

			if err := tx.ensureDir(filepath.Dir(sbPath)); err != nil {
				writeJSONError(w, http.StatusInternalServerError, "创建 sing-box 配置目录失败: "+err.Error())
				return
			}
			if err := tx.snapshotFile(sbPath); err != nil {
				writeJSONError(w, http.StatusInternalServerError, "快照现有 sing-box 配置失败: "+err.Error())
				return
			}
			if sbWorkPath != "" {
				_ = tx.snapshotFile(sbWorkPath)
			}

			if hasLiveSB {
				if applyErr := singbox.ApplyLiveSingBoxConfig(r.Context(), sbPath, sbWorkPath, recompiled, "backup-restore"); applyErr != nil {
					writeJSONError(w, http.StatusBadRequest, "sing-box 校验或热重载失败: "+applyErr.Error())
					return
				}
				restoredItems = append(restoredItems, "sing-box 策略热重载")
			} else {
				if err := singbox.ValidateAndReplaceSingBoxConfig(r.Context(), sbPath, recompiled, ".restore.tmp"); err != nil {
					writeJSONError(w, http.StatusBadRequest, "快照中的 sing-box 配置校验失败: "+err.Error())
					return
				}
				if sbWorkPath != "" {
					if err := singbox.SyncSandboxWorkConfig(r.Context(), sbPath, sbWorkPath, recompiled, ".restore.tmp"); err != nil {
						writeJSONError(w, http.StatusBadRequest, "同步 sing-box 沙盒配置失败: "+err.Error())
						return
					}
				}
				singbox.ReloadSingBoxProcess()
				restoredItems = append(restoredItems, "sing-box 配置")
			}

			// 同步对齐 .config.json.singctl-base，保证后续三路合并基线与跨机自适配结果一致
			if baseRaw, bErr := singbox.LoadBaseSnapshot(sbPath); bErr == nil && strings.TrimSpace(baseRaw) != "" {
				if adaptedBase, _, _, aErr := adaptSingBoxJSONForTarget(baseRaw, rsDir, writtenRS, noExternalDNS, targetLowMem); aErr == nil {
					if updatedBase, _, uErr := singbox.RecompileLiveConfigWithGroups(adaptedBase, loadedCfg, gc, ""); uErr == nil {
						_ = singbox.SaveBaseSnapshot(sbPath, updatedBase)
					}
				}
			}
		}
	}

	if skippedHeavyRS && !didPruneAd2InConfig {
		adaptations = append(adaptations, "目标机处于低内存模式，已跳过将重型规则集 geosite-ad2.srs 写入闪存")
	}

	// 全部校验与落盘成功，正式提交事务（不再回滚）
	tx.commit()

	if adguardRestored && !s.opts.SkipAdGuardProbeForTest && s.hasAdGuardBinary() {
		if rErr := s.newAdGuardManager(loadedCfg).Restart(); rErr != nil {
			logger.Warn("恢复备份后重启 AdGuard Home 提示: %v", rErr)
		}
	}
	if smartDNSRestored && !s.opts.SkipAdGuardProbeForTest && s.hasSmartDNSBinary() {
		if sdEng, ok := s.newDNSRegistry(loadedCfg).Get(constant.DNSEngineSmartDNS); ok {
			if rErr := sdEng.Restart(r.Context()); rErr != nil {
				logger.Warn("恢复备份后重启 SmartDNS 提示: %v", rErr)
			}
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
		"ruleSetCount":  restoredRuleSetCount,
		"adaptations":   adaptations,
	})
}
