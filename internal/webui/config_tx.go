// 文件职责：提供客户端 WebUI 统一配置修改事务（备份、原子落盘、热生效失败字节级回滚与看门狗通知）及错误 URL 脱敏。
package webui

import (
	"errors"
	"net/http"
	"os"
	"regexp"

	"singctl/internal/common/fsx"
	"singctl/internal/common/redact"
	"singctl/internal/config"
	"singctl/internal/daemon"
)

var urlInTextRe = regexp.MustCompile(`https?://[^\s"'<>]+`)

// sanitizeSubErrorText 使用 common/redact.MaskURL 对错误文本中的订阅 URL 与查询串凭据进行安全脱敏。
func sanitizeSubErrorText(err error) string {
	if err == nil {
		return ""
	}
	return urlInTextRe.ReplaceAllStringFunc(err.Error(), redact.MaskURL)
}

type apiStatusError struct {
	status int
	msg    string
}

func (e *apiStatusError) Error() string { return e.msg }

func writePartialSaveError(w http.ResponseWriter, err error) {
	if apiErr, ok := errors.AsType[*apiStatusError](err); ok {
		writeJSONError(w, apiErr.status, apiErr.msg)
		return
	}
	writeJSONError(w, http.StatusBadRequest, err.Error())
}

type configTxOptions struct {
	SyncAdGuard   bool
	InvalidateIOS bool
	SaveErrPrefix string
	LiveApply     func(cfg *config.Config) error
}

// updateConfigTx 在 s.cfgMu 互斥锁保护下执行：深拷贝可变配置 -> 业务变更校验 -> 滚动备份 -> 0600 落盘写透 ->
// 可选在线热应用（失败自动字节级回滚磁盘与内存缓存）-> 通知看门狗热重载。
func (s *Server) updateConfigTx(opts configTxOptions, mutate func(cfg *config.Config) error) (*config.Config, error) {
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()

	cfgPath := configPathFor(s)
	origBytes, origReadErr := os.ReadFile(cfgPath)

	cfg := s.loadMutableConfig()
	if err := mutate(cfg); err != nil {
		return nil, err
	}

	if err := backupConfig(cfgPath); err != nil {
		return nil, &apiStatusError{status: http.StatusInternalServerError, msg: "备份配置失败: " + err.Error()}
	}
	savePrefix := opts.SaveErrPrefix
	if savePrefix == "" {
		savePrefix = "保存配置失败: "
	}
	if err := s.saveConfig(cfg); err != nil {
		return nil, &apiStatusError{status: http.StatusInternalServerError, msg: savePrefix + err.Error()}
	}

	if opts.InvalidateIOS || opts.SyncAdGuard {
		s.invalidateIOSCache()
	}

	if opts.LiveApply != nil {
		if applyErr := opts.LiveApply(cfg); applyErr != nil {
			s.rollbackSavedConfigFile(cfgPath, origBytes, origReadErr)
			return nil, applyErr
		}
	}

	if opts.SyncAdGuard {
		s.syncAdGuardSubWhitelistAsync(cfg)
	}
	_ = daemon.NotifyReload()
	return cfg, nil
}

func (s *Server) rollbackSavedConfigFile(cfgPath string, origBytes []byte, origReadErr error) {
	if cfgPath == "" {
		return
	}
	if origReadErr == nil {
		_ = fsx.WriteAtomic0600(cfgPath, origBytes)
	} else if os.IsNotExist(origReadErr) {
		_ = os.Remove(cfgPath)
	}
	s.invalidateConfigStore()
}

func (s *Server) savePartialConfig(syncAdGuard bool, mutate func(cfg *config.Config) error) error {
	_, err := s.updateConfigTx(configTxOptions{SyncAdGuard: syncAdGuard}, mutate)
	return err
}
