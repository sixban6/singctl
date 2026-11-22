// 文件职责：提供客户端 WebUI 多渠道主动通知配置读取（强制脱敏）、密钥保留合并保存与渠道连通性测试接口。
package webui

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"singctl/internal/config"
	"singctl/internal/notify"
)

func redactedNotifyConfigDTO(cfg config.NotifyConfig) config.NotifyConfig {
	norm := cfg.Clone()
	norm.CooldownMinutes = cfg.EffectiveCooldownMinutes()
	norm.DailyLimit = cfg.EffectiveDailyLimit()
	norm.QuietHours = cfg.EffectiveQuietHours()
	norm.Events = cfg.EffectiveEvents()
	return norm.Redacted()
}

func decodeNotifyConfigBody(body io.Reader) (config.NotifyConfig, error) {
	raw, err := io.ReadAll(body)
	if err != nil {
		return config.NotifyConfig{}, err
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return config.NotifyConfig{}, err
	}
	target := raw
	if cfgRaw, ok := envelope["config"]; ok && len(cfgRaw) > 0 && string(cfgRaw) != "null" {
		target = cfgRaw
	}
	var cfg config.NotifyConfig
	if err := json.Unmarshal(target, &cfg); err != nil {
		return config.NotifyConfig{}, err
	}
	return cfg, nil
}

func (s *Server) handleNotifyConfigGet(w http.ResponseWriter, _ *http.Request) {
	cfg := s.readConfigOrEmpty()
	if s.notifier != nil {
		s.notifier.UpdateOptions(notify.OptionsFromConfig(cfg.Notify))
	}
	history := []notify.HistoryRecord{}
	if s.notifier != nil {
		if recent := s.notifier.RecentHistory(); recent != nil {
			history = recent
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"config":        redactedNotifyConfigDTO(cfg.Notify),
		"secretStatus":  cfg.Notify.SecretStatus(),
		"recentHistory": history,
	})
}

func (s *Server) handleNotifyConfigPut(w http.ResponseWriter, r *http.Request) {
	incoming, err := decodeNotifyConfigBody(r.Body)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}

	updatedCfg, err := s.updateConfigTx(configTxOptions{
		SaveErrPrefix: "保存通知配置失败: ",
	}, func(cfg *config.Config) error {
		merged := incoming.MergePreservingSecrets(cfg.Notify)
		if valErr := notify.ValidateConfig(merged); valErr != nil {
			return &apiStatusError{status: http.StatusBadRequest, msg: valErr.Error()}
		}
		if merged.CooldownMinutes > 0 {
			merged.CooldownMinutes = merged.EffectiveCooldownMinutes()
		}
		if merged.DailyLimit > 0 {
			merged.DailyLimit = merged.EffectiveDailyLimit()
		}
		cfg.Notify = merged
		return nil
	})
	if err != nil {
		writePartialSaveError(w, err)
		return
	}

	if s.notifier != nil {
		s.notifier.UpdateOptions(notify.OptionsFromConfig(updatedCfg.Notify))
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":           true,
		"config":       redactedNotifyConfigDTO(updatedCfg.Notify),
		"secretStatus": updatedCfg.Notify.SecretStatus(),
	})
}

func (s *Server) handleNotifyTestPost(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Channel string               `json:"channel"`
		Config  *config.NotifyConfig `json:"config"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil && !errors.Is(err, io.EOF) {
		writeJSONError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}

	saved := s.readConfigOrEmpty().Notify
	effective := saved
	if body.Config != nil {
		effective = body.Config.MergePreservingSecrets(saved)
	}
	opts := notify.OptionsFromConfig(effective)

	results := []notify.DeliveryResult{}
	history := []notify.HistoryRecord{}
	if s.notifier != nil {
		if res := s.notifier.SendTest(r.Context(), opts, body.Channel); res != nil {
			results = res
		}
		if recent := s.notifier.RecentHistory(); recent != nil {
			history = recent
		}
	}

	anySuccess := false
	for _, res := range results {
		if res.OK {
			anySuccess = true
			break
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":            anySuccess,
		"results":       results,
		"recentHistory": history,
	})
}
