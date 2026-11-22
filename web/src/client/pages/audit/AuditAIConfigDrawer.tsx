import React, { useCallback, useEffect, useRef, useState } from 'react';
import { RefreshCw } from 'lucide-react';
import { Button, SlideDrawer, useToast } from '../../../ui';
import { clientApi } from '../../api';
import { AuditAIConfig } from '../../types';

export interface AuditAIConfigDrawerProps {
  open: boolean;
  onClose: () => void;
}

export const AuditAIConfigDrawer: React.FC<AuditAIConfigDrawerProps> = ({ open, onClose }) => {
  const { success, error } = useToast();
  const [aiConfig, setAiConfig] = useState<AuditAIConfig>({
    baseUrl: '',
    apiKey: '',
    model: 'antigravity/gemini-3.8-flash',
  });
  const [aiCfgSaving, setAiCfgSaving] = useState(false);
  const [aiModels, setAiModels] = useState<string[]>([]);
  const [aiModelsLoading, setAiModelsLoading] = useState(false);
  const [aiModelsHint, setAiModelsHint] = useState<string>('');
  const [manualModelInput, setManualModelInput] = useState(false);
  const lastFetchedSigRef = useRef<string>('');

  const fetchAIModels = useCallback(
    async (baseUrl: string, apiKey: string, silent = false) => {
      const cleanBase = (baseUrl || '').trim();
      const cleanKey = (apiKey || '').trim();
      lastFetchedSigRef.current = `${cleanBase}|${cleanKey}`;
      setAiModelsLoading(true);
      try {
        const res = await clientApi.fetchAuditAIModels({
          baseUrl: cleanBase,
          apiKey: cleanKey,
        });
        if (res.ok && res.models && res.models.length > 0) {
          setAiModels(res.models);
          setAiModelsHint('');
          setManualModelInput(false);
          setAiConfig((prev) => {
            const cur = (prev.model || '').trim();
            if (!cur) {
              return { ...prev, model: res.models[0] };
            }
            return prev;
          });
          if (!silent) {
            success(`已从网关拉取 ${res.models.length} 个可用模型`);
          }
        } else {
          setAiModels([]);
          setManualModelInput(true);
          setAiModelsHint(res.error || '网关未返回模型列表');
          if (!silent) {
            error(`${res.error || '未能拉取到模型列表'}，请手动填写模型名称`);
          }
        }
      } catch (e) {
        const msg = (e as Error).message || '连接网关失败';
        setAiModels([]);
        setManualModelInput(true);
        setAiModelsHint(msg);
        if (!silent) {
          error(`拉取模型失败（${msg}），请手动填写`);
        }
      } finally {
        setAiModelsLoading(false);
      }
    },
    [success, error],
  );

  const loadAIConfig = useCallback(async () => {
    try {
      const cfg = await clientApi.getAuditAIConfig();
      const nextCfg: AuditAIConfig = {
        baseUrl: cfg.baseUrl || '',
        apiKey: cfg.apiKey || '',
        model: cfg.model || 'antigravity/gemini-3.8-flash',
        suggestedLanUrl: cfg.suggestedLanUrl,
      };
      setAiConfig(nextCfg);
      void fetchAIModels(nextCfg.baseUrl, nextCfg.apiKey, true);
    } catch (e) {
      error((e as Error).message || '读取 AI 网关配置失败');
    }
  }, [error, fetchAIModels]);

  useEffect(() => {
    if (open) {
      void loadAIConfig();
    }
  }, [open, loadAIConfig]);

  const handleSaveAIConfig = async () => {
    setAiCfgSaving(true);
    try {
      const res = await clientApi.saveAuditAIConfig({
        baseUrl: aiConfig.baseUrl.trim(),
        apiKey: aiConfig.apiKey.trim(),
        model: aiConfig.model.trim() || 'antigravity/gemini-3.8-flash',
      });
      success(res.message || 'AI 网关配置已保存');
      onClose();
    } catch (e) {
      error((e as Error).message || '保存 AI 网关配置失败');
    } finally {
      setAiCfgSaving(false);
    }
  };

  return (
    <SlideDrawer
      open={open}
      onClose={onClose}
      size="md"
      title="AI 审计网关配置"
      subtitle="支持本地 Magpie 反代网关或任意 OpenAI Compatible 接口"
      footer={
        <div className="flex justify-end gap-2">
          <Button variant="secondary" onClick={onClose}>
            取消
          </Button>
          <Button variant="primary" loading={aiCfgSaving} onClick={() => void handleSaveAIConfig()}>
            保存配置
          </Button>
        </div>
      }
    >
      <div className="space-y-4">
        {aiConfig.suggestedLanUrl && (
          <div className="rounded-xl border border-emerald-500/25 bg-emerald-500/10 p-3 flex items-center justify-between gap-2">
            <div className="text-xs text-secondary">
              检测到局域网 Magpie 候选地址：
              <span className="font-mono text-primary ml-1">{aiConfig.suggestedLanUrl}</span>
            </div>
            <Button
              size="xs"
              variant="secondary"
              onClick={() => {
                const nextUrl = aiConfig.suggestedLanUrl || aiConfig.baseUrl;
                setAiConfig((prev) => ({ ...prev, baseUrl: nextUrl }));
                void fetchAIModels(nextUrl, aiConfig.apiKey, false);
              }}
            >
              一键填入并拉取模型
            </Button>
          </div>
        )}

        <div>
          <label className="block text-xs font-semibold text-secondary mb-1.5">
            网关请求地址 (BaseURL)
          </label>
          <input
            type="text"
            value={aiConfig.baseUrl}
            onChange={(e) => setAiConfig({ ...aiConfig, baseUrl: e.target.value })}
            onBlur={() => {
              const sig = `${aiConfig.baseUrl.trim()}|${aiConfig.apiKey.trim()}`;
              if (sig !== lastFetchedSigRef.current) {
                void fetchAIModels(aiConfig.baseUrl, aiConfig.apiKey, true);
              }
            }}
            placeholder="http://127.0.0.1:3425/v1 (留空自动探测 :3425)"
            className="sc-input w-full px-3 py-2 text-xs font-mono"
          />
        </div>

        <div>
          <label className="block text-xs font-semibold text-secondary mb-1.5">
            网关密钥 (API Key)
          </label>
          <input
            type="password"
            autoComplete="new-password"
            value={aiConfig.apiKey}
            onChange={(e) => setAiConfig({ ...aiConfig, apiKey: e.target.value })}
            onBlur={() => {
              const sig = `${aiConfig.baseUrl.trim()}|${aiConfig.apiKey.trim()}`;
              if (sig !== lastFetchedSigRef.current) {
                void fetchAIModels(aiConfig.baseUrl, aiConfig.apiKey, true);
              }
            }}
            placeholder="sk-magpie-key-... (同机 127.0.0.1 可留空)"
            className="sc-input w-full px-3 py-2 text-xs font-mono"
          />
        </div>

        <div className="space-y-1.5">
          <div className="flex items-center justify-between gap-2">
            <label className="block text-xs font-semibold text-secondary">
              访问模型 (Model)
            </label>
            <div className="flex items-center gap-1.5">
              {aiModels.length > 0 && (
                <button
                  type="button"
                  onClick={() => setManualModelInput((v) => !v)}
                  className="text-[11px] text-emerald-400 hover:text-emerald-300 underline cursor-pointer"
                >
                  {manualModelInput ? `切换下拉选择 (${aiModels.length})` : '手动输入'}
                </button>
              )}
              <Button
                size="xs"
                variant="ghost"
                loading={aiModelsLoading}
                icon={<RefreshCw className="w-3 h-3" />}
                onClick={() => void fetchAIModels(aiConfig.baseUrl, aiConfig.apiKey, false)}
              >
                拉取模型
              </Button>
            </div>
          </div>

          {aiModels.length > 0 && !manualModelInput ? (
            <select
              aria-label="选择访问模型"
              value={aiConfig.model}
              onChange={(e) => {
                const val = e.target.value;
                if (val === '__manual__') {
                  setManualModelInput(true);
                  return;
                }
                setAiConfig({ ...aiConfig, model: val });
              }}
              className="sc-input w-full h-9 px-3 text-xs font-mono text-primary"
            >
              {aiConfig.model && !aiModels.includes(aiConfig.model) && (
                <option value={aiConfig.model}>{aiConfig.model} (当前已配置)</option>
              )}
              {aiModels.map((m) => (
                <option key={m} value={m}>
                  {m}
                </option>
              ))}
              <option value="__manual__">✍️ 手动填写其他模型名称…</option>
            </select>
          ) : (
            <input
              type="text"
              value={aiConfig.model}
              onChange={(e) => setAiConfig({ ...aiConfig, model: e.target.value })}
              placeholder="antigravity/gemini-3.8-flash"
              className="sc-input w-full px-3 py-2 text-xs font-mono"
            />
          )}

          {aiModelsLoading ? (
            <div className="text-[11px] text-muted">正在从网关拉取可用模型列表…</div>
          ) : aiModels.length > 0 && !manualModelInput ? (
            <div className="text-[11px] text-emerald-400">
              已自动从网关拉取 {aiModels.length} 个可用模型，可直接下拉选择或切换手动输入。
            </div>
          ) : aiModelsHint ? (
            <div className="text-[11px] text-muted">
              未能自动拉取模型列表（{aiModelsHint}），可直接手动填写模型名称。
            </div>
          ) : null}
        </div>

        <p className="text-xs text-muted leading-relaxed">
          默认使用 <code className="text-primary">antigravity/gemini-3.8-flash</code>。若留空 BaseURL，系统将按「配置网关 → 127.0.0.1:3425 → 当前电脑局域网 IP:3425 → 离线专家库」顺序自动探测。
        </p>
      </div>
    </SlideDrawer>
  );
};
