import React, { useState, useEffect, useCallback } from 'react';
import { Link2, Plus, RefreshCw, Save, Trash2, Zap } from 'lucide-react';
import { Button, SectionCard, useToast } from '../../../ui';
import { clientApi } from '../../api';
import { ClientConfigSubDTO } from '../../types';

export interface SubscriptionsPanelProps {
  busy: boolean;
  onAction: (name: string, params?: Record<string, unknown>, confirmMsg?: string) => void;
  onSaved?: () => void;
}

const EMPTY_SUB: ClientConfigSubDTO = {
  name: '',
  url: '',
  skip_tls_verify: false,
  remove_emoji: false,
};

export const SubscriptionsPanel: React.FC<SubscriptionsPanelProps> = ({ busy, onAction, onSaved }) => {
  const { success, error } = useToast();
  const [cfgPath, setCfgPath] = useState('');
  const [subs, setSubs] = useState<ClientConfigSubDTO[]>([{ ...EMPTY_SUB }]);
  const [hy2Up, setHy2Up] = useState(0);
  const [hy2Down, setHy2Down] = useState(0);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);

  const loadSubs = useCallback(async () => {
    setLoading(true);
    try {
      const res = await clientApi.getConfig();
      setCfgPath(res.path || '');
      const c = res.config;
      setSubs(c.subs?.length ? c.subs : [{ ...EMPTY_SUB }]);
      setHy2Up(c.hy2?.up || 0);
      setHy2Down(c.hy2?.down || 0);
    } catch (err: unknown) {
      error(`加载订阅配置失败：${err instanceof Error ? err.message : '未知错误'}`);
    } finally {
      setLoading(false);
    }
  }, [error]);

  useEffect(() => {
    void loadSubs();
  }, [loadSubs]);

  const updateSub = (idx: number, patch: Partial<ClientConfigSubDTO>) => {
    setSubs((prev) => prev.map((s, i) => (i === idx ? { ...s, ...patch } : s)));
  };

  const handleSave = async () => {
    const validSubs = subs.filter((s) => s.name.trim() || s.url.trim());
    for (const s of validSubs) {
      if (!s.url.trim()) {
        error(`订阅「${s.name || '未命名'}」缺少订阅 URL`);
        return;
      }
    }
    setSaving(true);
    try {
      await clientApi.saveSbSubs({
        subs: validSubs,
        hy2: {
          up: Math.max(0, Number(hy2Up) || 0),
          down: Math.max(0, Number(hy2Down) || 0),
        },
      });
      success('订阅源与 Hysteria2 带宽已保存（已自动备份原配置）');
      await loadSubs();
      onSaved?.();
    } catch (err: unknown) {
      error(`保存订阅失败：${err instanceof Error ? err.message : '未知错误'}`);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="space-y-4">
      <SectionCard
        title="机场订阅列表与带宽参数"
        icon={<Link2 className="w-4 h-4" />}
        subtitle={
          cfgPath
            ? `${cfgPath} · 仅更新订阅与 Hysteria2 速率，自动保留其余设置与注释`
            : '多订阅时请为每个订阅指定唯一名称'
        }
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <Button
              size="xs"
              disabled={loading || saving}
              onClick={() => void loadSubs()}
              icon={<RefreshCw className={`w-3 h-3 ${loading ? 'animate-spin' : ''}`} />}
            >
              重新加载
            </Button>
            <Button
              size="xs"
              disabled={loading || saving}
              onClick={() => setSubs((prev) => [...prev, { ...EMPTY_SUB }])}
              icon={<Plus className="w-3 h-3" />}
            >
              添加订阅
            </Button>
          </div>
        }
      >
        <div className="space-y-4">
          <div className="space-y-2.5">
            {subs.map((sub, idx) => (
              <div
                key={idx}
                className="grid grid-cols-1 md:grid-cols-12 gap-2.5 items-center p-3 rounded-xl bg-surface2 border border-subtle"
              >
                <input
                  type="text"
                  placeholder="名称"
                  value={sub.name}
                  onChange={(e) => updateSub(idx, { name: e.target.value })}
                  className="md:col-span-2 h-9 px-3 rounded-lg bg-surface1 border border-subtle text-xs text-primary focus:outline-none focus:border-strong"
                />
                <input
                  type="text"
                  placeholder="https://订阅地址"
                  value={sub.url}
                  onChange={(e) => updateSub(idx, { url: e.target.value })}
                  className="md:col-span-6 h-9 px-3 rounded-lg bg-surface1 border border-subtle text-xs font-mono text-primary focus:outline-none focus:border-strong"
                />
                <div className="md:col-span-3 flex items-center gap-3 text-xs text-primary">
                  <label className="inline-flex items-center gap-1.5 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={sub.skip_tls_verify}
                      onChange={(e) => updateSub(idx, { skip_tls_verify: e.target.checked })}
                      className="accent-[var(--accent)]"
                    />
                    跳过TLS
                  </label>
                  <label className="inline-flex items-center gap-1.5 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={sub.remove_emoji}
                      onChange={(e) => updateSub(idx, { remove_emoji: e.target.checked })}
                      className="accent-[var(--accent)]"
                    />
                    去Emoji
                  </label>
                </div>
                <div className="md:col-span-1 flex justify-end">
                  <button
                    type="button"
                    onClick={() =>
                      setSubs((prev) =>
                        prev.length > 1 ? prev.filter((_, i) => i !== idx) : [{ ...EMPTY_SUB }],
                      )
                    }
                    className="p-1.5 rounded-lg text-muted hover:text-red-400 hover:bg-surfaceHover transition-colors cursor-pointer"
                    title="删除此行"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              </div>
            ))}
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-2 border-t border-subtle text-xs">
            <label className="block space-y-1">
              <span className="text-secondary">Hysteria2 上行速率 (Mbps，0 表示不覆盖)</span>
              <input
                type="number"
                min={0}
                value={hy2Up || ''}
                placeholder="例如 30"
                onChange={(e) => setHy2Up(Math.max(0, Number(e.target.value) || 0))}
                className="w-full h-9 px-3 rounded-xl bg-surface2 border border-subtle text-primary font-mono tnum focus:outline-none focus:border-strong"
              />
            </label>
            <label className="block space-y-1">
              <span className="text-secondary">Hysteria2 下行速率 (Mbps，0 表示不覆盖)</span>
              <input
                type="number"
                min={0}
                value={hy2Down || ''}
                placeholder="例如 300"
                onChange={(e) => setHy2Down(Math.max(0, Number(e.target.value) || 0))}
                className="w-full h-9 px-3 rounded-xl bg-surface2 border border-subtle text-primary font-mono tnum focus:outline-none focus:border-strong"
              />
            </label>
          </div>

          <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-subtle">
            <span className="text-[11px] text-secondary">
              修改订阅并保存后，可直接点击右侧按钮立即重新生成 `config.json` 并热重载。
            </span>
            <div className="flex flex-wrap items-center gap-2">
              <Button
                variant="secondary"
                disabled={busy || saving}
                onClick={() => onAction('sb-gen')}
                icon={<Zap className="w-3.5 h-3.5" />}
              >
                生成配置并热重载
              </Button>
              <Button
                variant="primary"
                loading={saving}
                disabled={loading || busy}
                onClick={() => void handleSave()}
                icon={<Save className="w-3.5 h-3.5" />}
              >
                保存订阅与带宽
              </Button>
            </div>
          </div>
        </div>
      </SectionCard>
    </div>
  );
};
