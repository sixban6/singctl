import React, { useMemo, useState } from 'react';
import { CheckCircle2, Globe, Layers, Plus, RefreshCw, ShieldCheck, Trash2 } from 'lucide-react';
import { Badge, Button, SectionCard } from '../../../ui';
import { DNSCapabilities, DNSOverviewSnapshot } from '../../types';
import { formatNumber, resolveActiveEngine } from './adguardHelpers';

export interface AdGuardRulesAndRewritesSectionProps {
  snap: DNSOverviewSnapshot | null;
  capabilities: DNSCapabilities;
  canMutate: boolean;
  mutating: boolean;
  onWhitelist: (action: 'add' | 'remove', domain: string) => Promise<boolean>;
  onAddRewrite: (domain: string, answer: string) => Promise<boolean>;
  onDeleteRewrite: (domain: string, answer: string) => void;
  onFilterToggle: (url: string, name: string, enabled: boolean) => void;
  onAddCustomFilter: (name: string, url: string) => Promise<boolean>;
  onRemoveCustomFilter: (url: string, name: string) => void;
  onRefreshFilters: () => void;
}

export const AdGuardRulesAndRewritesSection: React.FC<AdGuardRulesAndRewritesSectionProps> = ({
  snap,
  capabilities,
  canMutate,
  mutating,
  onWhitelist,
  onAddRewrite,
  onDeleteRewrite,
  onFilterToggle,
  onAddCustomFilter,
  onRemoveCustomFilter,
  onRefreshFilters,
}) => {
  const [wlInput, setWlInput] = useState('');
  const [rwDomain, setRwDomain] = useState('');
  const [rwAnswer, setRwAnswer] = useState('');
  const [showCustomFilter, setShowCustomFilter] = useState(false);
  const [customFilterName, setCustomFilterName] = useState('');
  const [customFilterUrl, setCustomFilterUrl] = useState('');

  const activeEngine = resolveActiveEngine(snap);

  const presetUrlSet = useMemo(() => {
    return new Set((snap?.presets || []).map((p) => p.url));
  }, [snap?.presets]);

  const extraCustomFilters = useMemo(() => {
    return (snap?.filters || []).filter((f) => !presetUrlSet.has(f.url));
  }, [snap?.filters, presetUrlSet]);

  const submitWhitelist = async (e: React.FormEvent) => {
    e.preventDefault();
    const ok = await onWhitelist('add', wlInput);
    if (ok) setWlInput('');
  };

  const submitRewrite = async (e: React.FormEvent) => {
    e.preventDefault();
    const ok = await onAddRewrite(rwDomain, rwAnswer);
    if (ok) {
      setRwDomain('');
      setRwAnswer('');
    }
  };

  const submitCustomFilter = async (e: React.FormEvent) => {
    e.preventDefault();
    const ok = await onAddCustomFilter(customFilterName, customFilterUrl);
    if (ok) {
      setCustomFilterName('');
      setCustomFilterUrl('');
      setShowCustomFilter(false);
    }
  };

  const filterSubtitle =
    activeEngine === 'smartdns'
      ? '可选叠加 SmartDNS 轻量过滤规则集（默认关闭以保持极低内存占用，按需开启）'
      : '默认仅开启官方低误杀基础规则；可按需一键叠加中文增强与轻量规则';

  return (
    <>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <SectionCard
          title="高优白名单与自动豁免保护"
          icon={<CheckCircle2 className="w-4 h-4" />}
          subtitle="手动放行被误拦的业务域名，切换 SmartDNS / AdGuard Home 时自动同步迁移"
        >
          <div className="space-y-4">
            <form onSubmit={(e) => void submitWhitelist(e)} className="flex items-center gap-2">
              <input
                type="text"
                value={wlInput}
                onChange={(e) => setWlInput(e.target.value)}
                placeholder="手动输入需放行的域名（如 api.example.com）"
                className="flex-1 min-w-0 h-9 px-3 rounded-xl bg-surface2 border border-subtle text-xs sm:text-sm text-primary font-mono focus:outline-none focus:border-strong"
              />
              <Button
                type="submit"
                size="sm"
                variant="secondary"
                disabled={mutating || !canMutate || !wlInput.trim()}
                icon={<Plus className="w-3.5 h-3.5" />}
              >
                放行
              </Button>
            </form>

            {(snap?.whitelistedDomains?.length || 0) > 0 ? (
              <div className="space-y-1.5">
                <div className="text-[11px] text-muted">
                  当前手动放行白名单（点击 × 恢复规则过滤）：
                </div>
                <div className="flex flex-wrap gap-1.5">
                  {(snap?.whitelistedDomains || []).map((d) => (
                    <button
                      key={d}
                      type="button"
                      disabled={mutating || !canMutate}
                      onClick={() => void onWhitelist('remove', d)}
                      className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-mono bg-emerald-500/10 hover:bg-emerald-500/20 border border-emerald-500/25 text-emerald-400 transition-colors cursor-pointer disabled:opacity-50"
                    >
                      <span>{d}</span>
                      <span className="opacity-75">×</span>
                    </button>
                  ))}
                </div>
              </div>
            ) : (
              <div className="py-4 text-center text-xs text-muted">
                暂无手动白名单；可在上方「24h 拦截排行」中一键放行，或在此直接录入域名
              </div>
            )}

            {(snap?.autoWhitelistedSubs?.length || 0) > 0 && (
              <div className="pt-3 border-t border-subtle space-y-1.5">
                <div className="flex items-center gap-1.5 text-[11px] text-muted">
                  <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                  <span>已自动保护订阅节点域名（防止规则误伤导致订阅失联）：</span>
                </div>
                <div className="flex flex-wrap gap-1.5">
                  {(snap?.autoWhitelistedSubs || []).map((d) => (
                    <Badge key={d} tone="neutral" className="font-mono">
                      {d}
                    </Badge>
                  ))}
                </div>
              </div>
            )}
          </div>
        </SectionCard>

        <SectionCard
          title="局域网自定义域名映射 (DNS Rewrites)"
          icon={<Globe className="w-4 h-4" />}
          subtitle="为家庭 NAS、路由器或自建服务绑定好记的内网域名（支持 *.lan 通配符）"
        >
          <div className="space-y-4">
            <form
              onSubmit={(e) => void submitRewrite(e)}
              className="grid grid-cols-1 sm:grid-cols-12 gap-2"
            >
              <input
                type="text"
                value={rwDomain}
                onChange={(e) => setRwDomain(e.target.value)}
                placeholder="域名 (如 nas.example.com)"
                className="sm:col-span-5 h-9 px-3 rounded-xl bg-surface2 border border-subtle text-xs sm:text-sm text-primary font-mono focus:outline-none focus:border-strong"
              />
              <input
                type="text"
                value={rwAnswer}
                onChange={(e) => setRwAnswer(e.target.value)}
                placeholder="目标 IP (如 192.168.1.10)"
                className="sm:col-span-5 h-9 px-3 rounded-xl bg-surface2 border border-subtle text-xs sm:text-sm text-primary font-mono focus:outline-none focus:border-strong"
              />
              <div className="sm:col-span-2">
                <Button
                  type="submit"
                  size="sm"
                  variant="primary"
                  className="w-full h-9"
                  disabled={mutating || !canMutate}
                >
                  添加
                </Button>
              </div>
            </form>

            {!snap?.rewrites?.length ? (
              <div className="py-6 text-center text-xs text-muted">
                暂未配置自定义域名映射（例如可将 nas.example.com 指向 192.168.1.10）
              </div>
            ) : (
              <div className="divide-y divide-[var(--border-subtle)] text-xs sm:text-sm max-h-72 overflow-y-auto pr-1">
                {snap.rewrites.map((rw, idx) => (
                  <div
                    key={`${rw.domain}-${rw.answer}-${idx}`}
                    className="flex items-center justify-between gap-3 py-2"
                  >
                    <div className="min-w-0 flex-1 flex items-center gap-2 font-mono">
                      <span className="text-primary font-medium truncate">{rw.domain}</span>
                      <span className="text-muted">→</span>
                      <span className="text-secondary truncate">{rw.answer}</span>
                    </div>
                    <Button
                      size="xs"
                      variant="ghost"
                      disabled={mutating || !canMutate}
                      onClick={() => onDeleteRewrite(rw.domain, rw.answer)}
                      icon={<Trash2 className="w-3.5 h-3.5" />}
                    />
                  </div>
                ))}
              </div>
            )}
          </div>
        </SectionCard>
      </div>

      {capabilities.hasFilterLists && (
        <SectionCard
          title="去广告与隐私过滤规则库"
          icon={<Layers className="w-4 h-4" />}
          subtitle={filterSubtitle}
          actions={
            capabilities.hasCustomFilterURL ? (
              <div className="flex items-center gap-2">
                <Button
                  size="xs"
                  variant="ghost"
                  onClick={() => setShowCustomFilter((v) => !v)}
                  icon={<Plus className="w-3.5 h-3.5" />}
                >
                  自定义订阅
                </Button>
                <Button
                  size="xs"
                  variant="secondary"
                  disabled={mutating || !canMutate}
                  onClick={onRefreshFilters}
                  icon={<RefreshCw className="w-3.5 h-3.5" />}
                >
                  更新规则库
                </Button>
              </div>
            ) : undefined
          }
        >
          <div className="space-y-4">
            {snap?.isOpenWrt && (snap.totalRulesCount || 0) > 150000 && (
              <div className="p-3 rounded-xl bg-amber-500/10 border border-amber-500/25 text-xs text-amber-300">
                软路由内存提示：当前启用规则总数已超过 {formatNumber(snap.totalRulesCount)}{' '}
                条，小内存 OpenWrt 设备建议保持在 15 万条以内以兼顾流畅度。
              </div>
            )}

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {(snap?.presets || []).map((preset) => (
                <div
                  key={preset.id || preset.url}
                  className="p-3.5 rounded-xl border bg-surface2 border-subtle flex items-start justify-between gap-3"
                >
                  <div className="min-w-0 flex-1 space-y-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-xs sm:text-sm font-semibold text-primary">
                        {preset.name}
                      </span>
                      {preset.recommended && <Badge tone="accent">推荐</Badge>}
                      {preset.enabled && preset.rulesCount > 0 && (
                        <span className="text-[11px] font-mono text-muted tnum">
                          {formatNumber(preset.rulesCount)} 条
                        </span>
                      )}
                    </div>
                    <p className="text-[11px] sm:text-xs text-secondary leading-relaxed">
                      {preset.desc}
                    </p>
                  </div>
                  <Button
                    size="xs"
                    variant={preset.enabled ? 'primary' : 'secondary'}
                    disabled={mutating || !canMutate}
                    onClick={() => onFilterToggle(preset.url || preset.id, preset.name, !preset.enabled)}
                  >
                    {preset.enabled ? '已启用' : '启用'}
                  </Button>
                </div>
              ))}
            </div>

            {capabilities.hasCustomFilterURL && showCustomFilter && (
              <form
                onSubmit={(e) => void submitCustomFilter(e)}
                className="p-3.5 rounded-xl bg-surface2 border border-subtle grid grid-cols-1 sm:grid-cols-12 gap-2"
              >
                <input
                  type="text"
                  value={customFilterName}
                  onChange={(e) => setCustomFilterName(e.target.value)}
                  placeholder="规则名称（选填）"
                  className="sm:col-span-4 h-9 px-3 rounded-xl bg-surface border border-subtle text-xs text-primary focus:outline-none focus:border-strong"
                />
                <input
                  type="url"
                  value={customFilterUrl}
                  onChange={(e) => setCustomFilterUrl(e.target.value)}
                  placeholder="https://example.com/filter.txt"
                  className="sm:col-span-6 h-9 px-3 rounded-xl bg-surface border border-subtle text-xs font-mono text-primary focus:outline-none focus:border-strong"
                />
                <div className="sm:col-span-2">
                  <Button
                    type="submit"
                    size="sm"
                    variant="primary"
                    className="w-full h-9"
                    disabled={mutating || !canMutate}
                  >
                    添加订阅
                  </Button>
                </div>
              </form>
            )}

            {capabilities.hasCustomFilterURL && extraCustomFilters.length > 0 && (
              <div className="divide-y divide-[var(--border-subtle)] text-xs sm:text-sm pt-1">
                {extraCustomFilters.map((f) => (
                  <div key={f.url} className="flex items-center justify-between gap-3 py-2">
                    <div className="min-w-0 flex-1">
                      <div className="font-medium text-primary truncate">{f.name}</div>
                      <div className="text-[11px] font-mono text-muted truncate">
                        {f.url}
                        {f.rulesCount > 0 ? ` · ${formatNumber(f.rulesCount)} 条` : ''}
                      </div>
                    </div>
                    <div className="flex items-center gap-1.5 shrink-0">
                      <Button
                        size="xs"
                        variant={f.enabled ? 'primary' : 'secondary'}
                        disabled={mutating || !canMutate}
                        onClick={() => onFilterToggle(f.url, f.name, !f.enabled)}
                      >
                        {f.enabled ? '已启用' : '已停用'}
                      </Button>
                      <Button
                        size="xs"
                        variant="ghost"
                        disabled={mutating || !canMutate}
                        onClick={() => onRemoveCustomFilter(f.url, f.name)}
                        icon={<Trash2 className="w-3.5 h-3.5" />}
                      />
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </SectionCard>
      )}
    </>
  );
};
