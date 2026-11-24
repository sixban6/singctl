import React, { useCallback, useEffect, useState } from 'react';
import { AlertTriangle, ChevronDown, ChevronUp, Save, Shield, ShieldAlert } from 'lucide-react';
import { Badge, Button, SectionCard } from '../../../ui';
import { useToast } from '../../../ui/Toast';
import { clientApi } from '../../api';
import { DNSBypassGuardSnapshot } from '../../types';

export interface DNSBypassGuardCardProps {
  active?: boolean;
}

const RISK_META: Record<string, { label: string; tone: 'ok' | 'warn' | 'danger' }> = {
  low: { label: '极低误伤', tone: 'ok' },
  medium: { label: '低～中风险', tone: 'warn' },
  high: { label: '高风险', tone: 'danger' },
};

export const DNSBypassGuardCard: React.FC<DNSBypassGuardCardProps> = ({ active = true }) => {
  const { success, error } = useToast();
  const [snap, setSnap] = useState<DNSBypassGuardSnapshot | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [expanded, setExpanded] = useState(false);

  const [enabled, setEnabled] = useState(true);
  const [layers, setLayers] = useState<Record<string, boolean>>({});
  const [appGroups, setAppGroups] = useState<Record<string, boolean>>({});
  const [exemptText, setExemptText] = useState('');
  const [dirty, setDirty] = useState(false);

  const hydrateFromSnap = useCallback((data: DNSBypassGuardSnapshot) => {
    setSnap(data);
    setEnabled(data.enabled);
    const nextLayers: Record<string, boolean> = {};
    for (const l of data.layers || []) {
      nextLayers[l.id] = l.enabled;
    }
    setLayers(nextLayers);
    const nextGroups: Record<string, boolean> = {};
    for (const g of data.appGroups || []) {
      nextGroups[g.id] = g.enabled;
    }
    setAppGroups(nextGroups);
    setExemptText((data.exemptSourceIps || []).join(', '));
    setDirty(false);
  }, []);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const data = await clientApi.getDNSBypassGuard();
      hydrateFromSnap(data);
    } catch (e: unknown) {
      error(e instanceof Error ? e.message : '读取防绕过分层策略失败');
    } finally {
      setLoading(false);
    }
  }, [error, hydrateFromSnap]);

  useEffect(() => {
    if (active) {
      void load();
    }
  }, [active, load]);

  const handleToggleMaster = () => {
    setEnabled((v) => !v);
    setDirty(true);
  };

  const handleToggleLayer = (id: string) => {
    setLayers((prev) => ({ ...prev, [id]: !prev[id] }));
    setDirty(true);
  };

  const handleToggleGroup = (id: string) => {
    setAppGroups((prev) => ({ ...prev, [id]: !prev[id] }));
    setDirty(true);
  };

  const handleSave = async () => {
    setSaving(true);
    try {
      const exemptSourceIps = exemptText
        .split(/[\s,，;]+/)
        .map((s) => s.trim())
        .filter(Boolean);
      const res = await clientApi.saveDNSBypassGuard({
        enabled,
        layers,
        appGroups,
        exemptSourceIps,
      });
      if (res.bypassGuard) {
        hydrateFromSnap(res.bypassGuard);
      }
      success('已保存分层防 DNS 绕过策略并热重载 sing-box（零断网生效）');
    } catch (e: unknown) {
      error(e instanceof Error ? e.message : '保存防绕过分层策略失败');
    } finally {
      setSaving(false);
    }
  };

  const activeLayerCount = (snap?.layers || []).filter((l) => layers[l.id] ?? l.enabled).length;
  const wechatEnabled = Boolean(enabled && layers.app_httpdns && appGroups.wechat);

  return (
    <SectionCard
      title="防 DNS 绕过分层策略 (L0~L4)"
      icon={<Shield className="w-4 h-4" />}
      subtitle="按协议与误伤风险精细分层：通过毫秒级 TCP RST 逼退设备 DoT/DoH 与国内 App HTTPDNS 回落至网关 :53 统一审计与去广告"
      actions={
        <div className="flex flex-wrap items-center gap-2">
          <Badge tone={enabled ? 'ok' : 'neutral'} dot={enabled}>
            {enabled ? `已启用 ${activeLayerCount}/4 层 · ${snap?.activeRuleCount ?? 0} 条规则` : '已暂停拦截'}
          </Badge>
          <Button
            size="xs"
            variant="ghost"
            onClick={() => setExpanded((v) => !v)}
            icon={expanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
          >
            {expanded ? '收起策略' : '展开配置'}
          </Button>
        </div>
      }
    >
      {loading && !snap ? (
        <div className="text-xs text-muted py-2">正在读取分层防绕过策略…</div>
      ) : (
        <div className="space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-subtle bg-surface2/60 px-3.5 py-2.5 text-xs">
            <div className="flex flex-wrap items-center gap-2 text-secondary">
              <Badge tone="ok">L0 底座常开</Badge>
              <span>全屋 LAN TCP/UDP 53 端口强制透明劫持已由 sing-box 接管</span>
            </div>
            <label className="inline-flex items-center gap-2 cursor-pointer select-none">
              <input
                type="checkbox"
                checked={enabled}
                onChange={handleToggleMaster}
                className="accent-cyan-400 w-4 h-4 cursor-pointer"
              />
              <span className="font-medium text-primary">启用 L1~L4 防绕过拦截</span>
            </label>
          </div>

          {expanded && snap && (
            <div className="space-y-4 animate-sc-in">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {snap.layers.map((layer) => {
                  const on = Boolean(layers[layer.id]);
                  const risk = RISK_META[layer.risk] || RISK_META.low;
                  return (
                    <div
                      key={layer.id}
                      onClick={() => enabled && handleToggleLayer(layer.id)}
                      className={`rounded-xl border p-3.5 transition-colors flex flex-col justify-between gap-2 ${
                        !enabled
                          ? 'opacity-55 border-subtle bg-surface2/40 cursor-not-allowed'
                          : on
                            ? 'border-cyan-500/40 bg-cyan-500/5 cursor-pointer'
                            : 'border-subtle bg-surface2/50 hover:border-strong cursor-pointer'
                      }`}
                    >
                      <div className="flex items-start justify-between gap-2">
                        <div className="space-y-1 min-w-0">
                          <div className="flex flex-wrap items-center gap-1.5">
                            <span className="text-[11px] font-mono font-semibold px-1.5 py-0.5 rounded bg-surface1 border border-subtle text-cyan-300">
                              {layer.level}
                            </span>
                            <span className="text-xs sm:text-sm font-semibold text-primary">
                              {layer.name}
                            </span>
                            <Badge tone={risk.tone}>{risk.label}</Badge>
                          </div>
                          <p className="text-[11px] text-secondary leading-relaxed">{layer.desc}</p>
                        </div>
                        <input
                          type="checkbox"
                          checked={on}
                          disabled={!enabled}
                          onChange={() => handleToggleLayer(layer.id)}
                          onClick={(e) => e.stopPropagation()}
                          className="accent-cyan-400 w-4 h-4 mt-0.5 shrink-0 cursor-pointer"
                        />
                      </div>
                      <div className="flex flex-wrap items-center gap-2 text-[11px] font-mono text-muted">
                        <span>端口: {layer.ports.join('/')}</span>
                        {layer.ipCount > 0 && <span>IP/网段: {layer.ipCount}</span>}
                        {layer.domainCount > 0 && <span>域名: {layer.domainCount}</span>}
                      </div>
                    </div>
                  );
                })}
              </div>

              {enabled && layers.app_httpdns && (
                <div className="rounded-xl border border-subtle bg-surface2/40 p-3.5 space-y-2.5">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs font-semibold text-primary">
                      L4 大厂 App 自建 HTTPDNS 细粒度开关
                    </span>
                    <span className="text-[11px] text-muted">点击标签单独开启或关闭</span>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {snap.appGroups.map((grp) => {
                      const on = Boolean(appGroups[grp.id]);
                      const isHigh = grp.risk === 'high';
                      const targets = [...grp.domains, ...(grp.ips || [])];
                      return (
                        <button
                          key={grp.id}
                          type="button"
                          title={`${grp.desc} (${targets.join(', ')})`}
                          onClick={() => handleToggleGroup(grp.id)}
                          className={`inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-xl text-xs border transition-colors cursor-pointer ${
                            on
                              ? isHigh
                                ? 'bg-rose-500/15 text-rose-300 border-rose-500/40 font-medium'
                                : 'bg-emerald-500/15 text-emerald-300 border-emerald-500/35 font-medium'
                              : 'bg-surface1 text-secondary border-subtle hover:text-primary'
                          }`}
                        >
                          {isHigh && <ShieldAlert className="w-3.5 h-3.5" />}
                          <span>{grp.name}</span>
                          <span className="text-[10px] opacity-70 font-mono">{targets.length}</span>
                        </button>
                      );
                    })}
                  </div>
                  {wechatEnabled && (
                    <div className="flex items-start gap-2 rounded-lg border border-rose-500/35 bg-rose-500/10 px-3 py-2 text-[11px] text-rose-200">
                      <AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-0.5 text-rose-400" />
                      <span>
                        已勾选高风险「微信专有调度」：保存后将拦截 dns.weixin.qq.com / dns.weixin.qq.com.cn / aedns.weixin.qq.com，若出现微信搜一搜表情加载慢或裂图，取消勾选保存即可秒级恢复。
                      </span>
                    </div>
                  )}
                </div>
              )}

              <div className="rounded-xl border border-subtle bg-surface2/40 p-3.5 space-y-2">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <label htmlFor="bypass-exempt-ips" className="text-xs font-semibold text-primary">
                    横向逃生舱：免拦源设备 IP / 网段（可选）
                  </label>
                  <span className="text-[11px] text-muted">
                    多个用逗号或空格分隔（如强锁私人 DNS 的手机或特殊下级路由）
                  </span>
                </div>
                <input
                  id="bypass-exempt-ips"
                  type="text"
                  value={exemptText}
                  onChange={(e) => {
                    setExemptText(e.target.value);
                    setDirty(true);
                  }}
                  placeholder="例如：192.168.1.50, 192.168.1.2/32"
                  className="w-full h-9 px-3 rounded-xl bg-surface1 border border-subtle text-xs font-mono text-primary focus:outline-none focus:border-strong"
                />
              </div>

              <div className="flex flex-wrap items-center justify-between gap-2 pt-1">
                <span className="text-[11px] text-muted">
                  注：在下方「放行白名单」中添加的域名会自动豁免上述拦截，且所有修改均零断网热生效。
                </span>
                <Button
                  size="sm"
                  variant="primary"
                  loading={saving}
                  disabled={saving || !dirty}
                  onClick={() => void handleSave()}
                  icon={<Save className="w-3.5 h-3.5" />}
                >
                  保存并热生效
                </Button>
              </div>
            </div>
          )}
        </div>
      )}
    </SectionCard>
  );
};
