import React, { useEffect, useState } from 'react';
import { Globe, Plus, Save, Sparkles, Trash2 } from 'lucide-react';
import { Badge, Button, SlideDrawer } from '../../../../ui';
import {
  HomeDomainDeviceUpsertPayload,
  HomeDomainService,
} from '../../../types';

export interface DeviceEditInitial {
  originalAlias?: string;
  alias: string;
  displayName?: string;
  ip: string;
  mac?: string;
  source?: string;
  wildcard?: boolean;
  services?: HomeDomainService[];
  note?: string;
}

export interface DeviceEditDrawerProps {
  open: boolean;
  suffix: string;
  saving: boolean;
  initial: DeviceEditInitial | null;
  onClose: () => void;
  onSubmit: (payload: HomeDomainDeviceUpsertPayload) => Promise<boolean>;
}

const SERVICE_PRESETS: Array<{ label: string; scheme: 'http' | 'https' | 'ssh'; port: number }> = [
  { label: 'SingCtl WebUI', scheme: 'http', port: 8090 },
  { label: 'SSH', scheme: 'ssh', port: 22 },
  { label: 'OpenWrt LuCI', scheme: 'http', port: 80 },
  { label: 'NAS 管理', scheme: 'http', port: 5000 },
  { label: 'HTTPS 面板', scheme: 'https', port: 443 },
];

export const DeviceEditDrawer: React.FC<DeviceEditDrawerProps> = ({
  open,
  suffix,
  saving,
  initial,
  onClose,
  onSubmit,
}) => {
  const [alias, setAlias] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [ip, setIp] = useState('');
  const [mac, setMac] = useState('');
  const [source, setSource] = useState('manual');
  const [wildcard, setWildcard] = useState(false);
  const [services, setServices] = useState<HomeDomainService[]>([]);
  const [note, setNote] = useState('');
  const [formErr, setFormErr] = useState('');

  useEffect(() => {
    if (!open) return;
    setAlias(initial?.alias || '');
    setDisplayName(initial?.displayName || '');
    setIp(initial?.ip || '');
    setMac(initial?.mac || '');
    setSource(initial?.source || 'manual');
    setWildcard(Boolean(initial?.wildcard));
    setServices(initial?.services ? initial.services.map((s) => ({ ...s })) : []);
    setNote(initial?.note || '');
    setFormErr('');
  }, [open, initial]);

  const cleanAlias = alias.trim().toLowerCase();
  const previewFQDN = cleanAlias ? `${cleanAlias}.${suffix}` : `<短域名>.${suffix}`;

  const addPresetService = (preset: { label: string; scheme: 'http' | 'https' | 'ssh'; port: number }) => {
    const dup = services.some((s) => s.scheme === preset.scheme && Number(s.port || 0) === preset.port);
    if (dup) return;
    setServices((prev) => [...prev, { ...preset }]);
  };

  const addBlankService = () => {
    setServices((prev) => [...prev, { label: 'Web', scheme: 'http', port: 8080 }]);
  };

  const updateService = (idx: number, patch: Partial<HomeDomainService>) => {
    setServices((prev) => prev.map((item, i) => (i === idx ? { ...item, ...patch } : item)));
  };

  const removeService = (idx: number) => {
    setServices((prev) => prev.filter((_, i) => i !== idx));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormErr('');
    if (!cleanAlias) {
      setFormErr('请输入英文短域名（例如 ax3000t / nas / pc）');
      return;
    }
    if (!ip.trim()) {
      setFormErr('请输入目标 IP 地址（局域网 IP 或 Tailscale 100.x IP）');
      return;
    }
    const ok = await onSubmit({
      originalAlias: initial?.originalAlias,
      alias: cleanAlias,
      displayName: displayName.trim(),
      ip: ip.trim(),
      mac: mac.trim(),
      source,
      wildcard,
      services: services.filter((s) => (s.label || '').trim() || Number(s.port || 0) > 0),
      note: note.trim(),
    });
    if (ok) {
      onClose();
    }
  };

  return (
    <SlideDrawer
      open={open}
      onClose={onClose}
      size="md"
      title={initial?.originalAlias ? `编辑本地域名 · ${initial.originalAlias}.${suffix}` : '新增本地域名设备'}
      subtitle="保存后自动同步至本地防劫持 DNS、sing-box 与 Tailscale Split-DNS，并联动流量审计页展示友好昵称"
      footer={
        <div className="flex items-center justify-end gap-2">
          <Button size="sm" variant="ghost" onClick={onClose} disabled={saving}>
            取消
          </Button>
          <Button
            size="sm"
            variant="primary"
            loading={saving}
            icon={<Save className="w-3.5 h-3.5" />}
            onClick={(e) => void handleSubmit(e)}
          >
            保存并立即生效
          </Button>
        </div>
      }
    >
      <form onSubmit={(e) => void handleSubmit(e)} className="space-y-4 text-xs">
        <div className="rounded-xl border border-sky-500/25 bg-sky-500/10 p-3 flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2 min-w-0">
            <Globe className="w-4 h-4 text-sky-400 shrink-0" />
            <span className="text-secondary">生效域名预览：</span>
            <code className="font-mono text-sky-300 font-semibold truncate">{previewFQDN}</code>
          </div>
          {wildcard && cleanAlias && (
            <Badge tone="accent" className="font-mono">
              + *.{previewFQDN}
            </Badge>
          )}
        </div>

        {formErr && (
          <div className="rounded-xl border border-rose-500/40 bg-rose-500/10 px-3 py-2 text-rose-300">
            {formErr}
          </div>
        )}

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <label className="block space-y-1">
            <span className="text-secondary font-medium">英文短域名 *</span>
            <div className="flex items-center rounded-xl bg-surface1 border border-subtle focus-within:border-strong overflow-hidden">
              <input
                type="text"
                value={alias}
                onChange={(e) => setAlias(e.target.value)}
                placeholder="如 ax3000t / nas / pc"
                className="flex-1 min-w-0 h-9 px-3 bg-transparent text-primary font-mono focus:outline-none"
              />
              <span className="px-2.5 text-[11px] font-mono text-muted border-l border-subtle bg-surface2/60 h-9 inline-flex items-center">
                .{suffix}
              </span>
            </div>
            <span className="text-[11px] text-muted">仅支持小写字母、数字和连字符（-）</span>
          </label>

          <label className="block space-y-1">
            <span className="text-secondary font-medium">友好备注名（支持中文）</span>
            <input
              type="text"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              placeholder="如 书房路由 / 家庭NAS / 客厅电脑"
              className="w-full h-9 px-3 rounded-xl bg-surface1 border border-subtle text-primary focus:outline-none focus:border-strong"
            />
            <span className="text-[11px] text-muted">同步展示在「流量审计」与本页卡片</span>
          </label>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <label className="block space-y-1">
            <span className="text-secondary font-medium">目标 IP 地址 *</span>
            <input
              type="text"
              value={ip}
              onChange={(e) => setIp(e.target.value)}
              placeholder="局域网 IP 或 Tailscale 100.x IP"
              className="w-full h-9 px-3 rounded-xl bg-surface1 border border-subtle text-primary font-mono focus:outline-none focus:border-strong"
            />
            <span className="text-[11px] text-muted">跨子网下级路由推荐绑定 Tailscale IP</span>
          </label>

          <label className="block space-y-1">
            <span className="text-secondary font-medium">MAC 地址（可选 · 自动追 DHCP）</span>
            <input
              type="text"
              value={mac}
              onChange={(e) => setMac(e.target.value)}
              placeholder="aa:bb:cc:dd:ee:ff"
              className="w-full h-9 px-3 rounded-xl bg-surface1 border border-subtle text-primary font-mono focus:outline-none focus:border-strong"
            />
            <span className="text-[11px] text-muted">局域网设备换 IP 时自动跟随更新</span>
          </label>
        </div>

        <label className="flex items-start gap-2.5 p-3 rounded-xl bg-surface2/50 border border-subtle cursor-pointer select-none">
          <input
            type="checkbox"
            checked={wildcard}
            onChange={(e) => setWildcard(e.target.checked)}
            className="mt-0.5 accent-sky-500 w-4 h-4"
          />
          <div className="space-y-0.5">
            <div className="text-primary font-medium flex items-center gap-1.5">
              <Sparkles className="w-3.5 h-3.5 text-sky-400" />
              <span>同时启用通配子域名（*.{previewFQDN}）</span>
            </div>
            <div className="text-[11px] text-muted leading-relaxed">
              适合 NAS / 自建反代服务器：勾选后 photos.{previewFQDN}、git.{previewFQDN} 等任意子域名自动指向同一台设备
            </div>
          </div>
        </label>

        <div className="space-y-2 pt-1">
          <div className="flex items-center justify-between gap-2">
            <span className="text-secondary font-medium">卡片一键直达入口（可选）</span>
            <Button type="button" size="xs" variant="ghost" icon={<Plus className="w-3 h-3" />} onClick={addBlankService}>
              自定义入口
            </Button>
          </div>
          <div className="flex flex-wrap gap-1.5">
            {SERVICE_PRESETS.map((p) => (
              <button
                key={`${p.scheme}-${p.port}`}
                type="button"
                onClick={() => addPresetService(p)}
                className="px-2 py-1 rounded-lg text-[11px] bg-surface2 hover:bg-surface3 border border-subtle text-secondary hover:text-primary transition-colors cursor-pointer"
              >
                + {p.label} ({p.scheme === 'ssh' ? 'SSH' : `:${p.port}`})
              </button>
            ))}
          </div>

          {services.length > 0 && (
            <div className="space-y-2 pt-1">
              {services.map((svc, idx) => (
                <div key={idx} className="grid grid-cols-12 gap-2 items-center">
                  <input
                    type="text"
                    value={svc.label || ''}
                    onChange={(e) => updateService(idx, { label: e.target.value })}
                    placeholder="标签"
                    className="col-span-4 h-8 px-2.5 rounded-lg bg-surface1 border border-subtle text-primary focus:outline-none focus:border-strong"
                  />
                  <select
                    value={svc.scheme || 'http'}
                    onChange={(e) => updateService(idx, { scheme: e.target.value })}
                    className="col-span-3 h-8 px-2 rounded-lg bg-surface1 border border-subtle text-primary focus:outline-none focus:border-strong"
                  >
                    <option value="http">http</option>
                    <option value="https">https</option>
                    <option value="ssh">ssh</option>
                  </select>
                  <input
                    type="number"
                    min={0}
                    max={65535}
                    value={svc.port ?? ''}
                    onChange={(e) => updateService(idx, { port: Number(e.target.value || 0) })}
                    placeholder="端口"
                    className="col-span-3 h-8 px-2.5 rounded-lg bg-surface1 border border-subtle text-primary font-mono focus:outline-none focus:border-strong"
                  />
                  <div className="col-span-2 flex justify-end">
                    <Button
                      type="button"
                      size="xs"
                      variant="ghost"
                      icon={<Trash2 className="w-3.5 h-3.5" />}
                      onClick={() => removeService(idx)}
                    />
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </form>
    </SlideDrawer>
  );
};
