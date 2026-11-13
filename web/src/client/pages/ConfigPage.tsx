import React, { useState, useEffect, useCallback } from 'react';
import { Settings, FileCode, Plus, Trash2, Save, RefreshCw } from 'lucide-react';
import { Button, PageHeader, SectionCard, SegmentedTabs, useToast } from '../../ui';
import { clientApi } from '../api';
import { ClientConfigDTO, ClientConfigSubDTO } from '../types';

export interface ConfigPageProps {
  onSaved: () => void;
}

const EMPTY_SUB: ClientConfigSubDTO = {
  name: '',
  url: '',
  skip_tls_verify: false,
  remove_emoji: false,
};

export const ConfigPage: React.FC<ConfigPageProps> = ({ onSaved }) => {
  const { success, error } = useToast();
  const [mode, setMode] = useState<'form' | 'raw'>('form');
  const [cfgPath, setCfgPath] = useState('');
  const [subs, setSubs] = useState<ClientConfigSubDTO[]>([{ ...EMPTY_SUB }]);
  const [mirrorUrl, setMirrorUrl] = useState('');
  const [hy2Up, setHy2Up] = useState(0);
  const [hy2Down, setHy2Down] = useState(0);
  const [tsKey, setTsKey] = useState('');
  const [tsSubnets, setTsSubnets] = useState('');
  const [tsUseBuild, setTsUseBuild] = useState(false);
  const [srvDomain, setSrvDomain] = useState('');
  const [srvCFKey, setSrvCFKey] = useState('');
  const [srvSNI, setSrvSNI] = useState('');
  const [rawYaml, setRawYaml] = useState('');
  const [saving, setSaving] = useState(false);

  const loadForm = useCallback(async () => {
    try {
      const res = await clientApi.getConfig();
      const c = res.config;
      setCfgPath(res.path || '');
      setSubs(c.subs?.length ? c.subs : [{ ...EMPTY_SUB }]);
      setMirrorUrl(c.github?.mirror_url || '');
      setHy2Up(c.hy2?.up || 0);
      setHy2Down(c.hy2?.down || 0);
      setTsKey(c.tailscale?.auth_key || '');
      setTsUseBuild(Boolean(c.tailscale?.use_build));
      setTsSubnets(c.tailscale?.subnets || '');
      setSrvDomain(c.server?.sb_domain || '');
      setSrvCFKey(c.server?.cf_dns_key || '');
      setSrvSNI(c.server?.sni || '');
    } catch (err: unknown) {
      error(`加载配置失败：${err instanceof Error ? err.message : '未知错误'}`);
    }
  }, [error]);

  const loadRaw = useCallback(async () => {
    try {
      const res = await clientApi.getConfigRaw();
      setCfgPath(res.path || '');
      setRawYaml(res.content || '');
    } catch (err: unknown) {
      error(`读取 YAML 原文失败：${err instanceof Error ? err.message : '未知错误'}`);
    }
  }, [error]);

  useEffect(() => {
    void loadForm();
  }, [loadForm]);

  useEffect(() => {
    if (mode === 'raw') {
      void loadRaw();
    }
  }, [mode, loadRaw]);

  const updateSub = (idx: number, patch: Partial<ClientConfigSubDTO>) => {
    setSubs((prev) => prev.map((s, i) => (i === idx ? { ...s, ...patch } : s)));
  };

  const handleSaveForm = async () => {
    const validSubs = subs.filter((s) => s.name.trim() || s.url.trim());
    for (const s of validSubs) {
      if (!s.url.trim()) {
        error(`订阅「${s.name || '未命名'}」缺少订阅 URL`);
        return;
      }
    }
    const payload: ClientConfigDTO = {
      subs: validSubs,
      github: { mirror_url: mirrorUrl.trim() },
      hy2: { up: Number(hy2Up) || 0, down: Number(hy2Down) || 0 },
      tailscale: { auth_key: tsKey, use_build: tsUseBuild, subnets: tsSubnets.trim() },
      server: { sb_domain: srvDomain.trim(), cf_dns_key: srvCFKey, sni: srvSNI.trim() },
    };
    setSaving(true);
    try {
      await clientApi.saveConfig(payload);
      success('配置已保存（已自动备份原文件）');
      onSaved();
    } catch (err: unknown) {
      error(`保存失败：${err instanceof Error ? err.message : '未知错误'}`);
    } finally {
      setSaving(false);
    }
  };

  const handleSaveRaw = async () => {
    setSaving(true);
    try {
      await clientApi.saveConfigRaw(rawYaml);
      success('YAML 配置已保存（已自动备份）');
      await loadForm();
      onSaved();
    } catch (err: unknown) {
      error(`保存 YAML 失败：${err instanceof Error ? err.message : '未知错误'}`);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="space-y-5">
      <PageHeader
        title="配置管理"
        description={cfgPath || 'singctl.yaml'}
        actions={
          <SegmentedTabs
            value={mode}
            onChange={(k) => setMode(k as 'form' | 'raw')}
            items={[
              { key: 'form', label: '结构化向导', icon: <Settings className="w-3.5 h-3.5" /> },
              { key: 'raw', label: 'YAML 源码', icon: <FileCode className="w-3.5 h-3.5" /> },
            ]}
          />
        }
      />

      {mode === 'form' ? (
        <div className="space-y-5">
          <SectionCard
            title="机场订阅列表"
            subtitle="多订阅时请为每个订阅指定唯一名称"
            actions={
              <>
                <Button size="xs" onClick={loadForm} icon={<RefreshCw className="w-3 h-3" />}>
                  重新加载
                </Button>
                <Button
                  size="xs"
                  onClick={() => setSubs((prev) => [...prev, { ...EMPTY_SUB }])}
                  icon={<Plus className="w-3 h-3" />}
                >
                  添加订阅
                </Button>
              </>
            }
          >
            <div className="space-y-2.5">
              {subs.map((sub, idx) => (
                <div key={idx} className="grid grid-cols-1 md:grid-cols-12 gap-2.5 items-center p-3 rounded-xl bg-surface2">
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
                      onClick={() => setSubs((prev) => (prev.length > 1 ? prev.filter((_, i) => i !== idx) : [{ ...EMPTY_SUB }]))}
                      className="p-1.5 rounded-lg text-muted hover:text-red-400 hover:bg-surfaceHover transition-colors"
                      title="删除此行"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </SectionCard>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <SectionCard title="加速、带宽与 Tailscale">
              <div className="space-y-3 text-xs">
                <label className="block space-y-1">
                  <span className="text-secondary">GitHub 镜像地址 (`mirror_url`)</span>
                  <input
                    type="text"
                    value={mirrorUrl}
                    onChange={(e) => setMirrorUrl(e.target.value)}
                    placeholder="https://gh-proxy.com"
                    className="w-full h-9 px-3 rounded-xl bg-surface2 border border-subtle text-primary font-mono focus:outline-none focus:border-strong"
                  />
                </label>
                <div className="grid grid-cols-2 gap-3">
                  <label className="block space-y-1">
                    <span className="text-secondary">Hysteria2 上行 (Mbps)</span>
                    <input
                      type="number"
                      min={1}
                      value={hy2Up || ''}
                      onChange={(e) => setHy2Up(Number(e.target.value))}
                      className="w-full h-9 px-3 rounded-xl bg-surface2 border border-subtle text-primary font-mono tnum"
                    />
                  </label>
                  <label className="block space-y-1">
                    <span className="text-secondary">Hysteria2 下行 (Mbps)</span>
                    <input
                      type="number"
                      min={1}
                      value={hy2Down || ''}
                      onChange={(e) => setHy2Down(Number(e.target.value))}
                      className="w-full h-9 px-3 rounded-xl bg-surface2 border border-subtle text-primary font-mono tnum"
                    />
                  </label>
                </div>
                <label className="block space-y-1">
                  <span className="text-secondary">Tailscale Auth Key</span>
                  <input
                    type="password"
                    autoComplete="new-password"
                    value={tsKey}
                    onChange={(e) => setTsKey(e.target.value)}
                    placeholder="tskey-auth-..."
                    className="w-full h-9 px-3 rounded-xl bg-surface2 border border-subtle text-primary font-mono focus:outline-none focus:border-strong"
                  />
                </label>
                <label className="block space-y-1">
                  <span className="text-secondary">通告子网 (`subnets`，留空自动探测)</span>
                  <input
                    type="text"
                    value={tsSubnets}
                    onChange={(e) => setTsSubnets(e.target.value)}
                    placeholder="192.168.1.0/24"
                    className="w-full h-9 px-3 rounded-xl bg-surface2 border border-subtle text-primary font-mono focus:outline-none focus:border-strong"
                  />
                </label>
              </div>
            </SectionCard>

            <SectionCard title="服务端部署字段（仅 VPS 使用，可选）">
              <div className="space-y-3 text-xs">
                <label className="block space-y-1">
                  <span className="text-secondary">服务域名 (`sb_domain`)</span>
                  <input
                    type="text"
                    value={srvDomain}
                    onChange={(e) => setSrvDomain(e.target.value)}
                    placeholder="node.example.com"
                    className="w-full h-9 px-3 rounded-xl bg-surface2 border border-subtle text-primary font-mono focus:outline-none focus:border-strong"
                  />
                </label>
                <label className="block space-y-1">
                  <span className="text-secondary">Cloudflare API Token (`cf_dns_key`)</span>
                  <input
                    type="password"
                    autoComplete="new-password"
                    value={srvCFKey}
                    onChange={(e) => setSrvCFKey(e.target.value)}
                    className="w-full h-9 px-3 rounded-xl bg-surface2 border border-subtle text-primary font-mono focus:outline-none focus:border-strong"
                  />
                </label>
                <label className="block space-y-1">
                  <span className="text-secondary">Reality 伪装目标 (`sni`)</span>
                  <input
                    type="text"
                    value={srvSNI}
                    onChange={(e) => setSrvSNI(e.target.value)}
                    placeholder="swdist.apple.com"
                    className="w-full h-9 px-3 rounded-xl bg-surface2 border border-subtle text-primary font-mono focus:outline-none focus:border-strong"
                  />
                </label>
                <div className="pt-2">
                  <Button variant="primary" loading={saving} onClick={handleSaveForm} icon={<Save className="w-3.5 h-3.5" />}>
                    保存全部表单配置
                  </Button>
                </div>
              </div>
            </SectionCard>
          </div>
        </div>
      ) : (
        <SectionCard
          title="YAML 原文编辑"
          subtitle="保留全部人工注释与高级字段，保存时校验 YAML 合法性"
          actions={
            <Button size="sm" variant="primary" loading={saving} onClick={handleSaveRaw} icon={<Save className="w-3.5 h-3.5" />}>
              校验并保存 YAML
            </Button>
          }
        >
          <textarea
            value={rawYaml}
            onChange={(e) => setRawYaml(e.target.value)}
            spellCheck={false}
            rows={22}
            className="w-full p-3.5 rounded-xl bg-[var(--console-bg)] text-slate-200 border border-subtle font-mono text-xs leading-relaxed focus:outline-none focus:border-strong"
          />
        </SectionCard>
      )}
    </div>
  );
};
