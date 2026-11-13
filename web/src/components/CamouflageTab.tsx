import React, { useEffect, useState } from 'react';
import { CamouflagePreset, CamouflageReport, ServerStatusResponse } from '../types';
import { api } from '../api';
import { Badge, Button, PageHeader, SectionCard, useToast } from '../ui';
import {
  Radar,
  RefreshCw,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  ShieldCheck,
  ShieldAlert,
  Sliders,
  Sparkles,
  Server,
  Lock,
  Cpu,
  Globe,
} from 'lucide-react';

interface CamouflageTabProps {
  status: ServerStatusResponse | null;
}

export const CamouflageTab: React.FC<CamouflageTabProps> = ({ status }) => {
  const { success, error } = useToast();

  const [presets, setPresets] = useState<CamouflagePreset[]>([]);
  const [selectedPreset, setSelectedPreset] = useState<string>('local');
  const [ip, setIp] = useState<string>('');
  const [domain, setDomain] = useState<string>(status?.config?.nodeDomain || '');
  const [sni, setSni] = useState<string>(status?.config?.sni || '');
  const [ports, setPorts] = useState<string>('80,443');
  const [timeoutSec, setTimeoutSec] = useState<number>(4);

  const [loadingDefaults, setLoadingDefaults] = useState<boolean>(true);
  const [probing, setProbing] = useState<boolean>(false);
  const [report, setReport] = useState<CamouflageReport | null>(null);

  useEffect(() => {
    let mounted = true;
    setLoadingDefaults(true);
    api
      .getCamouflageDefaults()
      .then((res) => {
        if (!mounted) return;
        setIp(res.ip || '');
        setDomain(res.domain || status?.config?.nodeDomain || '');
        setSni(res.sni || status?.config?.sni || '');
        setPorts(res.ports || '80,443');
        setPresets(res.presets || []);
      })
      .catch(() => {
        if (!mounted) return;
        setDomain(status?.config?.nodeDomain || '');
        setSni(status?.config?.sni || '');
      })
      .finally(() => {
        if (mounted) setLoadingDefaults(false);
      });
    return () => {
      mounted = false;
    };
  }, [status?.config?.nodeDomain, status?.config?.sni]);

  const handleSelectPreset = (p: CamouflagePreset) => {
    setSelectedPreset(p.id);
    setIp(p.ip || '');
    setDomain(p.domain || '');
    if (p.sni) {
      setSni(p.sni);
    }
  };

  const handleRunProbe = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    setProbing(true);
    try {
      const res = await api.runCamouflageProbe({
        ip: ip.trim(),
        domain: domain.trim(),
        sni: sni.trim(),
        ports: ports.trim() || '80,443',
        timeoutSec,
      });
      setReport(res);
      if (res.total_score <= 20) {
        success(`伪装度评估通过：风险分 ${res.total_score}/100 (${res.risk_level})`);
      } else {
        error(`检测到伪装风险项：风险分 ${res.total_score}/100 (${res.risk_level})`);
      }
    } catch (err: unknown) {
      error(err instanceof Error ? err.message : '伪装度评估执行失败');
    } finally {
      setProbing(false);
    }
  };

  const getRiskMeta = (score: number) => {
    if (score <= 20) {
      return {
        tone: 'ok' as const,
        ring: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-400',
        title: '伪装优异 · 标准公网网关特征',
      };
    }
    if (score <= 50) {
      return {
        tone: 'warn' as const,
        ring: 'border-amber-500/40 bg-amber-500/10 text-amber-400',
        title: '轻度存疑 · 存在次要非标响应特征',
      };
    }
    if (score <= 75) {
      return {
        tone: 'warn' as const,
        ring: 'border-orange-500/40 bg-orange-500/10 text-orange-400',
        title: '高度存疑 · 暴露回落差异或握手异常',
      };
    }
    return {
      tone: 'danger' as const,
      ring: 'border-rose-500/40 bg-rose-500/10 text-rose-400',
      title: '高危暴露 · 显著代理或伪装破绽',
    };
  };

  return (
    <div className="space-y-5">
      <PageHeader
        title="节点伪装度与抗探测评估"
        description="并发执行端口对称性、HTTP 畸形容错、REALITY 源站证书比对、时延侧信道及 QUIC v1 双栈核验"
        actions={
          <Button
            variant="primary"
            loading={probing}
            disabled={loadingDefaults}
            icon={<RefreshCw className="w-3.5 h-3.5" />}
            onClick={() => handleRunProbe()}
          >
            {probing ? '五维审讯中…' : '立即开始评估'}
          </Button>
        }
      />

      <SectionCard title="探测目标参数" icon={<Radar className="w-4 h-4" />}>
        <div className="space-y-4">
          {presets.length > 0 && (
            <div className="space-y-2">
              <div className="text-xs font-medium text-secondary flex items-center gap-1.5">
                <Server className="w-3.5 h-3.5 text-muted" />
                <span>快速选择评估目标：</span>
              </div>
              <div className="flex flex-wrap gap-2">
                {presets.map((p) => {
                  const active = selectedPreset === p.id && ip === p.ip;
                  return (
                    <button
                      key={p.id}
                      type="button"
                      onClick={() => handleSelectPreset(p)}
                      className={`px-3 py-1.5 rounded-xl text-xs font-mono border transition-colors cursor-pointer ${
                        active
                          ? 'bg-sky-500/15 border-sky-500/40 text-accent font-semibold'
                          : 'bg-surface2 border-subtle text-secondary hover:text-primary'
                      }`}
                    >
                      <span>{p.name}</span>
                      {p.domain && <span className="text-muted ml-1.5">({p.domain})</span>}
                    </button>
                  );
                })}
              </div>
            </div>
          )}

          <form onSubmit={handleRunProbe} className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-secondary flex items-center gap-1.5">
                <Globe className="w-3.5 h-3.5 text-emerald-400" />
                <span>目标公网 IP / 地址</span>
              </label>
              <input
                type="text"
                value={ip}
                onChange={(e) => {
                  setIp(e.target.value);
                  setSelectedPreset('custom');
                }}
                placeholder="留空默认检测本机公网 IP"
                className="sc-input w-full px-3 py-2 text-xs font-mono"
              />
            </div>

            <div className="space-y-1.5">
              <label className="text-xs font-medium text-secondary flex items-center gap-1.5">
                <Lock className="w-3.5 h-3.5 text-sky-400" />
                <span>节点业务域名 (H3 / 双栈)</span>
              </label>
              <input
                type="text"
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                placeholder="例如 node.example.com"
                className="sc-input w-full px-3 py-2 text-xs font-mono"
              />
            </div>

            <div className="space-y-1.5">
              <label className="text-xs font-medium text-secondary flex items-center gap-1.5">
                <Sparkles className="w-3.5 h-3.5 text-amber-400" />
                <span>伪装 SNI 域名</span>
              </label>
              <input
                type="text"
                value={sni}
                onChange={(e) => setSni(e.target.value)}
                placeholder="例如 swdist.apple.com"
                className="sc-input w-full px-3 py-2 text-xs font-mono"
              />
            </div>

            <div className="grid grid-cols-2 gap-2">
              <div className="space-y-1.5">
                <label className="text-xs font-medium text-secondary flex items-center gap-1">
                  <Sliders className="w-3.5 h-3.5 text-muted" />
                  <span>探测端口</span>
                </label>
                <input
                  type="text"
                  value={ports}
                  onChange={(e) => setPorts(e.target.value)}
                  placeholder="80,443"
                  className="sc-input w-full px-3 py-2 text-xs font-mono"
                />
              </div>

              <div className="space-y-1.5">
                <label className="text-xs font-medium text-secondary flex items-center gap-1">
                  <Cpu className="w-3.5 h-3.5 text-muted" />
                  <span>超时 (秒)</span>
                </label>
                <input
                  type="number"
                  min={2}
                  max={10}
                  value={timeoutSec}
                  onChange={(e) => setTimeoutSec(Number(e.target.value) || 4)}
                  className="sc-input w-full px-3 py-2 text-xs font-mono tnum"
                />
              </div>
            </div>
          </form>
        </div>
      </SectionCard>

      {report ? (
        <div className="space-y-5">
          {(() => {
            const meta = getRiskMeta(report.total_score);
            return (
              <SectionCard>
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                  <div className="flex items-center gap-4">
                    <div
                      className={`w-20 h-20 rounded-2xl border-2 flex flex-col items-center justify-center shrink-0 font-mono tnum ${meta.ring}`}
                    >
                      <span className="text-2xl font-extrabold leading-none">{report.total_score}</span>
                      <span className="text-[10px] opacity-80 mt-1">/ 100 风险分</span>
                    </div>
                    <div className="space-y-1.5">
                      <div className="flex flex-wrap items-center gap-2">
                        <Badge tone={meta.tone}>{report.risk_level}</Badge>
                        <span className="text-sm font-bold text-primary">{meta.title}</span>
                      </div>
                      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs font-mono text-muted">
                        <span>
                          目标 IP: <strong className="text-primary">{report.target_ip}</strong>
                        </span>
                        {report.target_domain && (
                          <span>
                            域名: <strong className="text-primary">{report.target_domain}</strong>
                          </span>
                        )}
                        {report.target_sni && (
                          <span>
                            SNI: <strong className="text-primary">{report.target_sni}</strong>
                          </span>
                        )}
                        <span>{new Date(report.scan_time).toLocaleString()}</span>
                      </div>
                    </div>
                  </div>

                  {report.total_score === 0 ? (
                    <Badge tone="ok" dot>
                      <ShieldCheck className="w-3.5 h-3.5 mr-1" />
                      五维审讯满分通过
                    </Badge>
                  ) : (
                    <Badge tone="warn" dot>
                      <ShieldAlert className="w-3.5 h-3.5 mr-1" />
                      发现 {report.findings?.length || 0} 项异常特征
                    </Badge>
                  )}
                </div>

                {((report.findings && report.findings.length > 0) ||
                  (report.recommendations && report.recommendations.length > 0)) && (
                  <div className="mt-5 pt-5 border-t border-subtle grid grid-cols-1 lg:grid-cols-2 gap-4">
                    {report.findings && report.findings.length > 0 && (
                      <div className="p-4 rounded-xl bg-rose-500/8 border border-rose-500/25 space-y-2">
                        <div className="text-xs font-bold text-rose-400 flex items-center gap-1.5">
                          <AlertTriangle className="w-3.5 h-3.5" />
                          <span>命中的可疑特征明细 ({report.findings.length})</span>
                        </div>
                        <ul className="space-y-1.5 text-xs text-secondary font-mono">
                          {report.findings.map((f, idx) => (
                            <li key={idx}>• {f}</li>
                          ))}
                        </ul>
                      </div>
                    )}

                    {report.recommendations && report.recommendations.length > 0 && (
                      <div className="p-4 rounded-xl bg-amber-500/8 border border-amber-500/25 space-y-2">
                        <div className="text-xs font-bold text-amber-400 flex items-center gap-1.5">
                          <Sparkles className="w-3.5 h-3.5" />
                          <span>针对性抗探测加固建议</span>
                        </div>
                        <ul className="space-y-1.5 text-xs text-secondary">
                          {report.recommendations.map((rec, idx) => (
                            <li key={idx}>• {rec}</li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                )}
              </SectionCard>
            );
          })()}

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {report.categories.map((cat, cIdx) => {
              const catClean = cat.score === 0;
              return (
                <SectionCard
                  key={cIdx}
                  title={`[${cIdx + 1}/${report.categories.length}] ${cat.name}`}
                  badge={
                    <Badge tone={catClean ? 'ok' : 'danger'}>
                      风险: {cat.score} / {cat.max_score} 分
                    </Badge>
                  }
                >
                  <div className="space-y-3">
                    {cat.items.map((item, iIdx) => (
                      <div
                        key={iIdx}
                        className={`p-3.5 rounded-xl border ${
                          item.passed
                            ? 'bg-surface2/60 border-subtle'
                            : 'bg-rose-500/8 border-rose-500/25'
                        }`}
                      >
                        <div className="flex items-start justify-between gap-2">
                          <div className="flex items-center gap-2">
                            {item.passed ? (
                              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                            ) : (
                              <XCircle className="w-4 h-4 text-rose-400 shrink-0" />
                            )}
                            <span className="text-xs font-bold text-primary">{item.name}</span>
                          </div>
                          <Badge tone={item.passed ? 'ok' : 'danger'}>
                            {item.passed ? '通过 (+0)' : `异常 (+${item.score}/${item.max_score})`}
                          </Badge>
                        </div>

                        <p className="text-[11px] text-muted mt-1 pl-6">{item.description}</p>
                        <div className="mt-2 pl-6 text-xs font-mono text-secondary leading-relaxed break-all">
                          {item.details}
                        </div>

                        {!item.passed && item.mitigation && (
                          <div className="mt-2 ml-6 p-2.5 rounded-lg bg-amber-500/10 border border-amber-500/25 text-[11px] text-secondary">
                            <span className="font-semibold text-amber-400">加固建议：</span>
                            {item.mitigation}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </SectionCard>
              );
            })}
          </div>
        </div>
      ) : (
        <SectionCard>
          <div className="py-10 text-center space-y-2.5">
            <Radar className="w-8 h-8 text-accent mx-auto opacity-80" />
            <div className="text-sm font-semibold text-primary">准备好执行五维黑盒伪装度评估</div>
            <p className="text-xs text-muted max-w-lg mx-auto leading-relaxed">
              系统已自动填充当前节点的公网地址、业务域名与伪装 SNI。点击右上角「立即开始评估」即可在数秒内完成协议栈特征审讯与双栈证书核验。
            </p>
          </div>
        </SectionCard>
      )}
    </div>
  );
};
