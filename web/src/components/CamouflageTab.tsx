import React, { useEffect, useState } from 'react';
import {
  CamouflagePreset,
  CamouflageReport,
  ServerStatusResponse,
} from '../types';
import { api } from '../api';
import { useToast } from './Toast';
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
    } catch (err: any) {
      error(err.message || '伪装度评估执行失败');
    } finally {
      setProbing(false);
    }
  };

  const getRiskStyle = (score: number) => {
    if (score <= 20) {
      return {
        badge: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
        ring: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-400',
        bar: 'bg-emerald-500',
        title: '伪装优异 · 标准公网网关特征',
      };
    }
    if (score <= 50) {
      return {
        badge: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
        ring: 'border-amber-500/40 bg-amber-500/10 text-amber-400',
        bar: 'bg-amber-500',
        title: '轻度存疑 · 存在次要非标响应特征',
      };
    }
    if (score <= 75) {
      return {
        badge: 'bg-orange-500/15 text-orange-300 border-orange-500/30',
        ring: 'border-orange-500/40 bg-orange-500/10 text-orange-400',
        bar: 'bg-orange-500',
        title: '高度存疑 · 暴露回落差异或握手异常',
      };
    }
    return {
      badge: 'bg-rose-500/15 text-rose-300 border-rose-500/30',
      ring: 'border-rose-500/40 bg-rose-500/10 text-rose-400',
      bar: 'bg-rose-500',
      title: '高危暴露 · 显著代理或伪装破绽',
    };
  };

  return (
    <div className="space-y-6">
      {/* Control & Target Configuration Card */}
      <div className="p-6 rounded-2xl glass-card space-y-5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-800/80">
          <div>
            <div className="flex items-center gap-2 text-emerald-400 text-xs font-semibold uppercase tracking-wider mb-1">
              <Radar className="w-3.5 h-3.5" />
              <span>黑盒主动探测模拟与伪装度红队审讯</span>
            </div>
            <h2 className="text-xl font-bold text-white tracking-tight">
              节点伪装度与抗主动探测评估
            </h2>
            <p className="text-xs text-slate-400 mt-1 max-w-3xl">
              站在外部主动探测器的黑盒视角，并发执行端口对称性、HTTP 畸形容错、Reality 源站证书链与 L7 穿透、多阶段变长高熵时延侧信道、以及 QUIC v1 (H3) 双栈证书脑裂比对。分值越低代表伪装越完美（0 分最佳）。
            </p>
          </div>

          <button
            type="button"
            onClick={() => handleRunProbe()}
            disabled={probing || loadingDefaults}
            className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-emerald-500 hover:bg-emerald-600 text-slate-950 font-semibold text-xs transition-all shadow-lg shadow-emerald-500/20 disabled:opacity-50 self-start sm:self-auto shrink-0"
          >
            <RefreshCw className={`w-4 h-4 ${probing ? 'animate-spin' : ''}`} />
            <span>{probing ? '正在执行五维并发审讯...' : '立即开始评估'}</span>
          </button>
        </div>

        {/* Preset Node Selector */}
        {presets.length > 0 && (
          <div className="space-y-2">
            <div className="text-xs font-medium text-slate-400 flex items-center gap-1.5">
              <Server className="w-3.5 h-3.5 text-slate-500" />
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
                    className={`px-3 py-1.5 rounded-xl text-xs font-mono border transition-all ${
                      active
                        ? 'bg-emerald-500/15 border-emerald-500/40 text-emerald-300 font-semibold'
                        : 'bg-slate-950/70 border-slate-800 text-slate-300 hover:border-slate-700'
                    }`}
                  >
                    <span>{p.name}</span>
                    {p.domain && <span className="text-slate-500 ml-1.5">({p.domain})</span>}
                  </button>
                );
              })}
            </div>
          </div>
        )}

        {/* Target Parameters Form */}
        <form onSubmit={handleRunProbe} className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5 pt-1">
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-slate-300 flex items-center gap-1.5">
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
              className="w-full px-3 py-2 rounded-xl bg-slate-950/90 border border-slate-800 text-xs font-mono text-white placeholder-slate-600 focus:outline-none focus:border-emerald-500/50"
            />
          </div>

          <div className="space-y-1.5">
            <label className="text-xs font-medium text-slate-300 flex items-center gap-1.5">
              <Lock className="w-3.5 h-3.5 text-blue-400" />
              <span>节点业务域名 (用于 H3/双栈证书核验)</span>
            </label>
            <input
              type="text"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              placeholder="例如 cdn.example.com"
              className="w-full px-3 py-2 rounded-xl bg-slate-950/90 border border-slate-800 text-xs font-mono text-white placeholder-slate-600 focus:outline-none focus:border-emerald-500/50"
            />
          </div>

          <div className="space-y-1.5">
            <label className="text-xs font-medium text-slate-300 flex items-center gap-1.5">
              <Sparkles className="w-3.5 h-3.5 text-purple-400" />
              <span>伪装 SNI 域名 (Reality 源站比对)</span>
            </label>
            <input
              type="text"
              value={sni}
              onChange={(e) => setSni(e.target.value)}
              placeholder="例如 swdist.apple.com"
              className="w-full px-3 py-2 rounded-xl bg-slate-950/90 border border-slate-800 text-xs font-mono text-white placeholder-slate-600 focus:outline-none focus:border-emerald-500/50"
            />
          </div>

          <div className="grid grid-cols-2 gap-2">
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-slate-300 flex items-center gap-1">
                <Sliders className="w-3.5 h-3.5 text-amber-400" />
                <span>探测端口</span>
              </label>
              <input
                type="text"
                value={ports}
                onChange={(e) => setPorts(e.target.value)}
                placeholder="80,443"
                className="w-full px-3 py-2 rounded-xl bg-slate-950/90 border border-slate-800 text-xs font-mono text-white placeholder-slate-600 focus:outline-none focus:border-emerald-500/50"
              />
            </div>

            <div className="space-y-1.5">
              <label className="text-xs font-medium text-slate-300 flex items-center gap-1">
                <Cpu className="w-3.5 h-3.5 text-slate-400" />
                <span>单项超时 (秒)</span>
              </label>
              <input
                type="number"
                min={2}
                max={10}
                value={timeoutSec}
                onChange={(e) => setTimeoutSec(Number(e.target.value) || 4)}
                className="w-full px-3 py-2 rounded-xl bg-slate-950/90 border border-slate-800 text-xs font-mono text-white focus:outline-none focus:border-emerald-500/50"
              />
            </div>
          </div>
        </form>
      </div>

      {/* Assessment Report View */}
      {report ? (
        <div className="space-y-5 animate-fade-in">
          {/* Overall Score & Summary Hero */}
          {(() => {
            const style = getRiskStyle(report.total_score);
            return (
              <div className="p-6 rounded-2xl glass-card border border-slate-800/90">
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-5">
                  <div className="flex items-center gap-4">
                    <div
                      className={`w-20 h-20 rounded-2xl border-2 flex flex-col items-center justify-center shrink-0 font-mono ${style.ring}`}
                    >
                      <span className="text-2xl font-extrabold leading-none">
                        {report.total_score}
                      </span>
                      <span className="text-[10px] opacity-80 mt-1">/ 100 风险分</span>
                    </div>

                    <div className="space-y-1.5">
                      <div className="flex flex-wrap items-center gap-2">
                        <span
                          className={`px-2.5 py-0.5 rounded-full text-xs font-semibold border font-mono ${style.badge}`}
                        >
                          {report.risk_level}
                        </span>
                        <span className="text-sm font-bold text-white">{style.title}</span>
                      </div>

                      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs font-mono text-slate-400">
                        <span>
                          目标 IP: <strong className="text-slate-200">{report.target_ip}</strong>
                        </span>
                        {report.target_domain && (
                          <span>
                            节点域名:{' '}
                            <strong className="text-slate-200">{report.target_domain}</strong>
                          </span>
                        )}
                        {report.target_sni && (
                          <span>
                            伪装 SNI: <strong className="text-slate-200">{report.target_sni}</strong>
                          </span>
                        )}
                        <span>
                          评估时间:{' '}
                          {new Date(report.scan_time).toLocaleString()}
                        </span>
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center gap-2 text-xs font-mono">
                    {report.total_score === 0 ? (
                      <div className="flex items-center gap-2 px-3.5 py-2 rounded-xl bg-emerald-500/10 border border-emerald-500/25 text-emerald-300">
                        <ShieldCheck className="w-4 h-4 shrink-0" />
                        <span>五维审讯全部满分通过，零私有协议特征泄露</span>
                      </div>
                    ) : (
                      <div className="flex items-center gap-2 px-3.5 py-2 rounded-xl bg-amber-500/10 border border-amber-500/25 text-amber-200">
                        <ShieldAlert className="w-4 h-4 shrink-0" />
                        <span>发现 {report.findings?.length || 0} 项异常特征，请参考下方建议加固</span>
                      </div>
                    )}
                  </div>
                </div>

                {/* Findings & Recommendations Box */}
                {((report.findings && report.findings.length > 0) ||
                  (report.recommendations && report.recommendations.length > 0)) && (
                  <div className="mt-5 pt-5 border-t border-slate-800/80 grid grid-cols-1 lg:grid-cols-2 gap-4">
                    {report.findings && report.findings.length > 0 && (
                      <div className="p-4 rounded-xl bg-rose-500/5 border border-rose-500/20 space-y-2">
                        <div className="text-xs font-bold text-rose-300 flex items-center gap-1.5">
                          <AlertTriangle className="w-3.5 h-3.5" />
                          <span>命中的可疑特征明细 ({report.findings.length})</span>
                        </div>
                        <ul className="space-y-1.5 text-xs text-rose-200/90 font-mono">
                          {report.findings.map((f, idx) => (
                            <li key={idx} className="leading-relaxed">
                              • {f}
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}

                    {report.recommendations && report.recommendations.length > 0 && (
                      <div className="p-4 rounded-xl bg-amber-500/5 border border-amber-500/20 space-y-2">
                        <div className="text-xs font-bold text-amber-300 flex items-center gap-1.5">
                          <Sparkles className="w-3.5 h-3.5" />
                          <span>针对性抗探测加固建议</span>
                        </div>
                        <ul className="space-y-1.5 text-xs text-amber-100/90">
                          {report.recommendations.map((rec, idx) => (
                            <li key={idx} className="leading-relaxed">
                              {rec}
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })()}

          {/* 5 Categories Detailed Breakdown */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {report.categories.map((cat, cIdx) => {
              const catClean = cat.score === 0;
              return (
                <div
                  key={cIdx}
                  className="p-5 rounded-2xl glass-card border border-slate-800/80 flex flex-col justify-between space-y-4"
                >
                  <div>
                    <div className="flex items-center justify-between gap-2 pb-3 border-b border-slate-800/80">
                      <div className="flex items-center gap-2">
                        <span className="px-2 py-0.5 rounded-md bg-slate-900 border border-slate-800 text-[11px] font-mono text-slate-400">
                          [{cIdx + 1}/{report.categories.length}]
                        </span>
                        <h3 className="text-sm font-bold text-white">{cat.name}</h3>
                      </div>
                      <span
                        className={`px-2.5 py-0.5 rounded-full text-xs font-mono font-semibold border ${
                          catClean
                            ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/25'
                            : 'bg-rose-500/15 text-rose-300 border-rose-500/30'
                        }`}
                      >
                        风险贡献: {cat.score} / {cat.max_score} 分
                      </span>
                    </div>

                    <div className="space-y-3 mt-3.5">
                      {cat.items.map((item, iIdx) => (
                        <div
                          key={iIdx}
                          className={`p-3.5 rounded-xl border ${
                            item.passed
                              ? 'bg-slate-950/60 border-slate-800/80'
                              : 'bg-rose-950/20 border-rose-500/30'
                          }`}
                        >
                          <div className="flex items-start justify-between gap-2">
                            <div className="flex items-center gap-2">
                              {item.passed ? (
                                <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                              ) : (
                                <XCircle className="w-4 h-4 text-rose-400 shrink-0" />
                              )}
                              <span className="text-xs font-bold text-white">{item.name}</span>
                            </div>
                            <span
                              className={`text-[11px] font-mono px-2 py-0.5 rounded-md shrink-0 ${
                                item.passed
                                  ? 'bg-emerald-500/10 text-emerald-400'
                                  : 'bg-rose-500/20 text-rose-300 font-bold'
                              }`}
                            >
                              {item.passed ? '通过 (+0分)' : `异常 (+${item.score}/${item.max_score}分)`}
                            </span>
                          </div>

                          <p className="text-[11px] text-slate-400 mt-1 pl-6">
                            {item.description}
                          </p>

                          <div className="mt-2 pl-6 text-xs font-mono text-slate-200 leading-relaxed break-all">
                            {item.details}
                          </div>

                          {!item.passed && item.mitigation && (
                            <div className="mt-2 ml-6 p-2 rounded-lg bg-amber-500/10 border border-amber-500/25 text-[11px] text-amber-200">
                              <span className="font-semibold">加固建议：</span>
                              {item.mitigation}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      ) : (
        <div className="p-10 rounded-2xl glass-card border border-slate-800/80 text-center space-y-3">
          <div className="w-12 h-12 rounded-2xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400 mx-auto">
            <Radar className="w-6 h-6" />
          </div>
          <div className="text-sm font-bold text-slate-200">
            准备好执行五维黑盒伪装度评估
          </div>
          <p className="text-xs text-slate-400 max-w-lg mx-auto leading-relaxed">
            系统已自动填充当前节点的公网地址、业务域名与伪装 SNI。点击右上角【立即开始评估】即可在 2~4 秒内完成全套协议栈特征审讯与双栈证书核验。
          </p>
        </div>
      )}
    </div>
  );
};
