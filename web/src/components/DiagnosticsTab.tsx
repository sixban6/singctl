import React, { useState } from 'react';
import {
  WarpDiagnoseResponse,
  ServerStatusResponse,
  ReturnSummary,
  MediaUnlockReport,
  ExitProfile,
} from '../types';
import { api } from '../api';
import { Badge, Button, PageHeader, SectionCard, useToast } from '../ui';
import { TabKey } from '../App';
import {
  Globe,
  Activity,
  RefreshCw,
  ArrowUpDown,
  ChevronDown,
  ChevronUp,
  Sparkles,
  Tv,
  Bot,
  Search,
  PlaySquare,
  Shield,
  Split,
} from 'lucide-react';

interface DiagnosticsTabProps {
  status: ServerStatusResponse | null;
  onNavigate?: (tab: TabKey) => void;
}

export const DiagnosticsTab: React.FC<DiagnosticsTabProps> = ({ onNavigate }) => {
  const { success, error } = useToast();
  const [warpData, setWarpData] = useState<WarpDiagnoseResponse | null>(null);
  const [testingWarp, setTestingWarp] = useState(false);

  const [returnSummary, setReturnSummary] = useState<ReturnSummary | null>(null);
  const [testingReturn, setTestingReturn] = useState(false);
  const [showHops, setShowHops] = useState<Record<number, boolean>>({});

  const [unlockData, setUnlockData] = useState<MediaUnlockReport | null>(null);
  const [testingUnlock, setTestingUnlock] = useState(false);

  const runUnlockDiagnose = async () => {
    setTestingUnlock(true);
    try {
      const res = await api.getMediaUnlock();
      setUnlockData(res);
      success('全球边缘多点出口画像与服务连通性探测完成');
    } catch (err: unknown) {
      error(err instanceof Error ? err.message : '解锁探测失败');
    } finally {
      setTestingUnlock(false);
    }
  };

  const runWarpDiagnose = async () => {
    setTestingWarp(true);
    try {
      const res = await api.getWarpDiagnose();
      setWarpData(res);
      if (res.connected) {
        success('WARP 出口探测成功');
      } else {
        error('WARP 出口未连接或未响应');
      }
    } catch (err: unknown) {
      error(err instanceof Error ? err.message : '探测失败');
    } finally {
      setTestingWarp(false);
    }
  };

  const runReturnTest = async () => {
    setTestingReturn(true);
    try {
      const res = await api.getNetReturn();
      setReturnSummary(res);
      success('三网回程测试完成');
    } catch (err: unknown) {
      error(err instanceof Error ? err.message : '回程测试失败');
    } finally {
      setTestingReturn(false);
    }
  };

  const formatRTT = (ns?: number) => {
    if (!ns || ns <= 0) return '-';
    return `${(ns / 1_000_000).toFixed(1)} ms`;
  };

  const renderExitProfile = (profile: ExitProfile, isWarp: boolean) => (
    <div className="p-4 rounded-xl bg-surface2/60 border border-subtle space-y-3">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-2.5 border-b border-subtle">
        <div className="flex items-center gap-2.5">
          <div
            className={`p-1.5 rounded-lg border ${
              isWarp
                ? 'bg-amber-500/10 text-amber-400 border-amber-500/25'
                : 'bg-sky-500/10 text-accent border-sky-500/25'
            }`}
          >
            {isWarp ? <Shield className="w-4 h-4" /> : <Globe className="w-4 h-4" />}
          </div>
          <div>
            <span className="font-semibold text-primary text-xs sm:text-sm">{profile.name}</span>
            {profile.exitIP && (
              <span className="ml-2 font-mono text-[11px] text-muted">
                IP: <span className="text-primary">{profile.exitIP}</span>{' '}
                {profile.exitLoc ? `(${profile.exitLoc})` : ''}
              </span>
            )}
          </div>
        </div>

        <Badge tone={profile.available ? 'ok' : 'neutral'} dot={profile.available}>
          {profile.available ? '在线就绪' : '未启用 / 未启动'}
        </Badge>
      </div>

      {!profile.available ? (
        <div className="py-3 text-center text-xs text-muted font-mono">
          {profile.errorReason || '该出口未启动或端口未监听'}
        </div>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2.5">
          <div className="p-3 rounded-xl bg-surface1 border border-subtle flex items-start gap-2.5">
            <Bot className="w-4 h-4 text-emerald-400 mt-0.5 shrink-0" />
            <div className="flex-1 min-w-0">
              <div className="flex items-center justify-between gap-2">
                <span className="font-semibold text-xs text-primary">ChatGPT / OpenAI</span>
                <Badge tone={profile.openai.status === 'unlocked' ? 'ok' : 'danger'}>
                  {profile.openai.status === 'unlocked'
                    ? `解锁${profile.openai.region ? ` [${profile.openai.region}]` : ''}`
                    : '受限'}
                </Badge>
              </div>
              <p className="text-[11px] text-muted truncate mt-1">{profile.openai.details || '-'}</p>
            </div>
          </div>

          <div className="p-3 rounded-xl bg-surface1 border border-subtle flex items-start gap-2.5">
            <Tv className="w-4 h-4 text-rose-400 mt-0.5 shrink-0" />
            <div className="flex-1 min-w-0">
              <div className="flex items-center justify-between gap-2">
                <span className="font-semibold text-xs text-primary">Netflix</span>
                <Badge
                  tone={
                    profile.netflix.status === 'unlocked'
                      ? 'ok'
                      : profile.netflix.status === 'partially_unlocked'
                      ? 'warn'
                      : 'danger'
                  }
                >
                  {profile.netflix.status === 'unlocked'
                    ? '完整解锁'
                    : profile.netflix.status === 'partially_unlocked'
                    ? '自制剧'
                    : '未解锁'}
                </Badge>
              </div>
              <p className="text-[11px] text-muted truncate mt-1">{profile.netflix.details || '-'}</p>
            </div>
          </div>

          <div className="p-3 rounded-xl bg-surface1 border border-subtle flex items-start gap-2.5">
            <PlaySquare className="w-4 h-4 text-red-400 mt-0.5 shrink-0" />
            <div className="flex-1 min-w-0">
              <div className="flex items-center justify-between gap-2">
                <span className="font-semibold text-xs text-primary">YouTube Premium</span>
                <Badge tone={profile.youtube.status === 'unlocked' ? 'ok' : 'danger'}>
                  {profile.youtube.status === 'unlocked' ? '原生支持' : '受限'}
                </Badge>
              </div>
              <p className="text-[11px] text-muted truncate mt-1">{profile.youtube.details || '-'}</p>
            </div>
          </div>

          <div className="p-3 rounded-xl bg-surface1 border border-subtle flex items-start gap-2.5">
            <Globe className="w-4 h-4 text-sky-400 mt-0.5 shrink-0" />
            <div className="flex-1 min-w-0">
              <div className="flex items-center justify-between gap-2">
                <span className="font-semibold text-xs text-primary">Disney+</span>
                <Badge tone={profile.disney.status === 'unlocked' ? 'ok' : 'danger'}>
                  {profile.disney.status === 'unlocked' ? '支持访问' : '受阻'}
                </Badge>
              </div>
              <p className="text-[11px] text-muted truncate mt-1">{profile.disney.details || '-'}</p>
            </div>
          </div>

          <div className="p-3 rounded-xl bg-surface1 border border-subtle flex items-start gap-2.5">
            <Search className="w-4 h-4 text-amber-400 mt-0.5 shrink-0" />
            <div className="flex-1 min-w-0">
              <div className="flex items-center justify-between gap-2">
                <span className="font-semibold text-xs text-primary">Google 搜索</span>
                <Badge tone={profile.google.status === 'unlocked' ? 'ok' : 'warn'}>
                  {profile.google.status === 'unlocked' ? '无验证码' : '需验证码'}
                </Badge>
              </div>
              <p className="text-[11px] text-muted truncate mt-1">{profile.google.details || '-'}</p>
            </div>
          </div>
        </div>
      )}
    </div>
  );

  return (
    <div className="space-y-5">
      <PageHeader
        title="网络诊断与流媒体解锁"
        description="一站式实测三网回程线路质量、WARP 出口连通性及多出口流媒体 / AI 解锁状态"
      />

      {/* Three-Network Return Probe */}
      <SectionCard
        title="三网回程线路探测"
        subtitle="并发向中国电信 (163/CN2)、中国联通 (4837/9929)、中国移动 (CMI/CMIN2) 发起轻量探测"
        icon={<ArrowUpDown className="w-4 h-4" />}
        actions={
          <Button
            size="sm"
            variant="primary"
            loading={testingReturn}
            icon={<RefreshCw className="w-3.5 h-3.5" />}
            onClick={runReturnTest}
          >
            {testingReturn ? '探测中…' : '开始三网回程测试'}
          </Button>
        }
      >
        {returnSummary ? (
          <div className="space-y-4">
            <div className="p-3.5 rounded-xl bg-surface2/70 border border-subtle flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <div className="text-xs font-mono text-secondary">
                探测源 IP:{' '}
                <span className="text-primary font-semibold">
                  {returnSummary.server_ip || returnSummary.serverIp || '本机公网'}
                </span>
              </div>
              <Badge tone="ok">{returnSummary.summary}</Badge>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
              {returnSummary.results.map((r, i) => {
                const loss = r.loss_rate ?? r.lossRate ?? 0;
                const rtt = r.avg_rtt ?? r.avgRtt;
                const lineName = r.route_name || r.routeName || '普通回程';
                const hops = r.key_hops || r.keyHops;

                return (
                  <div
                    key={i}
                    className="p-4 rounded-xl bg-surface2/50 border border-subtle flex flex-col justify-between space-y-3"
                  >
                    <div>
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-xs font-bold text-primary">{r.name}</span>
                        <Badge tone="neutral">{r.city}</Badge>
                      </div>

                      <div className="space-y-1.5 text-xs font-mono tnum mt-2">
                        <div className="flex justify-between">
                          <span className="text-muted">骨干识别</span>
                          <span className="text-emerald-400 font-semibold">{lineName}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-muted">平均延迟</span>
                          <span className="text-primary">{formatRTT(rtt)}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-muted">丢包率</span>
                          <span className={loss > 5 ? 'text-rose-400 font-bold' : 'text-secondary'}>
                            {loss.toFixed(1)}%
                          </span>
                        </div>
                      </div>
                    </div>

                    {hops && hops.length > 0 && (
                      <div className="pt-2.5 border-t border-subtle">
                        <button
                          type="button"
                          onClick={() => setShowHops((prev) => ({ ...prev, [i]: !prev[i] }))}
                          className="text-[11px] text-secondary hover:text-primary flex items-center gap-1 font-mono cursor-pointer"
                        >
                          <span>沿途跳点 ({hops.length})</span>
                          {showHops[i] ? (
                            <ChevronUp className="w-3 h-3" />
                          ) : (
                            <ChevronDown className="w-3 h-3" />
                          )}
                        </button>
                        {showHops[i] && (
                          <div className="mt-2 text-[10.5px] font-mono text-muted space-y-1 bg-surface1 p-2.5 rounded-lg border border-subtle">
                            {hops.map((h, k) => (
                              <div key={k} className="truncate">
                                • {h}
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        ) : (
          <p className="text-xs text-muted">点击右上角按钮测试电信、联通、移动三大运营商直连回程路径。</p>
        )}
      </SectionCard>

      {/* WARP Exit Check */}
      <SectionCard
        title="Cloudflare WARP 出口探测"
        subtitle="模拟流量经由本地 wireproxy SOCKS5 出海，检测 Anycast IPv4/IPv6 与区域代码"
        icon={<Activity className="w-4 h-4" />}
        actions={
          <Button
            size="sm"
            variant="secondary"
            loading={testingWarp}
            icon={<RefreshCw className="w-3.5 h-3.5" />}
            onClick={runWarpDiagnose}
          >
            {testingWarp ? '探测中…' : '探测 WARP 落地 IP'}
          </Button>
        }
      >
        {warpData ? (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
            <div className="p-3.5 rounded-xl bg-surface2/60 border border-subtle">
              <div className="text-[11px] text-muted">WARP 状态</div>
              <div className="mt-2">
                <Badge tone={warpData.connected ? 'ok' : 'danger'} dot>
                  {warpData.connected ? '已连通 (ON)' : '未连通'}
                </Badge>
              </div>
            </div>
            <div className="p-3.5 rounded-xl bg-surface2/60 border border-subtle">
              <div className="text-[11px] text-muted">出口公网 IP</div>
              <div className="text-sm font-bold text-primary font-mono mt-1.5 truncate">
                {warpData.ip || '未知'}
              </div>
            </div>
            <div className="p-3.5 rounded-xl bg-surface2/60 border border-subtle">
              <div className="text-[11px] text-muted">出口地理位置</div>
              <div className="text-sm font-bold text-primary font-mono mt-1.5">
                {warpData.loc ? `${warpData.loc} (区域代码)` : '未知'}
              </div>
            </div>
            <div className="p-3.5 rounded-xl bg-surface2/60 border border-subtle">
              <div className="text-[11px] text-muted">Trace 延时</div>
              <div className="text-sm font-bold text-emerald-400 font-mono tnum mt-1.5">
                {warpData.latencyMs ? `${warpData.latencyMs} ms` : '-'}
              </div>
            </div>
          </div>
        ) : (
          <p className="text-xs text-muted">点击右上角按钮验证本机 wireproxy SOCKS5 通道状态。</p>
        )}
      </SectionCard>

      {/* Streaming & AI Unlock Matrix */}
      <SectionCard
        title="海外流媒体与 AI 解锁画像"
        subtitle="实测 VPS 原生直连与 WARP 分流双出口对 ChatGPT、Netflix、YouTube、Disney+ 与 Google 搜索风控"
        icon={<Sparkles className="w-4 h-4" />}
        actions={
          <Button
            size="sm"
            variant="primary"
            loading={testingUnlock}
            icon={<RefreshCw className="w-3.5 h-3.5" />}
            onClick={runUnlockDiagnose}
          >
            {testingUnlock ? '探测中…' : '开始解锁测试'}
          </Button>
        }
      >
        {unlockData ? (
          <div className="space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-2 text-xs font-mono text-muted">
              <span>探测时间: {unlockData.testedAt}</span>
              {onNavigate && (
                <Button
                  size="xs"
                  variant="secondary"
                  icon={<Split className="w-3.5 h-3.5" />}
                  onClick={() => onNavigate('warp')}
                >
                  前往 WARP 分流中心
                </Button>
              )}
            </div>
            {renderExitProfile(unlockData.direct, false)}
            {renderExitProfile(unlockData.warp, true)}
          </div>
        ) : (
          <div className="py-8 text-center space-y-2">
            <Sparkles className="w-7 h-7 text-accent mx-auto opacity-75" />
            <div className="text-xs font-semibold text-primary">尚未执行流媒体与 AI 解锁诊断</div>
            <p className="text-xs text-muted max-w-md mx-auto">
              点击上方「开始解锁测试」，并发验证 VPS 原生出口与 WARP 分流出口对海外服务的解锁和抗风控能力。
            </p>
          </div>
        )}
      </SectionCard>
    </div>
  );
};
