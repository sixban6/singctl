import React, { useCallback, useEffect, useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  MinusCircle,
  RefreshCw,
  Stethoscope,
  Wrench,
  XCircle,
} from 'lucide-react';
import { Badge, BadgeTone, Button, SlideDrawer, useToast } from '../../../ui';
import { clientApi } from '../../api';
import { DoctorCheckResult, DoctorReport, DoctorStatus } from '../../types';

export interface DoctorDrawerProps {
  open: boolean;
  onClose: () => void;
  onFixed?: () => void;
}

const STATUS_META: Record<
  DoctorStatus,
  { label: string; tone: BadgeTone; borderClass: string }
> = {
  pass: { label: '通过', tone: 'ok', borderClass: 'border-slate-800/80' },
  warn: { label: '建议优化', tone: 'warn', borderClass: 'border-amber-500/30' },
  fail: { label: '异常', tone: 'danger', borderClass: 'border-rose-500/35' },
  skip: { label: '已跳过', tone: 'neutral', borderClass: 'border-slate-800/70' },
};

const CATEGORY_LABELS: Record<string, string> = {
  host: '宿主机',
  dns: 'DNS',
  network: '网络',
  proxy: '代理',
  security: '安全',
  service: '服务',
  config: '配置',
};

function renderStatusIcon(status: DoctorStatus) {
  switch (status) {
    case 'pass':
      return <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />;
    case 'warn':
      return <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />;
    case 'fail':
      return <XCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />;
    default:
      return <MinusCircle className="w-4 h-4 text-slate-500 shrink-0 mt-0.5" />;
  }
}

function scoreColor(score: number): { stroke: string; text: string; tone: BadgeTone; label: string } {
  if (score >= 90) {
    return { stroke: '#34d399', text: 'text-emerald-400', tone: 'ok', label: '健康优秀' };
  }
  if (score >= 60) {
    return { stroke: '#fbbf24', text: 'text-amber-300', tone: 'warn', label: '存在优化项' };
  }
  return { stroke: '#fb7185', text: 'text-rose-400', tone: 'danger', label: '需尽快修复' };
}

export const DoctorDrawer: React.FC<DoctorDrawerProps> = ({ open, onClose, onFixed }) => {
  const { success, error } = useToast();
  const [report, setReport] = useState<DoctorReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [loadErr, setLoadErr] = useState<string | null>(null);
  const [fixingAction, setFixingAction] = useState<string | null>(null);
  const [expandedIds, setExpandedIds] = useState<Record<string, boolean>>({});

  const runCheck = useCallback(async () => {
    setLoading(true);
    setLoadErr(null);
    try {
      const res = await clientApi.runDoctor();
      setReport(res);
      const nextExpanded: Record<string, boolean> = {};
      for (const item of res.checks || []) {
        if (item.status === 'warn' || item.status === 'fail') {
          nextExpanded[item.id] = true;
        }
      }
      setExpandedIds(nextExpanded);
    } catch (err: unknown) {
      setLoadErr(err instanceof Error ? err.message : '深度体检执行失败');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (open && !report && !loading) {
      void runCheck();
    }
  }, [open, report, loading, runCheck]);

  const handleQuickFix = async (item: DoctorCheckResult) => {
    if (!item.fixAction) return;
    setFixingAction(item.fixAction);
    try {
      const res = await clientApi.runDoctorFix(item.fixAction);
      success(res.message || `已执行修复：${item.fixLabel || item.fixAction}`, 5000);
      onFixed?.();
      await runCheck();
    } catch (err: unknown) {
      error(`一键修复失败：${err instanceof Error ? err.message : '未知错误'}`);
    } finally {
      setFixingAction(null);
    }
  };

  const toggleExpand = (id: string) => {
    setExpandedIds((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  const scoreVal = Math.min(100, Math.max(0, report?.score ?? 0));
  const ringMeta = scoreColor(scoreVal);
  const radius = 34;
  const circumference = 2 * Math.PI * radius;
  const dashOffset = circumference - (scoreVal / 100) * circumference;

  return (
    <SlideDrawer
      open={open}
      onClose={onClose}
      size="lg"
      title={
        <span className="inline-flex items-center gap-2">
          <Stethoscope className="w-4 h-4 text-emerald-400" />
          <span>全链路深度体检</span>
        </span>
      }
      subtitle="8 项网关运行态、DNS 防劫持、连通性、内核参数与防失联安全扫描"
      headerExtra={
        <Button
          size="xs"
          variant="secondary"
          loading={loading}
          disabled={Boolean(fixingAction)}
          onClick={() => void runCheck()}
          icon={<RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />}
        >
          重新体检
        </Button>
      }
      footer={
        <div className="flex items-center justify-between gap-2 text-xs">
          <span className="text-slate-500 font-mono truncate">
            终端命令：<code className="text-emerald-400">singctl doctor</code>
          </span>
          <Button size="sm" variant="secondary" onClick={onClose}>
            关闭
          </Button>
        </div>
      }
    >
      {loading && !report ? (
        <div className="space-y-3 py-4">
          <div className="p-4 rounded-2xl bg-slate-950/70 border border-slate-800/80 flex items-center gap-3">
            <RefreshCw className="w-5 h-5 text-emerald-400 animate-spin shrink-0" />
            <div>
              <div className="text-sm font-semibold text-white">正在执行全链路 8 项深度体检…</div>
              <div className="text-xs text-slate-400 mt-0.5">
                正在检测宿主机闪存/内存、OOM 免疫、防劫持 DNS、代理转发与连通性
              </div>
            </div>
          </div>
          {Array.from({ length: 4 }).map((_, idx) => (
            <div
              key={idx}
              className="h-16 rounded-xl bg-slate-950/60 border border-slate-800/70 animate-pulse"
            />
          ))}
        </div>
      ) : loadErr && !report ? (
        <div className="p-5 rounded-2xl border border-rose-500/35 bg-rose-500/10 space-y-3 text-center">
          <XCircle className="w-8 h-8 text-rose-400 mx-auto" />
          <div className="text-sm font-semibold text-rose-200">深度体检执行失败</div>
          <p className="text-xs text-rose-300/85 break-words">{loadErr}</p>
          <Button size="sm" variant="secondary" onClick={() => void runCheck()}>
            重试体检
          </Button>
        </div>
      ) : report ? (
        <div className="space-y-4">
          {/* Score Overview Card */}
          <div className="p-4 rounded-2xl bg-slate-950/70 border border-slate-800/80 flex flex-col sm:flex-row sm:items-center gap-4">
            <div className="relative w-20 h-20 shrink-0 mx-auto sm:mx-0">
              <svg viewBox="0 0 84 84" className="w-20 h-20 -rotate-90">
                <circle
                  cx="42"
                  cy="42"
                  r={radius}
                  fill="none"
                  stroke="rgba(51, 65, 85, 0.55)"
                  strokeWidth="7"
                />
                <circle
                  cx="42"
                  cy="42"
                  r={radius}
                  fill="none"
                  stroke={ringMeta.stroke}
                  strokeWidth="7"
                  strokeLinecap="round"
                  strokeDasharray={circumference}
                  strokeDashoffset={dashOffset}
                  className="transition-all duration-500"
                />
              </svg>
              <div className="absolute inset-0 flex flex-col items-center justify-center">
                <span className={`text-xl font-bold font-mono tnum leading-none ${ringMeta.text}`}>
                  {scoreVal}
                </span>
                <span className="text-[10px] text-slate-500 mt-0.5">/ 100</span>
              </div>
            </div>

            <div className="flex-1 min-w-0 space-y-2.5 text-center sm:text-left">
              <div className="flex flex-wrap items-center justify-center sm:justify-start gap-2">
                <span className="text-sm font-semibold text-white">体检综合评分</span>
                <Badge tone={ringMeta.tone} dot>
                  {ringMeta.label}
                </Badge>
                {loading && (
                  <span className="text-[11px] text-emerald-400 inline-flex items-center gap-1">
                    <RefreshCw className="w-3 h-3 animate-spin" />
                    刷新中…
                  </span>
                )}
              </div>

              <div className="grid grid-cols-4 gap-2 text-center">
                <div className="px-2 py-1.5 rounded-xl bg-emerald-500/10 border border-emerald-500/20">
                  <div className="text-sm font-bold font-mono text-emerald-400 tnum">
                    {report.passed}
                  </div>
                  <div className="text-[10px] text-slate-400">通过</div>
                </div>
                <div className="px-2 py-1.5 rounded-xl bg-amber-500/10 border border-amber-500/20">
                  <div className="text-sm font-bold font-mono text-amber-300 tnum">
                    {report.warnings}
                  </div>
                  <div className="text-[10px] text-slate-400">警告</div>
                </div>
                <div className="px-2 py-1.5 rounded-xl bg-rose-500/10 border border-rose-500/20">
                  <div className="text-sm font-bold font-mono text-rose-400 tnum">
                    {report.failed}
                  </div>
                  <div className="text-[10px] text-slate-400">失败</div>
                </div>
                <div className="px-2 py-1.5 rounded-xl bg-slate-900/90 border border-slate-800">
                  <div className="text-sm font-bold font-mono text-slate-300 tnum">
                    {report.skipped}
                  </div>
                  <div className="text-[10px] text-slate-400">跳过</div>
                </div>
              </div>

              <div className="flex flex-wrap items-center justify-center sm:justify-between gap-2 text-[11px] font-mono text-slate-500 tnum">
                <span>体检耗时：{report.durationMs} ms</span>
                {report.checkedAt && <span>时间：{report.checkedAt}</span>}
              </div>
            </div>
          </div>

          {loadErr && (
            <div className="px-3 py-2 rounded-xl border border-rose-500/30 bg-rose-500/10 text-xs text-rose-300">
              上次刷新失败：{loadErr}
            </div>
          )}

          {/* 8 Check Items List */}
          <div className="space-y-2.5">
            {(report.checks || []).map((item) => {
              const meta = STATUS_META[item.status] || STATUS_META.skip;
              const hasExtra = Boolean(item.detail || item.advice);
              const expanded = Boolean(expandedIds[item.id]);
              const canFix = Boolean(item.fixAction && item.status !== 'pass');
              const isFixingThis = fixingAction === item.fixAction;
              const catLabel = CATEGORY_LABELS[item.category] || item.category;

              return (
                <div
                  key={item.id}
                  className={`p-3.5 rounded-xl bg-slate-950/65 border transition-colors ${meta.borderClass}`}
                >
                  <div className="flex items-start justify-between gap-2.5">
                    <div className="flex items-start gap-2.5 min-w-0 flex-1">
                      {renderStatusIcon(item.status)}
                      <div className="min-w-0 flex-1">
                        <div className="flex flex-wrap items-center gap-1.5">
                          <span className="text-xs sm:text-sm font-semibold text-white">
                            {item.title}
                          </span>
                          {catLabel && (
                            <span className="px-1.5 py-0.5 rounded bg-slate-900 border border-slate-800 text-[10px] font-mono text-slate-400">
                              {catLabel}
                            </span>
                          )}
                        </div>
                        <p className="text-xs text-slate-300 mt-1 leading-relaxed break-words">
                          {item.summary}
                        </p>
                      </div>
                    </div>

                    <div className="flex flex-col items-end gap-1 shrink-0">
                      <Badge tone={meta.tone}>{meta.label}</Badge>
                      <span className="text-[10px] font-mono text-slate-500 tnum">
                        {item.durationMs}ms
                      </span>
                    </div>
                  </div>

                  {(hasExtra || canFix) && (
                    <div className="mt-2.5 pl-6 space-y-2">
                      {hasExtra && (
                        <button
                          type="button"
                          onClick={() => toggleExpand(item.id)}
                          className="inline-flex items-center gap-1 text-[11px] text-slate-400 hover:text-slate-200 transition-colors cursor-pointer"
                        >
                          {expanded ? (
                            <ChevronDown className="w-3.5 h-3.5" />
                          ) : (
                            <ChevronRight className="w-3.5 h-3.5" />
                          )}
                          <span>{expanded ? '收起诊断详情' : '查看诊断详情与建议'}</span>
                        </button>
                      )}

                      {hasExtra && expanded && (
                        <div className="p-2.5 rounded-lg bg-slate-900/80 border border-slate-800/80 space-y-1.5 text-[11px] leading-relaxed">
                          {item.detail && (
                            <div className="font-mono text-slate-300 whitespace-pre-wrap break-words">
                              {item.detail}
                            </div>
                          )}
                          {item.advice && (
                            <div className="text-amber-300/90 break-words">
                              建议：{item.advice}
                            </div>
                          )}
                        </div>
                      )}

                      {canFix && (
                        <div className="pt-0.5">
                          <Button
                            size="xs"
                            variant="primary"
                            loading={isFixingThis}
                            disabled={loading || (Boolean(fixingAction) && !isFixingThis)}
                            onClick={() => void handleQuickFix(item)}
                            icon={<Wrench className="w-3 h-3" />}
                          >
                            {item.fixLabel || '一键修复'}
                          </Button>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      ) : null}
    </SlideDrawer>
  );
};
