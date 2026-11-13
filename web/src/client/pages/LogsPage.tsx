import React, { useState, useEffect, useCallback, useRef } from 'react';
import { Terminal, RefreshCw } from 'lucide-react';
import { Badge, Button, PageHeader, SectionCard, SegmentedTabs, useToast } from '../../ui';
import { clientApi } from '../api';
import { ClientLogsResponse } from '../types';

export interface LogsPageProps {
  initialLogName?: string;
}

export const LogsPage: React.FC<LogsPageProps> = ({ initialLogName }) => {
  const { error } = useToast();
  const [name, setName] = useState<'events' | 'daemon' | 'webui'>(
    initialLogName === 'events' || initialLogName === 'webui' ? initialLogName : 'daemon',
  );
  const [tail, setTail] = useState<number>(300);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [logData, setLogData] = useState<ClientLogsResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const viewRef = useRef<HTMLPreElement>(null);

  useEffect(() => {
    if (initialLogName === 'events' || initialLogName === 'daemon' || initialLogName === 'webui') {
      setName(initialLogName);
    }
  }, [initialLogName]);

  const fetchLogs = useCallback(
    async (silent = false) => {
      if (!silent) setLoading(true);
      try {
        const res = await clientApi.getLogs(name, tail);
        setLogData(res);
      } catch (err: unknown) {
        if (!silent) error(err instanceof Error ? err.message : '加载日志失败');
      } finally {
        setLoading(false);
      }
    },
    [name, tail, error],
  );

  useEffect(() => {
    void fetchLogs(false);
  }, [fetchLogs]);

  useEffect(() => {
    if (!autoRefresh) return;
    const t = setInterval(() => {
      if (document.visibilityState === 'visible') void fetchLogs(true);
    }, 5000);
    return () => clearInterval(t);
  }, [autoRefresh, fetchLogs]);

  useEffect(() => {
    if (viewRef.current) {
      viewRef.current.scrollTop = viewRef.current.scrollHeight;
    }
  }, [logData?.content]);

  const lines = (logData?.content || '').split('\n');

  return (
    <div className="space-y-4">
      <PageHeader
        title="运行日志"
        description={logData?.path ? `文件位置：${logData.path}` : '查看守护进程、容灾关键事件与 WebUI 运行日志'}
        badge={autoRefresh ? <Badge tone="ok" dot pulse>5s 自动刷新</Badge> : undefined}
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <select
              value={tail}
              onChange={(e) => setTail(Number(e.target.value))}
              className="h-8 px-2.5 rounded-lg bg-surface2 border border-subtle text-xs text-primary focus:outline-none"
            >
              <option value={100}>最近 100 行</option>
              <option value={300}>最近 300 行</option>
              <option value={1000}>最近 1000 行</option>
            </select>
            <Button size="sm" onClick={() => setAutoRefresh((v) => !v)}>
              {autoRefresh ? '暂停自动刷新' : '开启自动刷新'}
            </Button>
            <Button size="sm" variant="primary" loading={loading} onClick={() => fetchLogs(false)} icon={<RefreshCw className="w-3.5 h-3.5" />}>
              刷新
            </Button>
          </div>
        }
      />

      <SegmentedTabs
        value={name}
        onChange={(k) => setName(k as 'daemon' | 'events' | 'webui')}
        items={[
          { key: 'daemon', label: '守护进程完整日志' },
          { key: 'events', label: '看门狗与容灾关键事件' },
          { key: 'webui', label: 'WebUI 运行日志' },
        ]}
      />

      <SectionCard
        noPadding
        title={
          <span className="inline-flex items-center gap-2">
            <Terminal className="w-4 h-4" />
            终端日志输出
          </span>
        }
      >
        <pre
          ref={viewRef}
          className="h-[calc(100vh-17rem)] min-h-[380px] overflow-y-auto p-4 bg-[var(--console-bg)] font-mono text-[11.5px] leading-relaxed select-text"
        >
          {lines.map((line, i) => {
            const cls = line.includes('[ERROR]')
              ? 'text-rose-400'
              : line.includes('[WARN]')
              ? 'text-amber-300'
              : line.includes('[SUCCESS]') || line.includes('GROUP_FAILBACK')
              ? 'text-emerald-400'
              : line.includes('GROUP_FAILOVER') || line.includes('[INFO]')
              ? 'text-sky-300'
              : 'text-slate-300';
            return (
              <div key={i} className={`whitespace-pre-wrap break-all ${cls}`}>
                {line || ' '}
              </div>
            );
          })}
        </pre>
      </SectionCard>
    </div>
  );
};
