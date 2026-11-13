import React, { useEffect, useState, useCallback, useRef } from 'react';
import { api } from '../api';
import { Badge, Button, PageHeader, SectionCard, SegmentedTabs, useToast } from '../ui';
import { Terminal, RefreshCw, Trash2, Download, Pause, Play, Check, Copy } from 'lucide-react';

interface LogsTabProps {
  initialService?: string;
}

type ServerLogService = 'singbox' | 'caddy' | 'subhub' | 'warp' | 'system';

const SERVICE_TABS: { key: ServerLogService; label: string }[] = [
  { key: 'singbox', label: 'sing-box' },
  { key: 'caddy', label: 'Caddy' },
  { key: 'subhub', label: 'SubHub 订阅' },
  { key: 'warp', label: 'WARP' },
  { key: 'system', label: '系统日志' },
];

export const LogsTab: React.FC<LogsTabProps> = ({ initialService = 'singbox' }) => {
  const { success, error } = useToast();
  const normalizedInitial: ServerLogService = SERVICE_TABS.some((s) => s.key === initialService)
    ? (initialService as ServerLogService)
    : 'singbox';

  const [service, setService] = useState<ServerLogService>(normalizedInitial);
  const [lines, setLines] = useState(100);
  const [logs, setLogs] = useState('');
  const [loading, setLoading] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(false);
  const [copied, setCopied] = useState(false);
  const terminalEndRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (SERVICE_TABS.some((s) => s.key === initialService)) {
      setService(initialService as ServerLogService);
    }
  }, [initialService]);

  const fetchLogs = useCallback(
    async (silent = false) => {
      if (!silent) setLoading(true);
      try {
        const res = await api.getServiceLogs(service, lines);
        setLogs(res.logs || '暂无日志输出');
      } catch (err: unknown) {
        if (!silent) error(err instanceof Error ? err.message : '获取日志失败');
      } finally {
        if (!silent) setLoading(false);
      }
    },
    [service, lines, error],
  );

  useEffect(() => {
    fetchLogs(false);
  }, [fetchLogs]);

  useEffect(() => {
    if (!autoRefresh) return;
    const timer = window.setInterval(() => {
      fetchLogs(true);
    }, 3000);
    return () => window.clearInterval(timer);
  }, [autoRefresh, fetchLogs]);

  const handleCopyLogs = async () => {
    try {
      await navigator.clipboard.writeText(logs);
      setCopied(true);
      success('日志内容已复制');
      window.setTimeout(() => setCopied(false), 2000);
    } catch {
      error('复制失败');
    }
  };

  const handleDownloadLogs = () => {
    const blob = new Blob([logs], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${service}-logs-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-')}.log`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    success('日志文件已下载');
  };

  return (
    <div className="space-y-5">
      <PageHeader
        title="服务端运行日志"
        description="实时检索 systemd 服务进程与访问运行输出流"
        badge={
          autoRefresh ? (
            <Badge tone="ok" dot pulse>
              每 3 秒自动同步
            </Badge>
          ) : (
            <Badge tone="neutral">静态快照</Badge>
          )
        }
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <select
              value={lines}
              onChange={(e) => setLines(Number(e.target.value))}
              className="sc-input px-2.5 py-1.5 text-xs font-mono"
            >
              <option value={50}>最新 50 行</option>
              <option value={100}>最新 100 行</option>
              <option value={200}>最新 200 行</option>
              <option value={500}>最新 500 行</option>
            </select>

            <Button
              size="sm"
              variant={autoRefresh ? 'primary' : 'secondary'}
              icon={autoRefresh ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
              onClick={() => setAutoRefresh((v) => !v)}
            >
              {autoRefresh ? '暂停刷新' : '自动刷新'}
            </Button>

            <Button
              size="sm"
              variant="secondary"
              loading={loading}
              icon={<RefreshCw className="w-3.5 h-3.5" />}
              onClick={() => fetchLogs(false)}
            >
              刷新
            </Button>
          </div>
        }
      />

      <SegmentedTabs
        value={service}
        onChange={(k) => setService(k as ServerLogService)}
        items={SERVICE_TABS}
      />

      <SectionCard
        noPadding
        title={
          <span className="inline-flex items-center gap-2 font-mono text-xs sm:text-sm">
            <Terminal className="w-4 h-4 text-accent" />
            <span>journalctl · {service}</span>
          </span>
        }
        actions={
          <div className="flex items-center gap-1.5">
            <Button
              size="xs"
              variant="ghost"
              icon={copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              onClick={handleCopyLogs}
            >
              {copied ? '已复制' : '复制'}
            </Button>
            <Button
              size="xs"
              variant="ghost"
              icon={<Download className="w-3.5 h-3.5" />}
              onClick={handleDownloadLogs}
            >
              下载
            </Button>
            <Button
              size="xs"
              variant="ghost"
              icon={<Trash2 className="w-3.5 h-3.5" />}
              onClick={() => setLogs('')}
            >
              清屏
            </Button>
          </div>
        }
      >
        <div className="bg-[#060913] text-slate-300 p-4 max-h-[600px] overflow-auto font-mono text-xs leading-relaxed select-text">
          {logs ? (
            <pre className="whitespace-pre-wrap break-all">{logs}</pre>
          ) : (
            <div className="text-slate-500 italic py-10 text-center">暂无日志内容</div>
          )}
          <div ref={terminalEndRef} />
        </div>
      </SectionCard>
    </div>
  );
};
