import React, { useEffect, useState, useRef } from 'react';
import { api } from '../api';
import { useToast } from './Toast';
import { Terminal, RefreshCw, Trash2, Download, Pause, Play, Check } from 'lucide-react';

interface LogsTabProps {
  initialService?: string;
}

export const LogsTab: React.FC<LogsTabProps> = ({ initialService = 'singbox' }) => {
  const { success, error } = useToast();
  const [service, setService] = useState(initialService);
  const [lines, setLines] = useState(100);
  const [logs, setLogs] = useState('');
  const [loading, setLoading] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(false);
  const [copied, setCopied] = useState(false);
  const terminalEndRef = useRef<HTMLDivElement | null>(null);

  const fetchLogs = async (silent = false) => {
    if (!silent) setLoading(true);
    try {
      const res = await api.getServiceLogs(service, lines);
      setLogs(res.logs || '暂无日志输出');
    } catch (err: any) {
      if (!silent) error(err.message || '获取日志失败');
    } finally {
      if (!silent) setLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();
  }, [service, lines]);

  useEffect(() => {
    let timer: any;
    if (autoRefresh) {
      timer = setInterval(() => {
        fetchLogs(true);
      }, 3000);
    }
    return () => clearInterval(timer);
  }, [autoRefresh, service, lines]);

  const handleCopyLogs = () => {
    navigator.clipboard.writeText(logs);
    setCopied(true);
    success('日志内容已复制');
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownloadLogs = () => {
    const blob = new Blob([logs], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${service}-logs-${new Date().toISOString().slice(0, 19)}.log`;
    a.click();
    URL.revokeObjectURL(url);
    success('日志文件已下载');
  };

  const services = [
    { key: 'singbox', label: 'sing-box' },
    { key: 'caddy', label: 'Caddy' },
    { key: 'substore', label: 'Sub-Store' },
    { key: 'warp', label: 'WARP' },
    { key: 'system', label: '系统日志' },
  ];

  return (
    <div className="space-y-4">
      {/* Controls Bar */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 p-4 rounded-2xl glass-card">
        {/* Service Selector Tabs */}
        <div className="flex items-center gap-1.5 overflow-x-auto w-full sm:w-auto">
          {services.map((s) => (
            <button
              key={s.key}
              onClick={() => setService(s.key)}
              className={`px-3 py-1.5 rounded-xl text-xs font-medium font-mono whitespace-nowrap transition-colors ${
                service === s.key
                  ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                  : 'bg-slate-900/60 text-slate-400 hover:text-white border border-slate-800'
              }`}
            >
              {s.label}
            </button>
          ))}
        </div>

        {/* Action Controls */}
        <div className="flex items-center gap-2 w-full sm:w-auto justify-end text-xs">
          {/* Lines Selector */}
          <select
            value={lines}
            onChange={(e) => setLines(Number(e.target.value))}
            className="bg-slate-900 border border-slate-800 rounded-xl px-2.5 py-1.5 text-slate-300 font-mono text-xs focus:outline-none focus:border-emerald-500"
          >
            <option value={50}>最新 50 行</option>
            <option value={100}>最新 100 行</option>
            <option value={200}>最新 200 行</option>
            <option value={500}>最新 500 行</option>
          </select>

          {/* Auto Refresh Toggle */}
          <button
            onClick={() => setAutoRefresh(!autoRefresh)}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-xl border transition-colors ${
              autoRefresh
                ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
                : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-white'
            }`}
          >
            {autoRefresh ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
            <span>{autoRefresh ? '暂停刷新' : '自动刷新'}</span>
          </button>

          {/* Manual Refresh */}
          <button
            onClick={() => fetchLogs()}
            disabled={loading}
            className="p-1.5 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 hover:text-white transition-colors disabled:opacity-50"
            title="手动刷新"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin text-emerald-400' : ''}`} />
          </button>

          {/* Copy */}
          <button
            onClick={handleCopyLogs}
            className="p-1.5 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 hover:text-white transition-colors"
            title="复制全部日志"
          >
            {copied ? <Check className="w-4 h-4 text-emerald-400" /> : <Terminal className="w-4 h-4" />}
          </button>

          {/* Download */}
          <button
            onClick={handleDownloadLogs}
            className="p-1.5 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 hover:text-white transition-colors"
            title="下载日志文件"
          >
            <Download className="w-4 h-4" />
          </button>

          {/* Clear View */}
          <button
            onClick={() => setLogs('')}
            className="p-1.5 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 hover:text-white transition-colors"
            title="清空当前视图"
          >
            <Trash2 className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Terminal Display */}
      <div className="rounded-2xl border border-slate-800/90 bg-[#060913] shadow-2xl overflow-hidden">
        {/* Terminal Header */}
        <div className="flex items-center justify-between px-4 py-2.5 bg-slate-950 border-b border-slate-800/70 text-xs font-mono text-slate-400">
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-rose-500/80 inline-block"></span>
            <span className="w-2.5 h-2.5 rounded-full bg-amber-500/80 inline-block"></span>
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-500/80 inline-block"></span>
            <span className="ml-2 text-slate-300 font-medium">journalctl -u {service}</span>
          </div>
          <span className="text-[11px] text-slate-500">
            {autoRefresh ? '实时监听中 (每 3s)' : '静态快照'}
          </span>
        </div>

        {/* Console Body */}
        <div className="p-4 overflow-x-auto max-h-[600px] overflow-y-auto font-mono text-xs text-slate-300 leading-relaxed space-y-1">
          {logs ? (
            <pre className="whitespace-pre-wrap break-all">{logs}</pre>
          ) : (
            <div className="text-slate-600 italic py-8 text-center">暂无日志内容</div>
          )}
          <div ref={terminalEndRef}></div>
        </div>
      </div>
    </div>
  );
};
