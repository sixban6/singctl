import React from 'react';
import { DoctorReport } from '../../types';
import { AlertTriangle, CheckCircle2, Stethoscope, X, XCircle } from 'lucide-react';

export const DoctorReportModal: React.FC<{
  doctorReport: DoctorReport;
  onClose: () => void;
}> = ({ doctorReport, onClose }) => {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-fade-in">
      <div className="w-full max-w-2xl bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl overflow-hidden max-h-[90vh] flex flex-col">
        {/* Modal Header */}
        <div className="p-5 border-b border-slate-800 flex items-center justify-between bg-slate-950/60">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-xl bg-purple-500/10 text-purple-400 border border-purple-500/20">
              <Stethoscope className="w-5 h-5" />
            </div>
            <div>
              <h3 className="font-bold text-white text-base flex items-center gap-2">
                <span>全链路健康体检报告</span>
                <span
                  className={`text-xs px-2.5 py-0.5 rounded-full font-mono font-semibold border ${
                    doctorReport.score >= 90
                      ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30'
                      : doctorReport.score >= 60
                      ? 'bg-amber-500/20 text-amber-300 border-amber-500/30'
                      : 'bg-rose-500/20 text-rose-300 border-rose-500/30'
                  }`}
                >
                  综合评分: {doctorReport.score} / 100
                </span>
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">体检时间: {doctorReport.checkedAt}</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-5 overflow-y-auto space-y-4">
          <div
            className={`p-3.5 rounded-xl border text-xs leading-relaxed ${
              doctorReport.score >= 90
                ? 'bg-emerald-950/30 border-emerald-500/30 text-emerald-200'
                : doctorReport.score >= 60
                ? 'bg-amber-950/30 border-amber-500/30 text-amber-200'
                : 'bg-rose-950/30 border-rose-500/30 text-rose-200'
            }`}
          >
            {doctorReport.summary}
          </div>

          <div className="space-y-2">
            {doctorReport.items.map((item, idx) => (
              <div
                key={idx}
                className="p-3 rounded-xl bg-slate-950/60 border border-slate-800/80 flex items-start justify-between gap-3 text-xs"
              >
                <div className="flex-1">
                  <div className="flex items-center gap-2 font-medium text-slate-200">
                    {item.status === 'ok' ? (
                      <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                    ) : item.status === 'warn' ? (
                      <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
                    ) : (
                      <XCircle className="w-4 h-4 text-rose-400 shrink-0" />
                    )}
                    <span className="font-semibold text-white">{item.name}</span>
                  </div>
                  <p className="text-slate-300 font-mono mt-1 text-[11px] pl-6">{item.summary}</p>
                  {item.detail && <p className="text-slate-500 text-[11px] mt-0.5 pl-6">{item.detail}</p>}
                </div>

                <span
                  className={`text-[10px] uppercase font-mono px-2 py-0.5 rounded-md border shrink-0 ${
                    item.status === 'ok'
                      ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                      : item.status === 'warn'
                      ? 'bg-amber-500/10 text-amber-400 border-amber-500/20'
                      : 'bg-rose-500/10 text-rose-400 border-rose-500/20'
                  }`}
                >
                  {item.status === 'ok' ? '正常' : item.status === 'warn' ? '建议优化' : '异常'}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Modal Footer */}
        <div className="p-4 border-t border-slate-800 bg-slate-950/40 flex items-center justify-between">
          <span className="text-xs text-slate-500">
            支持在终端执行: <code className="text-purple-300 font-mono">singctl sr doctor</code>
          </span>
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-white transition-colors"
          >
            关闭体检报告
          </button>
        </div>
      </div>
    </div>
  );
};
