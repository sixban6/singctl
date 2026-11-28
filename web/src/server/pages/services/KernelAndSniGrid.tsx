import React, { useEffect, useState } from 'react';
import { ServerSocketTuneStatus, ServerStatusResponse } from '../../types';
import { CheckCircle2, Gauge, RefreshCw, ShieldCheck, Zap } from 'lucide-react';
import { formatSocketBytes } from '../../../ui';

interface KernelAndSniGridProps {
  status: ServerStatusResponse | null;
  enablingBBR: boolean;
  onEnableBBR: () => void;
  applyingSockTune: boolean;
  onApplySocketTune: (defaultPreset: 'auto' | '4m' | '8m') => void;
  editingSNI: boolean;
  setEditingSNI: (v: boolean) => void;
  sniInput: string;
  setSniInput: (v: string) => void;
  updatingSNI: boolean;
  onSaveSNI: () => void;
}

const presetByteMap: Record<'4m' | '8m', number> = {
  '4m': 4 * 1024 * 1024,
  '8m': 8 * 1024 * 1024,
};

function inferPresetFromStatus(st?: ServerSocketTuneStatus): '4m' | '8m' {
  if (!st) return '8m';
  if (st.rmemDefault === presetByteMap['4m']) return '4m';
  if (st.rmemDefault >= presetByteMap['8m']) return '8m';
  return st.recommendedRmemDefault <= presetByteMap['4m'] ? '4m' : '8m';
}

export const KernelAndSniGrid: React.FC<KernelAndSniGridProps> = ({
  status,
  enablingBBR,
  onEnableBBR,
  applyingSockTune,
  onApplySocketTune,
  editingSNI,
  setEditingSNI,
  sniInput,
  setSniInput,
  updatingSNI,
  onSaveSNI,
}) => {
  const st = status?.system?.socketTune;
  const [selectedPreset, setSelectedPreset] = useState<'4m' | '8m'>(() => inferPresetFromStatus(st));

  useEffect(() => {
    setSelectedPreset(inferPresetFromStatus(st));
  }, [st?.rmemDefault, st?.recommendedRmemDefault]);

  const targetDefaultBytes = presetByteMap[selectedPreset];
  const presetChanged = Boolean(st?.supported && st.rmemDefault !== targetDefaultBytes);
  const allReady = Boolean(st?.optimal && !presetChanged);

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
      {/* Kernel BBR & QUIC/UDP Socket Buffer Card */}
      {st?.supported ? (
        <div className="p-5 rounded-2xl glass-card flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between gap-2 pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2.5">
                <div className="p-2 rounded-xl bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                  <Gauge className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="font-semibold text-white text-base">内核网络加速 · BBR & QUIC 缓冲</h3>
                  <p className="text-xs text-slate-400">
                    TCP BBR 拥塞控制与 Caddy L4 UDP 默认缓冲调优 ({st.totalMemMb || '-'} MB RAM)
                  </p>
                </div>
              </div>
              <span
                className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-mono font-medium border shrink-0 ${
                  st.optimal
                    ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                    : st.defaultBottleneck
                      ? 'bg-rose-500/10 text-rose-400 border-rose-500/25'
                      : 'bg-amber-500/10 text-amber-400 border-amber-500/20'
                }`}
              >
                <span
                  className={`w-1.5 h-1.5 rounded-full ${
                    st.optimal ? 'bg-emerald-400' : st.defaultBottleneck ? 'bg-rose-400' : 'bg-amber-400'
                  }`}
                ></span>
                <span>{st.optimal ? '全项已优化' : st.defaultBottleneck ? 'UDP 缓冲瓶颈' : '可优化'}</span>
              </span>
            </div>

            <div className="mt-3 grid grid-cols-2 gap-2.5 text-xs font-mono">
              <div className="rounded-xl bg-slate-950/60 border border-slate-800/80 px-3 py-2">
                <div className="text-[11px] text-slate-500">TCP 拥塞 / 队列</div>
                <div className={`mt-0.5 font-semibold ${st.bbrEnabled && st.qdiscOptimal ? 'text-emerald-400' : 'text-amber-400'}`}>
                  {st.tcpCongestion || '-'} + {st.defaultQdisc || '-'}
                </div>
              </div>

              <div className="rounded-xl bg-slate-950/60 border border-slate-800/80 px-3 py-2">
                <div className="text-[11px] text-slate-500">缓冲上限 (max)</div>
                <div className={`mt-0.5 font-semibold ${st.maxBufferOptimal ? 'text-emerald-400' : 'text-amber-400'}`}>
                  {formatSocketBytes(st.rmemMax)}
                  {!st.maxBufferOptimal && (
                    <span className="text-slate-400 font-normal"> → {formatSocketBytes(st.recommendedRmemMax)}</span>
                  )}
                </div>
              </div>

              <div className="rounded-xl bg-slate-950/60 border border-slate-800/80 px-3 py-2">
                <div className="text-[11px] text-slate-500">默认缓冲 (Caddy L4 UDP)</div>
                <div className={`mt-0.5 font-semibold ${st.defaultBottleneck ? 'text-rose-400' : 'text-emerald-400'}`}>
                  {formatSocketBytes(st.rmemDefault)}
                  {st.defaultBottleneck && (
                    <span className="text-slate-400 font-normal"> → {formatSocketBytes(targetDefaultBytes)}</span>
                  )}
                </div>
              </div>

              <div className="rounded-xl bg-slate-950/60 border border-slate-800/80 px-3 py-2">
                <div className="text-[11px] text-slate-500">UDP RcvbufErrors</div>
                <div className={`mt-0.5 font-semibold ${st.udpRcvbufErrors > 0 ? 'text-amber-400' : 'text-emerald-400'}`}>
                  {st.udpRcvbufErrors.toLocaleString()}
                </div>
              </div>
            </div>

            {st.defaultBottleneck && (
              <p className="mt-2.5 text-[11px] text-rose-300/90 leading-relaxed bg-rose-500/10 border border-rose-500/20 rounded-xl px-3 py-2">
                Caddy 以非特权用户反代 UDP 443 时会继承内核默认缓冲（当前仅 {formatSocketBytes(st.rmemDefault)}），突发大流量极易溢出丢包；提升至 4–8 MB 并平滑重载 Caddy 可显著降低丢包并提速。
              </p>
            )}

            <div className="mt-3 flex items-center justify-between gap-2 flex-wrap">
              <span className="text-[11px] text-slate-400">Caddy UDP 默认缓冲档位:</span>
              <div className="flex items-center gap-1.5">
                {(['4m', '8m'] as const).map((preset) => (
                  <button
                    key={preset}
                    type="button"
                    disabled={applyingSockTune}
                    onClick={() => setSelectedPreset(preset)}
                    className={`px-2.5 py-1 rounded-lg text-[11px] font-mono font-medium border transition-colors ${
                      selectedPreset === preset
                        ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                        : 'bg-slate-900/70 text-slate-400 border-slate-800 hover:text-white hover:border-slate-700'
                    }`}
                  >
                    {preset === '4m' ? '4 MB (省内存)' : '8 MB (高吞吐推荐)'}
                  </button>
                ))}
              </div>
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center justify-between gap-3">
            <span className="text-[11px] text-slate-500">
              {allReady ? st.summary : '应用后将在 1 秒内平滑重载 Caddy 使新 UDP 默认缓冲生效'}
            </span>
            <button
              type="button"
              onClick={() => onApplySocketTune(selectedPreset)}
              disabled={applyingSockTune || allReady}
              className={`shrink-0 flex items-center gap-1.5 px-3.5 py-2 rounded-xl text-xs font-semibold transition-all ${
                allReady
                  ? 'bg-slate-800/60 text-emerald-400 border border-emerald-500/20 cursor-default'
                  : 'bg-emerald-500 hover:bg-emerald-600 text-slate-950 shadow-md shadow-emerald-500/20'
              }`}
            >
              {applyingSockTune ? (
                <>
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  <span>正在优化并重载...</span>
                </>
              ) : allReady ? (
                <>
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  <span>全项已优化</span>
                </>
              ) : st.optimal && presetChanged ? (
                <>
                  <Zap className="w-3.5 h-3.5" />
                  <span>切换至 {selectedPreset.toUpperCase()} 并重载 Caddy</span>
                </>
              ) : (
                <>
                  <Zap className="w-3.5 h-3.5" />
                  <span>一键优化并重载 Caddy</span>
                </>
              )}
            </button>
          </div>
        </div>
      ) : (
        <div className="p-5 rounded-2xl glass-card flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2.5">
                <div className="p-2 rounded-xl bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                  <ShieldCheck className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="font-semibold text-white text-base">Google BBR 拥塞控制</h3>
                  <p className="text-xs text-slate-400">内核层 TCP 加速与抗丢包算法</p>
                </div>
              </div>
              <span
                className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-mono font-medium border ${
                  status?.system?.bbr
                    ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                    : 'bg-amber-500/10 text-amber-400 border-amber-500/20'
                }`}
              >
                <span className={`w-1.5 h-1.5 rounded-full ${status?.system?.bbr ? 'bg-emerald-400' : 'bg-amber-400'}`}></span>
                <span>{status?.system?.bbr ? 'BBR 已开启' : '未开启'}</span>
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-3 leading-relaxed">
              {status?.system?.bbr
                ? '内核已启用 Google BBR 拥塞控制算法，大幅优化跨国高延迟与弱网长距离丢包，跑满服务器峰值带宽。'
                : '检测到内核尚未启用 BBR 算法，建议一键开启以大幅提升海外连接速度与抗丢包能力。'}
            </p>
          </div>
          <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center justify-between">
            <span className="text-xs text-slate-500 font-mono">
              状态: {status?.system?.bbr ? '运行中 (fq + bbr)' : '默认算法 (cubic)'}
            </span>
            <button
              onClick={onEnableBBR}
              disabled={enablingBBR || status?.system?.bbr}
              className={`flex items-center gap-1.5 px-3.5 py-2 rounded-xl text-xs font-semibold transition-all ${
                status?.system?.bbr
                  ? 'bg-slate-800/60 text-emerald-400 border border-emerald-500/20 cursor-default'
                  : 'bg-emerald-500 hover:bg-emerald-600 text-slate-950 shadow-md shadow-emerald-500/20'
              }`}
            >
              {enablingBBR ? (
                <>
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  <span>正在配置 BBR...</span>
                </>
              ) : status?.system?.bbr ? (
                <>
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  <span>BBR 加速已就绪</span>
                </>
              ) : (
                <>
                  <Zap className="w-3.5 h-3.5" />
                  <span>一键开启 BBR</span>
                </>
              )}
            </button>
          </div>
        </div>
      )}

      {/* Reality SNI Card */}
      <div className="p-5 rounded-2xl glass-card flex flex-col justify-between">
        <div>
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <div className="flex items-center gap-2.5">
              <div className="p-2 rounded-xl bg-purple-500/10 text-purple-400 border border-purple-500/20">
                <Zap className="w-5 h-5" />
              </div>
              <div>
                <h3 className="font-semibold text-white text-base">Reality 目标伪装与探测防御</h3>
                <p className="text-xs text-slate-400">TLS 握手伪装域名 (SNI)</p>
              </div>
            </div>
            <span className="px-2.5 py-1 rounded-full text-xs font-mono font-medium bg-purple-500/10 text-purple-400 border border-purple-500/20">
              TLS 1.3 拟态
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-3 leading-relaxed">
            伪装 TLS 握手域名，使 TLS 握手特征与官方分发站点的正常访问保持高度一致。
          </p>
          {editingSNI ? (
            <div className="mt-3 space-y-2">
              <input
                type="text"
                value={sniInput}
                onChange={(e) => setSniInput(e.target.value)}
                placeholder="例如: swdist.apple.com"
                className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs font-mono text-emerald-400 focus:outline-none focus:border-purple-500"
              />
              <div className="flex flex-wrap gap-1.5">
                {['swdist.apple.com', 'gateway.icloud.com', 'itunes.apple.com'].map((s) => (
                  <button
                    key={s}
                    type="button"
                    onClick={() => setSniInput(s)}
                    className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-300 hover:text-white hover:bg-slate-700"
                  >
                    {s}
                  </button>
                ))}
              </div>
            </div>
          ) : (
            <div className="mt-3 text-xs font-mono text-slate-300 bg-slate-950/60 px-3 py-2 rounded-xl border border-slate-800 flex items-center justify-between">
              <div>
                <span className="text-slate-500">当前伪装域名: </span>
                <span className="text-emerald-400 font-semibold">{status?.config?.sni || 'swdist.apple.com'}</span>
              </div>
            </div>
          )}
        </div>
        <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center justify-between">
          <span className="text-[11px] text-slate-500">修改后将自动重载网关、节点核心并同步更新订阅</span>
          {editingSNI ? (
            <div className="flex items-center gap-2">
              <button
                onClick={() => setEditingSNI(false)}
                className="px-3 py-1.5 rounded-xl text-xs text-slate-400 hover:text-white hover:bg-slate-800"
              >
                取消
              </button>
              <button
                onClick={onSaveSNI}
                disabled={updatingSNI || !sniInput.trim()}
                className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-xl bg-purple-500 hover:bg-purple-600 text-white font-semibold text-xs shadow-md shadow-purple-500/20 disabled:opacity-50"
              >
                {updatingSNI && <RefreshCw className="w-3 h-3 animate-spin" />}
                <span>保存并应用</span>
              </button>
            </div>
          ) : (
            <button
              onClick={() => {
                setSniInput(status?.config?.sni || 'swdist.apple.com');
                setEditingSNI(true);
              }}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 font-medium text-xs transition-colors"
            >
              <span>修改伪装域名</span>
            </button>
          )}
        </div>
      </div>
    </div>
  );
};
