import React from 'react';
import { Radar, Sparkles } from 'lucide-react';
import { Badge, Button, SectionCard } from '../../../../ui';
import { WifiChannelStat, WifiScanResult } from '../../../types';

interface WifiChannelChartProps {
  scan: WifiScanResult | null;
  scanning: boolean;
  busy: boolean;
  onScan: () => void;
  onApplyRecommended: (ch2g?: number, ch5g?: number) => void;
}

const ChannelBars: React.FC<{ title: string; items: WifiChannelStat[] }> = ({ title, items }) => {
  const maxScore = Math.max(25, ...items.map((x) => x.score));

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between text-xs">
        <span className="font-medium text-primary">{title}</span>
        <span className="text-[11px] text-secondary">柱越低越干净 · 已脱敏仅统计拥堵度</span>
      </div>
      <div className="grid grid-cols-6 sm:grid-cols-13 gap-1.5 items-end pt-3 pb-1 px-2 rounded-xl bg-white/[0.02] border border-white/10 min-h-[126px]">
        {items.map((c) => {
          const pct = Math.max(8, Math.min(100, Math.round((c.score / maxScore) * 100)));
          const barColor = c.recommended
            ? 'bg-emerald-400/90'
            : c.level === 'busy'
              ? 'bg-rose-400/80'
              : c.level === 'moderate'
                ? 'bg-amber-400/80'
                : 'bg-sky-400/75';
          const tip = `信道 ${c.channel}: ${c.apCount} 个邻居 AP${c.strongestDbm ? `，最强 ${c.strongestDbm} dBm` : ''}${c.dfs ? ' (DFS 雷达信道)' : ''}`;
          return (
            <div key={`${c.band}-${c.channel}`} title={tip} className="flex flex-col items-center gap-1">
              <div className="text-[10px] font-mono text-secondary h-3.5 leading-none">
                {c.apCount > 0 ? c.apCount : ''}
              </div>
              <div className="w-full h-16 flex items-end justify-center">
                <div
                  className={`w-full max-w-[20px] rounded-t-md transition-all ${barColor} ${
                    c.current ? 'ring-2 ring-white/80' : ''
                  }`}
                  style={{ height: `${pct}%` }}
                />
              </div>
              <div
                className={`text-[10px] font-mono leading-none ${
                  c.recommended
                    ? 'text-emerald-300 font-bold'
                    : c.current
                      ? 'text-white font-semibold'
                      : c.nonOverlapping
                        ? 'text-primary'
                        : 'text-secondary/70'
                }`}
              >
                {c.channel}
              </div>
              <div className="h-3 text-[9px] leading-none">
                {c.recommended ? (
                  <span className="text-emerald-300">推荐</span>
                ) : c.current ? (
                  <span className="text-sky-300">当前</span>
                ) : c.dfs ? (
                  <span className="text-amber-400/80">DFS</span>
                ) : null}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};

export const WifiChannelChart: React.FC<WifiChannelChartProps> = ({
  scan,
  scanning,
  busy,
  onScan,
  onApplyRecommended,
}) => {
  return (
    <SectionCard
      title={
        <span className="flex items-center gap-2">
          <Radar className="w-4 h-4 text-sky-400" />
          <span>周边信道干扰分析</span>
          {scan?.recommended2gChannel ? (
            <Badge tone="ok">2.4G 推荐信道 {scan.recommended2gChannel}</Badge>
          ) : null}
          {scan?.recommended5gChannel ? (
            <Badge tone="accent">5G 推荐信道 {scan.recommended5gChannel}</Badge>
          ) : null}
        </span>
      }
      subtitle="按需触发扫描（绝不在页面加载时自动扫描导致 Wi-Fi 瞬断），严格脱敏不显示邻居热点名与 MAC"
      actions={
        <div className="flex flex-wrap items-center gap-2">
          <Button
            size="xs"
            variant="secondary"
            loading={scanning}
            disabled={busy}
            icon={<Radar className="w-3.5 h-3.5" />}
            onClick={onScan}
          >
            {scan ? '重新扫描' : '扫描周边信道'}
          </Button>
          {scan && (scan.recommended2gChannel || scan.recommended5gChannel) && (
            <Button
              size="xs"
              variant="primary"
              disabled={busy || scanning}
              icon={<Sparkles className="w-3.5 h-3.5" />}
              onClick={() => onApplyRecommended(scan.recommended2gChannel, scan.recommended5gChannel)}
            >
              一键应用推荐信道
            </Button>
          )}
        </div>
      }
    >
      {!scan ? (
        <div className="rounded-xl border border-dashed border-white/15 bg-white/[0.02] p-5 text-center space-y-2">
          <div className="text-xs text-primary font-medium">尚未执行周边信道干扰扫描</div>
          <p className="text-[11px] text-secondary max-w-xl mx-auto">
            点击右上角「扫描周边信道」约 2 秒即可分析周边 2.4G（1–13）与 5G 信道拥堵度，自动推荐底噪最低的非重叠与非 DFS 信道。
          </p>
        </div>
      ) : (
        <div className="space-y-4">
          {scan.channels2g.length > 0 && <ChannelBars title="2.4 GHz 频段（仅 1 / 6 / 11 正交无重叠）" items={scan.channels2g} />}
          {scan.channels5g.length > 0 && <ChannelBars title="5 GHz 频段（优先非 DFS 高功率信道）" items={scan.channels5g} />}
          {scan.warnings && scan.warnings.length > 0 && (
            <div className="text-[11px] text-amber-300/90 space-y-0.5">
              {scan.warnings.map((w, i) => (
                <div key={i}>• {w}</div>
              ))}
            </div>
          )}
        </div>
      )}
    </SectionCard>
  );
};
