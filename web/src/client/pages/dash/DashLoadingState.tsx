import React from 'react';
import { AlertTriangle, RefreshCw } from 'lucide-react';
import { Button, CardSkeleton, PageHeader, SectionCard } from '../../../ui';

export interface DashLoadingStateProps {
  loading: boolean;
  error: string | null;
  onRetry?: () => void;
}

export const DashLoadingState: React.FC<DashLoadingStateProps> = ({
  loading,
  error,
  onRetry,
}) => (
  <div className="space-y-5">
    <PageHeader
      title="系统总览"
      description={error ? '网关状态接口暂时不可达' : '正在同步网关实时状态…'}
      actions={
        onRetry && (
          <Button
            size="sm"
            variant={error ? 'primary' : 'secondary'}
            loading={loading}
            onClick={onRetry}
            icon={<RefreshCw className="w-3.5 h-3.5" />}
          >
            {error ? '立即重试' : '刷新'}
          </Button>
        )
      }
    />
    {error ? (
      <SectionCard title="连接状态异常" icon={<AlertTriangle className="w-4 h-4 text-amber-400" />}>
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
          <p className="text-secondary leading-relaxed">
            未能读取网关状态（<span className="font-mono text-rose-300">{error}</span>）。若路由器刚完成重启或切换网络，请点击右侧按钮重新连接。
          </p>
          {onRetry && (
            <Button
              size="sm"
              variant="primary"
              loading={loading}
              onClick={onRetry}
              icon={<RefreshCw className="w-3.5 h-3.5" />}
              className="shrink-0"
            >
              立即重试
            </Button>
          )}
        </div>
      </SectionCard>
    ) : (
      <CardSkeleton rows={4} />
    )}
  </div>
);
