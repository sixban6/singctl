import React from 'react';
import { AlertTriangle, Home, RefreshCw } from 'lucide-react';
import { Button } from './Button';

export interface ErrorBoundaryProps {
  children: React.ReactNode;
  resetKey?: string | number;
  fallbackTitle?: string;
  onNavigateHome?: () => void;
}

interface ErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends React.Component<ErrorBoundaryProps, ErrorBoundaryState> {
  constructor(props: ErrorBoundaryProps) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, info: React.ErrorInfo): void {
    console.error('[UI ErrorBoundary]', error, info);
  }

  componentDidUpdate(prevProps: Readonly<ErrorBoundaryProps>): void {
    if (this.state.hasError && prevProps.resetKey !== this.props.resetKey) {
      this.setState({ hasError: false, error: null });
    }
  }

  private handleReset = () => {
    this.setState({ hasError: false, error: null });
  };

  render(): React.ReactNode {
    if (!this.state.hasError) {
      return this.props.children;
    }
    const msg = this.state.error?.message || '页面组件在渲染时遇到未知异常';
    return (
      <div className="rounded-2xl border border-rose-500/35 bg-slate-900/90 p-5 sm:p-6 shadow-xl space-y-4">
        <div className="flex items-start gap-3">
          <div className="w-10 h-10 rounded-xl bg-rose-500/15 border border-rose-500/30 flex items-center justify-center shrink-0">
            <AlertTriangle className="w-5 h-5 text-rose-400" />
          </div>
          <div className="min-w-0 space-y-1">
            <h3 className="text-sm sm:text-base font-semibold text-white">
              {this.props.fallbackTitle || '当前子页面渲染异常（侧边栏与后台服务未受影响）'}
            </h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              系统已隔离本次组件错误，防止整页黑屏。你可以重试加载当前模块，或通过左侧导航栏切换其他页面。
            </p>
          </div>
        </div>

        <pre className="rounded-xl border border-slate-800 bg-slate-950/90 p-3 text-xs font-mono text-rose-300 overflow-x-auto whitespace-pre-wrap break-all">
          {msg}
        </pre>

        <div className="flex flex-wrap items-center gap-2">
          <Button
            size="sm"
            variant="primary"
            icon={<RefreshCw className="w-3.5 h-3.5" />}
            onClick={this.handleReset}
          >
            重试加载当前模块
          </Button>
          {this.props.onNavigateHome && (
            <Button
              size="sm"
              variant="secondary"
              icon={<Home className="w-3.5 h-3.5" />}
              onClick={() => {
                this.handleReset();
                this.props.onNavigateHome?.();
              }}
            >
              返回概览
            </Button>
          )}
        </div>
      </div>
    );
  }
}
