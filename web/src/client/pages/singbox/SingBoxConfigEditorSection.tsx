import React from 'react';
import { FileCode, RefreshCw, RotateCcw, Save } from 'lucide-react';
import { Button, SectionCard } from '../../../ui';
import { SbConfigResponse } from '../../types';

export interface SingBoxConfigEditorSectionProps {
  sbCfg: SbConfigResponse | null;
  jsonText: string;
  onJsonTextChange: (next: string) => void;
  selectedBackup: string;
  onSelectedBackupChange: (next: string) => void;
  savingCfg: boolean;
  preserveManual: boolean;
  togglingPreserve: boolean;
  onTogglePreserve: (next: boolean) => void;
  onReload: () => void;
  onFormatJson: () => void;
  onSaveConfig: () => void;
  onOpenRestoreConfirm: () => void;
}

export const SingBoxConfigEditorSection: React.FC<SingBoxConfigEditorSectionProps> = ({
  sbCfg,
  jsonText,
  onJsonTextChange,
  selectedBackup,
  onSelectedBackupChange,
  savingCfg,
  preserveManual,
  togglingPreserve,
  onTogglePreserve,
  onReload,
  onFormatJson,
  onSaveConfig,
  onOpenRestoreConfirm,
}) => (
  <SectionCard
    title="sing-box config.json"
    icon={<FileCode className="w-4 h-4" />}
    subtitle={sbCfg ? `${sbCfg.path}${sbCfg.exists ? '' : '（尚未生成）'}` : '加载中…'}
    actions={
      <>
        <div
          className="inline-flex items-center gap-2 px-2.5 h-7 rounded-lg bg-surface2 border border-subtle text-xs text-secondary select-none"
          title="开启后，定时刷新订阅、更新版本或重新生成配置时自动合并保留你对 config.json 的改动；关闭则按最新订阅与默认模板全新覆盖"
        >
          <span className="cursor-pointer" onClick={() => onTogglePreserve(!preserveManual)}>
            保留手动修改
          </span>
          <button
            type="button"
            role="switch"
            aria-checked={preserveManual}
            aria-label="切换是否保留 config.json 手动修改"
            disabled={togglingPreserve}
            onClick={() => onTogglePreserve(!preserveManual)}
            className={`relative inline-flex h-5 w-9 shrink-0 cursor-pointer items-center rounded-full border transition-colors focus:outline-none disabled:opacity-50 ${
              preserveManual
                ? 'bg-[var(--accent)] border-transparent'
                : 'bg-surface1 border-strong'
            }`}
          >
            <span
              className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white shadow transition-transform ${
                preserveManual ? 'translate-x-4' : 'translate-x-0.5'
              }`}
            />
          </button>
        </div>
        <Button size="xs" onClick={onReload} icon={<RefreshCw className="w-3 h-3" />}>
          重新加载
        </Button>
        <Button size="xs" onClick={onFormatJson}>
          格式化 JSON
        </Button>
        <Button
          size="xs"
          variant="primary"
          loading={savingCfg}
          onClick={onSaveConfig}
          icon={<Save className="w-3 h-3" />}
        >
          校验并保存
        </Button>
      </>
    }
  >
    <div className="space-y-3">
      {sbCfg && sbCfg.backups?.length > 0 && (
        <div className="flex flex-wrap items-center gap-2 p-2.5 rounded-xl bg-surface2 border border-subtle">
          <span className="text-xs text-secondary">历史备份恢复：</span>
          <select
            value={selectedBackup}
            onChange={(e) => onSelectedBackupChange(e.target.value)}
            className="h-8 px-2.5 rounded-lg bg-surface1 border border-subtle text-xs text-primary font-mono focus:outline-none"
          >
            <option value="">选择备份时间点…</option>
            {sbCfg.backups.map((b) => (
              <option key={b} value={b}>
                {b.replace(/^.*\.webui-bak-/, '')}
              </option>
            ))}
          </select>
          <Button
            size="xs"
            disabled={!selectedBackup}
            onClick={onOpenRestoreConfirm}
            icon={<RotateCcw className="w-3 h-3" />}
          >
            恢复所选备份
          </Button>
        </div>
      )}

      <textarea
        value={jsonText}
        onChange={(e) => onJsonTextChange(e.target.value)}
        spellCheck={false}
        rows={20}
        className="w-full p-3.5 rounded-xl bg-[var(--console-bg)] text-slate-200 border border-subtle font-mono text-xs leading-relaxed focus:outline-none focus:border-strong"
      />
      <p className="text-xs text-muted">
        保存前自动创建 `.webui-bak-时间戳` 备份，并通过 `sing-box check` 校验语义合法性后热重载生效；右上角「保留手动修改」开启时，定时刷新订阅与更新版本会自动合并保留手改内容。
      </p>
    </div>
  </SectionCard>
);
