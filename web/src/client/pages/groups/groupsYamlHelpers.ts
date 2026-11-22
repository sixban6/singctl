export function parseYAMLErrorLine(errMsg: string): number | null {
  if (!errMsg) return null;
  const m = /\bline\s+(\d+)\b/i.exec(errMsg);
  if (!m) return null;
  const n = Number(m[1]);
  return Number.isFinite(n) && n > 0 ? n : null;
}

export function computeNextGroupName(yamlText: string): string {
  if (!yamlText.includes('"#New"') && !yamlText.includes(" '#New'") && !/name:\s*#New\b/.test(yamlText)) {
    return '#New';
  }
  for (let i = 2; i < 100; i++) {
    const cand = `#New${i}`;
    if (!yamlText.includes(cand)) return cand;
  }
  return `#New${Date.now() % 1000}`;
}

export function appendGroupSnippetToYAML(text: string): { next: string; groupName: string; focusLine: number } {
  const groupName = computeNextGroupName(text);
  const snippetLines = [
    `  - name: "${groupName}"`,
    `    type: urltest`,
    `    match: ["@hk"]`,
    `    exclude: ["@high_rate"]`,
  ];
  const snippet = snippetLines.join('\n');

  const lines = text.split('\n');
  // 场景 1: 空列表占位 `groups: []` —— 原地展开并保留其后的注释示例
  const emptyListIdx = lines.findIndex((ln) => /^groups:\s*\[\]\s*(#.*)?$/.test(ln));
  if (emptyListIdx >= 0) {
    lines.splice(emptyListIdx, 1, 'groups:', ...snippetLines);
    return {
      next: lines.join('\n'),
      groupName,
      focusLine: emptyListIdx + 2,
    };
  }

  // 场景 2: 已有 `groups:` —— 插入到最后一个有效条目之后（不破坏底部注释示例）
  const groupsHeaderIdx = lines.findIndex((ln) => /^groups:\s*(#.*)?$/.test(ln));
  if (groupsHeaderIdx >= 0) {
    let insertAfter = groupsHeaderIdx;
    for (let i = groupsHeaderIdx + 1; i < lines.length; i++) {
      const ln = lines[i];
      if (/^[a-zA-Z_][a-zA-Z0-9_-]*\s*:/.test(ln)) {
        break;
      }
      if (/^\s+\S/.test(ln)) {
        insertAfter = i;
      }
    }
    const toInsert = insertAfter > groupsHeaderIdx ? ['', ...snippetLines] : snippetLines;
    lines.splice(insertAfter + 1, 0, ...toInsert);
    return {
      next: lines.join('\n'),
      groupName,
      focusLine: insertAfter + 1 + (insertAfter > groupsHeaderIdx ? 2 : 1),
    };
  }

  // 场景 3: 文本尚无 `groups:` —— 末尾补充完整块
  const trimmed = text.replace(/\s+$/, '');
  const prefix = trimmed ? `${trimmed}\n\ngroups:\n` : 'version: 1\nmode: merge\n\ngroups:\n';
  const focusLine = prefix.split('\n').length;
  return {
    next: `${prefix}${snippet}\n`,
    groupName,
    focusLine,
  };
}

export function hasCustomDraftContent(yamlText: string): boolean {
  const activeLines = yamlText
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l !== '' && !l.startsWith('#'));
  if (activeLines.length <= 3 && activeLines.some((l) => /^groups:\s*\[\]/.test(l))) {
    return false;
  }
  return activeLines.length > 0;
}
