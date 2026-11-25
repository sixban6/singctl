/**
 * 将纯文本复制到剪贴板。
 * 优先使用现代 Clipboard API（HTTPS / localhost 安全上下文）；
 * 在路由器或服务器局域网 HTTP 非安全上下文（window.isSecureContext === false）下，
 * 自动降级为隐藏 textarea + document.execCommand('copy')，避免提示复制失败。
 */
export async function copyToClipboard(text: string): Promise<void> {
  if (
    typeof navigator !== 'undefined' &&
    typeof window !== 'undefined' &&
    window.isSecureContext &&
    navigator.clipboard?.writeText
  ) {
    try {
      await navigator.clipboard.writeText(text);
      return;
    } catch {
      // Clipboard API 被拒绝时继续尝试 execCommand 兜底
    }
  }

  if (typeof document === 'undefined' || !document.body) {
    throw new Error('clipboard unsupported');
  }

  const activeEl = document.activeElement instanceof HTMLElement ? document.activeElement : null;
  const ta = document.createElement('textarea');
  ta.value = text;
  ta.setAttribute('readonly', '');
  ta.style.position = 'fixed';
  ta.style.top = '0';
  ta.style.left = '0';
  ta.style.width = '1px';
  ta.style.height = '1px';
  ta.style.opacity = '0';
  ta.style.pointerEvents = 'none';
  document.body.appendChild(ta);

  try {
    ta.focus({ preventScroll: true });
    ta.select();
    ta.setSelectionRange(0, text.length);
    const ok = document.execCommand('copy');
    if (!ok) {
      throw new Error('copy unsupported');
    }
  } finally {
    ta.remove();
    activeEl?.focus({ preventScroll: true });
  }
}
