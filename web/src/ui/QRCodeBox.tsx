import React, { useEffect, useState } from 'react';
import QRCode from 'qrcode';

export interface QRCodeBoxProps {
  value: string;
  size?: number;
  className?: string;
}

export const QRCodeBox: React.FC<QRCodeBoxProps> = ({ value, size = 160, className = '' }) => {
  const [svgMarkup, setSvgMarkup] = useState<string>('');

  useEffect(() => {
    let cancelled = false;
    if (!value) {
      setSvgMarkup('');
      return;
    }
    QRCode.toString(value, {
      type: 'svg',
      margin: 1,
      width: size,
      color: { dark: '#0f172a', light: '#ffffff' },
    })
      .then((svg) => {
        if (!cancelled) setSvgMarkup(svg);
      })
      .catch(() => {
        if (!cancelled) setSvgMarkup('');
      });
    return () => {
      cancelled = true;
    };
  }, [value, size]);

  if (!svgMarkup) {
    return (
      <div
        style={{ width: size, height: size }}
        className={`rounded-xl bg-surface2 border border-subtle flex items-center justify-center text-[11px] text-muted ${className}`}
      >
        生成二维码中…
      </div>
    );
  }

  return (
    <div
      style={{ width: size, height: size }}
      className={`rounded-xl bg-white p-2 border border-subtle shadow-sm shrink-0 [&_svg]:w-full [&_svg]:h-full ${className}`}
      dangerouslySetInnerHTML={{ __html: svgMarkup }}
    />
  );
};
