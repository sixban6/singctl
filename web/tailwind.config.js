/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./client.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        brand: {
          50: '#f0fdf4',
          400: '#4ade80',
          500: '#22c55e',
          600: '#16a34a',
        },
        slate: {
          850: '#151e2e',
          900: '#0f172a',
          950: '#080d1a',
        },
        canvas: 'var(--bg-canvas)',
        surface1: 'var(--bg-surface-1)',
        surface2: 'var(--bg-surface-2)',
        surfaceHover: 'var(--bg-surface-hover)',
      },
      textColor: {
        primary: 'var(--text-primary)',
        secondary: 'var(--text-secondary)',
        muted: 'var(--text-muted)',
      },
      borderColor: {
        subtle: 'var(--border-subtle)',
        strong: 'var(--border-strong)',
      },
    },
  },
  plugins: [],
}
