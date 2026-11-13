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
        canvas: 'var(--bg-canvas)',
        surface1: 'var(--bg-surface-1)',
        surface2: 'var(--bg-surface-2)',
        surfaceHover: 'var(--bg-surface-hover)',
        accent: 'var(--accent)',
        accentStrong: 'var(--accent-strong)',
        brand: {
          50: '#f0f9ff',
          400: '#38bdf8',
          500: '#0ea5e9',
          600: '#0284c7',
        },
        slate: {
          850: '#151e2e',
          900: '#0f172a',
          950: '#090c12',
        },
      },
      borderColor: {
        subtle: 'var(--border-subtle)',
        strong: 'var(--border-strong)',
      },
      textColor: {
        primary: 'var(--text-primary)',
        secondary: 'var(--text-secondary)',
        muted: 'var(--text-muted)',
      },
    },
  },
  plugins: [],
};
