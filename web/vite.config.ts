import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  base: './', // CRITICAL: 保证构建生成的静态资源全部使用相对路径，适应任意 Caddy 隐蔽随机前缀
  build: {
    outDir: '../internal/serverweb/static',
    emptyOutDir: true,
  },
  server: {
    proxy: {
      '/api': 'http://127.0.0.1:8092',
    },
  },
});
