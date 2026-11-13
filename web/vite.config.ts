import { defineConfig, type Plugin } from 'vite';
import react from '@vitejs/plugin-react';
import { existsSync, renameSync } from 'node:fs';
import { resolve } from 'node:path';

const rootDir = import.meta.dirname;
const target = process.env.VITE_APP_TARGET === 'client' ? 'client' : 'server';
const clientOutDir = resolve(rootDir, '../internal/webui/static');

// 将 client.html 在最终产物中重命名为 index.html，以兼容 http.FileServer("/")
function renameClientEntryPlugin(): Plugin {
  return {
    name: 'singctl-rename-client-entry',
    enforce: 'post',
    generateBundle(_options, bundle) {
      if (target !== 'client') return;
      const chunk = bundle['client.html'];
      if (chunk && chunk.type === 'asset') {
        this.emitFile({
          type: 'asset',
          fileName: 'index.html',
          source: chunk.source,
        });
        delete bundle['client.html'];
      }
    },
    closeBundle() {
      if (target !== 'client') return;
      const src = resolve(clientOutDir, 'client.html');
      const dst = resolve(clientOutDir, 'index.html');
      if (existsSync(src)) {
        renameSync(src, dst);
      }
    },
  };
}

export default defineConfig({
  plugins: [react(), renameClientEntryPlugin()],
  base: './', // CRITICAL: 全部静态资源使用相对路径，适配服务端 Caddy 随机前缀与客户端反代
  build: {
    outDir: target === 'client' ? '../internal/webui/static' : '../internal/serverweb/static',
    emptyOutDir: true,
    rollupOptions: {
      input: resolve(rootDir, target === 'client' ? 'client.html' : 'index.html'),
    },
  },
  server: {
    proxy:
      target === 'client'
        ? {
            '/api': 'http://127.0.0.1:8090',
            '/clash': {
              target: 'http://127.0.0.1:8090',
              ws: true,
            },
          }
        : {
            '/api': 'http://127.0.0.1:8092',
          },
  },
});
