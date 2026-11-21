import { defineConfig, type Plugin } from 'vite';
import react from '@vitejs/plugin-react';
import { existsSync, renameSync } from 'node:fs';
import { resolve } from 'node:path';

const rootDir = import.meta.dirname;
const target = process.env.VITE_APP_TARGET === 'client' ? 'client' : 'server';
const entryHtml = target === 'client' ? 'client.html' : 'server.html';
const outDir = resolve(rootDir, target === 'client' ? '../internal/webui/static' : '../internal/serverweb/static');

// 统一将开发服务器 "/" 与构建产物的入口 HTML 映射为 "index.html"，以兼容 http.FileServer("/")
function renameEntryHtmlPlugin(): Plugin {
  return {
    name: 'singctl-rename-entry-html',
    enforce: 'post',
    configureServer(server) {
      server.middlewares.use((req, _res, next) => {
        if (req.url === '/' || req.url === '/index.html') {
          req.url = '/' + entryHtml;
        }
        next();
      });
    },
    generateBundle(_options, bundle) {
      const chunk = bundle[entryHtml];
      if (chunk && chunk.type === 'asset') {
        this.emitFile({
          type: 'asset',
          fileName: 'index.html',
          source: chunk.source,
        });
        delete bundle[entryHtml];
      }
    },
    closeBundle() {
      const src = resolve(outDir, entryHtml);
      const dst = resolve(outDir, 'index.html');
      if (existsSync(src)) {
        renameSync(src, dst);
      }
    },
  };
}

export default defineConfig({
  plugins: [react(), renameEntryHtmlPlugin()],
  base: './', // CRITICAL: 全部静态资源使用相对路径，适配服务端 Caddy 随机前缀与客户端反代
  build: {
    outDir,
    emptyOutDir: true,
    rollupOptions: {
      input: resolve(rootDir, entryHtml),
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
