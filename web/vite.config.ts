import { defineConfig, type Plugin } from 'vite';
import react from '@vitejs/plugin-react';
import { existsSync, readdirSync, readFileSync, renameSync, unlinkSync, writeFileSync } from 'node:fs';
import { extname, join, resolve } from 'node:path';
import { gzipSync } from 'node:zlib';

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

const PRECOMPRESS_EXTS = new Set(['.html', '.js', '.css', '.svg']);
const PRECOMPRESS_MIN_BYTES = 512;

// 仅针对客户端 WebUI 产物执行零外部依赖 gzip -9 预压缩并移除原文件，实现单份存储大幅缩减 Go embed 体积
function precompressClientStaticPlugin(): Plugin {
  const walkAndCompress = (dir: string) => {
    if (!existsSync(dir)) return;
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const fullPath = join(dir, entry.name);
      if (entry.isDirectory()) {
        walkAndCompress(fullPath);
        continue;
      }
      if (!entry.isFile()) continue;
      if (!PRECOMPRESS_EXTS.has(extname(entry.name).toLowerCase())) continue;
      const raw = readFileSync(fullPath);
      if (raw.byteLength <= PRECOMPRESS_MIN_BYTES) continue;
      const compressed = gzipSync(raw, { level: 9 });
      if (compressed.byteLength >= raw.byteLength) continue;
      writeFileSync(`${fullPath}.gz`, compressed);
      unlinkSync(fullPath);
    }
  };

  return {
    name: 'singctl-precompress-client-static',
    enforce: 'post',
    closeBundle() {
      walkAndCompress(outDir);
    },
  };
}

export default defineConfig({
  plugins:
    target === 'client'
      ? [react(), renameEntryHtmlPlugin(), precompressClientStaticPlugin()]
      : [react(), renameEntryHtmlPlugin()],
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
