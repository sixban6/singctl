// 文件职责：承载客户端 WebUI 未登录访问时的自包含免外链认证页 HTML 模板。
package webui

const embeddedLoginHTML = `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover" />
  <meta name="robots" content="noindex,nofollow" />
  <title>SingCtl WebUI · 访问验证</title>
  <style>
    :root {
      color-scheme: light dark;
      --bg: #f4f6fb;
      --card: #ffffff;
      --border: rgba(15, 23, 42, 0.09);
      --text: #0f172a;
      --muted: #64748b;
      --accent: #2563eb;
      --accent-hover: #1d4ed8;
      --danger: #dc2626;
      --danger-bg: rgba(220, 38, 38, 0.08);
      --input-bg: #f8fafc;
      --shadow: 0 20px 50px rgba(15, 23, 42, 0.08);
    }
    @media (prefers-color-scheme: dark) {
      :root {
        --bg: #090d16;
        --card: #111827;
        --border: rgba(148, 163, 184, 0.16);
        --text: #f8fafc;
        --muted: #94a3b8;
        --accent: #3b82f6;
        --accent-hover: #2563eb;
        --danger: #f87171;
        --danger-bg: rgba(248, 113, 113, 0.12);
        --input-bg: #0b1120;
        --shadow: 0 24px 60px rgba(0, 0, 0, 0.45);
      }
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
      background: radial-gradient(circle at 50% 0%, rgba(59, 130, 246, 0.12), transparent 55%), var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "SF Pro Text", "Segoe UI", Roboto, sans-serif;
    }
    .card {
      width: 100%;
      max-width: 390px;
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 18px;
      padding: 28px 24px;
      box-shadow: var(--shadow);
    }
    .brand {
      display: flex;
      align-items: center;
      gap: 12px;
      margin-bottom: 18px;
    }
    .logo {
      width: 40px;
      height: 40px;
      border-radius: 11px;
      background: linear-gradient(135deg, #2563eb, #06b6d4);
      display: flex;
      align-items: center;
      justify-content: center;
      color: #fff;
      font-weight: 700;
      font-size: 18px;
      flex-shrink: 0;
    }
    h1 {
      margin: 0;
      font-size: 18px;
      font-weight: 700;
      letter-spacing: -0.01em;
    }
    .sub {
      margin: 2px 0 0;
      font-size: 12.5px;
      color: var(--muted);
    }
    label {
      display: block;
      font-size: 12.5px;
      font-weight: 600;
      margin-bottom: 8px;
      color: var(--muted);
    }
    .field {
      position: relative;
      margin-bottom: 14px;
    }
    input {
      width: 100%;
      height: 42px;
      padding: 0 62px 0 13px;
      border-radius: 10px;
      border: 1px solid var(--border);
      background: var(--input-bg);
      color: var(--text);
      font-size: 14px;
      outline: none;
      transition: border-color 0.15s;
    }
    input:focus { border-color: var(--accent); }
    .toggle {
      position: absolute;
      right: 8px;
      top: 50%;
      transform: translateY(-50%);
      border: none;
      background: transparent;
      color: var(--muted);
      font-size: 12px;
      padding: 4px 6px;
      cursor: pointer;
    }
    .err {
      display: none;
      margin-bottom: 14px;
      padding: 9px 12px;
      border-radius: 10px;
      background: var(--danger-bg);
      color: var(--danger);
      font-size: 12.5px;
      line-height: 1.45;
    }
    .btn {
      width: 100%;
      height: 42px;
      border: none;
      border-radius: 10px;
      background: var(--accent);
      color: #fff;
      font-size: 14px;
      font-weight: 600;
      cursor: pointer;
      transition: background 0.15s, opacity 0.15s;
    }
    .btn:hover:not(:disabled) { background: var(--accent-hover); }
    .btn:disabled { opacity: 0.65; cursor: not-allowed; }
    .hint {
      margin-top: 14px;
      font-size: 11.5px;
      color: var(--muted);
      text-align: center;
    }
  </style>
</head>
<body>
  <form class="card" id="loginForm" autocomplete="on">
    <div class="brand">
      <div class="logo">S</div>
      <div>
        <h1>SingCtl 客户端控制台</h1>
        <p class="sub">请输入 WebUI 访问口令继续</p>
      </div>
    </div>
    <div class="err" id="errBox"></div>
    <label for="pwdInput">访问口令</label>
    <div class="field">
      <input id="pwdInput" name="password" type="password" autocomplete="current-password" placeholder="输入启动时设置的口令" required autofocus />
      <button type="button" class="toggle" id="toggleBtn">显示</button>
    </div>
    <button type="submit" class="btn" id="submitBtn">登录控制台</button>
    <div class="hint">验证成功后自动保持 30 天免密登录态</div>
  </form>
  <script>
    (function () {
      var form = document.getElementById('loginForm');
      var pwd = document.getElementById('pwdInput');
      var btn = document.getElementById('submitBtn');
      var errBox = document.getElementById('errBox');
      var toggleBtn = document.getElementById('toggleBtn');

      toggleBtn.addEventListener('click', function () {
        var show = pwd.type === 'password';
        pwd.type = show ? 'text' : 'password';
        toggleBtn.textContent = show ? '隐藏' : '显示';
        pwd.focus();
      });

      function showErr(msg) {
        errBox.textContent = msg;
        errBox.style.display = 'block';
      }

      form.addEventListener('submit', function (e) {
        e.preventDefault();
        var val = pwd.value || '';
        if (!val) {
          showErr('请输入访问口令');
          return;
        }
        errBox.style.display = 'none';
        btn.disabled = true;
        btn.textContent = '正在验证...';

        var ctrl = typeof AbortController !== 'undefined' ? new AbortController() : null;
        var timer = ctrl ? setTimeout(function () { ctrl.abort(); }, 10000) : null;

        fetch('/api/auth/login', {
          method: 'POST',
          credentials: 'same-origin',
          cache: 'no-store',
          headers: {
            'Content-Type': 'application/json',
            'X-Requested-With': 'SingCtlWebUI'
          },
          body: JSON.stringify({ password: val }),
          signal: ctrl ? ctrl.signal : undefined
        })
          .then(function (resp) {
            return resp.json().catch(function () { return {}; }).then(function (data) {
              if (!resp.ok) {
                throw new Error(data.error || ('验证失败 (HTTP ' + resp.status + ')'));
              }
              return data;
            });
          })
          .then(function (data) {
            try {
              if (data && data.token) {
                localStorage.setItem('sc_token', data.token);
              }
            } catch (_) {}
            var sep = window.location.pathname.indexOf('?') >= 0 ? '&' : '?';
            window.location.replace(window.location.pathname + sep + '_t=' + Date.now() + (window.location.hash || ''));
          })
          .catch(function (err) {
            if (err && err.name === 'AbortError') {
              showErr('登录请求超时，请检查网关连接后重试');
            } else {
              showErr((err && err.message) || '验证失败，请重试');
            }
            btn.disabled = false;
            btn.textContent = '登录控制台';
          })
          .finally(function () {
            if (timer) clearTimeout(timer);
          });
      });
    })();
  </script>
</body>
</html>`
