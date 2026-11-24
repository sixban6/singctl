import React from 'react';
import ReactDOM from 'react-dom/client';
import ServerApp from './ServerApp';
import '../index.css';

// 彻底清理同域名下可能存在的其他 ServiceWorker (如 Sub-Store PWA)，杜绝路由与静态资源劫持
if ('serviceWorker' in navigator) {
  void navigator.serviceWorker
    .getRegistrations()
    .then((registrations) => Promise.all(registrations.map((reg) => reg.unregister())))
    .catch(() => {});
}

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <ServerApp />
  </React.StrictMode>
);
