import React from 'react';

const RELOAD_PREFIX = 'singctl:chunk_reload:';

function readReloadFlag(key: string): string | null {
  try {
    return window.sessionStorage.getItem(RELOAD_PREFIX + key);
  } catch {
    return null;
  }
}

function writeReloadFlag(key: string, value: string): void {
  try {
    window.sessionStorage.setItem(RELOAD_PREFIX + key, value);
  } catch {
    // Ignore storage quota / private mode restrictions.
  }
}

function clearReloadFlag(key: string): void {
  try {
    window.sessionStorage.removeItem(RELOAD_PREFIX + key);
  } catch {
    // Ignore private mode restrictions.
  }
}

// lazyWithReload wraps React.lazy so a stale browser tab encountering replaced
// hashed asset filenames after a binary upgrade automatically reloads once cleanly.
export function lazyWithReload<T extends React.ComponentType<any>>(
  factory: () => Promise<{ default: T }>,
  chunkKey: string,
): React.LazyExoticComponent<T> {
  return React.lazy(async () => {
    try {
      const mod = await factory();
      clearReloadFlag(chunkKey);
      return mod;
    } catch (err) {
      if (readReloadFlag(chunkKey) !== '1') {
        writeReloadFlag(chunkKey, '1');
        window.location.reload();
        return new Promise<{ default: T }>(() => {});
      }
      clearReloadFlag(chunkKey);
      throw err;
    }
  });
}
