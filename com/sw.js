// web/sw.js — minimal service worker for an installable PWA.
//
// SECURITY: this worker caches ONLY the static application shell + vendored libs.
// It MUST NEVER cache API responses (/api/...), the WebSocket, keys, messages, or
// attachments. Those are E2E-sensitive and must always go to the network and live
// only in memory. A stale or poisoned cache of crypto code would break the trust
// model, so the shell is served network-first with a cache fallback for offline
// install only.
const SHELL_CACHE = 'com-shell-v5';
const SHELL = [
  './',
  './css/style.css',
  './js/app.js',
  './js/client-core.js',
  './js/api.js',
  './js/opaque-client.js',
  './js/sodium-helpers.js',
  './manifest.webmanifest',
  // NOTE: vendored crypto libs (web/vendor/*) get added here for real deployment.
];

self.addEventListener('install', (event) => {
  // 'reload' bypasses the HTTP cache so we never cache a stale shell on install.
  const fresh = SHELL.map((u) => new Request(u, { cache: 'reload' }));
  event.waitUntil(caches.open(SHELL_CACHE).then((c) => c.addAll(fresh)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== SHELL_CACHE).map((k) => caches.delete(k))),
    ).then(() => self.clients.claim()),
  );
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);

  // NEVER touch the API, the WebSocket upgrade, or files — always network, never cache.
  const isSensitive =
    url.pathname.startsWith('/api/') ||
    url.pathname.startsWith('/ws') ||
    event.request.method !== 'GET';
  if (isSensitive) return; // let the browser go straight to the network

  // Static shell: network-first (fresh crypto code), fall back to cache for offline install.
  event.respondWith(
    // 'reload' bypasses the ~10-min GitHub Pages HTTP cache so crypto/UI code is always fresh online.
    fetch(event.request, { cache: 'reload' })
      .then((res) => {
        // Only cache our own same-origin shell assets.
        if (url.origin === self.location.origin && SHELL.some((p) => url.pathname.endsWith(p.replace('./', '/')))) {
          const copy = res.clone();
          caches.open(SHELL_CACHE).then((c) => c.put(event.request, copy));
        }
        return res;
      })
      .catch(() => caches.match(event.request)),
  );
});
