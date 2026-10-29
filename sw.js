// Service Worker for Nick's Process Services Dashboard (admin.html).
// Caches ONLY static shell assets (HTML, fonts, icons) so the dashboard opens reliably on spotty cellular connections.
// NEVER caches /api/*, /__mock*, or cross-origin requests (such as signed document download URLs).
const CACHE_NAME = 'nps-dashboard-shell-v2';
const SHELL_ASSETS = [
    '/admin.html',
    '/manifest.webmanifest',
    '/assets/js/nps.js',
    '/assets/js/admin.js',
    '/assets/vendor/qrcode-generator-1.4.4/qrcode.js',
    '/assets/icon-180.png',
    '/assets/icon-192.png',
    '/assets/icon-512.png',
    '/assets/fonts/librecaslondisplay-400.woff2',
    '/assets/fonts/librecaslontext-400.woff2',
    '/assets/fonts/librecaslontext-400-italic.woff2',
    '/assets/fonts/librecaslontext-700.woff2',
    '/assets/fonts/montserrat-var.woff2',
];

self.addEventListener('install', (event) => {
    event.waitUntil(
        caches.open(CACHE_NAME).then((cache) => cache.addAll(SHELL_ASSETS).catch(() => {})).then(() => self.skipWaiting())
    );
});

self.addEventListener('activate', (event) => {
    event.waitUntil(
        caches.keys().then((keys) => Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k)))).then(() => self.clients.claim())
    );
});

self.addEventListener('message', (event) => {
    if (event.data && event.data.type === 'CLEAR_AUTH_CACHE') {
        event.waitUntil(
            caches.keys().then((keys) => Promise.all(keys.map((k) => caches.delete(k)))).catch(() => {})
        );
    }
});

self.addEventListener('fetch', (event) => {
    const req = event.request;
    if (req.method !== 'GET') return;
    const url = new URL(req.url);
    if (url.origin !== self.location.origin) return;
    if (url.pathname.startsWith('/api/') || url.pathname.startsWith('/__mock')) return;
    if (!SHELL_ASSETS.includes(url.pathname)) return;

    event.respondWith(
        fetch(req)
            .then((res) => {
                if (res && res.ok) {
                    const copy = res.clone();
                    caches.open(CACHE_NAME).then((c) => c.put(req, copy)).catch(() => {});
                }
                return res;
            })
            .catch(() => caches.match(req))
    );
});
