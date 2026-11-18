/* KidLink service worker — lecture des bracelets hors ligne. */
'use strict';
const CACHE = 'kidlink-{{ version }}';
const CORE = [
  '/', '/scanner/', '/v/_/', '/hors-ligne/', '/manifest.webmanifest',
  {% for a in assets %}'{{ a }}'{% if not forloop.last %}, {% endif %}{% endfor %}
];
const PRIVATE = ['/espace/', '/dev/', '/i/', '/connexion', '/invitation/', '/inscription-administrateur/', '/api/'];

self.addEventListener('install', (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(CORE)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys().then((keys) => Promise.all(keys.filter((k) => k.startsWith('kidlink-') && k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

function withTimeout(promise, ms) {
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error('timeout')), ms);
    promise.then((r) => { clearTimeout(t); resolve(r); }, (err) => { clearTimeout(t); reject(err); });
  });
}

self.addEventListener('fetch', (e) => {
  const req = e.request;
  const url = new URL(req.url);
  if (req.method !== 'GET' || url.origin !== self.location.origin) return;
  if (PRIVATE.some((p) => url.pathname.startsWith(p))) return; // jamais de cache pour les pages privées

  // Page d'un bracelet : réseau d'abord, sinon la page de lecture gardée en mémoire.
  if (req.mode === 'navigate' && url.pathname.startsWith('/v/')) {
    e.respondWith(withTimeout(fetch(req), 4000).catch(() => caches.match('/v/_/')));
    return;
  }
  if (req.mode === 'navigate') {
    e.respondWith(
      withTimeout(fetch(req), 5000).catch(() => caches.match(url.pathname).then((r) => r || caches.match('/hors-ligne/')))
    );
    return;
  }
  if (url.pathname.startsWith('/static/')) {
    e.respondWith(
      caches.match(req).then((hit) => hit || fetch(req).then((res) => {
        if (res.ok) { const copy = res.clone(); caches.open(CACHE).then((c) => c.put(req, copy)); }
        return res;
      }))
    );
  }
});
