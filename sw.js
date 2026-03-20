const CACHE_NAME = 'auth-v2';
const ASSETS = [
  './',
  './index.html',
  './styles.css',
  './app.js',
  './manifest.json',
  'https://cdn.jsdelivr.net/npm/jsqr@1.4.0/dist/jsQR.min.js'
];

// Install Event - Pre-cache assets and skip waiting
self.addEventListener('install', (e) => {
  self.skipWaiting();
  e.waitUntil(
    caches.open(CACHE_NAME).then(cache => cache.addAll(ASSETS))
  );
});

// Activate Event - Clean up old caches and claim clients
self.addEventListener('activate', (e) => {
  e.waitUntil(
    Promise.all([
      caches.keys().then(keys => {
        return Promise.all(keys.map(key => {
          if (key !== CACHE_NAME) return caches.delete(key);
        }));
      }),
      self.clients.claim()
    ])
  );
});

// Fetch Event - Cache first strategy
self.addEventListener('fetch', (e) => {
  e.respondWith(
    caches.match(e.request).then(response => response || fetch(e.request))
  );
});
