const CACHE_NAME = 'auth-v3';
const ASSETS = [
  './',
  './index.html',
  './styles.css',
  './app.js',
  './manifest.json',
  'https://cdn.jsdelivr.net/npm/jsqr@1.4.0/dist/jsQR.min.js'
];

// Install Event - Pre-cache assets
self.addEventListener('install', (e) => {
  self.skipWaiting();
  e.waitUntil(
    caches.open(CACHE_NAME).then(cache => cache.addAll(ASSETS))
  );
});

// Activate Event - Clean up old caches
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

// Fetch Event - Network First Strategy for better Brave compatibility
self.addEventListener('fetch', (e) => {
  // Only handle GET requests
  if (e.request.method !== 'GET') return;

  e.respondWith(
    fetch(e.request)
      .then(response => {
        // If success, clone and update cache
        const resClone = response.clone();
        caches.open(CACHE_NAME).then(cache => {
          cache.put(e.request, resClone);
        });
        return response;
      })
      .catch(() => {
        // If network fails, try cache
        return caches.match(e.request);
      })
  );
});
