/* ═══════════════════════════════════════════════════════════════════════
   Service Worker
   ─────────────────────────────────────────────────────────────────────
   Zwischenspeichert NUR die Programmhülle — niemals Nachrichten,
   Chiffrat oder Medien. Der Cache ist unverschlüsselt und liegt neben
   dem verschlüsselten Vault; alles, was hier landet, wäre im Klartext
   auf der Platte.
   ═══════════════════════════════════════════════════════════════════════ */

const VERSION = 'v2';
const SHELL = `shell-${VERSION}`;

/* Nur statische Dateien. Bewusst kurz gehalten. */
const ASSETS = [
  '/',
  '/index.html',
  '/config.js',
  '/manifest.json',
  '/icons/192.png',
  '/icons/512.png'
];

self.addEventListener('install', e => {
  e.waitUntil(
    caches.open(SHELL)
      .then(c => c.addAll(ASSETS))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys()
      .then(keys => Promise.all(
        keys.filter(k => k !== SHELL).map(k => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);

  /* Niemals zwischenspeichern: alles, was Nutzerdaten berührt
     oder dynamisch aktualisiert werden muss */
  if (e.request.method !== 'GET' ||
      url.pathname.startsWith('/api/') ||
      url.pathname.startsWith('/rest/') ||
      url.pathname.endsWith('.js') ||
      url.hostname.includes('supabase') ||
      url.hostname.includes('r2.') ||
      url.hostname.includes('mix-')) {
    return;   // direkt ans Netz, kein Cache
  }

  /* Programmhülle: erst Cache, dann Netz — startet auch offline */
  e.respondWith(
    caches.match(e.request).then(hit => hit || fetch(e.request).then(res => {
      if (res.ok && res.type === 'basic') {
        const copy = res.clone();
        caches.open(SHELL).then(c => c.put(e.request, copy));
      }
      return res;
    }).catch(() => caches.match('/index.html')))
  );
});

/* Push: Der Inhalt kommt NICHT vom Server — der kennt ihn nicht.
   Die Benachrichtigung ist bewusst inhaltslos; den Text holt sich
   der Client selbst, sobald er entschlüsseln kann. */
self.addEventListener('push', e => {
  e.waitUntil(self.registration.showNotification('SecureChat', {
    body: 'Neue Nachricht',
    icon: '/icons/192.png',
    badge: '/icons/192.png',
    tag: 'new-message',
    renotify: true,
    data: { url: '/' }
  }));
});

self.addEventListener('notificationclick', e => {
  e.notification.close();
  e.waitUntil(clients.matchAll({ type: 'window', includeUncontrolled: true })
    .then(list => {
      for (const c of list) if (c.url.includes(self.location.origin)) return c.focus();
      return clients.openWindow('/');
    }));
});
