/* ═══════════════════════════════════════════════════════════════════════
   SERVICE WORKER — Push-Benachrichtigungen im Hintergrund
   ─────────────────────────────────────────────────────────────────────
   Bewusst OHNE Cache-Strategie für JS/HTML (siehe Vorfall: gecachte
   Dateien haben zu stundenlangem Debugging von "Phantom-Bugs" geführt).
   Einzige Aufgabe dieses SW: Push-Events empfangen und als
   Systembenachrichtigung anzeigen, auch wenn kein Tab offen ist.
   ═══════════════════════════════════════════════════════════════════════ */
const VERSION = 'v3-push-only';

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => {
  e.waitUntil(self.clients.claim());
});

/* Der Server schickt bewusst KEINEN Klartext (siehe server.js
   notifyOffline) — nur einen Weckruf vom Typ 'new-message'. Der genaue
   Text kommt nie über den Push-Kanal, weil Web-Push-Server (Google/
   Mozilla) technisch Zugriff auf die verschlüsselte Nutzlast HABEN und
   ein Server, der Klartext hineinlegt, das Verschlüsselungsversprechen
   der App bräche. */
self.addEventListener('push', (e) => {
  let data = { type: 'new-message' };
  try { if (e.data) data = e.data.json(); } catch {}

  const title = data.type === 'call-offer' ? '📞 Eingehender Anruf' : '🔒 Neue Nachricht';
  const body = data.type === 'call-offer'
    ? 'Tippen, um anzunehmen'
    : 'Öffne SecureChat, um sie zu lesen';

  e.waitUntil(
    self.registration.showNotification(title, {
      body,
      icon: '/icons/icon-192.png',
      badge: '/icons/icon-192.png',
      tag: data.type === 'call-offer' ? 'call' : 'message',
      renotify: true,
      requireInteraction: data.type === 'call-offer',
      data: { url: '/' }
    })
  );
});

/* Klick auf die Benachrichtigung → App öffnen (oder vorhandenen Tab
   fokussieren, statt einen zweiten zu öffnen). */
self.addEventListener('notificationclick', (e) => {
  e.notification.close();
  e.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((clientList) => {
      for (const client of clientList) {
        if ('focus' in client) return client.focus();
      }
      if (self.clients.openWindow) return self.clients.openWindow('/');
    })
  );
});
