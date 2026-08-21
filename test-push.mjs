/* Testet den Push-Weckruf im echten Sendepfad (/api/send): Ein Gerät
   ohne WebSocket-Verbindung ("offline") muss einen echten,
   verschlüsselten Web-Push-Request auslösen. Ein lokaler Mock-Endpunkt
   protokolliert, was tatsächlich ankommt — das prüft nicht nur, dass
   notifyOffline() aufgerufen wird, sondern dass push.js einen laut
   RFC 8291/8292 korrekten Request tatsächlich verschickt.

   WICHTIG: notifyOffline() läuft im Server absichtlich ohne await
   (siehe Kommentar in server.js /api/send) — der Sendeaufruf soll
   nicht auf die Push-Zustellung warten. Der Test muss daher nach dem
   Senden kurz abwarten, bevor er den Mock-Endpunkt prüft. */
import { spawn } from 'node:child_process';
import http from 'node:http';
import crypto from 'node:crypto';

let pass = 0, fail = 0;
const ok = (c, m) => { c ? (pass++, console.log('  ✓', m)) : (fail++, console.log('  ✗', m)) };

const received = [];
const mockPush = http.createServer((req, res) => {
  const chunks = [];
  req.on('data', c => chunks.push(c));
  req.on('end', () => {
    received.push({
      contentEncoding: req.headers['content-encoding'],
      authorization: req.headers['authorization'],
      bodyLength: Buffer.concat(chunks).length,
      body: Buffer.concat(chunks)
    });
    res.writeHead(201); res.end();
  });
});

await new Promise(resolve => mockPush.listen(19998, resolve));
console.log('Mock-Push-Endpunkt lauscht auf 19998');

const server = spawn('node', ['server.js'], { cwd: import.meta.dirname, stdio: ['ignore', 'pipe', 'pipe'] });
let serverLog = '';
server.stdout.on('data', d => { serverLog += d; });
server.stderr.on('data', d => { serverLog += d; });

await new Promise(r => setTimeout(r, 2000));

try {
  const B = 'http://127.0.0.1:8787';
  const api = (p, o = {}) => fetch(B + p, {
    method: o.method || 'GET',
    headers: { 'Content-Type': 'application/json', ...(o.token ? { Authorization: 'Bearer ' + o.token } : {}) },
    body: o.body ? JSON.stringify(o.body) : undefined
  }).then(async r => ({ status: r.status, data: await r.json() }));
  const fk = () => ({ x: 'k' + Math.random().toString(36).slice(2), y: 'k' + Math.random().toString(36).slice(2) });
  const fb = () => ({ ikDH: fk(), ikSign: fk(), spk: { spkId: 1, pub: fk(), signature: 's', createdAt: Date.now() }, opks: [{ opkId: 1, pub: fk() }] });

  console.log('\nVAPID-Schlüssel-Endpunkt:');
  const vapidRes = await api('/api/push/vapid-key');
  ok(vapidRes.status === 200, 'öffentlich ohne Login erreichbar');
  ok(Buffer.from(vapidRes.data.publicKey, 'base64url').length === 65, 'Schlüssel ist unkomprimierter EC-Punkt (65 Byte)');

  console.log('\nKonten und Push-Abo:');
  const stamp = Date.now();
  const recv = await api('/api/register', { method: 'POST', body: {
    name: 'PR' + stamp, password: 'passwort123', phone: '+49pr' + Math.floor(Math.random() * 1e7),
    deviceName: 'd', platform: 'web', ...fb()
  }});
  const send = await api('/api/register', { method: 'POST', body: {
    name: 'PS' + stamp, password: 'passwort123', phone: '+49ps' + Math.floor(Math.random() * 1e7),
    deviceName: 'd', platform: 'web', ...fb()
  }});
  ok(recv.status === 201 && send.status === 201, 'beide Konten registriert');

  const clientKeys = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const clientPubRaw = clientKeys.publicKey.export({ type: 'spki', format: 'der' }).subarray(-65);
  const authSecret = crypto.randomBytes(16);
  const subRes = await api('/api/push/subscribe', { method: 'POST', token: recv.data.token, body: {
    platform: 'web', endpoint: 'http://127.0.0.1:19998/fake',
    p256dh: Buffer.from(clientPubRaw).toString('base64url'), auth: authSecret.toString('base64url')
  }});
  ok(subRes.status === 200, 'Push-Abo gespeichert');

  console.log('\nNachricht an OFFLINE-Gerät (kein WebSocket verbunden):');
  const sendRes = await api('/api/send', { method: 'POST', token: send.data.token, body: {
    recipientId: recv.data.user.id, convId: 'push-test', kind: 'text',
    perDevice: [{ deviceId: recv.data.device.id, header: { dh: { x: '1', y: '2' }, pn: 0, n: 0 }, ciphertext: 'AAAA' }]
  }});
  ok(sendRes.status === 200, 'Sendeaufruf erfolgreich');
  ok(sendRes.data.results[0].delivered === false, 'korrekt als NICHT sofort zugestellt markiert (kein WebSocket)');

  console.log('\nWarte auf asynchronen Push-Versand (läuft bewusst ohne await im Server)...');
  await new Promise(r => setTimeout(r, 1500));

  ok(received.length === 1, `Mock-Endpunkt hat genau einen Push-Request empfangen (${received.length})`);
  if (received[0]) {
    const r = received[0];
    ok(r.contentEncoding === 'aes128gcm', 'Content-Encoding ist aes128gcm (RFC 8291 verlangt exakt diesen Wert)');
    ok(r.authorization?.startsWith('vapid t='), 'Authorization-Header nutzt das vapid-Schema (RFC 8292)');
    ok(r.bodyLength > 50, `verschlüsselter Body hat plausible Größe (${r.bodyLength} Byte)`);
    ok(!r.body.includes('AAAA'), 'die Ratchet-Chiffrat-Nachricht selbst steht NICHT im Push-Body — nur ein Weckruf ohne Vorschau');
  }

  console.log('\nOnline-Gerät bekommt KEINEN Push (WebSocket reicht):');
  received.length = 0;
  const ws = new WebSocket('ws://127.0.0.1:8787/?token=' + recv.data.token);
  await new Promise((resolve, reject) => { ws.onopen = resolve; ws.onerror = reject; setTimeout(reject, 3000); });
  await new Promise(r => setTimeout(r, 300));

  const sendRes2 = await api('/api/send', { method: 'POST', token: send.data.token, body: {
    recipientId: recv.data.user.id, convId: 'push-test', kind: 'text',
    perDevice: [{ deviceId: recv.data.device.id, header: { dh: { x: '1', y: '2' }, pn: 0, n: 1 }, ciphertext: 'BBBB' }]
  }});
  ok(sendRes2.data.results[0].delivered === true, 'online: sofort per WebSocket zugestellt');
  await new Promise(r => setTimeout(r, 1000));
  ok(received.length === 0, 'kein Push-Request ausgelöst, wenn das Gerät bereits per WebSocket erreicht wurde — kein doppeltes Wecken');
  ws.close();

} finally {
  server.kill();
  mockPush.close();
}

console.log(`\n${pass} bestanden, ${fail} fehlgeschlagen`);
process.exit(fail ? 1 : 0);
