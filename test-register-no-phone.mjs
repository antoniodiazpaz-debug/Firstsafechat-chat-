/* Prüft: Registrierung funktioniert vollständig ohne Telefonnummer.
   Es gibt keine SMS-Verifikation im System — die Nummer ist rein
   optional für den Kontaktabgleich. Läuft gegen den echten Server. */
import { spawn } from 'node:child_process';

let pass = 0, fail = 0;
const ok = (c, m) => { c ? (pass++, console.log('  ✓', m)) : (fail++, console.log('  ✗', m)) };

const server = spawn('node', ['server.js'], { cwd: import.meta.dirname, stdio: ['ignore', 'pipe', 'pipe'] });
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

  console.log('Registrierung KOMPLETT OHNE Telefonnummer:');
  const stamp = Date.now();
  const noPhone = await api('/api/register', { method: 'POST', body: {
    name: 'NoPhone' + stamp, password: 'passwort123', deviceName: 'd', platform: 'web', ...fb()
    // bewusst: kein phone-Feld
  }});
  ok(noPhone.status === 201, `Registrierung ohne Telefonnummer erfolgreich (Status ${noPhone.status})`);
  ok(!noPhone.data.user.phone || noPhone.data.user.phone === '', 'Nutzerobjekt hat keine/leere Telefonnummer');
  ok(!!noPhone.data.token, 'Sitzungstoken trotzdem ausgestellt');

  console.log('\nKein SMS-Versand-Endpunkt existiert:');
  const smsAttempts = ['/api/sms/send', '/api/verify', '/api/otp', '/api/sms/verify', '/api/register/verify'];
  let noneExist = true;
  for (const path of smsAttempts) {
    const r = await api(path, { method: 'POST', body: {} });
    if (r.status !== 404) { noneExist = false; console.log('    unerwartet vorhanden:', path, r.status); }
  }
  ok(noneExist, 'keine der üblichen SMS/OTP-Routen existiert (alle 404)');

  console.log('\nAuch OHNE E-Mail funktioniert die Registrierung:');
  const noEmail = await api('/api/register', { method: 'POST', body: {
    name: 'NoEmail' + stamp, password: 'passwort123', deviceName: 'd', platform: 'web', ...fb()
  }});
  ok(noEmail.status === 201, 'weder Telefon noch E-Mail nötig — nur Name und Passwort');

  console.log('\nLogin funktioniert danach normal:');
  const login = await api('/api/login', { method: 'POST', body: {
    name: 'NoPhone' + stamp, password: 'passwort123', deviceId: noPhone.data.device.id
  }});
  ok(login.status === 200, 'Login mit dem telefonlosen Konto funktioniert');

  console.log('\nTelefonnummer bleibt optional nutzbar, wenn gewünscht:');
  const withPhone = await api('/api/register', { method: 'POST', body: {
    name: 'WithPhone' + stamp, password: 'passwort123', phone: '+49151' + Math.floor(Math.random() * 1e7),
    deviceName: 'd', platform: 'web', ...fb()
  }});
  ok(withPhone.status === 201, 'Registrierung MIT Telefonnummer funktioniert weiterhin (optional heißt nicht entfernt)');
  ok(!!withPhone.data.user.phone, 'Nummer wird gespeichert, wenn angegeben');

} finally {
  server.kill();
}

console.log(`\n${pass} bestanden, ${fail} fehlgeschlagen`);
process.exit(fail ? 1 : 0);
