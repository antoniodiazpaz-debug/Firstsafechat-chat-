/* Sealed Sender: Der Server stellt zu, ohne zu wissen, wer schreibt.
   Geprüft wird beides — dass es funktioniert UND dass der Server
   tatsächlich keine Absenderinformation bekommt. */
import { webcrypto as wc } from 'node:crypto';
import crypto from 'node:crypto';
import net from 'node:net';
import { DatabaseSync } from 'node:sqlite';

const SC = wc.subtle, te = new TextEncoder(), td = new TextDecoder();
const BASE = 'http://127.0.0.1:8787';
const b64 = b => Buffer.from(new Uint8Array(b)).toString('base64');
const ub64 = s => new Uint8Array(Buffer.from(s, 'base64'));
const cat = (...as) => { const t = as.reduce((n, a) => n + a.byteLength, 0);
  const o = new Uint8Array(t); let p = 0;
  for (const a of as) { o.set(new Uint8Array(a), p); p += a.byteLength } return o.buffer };

let pass = 0, fail = 0;
const ok = (c, m) => { c ? (pass++, console.log('  ✓', m)) : (fail++, console.log('  ✗', m)) };

async function api(path, { method = 'GET', body, token, headers = {} } = {}) {
  const r = await fetch(BASE + path, {
    method,
    headers: { 'Content-Type': 'application/json',
      ...(token ? { Authorization: 'Bearer ' + token } : {}), ...headers },
    body: body ? JSON.stringify(body) : undefined
  });
  return { status: r.status, data: await r.json() };
}

const P = {
  async genDH() { const kp = await SC.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
    return { priv: kp.privateKey, pubJwk: await SC.exportKey('jwk', kp.publicKey) } },
  async genSign() { const kp = await SC.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    return { priv: kp.privateKey, pubJwk: await SC.exportKey('jwk', kp.publicKey) } },
  impPub: j => SC.importKey('jwk', j, { name: 'ECDH', namedCurve: 'P-256' }, true, []),
  impVerify: j => SC.importKey('jwk', j, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']),
  dh: (a, b) => SC.deriveBits({ name: 'ECDH', public: b }, a, 256),
  sign: (p, d) => SC.sign({ name: 'ECDSA', hash: 'SHA-256' }, p, d),
  verify: (p, s, d) => SC.verify({ name: 'ECDSA', hash: 'SHA-256' }, p, s, d),
  async hkdf(ikm, salt, info, n = 32) {
    const k = await SC.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
    return SC.deriveBits({ name: 'HKDF', hash: 'SHA-256',
      salt: salt || new Uint8Array(32), info: te.encode(info) }, k, n * 8) },
  async seal(kr, iv, pt, aad) {
    const k = await SC.importKey('raw', kr, { name: 'AES-GCM' }, false, ['encrypt']);
    return SC.encrypt({ name: 'AES-GCM', iv: new Uint8Array(iv), additionalData: te.encode(aad) }, k, pt) },
  async open(kr, iv, ct, aad) {
    const k = await SC.importKey('raw', kr, { name: 'AES-GCM' }, false, ['decrypt']);
    return SC.decrypt({ name: 'AES-GCM', iv: new Uint8Array(iv), additionalData: te.encode(aad) }, k, ct) }
};
const sigData = (ik, spk, id, at) => te.encode([ik.x, ik.y, spk.x, spk.y, id, at].join('|'));

async function makeIdentity() {
  const IK = await P.genDH(), IKS = await P.genSign(), SPK = await P.genDH();
  const createdAt = Date.now();
  const signature = b64(await P.sign(IKS.priv, sigData(IK.pubJwk, SPK.pubJwk, 1, createdAt)));
  const opks = [];
  for (let i = 1; i <= 10; i++) opks.push({ opkId: i, key: await P.genDH() });
  return { IK, IKS, SPK, spkMeta: { spkId: 1, createdAt, signature }, opks,
    profileKey: crypto.randomBytes(32) };
}
const bundlePayload = id => ({
  ikDH: id.IK.pubJwk, ikSign: id.IKS.pubJwk,
  spk: { spkId: 1, pub: id.SPK.pubJwk, signature: id.spkMeta.signature, createdAt: id.spkMeta.createdAt },
  opks: id.opks.map(o => ({ opkId: o.opkId, pub: o.key.pubJwk }))
});

/*── Unidentified Access Key aus dem Profilschlüssel ──*/
async function deriveUAK(profileKey) {
  const bits = await P.hkdf(profileKey, null, 'SecureChat-UnidentifiedAccess-v1', 16);
  return b64(bits);
}

/*── Versiegeln: ephemeres ECDH an den Identitätsschlüssel des Empfängers ──*/
async function sealEnvelope(inner, recipientIkJwk) {
  const eph = await P.genDH();
  const shared = await P.dh(eph.priv, await P.impPub(recipientIkJwk));
  const out = await P.hkdf(shared, null, 'SecureChat-SealedSender-v1', 44);
  const key = out.slice(0, 32), iv = out.slice(32, 44);
  const ct = await P.seal(key, iv, te.encode(JSON.stringify(inner)), 'sealed-v1');
  return b64(cat(te.encode(JSON.stringify(eph.pubJwk) + '\u0000'), new Uint8Array(ct)));
}
async function unsealEnvelope(blob, myIK) {
  const raw = ub64(blob);
  const sep = raw.indexOf(0);
  const ephJwk = JSON.parse(td.decode(raw.subarray(0, sep)));
  const ct = raw.subarray(sep + 1);
  const shared = await P.dh(myIK.priv, await P.impPub(ephJwk));
  const out = await P.hkdf(shared, null, 'SecureChat-SealedSender-v1', 44);
  const pt = await P.open(out.slice(0, 32), out.slice(32, 44), ct, 'sealed-v1');
  return JSON.parse(td.decode(pt));
}

function wsConnect(token, onMsg) {
  return new Promise((resolve, reject) => {
    const key = crypto.randomBytes(16).toString('base64');
    const sock = net.connect(8787, '127.0.0.1', () => {
      sock.write(`GET /?token=${token} HTTP/1.1\r\nHost: 127.0.0.1:8787\r\n` +
        `Upgrade: websocket\r\nConnection: Upgrade\r\n` +
        `Sec-WebSocket-Key: ${key}\r\nSec-WebSocket-Version: 13\r\n\r\n`);
    });
    let hs = false, buf = Buffer.alloc(0);
    sock.on('data', chunk => {
      buf = Buffer.concat([buf, chunk]);
      if (!hs) { const i = buf.indexOf('\r\n\r\n'); if (i < 0) return;
        hs = true; buf = buf.subarray(i + 4); resolve({ sock }) }
      for (;;) {
        if (buf.length < 2) return;
        let len = buf[1] & 0x7f, off = 2;
        if (len === 126) { if (buf.length < 4) return; len = buf.readUInt16BE(2); off = 4 }
        else if (len === 127) { if (buf.length < 10) return; len = Number(buf.readBigUInt64BE(2)); off = 10 }
        if (buf.length < off + len) return;
        try { onMsg(JSON.parse(buf.subarray(off, off + len).toString())) } catch {}
        buf = buf.subarray(off + len);
      }
    });
    sock.on('error', reject);
  });
}

/*═══════════════════ TESTS ═══════════════════*/
/*═══════════════════ TESTS ═══════════════════*/
console.log('Vorbereitung:');
const aId = await makeIdentity(), bId = await makeIdentity(), cId = await makeIdentity();
const stamp = Date.now().toString(36);
const reg = async (n, id) => (await api('/api/register', { method: 'POST',
  body: { name: n + '_' + stamp, password: 'passwort123', deviceName: n + '-Gerät', platform: 'web',
    ...bundlePayload(id) } })).data;
const ra = await reg('Anna', aId);
const rb = await reg('Boris', bId);
const rc = await reg('Carla', cId);
const A = { ...ra, ...aId }, B = { ...rb, ...bId }, C = { ...rc, ...cId };
ok(A.token && B.token && C.token, 'drei Konten angelegt, jeweils mit primärem Gerät');
ok(!!A.device.id && !!B.device.id, 'jedes Konto hat eine eigene Geräte-ID');

console.log('\nZustellrecht hinterlegen:');
const uakB = await deriveUAK(B.profileKey);
const setRes = await api('/api/access-key', { method: 'POST', token: B.token, body: { uak: uakB } });
ok(setRes.status === 200 && setRes.data.allowSealed, 'Boris erlaubt anonyme Zustellung');

console.log('\nAbsenderzertifikat (jetzt an ein GERÄT gebunden):');
const certRes = await api('/api/sender-certificate', { token: A.token });
ok(certRes.status === 200 && certRes.data.certificate, 'Anna erhält ein Zertifikat');
const cert = certRes.data.certificate;
ok(cert.senderId === A.user.id, 'Zertifikat nennt die richtige Identität');
ok(cert.senderDeviceId === A.device.id, 'Zertifikat nennt auch das sendende GERÄT — nötig für den richtigen Ratchet-Zustand');
ok(cert.expiresAt > Date.now() && cert.expiresAt < Date.now() + 25 * 3600e3, 'Gültigkeit 24 Stunden');
const logPub = await SC.importKey('jwk', certRes.data.logKey,
  { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']);
const certData = te.encode(['sendercert-v1', cert.senderId, cert.senderName, cert.senderDeviceId,
  cert.ikX, cert.ikY, cert.expiresAt].join('|'));
ok(await P.verify(logPub, ub64(cert.signature), certData), 'Serversignatur des Zertifikats gültig');
const forgedName = { ...cert, senderName: 'Jemand-anderes' };
const forgedNameData = te.encode(['sendercert-v1', forgedName.senderId, forgedName.senderName,
  forgedName.senderDeviceId, forgedName.ikX, forgedName.ikY, forgedName.expiresAt].join('|'));
ok(!await P.verify(logPub, ub64(cert.signature), forgedNameData), 'geändertes Zertifikat fällt durch');
const forgedDevice = { ...cert, senderDeviceId: 'd-fremdes-geraet' };
const forgedDeviceData = te.encode(['sendercert-v1', forgedDevice.senderId, forgedDevice.senderName,
  forgedDevice.senderDeviceId, forgedDevice.ikX, forgedDevice.ikY, forgedDevice.expiresAt].join('|'));
ok(!await P.verify(logPub, ub64(cert.signature), forgedDeviceData),
  'untergeschobene Geräte-ID bricht ebenfalls die Signatur — verhindert Identitätsverwechslung zwischen Geräten');

console.log('\nAnonyme Zustellung (Fanout — hier an genau ein Gerät):');
const inbox = [];
const wsB = await wsConnect(B.token, m => inbox.push(m));
await new Promise(r => setTimeout(r, 250));

const inner = { cert, header: { dh: A.IK.pubJwk, pn: 0, n: 0 },
  ciphertext: b64(te.encode('geheime-nutzlast-simuliert')) };
const blob = await sealEnvelope(inner, B.user.ikDH ?? B.IK.pubJwk);

/* Bewusst OHNE Bearer-Token gesendet, jetzt mit perDevice-Liste wie beim
   normalen Versand — Sealed Sender ändert die Transportstruktur nicht,
   nur wer sich dabei zu erkennen gibt. */
const sent = await api('/api/send-sealed', { method: 'POST',
  headers: { 'X-Unidentified-Access-Key': uakB },
  body: { recipientId: B.user.id, convId: 'dm_sealed',
    perDevice: [{ deviceId: B.device.id, sealed: blob }] } });
ok(sent.status === 200, 'Server nimmt die Nachricht ohne Login an');
ok(sent.data.results?.[0]?.delivered, 'sofort zugestellt');

await new Promise(r => setTimeout(r, 300));
const got = inbox.find(m => m.type === 'envelope' && m.sealed);
ok(!!got, 'versiegelter Umschlag kam an');
ok(got.senderId === null, 'der Umschlag trägt keinen Absender-Nutzer');
ok(got.senderDeviceId === null, 'der Umschlag trägt auch kein Absender-GERÄT');
ok(got.recipientDeviceId === B.device.id, 'aber das Empfängergerät ist klar adressiert — sonst wüsste niemand, wohin');

console.log('\nEmpfänger öffnet und prüft:');
const opened = await unsealEnvelope(got.ciphertext, B.IK);
ok(opened.cert.senderId === A.user.id, 'Boris erfährt: die Nachricht kam von Anna');
ok(opened.cert.senderDeviceId === A.device.id, 'und von genau diesem Gerät — wichtig, falls Anna mehrere hat');
const oData = te.encode(['sendercert-v1', opened.cert.senderId, opened.cert.senderName,
  opened.cert.senderDeviceId, opened.cert.ikX, opened.cert.ikY, opened.cert.expiresAt].join('|'));
ok(await P.verify(logPub, ub64(opened.cert.signature), oData), 'Zertifikat im Umschlag verifiziert');
ok(opened.cert.ikX === A.IK.pubJwk.x, 'Identitätsschlüssel passt zum Ratchet-Partner');
ok(td.decode(ub64(opened.ciphertext)) === 'geheime-nutzlast-simuliert', 'Nutzlast intakt');

console.log('\nWas der Server gespeichert hat:');
const dbf = new DatabaseSync('./securechat.db', { readOnly: true });
const row = dbf.prepare('SELECT * FROM envelopes WHERE id=?').get(sent.data.results[0].id);
ok(row.sender_id === null, 'sender_id in der Datenbank ist NULL');
ok(row.sender_device_id === null, 'sender_device_id ist ebenfalls NULL');
ok(row.recipient_device_id === B.device.id, 'recipient_device_id ist gesetzt — sonst keine Zustellung möglich');
ok(row.sealed === 1, 'als versiegelt markiert');
ok(!JSON.stringify(row).includes(A.user.id), 'Annas Nutzer-ID taucht in der Zeile nirgends auf');
ok(!JSON.stringify(row).includes(A.device.id), 'Annas Geräte-ID taucht ebenfalls nirgends auf');
ok(!JSON.stringify(row).includes('geheime-nutzlast'), 'kein Klartext gespeichert');
console.log('    → gespeicherte Spalten:', Object.keys(row).filter(k => row[k] !== null).join(', '));
dbf.close();

console.log('\nMissbrauchsschutz:');
const noUak = await api('/api/send-sealed', { method: 'POST',
  body: { recipientId: B.user.id, convId: 'x', perDevice: [{ deviceId: B.device.id, sealed: blob }] } });
ok(noUak.status === 401, 'ohne Zustellrecht abgelehnt');
const wrongUak = await api('/api/send-sealed', { method: 'POST',
  headers: { 'X-Unidentified-Access-Key': b64(crypto.randomBytes(16)) },
  body: { recipientId: B.user.id, convId: 'x', perDevice: [{ deviceId: B.device.id, sealed: blob }] } });
ok(wrongUak.status === 403, 'falsches Zustellrecht abgelehnt');
const wrongTarget = await api('/api/send-sealed', { method: 'POST',
  headers: { 'X-Unidentified-Access-Key': uakB },
  body: { recipientId: C.user.id, convId: 'x', perDevice: [{ deviceId: C.device.id, sealed: blob }] } });
ok(wrongTarget.status === 403, 'Boris’ Recht gilt nicht für Carla');
const foreignDevice = await api('/api/send-sealed', { method: 'POST',
  headers: { 'X-Unidentified-Access-Key': uakB },
  body: { recipientId: B.user.id, convId: 'x', perDevice: [{ deviceId: C.device.id, sealed: blob }] } });
ok(foreignDevice.status === 200 && foreignDevice.data.results.length === 0,
  'ein fremdes Gerät in der perDevice-Liste wird still übergangen, nicht als Fehler quittiert');

console.log('\nAbschaltbar:');
await api('/api/access-key', { method: 'POST', token: C.token,
  body: { uak: await deriveUAK(C.profileKey), allowSealed: false } });
const refused = await api('/api/send-sealed', { method: 'POST',
  headers: { 'X-Unidentified-Access-Key': await deriveUAK(C.profileKey) },
  body: { recipientId: C.user.id, convId: 'x', perDevice: [{ deviceId: C.device.id, sealed: blob }] } });
ok(refused.status === 403, 'wer anonyme Zustellung ablehnt, bekommt keine');

console.log('\nStore-and-Forward auch versiegelt:');
wsB.sock.destroy();
await new Promise(r => setTimeout(r, 500));
const inner2 = { cert, header: { dh: A.IK.pubJwk, pn: 0, n: 1 },
  ciphertext: b64(te.encode('zweite-versiegelte-nachricht')) };
const blob2 = await sealEnvelope(inner2, B.user.ikDH ?? B.IK.pubJwk);
const sent2 = await api('/api/send-sealed', { method: 'POST',
  headers: { 'X-Unidentified-Access-Key': uakB },
  body: { recipientId: B.user.id, convId: 'dm_sealed',
    perDevice: [{ deviceId: B.device.id, sealed: blob2 }] } });
ok(!sent2.data.results[0].delivered, 'offline: wird zwischengespeichert');
const ibx = await api('/api/inbox', { token: B.token });
const waiting = ibx.data.envelopes.find(e => e.id === sent2.data.results[0].id);
ok(!!waiting && waiting.sealed, 'liegt versiegelt in der Inbox');
ok(waiting.senderId === null && waiting.senderDeviceId === null, 'auch in der Inbox ohne jeden Absenderhinweis');
const opened2 = await unsealEnvelope(waiting.ciphertext, B.IK);
ok(td.decode(ub64(opened2.ciphertext)) === 'zweite-versiegelte-nachricht', 'nachträglich geöffnet');

console.log('\nAbgelaufenes Zertifikat:');
const expired = { ...cert, expiresAt: Date.now() - 1000 };
const expData = te.encode(['sendercert-v1', expired.senderId, expired.senderName, expired.senderDeviceId,
  expired.ikX, expired.ikY, expired.expiresAt].join('|'));
const stillValid = await P.verify(logPub, ub64(cert.signature), expData);
ok(!stillValid, 'zurückdatiertes Zertifikat bricht die Signatur');
ok(cert.expiresAt > Date.now(), 'Empfänger kann Ablauf selbst prüfen');

console.log(`\n${pass} bestanden, ${fail} fehlgeschlagen`);
process.exit(fail ? 1 : 0);
