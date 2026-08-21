/* Mixnet über HTTP: Anna schickt an Boris, ohne dass irgendwo
   eine Verbindung zwischen beiden entsteht. */
import { webcrypto as wc } from 'node:crypto';
import crypto from 'node:crypto';
import net from 'node:net';
import { DatabaseSync } from 'node:sqlite';
import MIXPKG from './mixnet.js';
const { buildPacket, PACKET_SIZE, PATH_LENGTH, MAX_PAYLOAD } = MIXPKG;

const SC = wc.subtle, te = new TextEncoder(), td = new TextDecoder();
const BASE = 'http://127.0.0.1:8787';
const b64 = b => Buffer.from(new Uint8Array(b)).toString('base64');
const ub64 = s => new Uint8Array(Buffer.from(s, 'base64'));
const cat = (...as) => { const t = as.reduce((n, a) => n + a.byteLength, 0);
  const o = new Uint8Array(t); let p = 0;
  for (const a of as) { o.set(new Uint8Array(a), p); p += a.byteLength } return o.buffer };

let pass = 0, fail = 0;
const ok = (c, m) => { c ? (pass++, console.log('  ✓', m)) : (fail++, console.log('  ✗', m)); };

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
  dh: (a, b) => SC.deriveBits({ name: 'ECDH', public: b }, a, 256),
  sign: (p, d) => SC.sign({ name: 'ECDSA', hash: 'SHA-256' }, p, d),
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
const deriveUAK = async pk => b64(await P.hkdf(pk, null, 'SecureChat-UnidentifiedAccess-v1', 16));

async function sealEnvelope(inner, recipientIkJwk) {
  const eph = await P.genDH();
  const shared = await P.dh(eph.priv, await P.impPub(recipientIkJwk));
  const out = await P.hkdf(shared, null, 'SecureChat-SealedSender-v1', 44);
  const ct = await P.seal(out.slice(0, 32), out.slice(32, 44),
    te.encode(JSON.stringify(inner)), 'sealed-v1');
  return b64(cat(te.encode(JSON.stringify(eph.pubJwk) + '\u0000'), new Uint8Array(ct)));
}
async function unsealEnvelope(blob, myIK) {
  const raw = ub64(blob), sep = raw.indexOf(0);
  const ephJwk = JSON.parse(td.decode(raw.subarray(0, sep)));
  const shared = await P.dh(myIK.priv, await P.impPub(ephJwk));
  const out = await P.hkdf(shared, null, 'SecureChat-SealedSender-v1', 44);
  const pt = await P.open(out.slice(0, 32), out.slice(32, 44), raw.subarray(sep + 1), 'sealed-v1');
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
console.log('Verzeichnis:');
const dir = await api('/api/mix/directory');
ok(dir.status === 200 && dir.data.nodes.length >= 3,
  `${dir.data.nodes.length} Mix-Knoten veröffentlicht`);
ok(dir.data.pathLength === PATH_LENGTH, `Pfadlänge ${dir.data.pathLength}`);
ok(dir.data.packetSize === PACKET_SIZE, `Paketgröße ${dir.data.packetSize} Byte`);
const nodes = dir.data.nodes.map(n => ({ id: n.id, pub: Buffer.from(n.pub, 'base64') }));
const pickPath = () => {
  const pool = [...nodes], out = [];
  while (out.length < PATH_LENGTH) out.push(pool.splice(crypto.randomInt(0, pool.length), 1)[0]);
  return out;
};

console.log('\nKonten:');
const stamp = Date.now().toString(36);
const aId = await makeIdentity(), bId = await makeIdentity();
const reg = async (n, id) => (await api('/api/register', { method: 'POST',
  body: { name: n + '_' + stamp, password: 'passwort123', deviceName: n + '-Gerät', platform: 'web',
    ...bundlePayload(id) } })).data;
const A = { ...(await reg('Anna', aId)), ...aId };
const B = { ...(await reg('Boris', bId)), ...bId };
const uakB = await deriveUAK(B.profileKey);
await api('/api/access-key', { method: 'POST', token: B.token, body: { uak: uakB } });
ok(!!A.token && !!B.token, 'Anna und Boris registriert');

console.log('\nZustellung durch das Mixnet:');
const inbox = [];
const wsB = await wsConnect(B.token, m => inbox.push(m));
await new Promise(r => setTimeout(r, 250));

const certRes = await api('/api/sender-certificate', { token: A.token });
const inner = { cert: certRes.data.certificate,
  header: { dh: A.IK.pubJwk, pn: 0, n: 0 },
  ciphertext: b64(te.encode('durch drei Mix-Knoten geschickt')) };
/* Identität liegt jetzt am GERÄT — B.device.ikDH statt B.user.ikDH.
   Und die versiegelte Nutzlast muss recipientDeviceId enthalten, damit
   der Mixnet-Zustelldienst im Server weiß, welches Gerät gemeint ist
   (siehe mixNet-Callback in server.js). */
const sealed = await sealEnvelope(inner, B.device.ikDH);
const finalPayload = Buffer.from(JSON.stringify({ sealed, convId: 'dm_mix', recipientDeviceId: B.device.id }));
ok(finalPayload.length < MAX_PAYLOAD, `Nutzlast passt (${finalPayload.length} < ${MAX_PAYLOAD})`);

const t0 = Date.now();
const pkt = buildPacket(pickPath(), finalPayload, { recipientId: B.user.id });
const inj = await api('/api/mix/inject', { method: 'POST',
  body: { packet: pkt.packet.toString('base64'), firstHop: pkt.firstHop } });
const ackTime = Date.now() - t0;
ok(inj.status === 202, 'Server nimmt das Paket an');
ok(ackTime < 150, `Quittung nach ${ackTime} ms — verrät die Gesamtlatenz nicht`);

/* Warten, bis das Paket den Weg durch hat */
let got = null;
for (let i = 0; i < 60 && !got; i++) {
  await new Promise(r => setTimeout(r, 100));
  got = inbox.find(m => m.type === 'envelope' && m.viaMix);
}
const latency = Date.now() - t0;
ok(!!got, `Umschlag nach ${latency} ms angekommen`);
ok(latency > ackTime, 'echte Zustellung dauerte länger als die Quittung');
ok(got.senderId === null, 'kein Absender am Umschlag');
ok(got.viaMix === true, 'als Mixnet-Zustellung markiert');

console.log('\nEmpfänger öffnet:');
const opened = await unsealEnvelope(got.ciphertext, B.IK);
ok(opened.cert.senderId === A.user.id, 'Boris erfährt: von Anna');
ok(td.decode(ub64(opened.ciphertext)) === 'durch drei Mix-Knoten geschickt', 'Nutzlast intakt');

console.log('\nWas in der Datenbank steht:');
const dbf = new DatabaseSync('./securechat.db', { readOnly: true });
const row = dbf.prepare('SELECT * FROM envelopes WHERE id=?').get(got.id);
ok(row.sender_id === null, 'sender_id ist NULL');
ok(!JSON.stringify(row).includes(A.user.id), 'Annas ID kommt nirgends vor');
ok(!JSON.stringify(row).includes('drei Mix-Knoten'), 'kein Klartext');
dbf.close();

console.log('\nMissbrauchsschutz am Eingang:');
const wrongSize = await api('/api/mix/inject', { method: 'POST',
  body: { packet: Buffer.alloc(100).toString('base64'), firstHop: nodes[0].id } });
ok(wrongSize.status === 400, 'falsche Paketgröße abgelehnt');
const noHop = await api('/api/mix/inject', { method: 'POST',
  body: { packet: pkt.packet.toString('base64') } });
ok(noHop.status === 400, 'fehlender firstHop abgelehnt');

console.log('\nDummy-Verkehr über HTTP:');
const countEnvelopes = () => { const d = new DatabaseSync('./securechat.db', { readOnly: true });
  const n = d.prepare('SELECT COUNT(*) c FROM envelopes').get().c; d.close(); return n };
const envBefore = countEnvelopes();
const statsBefore = (await api('/api/mix/stats')).data;
const dummiesBefore = Object.values(statsBefore.nodes).reduce((a, n) => a + n.dummies, 0);
for (let i = 0; i < 4; i++) {
  const d = buildPacket(pickPath(), crypto.randomBytes(300), { dummy: true });
  await api('/api/mix/inject', { method: 'POST',
    body: { packet: d.packet.toString('base64'), firstHop: d.firstHop } });
}
await new Promise(r => setTimeout(r, 3000));
const statsAfter = (await api('/api/mix/stats')).data;
const dummiesAfter = Object.values(statsAfter.nodes).reduce((a, n) => a + n.dummies, 0);
ok(dummiesAfter > dummiesBefore, `${dummiesAfter - dummiesBefore} Dummy-Pakete verpufften im Netz`);
ok(countEnvelopes() === envBefore, 'Dummies haben keine einzige Nachricht erzeugt');

console.log('\nLastprobe — viele Absender gleichzeitig:');
const N = 10;
const before = (await api('/api/mix/stats')).data;
const beforeRecv = Object.values(before.nodes).reduce((a, n) => a + n.received, 0);
const sentAt = [];
for (let i = 0; i < N; i++) {
  const s = await sealEnvelope({ cert: certRes.data.certificate,
    header: { dh: A.IK.pubJwk, pn: 0, n: i + 1 },
    ciphertext: b64(te.encode('last-' + i)) }, B.device.ikDH);
  const pl = Buffer.from(JSON.stringify({ sealed: s, convId: 'dm_mix', recipientDeviceId: B.device.id }));
  const p = buildPacket(pickPath(), pl, { recipientId: B.user.id });
  sentAt.push({ i, at: Date.now() });
  await api('/api/mix/inject', { method: 'POST',
    body: { packet: p.packet.toString('base64'), firstHop: p.firstHop } });
  await new Promise(r => setTimeout(r, 20));
}
for (let i = 0; i < 80; i++) {
  await new Promise(r => setTimeout(r, 100));
  if (inbox.filter(m => m.viaMix).length >= N + 1) break;
}
const arrived = inbox.filter(m => m.viaMix);
ok(arrived.length === N + 1, `alle ${N} Nachrichten zugestellt`);

/* Reihenfolge am Ausgang gegen Reihenfolge am Eingang */
const order = [];
for (const m of arrived.slice(1)) {
  const o = await unsealEnvelope(m.ciphertext, B.IK);
  order.push(parseInt(td.decode(ub64(o.ciphertext)).split('-')[1], 10));
}
const inOrder = sentAt.map(x => x.i);
let samePos = 0;
for (let i = 0; i < N; i++) if (order[i] === inOrder[i]) samePos++;
console.log(`    Eingang : ${inOrder.join(' ')}`);
console.log(`    Ausgang : ${order.join(' ')}`);
ok(samePos < N, `Reihenfolge verändert — nur ${samePos} von ${N} an gleicher Position`);

const after = (await api('/api/mix/stats')).data;
const afterRecv = Object.values(after.nodes).reduce((a, n) => a + n.received, 0);
const perNode = Object.entries(after.nodes).map(([id, n]) => `${id}:${n.received}`);
console.log(`    Schichtöffnungen je Knoten: ${perNode.join('  ')}`);
ok(afterRecv - beforeRecv >= N * PATH_LENGTH, 'jede Nachricht lief über drei Knoten');
const maxNode = Math.max(...Object.values(after.nodes).map(n => n.received));
ok(maxNode < afterRecv, 'kein einzelner Knoten hat allen Verkehr gesehen');

wsB.sock.destroy();
console.log(`\n${pass} bestanden, ${fail} fehlgeschlagen`);
process.exit(fail ? 1 : 0);
