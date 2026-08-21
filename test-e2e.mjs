/* End-to-End-Test gegen den laufenden Server.
   Zwei echte Clients, echte HTTP-Aufrufe, echte WebSockets,
   echtes X3DH + Double Ratchet. Der Server sieht nur Chiffrat. */
import { webcrypto as wc } from 'node:crypto';
import net from 'node:net';
import crypto from 'node:crypto';

const SC = wc.subtle, te = new TextEncoder(), td = new TextDecoder();
const BASE = 'http://127.0.0.1:8787';
const b64 = b => Buffer.from(new Uint8Array(b)).toString('base64');
const ub64 = s => new Uint8Array(Buffer.from(s, 'base64'));
const hexs = b => Buffer.from(new Uint8Array(b)).toString('hex');
const cat = (...as) => { const t = as.reduce((n, a) => n + a.byteLength, 0);
  const o = new Uint8Array(t); let p = 0;
  for (const a of as) { o.set(new Uint8Array(a), p); p += a.byteLength } return o.buffer };

let pass = 0, fail = 0;
const ok = (c, m) => { c ? (pass++, console.log('  ✓', m)) : (fail++, console.log('  ✗', m)) };

async function api(path, { method = 'GET', body, token } = {}) {
  const r = await fetch(BASE + path, {
    method,
    headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: 'Bearer ' + token } : {}) },
    body: body ? JSON.stringify(body) : undefined
  });
  return { status: r.status, data: await r.json() };
}

/*── Krypto-Primitive (wie im Client) ──*/
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
  async hmac(kb, d) { const k = await SC.importKey('raw', kb, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    return SC.sign('HMAC', k, d) },
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
  return { IK, IKS, SPK, spkMeta: { spkId: 1, createdAt, signature }, opks };
}
const bundlePayload = id => ({
  ikDH: id.IK.pubJwk, ikSign: id.IKS.pubJwk,
  spk: { spkId: 1, pub: id.SPK.pubJwk, signature: id.spkMeta.signature, createdAt: id.spkMeta.createdAt },
  opks: id.opks.map(o => ({ opkId: o.opkId, pub: o.key.pubJwk }))
});

/*── Double Ratchet ──*/
const R = {
  async kdfRK(RK, dh) { const o = await P.hkdf(dh, new Uint8Array(RK), 'SecureChat-RootRatchet-v1', 64);
    return [o.slice(0, 32), o.slice(32, 64)] },
  async kdfCK(CK) { return [await P.hmac(CK, new Uint8Array([1])), await P.hmac(CK, new Uint8Array([2]))] },
  async mk(MK) { const o = await P.hkdf(MK, new Uint8Array(32), 'SecureChat-MessageKey-v1', 44);
    return { key: o.slice(0, 32), iv: o.slice(32, 44) } },
  async initSender(SK, spkJwk) {
    const DHs = await P.genDH(), DHr = await P.impPub(spkJwk);
    const [RK, CKs] = await R.kdfRK(SK, await P.dh(DHs.priv, DHr));
    return { RK, DHs, DHrJwk: spkJwk, DHr, CKs, CKr: null, Ns: 0, Nr: 0, PN: 0, skipped: new Map(), steps: 1 } },
  initReceiver(SK, SPK) {
    return { RK: SK, DHs: SPK, DHrJwk: null, DHr: null, CKs: null, CKr: null,
      Ns: 0, Nr: 0, PN: 0, skipped: new Map(), steps: 0 } },
  async encrypt(st, buf, aad) {
    const [MK, CK2] = await R.kdfCK(st.CKs); st.CKs = CK2;
    const header = { dh: st.DHs.pubJwk, pn: st.PN, n: st.Ns }; st.Ns++;
    const { key, iv } = await R.mk(MK);
    return { header, ct: b64(await P.seal(key, iv, buf, aad + '|' + JSON.stringify(header))) } },
  async decrypt(st, msg, aad) {
    const sk = msg.header.dh.x + ':' + msg.header.n;
    if (st.skipped.has(sk)) { const MK = st.skipped.get(sk); st.skipped.delete(sk); return R.open(MK, msg, aad) }
    if (!st.DHrJwk || msg.header.dh.x !== st.DHrJwk.x) { await R.skip(st, msg.header.pn); await R.step(st, msg.header.dh) }
    await R.skip(st, msg.header.n);
    const [MK, CK2] = await R.kdfCK(st.CKr); st.CKr = CK2; st.Nr++;
    return R.open(MK, msg, aad) },
  async open(MK, msg, aad) { const { key, iv } = await R.mk(MK);
    return P.open(key, iv, ub64(msg.ct), aad + '|' + JSON.stringify(msg.header)) },
  async skip(st, until) { if (!st.CKr) return;
    while (st.Nr < until) { const [MK, CK2] = await R.kdfCK(st.CKr);
      st.skipped.set(st.DHrJwk.x + ':' + st.Nr, MK); st.CKr = CK2; st.Nr++ } },
  async step(st, theirJwk) {
    st.PN = st.Ns; st.Ns = 0; st.Nr = 0; st.DHrJwk = theirJwk; st.DHr = await P.impPub(theirJwk);
    [st.RK, st.CKr] = await R.kdfRK(st.RK, await P.dh(st.DHs.priv, st.DHr));
    st.DHs = await P.genDH();
    [st.RK, st.CKs] = await R.kdfRK(st.RK, await P.dh(st.DHs.priv, st.DHr));
    st.steps++ }
};

/*── Merkle-Verifikation clientseitig ──*/
const sha = b => new Uint8Array(crypto.createHash('sha256').update(Buffer.from(b)).digest());
const nodeH = (l, r) => sha(Buffer.concat([Buffer.from([1]), Buffer.from(l), Buffer.from(r)]));
const leafH = d => sha(Buffer.concat([Buffer.from([0]), Buffer.from(d)]));
function verifyInclusion(leaf, index, size, path, root) {
  if (index >= size) return false;
  let fn = index, sn = size - 1, r = leaf;
  for (const p of path) {
    if (sn === 0) return false;
    if (fn % 2 === 1 || fn === sn) { r = nodeH(p, r); while (fn % 2 === 0 && fn !== 0) { fn >>= 1; sn >>= 1 } }
    else r = nodeH(r, p);
    fn >>= 1; sn >>= 1;
  }
  return sn === 0 && Buffer.from(r).equals(Buffer.from(root));
}

/*── Minimaler WebSocket-Client ──*/
function wsConnect(token, onMsg) {
  return new Promise((resolve, reject) => {
    const key = crypto.randomBytes(16).toString('base64');
    const sock = net.connect(8787, '127.0.0.1', () => {
      sock.write(`GET /?token=${token} HTTP/1.1\r\nHost: 127.0.0.1:8787\r\n` +
        `Upgrade: websocket\r\nConnection: Upgrade\r\n` +
        `Sec-WebSocket-Key: ${key}\r\nSec-WebSocket-Version: 13\r\n\r\n`);
    });
    let handshook = false, buf = Buffer.alloc(0);
    sock.on('data', chunk => {
      buf = Buffer.concat([buf, chunk]);
      if (!handshook) {
        const i = buf.indexOf('\r\n\r\n');
        if (i < 0) return;
        const head = buf.subarray(0, i).toString();
        if (!head.includes('101')) { reject(new Error('Upgrade fehlgeschlagen')); return }
        handshook = true; buf = buf.subarray(i + 4); resolve({ sock, send });
      }
      for (;;) {
        if (buf.length < 2) return;
        let len = buf[1] & 0x7f, off = 2;
        if (len === 126) { if (buf.length < 4) return; len = buf.readUInt16BE(2); off = 4 }
        else if (len === 127) { if (buf.length < 10) return; len = Number(buf.readBigUInt64BE(2)); off = 10 }
        if (buf.length < off + len) return;
        const payload = buf.subarray(off, off + len).toString();
        buf = buf.subarray(off + len);
        try { onMsg(JSON.parse(payload)) } catch {}
      }
    });
    sock.on('error', reject);
    function send(obj) {
      const data = Buffer.from(JSON.stringify(obj));
      const mask = crypto.randomBytes(4);
      const masked = Buffer.from(data); for (let i = 0; i < masked.length; i++) masked[i] ^= mask[i % 4];
      let head;
      if (data.length < 126) { head = Buffer.from([0x81, 0x80 | data.length]) }
      else { head = Buffer.alloc(4); head[0] = 0x81; head[1] = 0x80 | 126; head.writeUInt16BE(data.length, 2) }
      sock.write(Buffer.concat([head, mask, masked]));
    }
  });
}

/*═══════════════════ TESTS ═══════════════════*/
/*═══════════════════ TESTS ═══════════════════*/
console.log('Server erreichbar:');
const health = await api('/api/health');
ok(health.status === 200 && health.data.ok, `Health OK (Log: ${health.data.logSize} Einträge)`);

console.log('\nRegistrierung (legt automatisch das primäre Gerät an):');
const aliceId = await makeIdentity(), bobId = await makeIdentity();
const aliceName = 'Alice_' + Date.now().toString(36);
const bobName = 'Bob_' + Date.now().toString(36);
const ra = await api('/api/register', { method: 'POST',
  body: { name: aliceName, password: 'passwort123', deviceName: 'Alice-Handy', platform: 'android',
    ...bundlePayload(aliceId) } });
ok(ra.status === 201 && ra.data.token, 'Alice registriert, Token erhalten');
ok(ra.data.device && ra.data.device.isPrimary, 'primäres Gerät automatisch angelegt');
const rb = await api('/api/register', { method: 'POST',
  body: { name: bobName, password: 'passwort456', deviceName: 'Bob-Laptop', platform: 'web',
    ...bundlePayload(bobId) } });
ok(rb.status === 201, 'Bob registriert');
const A = { token: ra.data.token, id: ra.data.user.id, deviceId: ra.data.device.id, ...aliceId };
const B = { token: rb.data.token, id: rb.data.user.id, deviceId: rb.data.device.id, ...bobId };
ok(ra.data.sth.size >= 1 || rb.data.sth.size >= 1, 'Identitäten im Transparenz-Log');

const dup = await api('/api/register', { method: 'POST',
  body: { name: aliceName, password: 'x'.repeat(9), deviceName: 'x', platform: 'web',
    ...bundlePayload(aliceId) } });
ok(dup.status === 409, 'doppelter Name wird abgelehnt');

console.log('\nAuthentifizierung:');
const badLogin = await api('/api/login', { method: 'POST', body: { name: aliceName, password: 'falsch' } });
ok(badLogin.status === 401, 'falsches Passwort abgelehnt');
const loginNoDevice = await api('/api/login', { method: 'POST', body: { name: aliceName, password: 'passwort123' } });
ok(loginNoDevice.status === 428 && loginNoDevice.data.needsPairing,
  'Login ohne bekanntes Gerät verlangt Pairing statt stillschweigend ein neues Gerät zu akzeptieren');
const goodLogin = await api('/api/login', { method: 'POST',
  body: { name: aliceName, password: 'passwort123', deviceId: A.deviceId } });
ok(goodLogin.status === 200 && goodLogin.data.token, 'Login mit bekanntem Gerät liefert Token');
const noAuth = await api('/api/me');
ok(noAuth.status === 401, 'Endpunkt ohne Token gesperrt');
const withAuth = await api('/api/me', { token: A.token });
ok(withAuth.status === 200 && withAuth.data.user.name === aliceName, 'authentifizierter Abruf funktioniert');
ok(withAuth.data.devices.length === 1, '/api/me listet die eigenen Geräte');

console.log('\nMulti-Device: zweites Gerät per Pairing:');
const pairReq = await api('/api/devices/pair-request', { method: 'POST', token: A.token });
ok(pairReq.status === 200 && !!pairReq.data.code, 'Hauptgerät erzeugt Pairing-Code');
const aliceLaptopId = await makeIdentity();
const claim = await api('/api/devices/pair-claim', { method: 'POST', body: {
  code: pairReq.data.code, deviceName: 'Alice-Laptop', platform: 'web', ...bundlePayload(aliceLaptopId) } });
ok(claim.status === 201, 'zweites Gerät erfolgreich gepaart');
const A2 = { token: claim.data.token, deviceId: claim.data.device.id, ...aliceLaptopId };
ok(A2.deviceId !== A.deviceId, 'zweites Gerät hat eine andere Geräte-ID');
ok(!claim.data.device.isPrimary, 'zweites Gerät ist nicht primär');
const usedCode = await api('/api/devices/pair-claim', { method: 'POST', body: {
  code: pairReq.data.code, deviceName: 'x', platform: 'web', ...bundlePayload(await makeIdentity()) } });
ok(usedCode.status === 410, 'derselbe Pairing-Code kann nicht zweimal benutzt werden');

const deviceList = await api('/api/devices', { token: A.token });
ok(deviceList.data.devices.length === 2, 'Alice hat jetzt 2 aktive Geräte');

console.log('\nPrekey-Bundle vom Server (liefert ALLE Geräte des Nutzers):');
const bres = await api('/api/bundle?user=' + A.id, { token: B.token });
ok(bres.status === 200 && Array.isArray(bres.data.bundles), 'Bundle-Liste abgerufen');
ok(bres.data.bundles.length === 2, 'Bundle enthält beide Geräte von Alice: ' + bres.data.bundles.length);
const bundlePrimary = bres.data.bundles.find(x => x.isPrimary);
const bundleSecondary = bres.data.bundles.find(x => !x.isPrimary);
ok(!!bundlePrimary && !!bundleSecondary, 'primäres und sekundäres Gerät klar unterscheidbar');
ok(bundlePrimary.opkId !== null, 'One-Time Prekey für das primäre Gerät ausgegeben');
const before = bundlePrimary.opksLeft;
const bres2 = await api('/api/bundle?user=' + A.id, { token: B.token });
const bundlePrimary2 = bres2.data.bundles.find(x => x.isPrimary);
ok(bundlePrimary2.opkId !== bundlePrimary.opkId, 'zweiter Abruf liefert anderen OPK für dasselbe Gerät');
ok(bundlePrimary2.opksLeft === before - 1, 'Pool des primären Geräts wird korrekt heruntergezählt');

const gezielt = await api('/api/bundle?user=' + A.id + '&device=' + A.deviceId, { token: B.token });
ok(gezielt.data.bundles.length === 1 && gezielt.data.bundles[0].deviceId === A.deviceId,
  'gezielte Abfrage nach einem Gerät liefert nur dieses eine');

console.log('\nSignaturprüfung des Bundles:');
const vpub = await P.impVerify(bundlePrimary.ikSign);
const sigOk = await P.verify(vpub, ub64(bundlePrimary.spkSig),
  sigData(bundlePrimary.ikDH, bundlePrimary.spk, bundlePrimary.spkId, bundlePrimary.spkCreatedAt));
ok(sigOk, 'Signed Prekey des primären Geräts trägt gültige Signatur');
const tampered = { ...bundlePrimary, spk: (await P.genDH()).pubJwk };
const sigBad = await P.verify(vpub, ub64(tampered.spkSig),
  sigData(tampered.ikDH, tampered.spk, tampered.spkId, tampered.spkCreatedAt));
ok(!sigBad, 'ausgetauschter Prekey bricht die Signatur');

console.log('\nKey-Transparency-Beweis (über den NUTZER, nicht das Gerät):');
const kt = bres.data.kt;
ok(!!kt, 'Server liefert Inklusionsbeweis mit');
const entryBytes = te.encode(['kt-v1', kt.entry.userId, kt.entry.keyX, kt.entry.keyY, kt.entry.version].join('|'));
const incOk = verifyInclusion(leafH(entryBytes), kt.index, kt.sth.size,
  kt.path.map(p => ub64(p)), ub64(kt.sth.root));
ok(incOk, 'Inklusionsbeweis verifiziert gegen die Wurzel');
ok(kt.entry.keyX === bundlePrimary.ikDH.x, 'Log-Eintrag deckt sich mit dem Schlüssel des PRIMÄREN Geräts');
const badInc = verifyInclusion(leafH(te.encode('gefälscht')), kt.index, kt.sth.size,
  kt.path.map(p => ub64(p)), ub64(kt.sth.root));
ok(!badInc, 'fremder Eintrag scheitert am Beweis');

console.log('\nSTH und Witnesses:');
const sthRes = await api('/api/kt/sth');
ok(sthRes.data.sth.cosigs.length >= 2, `${sthRes.data.sth.cosigs.length} Witness-Mitunterschriften`);
const logPub = await SC.importKey('jwk', sthRes.data.logKey, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']);
const sth = sthRes.data.sth;
const sthOk = await P.verify(logPub, ub64(sth.sig),
  te.encode(['sth-v1', sth.size, hexs(ub64(sth.root)), sth.ts].join('|')));
ok(sthOk, 'STH-Signatur des Servers gültig');
let cosigValid = 0;
for (const c of sth.cosigs) {
  const wp = await SC.importKey('jwk', c.jwk, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']);
  if (await P.verify(wp, ub64(c.sig),
      te.encode(['witness-v1', c.witness, sth.size, hexs(ub64(sth.root))].join('|')))) cosigValid++;
}
ok(cosigValid === sth.cosigs.length, `alle ${cosigValid} Mitunterschriften verifizieren`);

console.log('\nKonsistenzbeweis:');
const cons = await api('/api/kt/consistency?from=1');
ok(cons.status === 200 && Array.isArray(cons.data.proof), 'Konsistenzbeweis abrufbar');
ok(cons.data.to >= cons.data.from, 'Log ist nicht geschrumpft');

console.log('\nX3DH über den Server (gegen das PRIMÄRE Gerät von Alice):');
const EK = await P.genDH();
const dh1 = await P.dh(B.IK.priv, await P.impPub(bundlePrimary.spk));
const dh2 = await P.dh(EK.priv, await P.impPub(bundlePrimary.ikDH));
const dh3 = await P.dh(EK.priv, await P.impPub(bundlePrimary.spk));
const dh4 = bundlePrimary.opk ? await P.dh(EK.priv, await P.impPub(bundlePrimary.opk)) : new ArrayBuffer(0);
const SK = await P.hkdf(cat(dh1, dh2, dh3, dh4), null, 'SecureChat-X3DH-v1');
const usedOpk = A.opks.find(o => o.opkId === bundlePrimary.opkId);
const d1 = await P.dh(A.SPK.priv, await P.impPub(B.IK.pubJwk));
const d2 = await P.dh(A.IK.priv, await P.impPub(EK.pubJwk));
const d3 = await P.dh(A.SPK.priv, await P.impPub(EK.pubJwk));
const d4 = usedOpk ? await P.dh(usedOpk.key.priv, await P.impPub(EK.pubJwk)) : new ArrayBuffer(0);
const SK2 = await P.hkdf(cat(d1, d2, d3, d4), null, 'SecureChat-X3DH-v1');
ok(hexs(SK) === hexs(SK2), 'beide Seiten leiten dasselbe Startgeheimnis ab');

console.log('\nWebSocket und Fanout-Zustellung an BEIDE Geräte:');
const inboxPrimary = [], inboxSecondary = [];
const wsAPrimary = await wsConnect(A.token, m => inboxPrimary.push(m));
const wsASecondary = await wsConnect(A2.token, m => inboxSecondary.push(m));
await new Promise(r => setTimeout(r, 250));
ok(inboxPrimary.some(m => m.type === 'ready'), 'primäres Gerät per WebSocket verbunden');
ok(inboxSecondary.some(m => m.type === 'ready'), 'sekundäres Gerät per WebSocket verbunden');

const aStPrimary = await R.initSender(SK, bundlePrimary.spk);
const bStPrimary = R.initReceiver(SK2, A.SPK);
const AADPrimary = `v1|${B.id}|dm_test`;
const env1 = await R.encrypt(aStPrimary, te.encode('Hallo Alice, auf beiden Geräten!'), AADPrimary);

/* Realistischer Fanout: Bob verschlüsselt getrennt für jedes Gerät.
   Für das sekundäre Gerät bräuchte er einen eigenen Ratchet-Zustand;
   hier reicht zum Testen des Transportwegs ein zweites, unabhängiges
   Chiffrat mit demselben Klartext. */
const dh1b = await P.dh(B.IK.priv, await P.impPub(bundleSecondary.spk));
const dh2b = await P.dh(EK.priv, await P.impPub(bundleSecondary.ikDH));
const dh3b = await P.dh(EK.priv, await P.impPub(bundleSecondary.spk));
const SKb = await P.hkdf(cat(dh1b, dh2b, dh3b, new ArrayBuffer(0)), null, 'SecureChat-X3DH-v1');
const aStSecondary = await R.initSender(SKb, bundleSecondary.spk);
const env2 = await R.encrypt(aStSecondary, te.encode('Hallo Alice, auf beiden Geräten!'), `v1|${B.id}|dm_test`);

const send1 = await api('/api/send', { method: 'POST', token: B.token,
  body: { recipientId: A.id, convId: 'dm_test',
    perDevice: [
      { deviceId: A.deviceId, header: env1.header, ciphertext: env1.ct },
      { deviceId: A2.deviceId, header: env2.header, ciphertext: env2.ct }
    ] } });
ok(send1.status === 200 && send1.data.results.length === 2, 'ein Send-Aufruf erzeugt 2 Umschläge (Fanout)');
ok(send1.data.results.every(r => r.delivered), 'beide sofort zugestellt, weil beide Geräte online sind');

await new Promise(r => setTimeout(r, 300));
const gotPrimary = inboxPrimary.find(m => m.type === 'envelope');
const gotSecondary = inboxSecondary.find(m => m.type === 'envelope');
ok(!!gotPrimary, 'primäres Gerät hat seinen eigenen Umschlag bekommen');
ok(!!gotSecondary, 'sekundäres Gerät hat seinen eigenen Umschlag bekommen');
const plain1 = td.decode(await R.decrypt(bStPrimary, { header: gotPrimary.header, ct: gotPrimary.ciphertext }, AADPrimary));
ok(plain1 === 'Hallo Alice, auf beiden Geräten!', 'primäres Gerät entschlüsselt korrekt');
console.log('    →', plain1);

console.log('\nServer sieht keinen Klartext:');
ok(!gotPrimary.ciphertext.includes('Hallo'), 'Chiffrat enthält keinen erkennbaren Klartext');
const rows = await api('/api/inbox', { token: A2.token });
ok(!JSON.stringify(rows.data).includes('Hallo Alice'), 'auch die Serverantwort enthält keinen Klartext');

/* Live per WebSocket zugestellte Umschläge bleiben in der DB als
   unquittiert stehen, bis der Client sie bestätigt — genau wie im echten
   Client-Code (ack läuft dort im WebSocket-Handler). Ohne diese
   Quittierung würde der spätere Isolations-Test auf dieser alten,
   längst zugestellten Nachricht aufsetzen und fälschlich ein Leck
   zwischen den Geräte-Inboxen vermuten lassen. */
wsAPrimary.send({ type: 'ack', ids: [gotPrimary.id] });
wsASecondary.send({ type: 'ack', ids: [gotSecondary.id] });
await new Promise(r => setTimeout(r, 200));

console.log('\nStore-and-Forward (ein Gerät offline):');
const env3 = await R.encrypt(aStPrimary, te.encode('Nachricht während Laptop offline ist'), AADPrimary);
wsASecondary.sock.destroy();
await new Promise(r => setTimeout(r, 500));
const send2 = await api('/api/send', { method: 'POST', token: B.token,
  body: { recipientId: A.id, convId: 'dm_test',
    perDevice: [{ deviceId: A2.deviceId, header: env3.header, ciphertext: env3.ct }] } });
ok(send2.status === 200 && !send2.data.results[0].delivered, 'offline: Nachricht wird zwischengespeichert');
const inbox2 = await api('/api/inbox', { token: A2.token });
ok(inbox2.data.envelopes.length >= 1, 'Nachricht liegt in der Inbox des offline-Geräts bereit');
/* Primäres Gerät bekommt NICHTS von dieser Nachricht — sie war gezielt
   nur an das sekundäre Gerät adressiert. Das ist der Kern des
   Fanout-Modells: jedes Gerät hat seine eigene, unabhängige Warteschlange. */
const inboxPrimaryCheck = await api('/api/inbox', { token: A.token });
ok(inboxPrimaryCheck.data.envelopes.length === 0,
  'primäres Gerät hat KEINE der an das sekundäre Gerät gerichteten Nachrichten');

console.log('\nGeräte-Widerruf:');
const revoke = await api('/api/devices/revoke', { method: 'POST', token: A.token,
  body: { deviceId: A2.deviceId } });
ok(revoke.status === 200, 'Hauptgerät kann Zweitgerät entfernen');
const meRevoked = await api('/api/me', { token: A2.token });
ok(meRevoked.status === 401, 'widerrufenes Gerät ist nicht mehr angemeldet');
const devicesAfter = await api('/api/devices', { token: A.token });
ok(devicesAfter.data.devices.length === 1, 'nur noch 1 aktives Gerät gelistet');
const lastPrimaryRevoke = await api('/api/devices/revoke', { method: 'POST', token: A.token,
  body: { deviceId: A.deviceId } });
ok(lastPrimaryRevoke.status === 400, 'letztes Hauptgerät kann nicht entfernt werden — Konto bliebe unzugänglich');

console.log('\nBlockieren:');
const block = await api('/api/block', { method: 'POST', token: A.token, body: { userId: B.id } });
ok(block.status === 200, 'Blockieren erfolgreich');
const blockedList = await api('/api/blocks', { token: A.token });
ok(blockedList.data.blocked.includes(B.id), 'blockierter Nutzer erscheint in der Liste');
const blockedSend = await api('/api/send', { method: 'POST', token: B.token,
  body: { recipientId: A.id, convId: 'dm_test',
    perDevice: [{ deviceId: A.deviceId, header: env1.header, ciphertext: env1.ct }] } });
ok(blockedSend.status === 403, 'Versand von blockiertem Nutzer wird serverseitig abgelehnt');
const blockedBundle = await api('/api/bundle?user=' + A.id, { token: B.token });
ok(blockedBundle.status === 403, 'auch der Bundle-Abruf ist gesperrt');
const unblock = await api('/api/unblock', { method: 'POST', token: A.token, body: { userId: B.id } });
ok(unblock.status === 200, 'Entblocken erfolgreich');
const afterUnblock = await api('/api/bundle?user=' + A.id, { token: B.token });
ok(afterUnblock.status === 200, 'nach Entblocken wieder erreichbar');

console.log('\nMelden:');
const report = await api('/api/report', { method: 'POST', token: A.token,
  body: { reportedId: B.id, convId: 'dm_test', reason: 'spam', note: 'testweise' } });
ok(report.status === 200 && !!report.data.id, 'Meldung ohne Inhalt erfolgreich abgesetzt');
const reportWithContent = await api('/api/report', { method: 'POST', token: A.token,
  body: { reportedId: B.id, reason: 'harassment', includedContent: plain1 } });
ok(reportWithContent.status === 200, 'Meldung MIT ausdrücklich beigefügtem Inhalt ebenfalls möglich');
const missingReason = await api('/api/report', { method: 'POST', token: A.token, body: { reportedId: B.id } });
ok(missingReason.status === 400, 'Meldung ohne Grund wird abgelehnt');

console.log('\nRichtungswechsel über den Server:');
const rev = await R.encrypt(bStPrimary, te.encode('Antwort von Alice'), `v1|${A.id}|dm_test`);
ok(bStPrimary.steps === 1, 'Alice-Client hat einen DH-Ratchet-Schritt gemacht');
const sendRev = await api('/api/send', { method: 'POST', token: A.token,
  body: { recipientId: B.id, convId: 'dm_test',
    perDevice: [{ deviceId: B.deviceId, header: rev.header, ciphertext: rev.ct }] } });
ok(sendRev.status === 200, 'Antwort angenommen');
const backB = td.decode(await R.decrypt(aStPrimary, { header: rev.header, ct: rev.ct }, `v1|${A.id}|dm_test`));
ok(backB === 'Antwort von Alice', 'Bob entschlüsselt die Antwort');
ok(aStPrimary.steps === 2, 'Bob-Client ratchet ebenfalls weiter');

console.log('\nPrekeys nachfüllen (pro Gerät):');
const more = [];
for (let i = 11; i <= 20; i++) more.push({ opkId: i, pub: (await P.genDH()).pubJwk });
const refill = await api('/api/prekeys', { method: 'POST', token: B.token, body: { opks: more } });
ok(refill.data.added === 10 && refill.data.available > 10, `Pool aufgefüllt auf ${refill.data.available}`);

console.log('\nIdentitätsrotation nur durchs Hauptgerät:');
const newIK = await P.genDH();
const sizeBefore = (await api('/api/kt/sth')).data.sth.size;
const rot = await api('/api/rotate-identity', { method: 'POST', token: B.token, body: { ikDH: newIK.pubJwk } });
ok(rot.data.sth.size === sizeBefore + 1, 'Log ist um einen Eintrag gewachsen');
const hist = await api('/api/kt/history?user=' + B.id);
ok(hist.data.entries.length === 2, 'Historie zeigt beide Versionen');
ok(hist.data.entries[1].keyX === newIK.pubJwk.x, 'neue Version trägt den neuen Schlüssel');

console.log('\nGruppen:');
const grp = await api('/api/group', { method: 'POST', token: A.token,
  body: { name: 'Testgruppe', members: [B.id], wrapped: { [A.id]: 'wrappedA', [B.id]: 'wrappedB' } } });
ok(grp.status === 201 && grp.data.groupId, 'Gruppe angelegt');
const gl = await api('/api/groups', { token: B.token });
ok(gl.data.groups.length === 1 && gl.data.groups[0].wrapped === 'wrappedB',
  'Bob sieht die Gruppe mit seinem eigenen verpackten Schlüssel');

console.log('\nPräsenz (aggregiert über alle Geräte des Nutzers):');
/* Bob verbindet sich erst jetzt per WebSocket — isOnline() spiegelt den
   echten Verbindungsstatus wider, nicht bloß "Konto existiert". */
const bobInbox = [];
const wsB = await wsConnect(B.token, m => bobInbox.push(m));
await new Promise(r => setTimeout(r, 250));
const meB = await api('/api/me', { token: B.token });
ok(meB.data.user.online === true, 'Bob wird als online geführt, nachdem er sich verbunden hat');
wsAPrimary.sock.destroy();
wsB.sock.destroy();
await new Promise(r => setTimeout(r, 300));
const meA2 = await api('/api/users', { token: B.token });
const aliceRow = meA2.data.users.find(x => x.id === A.id);
ok(aliceRow.online === false, 'Alice ist offline, sobald ihr letztes verbundenes Gerät trennt');

console.log(`\n${pass} bestanden, ${fail} fehlgeschlagen`);
process.exit(fail ? 1 : 0);
