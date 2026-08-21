/* Testet die reinen Logikfunktionen aus public/app.js — Identitäts-
   Rekonstruktion aus dem Vault, Umschlag-Verarbeitung, sicheres
   Rendering — ohne echtes DOM/IndexedDB (minimale Mocks). */
import { installBrowserMocks } from './test-helpers/browser-mocks.mjs';
installBrowserMocks();

const SC = globalThis.crypto.subtle;
const M = await import('./public/app.js');

let pass = 0, fail = 0;
const ok = (c, m) => { c ? (pass++, console.log('  ✓', m)) : (fail++, console.log('  ✗', m)) };

console.log('Identitäts-Rekonstruktion aus dem Vault:');
const dhPair = await SC.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
const signPair = await SC.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
const spkPair = await SC.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
const opkPair = await SC.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);

const vaultData = {
  IK: await SC.exportKey('jwk', dhPair.privateKey),
  IKS: await SC.exportKey('jwk', signPair.privateKey),
  SPK: await SC.exportKey('jwk', spkPair.privateKey),
  opks: [[1, await SC.exportKey('jwk', opkPair.privateKey)]]
};

const identity = await M.reconstructIdentityFromVault(vaultData);
ok(!!identity.IK.priv && identity.IK.priv.type === 'private', 'IK-Privatschlüssel importiert und als solcher erkannt');
ok(!!identity.IKS.priv && identity.IKS.priv.type === 'private', 'IKS-Privatschlüssel importiert');
ok(!!identity.SPK.priv, 'SPK-Privatschlüssel importiert');
ok(identity.opks.size === 1, 'genau ein One-Time Prekey rekonstruiert');
ok(!identity.IK.pubJwk.d, 'öffentlicher JWK enthält KEINEN privaten Exponenten (d gelöscht)');
ok(!!identity.IK.pubJwk.x && !!identity.IK.pubJwk.y, 'öffentlicher JWK behält x/y-Koordinaten');

const otherPair = await SC.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
const shared1 = await SC.deriveBits({ name: 'ECDH', public: otherPair.publicKey }, identity.IK.priv, 256);
ok(shared1.byteLength === 32, 'rekonstruierter Schlüssel führt echtes ECDH durch (32 Byte Shared Secret)');

console.log('\nsk() — Sitzungsschlüssel-Bildung:');
ok(M.sk('u1', 'd1') === 'u1>d1', 'Format ist peerId>deviceId');
ok(M.sk('u1', 'd1') !== M.sk('u1', 'd2'), 'verschiedene Geräte desselben Peers ergeben verschiedene Schlüssel');

console.log('\nconvRow() — sicheres Rendering ohne echtes DOM:');
const row1 = M.convRow({ name: 'Anna', lastMsg: { text: 'Hallo', ts: Date.now() }, unread: 3 }, 0);
ok(row1.includes('Anna'), 'Name erscheint in der Zeile');
ok(row1.includes('3'), 'Unread-Zähler erscheint');
ok(row1.includes('window.__app.openConv(0)'), 'Klick-Handler mit korrektem Index');
const rowXss = M.convRow({ name: '<script>alert(1)</script>', lastMsg: null, unread: 0 }, 1);
ok(!rowXss.includes('<script>'), 'Name wird escaped — kein XSS über Kontaktnamen möglich');
ok(rowXss.includes('&lt;script&gt;'), 'escaped-Form ist vorhanden');

console.log('\nhandleEnvelope() — Umschlag ohne Sitzung fällt sichtbar aus, nicht still:');
M.state.me = { id: 'me' };
await M.handleEnvelope({
  id: 'e1', senderId: 'stranger', senderDeviceId: 'd-stranger',
  convId: 'dm_test', header: { dh: {}, pn: 0, n: 0 }, ciphertext: 'AAAA', sentAt: Date.now()
}, false);
const msgs = M.state.messages.get('dm_test');
ok(msgs && msgs.length === 1, 'Nachricht wird trotz fehlgeschlagener Entschlüsselung erfasst');
ok(msgs[0].text.includes('Nicht entschlüsselbar'), 'Fehlerzustand ist für den Nutzer sichtbar, kein stiller Datenverlust');
const conv = M.state.convs.get('dm_test');
ok(conv && conv.unread === 1, 'Konversation wird angelegt und als ungelesen markiert');

console.log(`\n${pass} bestanden, ${fail} fehlgeschlagen`);
process.exit(fail ? 1 : 0);
