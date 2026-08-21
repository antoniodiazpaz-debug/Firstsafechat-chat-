/* Testet push.js: VAPID-Schlüsselerzeugung, JWT-Signatur (RFC 8292),
   und Web-Push-Verschlüsselung (RFC 8291) im vollen Rundlauf — eine
   simulierte Client-Seite entschlüsselt, was der Server verschlüsselt
   hat, und verifiziert die JWT-Signatur unabhängig gegen den
   öffentlichen Schlüssel. Reine Kryptologik, kein laufender Server nötig
   (siehe test-push.mjs für den Server-Integrationstest). */
import crypto from 'node:crypto';
const P = await import('./push.js');
const b64url = b => Buffer.from(b).toString('base64url');

let pass = 0, fail = 0;
const ok = (c, m) => { c ? (pass++, console.log('  ✓', m)) : (fail++, console.log('  ✗', m)) };

console.log('VAPID-Schlüsselerzeugung:');
const vapid = P.generateVapidKeys();
ok(typeof vapid.publicKey === 'string' && vapid.publicKey.length > 80, 'öffentlicher Schlüssel als base64url-String erzeugt');
const rawPub = Buffer.from(vapid.publicKey, 'base64url');
ok(rawPub.length === 65 && rawPub[0] === 0x04, 'Format ist unkomprimierter EC-Punkt (65 Byte, beginnt mit 0x04)');
ok(!!vapid.privateKeyJwk.d, 'privater Schlüssel enthält das geheime d-Feld');

console.log('\nVAPID-JWT (RFC 8292):');
const header = P.vapidHeader('https://push.example.com/abc123', vapid.privateKeyJwk, vapid.publicKey, 'mailto:test@example.com');
ok(header.startsWith('vapid t='), 'Header beginnt mit vapid-Schema');
const jwt = header.match(/t=([^,]+)/)[1];
const parts = jwt.split('.');
ok(parts.length === 3, 'JWT hat drei Teile');
const [h, p, s] = parts;
const headerJson = JSON.parse(Buffer.from(h, 'base64url').toString());
const payloadJson = JSON.parse(Buffer.from(p, 'base64url').toString());
ok(headerJson.alg === 'ES256', 'Algorithmus ES256');
ok(payloadJson.aud === 'https://push.example.com', 'aud-Claim ist Origin, nicht der volle Pfad');
ok(payloadJson.sub === 'mailto:test@example.com', 'sub-Claim korrekt');
ok(payloadJson.exp > Math.floor(Date.now() / 1000), 'exp-Claim liegt in der Zukunft');

console.log('\nJWT-Signatur unabhängig verifiziert:');
const pubKeyObj = crypto.createPublicKey({ key: vapid.publicKeyJwk, format: 'jwk' });
const sigBuf = Buffer.from(s, 'base64url');
ok(sigBuf.length === 64, 'JOSE-Signatur ist 64 Byte, nicht DER-kodiert');
function joseToDer(jose) {
  const r = jose.subarray(0, 32), sPart = jose.subarray(32, 64);
  const enc = v => { let b = v; while (b[0] === 0 && b.length > 1) b = b.subarray(1);
    if (b[0] & 0x80) b = Buffer.concat([Buffer.from([0]), b]);
    return Buffer.concat([Buffer.from([0x02, b.length]), b]); };
  const body = Buffer.concat([enc(r), enc(sPart)]);
  return Buffer.concat([Buffer.from([0x30, body.length]), body]);
}
const der = joseToDer(sigBuf);
const verified = crypto.verify('sha256', Buffer.from(h + '.' + p), { key: pubKeyObj, dsaEncoding: 'der' }, der);
ok(verified, 'Signatur verifiziert korrekt gegen den öffentlichen VAPID-Schlüssel');

console.log('\nWeb-Push-Verschlüsselung (RFC 8291) — voller Rundlauf:');
const clientKeys = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const clientPubRaw = clientKeys.publicKey.export({ type: 'spki', format: 'der' }).subarray(-65);
const authSecret = crypto.randomBytes(16);
const subscription = {
  endpoint: 'https://push.example.com/xyz',
  p256dh: Buffer.from(clientPubRaw).toString('base64url'),
  auth: authSecret.toString('base64url')
};
const plaintext = JSON.stringify({ type: 'new-message' });
const encrypted = await P.encryptPayload(Buffer.from(plaintext), subscription);
ok(encrypted.length > plaintext.length, 'verschlüsselte Nutzlast größer als Klartext');

const salt = encrypted.subarray(0, 16);
const rs = encrypted.readUInt32BE(16);
const keyidLen = encrypted[20];
const serverPub = encrypted.subarray(21, 21 + keyidLen);
ok(rs === 4096, 'Record-Size korrekt (4096)');
ok(keyidLen === 65, 'eingebetteter Server-Public-Key ist 65 Byte');

const serverPubKeyObj = crypto.createPublicKey({
  key: { kty: 'EC', crv: 'P-256', x: b64url(serverPub.subarray(1, 33)), y: b64url(serverPub.subarray(33, 65)) },
  format: 'jwk'
});
const sharedSecret = crypto.diffieHellman({ privateKey: clientKeys.privateKey, publicKey: serverPubKeyObj });
const prk = crypto.createHmac('sha256', authSecret).update(sharedSecret).digest();
const keyInfo = Buffer.concat([Buffer.from('WebPush: info\0'), clientPubRaw, serverPub]);
const ikm = crypto.createHmac('sha256', prk).update(Buffer.concat([keyInfo, Buffer.from([1])])).digest();
const prk2 = crypto.createHmac('sha256', salt).update(ikm).digest();
const cek = crypto.createHmac('sha256', prk2).update(Buffer.concat([Buffer.from('Content-Encoding: aes128gcm\0'), Buffer.from([1])])).digest().subarray(0, 16);
const nonce = crypto.createHmac('sha256', prk2).update(Buffer.concat([Buffer.from('Content-Encoding: nonce\0'), Buffer.from([1])])).digest().subarray(0, 12);

const body = encrypted.subarray(21 + keyidLen);
const ciphertext = body.subarray(0, body.length - 16);
const tag = body.subarray(body.length - 16);
const decipher = crypto.createDecipheriv('aes-128-gcm', cek, nonce);
decipher.setAuthTag(tag);
const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
const unpadded = decrypted.subarray(0, decrypted.length - 1);
ok(unpadded.toString() === plaintext, 'unabhängiger Client entschlüsselt exakt denselben Klartext');
ok(decrypted[decrypted.length - 1] === 0x02, 'Padding-Trennzeichen ist 0x02 (RFC 8188 letzter Record)');

console.log('\nManipulierter Ciphertext scheitert an der Authentifizierung:');
const tamperedBody = Buffer.from(body);
tamperedBody[5] ^= 0xff;
const tCiphertext = tamperedBody.subarray(0, tamperedBody.length - 16);
const tTag = tamperedBody.subarray(tamperedBody.length - 16);
let tamperCaught = false;
try {
  const d2 = crypto.createDecipheriv('aes-128-gcm', cek, nonce);
  d2.setAuthTag(tTag);
  Buffer.concat([d2.update(tCiphertext), d2.final()]);
} catch { tamperCaught = true; }
ok(tamperCaught, 'manipulierter Ciphertext bricht am GCM-Tag');

console.log('\nVerschiedene Nachrichten ergeben verschiedene Ciphertexte (Salt ist zufällig):');
const enc2 = await P.encryptPayload(Buffer.from(plaintext), subscription);
ok(!encrypted.equals(enc2), 'zwei Verschlüsselungen derselben Nachricht sind unterschiedlich (Salt-Randomisierung greift)');

console.log(`\n${pass} bestanden, ${fail} fehlgeschlagen`);
process.exit(fail ? 1 : 0);
