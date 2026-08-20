/* ═══════════════════════════════════════════════════════════════════════
   PUSH — Web Push (RFC 8291/8292) und FCM HTTP v1, ohne npm-Abhängigkeiten
   ─────────────────────────────────────────────────────────────────────
   Reines node:crypto. Kein "web-push"-Paket, kein "firebase-admin" —
   passend zum Zero-Dependency-Prinzip des restlichen Projekts.

   WICHTIG: Die frühere FCM-Implementierung nutzte die Legacy-HTTP-API
   (fcm.googleapis.com/fcm/send mit statischem Server-Key). Diese wurde
   von Google Mitte 2024 endgültig abgeschaltet — der alte Code hätte in
   der Praxis nie funktioniert. FCM HTTP v1 verlangt stattdessen ein
   kurzlebiges OAuth2-Zugriffstoken, das aus einem Service-Account-JSON
   selbst signiert wird (kein externer Auth-Server-Aufruf nötig, die
   Signatur macht node:crypto).
   ═══════════════════════════════════════════════════════════════════════ */
const crypto = require('node:crypto');

const b64url = buf => Buffer.from(buf).toString('base64url');
const ub64url = s => Buffer.from(s, 'base64url');

/* ─────────────────────────────────────────────────────────────────────
   VAPID-Schlüssel erzeugen (einmalig, dann dauerhaft speichern)
───────────────────────────────────────────────────────────────────── */
function generateVapidKeys() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const pubJwk = publicKey.export({ format: 'jwk' });
  const privJwk = privateKey.export({ format: 'jwk' });
  /* Unkomprimierter Punkt (0x04 ‖ x ‖ y) — das Format, das der Browser
     als applicationServerKey für pushManager.subscribe() erwartet. */
  const rawPublic = Buffer.concat([Buffer.from([0x04]), ub64url(pubJwk.x), ub64url(pubJwk.y)]);
  return {
    publicKey: b64url(rawPublic),          // an den Client geben
    privateKeyJwk: privJwk,                 // geheim, nur Server
    publicKeyJwk: pubJwk
  };
}

/* ─────────────────────────────────────────────────────────────────────
   VAPID-JWT (RFC 8292): ES256, signiert mit dem VAPID-Privatschlüssel
───────────────────────────────────────────────────────────────────── */
function vapidHeader(endpoint, vapidPrivateJwk, vapidPublicKey, subject) {
  const url = new URL(endpoint);
  const aud = `${url.protocol}//${url.host}`;
  const header = { typ: 'JWT', alg: 'ES256' };
  const payload = { aud, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: subject };
  const signingInput = b64url(JSON.stringify(header)) + '.' + b64url(JSON.stringify(payload));

  const key = crypto.createPrivateKey({ key: vapidPrivateJwk, format: 'jwk' });
  /* ECDSA liefert von node:crypto standardmäßig DER-kodiert — JWS
     verlangt aber die rohe r‖s-Verkettung (je 32 Byte für P-256). */
  const derSig = crypto.sign('sha256', Buffer.from(signingInput), { key, dsaEncoding: 'der' });
  const jose = derToJose(derSig, 32);
  const jwt = signingInput + '.' + b64url(jose);

  return `vapid t=${jwt}, k=${vapidPublicKey}`;
}

/* DER-ECDSA-Signatur → JOSE (rohe r‖s-Verkettung), RFC 7515 §A.3 */
function derToJose(der, len) {
  let offset = 2; // SEQUENCE-Tag + Länge überspringen
  function readInt() {
    if (der[offset] !== 0x02) throw new Error('Erwarte INTEGER-Tag in DER-Signatur');
    offset++;
    let l = der[offset++];
    let v = der.subarray(offset, offset + l);
    offset += l;
    if (v[0] === 0x00) v = v.subarray(1);      // führende Null bei negativem Bit entfernen
    return Buffer.concat([Buffer.alloc(Math.max(0, len - v.length)), v]);
  }
  const r = readInt(), s = readInt();
  return Buffer.concat([r, s]);
}

/* ─────────────────────────────────────────────────────────────────────
   Web-Push-Verschlüsselung (RFC 8291, aes128gcm)
───────────────────────────────────────────────────────────────────── */
async function encryptPayload(payloadBuf, subscription) {
  const userPublic = ub64url(subscription.p256dh);   // 65 Byte, unkomprimierter Punkt
  const userAuth = ub64url(subscription.auth);        // 16 Byte

  const localKeys = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const localPublicRaw = localKeys.publicKey.export({ type: 'spki', format: 'der' }).subarray(-65);

  const userKeyObj = crypto.createPublicKey({
    key: { kty: 'EC', crv: 'P-256', x: b64url(userPublic.subarray(1, 33)), y: b64url(userPublic.subarray(33, 65)) },
    format: 'jwk'
  });
  const sharedSecret = crypto.diffieHellman({ privateKey: localKeys.privateKey, publicKey: userKeyObj });

  const salt = crypto.randomBytes(16);

  /* PRK = HMAC-SHA256(auth_secret, ecdh_secret) — RFC 8291 §3.3 */
  const prk = crypto.createHmac('sha256', userAuth).update(sharedSecret).digest();

  /* key_info = "WebPush: info" ‖ 0x00 ‖ ua_public ‖ as_public */
  const keyInfo = Buffer.concat([
    Buffer.from('WebPush: info\0'), userPublic, localPublicRaw
  ]);
  const ikm = hkdfExpand(prk, keyInfo, 32);

  const cekInfo = Buffer.from('Content-Encoding: aes128gcm\0');
  const cek = hkdfExpandFrom(ikm, salt, cekInfo, 16);
  const nonceInfo = Buffer.from('Content-Encoding: nonce\0');
  const nonce = hkdfExpandFrom(ikm, salt, nonceInfo, 12);

  /* aes128gcm-Record: Padding-Trennzeichen 0x02 anhängen (letzter/
     einziger Record, RFC 8188), dann AES-128-GCM verschlüsseln. */
  const padded = Buffer.concat([payloadBuf, Buffer.from([0x02])]);
  const cipher = crypto.createCipheriv('aes-128-gcm', cek, nonce);
  const ciphertext = Buffer.concat([cipher.update(padded), cipher.final()]);
  const tag = cipher.getAuthTag();

  /* Header: salt(16) ‖ rs(4, big-endian) ‖ keyid-Länge(1) ‖ keyid(65) */
  const rs = Buffer.alloc(4); rs.writeUInt32BE(4096);
  const header = Buffer.concat([salt, rs, Buffer.from([localPublicRaw.length]), localPublicRaw]);

  return Buffer.concat([header, ciphertext, tag]);
}

/* HKDF-Extract+Expand in einem Schritt für die äußere Ableitung */
function hkdfExpand(prk, info, len) {
  const t1 = crypto.createHmac('sha256', prk).update(Buffer.concat([info, Buffer.from([1])])).digest();
  return t1.subarray(0, len);
}
/* Zweite HKDF-Stufe: PRK = HMAC(salt, ikm), dann Expand */
function hkdfExpandFrom(ikm, salt, info, len) {
  const prk = crypto.createHmac('sha256', salt).update(ikm).digest();
  const t1 = crypto.createHmac('sha256', prk).update(Buffer.concat([info, Buffer.from([1])])).digest();
  return t1.subarray(0, len);
}

/* ─────────────────────────────────────────────────────────────────────
   Web Push verschicken
───────────────────────────────────────────────────────────────────── */
async function sendWebPush(subscription, payloadObj, vapid) {
  const payload = Buffer.from(JSON.stringify(payloadObj));
  const encrypted = await encryptPayload(payload, subscription);
  const auth = vapidHeader(subscription.endpoint, vapid.privateKeyJwk, vapid.publicKey, vapid.subject);

  const res = await fetch(subscription.endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/octet-stream',
      'Content-Encoding': 'aes128gcm',
      'TTL': '86400',
      'Urgency': 'normal',
      'Authorization': auth
    },
    body: encrypted
  });

  /* 404/410: Abo ist tot (Nutzer hat Benachrichtigungen deaktiviert
     oder Browserdaten gelöscht) — der Aufrufer sollte es dann löschen. */
  return { ok: res.ok, status: res.status, expired: res.status === 404 || res.status === 410 };
}

/* ─────────────────────────────────────────────────────────────────────
   FCM HTTP v1 — OAuth2-Zugriffstoken aus Service-Account selbst signieren
───────────────────────────────────────────────────────────────────── */
let _fcmTokenCache = null;   // { token, expiresAt }

async function getFcmAccessToken(serviceAccount) {
  if (_fcmTokenCache && _fcmTokenCache.expiresAt > Date.now() + 60000) {
    return _fcmTokenCache.token;
  }
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: 'RS256', typ: 'JWT' };
  const claims = {
    iss: serviceAccount.client_email,
    scope: 'https://www.googleapis.com/auth/firebase.messaging',
    aud: 'https://oauth2.googleapis.com/token',
    iat: now, exp: now + 3600
  };
  const signingInput = b64url(JSON.stringify(header)) + '.' + b64url(JSON.stringify(claims));
  const key = crypto.createPrivateKey(serviceAccount.private_key);
  const signature = crypto.sign('RSA-SHA256', Buffer.from(signingInput), key);
  const assertion = signingInput + '.' + b64url(signature);

  const res = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion
    })
  });
  if (!res.ok) throw new Error('FCM-OAuth2-Token-Anfrage fehlgeschlagen: ' + res.status);
  const data = await res.json();
  _fcmTokenCache = { token: data.access_token, expiresAt: Date.now() + data.expires_in * 1000 };
  return data.access_token;
}

async function sendFcmPush(token, dataPayload, serviceAccount) {
  const accessToken = await getFcmAccessToken(serviceAccount);
  const res = await fetch(
    `https://fcm.googleapis.com/v1/projects/${serviceAccount.project_id}/messages:send`,
    {
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + accessToken, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        message: {
          token,
          data: dataPayload,        // nur Schlüsseltyp-Hinweise, kein Klartext
          android: { priority: 'high' },
          apns: { headers: { 'apns-priority': '10' } }
        }
      })
    }
  );
  const expired = res.status === 404 ||
    (res.status === 400 && (await res.clone().text()).includes('UNREGISTERED'));
  return { ok: res.ok, status: res.status, expired };
}

module.exports = {
  generateVapidKeys, sendWebPush, sendFcmPush, vapidHeader, encryptPayload
};
