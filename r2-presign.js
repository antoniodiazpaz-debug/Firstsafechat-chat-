/* ═══════════════════════════════════════════════════════════════════════
   R2-PRESIGN — AWS-Signature-V4-Presigned-URLs für Cloudflare R2
   ─────────────────────────────────────────────────────────────────────
   Reines node:crypto, kein AWS-SDK — passend zum Zero-Dependency-Prinzip
   des restlichen Projekts (siehe push.js für dieselbe Herangehensweise
   bei Web Push, mail.js bei SMTP).

   R2 ist S3-kompatibel und versteht denselben Signaturalgorithmus wie
   AWS S3 (SigV4). Eine Presigned URL erlaubt dem BROWSER, eine Datei
   direkt zu R2 hochzuladen, ohne dass die Datei jemals durch diesen
   Server läuft — der Server erzeugt nur die signierte URL, sieht nie
   den Dateiinhalt (der zudem clientseitig verschlüsselt wird, siehe
   media-storage.js).

   Umgebungsvariablen (bei Render unter Environment eintragen):
     R2_ACCOUNT_ID       — aus dem Cloudflare-Dashboard
     R2_ACCESS_KEY_ID    — R2-API-Token, siehe developers.cloudflare.com/r2/api/tokens
     R2_SECRET_ACCESS_KEY
     R2_BUCKET           — Name des Buckets
   ═══════════════════════════════════════════════════════════════════════ */
'use strict';
const crypto = require('node:crypto');

function isConfigured() {
  return !!(process.env.R2_ACCOUNT_ID && process.env.R2_ACCESS_KEY_ID &&
    process.env.R2_SECRET_ACCESS_KEY && process.env.R2_BUCKET);
}

const REGION = 'auto';   // von R2 verlangt, aber nicht ausgewertet
const SERVICE = 's3';

function hmac(key, data) {
  return crypto.createHmac('sha256', key).update(data).digest();
}
function sha256hex(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

/* Signierschlüssel-Kette laut AWS SigV4: date -> region -> service -> "aws4_request" */
function signingKey(secretKey, dateStamp) {
  const kDate = hmac('AWS4' + secretKey, dateStamp);
  const kRegion = hmac(kDate, REGION);
  const kService = hmac(kRegion, SERVICE);
  return hmac(kService, 'aws4_request');
}

/* Erzeugt eine Presigned URL für PUT (Hochladen) oder GET (Herunterladen).
   expiresInSeconds: max. 604800 (7 Tage) laut R2-Grenze. */
function presign({ method, key, contentType, expiresInSeconds = 3600 }) {
  if (!isConfigured()) throw new Error('R2 nicht konfiguriert (R2_ACCOUNT_ID/R2_ACCESS_KEY_ID/R2_SECRET_ACCESS_KEY/R2_BUCKET fehlen)');

  const accountId = process.env.R2_ACCOUNT_ID;
  const accessKeyId = process.env.R2_ACCESS_KEY_ID;
  const secretKey = process.env.R2_SECRET_ACCESS_KEY;
  const bucket = process.env.R2_BUCKET;

  const host = `${bucket}.${accountId}.r2.cloudflarestorage.com`;
  const now = new Date();
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, '');   // YYYYMMDDTHHMMSSZ
  const dateStamp = amzDate.slice(0, 8);                             // YYYYMMDD

  const credentialScope = `${dateStamp}/${REGION}/${SERVICE}/aws4_request`;
  const credential = `${accessKeyId}/${credentialScope}`;

  /* Nur "host" wird signiert — Content-Type NICHT mit in die signierten
     Header aufnehmen (siehe Rechercheergebnis oben: das Signieren von
     Content-Type lässt Browser-Uploads mit 403 scheitern, weil manche
     Browser den Header beim tatsächlichen PUT leicht anders senden,
     als der Presign-Aufruf ihn erwartet hatte). */
  const signedHeaders = 'host';

  const query = new URLSearchParams({
    'X-Amz-Algorithm': 'AWS4-HMAC-SHA256',
    'X-Amz-Credential': credential,
    'X-Amz-Date': amzDate,
    'X-Amz-Expires': String(expiresInSeconds),
    'X-Amz-SignedHeaders': signedHeaders
  });
  /* Query-Parameter müssen für die Signaturberechnung alphabetisch
     sortiert sein — URLSearchParams gibt sie in Einfügereihenfolge
     zurück, die hier bereits alphabetisch gewählt wurde, aber zur
     Sicherheit explizit sortieren, damit spätere Änderungen an dieser
     Liste nicht versehentlich die Reihenfolge brechen. */
  query.sort();

  const canonicalUri = `/${encodeURIComponent(key).replace(/%2F/g, '/')}`;
  const canonicalQuery = query.toString();
  const canonicalHeaders = `host:${host}\n`;
  const payloadHash = 'UNSIGNED-PAYLOAD';   // Standard bei Presigned URLs — Inhalt ist zum Signierzeitpunkt unbekannt

  const canonicalRequest = [
    method, canonicalUri, canonicalQuery, canonicalHeaders, signedHeaders, payloadHash
  ].join('\n');

  const stringToSign = [
    'AWS4-HMAC-SHA256', amzDate, credentialScope, sha256hex(canonicalRequest)
  ].join('\n');

  const signature = hmac(signingKey(secretKey, dateStamp), stringToSign).toString('hex');
  query.set('X-Amz-Signature', signature);

  return `https://${host}${canonicalUri}?${query.toString()}`;
}

/* Zufälligen, kollisionsarmen Objektschlüssel erzeugen — UUID-artig,
   passend zum bereits im Server vorhandenen Validierungsmuster
   /^[0-9a-f-]{36}\.bin$/ (siehe server.js /api/profile/avatar). */
function randomObjectKey() {
  return crypto.randomUUID() + '.bin';
}

module.exports = { isConfigured, presign, randomObjectKey };
