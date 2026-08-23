/* ═══════════════════════════════════════════════════════════════════════
   MEDIA-STORAGE — clientseitige Verschlüsselung + direkter R2-Upload
   ─────────────────────────────────────────────────────────────────────
   Läuft im BROWSER, nicht auf dem Server. Ablauf für einen Upload:

   1. Zufälligen AES-256-Schlüssel erzeugen (bleibt beim Client bzw.
      wird — bei Chat-Anhängen — über den bereits verschlüsselten
      Ratchet-Kanal an den Empfänger mitgeschickt, NIE über den Server
      im Klartext).
   2. Datei mit diesem Schlüssel lokal verschlüsseln (AES-GCM, dasselbe
      Verfahren wie crypto-core.js für Nachrichten — siehe dort P.seal).
   3. Presigned-Upload-URL vom Server holen (POST /api/media/upload-url)
      — der Server sieht dabei nur an, DASS eine Datei kommt, nie WAS.
   4. Verschlüsselte Bytes direkt per PUT zu R2 hochladen — der Server
      ist an diesem Schritt gar nicht mehr beteiligt.
   5. Den vom Server vergebenen Pfad + den lokalen AES-Schlüssel behalten
      (Pfad geht z. B. als avatarPath an /api/profile/avatar, der
      Schlüssel bei Chat-Anhängen zusätzlich verschlüsselt an den
      Empfänger).

   Download läuft spiegelbildlich: Presigned-Download-URL holen, Bytes
   laden, mit demselben AES-Schlüssel lokal entschlüsseln.
   ═══════════════════════════════════════════════════════════════════════ */

const SC = window.crypto?.subtle;
if (!SC) throw new Error('WebCrypto nicht verfügbar — bitte HTTPS oder localhost.');

/* ─────────────────────────────────────────────────────────────────────
   Verschlüsselung — dieselbe AES-GCM-Machart wie crypto-core.js, damit
   im Projekt nur ein einziges Verschlüsselungsmuster existiert.
───────────────────────────────────────────────────────────────────── */
async function generateFileKey() {
  const raw = crypto.getRandomValues(new Uint8Array(32));   // AES-256
  return raw;
}

async function encryptFile(fileBuf, rawKey) {
  const key = await SC.importKey('raw', rawKey, { name: 'AES-GCM' }, false, ['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await SC.encrypt({ name: 'AES-GCM', iv }, key, fileBuf);
  /* iv wird VOR den Chiffretext gestellt — der Empfänger liest die
     ersten 12 Byte als iv, den Rest als Chiffretext. Kein separates
     Metadatenfeld nötig, eine einzige zusammenhängende Byte-Folge geht
     zu R2. */
  const out = new Uint8Array(iv.length + ct.byteLength);
  out.set(iv, 0);
  out.set(new Uint8Array(ct), iv.length);
  return out;
}

async function decryptFile(encryptedBuf, rawKey) {
  const bytes = new Uint8Array(encryptedBuf);
  const iv = bytes.slice(0, 12);
  const ct = bytes.slice(12);
  const key = await SC.importKey('raw', rawKey, { name: 'AES-GCM' }, false, ['decrypt']);
  return SC.decrypt({ name: 'AES-GCM', iv }, key, ct);
}

/* ─────────────────────────────────────────────────────────────────────
   Bildverkleinerung — vor dem Verschlüsseln, damit Profilbilder/
   Anhänge nicht unnötig groß werden. Nur für Bilder relevant;
   PDFs/Videos/etc. laufen unverändert durch encryptFile().
───────────────────────────────────────────────────────────────────── */
async function shrinkImage(file, maxDim = 1600, quality = 0.82) {
  if (!file.type.startsWith('image/')) return file;   // kein Bild — unverändert lassen
  const bitmap = await createImageBitmap(file);
  const scale = Math.min(1, maxDim / Math.max(bitmap.width, bitmap.height));
  if (scale === 1) { bitmap.close(); return file; }    // bereits klein genug

  const canvas = document.createElement('canvas');
  canvas.width = Math.round(bitmap.width * scale);
  canvas.height = Math.round(bitmap.height * scale);
  const ctx = canvas.getContext('2d');
  ctx.drawImage(bitmap, 0, 0, canvas.width, canvas.height);
  bitmap.close();

  const blob = await new Promise(resolve => canvas.toBlob(resolve, 'image/jpeg', quality));
  return new File([blob], file.name, { type: 'image/jpeg' });
}

/* ─────────────────────────────────────────────────────────────────────
   Upload: Server-Presign holen, dann DIREKT zu R2 hochladen
───────────────────────────────────────────────────────────────────── */
async function uploadMedia(file, { apiFetch }) {
  /* apiFetch ist der bereits mit Auth-Header ausgestattete fetch-Wrapper
     der aufrufenden App (z. B. aus api-client.js) — media-storage.js
     kennt selbst keine Tokens, um Kopplung gering zu halten. */
  const presignRes = await apiFetch('/api/media/upload-url', { method: 'POST' });
  if (!presignRes.ok) {
    const body = await presignRes.json().catch(() => ({}));
    throw new Error(body.error || 'Kein Medien-Upload möglich (Server antwortete ' + presignRes.status + ')');
  }
  const { path, uploadUrl } = await presignRes.json();

  const rawKey = await generateFileKey();
  const fileBuf = await file.arrayBuffer();
  const encrypted = await encryptFile(fileBuf, rawKey);

  const putRes = await fetch(uploadUrl, {
    method: 'PUT',
    body: encrypted
    /* Bewusst KEIN Content-Type-Header hier — die Presigned URL wurde
       ohne signierten Content-Type erzeugt (siehe r2-presign.js-
       Kommentar: das Signieren von Content-Type lässt Browser-Uploads
       öfter an 403 scheitern, weil der tatsächlich gesendete Header
       nicht immer exakt dem entspricht, der beim Signieren erwartet
       wurde). */
  });
  if (!putRes.ok) throw new Error('Upload zu R2 fehlgeschlagen (Status ' + putRes.status + ')');

  return { path, key: rawKey, size: encrypted.byteLength, mime: file.type, name: file.name };
}

/* ─────────────────────────────────────────────────────────────────────
   Download: Server-Presign holen, Bytes laden, lokal entschlüsseln
───────────────────────────────────────────────────────────────────── */
async function downloadMedia(path, rawKey, { apiFetch }) {
  const presignRes = await apiFetch('/api/media/download-url?path=' + encodeURIComponent(path));
  if (!presignRes.ok) {
    const body = await presignRes.json().catch(() => ({}));
    throw new Error(body.error || 'Kein Medien-Download möglich (Server antwortete ' + presignRes.status + ')');
  }
  const { downloadUrl } = await presignRes.json();

  const getRes = await fetch(downloadUrl);
  if (!getRes.ok) throw new Error('Herunterladen von R2 fehlgeschlagen (Status ' + getRes.status + ')');
  const encrypted = await getRes.arrayBuffer();

  return decryptFile(encrypted, rawKey);
}

/* Kompakte, weitergebbare Referenz — das ist es, was tatsächlich an
   einen Chat-Partner geschickt wird (über den bereits verschlüsselten
   Ratchet-Kanal, NICHT über den Server im Klartext): Pfad + Schlüssel
   zusammen als eine einzige Zeichenkette. */
function mediaReference(uploadResult) {
  const keyB64 = btoa(String.fromCharCode(...uploadResult.key));
  return `${uploadResult.path}:${keyB64}:${uploadResult.mime}:${uploadResult.name}`;
}
function parseMediaReference(ref) {
  const [path, keyB64, mime, ...nameParts] = ref.split(':');
  const key = Uint8Array.from(atob(keyB64), c => c.charCodeAt(0));
  return { path, key, mime, name: nameParts.join(':') };
}

export {
  generateFileKey, encryptFile, decryptFile, shrinkImage,
  uploadMedia, downloadMedia, mediaReference, parseMediaReference
};
