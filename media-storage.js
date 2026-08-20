/* ═══════════════════════════════════════════════════════════════════════
   MEDIA-STORAGE — getrennter Weg für Fotos, Videos, Profilbilder
   ─────────────────────────────────────────────────────────────────────
   Warum getrennt vom Ratchet/Mixnet-Pfad: Die Mixnet-Nutzlast ist auf
   7 KB begrenzt (feste Paketgröße ist die Voraussetzung für Anonymität).
   Ein 500-KB-Foto passt dort nicht hinein, und würde man es fragmentieren,
   wäre das Muster von 96 Paketen zum selben Empfänger ein Fingerabdruck,
   den jeder Beobachter erkennt.

   Deshalb: Datei bekommt einen eigenen, zufälligen AES-Schlüssel,
   wird damit verschlüsselt und nach R2 hochgeladen. NUR der Schlüssel
   und ein Pfad — etwa 250 Byte — reisen durch den geschützten Weg
   (Ratchet + Mixnet). Der Speicher selbst sieht nur einen undurchsichtigen
   Blob ohne Namen. Signal macht Anhänge auf demselben Weg: über ein CDN,
   nicht durch die Sealed-Sender-Kette.

   Ehrlicher Kompromiss: Für Medien ist der Absender wieder sichtbar,
   weil der Client direkt mit dem Speicher spricht. Der Nutzer sieht das
   am Symbol an der Nachricht (📎 statt 🔒) — siehe media-badge in bubble().
   ═══════════════════════════════════════════════════════════════════════ */

const te = new TextEncoder();
const b64 = b => btoa(String.fromCharCode(...new Uint8Array(b)));
const ub64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));

export const LIMITS = {
  profileImage: 100 * 1024,
  photo:        2 * 1024 * 1024,
  video:        20 * 1024 * 1024,
  audio:        8 * 1024 * 1024,
  file:         10 * 1024 * 1024
};

/* ── Clientseitige Verkleinerung — der größte Hebel gegen Speicherkosten ── */
export async function shrinkImage(file, maxDim = 1600, quality = 0.8) {
  if (!file.type.startsWith('image/')) return file;
  const bmp = await createImageBitmap(file).catch(() => null);
  if (!bmp) return file;                          // z. B. HEIC ohne Decoder

  const scale = Math.min(1, maxDim / Math.max(bmp.width, bmp.height));
  const w = Math.round(bmp.width * scale), h = Math.round(bmp.height * scale);
  const canvas = new OffscreenCanvas(w, h);
  const ctx = canvas.getContext('2d');
  ctx.drawImage(bmp, 0, 0, w, h);
  bmp.close?.();

  const blob = await canvas.convertToBlob({ type: 'image/webp', quality });
  return blob.size < file.size ? blob : file;      // nie größer machen
}

export async function shrinkProfileImage(file) {
  const bmp = await createImageBitmap(file).catch(() => null);
  if (!bmp) return file;
  const size = 128;
  const canvas = new OffscreenCanvas(size, size);
  const ctx = canvas.getContext('2d');
  const s = Math.min(bmp.width, bmp.height);
  ctx.drawImage(bmp, (bmp.width - s) / 2, (bmp.height - s) / 2, s, s, 0, 0, size, size);
  bmp.close?.();
  return canvas.convertToBlob({ type: 'image/webp', quality: 0.85 });
}

/* ── Winzige Vorschau (Blurhash-ähnlich): 8×8 Pixel als Base64-PNG.
   Kostet ~200 Byte, reist im Ratchet mit, zeigt sofort etwas an,
   während die eigentliche Datei noch lädt. ── */
export async function tinyPreview(file) {
  if (!file.type.startsWith('image/')) return null;
  const bmp = await createImageBitmap(file).catch(() => null);
  if (!bmp) return null;
  const canvas = new OffscreenCanvas(8, 8);
  const ctx = canvas.getContext('2d');
  ctx.drawImage(bmp, 0, 0, 8, 8);
  bmp.close?.();
  const blob = await canvas.convertToBlob({ type: 'image/png' });
  return b64(await blob.arrayBuffer());
}

/* ── Verschlüsseln + Hochladen ── */
export async function uploadMedia(file, { uploadUrl, kind }) {
  const limit = LIMITS[kind] || LIMITS.file;
  if (file.size > limit)
    throw new Error(`Datei zu groß (${(file.size/1048576).toFixed(1)} MB, Limit ${(limit/1048576).toFixed(0)} MB)`);

  const fileKey = crypto.getRandomValues(new Uint8Array(32));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.importKey('raw', fileKey, 'AES-GCM', false, ['encrypt']);
  const buf = await file.arrayBuffer();
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, buf);

  const path = crypto.randomUUID() + '.bin';    // kein Name, keine Endung im Speicher

  const res = await fetch(uploadUrl.replace('{path}', path), {
    method: 'PUT',
    headers: { 'Content-Type': 'application/octet-stream' },
    body: ct
  });
  if (!res.ok) throw new Error('Upload fehlgeschlagen: ' + res.status);

  return {
    path, key: b64(fileKey), iv: b64(iv),
    size: file.size, mime: file.type,
    preview: await tinyPreview(file)
  };
}

/* ── Herunterladen + Entschlüsseln ── */
export async function downloadMedia(ref, { downloadUrl }) {
  const res = await fetch(downloadUrl.replace('{path}', ref.path));
  if (!res.ok) throw new Error('Datei nicht gefunden (' + res.status + ')');
  const ct = await res.arrayBuffer();

  const key = await crypto.subtle.importKey('raw', ub64(ref.key), 'AES-GCM', false, ['decrypt']);
  const buf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: ub64(ref.iv) }, key, ct);
  return new Blob([buf], { type: ref.mime || 'application/octet-stream' });
}

/* ── Referenz, die durch Ratchet + Mixnet reist — bewusst winzig ── */
export function mediaReference(uploaded) {
  return {
    path: uploaded.path, key: uploaded.key, iv: uploaded.iv,
    size: uploaded.size, mime: uploaded.mime, preview: uploaded.preview
  };
}
