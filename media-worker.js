/* ═══════════════════════════════════════════════════════════════════════
   R2-MEDIEN-WORKER
   ─────────────────────────────────────────────────────────────────────
   Nimmt bereits verschlüsselte Blobs entgegen und legt sie in R2 ab.
   Sieht selbst nie den Schlüssel — der reist getrennt durch den Ratchet
   (siehe media-storage.js). Für den Worker ist jede Datei undurchsichtiges
   Rauschen fester Struktur.

   Route:
     PUT    /upload/:path    Datei ablegen (angemeldeter Nutzer)
     GET    /:path           Datei abrufen (jeder mit dem Pfad — der Pfad
                              ist eine UUID, praktisch nicht zu erraten)
     DELETE /:path           Löschen (nur Eigentümer)

   Deploy:
     wrangler r2 bucket create securechat-media
     wrangler deploy
   ═══════════════════════════════════════════════════════════════════════ */

const MAX_UPLOAD = 21 * 1024 * 1024;      // etwas über dem größten Client-Limit
const PATH_RE = /^[0-9a-f-]{36}\.bin$/;   // exakt eine UUID + .bin, sonst nichts

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const cors = corsHeaders(env);

    if (request.method === 'OPTIONS') return new Response(null, { headers: cors });

    try {
      if (request.method === 'PUT' && url.pathname.startsWith('/upload/'))
        return await handleUpload(request, env, url, cors);
      if (request.method === 'GET' && url.pathname !== '/')
        return await handleDownload(request, env, url, cors);
      if (request.method === 'DELETE' && url.pathname !== '/')
        return await handleDelete(request, env, url, cors);
      return json({ error: 'Unbekannte Route' }, 404, cors);
    } catch (e) {
      console.error(e);
      return json({ error: 'Interner Fehler' }, 500, cors);
    }
  }
};

async function handleUpload(request, env, url, cors) {
  const userId = await authenticate(request, env);
  if (!userId) return json({ error: 'Nicht angemeldet' }, 401, cors);

  const path = url.pathname.replace('/upload/', '');
  if (!PATH_RE.test(path)) return json({ error: 'Ungültiger Pfad' }, 400, cors);

  const len = parseInt(request.headers.get('content-length') || '0', 10);
  if (len <= 0 || len > MAX_UPLOAD)
    return json({ error: `Größe muss zwischen 1 und ${MAX_UPLOAD} Byte liegen` }, 413, cors);

  /* Kontingent prüfen, bevor der Body überhaupt gelesen wird */
  const quota = await checkQuota(env, userId, len);
  if (!quota.ok) return json({ error: quota.reason }, 413, cors);

  await env.MEDIA.put(path, request.body, {
    httpMetadata: { contentType: 'application/octet-stream' },
    customMetadata: { owner: userId, uploadedAt: String(Date.now()) }
  });

  await recordUsage(env, userId, path, len);
  return json({ path, size: len }, 201, cors);
}

async function handleDownload(request, env, url, cors) {
  const path = url.pathname.slice(1);
  if (!PATH_RE.test(path)) return json({ error: 'Ungültiger Pfad' }, 400, cors);

  const obj = await env.MEDIA.get(path);
  if (!obj) return json({ error: 'Nicht gefunden' }, 404, cors);

  return new Response(obj.body, {
    headers: {
      ...cors,
      'Content-Type': 'application/octet-stream',
      'Cache-Control': 'private, max-age=31536000, immutable',
      'ETag': obj.httpEtag
    }
  });
}

async function handleDelete(request, env, url, cors) {
  const userId = await authenticate(request, env);
  if (!userId) return json({ error: 'Nicht angemeldet' }, 401, cors);

  const path = url.pathname.slice(1);
  if (!PATH_RE.test(path)) return json({ error: 'Ungültiger Pfad' }, 400, cors);

  const obj = await env.MEDIA.head(path);
  if (!obj) return json({ ok: true }, 200, cors);           // schon weg
  if (obj.customMetadata?.owner !== userId)
    return json({ error: 'Nicht dein Eigentum' }, 403, cors);

  await env.MEDIA.delete(path);
  await releaseUsage(env, userId, obj.size);
  return json({ ok: true }, 200, cors);
}

/* ── Authentifizierung: Bearer-Token gegen den Hauptserver prüfen.
   Der Worker führt keine eigene Sitzungsverwaltung, sondern fragt
   den bestehenden Server — eine Quelle der Wahrheit. ── */
async function authenticate(request, env) {
  const auth = request.headers.get('Authorization') || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return null;

  const cacheKey = 'auth:' + token;
  const cached = await env.SESSIONS?.get(cacheKey);
  if (cached) return cached;

  const res = await fetch(env.AUTH_CHECK_URL, {
    headers: { Authorization: 'Bearer ' + token }
  });
  if (!res.ok) return null;
  const { user } = await res.json();
  if (!user?.id) return null;

  await env.SESSIONS?.put(cacheKey, user.id, { expirationTtl: 300 });
  return user.id;
}

/* ── Kontingent: gleiche Grenzen wie im Postgres-Schema (media_refs) ── */
async function checkQuota(env, userId, addBytes) {
  const key = 'quota:' + userId;
  const used = parseInt(await env.SESSIONS?.get(key) || '0', 10);
  const limit = parseInt(env.QUOTA_BYTES || String(50 * 1024 * 1024), 10);
  if (used + addBytes > limit)
    return { ok: false, reason: `Speicherkontingent erschöpft (${used} von ${limit} Byte)` };
  return { ok: true, used };
}
async function recordUsage(env, userId, path, bytes) {
  const key = 'quota:' + userId;
  const used = parseInt(await env.SESSIONS?.get(key) || '0', 10);
  await env.SESSIONS?.put(key, String(used + bytes));
}
async function releaseUsage(env, userId, bytes) {
  const key = 'quota:' + userId;
  const used = parseInt(await env.SESSIONS?.get(key) || '0', 10);
  await env.SESSIONS?.put(key, String(Math.max(0, used - bytes)));
}

function corsHeaders(env) {
  return {
    'Access-Control-Allow-Origin': env.ALLOWED_ORIGIN || '*',
    'Access-Control-Allow-Methods': 'GET, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Authorization, Content-Type'
  };
}
function json(obj, status, cors) {
  return new Response(JSON.stringify(obj), {
    status, headers: { ...cors, 'Content-Type': 'application/json' }
  });
}
