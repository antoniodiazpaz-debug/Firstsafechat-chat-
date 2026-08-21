import fs from 'fs';
const src = fs.readFileSync('media-worker.js','utf8').replace('export default', 'const worker =');
fs.writeFileSync('/tmp/worker.mjs', src + '\nexport default worker;');
const { default: worker } = await import('/tmp/worker.mjs');

let pass=0,fail=0; const ok=(c,m)=>{c?(pass++,console.log('  ✓',m)):(fail++,console.log('  ✗',m))};

// Minimaler R2/KV-Mock
function makeEnv() {
  const store = new Map(), meta = new Map(), kv = new Map();
  return {
    MEDIA: {
      async put(key, body, opts) {
        const chunks=[]; for await (const c of body) chunks.push(c);
        store.set(key, Buffer.concat(chunks.map(c=>Buffer.from(c))));
        meta.set(key, opts.customMetadata);
      },
      async get(key) {
        if (!store.has(key)) return null;
        const data = store.get(key);
        return { body: (async function*(){yield data})(), httpEtag: 'x' };
      },
      async head(key) {
        if (!store.has(key)) return null;
        return { size: store.get(key).length, customMetadata: meta.get(key) };
      },
      async delete(key) { store.delete(key); meta.delete(key) }
    },
    SESSIONS: {
      async get(k){ return kv.get(k) ?? null },
      async put(k,v){ kv.set(k,v) }
    },
    AUTH_CHECK_URL: 'https://auth.test/me',
    QUOTA_BYTES: '1000',
    ALLOWED_ORIGIN: '*',
    _store: store
  };
}

const UUID = '12345678-1234-1234-1234-123456789abc.bin';

console.log('Authentifizierung:');
global.fetch = async (url, opts) => {
  const t = opts.headers.Authorization;
  if (t === 'Bearer good') return { ok:true, json: async()=>({user:{id:'alice'}}) };
  return { ok:false };
};
let env = makeEnv();
const noAuth = await worker.fetch(new Request(`https://x/upload/${UUID}`,
  {method:'PUT', headers:{'content-length':'10'}, body:'x'.repeat(10)}), env);
ok(noAuth.status===401, 'Upload ohne Token abgelehnt');

console.log('\nErfolgreicher Upload:');
env = makeEnv();
const body = Buffer.from('verschlüsselte-daten-simuliert');
const up = await worker.fetch(new Request(`https://x/upload/${UUID}`,
  {method:'PUT', headers:{'Authorization':'Bearer good','content-length':String(body.length)}, body}), env);
ok(up.status===201, 'Upload akzeptiert (' + up.status + ')');
const upData = await up.json();
ok(upData.path === UUID, 'Pfad in der Antwort korrekt');
ok(env._store.has(UUID), 'Datei wirklich im Speicher abgelegt');
ok(Buffer.compare(env._store.get(UUID), body)===0, 'gespeicherte Bytes identisch zum Upload');

console.log('\nDownload ohne Auth (Pfad ist die Legitimation):');
const down = await worker.fetch(new Request(`https://x/${UUID}`), env);
ok(down.status===200, 'Download ohne Token funktioniert — Pfad-UUID ist der Zugriffsschutz');
const downBuf = Buffer.from(await down.arrayBuffer());
ok(Buffer.compare(downBuf, body)===0, 'heruntergeladene Bytes identisch');

console.log('\nUngültige Pfade:');
// Request/URL normalisiert simple ../ bereits selbst — hier die Fälle,
// die die /upload/-Route tatsächlich noch treffen und PATH_RE prüfen müssen
for (const p of ['/upload/foo/../bar.bin', '/upload/..%2f..%2fetc%2fpasswd', '/upload/....//etc/passwd']) {
  const r = await worker.fetch(new Request('https://x'+p,
    {method:'PUT', headers:{'Authorization':'Bearer good','content-length':'5'}, body:'xxxxx'}), env);
  ok(r.status===400, 'Pfadmanipulation "'+p+'" abgelehnt (Status '+r.status+')');
}
const bad2 = await worker.fetch(new Request('https://x/upload/malicious.js',
  {method:'PUT', headers:{'Authorization':'Bearer good','content-length':'5'}, body:'xxxxx'}), env);
ok(bad2.status===400, 'Nicht-UUID-Pfad abgelehnt');

console.log('\nGrößenlimit:');
env = makeEnv();
const tooBig = await worker.fetch(new Request(`https://x/upload/${UUID}`,
  {method:'PUT', headers:{'Authorization':'Bearer good','content-length':String(22*1024*1024)}, body:'x'}), env);
ok(tooBig.status===413, 'Über 21 MB wird abgelehnt');

console.log('\nKontingent:');
env = makeEnv();  // QUOTA_BYTES=1000
const okUp = await worker.fetch(new Request(`https://x/upload/${UUID}`,
  {method:'PUT', headers:{'Authorization':'Bearer good','content-length':'900'}, body:'x'.repeat(900)}), env);
ok(okUp.status===201, 'erster Upload unter Kontingent geht durch');
const UUID2 = '22222222-1234-1234-1234-123456789abc.bin';
const overQuota = await worker.fetch(new Request(`https://x/upload/${UUID2}`,
  {method:'PUT', headers:{'Authorization':'Bearer good','content-length':'200'}, body:'x'.repeat(200)}), env);
ok(overQuota.status===413, 'zweiter Upload über Kontingent wird abgelehnt (900+200 > 1000)');

console.log('\nLöschen — nur Eigentümer:');
env = makeEnv();
await worker.fetch(new Request(`https://x/upload/${UUID}`,
  {method:'PUT', headers:{'Authorization':'Bearer good','content-length':'10'}, body:'x'.repeat(10)}), env);
global.fetch = async (url, opts) => {
  const t = opts.headers.Authorization;
  if (t === 'Bearer good') return { ok:true, json: async()=>({user:{id:'alice'}}) };
  if (t === 'Bearer other') return { ok:true, json: async()=>({user:{id:'mallory'}}) };
  return { ok:false };
};
const delWrong = await worker.fetch(new Request(`https://x/${UUID}`,
  {method:'DELETE', headers:{'Authorization':'Bearer other'}}), env);
ok(delWrong.status===403, 'fremder Nutzer kann nicht löschen');
ok(env._store.has(UUID), 'Datei ist nach fehlgeschlagenem Löschversuch noch da');
const delRight = await worker.fetch(new Request(`https://x/${UUID}`,
  {method:'DELETE', headers:{'Authorization':'Bearer good'}}), env);
ok(delRight.status===200, 'Eigentümer kann löschen');
ok(!env._store.has(UUID), 'Datei ist wirklich weg');

console.log('\nCORS:');
const opt = await worker.fetch(new Request('https://x/', {method:'OPTIONS'}), makeEnv());
ok(opt.status===200 || opt.status===204, 'OPTIONS wird beantwortet');
ok(!!opt.headers.get('Access-Control-Allow-Origin'), 'CORS-Header gesetzt');

console.log(`\n${pass} bestanden, ${fail} fehlgeschlagen`);
process.exit(fail?1:0);
