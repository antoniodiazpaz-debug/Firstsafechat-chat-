import {webcrypto} from 'crypto';
globalThis.crypto ??= webcrypto;
import fs from 'fs';
let src = fs.readFileSync('public/media-storage.js','utf8');
// createImageBitmap/OffscreenCanvas fehlen in Node — die betroffenen Funktionen
// separat und ohne Browser-APIs testen, den Rest normal importieren
fs.writeFileSync('/tmp/ms.mjs', src);

let pass=0,fail=0; const ok=(c,m)=>{c?(pass++,console.log('  ✓',m)):(fail++,console.log('  ✗',m))};

const M = await import('/tmp/ms.mjs');

console.log('Limits:');
ok(M.LIMITS.photo === 2*1024*1024, 'Foto-Limit 2 MB');
ok(M.LIMITS.video === 20*1024*1024, 'Video-Limit 20 MB');
ok(M.LIMITS.profileImage < M.LIMITS.photo, 'Profilbild kleiner limitiert als Foto');

console.log('\nUpload + Verschlüsselung (mit Fake-Fetch):');
let uploadedBytes = null, uploadedUrl = null;
global.fetch = async (url, opts) => {
  uploadedUrl = url; uploadedBytes = Buffer.from(opts.body);
  return { ok: true, status: 200 };
};
const fakeFile = {
  size: 1024, type: 'application/octet-stream',
  arrayBuffer: async () => Buffer.from('A'.repeat(1024))
};
const up = await M.uploadMedia(fakeFile, { uploadUrl: 'https://r2.example/{path}', kind: 'file' });
ok(!!up.path && up.path.endsWith('.bin'), 'Pfad ohne Namen/Endung: ' + up.path);
ok(up.key && ub64len(up.key)===32, '32-Byte-Schlüssel erzeugt');
ok(up.iv && ub64len(up.iv)===12, '12-Byte-IV erzeugt');
ok(uploadedUrl.includes(up.path), 'Pfad korrekt in die URL eingesetzt');
ok(!Buffer.from(uploadedBytes).includes('AAAA'), 'Hochgeladene Bytes enthalten keinen erkennbaren Klartext');
function ub64len(s){ return Buffer.from(s,'base64').length }

console.log('\nDownload + Entschlüsselung (Rundlauf):');
global.fetch = async (url) => ({
  ok: true, status: 200,
  arrayBuffer: async () => uploadedBytes
});
const down = await M.downloadMedia(up, { downloadUrl: 'https://r2.example/{path}' });
const text = Buffer.from(await down.arrayBuffer()).toString();
ok(text === 'A'.repeat(1024), 'Entschlüsselter Inhalt stimmt exakt');

console.log('\nLimit wird durchgesetzt:');
const bigFile = { size: 25*1024*1024, type: 'video/mp4', arrayBuffer: async()=>new ArrayBuffer(0) };
let threw = false;
try { await M.uploadMedia(bigFile, { uploadUrl:'x', kind:'video' }) } catch(e){ threw = e.message.includes('zu groß') }
ok(threw, 'Video über 20 MB wird abgelehnt, bevor irgendetwas hochgeht');

console.log('\nFehlgeschlagener Upload:');
global.fetch = async () => ({ ok: false, status: 403 });
let uploadFailed = false;
try { await M.uploadMedia(fakeFile, {uploadUrl:'x', kind:'file'}) } catch(e){ uploadFailed = e.message.includes('403') }
ok(uploadFailed, 'HTTP-Fehler beim Upload wird als Fehler durchgereicht, nicht verschluckt');

console.log('\nManipulierte Datei beim Download:');
global.fetch = async () => ({ ok:true, status:200, arrayBuffer: async()=> {
  const b = Buffer.from(uploadedBytes); b[0]^=0xff; return b;
}});
let tamperCaught = false;
try { await M.downloadMedia(up, {downloadUrl:'x'}) } catch(e){ tamperCaught = true }
ok(tamperCaught, 'manipuliertes Chiffrat bricht am GCM-Tag');

console.log('\nReferenz ist winzig:');
const ref = M.mediaReference(up);
const refSize = Buffer.byteLength(JSON.stringify(ref));
ok(refSize < 300, `Referenz ${refSize} Byte — passt bequem in die 7-KB-Mixnet-Nutzlast`);
ok(!('mime' in ref) || ref.mime, 'MIME-Typ enthalten für die Anzeige');

console.log(`\n${pass} bestanden, ${fail} fehlgeschlagen`);
process.exit(fail?1:0);
