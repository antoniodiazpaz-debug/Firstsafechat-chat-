/* Prüft die statische Dateiauslieferung: index.html ist die echte App
   und die Startseite unter "/" (Webserver-Konvention), app.html liefert
   denselben Inhalt als Alias. Alle von der App tatsächlich benötigten
   Module werden korrekt ausgeliefert (das war vorher eine echte Lücke —
   nur eine HTML-Datei hatte eine Route, app.js/crypto-core.js/etc.
   waren nie erreichbar), und Pfad-Traversal-Versuche scheitern
   zuverlässig. Die frühere Entwicklungs-Simulation ohne echte
   Serveranbindung liegt als index-simulation-demo.html weiterhin vor. */
import { spawn } from 'node:child_process';

let pass = 0, fail = 0;
const ok = (c, m) => { c ? (pass++, console.log('  ✓', m)) : (fail++, console.log('  ✗', m)) };

const server = spawn('node', ['server.js'], { cwd: import.meta.dirname, stdio: ['ignore', 'pipe', 'pipe'] });
await new Promise(r => setTimeout(r, 2000));

try {
  const B = 'http://127.0.0.1:8787';
  const get = async path => {
    const r = await fetch(B + path);
    return { status: r.status, contentType: r.headers.get('content-type'), text: await r.text() };
  };

  console.log('Startseite:');
  const root = await get('/');
  ok(root.status === 200, '/ liefert 200');
  ok(root.text.includes('app.js'), '/ liefert die echte App (referenziert app.js), nicht die alte Simulation');

  const indexHtml = await get('/index.html');
  ok(indexHtml.status === 200 && indexHtml.text === root.text, '/index.html liefert identischen Inhalt wie /');

  const appHtml = await get('/app.html');
  ok(appHtml.status === 200 && appHtml.text === root.text, '/app.html liefert denselben Inhalt als Alias');

  console.log('\nAlle von der App tatsächlich importierten Module:');
  const modules = [
    ['/app.js', 'text/javascript'],
    ['/crypto-core.js', 'text/javascript'],
    ['/api-client.js', 'text/javascript'],
    ['/i18n.js', 'text/javascript'],
    ['/device-info.js', 'text/javascript'],
    ['/media-storage.js', 'text/javascript'],
    ['/storage-guard.js', 'text/javascript'],
    ['/manifest.json', 'application/json'],
    ['/sw.js', 'text/javascript']
  ];
  for (const [path, expectedType] of modules) {
    const r = await get(path);
    ok(r.status === 200 && r.contentType?.includes(expectedType),
      `${path} → 200, ${r.contentType}`);
  }

  console.log('\nIcons (binär, dürfen nicht als Text/JSON interpretiert werden):');
  const icon = await fetch(B + '/icons/512.png');
  ok(icon.status === 200, 'Icon abrufbar');
  ok(icon.headers.get('content-type') === 'image/png', 'korrekter MIME-Typ image/png');
  const iconBuf = Buffer.from(await icon.arrayBuffer());
  ok(iconBuf.length > 100 && iconBuf[0] === 0x89 && iconBuf[1] === 0x50,
    'PNG-Signatur intakt (0x89 0x50 = "\\x89PNG"), Datei wurde nicht als Text beschädigt');

  console.log('\nAlte Simulation bleibt unter eigenem Namen erreichbar, ist aber nicht mehr die Startseite:');
  const oldSim = await get('/index-simulation-demo.html');
  ok(oldSim.status === 200, 'index-simulation-demo.html abrufbar (nicht gelöscht)');
  ok(oldSim.text !== root.text, 'unterscheidet sich von der neuen Startseite');
  ok(!oldSim.text.includes("src=\"/app.js\""), 'alte Simulation lädt app.js nicht — eigenständige Datei ohne Serveranbindung');

  console.log('\nUnbekannte Datei liefert 404, kein Absturz:');
  const missing = await get('/does-not-exist.js');
  ok(missing.status === 404, 'fehlende Datei → sauberes 404');

  console.log('\nPfad-Traversal wird zuverlässig verhindert:');
  const traversalAttempts = [
    '/../server.js',
    '/%2e%2e/server.js',
    '/%252e%252e/server.js',
    '/../log-signing-key.json',
    '/../vapid-key.json',
    '/../securechat.db',
    '/..%2fserver.js',
    '/....//server.js'
  ];
  let allBlocked = true;
  for (const attempt of traversalAttempts) {
    const r = await fetch(B + attempt);
    if (r.status === 200) { allBlocked = false; console.log('    DURCHGELASSEN:', attempt, r.status); }
  }
  ok(allBlocked, `alle ${traversalAttempts.length} Traversal-Versuche blockiert`);

  console.log('\n/api/-Pfade werden NICHT von serveStatic behandelt (gehen an die Routen):');
  const apiRoot = await fetch(B + '/api/health');
  ok(apiRoot.status === 200, '/api/health funktioniert weiterhin normal über den Routen-Handler');
  const apiData = await apiRoot.json();
  ok(apiData.ok === true, 'liefert echtes JSON von der Route, nicht versehentlich eine Datei');

  console.log('\nCache-Control unterscheidet HTML von Modulen:');
  const htmlRes = await fetch(B + '/index.html');
  const jsRes = await fetch(B + '/app.js');
  ok(htmlRes.headers.get('cache-control') === 'no-cache', 'HTML wird nie langfristig gecacht (Deploy-Updates sichtbar)');
  ok(jsRes.headers.get('cache-control')?.includes('max-age'), 'Module dürfen kurzfristig gecacht werden');

} finally {
  server.kill();
}

console.log(`\n${pass} bestanden, ${fail} fehlgeschlagen`);
process.exit(fail ? 1 : 0);
