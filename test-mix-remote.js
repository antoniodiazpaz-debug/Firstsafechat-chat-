/* Drei Mix-Knoten als getrennte Prozesse auf eigenen Ports.
   Geprüft wird, dass ein Paket wirklich über HTTP von Knoten zu Knoten
   wandert und keiner von ihnen den ganzen Pfad kennt. */
const http = require('node:http');
const crypto = require('node:crypto');
const MIX = require('./mixnet');

let pass = 0, fail = 0;
const ok = (c, m) => { c ? (pass++, console.log('  ✓', m)) : (fail++, console.log('  ✗', m)); };
const sleep = ms => new Promise(r => setTimeout(r, ms));

(async () => {

/* Zustelldienst: spielt den Hauptserver */
const delivered = [];
let deliverAuthSeen = null;
const sink = http.createServer((req, res) => {
  let d = '';
  req.on('data', c => d += c);
  req.on('end', () => {
    deliverAuthSeen = req.headers['x-mix-auth'] || null;
    try {
      const b = JSON.parse(d);
      delivered.push({ at: Date.now(), recipientId: b.recipientId,
        payload: Buffer.from(b.payload, 'base64').toString() });
    } catch {}
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end('{"ok":true}');
  });
});
await new Promise(r => sink.listen(9200, r));

/* Drei Knoten, jeder mit eigenem Schlüssel und eigenem Port */
const NODES = [
  { id: 'mix-eu', port: 9201 },
  { id: 'mix-us', port: 9202 },
  { id: 'mix-ch', port: 9203 }
];
const AUTH = crypto.randomBytes(16).toString('hex');

const running = [];
for (const n of NODES) {
  const node = new MIX.MixNode(n.id, { meanDelay: 80 });
  n.node = node;
  n.pub = node.keys.pub.toString('base64');
}
const directory = NODES.map(n => ({ id: n.id, url: `http://127.0.0.1:${n.port}`, pub: n.pub }));

/* Jeder Knoten bekommt sein eigenes RemoteMixNetwork — er kennt nur
   das Verzeichnis, nicht den Pfad einer einzelnen Nachricht */
for (const n of NODES) {
  const rnet = new MIX.RemoteMixNetwork(directory, {
    deliverUrl: 'http://127.0.0.1:9200/deliver', deliverAuth: AUTH
  });
  n.rnet = rnet;
  const srv = http.createServer((req, res) => {
    if (req.method === 'GET' && req.url === '/info') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ id: n.id, pub: n.pub }));
    }
    let d = '';
    req.on('data', c => d += c);
    req.on('end', () => {
      let packet;
      try { packet = Buffer.from(JSON.parse(d).packet, 'base64'); }
      catch { res.writeHead(400); return res.end('{}'); }
      if (!MIX.HOP_SIZES.includes(packet.length)) { res.writeHead(400); return res.end('{}'); }
      res.writeHead(202, { 'Content-Type': 'application/json' });
      res.end('{"accepted":true}');
      n.node.accept(packet, null).then(r => {
        if (r.dummy) return;
        if (r.forward) return rnet.forward(r.next, r.packet);
        if (r.deliver) return rnet.deliver(r.recipientId, r.payload);
      }).catch(() => {});
    });
  });
  await new Promise(r => srv.listen(n.port, r));
  running.push(srv);
}

console.log('Knoten laufen:');
for (const n of NODES) {
  const r = await fetch(`http://127.0.0.1:${n.port}/info`);
  const info = await r.json();
  ok(info.id === n.id, `${n.id} auf Port ${n.port} erreichbar`);
}

console.log('\nRemoteMixNetwork:');
const client = new MIX.RemoteMixNetwork(directory, {});
ok(client.directory.length === 3, 'Verzeichnis mit drei Knoten geladen');
const path = client.pickPath();
ok(path.length === MIX.PATH_LENGTH, `Pfad über ${path.length} Knoten gewählt`);
ok(new Set(path.map(p => p.id)).size === 3, 'kein Knoten doppelt');
console.log(`    gewählter Pfad: ${path.map(p => p.id).join(' → ')}`);

console.log('\nZustellung über echte HTTP-Sprünge:');
const t0 = Date.now();
const pkt = MIX.buildPacket(path, 'quer durch drei Prozesse', { recipientId: 'boris' });
const inj = await client.inject(pkt.firstHop, pkt.packet);
const ackAfter = Date.now() - t0;
ok(inj.status === 202, 'erster Knoten quittiert mit 202');
ok(ackAfter < 100, `Quittung nach ${ackAfter} ms — unabhängig von der Pfadlänge`);

for (let i = 0; i < 100 && !delivered.length; i++) await sleep(50);
const latency = Date.now() - t0;
ok(delivered.length === 1, `nach ${latency} ms zugestellt`);
ok(delivered[0].payload === 'quer durch drei Prozesse', 'Nutzlast unverändert');
ok(delivered[0].recipientId === 'boris', 'Empfänger korrekt');
ok(latency > ackAfter * 2, 'echte Laufzeit deutlich länger als die Quittung');
ok(deliverAuthSeen === AUTH, 'Zustellung war authentifiziert');

console.log('\nWer hat was gesehen:');
const seen = NODES.map(n => ({ id: n.id, ...n.node.stats }));
for (const s of seen) {
  console.log(`    ${s.id}: empfangen ${s.received}, weitergeleitet ${s.forwarded}, zugestellt ${s.delivered}`);
}
ok(seen.filter(s => s.received > 0).length === 3, 'alle drei Knoten waren beteiligt');
ok(seen.filter(s => s.delivered > 0).length === 1, 'nur der letzte Knoten kennt den Empfänger');
ok(seen.filter(s => s.forwarded > 0).length === 2, 'die ersten beiden haben nur weitergereicht');
const entryNode = NODES.find(n => n.id === path[0].id);
ok(entryNode.node.stats.delivered === 0, 'der Eingangsknoten kennt den Empfänger nicht');
const exitNode = NODES.find(n => n.id === path[2].id);
ok(exitNode.node.stats.forwarded === 0, 'der Ausgangsknoten kennt den Absender nicht');

console.log('\nDummy-Verkehr verpufft:');
const beforeDeliver = delivered.length;
const d = MIX.buildPacket(client.pickPath(), crypto.randomBytes(200), { dummy: true });
await client.inject(d.firstHop, d.packet);
await sleep(1200);
ok(delivered.length === beforeDeliver, 'Dummy erreicht den Zustelldienst nicht');
const dummies = NODES.reduce((a, n) => a + n.node.stats.dummies, 0);
ok(dummies >= 1, 'ein Knoten hat den Dummy verworfen');

console.log('\nFehler bleiben lokal:');
/* Müll in korrekter WIRE-Größe (inklusive Versionsbyte) — sonst schlägt
   schon die Größenvorprüfung zu, und wir testen nicht, was wir wollen:
   dass kryptografisch ungültiger, aber korrekt dimensionierter Inhalt
   den Absender nicht über den Fehlschlag informiert. */
const junk = Buffer.alloc(MIX.VERSION_BYTE_SIZE + MIX.PACKET_SIZE);
junk[0] = MIX.CURRENT_VERSION;               // Versionsbyte muss gültig sein,
crypto.randomFillSync(junk, 1);              // der Rest ist reines Rauschen
const r = await client.inject(NODES[0].id, junk);
ok(r.status === 202, 'auch Müll mit gültiger Größe wird mit 202 quittiert');
console.log('    → kein Rückschluss möglich, ob das Paket gültig war');
await sleep(300);
ok(delivered.length === beforeDeliver, 'Müllpaket wurde still verworfen');

console.log('\nGrößenprüfung am Eingang:');
const small = await fetch(`http://127.0.0.1:${NODES[0].port}/forward`, {
  method: 'POST', headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ packet: Buffer.alloc(50).toString('base64') })
});
ok(small.status === 400, 'zu kleines Paket wird abgelehnt');

console.log('\nParallelbetrieb:');
const N = 8;
const startCount = delivered.length;
for (let i = 0; i < N; i++) {
  const p = MIX.buildPacket(client.pickPath(), 'last-' + i, { recipientId: 'boris' });
  await client.inject(p.firstHop, p.packet);
  await sleep(15);
}
for (let i = 0; i < 120 && delivered.length < startCount + N; i++) await sleep(50);
const got = delivered.slice(startCount);
ok(got.length === N, `alle ${N} Nachrichten zugestellt`);
const order = got.map(g => parseInt(g.payload.split('-')[1], 10));
let same = 0;
for (let i = 0; i < N; i++) if (order[i] === i) same++;
console.log(`    Eingang : ${Array.from({ length: N }, (_, i) => i).join(' ')}`);
console.log(`    Ausgang : ${order.join(' ')}`);
ok(same < N, `Reihenfolge gemischt — ${same} von ${N} an gleicher Position`);
ok(client.stats.injected >= N, `${client.stats.injected} Einspeisungen gezählt`);

for (const s of running) s.close();
sink.close();
console.log(`\n${pass} bestanden, ${fail} fehlgeschlagen`);
process.exit(fail ? 1 : 0);

})().catch(e => { console.error('Fehler:', e); process.exit(1); });
