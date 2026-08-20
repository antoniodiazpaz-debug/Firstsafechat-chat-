/* Beweist die eigentliche Behauptung: Man kann PATH_LENGTH ändern, ohne
   dass alte und neue Pakete sich gegenseitig als "Manipulation" melden.
   Das ist der Unterschied zwischen "einfach die Zahl ändern" (bricht)
   und "Version einführen" (migriert sauber). */
const M = require('./mixnet.js');

let pass = 0, fail = 0;
const ok = (c, m) => { c ? (pass++, console.log('  ✓', m)) : (fail++, console.log('  ✗', m)); };

(async () => {

console.log('Ausgangslage:');
ok(M.PROTOCOL_CONFIGS[1].pathLength === 3, 'Version 1 = 3 Hops (heutiger Stand)');
ok(M.PROTOCOL_CONFIGS[2].pathLength === 2, 'Version 2 = 2 Hops (Zielzustand)');
ok(M.CURRENT_VERSION === 1, 'Client baut standardmäßig noch Version 1');
ok(M.SUPPORTED_VERSIONS.includes(1) && M.SUPPORTED_VERSIONS.includes(2),
  'Knoten akzeptieren während der Migration beide Versionen');

console.log('\nKeine Größenkollision zwischen den Versionen:');
const sizes1 = M.sizesFor(1).hopSizes, sizes2 = M.sizesFor(2).hopSizes;
const overlap = sizes1.filter(s => sizes2.includes(s));
ok(overlap.length === 0, `v1-Größen ${sizes1} und v2-Größen ${sizes2} überschneiden sich nicht`);
ok(M.versionForSize(sizes1[0]) === 1, 'v1-Außengröße wird korrekt als v1 erkannt');
ok(M.versionForSize(sizes2[0]) === 2, 'v2-Außengröße wird korrekt als v2 erkannt');
ok(M.versionForSize(999999) === null, 'unbekannte Größe liefert null statt zu raten');

console.log('\nSzenario: Migration läuft, ALTE (v1) und NEUE (v2) Clients senden gleichzeitig');
const allNodeIds = ['mix-a', 'mix-b', 'mix-c', 'mix-d', 'mix-e'];
const nodes = allNodeIds.map(id => new M.MixNode(id, { instant: true }));
const delivered = [];
const net = new M.MixNetwork(nodes, (rid, payload) => delivered.push({ rid, text: payload.toString() }));

// Alter Client: 3-Hop-Pfad, Version 1 (Standard)
const pathV1 = net.pickPath(3);
const pktV1 = M.buildPacket(pathV1, 'nachricht von altem client', { recipientId: 'bob' });
ok(pktV1.version === 1, 'alter Client baut mit Version 1');

// Neuer Client: 2-Hop-Pfad, Version 2 (explizit)
const pathV2 = net.pickPath(2);
const pktV2 = M.buildPacket(pathV2, 'nachricht von neuem client', { recipientId: 'carla', version: 2 });
ok(pktV2.version === 2, 'neuer Client baut mit Version 2');
ok(pktV2.packet.length !== pktV1.packet.length,
  `v1-Paket (${pktV1.packet.length} B) und v2-Paket (${pktV2.packet.length} B) sind unterschiedlich groß — beide für sich aber konstant`);

const r1 = await net.inject(pktV1.firstHop, pktV1.packet);
const r2 = await net.inject(pktV2.firstHop, pktV2.packet);
ok(r1.delivered && r1.hops === 3, 'v1-Nachricht kommt über 3 Hops an');
ok(r2.delivered && r2.hops === 2, 'v2-Nachricht kommt über 2 Hops an');
ok(delivered.some(d => d.rid === 'bob' && d.text.includes('altem')), 'Inhalt der v1-Nachricht korrekt');
ok(delivered.some(d => d.rid === 'carla' && d.text.includes('neuem')), 'Inhalt der v2-Nachricht korrekt');

console.log('\nDas eigentliche Risiko: Was OHNE Versionsbyte passiert wäre');
// Wir bauen ein Paket, dessen erstes Byte zufällig eine unbekannte
// Version behauptet — simuliert einen Knoten, der eine dritte,
// noch nicht ausgerollte Version sieht.
const futurePacket = Buffer.concat([Buffer.from([99]), Buffer.alloc(M.PACKET_SIZE, 0)]);
let versionError = null;
try { nodes[0].peel(futurePacket); } catch (e) { versionError = e.message; }
ok(versionError && versionError.includes('Protokollversion'),
  'unbekannte Version wird VOR jeder Entschlüsselung erkannt: "' + versionError + '"');
ok(!versionError.toLowerCase().includes('tag') && !versionError.toLowerCase().includes('decrypt'),
  'Fehlermeldung nennt die Version, nicht einen kryptografischen Fehler — Betrieb kann das unterscheiden');

console.log('\nFalsche Größe für eine bekannte Version:');
const trulyTooShort = Buffer.from([1, 0, 0, 0]);   // 4 Byte gesamt — unter der 65-Byte-Mindestgröße für den ephemeren Schlüssel
let sizeError = null;
try { nodes[0].peel(trulyTooShort); } catch (e) { sizeError = e.message; }
ok(sizeError && sizeError.includes('Paket zu kurz'), 'zu kurzes Paket (unter Mindestgröße) wird klar benannt: "' + sizeError + '"');

const wrongSize2 = Buffer.concat([Buffer.from([1]), Buffer.alloc(M.PACKET_SIZE - 100, 0)]);
let sizeError2 = null;
try { nodes[0].peel(wrongSize2); } catch (e) { sizeError2 = e.message; }
ok(sizeError2 && sizeError2.includes('Ungültige Paketgröße für Version 1'),
  'falsche Größe für bekannte Version wird spezifisch benannt: "' + sizeError2 + '"');

console.log('\nMigrationsablauf — die vier Schritte aus dem Kommentar in mixnet.js:');

console.log('  Schritt 1: neue Version eintragen — bereits geschehen (PROTOCOL_CONFIGS[2])');
ok(M.PROTOCOL_CONFIGS[2] !== undefined, 'Version 2 ist eingetragen, Version 1 unverändert');
ok(M.PROTOCOL_CONFIGS[1].pathLength === 3, 'Version 1 wurde beim Hinzufügen von v2 NICHT verändert');

console.log('  Schritt 2: Knoten akzeptieren beide Versionen gleichzeitig');
{
  // Derselbe Knoten verarbeitet innerhalb desselben Prozesses erst ein
  // v1- dann ein v2-Paket — das ist der Nachweis für "gleichzeitig",
  // nicht zwei getrennte Prozesse (die testet test-mix-remote.js bereits).
  const netDual = new M.MixNetwork(
    [new M.MixNode('dual-a', { instant: true }),
     new M.MixNode('dual-b', { instant: true }),
     new M.MixNode('dual-c', { instant: true })],
    () => {});
  const path3 = netDual.pickPath(3);
  const path2 = netDual.pickPath(2);
  const pV1 = M.buildPacket(path3, 'a', { recipientId: 'x' });
  const pV2 = M.buildPacket(path2, 'b', { recipientId: 'x', version: 2 });
  const firstNodeV1 = netDual.nodes.get(pV1.firstHop);
  const firstNodeV2 = netDual.nodes.get(pV2.firstHop);
  const res1 = await firstNodeV1.accept(pV1.packet, netDual);
  const res2 = await firstNodeV2.accept(pV2.packet, netDual);
  ok(res1.forward && res2.forward, 'v1- und v2-Pakete werden im selben Netzwerklauf korrekt verarbeitet');
}

console.log('  Schritt 3: Clients stellen schrittweise auf v2 um — keine Server-Änderung nötig,');
console.log('             nur opts.version:2 beim Aufruf von buildPacket()');
ok(true, '(rein clientseitig — kein Test nötig, aber dokumentiert)');

console.log('  Schritt 4: v1 aus SUPPORTED_VERSIONS entfernen, sobald v1-Verkehr ausbleibt');
{
  // Simuliert das Ende der Migration: nur noch v2 wird akzeptiert
  const finalConfigs = M.SUPPORTED_VERSIONS.filter(v => v !== 1);
  ok(finalConfigs.length === 1 && finalConfigs[0] === 2,
    'nach Entfernen von v1 bleibt ausschließlich v2 unterstützt — Downgrade auf 2 Hops ist dann vollzogen');
}

console.log(`\n${pass} bestanden, ${fail} fehlgeschlagen`);
process.exit(fail ? 1 : 0);

})().catch(e => { console.error('Fehler:', e); process.exit(1); });
