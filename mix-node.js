#!/usr/bin/env node
'use strict';
/*═══════════════════════════════════════════════════════════════════════════
  EIGENSTÄNDIGER MIX-KNOTEN
  ─────────────────────────────────────────────────────────────────────────
  Ein Prozess, ein Knoten. Gedacht zum Deployen bei verschiedenen Betreibern
  in verschiedenen Jurisdiktionen — das ist der ganze Punkt.

    NODE_ID=mix-eu PORT=9101 DIRECTORY=./directory.json \
    DELIVER_URL=https://chat.example.com/api/mix/deliver \
    DELIVER_AUTH=<geheim> node mix-node.js

  Der Knoten kennt:
    • seinen eigenen privaten Schlüssel
    • das Verzeichnis, um Nachfolger zu erreichen
    • die Zustelladresse für den Fall, dass er der letzte im Pfad ist

  Er kennt NICHT:
    • wer das Paket losgeschickt hat
    • den vollständigen Pfad
    • den Inhalt

  Betreiberhinweis: Wer alle Knoten betreibt, hat kein Mixnet, sondern
  einen umständlichen Proxy. Mindestens drei unabhängige Betreiber.
═══════════════════════════════════════════════════════════════════════════*/

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const MIX = require('./mixnet');

const NODE_ID      = process.env.NODE_ID      || 'mix-1';
const PORT         = parseInt(process.env.PORT || '9101', 10);
const DIR_FILE     = process.env.DIRECTORY    || path.join(__dirname, 'directory.json');
const KEY_FILE     = process.env.KEY_FILE     || path.join(__dirname, `mixkey-${NODE_ID}.json`);
const DELIVER_URL  = process.env.DELIVER_URL  || null;
const DELIVER_AUTH = process.env.DELIVER_AUTH || null;
const MEAN_DELAY   = parseInt(process.env.MEAN_DELAY || String(MIX.MEAN_DELAY_MS), 10);

/*── Schlüssel: einmal erzeugen, dann von Platte ──*/
let keys;
if (fs.existsSync(KEY_FILE)) {
  const j = JSON.parse(fs.readFileSync(KEY_FILE, 'utf8'));
  keys = { priv: Buffer.from(j.priv, 'base64'), pub: Buffer.from(j.pub, 'base64') };
} else {
  keys = MIX.newKeypair();
  fs.writeFileSync(KEY_FILE, JSON.stringify({
    id: NODE_ID,
    priv: keys.priv.toString('base64'),
    pub: keys.pub.toString('base64')
  }, null, 2), { mode: 0o600 });
  console.log(`→ Neuer Schlüssel für ${NODE_ID}: ${KEY_FILE}`);
}

const node = new MIX.MixNode(NODE_ID, { meanDelay: MEAN_DELAY });
node.keys = keys;   /* geladenen Schlüssel einsetzen */

/*── Verzeichnis: wird bei Änderung neu gelesen ──*/
let directory = [];
function loadDirectory() {
  try {
    directory = JSON.parse(fs.readFileSync(DIR_FILE, 'utf8'));
    net.dir = new Map(directory.map(n => [n.id, n]));
  } catch { directory = []; }
}
const net = new MIX.RemoteMixNetwork([], {
  deliverUrl: DELIVER_URL, deliverAuth: DELIVER_AUTH
});
loadDirectory();
if (fs.existsSync(DIR_FILE)) fs.watchFile(DIR_FILE, { interval: 5000 }, loadDirectory);

setInterval(() => node.sweep(), 60000).unref();

/*── HTTP ──*/
const json = (res, code, obj) => {
  const b = JSON.stringify(obj);
  res.writeHead(code, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(b) });
  res.end(b);
};
const readBody = req => new Promise((resolve, reject) => {
  let d = '', n = 0;
  req.on('data', c => { n += c.length; if (n > 64 * 1024) { req.destroy(); reject(new Error('zu groß')); } d += c; });
  req.on('end', () => { try { resolve(JSON.parse(d || '{}')); } catch (e) { reject(e); } });
  req.on('error', reject);
});

const server = http.createServer(async (req, res) => {
  if (req.method === 'GET' && req.url === '/info') {
    return json(res, 200, {
      id: NODE_ID, pub: keys.pub.toString('base64'),
      packetSize: MIX.PACKET_SIZE, meanDelay: MEAN_DELAY
    });
  }
  if (req.method === 'GET' && req.url === '/stats') {
    return json(res, 200, { id: NODE_ID, ...node.stats,
      avgDelay: node.avgDelay, queued: node.queue.size, peers: directory.length });
  }
  if (req.method !== 'POST' || req.url !== '/forward') {
    return json(res, 404, { error: 'unbekannt' });
  }

  let body;
  try { body = await readBody(req); } catch { return json(res, 400, { error: 'ungültig' }); }
  const packet = body.packet ? Buffer.from(body.packet, 'base64') : null;

  /* Größe prüfen, bevor irgendetwas gerechnet wird. Gegen alle gültigen
     Größen über alle unterstützten Versionen, nicht nur die aktuelle —
     ein Knoten während der Migration muss altes UND neues Format
     durchlassen (die autoritative Versions-/Entschlüsselungsprüfung
     macht ohnehin node.accept → MixNode.peel). */
  const validSizes = MIX.SUPPORTED_VERSIONS.flatMap(v => MIX.sizesFor(v).hopSizes);
  if (!packet || !validSizes.includes(packet.length))
    return json(res, 400, { error: 'Paketgröße unzulässig' });

  /* SOFORT quittieren. Würden wir bis zur Weiterleitung warten, wäre die
     Antwortzeit ein Maß für die verbleibende Pfadlänge. */
  json(res, 202, { accepted: true });

  /* Ab hier asynchron, ohne dass der Absender etwas davon mitbekommt */
  node.accept(packet, null).then(r => {
    if (r.dummy) return;                              // Cover Traffic endet hier
    if (r.forward) return net.forward(r.next, r.packet);
    if (r.deliver) return net.deliver(r.recipientId, r.payload)
      .catch(e => console.error(`[${NODE_ID}] Zustellung fehlgeschlagen:`, e.message));
  }).catch(e => {
    /* Fehler bleiben lokal. Eine Rückmeldung verriete, wo es klemmte. */
    if (!/Replay/.test(e.message)) console.error(`[${NODE_ID}]`, e.message);
  });
});

server.listen(PORT, () => {
  console.log(`Mix-Knoten ${NODE_ID} auf Port ${PORT}`);
  console.log(`  Öffentlicher Schlüssel: ${keys.pub.toString('base64').slice(0, 24)}…`);
  console.log(`  Mittlere Verzögerung  : ${MEAN_DELAY} ms`);
  console.log(`  Bekannte Nachbarn     : ${directory.length}`);
  console.log(`  Zustellung an         : ${DELIVER_URL || '(keine — reiner Zwischenknoten)'}`);
});

module.exports = { server, node };
