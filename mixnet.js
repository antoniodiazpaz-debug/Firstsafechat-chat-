'use strict';
/*═══════════════════════════════════════════════════════════════════════════
  MIXNET — Schutz gegen Verkehrsanalyse
  ─────────────────────────────────────────────────────────────────────────
  Sealed Sender nimmt dem Server den Absendernamen. Was bleibt, ist das
  Verkehrsmuster: Wer sendet wann, wie groß, an wen wird zugestellt. Wer
  die Leitung beobachtet, korreliert Ein- und Ausgang und hat den Absender
  trotzdem. Genau dagegen arbeitet ein Mixnet.

  Vier Mechanismen, die zusammen wirken müssen — einer allein bringt nichts:

  1) GESCHICHTETE VERSCHLÜSSELUNG (Sphinx-artig)
     Der Client wählt einen Pfad über drei Mix-Knoten und packt die
     Nachricht in drei Schichten. Jeder Knoten kann genau seine eigene
     Schicht öffnen und erfährt dabei nur den nächsten Hop — nie den
     ganzen Pfad. Der erste Knoten kennt den Absender, aber nicht das
     Ziel. Der letzte kennt das Ziel, aber nicht den Absender. Kein
     einzelner Knoten hat beides.

  2) FESTE PAKETGRÖSSE
     Jedes Paket ist exakt gleich groß, egal ob "ok" oder ein langer Text.
     Ohne das verrät die Länge, welches eingehende Paket welches ausgehende
     ist — und die ganze Mischung wäre wertlos.

  3) POISSON-VERZÖGERUNG
     Jeder Knoten hält jedes Paket eine exponentialverteilt zufällige Zeit
     zurück. Das ist der eigentliche Mischvorgang: Die Reihenfolge am
     Ausgang sagt nichts mehr über die Reihenfolge am Eingang. Exponential
     deshalb, weil die Verteilung gedächtnislos ist — die bisherige
     Wartezeit verrät nichts über die verbleibende.

  4) COVER TRAFFIC
     Clients senden auch dann Pakete, wenn sie nichts zu sagen haben.
     Diese Dummies sehen identisch aus und werden erst im letzten Knoten
     verworfen. Ohne sie verrät schon die bloße Tatsache, dass jemand
     sendet, dass ein Gespräch läuft.

  Preis: Latenz. Bei drei Hops mit je 200 ms Mittelwert liegt die typische
  Zustellung bei rund einer halben bis zwei Sekunden. Das ist der Handel,
  den man eingeht — Metadatenschutz gegen Sofortzustellung.
═══════════════════════════════════════════════════════════════════════════*/

const crypto = require('node:crypto');

/*───────────────────────────────────────────────────────────────────────────
  PROTOKOLLVERSION
  ─────────────────────────────────────────────────────────────────────────
  PATH_LENGTH bestimmt PACKET_SIZE und HOP_SIZES — beide werden bei jedem
  buildPacket() fest in die Paketstruktur eingebacken. Ändert man
  PATH_LENGTH, ändert sich damit unweigerlich die Paketgröße. Ein Knoten
  mit alter Konfiguration, der ein Paket mit neuer Größe bekommt, würde
  ohne Gegenmaßnahme direkt in der GCM-Entschlüsselung scheitern — und
  das sieht identisch aus wie eine Manipulation. Das Versionsbyte trennt
  diese beiden Fälle: Ein Größen-/Versionskonflikt wird VOR jeder
  kryptografischen Operation erkannt und klar benannt.

  Jedes Paket beginnt jetzt mit genau einem Versionsbyte. Ein Knoten liest
  es zuerst, schlägt die dazu passende Paketgröße nach und prüft erst DANN
  die Länge — bevor irgendein Schlüssel angefasst wird. Kennt der Knoten
  die Version nicht, bricht er mit einer klaren Meldung ab statt mit einem
  kryptografischen Fehler, der wie ein Angriff aussieht.

  Migration von Version 1 (3 Hops) auf Version 2 (2 Hops) läuft so:
    1. Neue Version in PROTOCOL_CONFIGS eintragen (nie eine bestehende
       Zeile ändern — das wäre wieder der stille Bruch).
    2. Knoten aktualisieren; sie akzeptieren dank SUPPORTED_VERSIONS
       für eine Übergangszeit beide Versionen gleichzeitig.
    3. Clients schrittweise auf die neue Version umstellen (buildPacket
       nimmt opts.version).
    4. Alte Version aus SUPPORTED_VERSIONS entfernen, sobald keine
       Pakete der alten Version mehr beobachtet werden.
  Kein Big-Bang-Deploy mehr nötig — siehe test-mixnet-versioning.js.
───────────────────────────────────────────────────────────────────────────*/
const VERSION_BYTE_SIZE = 1;
const LAYER_OVERHEAD = 65 + 16;        // ephemerer Pubkey + GCM-Tag
                                        // (der IV wird abgeleitet, nicht mitgeschickt)
const HEADER_SIZE = 256;               // Routing-Kopf je Schicht, fest

const PROTOCOL_CONFIGS = {
  1: { pathLength: 3, packetSize: 8192 },
  /* Eigene Basisgröße nötig: Mit derselben packetSize wie Version 1 wäre
     der äußerste Hop beider Versionen exakt gleich groß (siehe
     assertNoSizeCollision unten) — die Version ließe sich dann erst nach
     dem Entschlüsseln unterscheiden, und genau das soll das Versionsbyte
     verhindern. 8448 statt 8192 hält beide Größenräume getrennt, ohne
     dass Version 2 spürbar mehr Bandbreite kostet. */
  2: { pathLength: 2, packetSize: 8448 }
};
const CURRENT_VERSION = 1;             // das baut der Client standardmäßig
const SUPPORTED_VERSIONS = [1, 2];     // das akzeptieren Knoten während der Migration

function configFor(version) {
  const cfg = PROTOCOL_CONFIGS[version];
  if (!cfg) throw new Error(`Unbekannte Protokollversion: ${version}`);
  return cfg;
}
/* Innerhalb einer Version ist die Größe fix, aber sie schrumpft pro Hop:
   jede Schicht kostet Kopf + Overhead. Entscheidend ist nicht, dass alle
   Pakete überall gleich groß sind, sondern dass alle Pakete AUF DERSELBEN
   STRECKE gleich groß sind — Hop 1 sieht bei Version 1 immer 8193 Byte
   (inklusive Versionsbyte), Hop 2 immer 7856, unabhängig vom Inhalt. */
function sizesFor(version) {
  const { pathLength, packetSize } = configFor(version);
  const hopSizes = Array.from({ length: pathLength },
    (_, i) => VERSION_BYTE_SIZE + packetSize - i * (LAYER_OVERHEAD + HEADER_SIZE));
  const maxPayload = packetSize - pathLength * (LAYER_OVERHEAD + HEADER_SIZE);
  return { pathLength, packetSize, hopSizes, maxPayload };
}
/* Größe → Version nachschlagen, ohne dass zwei Versionen dieselbe
   Außengröße haben dürfen (sonst wäre die Zuordnung mehrdeutig, noch
   bevor überhaupt ein Byte gelesen wird). */
function versionForSize(totalSize) {
  for (const v of SUPPORTED_VERSIONS) {
    if (sizesFor(v).hopSizes.includes(totalSize)) return v;
  }
  return null;
}
(function assertNoSizeCollision() {
  const seen = new Map();
  for (const v of Object.keys(PROTOCOL_CONFIGS).map(Number)) {
    for (const s of sizesFor(v).hopSizes) {
      if (seen.has(s) && seen.get(s) !== v)
        throw new Error(`Größenkollision zwischen Version ${seen.get(s)} und ${v} bei ${s} Byte`);
      seen.set(s, v);
    }
  }
})();

/* Legacy-Namen: entsprechen CURRENT_VERSION, damit bestehender Code und
   ältere Tests unverändert funktionieren. Neuer Code, der versionsbewusst
   sein muss, verwendet sizesFor(version) direkt. */
const { pathLength: PATH_LENGTH, packetSize: PACKET_SIZE,
        hopSizes: HOP_SIZES, maxPayload: MAX_PAYLOAD } = sizesFor(CURRENT_VERSION);

const MEAN_DELAY_MS = 200;     // Mittelwert der Verzögerung je Knoten
const REPLAY_WINDOW = 10 * 60 * 1000;

/*───────────────────────────────────────────────────────────────────────────
  Krypto-Helfer
───────────────────────────────────────────────────────────────────────────*/
const sha256 = b => crypto.createHash('sha256').update(b).digest();

/* ECDH über P-256 mit rohen Punkten — kompakt und ohne JWK-Ballast */
function newKeypair() {
  const ecdh = crypto.createECDH('prime256v1');
  ecdh.generateKeys();
  return { priv: ecdh.getPrivateKey(), pub: ecdh.getPublicKey() };  // 65 Byte unkomprimiert
}
function sharedSecret(privBuf, peerPub) {
  const ecdh = crypto.createECDH('prime256v1');
  ecdh.setPrivateKey(privBuf);
  return ecdh.computeSecret(peerPub);
}
/* HKDF-SHA256 → Schlüssel + IV für eine Schicht */
function deriveLayer(secret, info) {
  const okm = crypto.hkdfSync('sha256', secret, Buffer.alloc(32), Buffer.from(info), 44);
  const b = Buffer.from(okm);
  return { key: b.subarray(0, 32), iv: b.subarray(32, 44) };
}
function sealLayer(key, iv, plain) {
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([c.update(plain), c.final()]);
  return Buffer.concat([ct, c.getAuthTag()]);
}
function openLayer(key, iv, blob) {
  const tag = blob.subarray(blob.length - 16);
  const ct = blob.subarray(0, blob.length - 16);
  const d = crypto.createDecipheriv('aes-256-gcm', key, iv);
  d.setAuthTag(tag);
  return Buffer.concat([d.update(ct), d.final()]);
}

/* Exponentialverteilte Wartezeit — der eigentliche Mischvorgang */
function poissonDelay(mean = MEAN_DELAY_MS) {
  const u = Math.max(crypto.randomInt(1, 1e6) / 1e6, 1e-6);
  return Math.round(-Math.log(u) * mean);
}

/*───────────────────────────────────────────────────────────────────────────
  Routing-Kopf: feste Größe, damit keine Schicht die Pfadlänge verrät
───────────────────────────────────────────────────────────────────────────*/
function packHeader({ type, next, delay }) {
  const h = Buffer.alloc(HEADER_SIZE);
  h.writeUInt8(type, 0);                      // 1=weiterleiten, 2=zustellen, 3=Dummy
  h.writeUInt16BE(Math.min(delay, 65535), 1);
  const s = Buffer.from(next || '', 'utf8');
  h.writeUInt8(Math.min(s.length, 200), 3);
  s.copy(h, 4, 0, Math.min(s.length, 200));
  return h;
}
function unpackHeader(h) {
  const type = h.readUInt8(0);
  const delay = h.readUInt16BE(1);
  const len = h.readUInt8(3);
  return { type, delay, next: h.subarray(4, 4 + len).toString('utf8') };
}

/*───────────────────────────────────────────────────────────────────────────
  PAKETBAU (Client)
  Von innen nach außen: die letzte Schicht wird zuerst gepackt.
───────────────────────────────────────────────────────────────────────────*/
function buildPacket(path, finalPayload, opts = {}) {
  const version = opts.version ?? CURRENT_VERSION;
  const { pathLength, packetSize, maxPayload } = sizesFor(version);

  if (path.length !== pathLength)
    throw new Error(`Pfad muss für Version ${version} genau ${pathLength} Knoten haben`);

  const payload = Buffer.isBuffer(finalPayload) ? finalPayload : Buffer.from(finalPayload);
  if (payload.length > maxPayload)
    throw new Error(`Nutzlast zu groß: ${payload.length} > ${maxPayload}`);

  /* Auf feste Länge auffüllen: 4 Byte echte Länge, dann Zufallsfüllung.
     So ist jedes Paket gleich groß, ganz gleich wie kurz die Nachricht ist. */
  const padded = Buffer.alloc(maxPayload);
  padded.writeUInt32BE(payload.length, 0);
  payload.copy(padded, 4);
  crypto.randomFillSync(padded, 4 + payload.length);

  const delays = path.map(() => poissonDelay(opts.meanDelay));
  let body = padded;

  /* Rückwärts durch den Pfad: innerste Schicht zuerst */
  for (let i = path.length - 1; i >= 0; i--) {
    const hop = path[i];
    const isLast = i === path.length - 1;
    const header = packHeader({
      type: isLast ? (opts.dummy ? 3 : 2) : 1,
      next: isLast ? (opts.recipientId || '') : path[i + 1].id,
      delay: delays[i]
    });
    const eph = newKeypair();
    /* Die Versionsnummer geht als AAD-artiger Kontext in die Ableitung ein:
       ein Paket, das für Version 1 gebaut wurde, lässt sich nicht als
       Version 2 fehlinterpretieren, selbst wenn die Bytes zufällig zur
       falschen Größe passen würden (durch die Kollisionsprüfung oben
       ausgeschlossen, aber die Ableitung macht es doppelt sicher). */
    const { key, iv } = deriveLayer(sharedSecret(eph.priv, hop.pub), `SecureChat-Mix-v${version}`);
    const sealed = sealLayer(key, iv, Buffer.concat([header, body]));
    body = Buffer.concat([eph.pub, sealed]);
  }

  /* Versionsbyte VOR alles andere — der einzige Teil des Pakets, der
     ohne jede kryptografische Operation lesbar sein muss. */
  const withVersion = Buffer.concat([Buffer.from([version]), body]);

  if (withVersion.length !== VERSION_BYTE_SIZE + packetSize)
    throw new Error(`Paketgröße stimmt nicht: ${withVersion.length} statt ${VERSION_BYTE_SIZE + packetSize}`);
  return { packet: withVersion, firstHop: path[0].id, delays, version,
    expectedLatency: delays.reduce((a, b) => a + b, 0) };
}

/* Ganz innen wieder auspacken — macht nur der Zustelldienst */
function unwrapPayload(padded) {
  const len = padded.readUInt32BE(0);
  return padded.subarray(4, 4 + len);
}

/*───────────────────────────────────────────────────────────────────────────
  MIX-KNOTEN
───────────────────────────────────────────────────────────────────────────*/
class MixNode {
  constructor(id, opts = {}) {
    this.id = id;
    this.keys = newKeypair();
    this.queue = new Map();          // Pakete, die gerade ihre Wartezeit absitzen
    this.seen = new Map();           // Replay-Schutz: Tag → Zeitpunkt
    this.stats = { received: 0, forwarded: 0, delivered: 0, dropped: 0,
      dummies: 0, replays: 0, totalDelay: 0 };
    this.meanDelay = opts.meanDelay ?? MEAN_DELAY_MS;
    this.instant = opts.instant === true;    // nur für Tests: ohne Warten
  }

  get info() { return { id: this.id, pub: this.keys.pub.toString('base64') }; }

  /* Eine Schicht öffnen. Der Knoten erfährt: nächster Hop und Wartezeit.
     Was davor lag und was danach kommt, bleibt ihm verborgen.

     Reihenfolge ist hier bewusst: erst Version lesen (1 Byte, keine
     Krypto), dann Größe dagegen prüfen (Vergleich, keine Krypto), und
     ERST DANN den ephemeren Schlüssel anfassen. Ein Paket mit unbekannter
     Version oder falscher Größe für seine Version bricht also mit einer
     klaren Meldung ab — nie mit einem GCM-Fehler, der wie eine Manipulation
     aussieht, aber in Wahrheit nur ein Versionskonflikt war. */
  peel(packet) {
    if (packet.length < VERSION_BYTE_SIZE + 65)
      throw new Error(`Paket zu kurz: ${packet.length} Byte`);

    const version = packet.readUInt8(0);
    if (!SUPPORTED_VERSIONS.includes(version))
      throw new Error(`Nicht unterstützte Protokollversion: ${version}`);

    const body0 = packet.subarray(VERSION_BYTE_SIZE);
    const expected = sizesFor(version).hopSizes;
    if (!expected.includes(body0.length + VERSION_BYTE_SIZE))
      throw new Error(
        `Ungültige Paketgröße für Version ${version}: ${packet.length} Byte ` +
        `(erwartet eine von: ${expected.join(', ')})`);

    const eph = body0.subarray(0, 65);
    const rest = body0.subarray(65);

    const tag = sha256(eph).toString('base64');
    if (this.seen.has(tag)) { this.stats.replays++; throw new Error('Replay erkannt'); }

    const { key, iv } = deriveLayer(sharedSecret(this.keys.priv, eph), `SecureChat-Mix-v${version}`);
    const opened = openLayer(key, iv, rest);
    this.seen.set(tag, Date.now());

    const header = unpackHeader(opened.subarray(0, HEADER_SIZE));
    const body = opened.subarray(HEADER_SIZE);
    /* Versionsbyte bleibt für den nächsten Hop erhalten — er muss es
       genauso lesen können wie wir gerade. */
    const forwardBody = header.type === 1
      ? Buffer.concat([Buffer.from([version]), body])
      : body;
    return { header, body: forwardBody, version };
  }

  /* Paket annehmen, Schicht öffnen, verzögern, weiterreichen */
  async accept(packet, network) {
    this.stats.received++;
    let peeled;
    try { peeled = this.peel(packet); }
    catch (e) { this.stats.dropped++; throw e; }

    const { header, body } = peeled;
    const wait = this.instant ? 0 : header.delay;
    this.stats.totalDelay += wait;

    const token = crypto.randomBytes(8).toString('hex');
    this.queue.set(token, { at: Date.now() + wait });

    await new Promise(r => setTimeout(r, wait));
    this.queue.delete(token);

    if (header.type === 3) {                     // Dummy: hier endet der Weg
      this.stats.dummies++;
      return { dummy: true };
    }
    if (header.type === 2) {                     // Zustellung
      this.stats.delivered++;
      /* Der letzte Knoten sieht den Empfänger — aber nicht den Absender */
      return { deliver: true, recipientId: header.next, payload: unwrapPayload(body) };
    }
    /* Weiterleiten: die ausgepackte Schicht ist das nächste Paket */
    this.stats.forwarded++;
    return { forward: true, next: header.next, packet: body };
  }

  /* Alte Replay-Einträge aufräumen */
  sweep() {
    const cutoff = Date.now() - REPLAY_WINDOW;
    for (const [t, at] of this.seen) if (at < cutoff) this.seen.delete(t);
  }
  get avgDelay() {
    const n = this.stats.received - this.stats.dropped;
    return n ? Math.round(this.stats.totalDelay / n) : 0;
  }
}

/*───────────────────────────────────────────────────────────────────────────
  NETZWERK — hält die Knoten und schleust Pakete durch
───────────────────────────────────────────────────────────────────────────*/
class MixNetwork {
  constructor(nodes, onDeliver) {
    this.nodes = new Map(nodes.map(n => [n.id, n]));
    this.onDeliver = onDeliver;
    this.inFlight = 0;
  }
  get directory() { return [...this.nodes.values()].map(n => n.info); }

  /* Zufälligen Pfad wählen — ohne einen Knoten doppelt zu nehmen */
  pickPath(length = PATH_LENGTH) {
    const pool = [...this.nodes.values()];
    if (pool.length < length) throw new Error('Zu wenige Mix-Knoten');
    const path = [];
    while (path.length < length) {
      const i = crypto.randomInt(0, pool.length);
      const cand = pool.splice(i, 1)[0];
      path.push({ id: cand.id, pub: cand.keys.pub });
    }
    return path;
  }

  async inject(firstHopId, packet) {
    this.inFlight++;
    try {
      let hop = firstHopId, pkt = packet;
      for (let i = 0; i < PATH_LENGTH + 1; i++) {
        const node = this.nodes.get(hop);
        if (!node) throw new Error('Unbekannter Knoten: ' + hop);
        const r = await node.accept(pkt, this);
        if (r.dummy) return { dummy: true, hops: i + 1 };
        if (r.deliver) {
          if (this.onDeliver) await this.onDeliver(r.recipientId, r.payload);
          return { delivered: true, recipientId: r.recipientId, hops: i + 1 };
        }
        hop = r.next; pkt = r.packet;
      }
      throw new Error('Pfad zu lang');
    } finally { this.inFlight--; }
  }

  stats() {
    const out = {};
    for (const [id, n] of this.nodes)
      out[id] = { ...n.stats, avgDelay: n.avgDelay, queued: n.queue.size };
    return out;
  }
}

/*───────────────────────────────────────────────────────────────────────────
  REMOTE-BETRIEB — Knoten auf fremden Hosts
  ─────────────────────────────────────────────────────────────────────────
  Solange alle Knoten im selben Prozess laufen, ist das Mixnet Theater:
  Wer den Prozess kontrolliert, sieht jede Schicht. Echter Schutz entsteht
  erst, wenn die Knoten bei verschiedenen Betreibern stehen.

  RemoteMixNetwork spricht die Knoten über HTTP an. Die Klasse MixNode
  bleibt unverändert — sie läuft dann eben in einem fremden Prozess
  (siehe mix-node.js).

  Wichtig für die Anonymität:
  • Jeder Knoten kennt nur seinen Nachfolger, nie den ganzen Pfad.
  • Weitergeleitet wird "fire and forget": Der weiterreichende Knoten
    wartet NICHT auf die Antwort des nächsten. Sonst wäre die Antwortzeit
    ein Maß für die Restlänge des Pfades.
  • Fehler werden geschluckt statt zurückgemeldet. Eine Fehlermeldung, die
    bis zum Absender zurückläuft, verrät, wo im Pfad es klemmte.
───────────────────────────────────────────────────────────────────────────*/
class RemoteMixNetwork {
  /**
   * @param directory [{id, url, pub}] — pub als Base64 wie in MixNode.info
   * @param opts.deliverUrl  Wohin der letzte Knoten zustellt
   * @param opts.deliverAuth Gemeinsames Geheimnis für die Zustellung
   * @param opts.timeoutMs   Abbruch je HTTP-Sprung
   */
  constructor(directory, opts = {}) {
    this.dir = new Map(directory.map(n => [n.id, n]));
    this.deliverUrl = opts.deliverUrl || null;
    this.deliverAuth = opts.deliverAuth || null;
    this.timeoutMs = opts.timeoutMs ?? 5000;
    this.fetchImpl = opts.fetch || globalThis.fetch;
    this.stats = { injected: 0, forwarded: 0, failed: 0 };
  }

  get directory() {
    return [...this.dir.values()].map(n => ({ id: n.id, pub: n.pub }));
  }

  pickPath(length = PATH_LENGTH) {
    const pool = [...this.dir.values()];
    if (pool.length < length) throw new Error('Zu wenige Mix-Knoten');
    const path = [];
    while (path.length < length) {
      const i = crypto.randomInt(0, pool.length);
      const cand = pool.splice(i, 1)[0];
      path.push({ id: cand.id, pub: Buffer.from(cand.pub, 'base64') });
    }
    return path;
  }

  /* Paket beim ersten Knoten einwerfen und sofort zurückkehren */
  async inject(firstHopId, packet) {
    const node = this.dir.get(firstHopId);
    if (!node) throw new Error('Unbekannter Knoten: ' + firstHopId);
    /* Gegen alle gültigen Größen über alle unterstützten Versionen prüfen,
       nicht gegen eine einzelne feste Konstante — sonst bräche das bei
       jedem Versionswechsel wieder, genau wie beim ursprünglichen Fehler
       in server.js. Die eigentliche, autoritative Prüfung macht ohnehin
       der empfangende Knoten in MixNode.peel(). */
    const validSizes = SUPPORTED_VERSIONS.flatMap(v => sizesFor(v).hopSizes);
    if (!validSizes.includes(packet.length))
      throw new Error(`Paketgröße ${packet.length} passt zu keiner unterstützten Protokollversion`);
    this.stats.injected++;
    return this.post(node.url + '/forward', {
      packet: Buffer.from(packet).toString('base64')
    });
  }

  /* Von einem Knoten zum nächsten — ohne auf das Ergebnis zu warten */
  forward(nextId, packet) {
    const node = this.dir.get(nextId);
    if (!node) { this.stats.failed++; return; }
    this.stats.forwarded++;
    this.post(node.url + '/forward', {
      packet: Buffer.from(packet).toString('base64')
    }).catch(() => { this.stats.failed++; });
  }

  /* Letzter Knoten liefert beim Zustelldienst ab */
  async deliver(recipientId, payload) {
    if (!this.deliverUrl) return;
    return this.post(this.deliverUrl, {
      recipientId,
      payload: Buffer.from(payload).toString('base64')
    }, this.deliverAuth);
  }

  async post(url, body, auth) {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), this.timeoutMs);
    try {
      const r = await this.fetchImpl(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(auth ? { 'X-Mix-Auth': auth } : {})
        },
        body: JSON.stringify(body),
        signal: ctrl.signal
      });
      return { status: r.status };
    } finally { clearTimeout(t); }
  }
}

module.exports = {
  PACKET_SIZE, PATH_LENGTH, MAX_PAYLOAD, MEAN_DELAY_MS, HOP_SIZES,
  MixNode, MixNetwork, RemoteMixNetwork, buildPacket, unwrapPayload,
  newKeypair, poissonDelay, packHeader, unpackHeader,
  PROTOCOL_CONFIGS, CURRENT_VERSION, SUPPORTED_VERSIONS,
  configFor, sizesFor, versionForSize, VERSION_BYTE_SIZE
};
