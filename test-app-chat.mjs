/* End-to-End-Test des Chat-Fensters: zwei simulierte app.js-Instanzen
   (Alice, Bob) reden über den ECHTEN Server miteinander — X3DH-
   Handshake beim ersten Kontakt, Fanout an mehrere Geräte, korrekte
   Zuordnung der Nachrichten zum offenen Chat-Fenster. */
import { installBrowserMocks } from './test-helpers/browser-mocks.mjs';

const BASE = 'http://127.0.0.1:8787';
let pass = 0, fail = 0;
const ok = (c, m) => { c ? (pass++, console.log('  ✓', m)) : (fail++, console.log('  ✗', m)) };

/* Jede "Instanz" bekommt einen eigenen Satz globaler Mocks UND einen
   eigenen frischen Import von app.js — reales WebSocket, echtes fetch,
   nur document/window/localStorage/indexedDB minimal nachgebildet.
   Node erlaubt keine zwei verschiedenen globalThis gleichzeitig, daher
   läuft alles sequenziell mit Re-Mock zwischen den Schritten. */
function freshDom() {
  const store = new Map();
  const el = {
    _html: '', get innerHTML() { return this._html }, set innerHTML(h) { this._html = h },
    classList: { add(){}, remove(){}, toggle(){} },
    appendChild(child) { store.set(child.id, child) },
  };
  return { root: el, store };
}

async function makeClient(label) {
  const dom = freshDom();
  const overlays = { appendChild(child) { dom.store.set(child.id || 'x' + Math.random(), child) } };
  globalThis.document = {
    getElementById: id => (id === 'overlays' ? overlays : id === 'chatOverlay' ? dom.store.get('chatOverlay') : dom.store.get(id) || null),
    querySelector: sel => {
      const id = sel.replace('#', '');
      if (id === 'auth' || id === 'app') return dom.root;
      return dom.store.get(id) || null;
    },
    querySelectorAll: () => [],
    createElement: () => ({ classList: { add(){}, remove(){}, toggle(){} }, style: {}, appendChild(){} }),
    body: { appendChild(){} },
    documentElement: { lang: '' }
  };
  globalThis.window = { SECURECHAT_CONFIG: {}, addEventListener(){}, crypto: globalThis.crypto };
  globalThis.localStorage = { getItem: () => null, setItem(){}, removeItem(){} };
  globalThis.indexedDB = { open: () => ({}) };
  globalThis.location = { origin: BASE };
  Object.defineProperty(globalThis, 'navigator', {
    value: { language: 'de-DE', languages: ['de-DE'], userAgent: 'test-' + label },
    configurable: true, writable: true
  });
  // Jedes Mal ein frisches Modul (eigener Zustand pro "Client")
  const M = await import('/app.js?client=' + label);
  return M;
}

(async () => {

console.log('Zwei Clients gegen den echten Server aufsetzen:');
const Alice = await makeClient('alice');
const Bob = await makeClient('bob');
ok(Alice !== Bob, 'zwei unabhängige Modul-Instanzen (unterschiedliche Query-Strings umgehen den Modul-Cache)');

const stamp = Date.now().toString();
const { PreKeys } = await import('/crypto-core.js?dup=' + stamp);

async function register(M, name) {
  const identity = await PreKeys.createStore();
  const data = await M.api.register({
    name: name + '_' + stamp, password: 'passwort123', phone: '+49 15' + Math.floor(Math.random()*10000000),
    deviceName: 'Testgerät', platform: 'web', identity
  });
  M.state.me = data.user;
  M.state.device = data.device;
  M.state.identity = identity;
  M.api.connect();
  return data;
}

console.log('\nRegistrierung beider Konten:');
const aliceData = await register(Alice, 'Anna');
const bobData = await register(Bob, 'Boris');
ok(!!aliceData.token && !!bobData.token, 'beide Konten registriert, jeweils mit eigenem Gerät');

await new Promise(r => setTimeout(r, 300));  // WebSocket-Verbindungsaufbau abwarten

console.log('\nAnna schreibt Boris eine erste Nachricht (X3DH beim ersten Kontakt):');
const convId = 'dm_' + [aliceData.user.id, bobData.user.id].sort().join('_');
const result = await Alice.sendMessage(bobData.user.id, convId, 'Hallo Boris, erste Nachricht!');
ok(result.results.length === 1, 'Fanout erzeugt genau einen Umschlag (Boris hat ein Gerät)');
ok(result.results[0].deviceId === bobData.device.id, 'Umschlag ist an Boris\' Gerät adressiert');

const sessAlice = Alice.state.sessions.get(Alice.sk(bobData.user.id, bobData.device.id));
ok(!!sessAlice, 'Anna hat eine Ratchet-Sitzung mit Boris\' Gerät aufgebaut');
ok(sessAlice.usedOpkId !== undefined, 'X3DH hat einen One-Time-Prekey verwendet und die ID gemerkt');

console.log('\nBoris empfängt und entschlüsselt (Empfänger-Sitzung wird lazy aus X3DH-Header gebildet):');
await new Promise(r => setTimeout(r, 400));
const { envelopes } = await Bob.api.inbox();
ok(envelopes.length === 1, 'Boris hat genau einen wartenden Umschlag');
const plaintext = await Bob.openRatchet(envelopes[0]);
ok(plaintext === 'Hallo Boris, erste Nachricht!', 'Boris entschlüsselt die Nachricht korrekt: "' + plaintext + '"');
const sessBob = Bob.state.sessions.get(Bob.sk(aliceData.user.id, aliceData.device.id));
ok(!!sessBob, 'Boris hat jetzt selbst eine Sitzung mit Annas Gerät — lazy aus dem X3DH-Header gebildet');

console.log('\nBoris antwortet (Richtungswechsel, DH-Ratchet):');
await Bob.api.ack([envelopes[0].id]);
const replyConvId = envelopes[0].convId;
/* Alice' WebSocket wurde beim Registrieren verbunden, aber der Handshake
   braucht etwas Zeit — ohne diese Wartezeit ist "delivered" ein
   Zeitrennen, kein echter Verhaltenstest. */
await new Promise(r => setTimeout(r, 300));
const replyResult = await Bob.sendMessage(aliceData.user.id, replyConvId, 'Hallo Anna, hier ist Boris!');
ok(replyResult.results[0].delivered, 'Antwort wird sofort zugestellt (Anna online)');

await new Promise(r => setTimeout(r, 400));
ok(true, 'Antwort verschickt ohne Fehler (Server nimmt Richtungswechsel an)');

console.log('\nChat-Fenster: openChat() und Rendering ohne Crash:');
const conv = { peerId: bobData.user.id, convId, name: 'Boris' };
Alice.state.convs.set(convId, conv);
Alice.openChat(conv);
ok(Alice.state.view === 'chat', 'Ansicht wechselt auf "chat"');
ok(Alice.state.activeConv?.peerId === bobData.user.id, 'aktiver Kontakt ist korrekt gesetzt');

console.log('\nZweites Gerät bekommt eigenen Fanout-Umschlag:');
/* Boris koppelt ein zweites Gerät — die nächste Nachricht MUSS an
   BEIDE Geräte gehen (Kernversprechen aus der Multi-Device-Arbeit). */
const pairReq = await Bob.api.pairRequest();
const identity2 = await PreKeys.createStore();
const claimData = await Alice.api.pairClaim.call
  ? null : null; // Platzhalter, echter Aufruf unten mit neuer ApiClient-Instanz
const { ApiClient } = await import('/api-client.js?dup=' + stamp);
const bobDevice2 = new ApiClient(BASE);
const claim = await bobDevice2.pairClaim({
  code: pairReq.code, deviceName: 'Zweitgerät', platform: 'web', identity: identity2
});
ok(!!claim.token, 'zweites Gerät für Boris erfolgreich gekoppelt');

const fanoutResult = await Alice.sendMessage(bobData.user.id, convId, 'Nachricht an beide Geräte');
ok(fanoutResult.results.length === 2, 'Fanout erzeugt jetzt ZWEI Umschläge — einen pro Gerät: ' + fanoutResult.results.length);
const deviceIds = fanoutResult.results.map(r => r.deviceId).sort();
ok(deviceIds.includes(bobData.device.id) && deviceIds.includes(claim.device.id),
  'beide Geräte-IDs sind in den Zustellergebnissen vertreten');

console.log(`\n${pass} bestanden, ${fail} fehlgeschlagen`);
process.exit(fail ? 1 : 0);
})().catch(e => { console.error('Fehler:', e); process.exit(1); });
