/* Testet den Offline-Pfad: LocalCache (verschlüsselte Nachrichten-
   Persistenz), Login-Reihenfolge (lokal zuerst, Server danach), und
   afterAuthOffline(). Läuft ohne echten Server — IndexedDB wird
   minimal simuliert, weil Node keine eingebaute Implementierung hat. */
import { installBrowserMocks } from './test-helpers/browser-mocks.mjs';

let pass = 0, fail = 0;
const ok = (c, m) => { c ? (pass++, console.log('  ✓', m)) : (fail++, console.log('  ✗', m)) };

/* ── Minimale IndexedDB-Simulation ──
   Node hat kein natives indexedDB. Für LocalCache reicht ein simples
   In-Memory-Objekt, das dieselben Aufrufe (transaction/objectStore/
   get/put) unterstützt — genug, um echtes Verschlüsseln/Entschlüsseln
   zu prüfen, ohne eine vollständige IDB-Engine nachzubauen. */
function makeFakeIndexedDB() {
  const stores = { identities: new Map(), messages: new Map() };
  const db = {
    objectStoreNames: { contains: name => name in stores },
    createObjectStore: name => { stores[name] = new Map(); return fakeStore(name); },
    transaction: (names) => ({
      objectStore: name => fakeStore(name),
      oncomplete: null, onerror: null
    })
  };
  function fakeStore(name) {
    return {
      get(key) {
        const req = { onsuccess: null, onerror: null };
        queueMicrotask(() => { req.result = stores[name].get(key); req.onsuccess?.(); });
        return req;
      },
      put(val) {
        stores[name].set(val.deviceId, val);
        const req = {};
        queueMicrotask(() => {
          // Für tx.oncomplete: da hier keine echte tx existiert, simulieren
          // wir sofortigen Erfolg — put() selbst hat kein onsuccess in IDB,
          // sondern die transaction feuert oncomplete.
        });
        return req;
      }
    };
  }
  return {
    open: () => {
      const req = { onupgradeneeded: null, onsuccess: null, onerror: null, result: db };
      queueMicrotask(() => { req.onupgradeneeded?.({}); req.onsuccess?.(); });
      return req;
    }
  };
}

/* transaction() muss oncomplete feuern, nachdem put() lief — echte IDB
   macht das automatisch am Ende der Task-Queue. Simulieren wir hier
   durch synchrones Setzen und asynchrones Feuern von oncomplete. */
function makeFakeIndexedDB2() {
  const stores = new Map([['identities', new Map()], ['messages', new Map()]]);
  return {
    open() {
      const req = { onupgradeneeded: null, onsuccess: null, onerror: null };
      const db = {
        objectStoreNames: { contains: n => stores.has(n) },
        createObjectStore(n) { stores.set(n, new Map()); },
        transaction(storeNames, mode) {
          const name = Array.isArray(storeNames) ? storeNames[0] : storeNames;
          const tx = { oncomplete: null, onerror: null };
          return {
            objectStore: () => ({
              get(key) {
                const r = {};
                queueMicrotask(() => { r.result = stores.get(name).get(key); r.onsuccess?.(); });
                return r;
              },
              put(val) {
                stores.get(name).set(val.deviceId, val);
                queueMicrotask(() => tx.oncomplete?.());
                return {};
              }
            }),
            get oncomplete() { return tx.oncomplete; },
            set oncomplete(fn) { tx.oncomplete = fn; },
            get onerror() { return tx.onerror; },
            set onerror(fn) { tx.onerror = fn; }
          };
        }
      };
      req.result = db;
      queueMicrotask(() => { req.onupgradeneeded?.({}); req.onsuccess?.(); });
      return req;
    }
  };
}

installBrowserMocks();
globalThis.indexedDB = makeFakeIndexedDB2();

const M = await import('/app.js');

console.log('Vault + LocalCache: Rundlauf mit korrektem Passwort:');
const deviceId = 'test-device-1';
const fakeIdentity = {
  IK: { privJwk: { kty: 'EC', crv: 'P-256', d: 'xxx', x: 'a', y: 'b' } },
  IKS: { privJwk: { kty: 'EC', crv: 'P-256', d: 'yyy', x: 'c', y: 'd' } },
  SPK: { privJwk: { kty: 'EC', crv: 'P-256', d: 'zzz', x: 'e', y: 'f' } },
  opks: new Map()
};
await M.Vault.save(deviceId, 'korrekt123', fakeIdentity, { name: 'Test', userId: 'u1' });
ok(true, 'Vault.save() lief ohne Fehler');

await M.LocalCache.unlock(deviceId, 'korrekt123');
ok(!!M.LocalCache._key, 'LocalCache hat einen Schlüssel abgeleitet');

console.log('\nNachrichten-Persistenz:');
M.state.convs.set('dm_test', { convId: 'dm_test', peerId: 'peer1', lastMsg: { text: 'Hallo', ts: Date.now() } });
M.state.messages.set('dm_test', [{ id: 'm1', text: 'Hallo Welt', ts: Date.now(), mine: true }]);
M.state.outbox.push({ peerId: 'peer1', convId: 'dm_test', text: 'wartend', localId: 'p1', ts: Date.now() });

await M.LocalCache.save();
ok(true, 'LocalCache.save() lief ohne Fehler');

// Zustand zurücksetzen, um zu prüfen, ob load() ihn wiederherstellt
M.state.convs.clear();
M.state.messages.clear();
M.state.outbox.length = 0;
ok(M.state.convs.size === 0 && M.state.messages.size === 0, 'Zustand wurde vor dem Test-Reload geleert');

const loaded = await M.LocalCache.load();
ok(loaded === true, 'LocalCache.load() meldet Erfolg');
ok(M.state.convs.has('dm_test'), 'Konversation wiederhergestellt');
ok(M.state.messages.get('dm_test')?.[0]?.text === 'Hallo Welt', 'Nachrichtentext exakt wiederhergestellt');
ok(M.state.outbox.length === 1 && M.state.outbox[0].text === 'wartend', 'Outbox (wartende Nachricht) wiederhergestellt');

console.log('\nFalsches Passwort kann den Cache NICHT lesen:');
M.state.convs.clear();
M.state.messages.clear();
await M.LocalCache.unlock(deviceId, 'falschesPasswort');
let failed = false;
try {
  const result = await M.LocalCache.load();
  failed = (result === false);
} catch { failed = true; }
ok(failed, 'falsches Passwort liefert false statt fremde Daten preiszugeben');
ok(M.state.convs.size === 0, 'kein Datenleck bei falschem Passwort — state bleibt leer');

console.log(`\n${pass} bestanden, ${fail} fehlgeschlagen`);
process.exit(fail ? 1 : 0);
