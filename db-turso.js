/* ═══════════════════════════════════════════════════════════════════════
   DB-TURSO — Adapter: bildet die node:sqlite-DatabaseSync-Oberfläche
   (db.exec, db.prepare(sql).run/get/all) auf @libsql/client nach
   ─────────────────────────────────────────────────────────────────────
   GRUND: server.js nutzt an 128 Stellen das Muster
     q.xyz = db.prepare('...')
     q.xyz.run(...) / .get(...) / .all(...)
   Das ist SYNCHRON (node:sqlite). @libsql/client ist dagegen komplett
   ASYNCHRON (HTTP-basiert) und hat eine andere API:
     client.execute({sql, args}) -> Promise<ResultSet>  mit .rows
   Statt alle 128 Stellen einzeln auf ein fremdes API-Muster umzustellen,
   bildet dieser Adapter das VERTRAUTE Muster nach — jede zurückgegebene
   .run()/.get()/.all()-Methode liefert jetzt ein PROMISE statt eines
   direkten Werts. Der Umbau in server.js beschränkt sich dadurch auf:
   jeden Aufrufort mit "await" versehen und die umschließende Funktion
   zu "async" machen — die Statement-Definitionen selbst (q = {...})
   bleiben unverändert.

   Turso-Auth: URL und Token kommen ausschließlich aus der Umgebung
   (TURSO_DATABASE_URL, TURSO_AUTH_TOKEN) — nie hartkodiert. Für lokale
   Entwicklung ohne Turso-Konto reicht eine Datei-URL (file:./local.db),
   dieselbe API, kein Netzwerk nötig.
   ═══════════════════════════════════════════════════════════════════════ */
'use strict';

let createClient;
try {
  // Echtes SDK, falls installiert (bei dir: npm install @libsql/client)
  ({ createClient } = require('@libsql/client'));
} catch {
  /* In dieser Entwicklungsumgebung ohne npm-Registry-Zugriff nicht
     installierbar — Fallback auf einen strukturell identischen,
     lokalen Mock (siehe db-turso-mock.js), damit die Umstellungslogik
     hier trotzdem lauffähig getestet werden kann. In einer Umgebung
     mit echtem @libsql/client greift der try-Zweig oben, dieser Mock
     wird dann nie geladen. */
  ({ createClient } = require('./db-turso-mock.js'));
  console.warn('→ @libsql/client nicht gefunden — nutze lokalen Test-Mock (nur für Entwicklung ohne npm-Zugriff)');
}

function connect() {
  const url = process.env.TURSO_DATABASE_URL || 'file:./local.db';
  const authToken = process.env.TURSO_AUTH_TOKEN;   // undefined bei lokaler Datei ist ok
  const client = createClient(authToken ? { url, authToken } : { url });
  return wrap(client);
}

/* Bildet DatabaseSync.exec()/.prepare() nach — .prepare() gibt ein
   Objekt mit .run()/.get()/.all() zurück, jetzt alle async. */
function wrap(client) {
  return {
    /* db.exec('CREATE TABLE ...; CREATE TABLE ...; ...') — mehrere
       Anweisungen durch Semikolon getrennt, wie es die Schema-Definition
       am Anfang von server.js nutzt. libSQL braucht dafür executeMultiple
       statt execute (execute erlaubt nur eine einzelne Anweisung). */
    async exec(sql) {
      await client.executeMultiple(sql);
    },

    prepare(sql) {
      return {
        async run(...args) {
          const result = await client.execute({ sql, args: normalizeArgs(args) });
          /* node:sqlite liefert bei .run() { changes, lastInsertRowid } —
             ResultSet von libSQL hat rowsAffected/lastInsertRowid, hier
             auf denselben Namen gebracht, damit server.js's result.changes
             (siehe purgeAcked-Aufruf) unverändert funktioniert. */
          return { changes: result.rowsAffected, lastInsertRowid: result.lastInsertRowid };
        },
        async get(...args) {
          const result = await client.execute({ sql, args: normalizeArgs(args) });
          if (!result.rows.length) return undefined;   // node:sqlite liefert undefined, nicht null, bei keinem Treffer
          return rowToObject(result.rows[0], result.columns);
        },
        async all(...args) {
          const result = await client.execute({ sql, args: normalizeArgs(args) });
          return result.rows.map(r => rowToObject(r, result.columns));
        }
      };
    },

    close() {
      client.close?.();
    }
  };
}

/* node:sqlite akzeptiert Positions-Parameter direkt als Funktionsargumente
   (z. B. .run(id, name, email)) — @libsql/client will sie als args-Array
   im execute()-Aufruf. Ein einzelnes Argument, das bereits ein Array ist
   (selten, aber zur Sicherheit abgefangen), wird nicht doppelt verschachtelt. */
function normalizeArgs(args) {
  if (args.length === 1 && Array.isArray(args[0])) return args[0];
  return args;
}

/* libSQL liefert Zeilen als Array parallel zu einem separaten columns-
   Array (positionsbasiert) — node:sqlite liefert direkt ein Objekt mit
   Spaltennamen als Keys. Diese Funktion gleicht das an, damit server.js
   weiterhin z. B. row.email statt row[3] schreiben kann. */
function rowToObject(row, columns) {
  if (!Array.isArray(row)) return row;   // schon ein Objekt (z. B. beim Mock)
  const obj = {};
  columns.forEach((col, i) => { obj[col] = row[i]; });
  return obj;
}

module.exports = { connect };
