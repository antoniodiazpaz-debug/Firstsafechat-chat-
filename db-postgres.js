/* ═══════════════════════════════════════════════════════════════════════
   DB-POSTGRES — Adapter: bildet die node:sqlite-DatabaseSync-Oberfläche
   (db.exec, db.prepare(sql).run/get/all) auf Postgres (Neon) nach
   ─────────────────────────────────────────────────────────────────────
   Nutzt @neondatabase/serverless im Pool-Modus (TCP, nicht der HTTP-
   One-Shot-Modus) — passend für einen dauerhaft laufenden Node-Prozess
   wie diesen Server, nicht für Edge/Serverless-Funktionen. Laut Neons
   eigener Dokumentation ist Pool/Client aus diesem Paket ein Drop-in-
   Replacement für node-postgres (pg), das Standard-SQL-Protokoll bleibt
   dasselbe.

   WICHTIG — zwei strukturelle Unterschiede zu SQLite, die dieser Adapter
   automatisch ausgleicht, damit server.js unverändert bleiben kann:

   1. Platzhalter: SQLite nutzt "?", Postgres nutzt "$1, $2, ...". Dieser
      Adapter wandelt jedes "?" in der SQL beim ersten prepare()-Aufruf
      automatisch in nummerierte Platzhalter um.

   2. Rückgabewerte: node:sqlite liefert bei .get() ein Objekt oder
      undefined, bei .run() {changes, lastInsertRowid}. pg/Neon liefert
      ein {rows, rowCount}-Objekt. Dieser Adapter formt das auf dasselbe
      vertraute Muster um.

   Was dieser Adapter NICHT automatisch löst: reines SQLite-Schema
   (AUTOINCREMENT, INTEGER für Booleans als 0/1) muss im CREATE-TABLE-
   Text selbst auf Postgres-Syntax angepasst werden (SERIAL, BOOLEAN) —
   das ist eine einmalige Änderung an der Schema-Definition in server.js,
   keine, die dieser Adapter zur Laufzeit übernehmen kann.
   ═══════════════════════════════════════════════════════════════════════ */
'use strict';

let Pool, neonConfig;
try {
  ({ Pool, neonConfig } = require('@neondatabase/serverless'));
  /* Node.js hat kein eingebautes WebSocket-Modul, das die Pool/Client-
     Verbindung von @neondatabase/serverless braucht (anders als Browser/
     Edge-Laufzeiten) — das ws-Paket muss explizit als Konstruktor
     angegeben werden. Ohne diese Zeile scheitert jede Verbindung mit
     einem unklaren "WebSocket is not defined"-Fehler. */
  neonConfig.webSocketConstructor = require('ws');
} catch {
  console.warn('→ @neondatabase/serverless nicht gefunden — Datenbank nicht nutzbar, bis installiert');
  throw new Error('@neondatabase/serverless fehlt — npm install @neondatabase/serverless ausführen');
}

function connect() {
  const connectionString = process.env.DATABASE_URL;
  if (!connectionString) {
    throw new Error('DATABASE_URL fehlt — Neon-Verbindungsstring als Umgebungsvariable setzen');
  }
  const pool = new Pool({ connectionString });
  return wrap(pool);
}

/* Wandelt SQLite-Style "?"-Platzhalter in Postgres-Style "$1, $2, ..."
   um. Läuft einmal pro prepare()-Aufruf, das Ergebnis wird für alle
   späteren .run()/.get()/.all()-Aufrufe desselben Statements wiederverwendet. */
function toPositional(sql) {
  let i = 0;
  return sql.replace(/\?/g, () => `$${++i}`);
}

function wrap(pool) {
  return {
    async exec(sql) {
      /* Mehrere durch Semikolon getrennte CREATE-TABLE-Anweisungen in
         einem Rutsch — pg erlaubt das über einen einzelnen query()-Aufruf
         mit mehreren Statements, solange keine Parameter übergeben werden. */
      await pool.query(sql);
    },

    prepare(sql) {
      const pgSql = toPositional(sql);
      return {
        async run(...args) {
          const result = await pool.query(pgSql, args);
          /* node:sqlite liefert lastInsertRowid nur bei AUTOINCREMENT-
             Tabellen automatisch mit — Postgres braucht dafür ein
             explizites "RETURNING id" im ursprünglichen SQL, das server.js
             an den paar Stellen ergänzen muss, die lastInsertRowid nutzen
             (siehe one_time_prekeys INSERT). Ohne RETURNING bleibt das
             Feld undefined, was für die meisten Aufrufer unschädlich ist,
             weil sie eigene TEXT-IDs per crypto.randomBytes erzeugen,
             nicht auf automatische Postgres-IDs angewiesen sind. */
          return {
            changes: result.rowCount,
            lastInsertRowid: result.rows[0]?.id
          };
        },
        async get(...args) {
          const result = await pool.query(pgSql, args);
          return result.rows[0];   // undefined bei keinem Treffer, wie node:sqlite
        },
        async all(...args) {
          const result = await pool.query(pgSql, args);
          return result.rows;
        }
      };
    },

    async close() {
      await pool.end();
    }
  };
}

module.exports = { connect };
