/* ═══════════════════════════════════════════════════════════════════════
   DB-TURSO-MOCK — NUR für Entwicklung ohne npm-Registry-Zugriff
   ─────────────────────────────────────────────────────────────────────
   Bildet die execute()-Oberfläche von @libsql/client strukturell exakt
   nach (gleiche Rückgabeform: {rows, columns, rowsAffected,
   lastInsertRowid}), nutzt darunter aber node:sqlite statt echtem
   libSQL/Turso. Zweck: db-turso.js (der eigentliche Adapter, der
   server.js von node:sqlite auf Turso umstellt) lässt sich damit hier
   wirklich end-to-end testen — inklusive async/await-Verhalten, Zeilen-
   umwandlung, Fehlerfälle — bevor es bei dir gegen echtes Turso läuft.

   Diese Datei wird NUR geladen, wenn @libsql/client nicht installierbar
   ist (siehe db-turso.js). Bei dir mit `npm install @libsql/client`
   kommt sie nie zum Einsatz — der Adapter nutzt dann automatisch die
   echte Bibliothek.
   ═══════════════════════════════════════════════════════════════════════ */
'use strict';
const { DatabaseSync } = require('node:sqlite');

function createClient({ url }) {
  const filePath = url.startsWith('file:') ? url.slice(5) : url;
  const db = new DatabaseSync(filePath);

  return {
    async executeMultiple(sql) {
      db.exec(sql);
    },
    async execute({ sql, args = [] }) {
      const stmt = db.prepare(sql);
      const isSelect = /^\s*select/i.test(sql) || /^\s*pragma/i.test(sql);

      if (isSelect) {
        const rows = stmt.all(...args);
        const columns = rows.length ? Object.keys(rows[0]) : [];
        /* node:sqlite liefert bereits Objekte — für die Adapter-Logik
           in db-turso.js (die echtes libSQL mit Array-Zeilen erwartet)
           hier absichtlich AUCH als Array-Form zurückgeben, damit
           rowToObject() in db-turso.js denselben Codepfad wie bei
           echtem Turso durchläuft, statt einen Sonderfall zu brauchen. */
        return {
          rows: rows.map(r => columns.map(c => r[c])),
          columns,
          rowsAffected: 0,
          lastInsertRowid: undefined
        };
      } else {
        const result = stmt.run(...args);
        return {
          rows: [],
          columns: [],
          rowsAffected: result.changes,
          lastInsertRowid: result.lastInsertRowid
        };
      }
    },
    close() {
      db.close();
    }
  };
}

module.exports = { createClient };
