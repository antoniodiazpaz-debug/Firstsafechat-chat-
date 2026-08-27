#!/usr/bin/env node
'use strict';
/*═══════════════════════════════════════════════════════════════════════════
  SecureChat Server — Infrastruktur ohne Fremdabhängigkeiten
  ─────────────────────────────────────────────────────────────────────────
  Nur Node-Bordmittel: node:http, node:crypto, node:sqlite.
  Kein npm install nötig.

  Der Server sieht NIEMALS Klartext. Er speichert:
    • öffentliche Identitäts- und Signaturschlüssel
    • signierte Prekey-Bundles (Signed Prekey + One-Time-Pool)
    • verschlüsselte Nachrichten-Umschläge bis zur Zustellung
    • das Transparenz-Log über alle Identitätsschlüssel

  Was er NICHT kann:
    • Nachrichten lesen (er hat keine privaten Schlüssel)
    • unbemerkt Prekeys austauschen (Bundles sind clientseitig signiert)
    • unbemerkt Identitäten unterschieben (Transparenz-Log + Witnesses)
═══════════════════════════════════════════════════════════════════════════*/

const http = require('node:http');
const crypto = require('node:crypto');
const PUSH = require('./push.js');
const MAIL = require('./mail.js');
const DB = require('./db-postgres.js');
const R2 = require('./r2-presign.js');
const fs = require('node:fs');
const path = require('node:path');

const PORT = process.env.PORT || 8787;
const OPK_LOW_WATER = 5;
/* 19 Jahre statt der früheren 30 Tage — mit der Umstellung auf
   passwortlose Anmeldung gibt es ohne ein noch gültiges Token keinen
   Weg zurück ins Konto außer über Pairing von einem anderen Gerät oder
   die E-Mail-Wiederherstellung (siehe /api/account/recover). Eine
   kurze Ablaufzeit hätte bedeutet, dass ein Konto nach 30 Tagen
   Inaktivität faktisch verloren ist. */
const SESSION_LIFETIME_MS = 19 * 365 * 864e5;

/*───────────────────────────────────────────────────────────────────────────
  DATENBANK
  ─────────────────────────────────────────────────────────────────────────
  Postgres (Neon) statt lokaler node:sqlite-Datei: die Datenbank überlebt
  damit einen Neustart des Servers (wichtig z. B. bei Render/Fly.io/
  Railway, wo das lokale Dateisystem flüchtig ist). DATABASE_URL kommt
  aus der Umgebung — der vollständige Verbindungsstring aus dem
  Neon-Dashboard (siehe db-postgres.js für den Adapter, der SQLite-
  Syntax automatisch auf Postgres abbildet).
───────────────────────────────────────────────────────────────────────────*/
const db = DB.connect();

/* WICHTIG: db.exec() ist jetzt asynchron (Turso/libSQL statt der
   synchronen node:sqlite-API) — die gesamte restliche Server-Definition
   (Statements, Routen, WebSocket-Handler, Serverstart) hängt direkt oder
   indirekt von einer fertig aufgebauten Datenbank ab und läuft deshalb
   innerhalb dieser async-Funktion. Das ist die zentrale strukturelle
   Änderung der Turso-Migration: node:sqlite war komplett synchron und
   erlaubte Top-Level-Code, Turso ist HTTP-basiert und asynchron. */
async function main() {

await db.exec(`
-- Hinweis: SQLite-PRAGMAs (journal_mode, foreign_keys) entfallen hier —
-- Postgres erzwingt Fremdschlüssel immer und hat mit WAL vergleichbare
-- Haltbarkeitsgarantien standardmäßig eingebaut, ohne separate Anweisung.

CREATE TABLE IF NOT EXISTS users (
  id            TEXT PRIMARY KEY,
  name          TEXT UNIQUE NOT NULL,
  phone         TEXT,
  email         TEXT,
  avatar_path   TEXT,        -- Verweis auf R2, das Bild selbst liegt nie in der DB
  bio           TEXT DEFAULT '',
  /* NULLABLE seit der Umstellung auf passwortlose Anmeldung — bleiben
     als Spalten bestehen (nicht per ALTER TABLE entfernt), um keine
     weitere Schema-Migration auf bestehenden Datenbanken zu erzwingen,
     genau das Problem, das die frühere BIGINT-Umstellung schon einmal
     verursacht hat. Neue Registrierungen befüllen sie einfach nicht. */
  pw_salt       TEXT,
  pw_hash       TEXT,
  uak           TEXT,
  allow_sealed  INTEGER DEFAULT 1,
  /* Ohne SMS-Versanddienst gibt es keinen Weg, eine Telefonnummer
     tatsächlich zu bestätigen — jeder könnte sonst jede Nummer angeben.
     E-Mail lässt sich dagegen ohne externen SMS-Anbieter verifizieren
     (ein Link im Posteingang). Beide Felder sind bewusst getrennt von
     phone/email selbst: ein unverifizierter Kontaktweg bleibt nutzbar
     für den Kontaktabgleich, aber Funktionen, die echte Identität
     brauchen (Kontowiederherstellung, Meldung an Behörden), können auf
     is_email_verified prüfen. */
  email_verified   INTEGER DEFAULT 0,
  phone_verified   INTEGER DEFAULT 0,   -- nur über WebOTP im Browser möglich, siehe unten
  created_at    BIGINT NOT NULL,
  last_seen     BIGINT NOT NULL
);

-- ═══════════════════════════════════════════════════════════════════════
-- E-MAIL-VERIFIZIERUNG
-- ─────────────────────────────────────────────────────────────────────
-- Kein SMS-Anbieter nötig: ein zufälliger Code läuft über den bereits
-- gehashten Kontaktkanal E-Mail. Ohne konfigurierten SMTP_* in der Umgebung
-- wird kein Code verschickt, aber das Konto funktioniert trotzdem —
-- email_verified bleibt dann einfach 0, statt Registrierung zu blockieren.
-- Eine harte SMS-Pflicht würde Menschen ohne eigene Nummer ausschließen,
-- was für ein Werkzeug mit Sicherheitsanspruch der falsche Kompromiss ist.
-- ═══════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS email_verifications (
  user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code_hash   TEXT NOT NULL,      -- SHA-256 des Codes, nie der Code selbst
  attempts    INTEGER DEFAULT 0,
  created_at  BIGINT NOT NULL,
  expires_at  BIGINT NOT NULL,
  PRIMARY KEY (user_id)
);

/* Kontowiederherstellung: falls das lokale Sitzungstoken verloren geht
   (Browser-Daten gelöscht, neues Gerät ohne Möglichkeit zu koppeln),
   ist die verifizierte E-Mail-Adresse der einzige verbleibende Weg
   zurück ins bestehende Konto — es gibt kein Passwort mehr, das
   alternativ abgefragt werden könnte. Bewusst eine EIGENE Tabelle statt
   Wiederverwendung von email_verifications: die beiden Codes haben
   unterschiedliche Tragweite (E-Mail bestätigen vs. tatsächlichen
   Kontenzugriff gewähren) und sollen nie versehentlich gegeneinander
   austauschbar sein. */
CREATE TABLE IF NOT EXISTS account_recovery (
  user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code_hash   TEXT NOT NULL,
  attempts    INTEGER DEFAULT 0,
  created_at  BIGINT NOT NULL,
  expires_at  BIGINT NOT NULL,
  PRIMARY KEY (user_id)
);


-- ═══════════════════════════════════════════════════════════════════════
-- GERÄTE — Multi-Device (Weg B)
-- ─────────────────────────────────────────────────────────────────────
-- Ein Nutzer kann mehrere Geräte registrieren. Jedes Gerät hat sein
-- EIGENES Identitätsschlüsselpaar und damit seinen eigenen Ratchet-
-- Zustand mit jedem Kontakt. Absender verschlüsseln beim Senden für
-- ALLE aktiven Geräte des Empfängers (Sender-Key-Fanout, wie bei
-- Signal) — nicht für den Nutzer als solchen.
--
-- Das Hauptgerät (is_primary=1) kann neue Geräte autorisieren, indem es
-- einen kurzlebigen Pairing-Code erzeugt, den das neue Gerät per QR
-- einliest (siehe /api/devices/pair-*). Ohne dieses Einverständnis kann
-- sich kein zweites Gerät als "vertrauenswürdig" eintragen.
-- ═══════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS devices (
  id            TEXT PRIMARY KEY,
  user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name          TEXT NOT NULL,       -- "iPhone von Anna", "Chrome auf Laptop" …
  platform      TEXT NOT NULL,       -- web | android | ios
  ik_dh         TEXT NOT NULL,       -- öffentlicher ECDH-Identitätsschlüssel dieses Geräts
  ik_sign       TEXT NOT NULL,       -- öffentlicher ECDSA-Signaturschlüssel dieses Geräts
  is_primary    INTEGER DEFAULT 0,
  push_token    TEXT,                -- FCM/Web-Push-Endpunkt, siehe push_subscriptions
  created_at    BIGINT NOT NULL,
  last_seen     BIGINT NOT NULL,
  revoked_at    BIGINT              -- gesetzt, wenn das Gerät entfernt wurde
);
CREATE INDEX IF NOT EXISTS idx_devices_user ON devices(user_id) WHERE revoked_at IS NULL;

-- Kurzlebiger Pairing-Code: Hauptgerät zeigt QR, neues Gerät scannt ihn.
CREATE TABLE IF NOT EXISTS device_pairings (
  code        TEXT PRIMARY KEY,
  user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at  BIGINT NOT NULL,
  expires_at  BIGINT NOT NULL,
  consumed    INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS sessions (
  token      TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  device_id  TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  created_at BIGINT NOT NULL,
  expires_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_device ON sessions(device_id);

-- Signed Prekey: einer pro GERÄT, nicht pro Nutzer — jedes Gerät hat
-- seinen eigenen Ratchet-Zustand und braucht daher eigene Prekeys.
CREATE TABLE IF NOT EXISTS signed_prekeys (
  device_id  TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
  spk_id     INTEGER NOT NULL,
  pub        TEXT NOT NULL,
  signature  TEXT NOT NULL,         -- ECDSA über ikDH‖spk‖spkId‖createdAt (des Geräts)
  created_at BIGINT NOT NULL
);

-- One-Time Prekeys: Pool pro Gerät
CREATE TABLE IF NOT EXISTS one_time_prekeys (
  id         SERIAL PRIMARY KEY,
  device_id  TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  opk_id     INTEGER NOT NULL,
  pub        TEXT NOT NULL,
  consumed   INTEGER DEFAULT 0,
  consumed_at BIGINT,
  UNIQUE(device_id, opk_id)
);
CREATE INDEX IF NOT EXISTS idx_opk_avail ON one_time_prekeys(device_id, consumed);

-- Verschlüsselte Umschläge: Store-and-Forward bis zur Zustellung.
-- recipient_device_id ist das eigentlich Neue: eine gesendete Nachricht
-- erzeugt einen Umschlag PRO aktivem Empfängergerät (Sender-Key-Fanout),
-- weil jedes Gerät seinen eigenen Ratchet-Zustand hat und die Nachricht
-- separat verschlüsselt bekommen muss.
CREATE TABLE IF NOT EXISTS envelopes (
  id                   TEXT PRIMARY KEY,
  sender_id            TEXT,               -- NULL bei Sealed Sender
  sender_device_id     TEXT,               -- NULL bei Sealed Sender
  sealed               INTEGER DEFAULT 0,
  recipient_id         TEXT NOT NULL,
  recipient_device_id  TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  conv_id              TEXT NOT NULL,
  group_id             TEXT,
  kind                 TEXT NOT NULL DEFAULT 'text',
  header               TEXT,               -- Ratchet-Header; bei sealed Teil des Blobs
  ciphertext           TEXT NOT NULL,      -- Base64, für den Server undurchsichtig
  gossip               TEXT,               -- mitgereiste Log-Wurzel des Absenders
  sent_at              BIGINT NOT NULL,
  delivered_at         BIGINT,
  acked                INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_env_recipient ON envelopes(recipient_device_id, acked);

-- Transparenz-Log: append-only, jede Zeile ist ein Blatt
CREATE TABLE IF NOT EXISTS kt_entries (
  idx        INTEGER PRIMARY KEY,   -- Blattindex, lückenlos ab 0
  user_id    TEXT NOT NULL,
  key_x      TEXT NOT NULL,
  key_y      TEXT NOT NULL,
  version    INTEGER NOT NULL,
  leaf_hash  TEXT NOT NULL,
  added_at   BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_kt_user ON kt_entries(user_id);

CREATE TABLE IF NOT EXISTS kt_sths (
  size       INTEGER PRIMARY KEY,
  root       TEXT NOT NULL,
  ts         BIGINT NOT NULL,
  signature  TEXT NOT NULL,
  cosigs     TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS groups_tbl (
  id         TEXT PRIMARY KEY,
  name       TEXT NOT NULL,
  avatar     TEXT DEFAULT '👥',
  owner_id   TEXT NOT NULL,
  created_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS group_members (
  group_id  TEXT NOT NULL REFERENCES groups_tbl(id) ON DELETE CASCADE,
  user_id   TEXT NOT NULL,
  wrapped   TEXT,                   -- für dieses Mitglied verschlüsselter Gruppenschlüssel
  is_admin  INTEGER DEFAULT 0,
  PRIMARY KEY(group_id, user_id)
);

-- ═══════════════════════════════════════════════════════════════════════
-- PUSH-BENACHRICHTIGUNGEN
-- ─────────────────────────────────────────────────────────────────────
-- Web Push (VAPID) für die Browser-Version, FCM-Token für Android/iOS
-- über Capacitor. Der Inhalt der Push-Nachricht ist bewusst leer/generisch
-- (siehe sw.js) — der Server kennt den Klartext nie, kann ihn also auch
-- nicht in eine Push-Payload packen.
-- ═══════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS push_subscriptions (
  device_id   TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
  platform    TEXT NOT NULL,         -- web | fcm
  endpoint    TEXT NOT NULL,         -- Web-Push-URL oder FCM-Token
  p256dh      TEXT,                  -- nur bei web
  auth        TEXT,                  -- nur bei web
  created_at  BIGINT NOT NULL
);

-- ═══════════════════════════════════════════════════════════════════════
-- KONTAKTABGLEICH ("X nutzt die App auch")
-- ─────────────────────────────────────────────────────────────────────
-- Der Client hasht Telefonnummern/E-Mails LOKAL (SHA-256 + Salt) und
-- schickt nur die Hashes. Der Server vergleicht Hash gegen Hash und
-- verrät nie eine im Klartext gespeicherte Nummer eines Dritten.
-- contact_hashes speichert, was EIN Nutzer bereits als "gefunden"
-- gemeldet bekam, damit die Push-Benachrichtigung nicht bei jedem
-- Sync erneut verschickt wird.
-- ═══════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS contact_hashes (
  user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  hash        TEXT NOT NULL,         -- SHA-256(normalisierte Nummer/E-Mail + Pfeffer)
  kind        TEXT NOT NULL DEFAULT 'contact',  -- 'self' = eigene Nummer/E-Mail, 'contact' = aus Adressbuch importiert
  PRIMARY KEY(user_id, hash)
);
CREATE INDEX IF NOT EXISTS idx_contact_hashes_hash ON contact_hashes(hash);

CREATE TABLE IF NOT EXISTS contact_matches_notified (
  user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  matched_id   TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  notified_at  BIGINT NOT NULL,
  PRIMARY KEY(user_id, matched_id)
);

-- ═══════════════════════════════════════════════════════════════════════
-- BLOCKIEREN UND MELDEN
-- ═══════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS blocks (
  blocker_id  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  blocked_id  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at  BIGINT NOT NULL,
  PRIMARY KEY(blocker_id, blocked_id)
);

CREATE TABLE IF NOT EXISTS reports (
  id            TEXT PRIMARY KEY,
  reporter_id   TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  reported_id   TEXT NOT NULL,        -- wer gemeldet wird — kein FK, falls Konto gelöscht wird
  conv_id       TEXT,
  reason        TEXT NOT NULL,
  note          TEXT,
  -- Inhalt wird NUR gespeichert, wenn der Meldende ihn ausdrücklich
  -- beifügt (siehe reportMessage() im Client) — niemals automatisch,
  -- weil der Server bei E2EE sonst gar keinen Klartext hätte.
  included_content TEXT,
  created_at    BIGINT NOT NULL,
  reviewed      INTEGER DEFAULT 0
);
`);

const q = {
  userByName:   db.prepare('SELECT * FROM users WHERE lower(name)=lower(?)'),
  userById:     db.prepare('SELECT * FROM users WHERE id=?'),
  userByEmail:  db.prepare('SELECT * FROM users WHERE email=?'),
  allUsers:     db.prepare('SELECT id,name,avatar_path,bio,phone,last_seen FROM users'),
  insertUser:   db.prepare(`INSERT INTO users
    (id,name,phone,email,avatar_path,bio,pw_salt,pw_hash,created_at,last_seen)
    VALUES (?,?,?,?,?,?,?,?,?,?)`),
  /* ON DELETE CASCADE ist auf JEDER Tabelle mit user_id-Fremdschlüssel
     bereits gesetzt (devices, sessions, envelopes, contact_hashes,
     blocks, reports, ...) — ein einziges DELETE hier räumt daher das
     komplette Konto vollständig ab, ohne dass server.js jede Tabelle
     einzeln einzeln durchgehen muss. */
  deleteUser:   db.prepare('DELETE FROM users WHERE id=?'),
  touchUser:    db.prepare('UPDATE users SET last_seen=? WHERE id=?'),
  updateProfile:db.prepare('UPDATE users SET name=?,bio=?,phone=? WHERE id=?'),
  updateAvatar: db.prepare('UPDATE users SET avatar_path=? WHERE id=?'),
  markEmailVerified: db.prepare('UPDATE users SET email_verified=1 WHERE id=?'),
  markPhoneVerified: db.prepare('UPDATE users SET phone_verified=1 WHERE id=?'),

  /* ---- E-Mail-Verifizierung ---- */
  putEmailCode: db.prepare(`INSERT INTO email_verifications (user_id,code_hash,attempts,created_at,expires_at)
    VALUES (?,?,0,?,?) ON CONFLICT(user_id) DO UPDATE SET
    code_hash=excluded.code_hash, attempts=0, created_at=excluded.created_at, expires_at=excluded.expires_at`),
  getEmailCode: db.prepare('SELECT * FROM email_verifications WHERE user_id=?'),
  bumpEmailAttempts: db.prepare('UPDATE email_verifications SET attempts=attempts+1 WHERE user_id=?'),
  dropEmailCode: db.prepare('DELETE FROM email_verifications WHERE user_id=?'),

  /* ---- Kontowiederherstellung ---- */
  putRecoveryCode: db.prepare(`INSERT INTO account_recovery (user_id,code_hash,attempts,created_at,expires_at)
    VALUES (?,?,0,?,?) ON CONFLICT(user_id) DO UPDATE SET
    code_hash=excluded.code_hash, attempts=0, created_at=excluded.created_at, expires_at=excluded.expires_at`),
  getRecoveryCode: db.prepare('SELECT * FROM account_recovery WHERE user_id=?'),
  bumpRecoveryAttempts: db.prepare('UPDATE account_recovery SET attempts=attempts+1 WHERE user_id=?'),
  dropRecoveryCode: db.prepare('DELETE FROM account_recovery WHERE user_id=?'),

  /* ---- Geräte ---- */
  insertDevice: db.prepare(`INSERT INTO devices
    (id,user_id,name,platform,ik_dh,ik_sign,is_primary,created_at,last_seen)
    VALUES (?,?,?,?,?,?,?,?,?)`),
  deviceById:   db.prepare('SELECT * FROM devices WHERE id=? AND revoked_at IS NULL'),
  devicesOf:    db.prepare('SELECT * FROM devices WHERE user_id=? AND revoked_at IS NULL ORDER BY created_at'),
  touchDevice:  db.prepare('UPDATE devices SET last_seen=? WHERE id=?'),
  revokeDevice: db.prepare('UPDATE devices SET revoked_at=? WHERE id=? AND user_id=?'),
  hasPrimary:   db.prepare('SELECT COUNT(*) AS n FROM devices WHERE user_id=? AND is_primary=1 AND revoked_at IS NULL'),
  countDevices: db.prepare('SELECT COUNT(*) AS n FROM devices WHERE user_id=? AND revoked_at IS NULL'),

  createPairing: db.prepare('INSERT INTO device_pairings (code,user_id,created_at,expires_at) VALUES (?,?,?,?)'),
  getPairing:    db.prepare('SELECT * FROM device_pairings WHERE code=? AND expires_at>? AND consumed=0'),
  consumePairing:db.prepare('UPDATE device_pairings SET consumed=1 WHERE code=?'),

  insertSession:db.prepare('INSERT INTO sessions (token,user_id,device_id,created_at,expires_at) VALUES (?,?,?,?,?)'),
  session:      db.prepare('SELECT * FROM sessions WHERE token=? AND expires_at>?'),
  dropSession:  db.prepare('DELETE FROM sessions WHERE token=?'),
  dropDeviceSessions: db.prepare('DELETE FROM sessions WHERE device_id=?'),

  /* ---- Prekeys, jetzt pro Gerät ---- */
  putSPK:       db.prepare(`INSERT INTO signed_prekeys (device_id,spk_id,pub,signature,created_at)
    VALUES (?,?,?,?,?) ON CONFLICT(device_id) DO UPDATE SET
    spk_id=excluded.spk_id, pub=excluded.pub, signature=excluded.signature,
    created_at=excluded.created_at`),
  getSPK:       db.prepare('SELECT * FROM signed_prekeys WHERE device_id=?'),

  addOPK:       db.prepare('INSERT INTO one_time_prekeys (device_id,opk_id,pub) VALUES (?,?,?) ON CONFLICT(device_id,opk_id) DO NOTHING'),
  takeOPK:      db.prepare('SELECT * FROM one_time_prekeys WHERE device_id=? AND consumed=0 ORDER BY opk_id LIMIT 1'),
  markOPK:      db.prepare('UPDATE one_time_prekeys SET consumed=1, consumed_at=? WHERE id=?'),
  countOPK:     db.prepare('SELECT COUNT(*) AS n FROM one_time_prekeys WHERE device_id=? AND consumed=0'),

  setUAK:       db.prepare('UPDATE users SET uak=?, allow_sealed=? WHERE id=?'),
  byUAK:        db.prepare('SELECT * FROM users WHERE id=? AND uak=? AND allow_sealed=1'),

  /* ---- Umschläge: jetzt pro Empfängergerät ---- */
  putEnvelope:  db.prepare(`INSERT INTO envelopes
    (id,sender_id,sender_device_id,sealed,recipient_id,recipient_device_id,conv_id,group_id,kind,header,ciphertext,gossip,sent_at)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`),
  pending:      db.prepare('SELECT * FROM envelopes WHERE recipient_device_id=? AND acked=0 ORDER BY sent_at'),
  ackEnvelope:  db.prepare('UPDATE envelopes SET acked=1, delivered_at=? WHERE id=? AND recipient_device_id=?'),
  purgeAcked:   db.prepare('DELETE FROM envelopes WHERE acked=1 AND delivered_at < ?'),

  ktCount:      db.prepare('SELECT COUNT(*) AS n FROM kt_entries'),
  ktLeaves:     db.prepare('SELECT leaf_hash FROM kt_entries ORDER BY idx'),
  ktAdd:        db.prepare(`INSERT INTO kt_entries (idx,user_id,key_x,key_y,version,leaf_hash,added_at)
    VALUES (?,?,?,?,?,?,?)`),
  ktByUser:     db.prepare('SELECT * FROM kt_entries WHERE user_id=? ORDER BY idx'),
  ktLatestFor:  db.prepare('SELECT * FROM kt_entries WHERE user_id=? ORDER BY idx DESC LIMIT 1'),
  ktPutSTH:     db.prepare(`INSERT INTO kt_sths (size,root,ts,signature,cosigs) VALUES (?,?,?,?,?)
    ON CONFLICT(size) DO UPDATE SET root=excluded.root, ts=excluded.ts,
    signature=excluded.signature, cosigs=excluded.cosigs`),
  ktLatestSTH:  db.prepare('SELECT * FROM kt_sths ORDER BY size DESC LIMIT 1'),
  ktSTHBySize:  db.prepare('SELECT * FROM kt_sths WHERE size=?'),

  addGroup:     db.prepare('INSERT INTO groups_tbl (id,name,avatar,owner_id,created_at) VALUES (?,?,?,?,?)'),
  addMember:    db.prepare(`INSERT INTO group_members (group_id,user_id,wrapped,is_admin) VALUES (?,?,?,?)
    ON CONFLICT(group_id,user_id) DO UPDATE SET wrapped=excluded.wrapped, is_admin=excluded.is_admin`),
  groupsOf:     db.prepare(`SELECT g.* FROM groups_tbl g JOIN group_members m ON m.group_id=g.id
                            WHERE m.user_id=?`),
  membersOf:    db.prepare('SELECT * FROM group_members WHERE group_id=?'),
  myWrapped:    db.prepare('SELECT wrapped FROM group_members WHERE group_id=? AND user_id=?'),

  /* ---- Push ---- */
  putPush:      db.prepare(`INSERT INTO push_subscriptions (device_id,platform,endpoint,p256dh,auth,created_at)
    VALUES (?,?,?,?,?,?) ON CONFLICT(device_id) DO UPDATE SET
    platform=excluded.platform, endpoint=excluded.endpoint, p256dh=excluded.p256dh,
    auth=excluded.auth, created_at=excluded.created_at`),
  pushForDevice:db.prepare('SELECT * FROM push_subscriptions WHERE device_id=?'),
  dropPush:     db.prepare('DELETE FROM push_subscriptions WHERE device_id=?'),

  /* ---- Kontaktabgleich ---- */
  putSelfHash:  db.prepare(`INSERT INTO contact_hashes (user_id,hash,kind) VALUES (?,?,'self') ON CONFLICT(user_id,hash) DO NOTHING`),
  putContactHash: db.prepare(`INSERT INTO contact_hashes (user_id,hash,kind) VALUES (?,?,'contact') ON CONFLICT(user_id,hash) DO NOTHING`),
  clearContactHashes: db.prepare(`DELETE FROM contact_hashes WHERE user_id=? AND kind='contact'`),
  /* Ein Treffer entsteht, wenn EIN eingereichter Kontakt-Hash mit dem
     SELBST-Hash eines anderen Nutzers übereinstimmt — nicht mit dessen
     importierter Kontaktliste. Sonst würde A schon dann als "gefunden"
     gelten, wenn B zufällig dieselbe dritte Person kennt wie A. */
  findByHash:   db.prepare(`SELECT DISTINCT self.user_id AS matched_id
    FROM contact_hashes mine
    JOIN contact_hashes self ON mine.hash = self.hash AND self.kind = 'self'
    WHERE mine.user_id=? AND mine.kind='contact' AND self.user_id!=?`),
  wasNotified:  db.prepare('SELECT 1 FROM contact_matches_notified WHERE user_id=? AND matched_id=?'),
  markNotified: db.prepare('INSERT INTO contact_matches_notified (user_id,matched_id,notified_at) VALUES (?,?,?) ON CONFLICT(user_id,matched_id) DO NOTHING'),

  /* ---- Blockieren & Melden ---- */
  addBlock:     db.prepare('INSERT INTO blocks (blocker_id,blocked_id,created_at) VALUES (?,?,?) ON CONFLICT(blocker_id,blocked_id) DO NOTHING'),
  removeBlock:  db.prepare('DELETE FROM blocks WHERE blocker_id=? AND blocked_id=?'),
  isBlocked:    db.prepare('SELECT 1 FROM blocks WHERE blocker_id=? AND blocked_id=?'),
  blockedByMe:  db.prepare('SELECT blocked_id FROM blocks WHERE blocker_id=?'),

  addReport:    db.prepare(`INSERT INTO reports
    (id,reporter_id,reported_id,conv_id,reason,note,included_content,created_at)
    VALUES (?,?,?,?,?,?,?,?)`)
};

/*───────────────────────────────────────────────────────────────────────────
  KRYPTO — nur was der Server selbst braucht
───────────────────────────────────────────────────────────────────────────*/
const sha256 = b => crypto.createHash('sha256').update(b).digest();
const b64 = b => Buffer.from(b).toString('base64');
const ub64 = s => Buffer.from(s, 'base64');

/* UNGENUTZT seit der Umstellung auf passwortlose Anmeldung — keine
   Route ruft diese Funktionen mehr auf. Bleiben bestehen (nicht
   gelöscht), weil sie am Ende der Datei exportiert werden und
   möglicherweise von externen Testdateien referenziert werden. */
function hashPw(pw, saltB64) {
  const salt = saltB64 ? ub64(saltB64) : crypto.randomBytes(16);
  const hash = crypto.scryptSync(pw, salt, 64, { N: 16384, r: 8, p: 1 });
  return { salt: b64(salt), hash: b64(hash) };
}
function verifyPw(pw, rec) {
  const { hash } = hashPw(pw, rec.pw_salt);
  const a = ub64(hash), b = ub64(rec.pw_hash);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

/* Log-Signaturschlüssel: beim ersten Start erzeugt, danach von Platte */
const KEYFILE = path.join(__dirname, 'log-signing-key.json');
let logKeys;
if (fs.existsSync(KEYFILE)) {
  logKeys = JSON.parse(fs.readFileSync(KEYFILE, 'utf8'));
} else {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  logKeys = {
    priv: privateKey.export({ type: 'pkcs8', format: 'pem' }),
    pub:  publicKey.export({ type: 'spki',  format: 'pem' }),
    jwk:  publicKey.export({ format: 'jwk' })
  };
  fs.writeFileSync(KEYFILE, JSON.stringify(logKeys, null, 2), { mode: 0o600 });
  console.log('→ Neuer Log-Signaturschlüssel erzeugt:', KEYFILE);
}
const signLog = data =>
  b64(crypto.sign('sha256', Buffer.from(data), { key: logKeys.priv, dsaEncoding: 'ieee-p1363' }));

/* VAPID-Schlüssel (RFC 8292) für Web Push: wie der Log-Signaturschlüssel
   einmalig erzeugt und dauerhaft gespeichert. Ein Schlüsselwechsel würde
   alle bestehenden Push-Abos ungültig machen — Browser binden das Abo
   an den öffentlichen Schlüssel, mit dem es erstellt wurde. */
const VAPID_KEYFILE = path.join(__dirname, 'vapid-key.json');
let vapidKeys;
if (fs.existsSync(VAPID_KEYFILE)) {
  vapidKeys = JSON.parse(fs.readFileSync(VAPID_KEYFILE, 'utf8'));
} else {
  const generated = PUSH.generateVapidKeys();
  vapidKeys = { publicKey: generated.publicKey, privateKeyJwk: generated.privateKeyJwk };
  fs.writeFileSync(VAPID_KEYFILE, JSON.stringify(vapidKeys, null, 2), { mode: 0o600 });
  console.log('→ Neue VAPID-Schlüssel erzeugt:', VAPID_KEYFILE);
}
const VAPID_SUBJECT = process.env.VAPID_SUBJECT || 'mailto:admin@example.com';

/* FCM-Service-Account (HTTP v1 API): JSON-Datei, wie sie die Firebase-
   Konsole unter Projekteinstellungen → Dienstkonten → Neuen privaten
   Schlüssel generieren liefert. Optional — ohne diese Datei funktioniert
   alles außer Android/iOS-Push weiterhin normal. */
const FCM_KEYFILE = process.env.FCM_SERVICE_ACCOUNT_FILE ||
  path.join(__dirname, 'fcm-service-account.json');
let fcmServiceAccount = null;
if (fs.existsSync(FCM_KEYFILE)) {
  try { fcmServiceAccount = JSON.parse(fs.readFileSync(FCM_KEYFILE, 'utf8')); }
  catch (e) { console.warn('→ FCM-Service-Account-Datei ungültig:', e.message); }
}

/*───────────────────────────────────────────────────────────────────────────
  SEALED SENDER
  ─────────────────────────────────────────────────────────────────────────
  Ziel: Der Server soll nicht wissen, WER schreibt — nur an wen zuzustellen ist.

  Zwei Bausteine greifen ineinander:

  1) Absenderzertifikat
     Der Server stellt jedem angemeldeten Nutzer ein kurzlebiges, signiertes
     Zertifikat aus: { senderId, senderName, ikDH, expiresAt }.
     Es wandert VERSCHLÜSSELT im Umschlag mit. Der Empfänger prüft die
     Serversignatur und weiß dadurch, dass die Absenderangabe echt ist —
     ohne dass der Server beim Senden erfährt, wer gerade schreibt.

  2) Unidentified Access Key (UAK)
     Aus dem Profilschlüssel abgeleitet und nur an Kontakte weitergegeben.
     Wer den UAK vorzeigt, darf ohne Login an genau diesen Empfänger
     zustellen. Das ersetzt die Authentifizierung als Spam-Bremse, ohne
     eine Absenderidentität preiszugeben.

  Der Umschlag selbst ist an den Identitätsschlüssel des Empfängers
  verschlüsselt: ephemeres ECDH → HKDF → AES-256-GCM. Innen liegen
  Zertifikat, Ratchet-Header und das eigentliche Chiffrat.
  Der Server sieht: Empfänger, Größe, Zeitpunkt. Sonst nichts.
───────────────────────────────────────────────────────────────────────────*/
const CERT_TTL = 24 * 3600 * 1000;

const certBytes = c =>
  Buffer.from(['sendercert-v1', c.senderId, c.senderName, c.senderDeviceId, c.ikX, c.ikY, c.expiresAt].join('|'));

/* Zertifikat gehört zum sendenden GERÄT, nicht nur zum Nutzer — der
   Empfänger muss wissen, welches Gerät geschrieben hat, um den richtigen
   Ratchet-Zustand zu verwenden (jedes Gerät hat einen eigenen). */
function issueSenderCertificate(user, device) {
  const ik = JSON.parse(device.ik_dh);
  const cert = {
    senderId: user.id, senderName: user.name, senderDeviceId: device.id,
    ikX: ik.x, ikY: ik.y,
    expiresAt: Date.now() + CERT_TTL
  };
  cert.signature = signLog(certBytes(cert).toString());
  return cert;
}

/*───────────────────────────────────────────────────────────────────────────*/
/*───────────────────────────────────────────────────────────────────────────
  MERKLE-LOG nach RFC 6962
───────────────────────────────────────────────────────────────────────────*/
const leafHash = d => sha256(Buffer.concat([Buffer.from([0x00]), Buffer.from(d)]));
const nodeHash = (l, r) => sha256(Buffer.concat([Buffer.from([0x01]), l, r]));
const splitPoint = n => { let k = 1; while (k * 2 < n) k *= 2; return k; };

function MTH(lv) {
  if (lv.length === 0) return sha256(Buffer.alloc(0));
  if (lv.length === 1) return lv[0];
  const k = splitPoint(lv.length);
  return nodeHash(MTH(lv.slice(0, k)), MTH(lv.slice(k)));
}
function inclusionPath(m, lv) {
  if (lv.length === 1) return [];
  const k = splitPoint(lv.length);
  return m < k
    ? [...inclusionPath(m, lv.slice(0, k)), MTH(lv.slice(k))]
    : [...inclusionPath(m - k, lv.slice(k)), MTH(lv.slice(0, k))];
}
function subproof(m, lv, b) {
  if (m === lv.length) return b ? [] : [MTH(lv)];
  const k = splitPoint(lv.length);
  return m <= k
    ? [...subproof(m, lv.slice(0, k), b), MTH(lv.slice(k))]
    : [...subproof(m - k, lv.slice(k), false), MTH(lv.slice(0, k))];
}
function consistencyProof(m, lv) {
  if (m === 0 || m > lv.length || m === lv.length) return [];
  return subproof(m, lv, true);
}
const entryBytes = e => Buffer.from(['kt-v1', e.user_id, e.key_x, e.key_y, e.version].join('|'));
/* Array.from() erzwingt hier explizit ein ECHTES Array, unabhängig
   davon, was der jeweilige Datenbanktreiber für .all() zurückgibt.
   Grund: bei einem Wechsel von node:sqlite (liefert immer ein reines
   Array) zu @neondatabase/serverless trat ein Fehler auf
   ("lv.slice is not a function"), der nur erklärbar ist, wenn
   q.ktLeaves.all() dort ein Array-ähnliches, aber kein echtes Array
   zurückgab. .map() allein reicht nicht als Schutz, weil ein
   .map()-Aufruf auf einem Nicht-Array-Objekt selbst schon fehlschlagen
   würde (was hier NICHT der Fehler war) oder .map() vom jeweiligen
   Objekt anders implementiert sein könnte. Array.from() normalisiert
   zuverlässig auf ein natives Array, bevor die eigentliche MTH/
   inclusionPath-Rekursion beginnt, die zwingend .slice() braucht. */
const allLeaves = async () => Array.from(await q.ktLeaves.all()).map(r => ub64(r.leaf_hash));

/* Neuen Identitätsschlüssel ins Log aufnehmen und STH veröffentlichen */
async function ktAppend(userId, ikJwk) {
  const prev = await q.ktLatestFor.get(userId);
  const version = prev ? prev.version + 1 : 1;
  const idx = (await q.ktCount.get()).n;
  const entry = { user_id: userId, key_x: ikJwk.x, key_y: ikJwk.y, version };
  const lh = leafHash(entryBytes(entry));
  await q.ktAdd.run(idx, userId, ikJwk.x, ikJwk.y, version, b64(lh), Date.now());
  return publishSTH();
}
async function publishSTH() {
  const lv = await allLeaves();
  const size = lv.length;
  const root = MTH(lv);
  const ts = Date.now();
  const sig = signLog(['sth-v1', size, root.toString('hex'), ts].join('|'));
  const cosigs = collectCosigs({ size, root, ts }, lv);
  await q.ktPutSTH.run(size, b64(root), ts, sig, JSON.stringify(cosigs));
  return { size, root: b64(root), ts, sig, cosigs };
}
async function latestSTH() {
  const r = await q.ktLatestSTH.get();
  if (!r) return publishSTH();
  return { size: r.size, root: r.root, ts: r.ts, sig: r.signature, cosigs: JSON.parse(r.cosigs) };
}

/*───────────────────────────────────────────────────────────────────────────
  WITNESSES — unabhängige Mitzeichner
  Im Ein-Prozess-Betrieb laufen sie als getrennte Schlüssel mit eigenem
  Gedächtnis. In echt wären das fremde Hosts; das Protokoll ist dasselbe.
───────────────────────────────────────────────────────────────────────────*/
const WITNESS_FILE = path.join(__dirname, 'witnesses.json');
let witnesses;
if (fs.existsSync(WITNESS_FILE)) {
  witnesses = JSON.parse(fs.readFileSync(WITNESS_FILE, 'utf8'));
} else {
  witnesses = ['Auditor-EU', 'Auditor-US', 'Uni-Labor'].map(name => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    return {
      name,
      priv: privateKey.export({ type: 'pkcs8', format: 'pem' }),
      jwk: publicKey.export({ format: 'jwk' }),
      seen: {},         // size → roothex
      lastSize: 0, lastRoot: null,
      refusals: []
    };
  });
  fs.writeFileSync(WITNESS_FILE, JSON.stringify(witnesses, null, 2), { mode: 0o600 });
}
const saveWitnesses = () =>
  fs.writeFileSync(WITNESS_FILE, JSON.stringify(witnesses, null, 2), { mode: 0o600 });

function collectCosigs(sth, lv) {
  const out = [];
  const rootHex = sth.root.toString('hex');
  for (const w of witnesses) {
    const prior = w.seen[sth.size];
    if (prior && prior !== rootHex) {
      w.refusals.push({ size: sth.size, at: Date.now(), reason: 'zwei Wurzeln für dieselbe Größe' });
      continue;
    }
    if (w.lastSize > 0 && sth.size > w.lastSize) {
      const proof = consistencyProof(w.lastSize, lv);
      if (!verifyConsistency(w.lastSize, sth.size, proof, ub64(w.lastRoot), sth.root)) {
        w.refusals.push({ size: sth.size, at: Date.now(), reason: 'Konsistenz verletzt' });
        continue;
      }
    }
    if (sth.size < w.lastSize) {
      w.refusals.push({ size: sth.size, at: Date.now(), reason: 'Log geschrumpft' });
      continue;
    }
    w.seen[sth.size] = rootHex;
    w.lastSize = sth.size;
    w.lastRoot = b64(sth.root);
    out.push({
      witness: w.name,
      jwk: w.jwk,
      sig: b64(crypto.sign('sha256',
        Buffer.from(['witness-v1', w.name, sth.size, rootHex].join('|')),
        { key: w.priv, dsaEncoding: 'ieee-p1363' }))
    });
  }
  saveWitnesses();
  return out;
}
function verifyConsistency(m, n, proof, oldRoot, newRoot) {
  if (m === n) return proof.length === 0 && oldRoot.equals(newRoot);
  if (m === 0 || m > n) return false;
  let idx = 0, node, fn = m - 1, sn = n - 1;
  if ((m & (m - 1)) === 0) node = oldRoot;
  else { if (!proof.length) return false; node = proof[idx++]; }
  while (fn % 2 === 1) { fn >>= 1; sn >>= 1; }
  let r1 = node, r2 = node;
  while (idx < proof.length) {
    if (sn === 0) return false;
    const p = proof[idx++];
    if (fn % 2 === 1 || fn === sn) {
      r1 = nodeHash(p, r1); r2 = nodeHash(p, r2);
      while (fn % 2 === 0 && fn !== 0) { fn >>= 1; sn >>= 1; }
    } else r2 = nodeHash(r2, p);
    fn >>= 1; sn >>= 1;
  }
  return sn === 0 && r1.equals(oldRoot) && r2.equals(newRoot);
}

/*───────────────────────────────────────────────────────────────────────────
  WEBSOCKET — RFC 6455, minimal aber korrekt
───────────────────────────────────────────────────────────────────────────*/
/* RFC 6455 §1.3: exakt dieser String, kein Zeichen mehr oder weniger.
   Ein früherer Tippfehler hier (...95CA-5AB0DC85B11F statt
   ...95CA-C5AB0DC85B11) ließ den Server einen falschen
   Sec-WebSocket-Accept-Hash berechnen — Browser mit tolerantem
   WebSocket-Client bemerkten es nie, aber jeder RFC-strikte Client
   (z. B. Node's eingebautes WebSocket/undici) lehnte den Handshake mit
   "Incorrect hash received in Sec-WebSocket-Accept header" ab. */
const WS_MAGIC = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
/* Geräte-zentriert: eine WebSocket-Verbindung gehört zu genau einem
   Gerät, nicht direkt zum Nutzer. Bei Multi-Device kann ein Nutzer also
   mehrere Einträge gleichzeitig haben — einen pro angemeldetem Gerät. */
const live = new Map();     // deviceId → Set<socket>
const deviceOwner = new Map();  // deviceId → userId, für die Präsenz-Aggregation

function wsAccept(key) {
  return crypto.createHash('sha1').update(key + WS_MAGIC).digest('base64');
}
function wsFrame(payload) {
  const data = Buffer.from(payload);
  const len = data.length;
  let head;
  if (len < 126) { head = Buffer.alloc(2); head[1] = len; }
  else if (len < 65536) { head = Buffer.alloc(4); head[1] = 126; head.writeUInt16BE(len, 2); }
  else { head = Buffer.alloc(10); head[1] = 127; head.writeBigUInt64BE(BigInt(len), 2); }
  head[0] = 0x81;   // FIN + Textframe
  return Buffer.concat([head, data]);
}
function wsSend(sock, obj) {
  if (sock.destroyed || !sock.writable) return false;
  try { sock.write(wsFrame(JSON.stringify(obj))); return true; }
  catch { return false; }
}
/* Tote Sockets aussortieren: nur so stimmt die Zustellmeldung wirklich */
function liveSockets(deviceId) {
  const set = live.get(deviceId);
  if (!set) return [];
  for (const s of [...set]) if (s.destroyed || !s.writable) set.delete(s);
  if (!set.size) { live.delete(deviceId); deviceOwner.delete(deviceId); return []; }
  return [...set];
}
function deliverToDevice(deviceId, obj) {
  const socks = liveSockets(deviceId);
  let sent = 0;
  for (const s of socks) if (wsSend(s, obj)) sent++;
  if (!sent) liveSockets(deviceId);
  return sent > 0;
}
/* An ALLE aktiven Geräte eines Nutzers gleichzeitig senden — für
   Präsenz-Broadcasts und Dinge, die jedes Gerät wissen muss
   (Kontaktabgleich-Treffer, Blockierung, etc.), nicht für Nachrichten
   selbst (die gehen gezielt per deliverToDevice, siehe /api/send). */
function deliverToUser(userId, obj) {
  let sent = false;
  for (const [devId, owner] of deviceOwner) {
    if (owner === userId && deliverToDevice(devId, obj)) sent = true;
  }
  return sent;
}
const isOnline = userId => {
  for (const [devId, owner] of deviceOwner) if (owner === userId && liveSockets(devId).length) return true;
  return false;
};

/* Eingehende Frames zerlegen; unterstützt Fragmentierung und Ping/Close */
function makeWsParser(onMessage, onClose) {
  let buf = Buffer.alloc(0);
  return chunk => {
    buf = Buffer.concat([buf, chunk]);
    for (;;) {
      if (buf.length < 2) return;
      const fin = (buf[0] & 0x80) !== 0, opcode = buf[0] & 0x0f;
      const masked = (buf[1] & 0x80) !== 0;
      let len = buf[1] & 0x7f, off = 2;
      if (len === 126) { if (buf.length < 4) return; len = buf.readUInt16BE(2); off = 4; }
      else if (len === 127) { if (buf.length < 10) return; len = Number(buf.readBigUInt64BE(2)); off = 10; }
      const maskLen = masked ? 4 : 0;
      if (buf.length < off + maskLen + len) return;
      const mask = masked ? buf.subarray(off, off + 4) : null;
      const payload = Buffer.from(buf.subarray(off + maskLen, off + maskLen + len));
      if (mask) for (let i = 0; i < payload.length; i++) payload[i] ^= mask[i % 4];
      buf = buf.subarray(off + maskLen + len);
      if (opcode === 0x8) { onClose(); return; }
      if (opcode === 0x9) continue;              // Ping — Pong optional
      if (opcode === 0x1 || opcode === 0x0) {
        if (fin) { try { onMessage(JSON.parse(payload.toString('utf8'))); } catch {} }
      }
    }
  };
}

/*───────────────────────────────────────────────────────────────────────────
  MIXNET — Betrieb der Mix-Knoten
  Im Einzelprozess laufen die Knoten nebeneinander. Das Protokoll stimmt,
  die Unabhängigkeit nicht: Wer diesen Prozess kontrolliert, sieht alle
  Schichten. In echt gehören die Knoten zu verschiedenen Betreibern und
  sprechen über HTTP miteinander — die Klasse bliebe dieselbe.
───────────────────────────────────────────────────────────────────────────*/
const MIX = require('./mixnet');
const MIX_NODE_COUNT = 5;

const mixNodes = Array.from({ length: MIX_NODE_COUNT },
  (_, i) => new MIX.MixNode('mix-' + (i + 1)));

/* Am Ende des Pfades landet das Paket hier: der Zustelldienst legt es
   als versiegelten Umschlag ab — ohne zu wissen, wer ihn geschickt hat.
   Die innere Nutzlast muss recipientDeviceId enthalten, genau wie beim
   direkten Sealed-Sender-Pfad — der Client kennt die Geräteliste des
   Empfängers aus einem vorherigen /api/bundle-Aufruf. */
const mixNet = new MIX.MixNetwork(mixNodes, async (recipientId, payload) => {
  let inner;
  try { inner = JSON.parse(payload.toString('utf8')) }
  catch { return; }
  if (!inner.recipientDeviceId) return;
  const dev = await q.deviceById.get(inner.recipientDeviceId);
  if (!dev || dev.user_id !== recipientId) return;

  const id = 'e' + crypto.randomBytes(10).toString('hex');
  const now = Date.now();
  await q.putEnvelope.run(id, null, null, 1, recipientId, inner.recipientDeviceId,
    inner.convId || '', null, 'sealed', null, inner.sealed,
    inner.gossip ? JSON.stringify(inner.gossip) : null, now);
  deliverToDevice(inner.recipientDeviceId, {
    type: 'envelope', id, sealed: true, senderId: null, senderDeviceId: null, viaMix: true,
    recipientId, recipientDeviceId: inner.recipientDeviceId, convId: inner.convId, kind: 'sealed',
    ciphertext: inner.sealed, gossip: inner.gossip || null, sentAt: now
  }) || notifyOffline(inner.recipientDeviceId);
});

setInterval(() => { for (const n of mixNodes) n.sweep() }, 60000).unref();

/*───────────────────────────────────────────────────────────────────────────*/
const json = (res, code, obj) => {
  const body = JSON.stringify(obj);
  res.writeHead(code, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS'
  });
  res.end(body);
};
const readBody = req => new Promise((resolve, reject) => {
  let d = ''; let size = 0;
  req.on('data', c => {
    size += c.length;
    if (size > 8 * 1024 * 1024) { reject(new Error('Body zu groß')); req.destroy(); return; }
    d += c;
  });
  req.on('end', () => { try { resolve(d ? JSON.parse(d) : {}); } catch (e) { reject(e); } });
  req.on('error', reject);
});
/* Liefert {user, device} — jede Session gehört jetzt zu genau einem
   Gerät, nicht mehr direkt zum Nutzer. Routen, die eine Geräte-Identität
   brauchen (Prekeys, Senden), lesen device; Routen, die nur den Account
   betreffen (Profil, Kontaktliste), brauchen nur user. */
async function auth(req) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token) return null;
  const s = await q.session.get(token, Date.now());
  if (!s) return null;
  const user = await q.userById.get(s.user_id);
  const device = await q.deviceById.get(s.device_id);
  if (!user || !device) return null;   // Gerät zwischenzeitlich entfernt
  return { user, device };
}
const pub = u => u && ({
  id: u.id, name: u.name, avatarPath: u.avatar_path, bio: u.bio, phone: u.phone,
  email: u.email, emailVerified: !!u.email_verified,
  lastSeen: u.last_seen, online: isOnline(u.id)
});
const pubDevice = d => d && ({
  id: d.id, name: d.name, platform: d.platform, isPrimary: !!d.is_primary,
  ikDH: JSON.parse(d.ik_dh), ikSign: JSON.parse(d.ik_sign),
  createdAt: d.created_at, lastSeen: d.last_seen
});

/* Einfache Ratenbegrenzung pro IP */
const rate = new Map();
function rateLimit(ip, max = 120, windowMs = 60000) {
  const now = Date.now();
  const e = rate.get(ip) || { n: 0, reset: now + windowMs };
  if (now > e.reset) { e.n = 0; e.reset = now + windowMs; }
  e.n++; rate.set(ip, e);
  return e.n <= max;
}

/*───────────────────────────────────────────────────────────────────────────
  KONTAKTABGLEICH — Pfeffer
  ─────────────────────────────────────────────────────────────────────────
  Muss auf Server UND Client identisch sein, sonst passen die Hashes nie
  zusammen. Der Client hasht SEINE Kontakte damit; der Server hasht bei
  der Registrierung die EIGENE Nummer/E-Mail des neuen Kontos damit —
  nur wenn beide denselben Pfeffer verwenden, kann ein Treffer entstehen.
  In Produktion aus der Umgebung laden, hier ein fester Wert fürs Beispiel.
───────────────────────────────────────────────────────────────────────────*/
const CONTACT_PEPPER = process.env.CONTACT_PEPPER || 'app-weiter-pfeffer-v1';
function contactHash(value) {
  if (!value) return null;
  const norm = String(value).replace(/[^\d+a-zA-Z@.]/g, '').toLowerCase();
  if (!norm) return null;
  return crypto.createHash('sha256').update(norm + '|' + CONTACT_PEPPER).digest('base64');
}

const routes = {
  /* ---- Konten ---- */
  /* Registrierung legt gleichzeitig das erste (primäre) Gerät an — ein
     Konto ohne mindestens ein Gerät kann nichts entschlüsseln. */
  'POST /api/register': async (req, res) => {
    const b = await readBody(req);
    for (const f of ['name', 'email', 'ikDH', 'ikSign', 'spk', 'opks', 'deviceName', 'platform'])
      if (!b[f]) return json(res, 400, { error: `Feld fehlt: ${f}` });
    if (await q.userByName.get(b.name)) return json(res, 409, { error: 'Name bereits vergeben' });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(b.email)) return json(res, 400, { error: 'Ungültige E-Mail-Adresse' });
    if (await q.userByEmail.get(b.email)) return json(res, 409, { error: 'E-Mail bereits vergeben' });

    const id = 'u' + crypto.randomBytes(8).toString('hex');
    const now = Date.now();
    await q.insertUser.run(id, b.name, b.phone || '', b.email || null, null, b.bio || '',
      null, null, now, now);

    const deviceId = 'd' + crypto.randomBytes(8).toString('hex');
    await q.insertDevice.run(deviceId, id, b.deviceName, b.platform,
      JSON.stringify(b.ikDH), JSON.stringify(b.ikSign), 1, now, now);
    await q.putSPK.run(deviceId, b.spk.spkId, JSON.stringify(b.spk.pub), b.spk.signature, b.spk.createdAt);
    for (const o of b.opks) await q.addOPK.run(deviceId, o.opkId, JSON.stringify(o.pub));

    /* Das Transparenz-Log führt weiterhin über den NUTZER, nicht das
       Gerät — Kontakte verifizieren eine Person, kein einzelnes Handy.
       Bei Multi-Device zeigt der Log-Eintrag den Schlüssel des
       Hauptgeräts; jedes weitere Gerät wird separat über das Pairing
       autorisiert und bekommt keinen eigenen Log-Eintrag. */
    const sth = await ktAppend(id, b.ikDH);

    /* Eigene Telefonnummer/E-Mail selbst hashen und unter der eigenen
       user_id hinterlegen — nur dadurch können ANDERE Nutzer diesen
       Account später über ihre Kontaktliste finden (siehe
       /api/contacts/sync). Ohne diesen Schritt gäbe es nie einen
       Treffer, weil kein Hash zum Vergleichen existierte. */
    const ownPhoneHash = contactHash(b.phone);
    const ownEmailHash = contactHash(b.email);
    if (ownPhoneHash) await q.putSelfHash.run(id, ownPhoneHash);
    if (ownEmailHash) await q.putSelfHash.run(id, ownEmailHash);

    const token = crypto.randomBytes(32).toString('hex');
    await q.insertSession.run(token, id, deviceId, now, now + SESSION_LIFETIME_MS);

    /* E-Mail ist jetzt Pflichtfeld (siehe Feld-Prüfung oben) — der
       Verifizierungscode wird deshalb IMMER verschickt, nicht mehr nur
       versuchsweise. Schlägt der Versand fehl, wird die gesamte
       Registrierung zurückgerollt (Konto + Gerät + Sitzung gelöscht),
       statt ein Konto zu erzeugen, das seinen Code nie bekommen hat
       und sich damit nie verifizieren lassen könnte. Der Code selbst
       wird nie im Klartext gespeichert, nur sein SHA-256-Hash
       (dieselbe Technik wie bei Passwörtern, sha256() ist bereits
       weiter oben definiert). */
    if (!MAIL.isConfigured()) {
      await q.deleteUser.run(id);
      return json(res, 503, { error: 'Registrierung derzeit nicht möglich — Mailversand nicht konfiguriert' });
    }
    const code = String(crypto.randomInt(100000, 1000000));
    const codeHash = b64(sha256(Buffer.from(code)));
    await q.putEmailCode.run(id, codeHash, now, now + 15 * 60000);
    try {
      await MAIL.sendVerificationCode(b.email, code);
    } catch (err) {
      await q.deleteUser.run(id);
      return json(res, 500, { error: 'Bestätigungsmail konnte nicht verschickt werden — bitte E-Mail-Adresse prüfen' });
    }

    const newUser = await q.userById.get(id);
    const newDevice = await q.deviceById.get(deviceId);
    json(res, 201, { token, user: pub(newUser), device: pubDevice(newDevice), sth });
  },

  /* Code aus der Verifizierungsmail bestätigen. Höchstens 5 Versuche,
     dann muss ein neuer Code angefordert werden — verhindert Erraten
     der 6-stelligen Zahl per Brute-Force. */
  'POST /api/verify-email': async (req, res) => {
    const a = await auth(req); if (!a) return json(res, 401, { error: 'Nicht angemeldet' });
    const b = await readBody(req);
    if (!b.code) return json(res, 400, { error: 'Code fehlt' });

    const row = await q.getEmailCode.get(a.user.id);
    if (!row) return json(res, 404, { error: 'Kein Code angefordert oder bereits verifiziert' });
    if (row.expires_at < Date.now()) {
      await q.dropEmailCode.run(a.user.id);
      return json(res, 410, { error: 'Code abgelaufen — neuen anfordern' });
    }
    if (row.attempts >= 5) {
      await q.dropEmailCode.run(a.user.id);
      return json(res, 429, { error: 'Zu viele Fehlversuche — neuen Code anfordern' });
    }

    const givenHash = b64(sha256(Buffer.from(String(b.code))));
    if (givenHash !== row.code_hash) {
      await q.bumpEmailAttempts.run(a.user.id);
      return json(res, 400, { error: 'Code falsch' });
    }

    await q.markEmailVerified.run(a.user.id);
    await q.dropEmailCode.run(a.user.id);
    json(res, 200, { verified: true });
  },

  /* Neuen Code anfordern — z. B. wenn der erste nie ankam oder abgelaufen ist. */
  'POST /api/resend-verification': async (req, res) => {
    const a = await auth(req); if (!a) return json(res, 401, { error: 'Nicht angemeldet' });
    if (!a.user.email) return json(res, 400, { error: 'Kein E-Mail-Kontakt hinterlegt' });
    if (!MAIL.isConfigured()) return json(res, 503, { error: 'Mailversand nicht konfiguriert' });

    const code = String(crypto.randomInt(100000, 1000000));
    const codeHash = b64(sha256(Buffer.from(code)));
    await q.putEmailCode.run(a.user.id, codeHash, Date.now(), Date.now() + 15 * 60000);
    try {
      await MAIL.sendVerificationCode(a.user.email, code);
    } catch (err) {
      console.warn('Mailversand fehlgeschlagen:', err.message);
      return json(res, 500, { error: 'Mailversand fehlgeschlagen' });
    }
    json(res, 200, { sent: true });
  },

  /* ---- Kontowiederherstellung ---- */
  /* Läuft OHNE bestehende Anmeldung — genau dafür ist sie da: das lokale
     Sitzungstoken ist verloren (Browser-Daten gelöscht, neues Gerät),
     die verifizierte E-Mail ist der letzte verbleibende Nachweis.

     WICHTIG: liefert bewusst IMMER dieselbe generische Erfolgsmeldung,
     unabhängig davon, ob die E-Mail-Adresse tatsächlich zu einem Konto
     gehört. Ohne dieses Verhalten ließe sich dieser Endpunkt missbrauchen,
     um herauszufinden, welche E-Mail-Adressen bei diesem Dienst
     registriert sind — bei einem privatsphäre-orientierten Messenger ist
     das selbst eine sensible Information, unabhängig vom Kontoinhalt. */
  'POST /api/account/recover-request': async (req, res) => {
    const b = await readBody(req);
    if (!b.email) return json(res, 400, { error: 'E-Mail-Adresse erforderlich' });

    const u = await q.userByEmail.get(b.email);
    /* TEMPORÄR zur Fehlersuche: zeigt im Server-Log, welcher der drei
       stillen Fehlerfälle tatsächlich zutrifft — von außen bewusst
       nicht unterscheidbar (siehe Kommentar unten), aber im eigenen
       Log sichtbar zu machen verrät nichts an einen Angreifer. */
    console.log('DEBUG recover-request:', JSON.stringify({
      email: b.email,
      userFound: !!u,
      emailVerified: u ? !!u.email_verified : null,
      mailConfigured: MAIL.isConfigured()
    }));
    if (u && u.email_verified && MAIL.isConfigured()) {
      const code = String(crypto.randomInt(100000, 1000000));
      const codeHash = b64(sha256(Buffer.from(code)));
      await q.putRecoveryCode.run(u.id, codeHash, Date.now(), Date.now() + 15 * 60000);
      MAIL.sendVerificationCode(b.email, code).catch(err =>
        console.warn('Wiederherstellungsmail fehlgeschlagen:', err.message));
    }
    /* Absichtlich identische Antwort in JEDEM Fall — siehe Kommentar oben. */
    json(res, 200, { sent: true });
  },

  /* Code einreichen, neues Sitzungstoken bekommen. Das neue Token gilt
     für ein NEUES Gerät (siehe deviceName/platform/identity im Body) —
     die alten Identitätsschlüssel des verlorenen Geräts lassen sich
     serverseitig nicht wiederherstellen (sie haben das ursprüngliche
     Gerät nie verlassen, das ist der ganze Sinn von Ende-zu-Ende-
     Verschlüsselung). Wiederherstellung stellt also den KONTOZUGRIFF
     wieder her, nicht die alte lokale Sitzung — der Nutzer bekommt ein
     frisches Gerät im selben Konto, mit demselben Namen und derselben
     Kontakthistorie serverseitig, aber einem neuen Schlüsselpaar. */
  'POST /api/account/recover-verify': async (req, res) => {
    const b = await readBody(req);
    if (!b.email || !b.code || !b.deviceName || !b.platform || !b.ikDH || !b.ikSign || !b.spk || !b.opks)
      return json(res, 400, { error: 'Felder fehlen' });

    const u = await q.userByEmail.get(b.email);
    if (!u) return json(res, 400, { error: 'Code ungültig oder abgelaufen' });

    const row = await q.getRecoveryCode.get(u.id);
    if (!row) return json(res, 400, { error: 'Code ungültig oder abgelaufen' });
    if (row.expires_at < Date.now()) {
      await q.dropRecoveryCode.run(u.id);
      return json(res, 400, { error: 'Code ungültig oder abgelaufen' });
    }
    if (row.attempts >= 5) {
      await q.dropRecoveryCode.run(u.id);
      return json(res, 429, { error: 'Zu viele Fehlversuche — neuen Code anfordern' });
    }

    const givenHash = b64(sha256(Buffer.from(String(b.code))));
    if (givenHash !== row.code_hash) {
      await q.bumpRecoveryAttempts.run(u.id);
      return json(res, 400, { error: 'Code ungültig oder abgelaufen' });
    }
    await q.dropRecoveryCode.run(u.id);

    const now = Date.now();
    const deviceId = 'd' + crypto.randomBytes(8).toString('hex');
    await q.insertDevice.run(deviceId, u.id, b.deviceName, b.platform,
      JSON.stringify(b.ikDH), JSON.stringify(b.ikSign), 1, now, now);
    await q.putSPK.run(deviceId, b.spk.spkId, JSON.stringify(b.spk.pub), b.spk.signature, b.spk.createdAt);
    for (const o of b.opks) await q.addOPK.run(deviceId, o.opkId, JSON.stringify(o.pub));

    const token = crypto.randomBytes(32).toString('hex');
    await q.insertSession.run(token, u.id, deviceId, now, now + SESSION_LIFETIME_MS);
    await q.touchUser.run(now, u.id);

    const newDevice = await q.deviceById.get(deviceId);
    json(res, 200, { token, user: pub(u), device: pubDevice(newDevice), sth: await latestSTH() });
  },

  /* DEAKTIVIERT seit der Umstellung auf passwortlose Anmeldung. Ohne
     Passwort wäre eine Prüfung, die nur auf "name" beruht, ein echtes
     Sicherheitsloch: Nutzernamen sind öffentlich sichtbar (siehe
     /api/users), jeder könnte sich sonst als jeder andere ausgeben.
     Die App ruft diese Route nicht mehr auf — ein bekanntes Gerät meldet
     sich über /api/me mit dem lokal gespeicherten Sitzungstoken an, ein
     neues Gerät ausschließlich über Pairing (das einen Code von einem
     bereits angemeldeten Gerät braucht, kein bloßes Erraten eines
     Namens). Route bleibt als klar abgelehnter Pfad bestehen, statt sie
     ersatzlos zu entfernen — falls irgendein alter Client sie noch
     aufruft, bekommt er eine eindeutige Fehlermeldung statt eines
     stillen Absturzes. */
  'POST /api/login': async (req, res) => {
    return json(res, 410, {
      error: 'Passwort-Login ist entfernt worden. Bitte über Pairing anmelden oder das Konto neu registrieren.'
    });
  },

  'POST /api/logout': async (req, res) => {
    const h = req.headers.authorization || '';
    if (h.startsWith('Bearer ')) await q.dropSession.run(h.slice(7));
    json(res, 200, { ok: true });
  },

  /* Konto endgültig löschen. Passwort-Bestätigung ist Pflicht — ein
     gestohlener/geleakter Sitzungstoken allein darf nicht reichen, um
     ein Konto zu vernichten, das ist eine deutlich schwerwiegendere
     Aktion als z. B. nur ausloggen. ON DELETE CASCADE auf jeder
     user_id-Fremdschlüsseltabelle räumt Geräte, Sitzungen, Nachrichten,
     Kontakt-Hashes, Blocks und Meldungen automatisch mit ab — kein
     Nachfassen an anderer Stelle nötig. */
  /* Konto endgültig löschen. Ein gültiges Bearer-Token ist der alleinige
     Identitätsnachweis (es gibt kein Passwort mehr im System). Die
     bewusste Bestätigung passiert client-seitig (Namen exakt eintippen,
     siehe confirmDeleteAccount in app.js) — auf Serverseite reicht ein
     angemeldetes Gerät, um sein eigenes Konto zu löschen. ON DELETE
     CASCADE auf jeder user_id-Fremdschlüsseltabelle räumt Geräte,
     Sitzungen, Nachrichten, Kontakt-Hashes, Blocks und Meldungen
     automatisch mit ab — kein Nachfassen an anderer Stelle nötig. */
  'POST /api/account/delete': async (req, res) => {
    const a = await auth(req); if (!a) return json(res, 401, { error: 'Nicht angemeldet' });
    await q.deleteUser.run(a.user.id);
    json(res, 200, { ok: true });
  },

  'GET /api/me': async (req, res) => {
    const a = await auth(req); if (!a) return json(res, 401, { error: 'Nicht angemeldet' });
    const devices = await q.devicesOf.all(a.user.id);
    const opkCount = await q.countOPK.get(a.device.id);
    json(res, 200, {
      user: pub(a.user), device: pubDevice(a.device),
      devices: devices.map(pubDevice),
      opksLeft: opkCount.n
    });
  },

  'POST /api/profile': async (req, res) => {
    const a = await auth(req); if (!a) return json(res, 401, { error: 'Nicht angemeldet' });
    const b = await readBody(req);
    await q.updateProfile.run(b.name || a.user.name, b.bio ?? a.user.bio, b.phone ?? a.user.phone, a.user.id);
    json(res, 200, { user: pub(await q.userById.get(a.user.id)) });
  },

  /* Presigned-Upload-URL ausstellen: Client verschlüsselt die Datei
     LOKAL im Browser (siehe media-storage.js), lädt sie dann DIREKT zu
     R2 hoch — ohne Umweg über diesen Server. Der Server sieht nie den
     Dateiinhalt, nur den (bereits eindeutigen, zufälligen) Objekt-
     schlüssel, den er selbst vergeben hat. Ohne konfiguriertes R2
     (R2_ACCOUNT_ID/R2_ACCESS_KEY_ID/R2_SECRET_ACCESS_KEY/R2_BUCKET)
     liefert diese Route einen klaren 503 statt eines kryptischen
     Absturzes — Medien-Uploads sind optional, der Rest der App bleibt
     ohne sie voll nutzbar. */
  'POST /api/media/upload-url': async (req, res) => {
    const a = await auth(req); if (!a) return json(res, 401, { error: 'Nicht angemeldet' });
    if (!R2.isConfigured()) return json(res, 503, { error: 'Medien-Speicher nicht konfiguriert' });
    const key = R2.randomObjectKey();
    const uploadUrl = R2.presign({ method: 'PUT', key, expiresInSeconds: 600 });
    json(res, 200, { path: key, uploadUrl, expiresIn: 600 });
  },

  /* Presigned-Download-URL für einen bereits hochgeladenen Pfad —
     nötig, weil R2-Objekte nicht standardmäßig öffentlich lesbar sind.
     Kein Eigentumsnachweis über die Datenbank nötig: wer den (zufälligen,
     36-stelligen UUID-artigen) Pfad kennt, hat ihn entweder selbst
     hochgeladen oder über eine legitime Quelle bekommen (z. B. als
     avatarPath eines Kontakts über /api/users). */
  'GET /api/media/download-url': async (req, res, url) => {
    const a = await auth(req); if (!a) return json(res, 401, { error: 'Nicht angemeldet' });
    if (!R2.isConfigured()) return json(res, 503, { error: 'Medien-Speicher nicht konfiguriert' });
    const path = url.searchParams.get('path');
    if (!path || !/^[0-9a-f-]{36}\.bin$/.test(path))
      return json(res, 400, { error: 'Ungültiger Medienpfad' });
    const downloadUrl = R2.presign({ method: 'GET', key: path, expiresInSeconds: 600 });
    json(res, 200, { downloadUrl, expiresIn: 600 });
  },

  /* Profilbild: Client lädt bereits verschlüsselt zu R2 hoch (siehe
     media-storage.js) und meldet hier nur den Pfad — der Server sieht
     nie das Bild selbst. */
  'POST /api/profile/avatar': async (req, res) => {
    const a = await auth(req); if (!a) return json(res, 401, { error: 'Nicht angemeldet' });
    const b = await readBody(req);
    if (!b.path || !/^[0-9a-f-]{36}\.bin$/.test(b.path))
      return json(res, 400, { error: 'Ungültiger Medienpfad' });
    await q.updateAvatar.run(b.path, a.user.id);
    json(res, 200, { user: pub(await q.userById.get(a.user.id)) });
  },

  'GET /api/users': async (req, res) => {
    const a = await auth(req); if (!a) return json(res, 401, { error: 'Nicht angemeldet' });
    const blockedRows = await q.blockedByMe.all(a.user.id);
    const blocked = new Set(blockedRows.map(r => r.blocked_id));
    const allUsersRows = await q.allUsers.all();
    const candidates = allUsersRows.filter(x => x.id !== a.user.id && !blocked.has(x.id));
    const users = await Promise.all(candidates.map(async x => pub(await q.userById.get(x.id))));
    json(res, 200, { users });
  },

  /* ---- Geräte-Verwaltung (Multi-Device) ---- */

  /* Hauptgerät erzeugt einen kurzlebigen Code, das neue Gerät scannt ihn
     als QR. Ohne dieses Einverständnis kann sich kein zweites Gerät
     eintragen — reines Passwortwissen reicht nicht. */
  'POST /api/devices/pair-request': async (req, res) => {
    const a = await auth(req); if (!a) return json(res, 401, { error: 'Nicht angemeldet' });
    const code = crypto.randomBytes(16).toString('hex');
    const now = Date.now();
    await q.createPairing.run(code, a.user.id, now, now + 5 * 60000);   // 5 Minuten gültig
    json(res, 200, { code, expiresAt: now + 5 * 60000 });
  },

  /* Neues Gerät liefert Name, Plattform und sein eigenes frisch erzeugtes
     Identitätsschlüsselpaar samt Prekeys — bekommt im Erfolgsfall direkt
     ein Sitzungstoken, muss sich also nicht separat einloggen. */
  'POST /api/devices/pair-claim': async (req, res) => {
    const b = await readBody(req);
    for (const f of ['code', 'deviceName', 'platform', 'ikDH', 'ikSign', 'spk', 'opks'])
      if (!b[f]) return json(res, 400, { error: `Feld fehlt: ${f}` });

    const pairing = await q.getPairing.get(b.code, Date.now());
    if (!pairing) return json(res, 410, { error: 'Code ungültig oder abgelaufen' });
    await q.consumePairing.run(b.code);   // einmal verwendbar, auch bei Folgefehlern

    const user = await q.userById.get(pairing.user_id);
    const deviceId = 'd' + crypto.randomBytes(8).toString('hex');
    const now = Date.now();
    await q.insertDevice.run(deviceId, user.id, b.deviceName, b.platform,
      JSON.stringify(b.ikDH), JSON.stringify(b.ikSign), 0, now, now);
    await q.putSPK.run(deviceId, b.spk.spkId, JSON.stringify(b.spk.pub), b.spk.signature, b.spk.createdAt);
    for (const o of b.opks) await q.addOPK.run(deviceId, o.opkId, JSON.stringify(o.pub));

    const token = crypto.randomBytes(32).toString('hex');
    await q.insertSession.run(token, user.id, deviceId, now, now + SESSION_LIFETIME_MS);

    /* Alle bereits angemeldeten Geräte des Nutzers informieren — vor
       allem das Hauptgerät zeigt "neues Gerät verbunden" an. */
    const newDevicePub = pubDevice(await q.deviceById.get(deviceId));
    const existingDevices = await q.devicesOf.all(user.id);
    for (const d of existingDevices) {
      if (d.id !== deviceId) deliverToDevice(d.id, { type: 'device-added', device: newDevicePub });
    }
    json(res, 201, { token, user: pub(user), device: newDevicePub });
  },

  'GET /api/devices': async (req, res) => {
    const a = await auth(req); if (!a) return json(res, 401, { error: 'Nicht angemeldet' });
    const devices = await q.devicesOf.all(a.user.id);
    json(res, 200, { devices: devices.map(pubDevice), currentDeviceId: a.device.id });
  },

  /* Gerät entfernen — jedes Gerät kann sich selbst entfernen, das
     Hauptgerät kann auch andere entfernen (verlorenes Handy usw.). */
  'POST /api/devices/revoke': async (req, res) => {
    const a = await auth(req); if (!a) return json(res, 401, { error: 'Nicht angemeldet' });
    const b = await readBody(req);
    const target = b.deviceId || a.device.id;
    if (target !== a.device.id && !a.device.is_primary)
      return json(res, 403, { error: 'Nur das Hauptgerät kann andere Geräte entfernen' });
    const primaryCount = await q.hasPrimary.get(a.user.id);
    if (primaryCount.n <= 1 && target === a.device.id && a.device.is_primary)
      return json(res, 400, { error: 'Letztes Hauptgerät kann nicht entfernt werden — Konto würde unzugänglich' });

    await q.revokeDevice.run(Date.now(), target, a.user.id);
    await q.dropDeviceSessions.run(target);
    await q.dropPush.run(target);
    deliverToDevice(target, { type: 'device-revoked' });
    json(res, 200, { ok: true });

  },

  /* ---- Push-Registrierung ----
     Web Push (VAPID) meldet endpoint+p256dh+auth, FCM meldet nur ein
     Token als endpoint. Beides landet in derselben Tabelle, siehe
     push_subscriptions im Schema. */
  'GET /api/push/vapid-key': async (req, res) => {
    /* Öffentlich, kein Login nötig — der Browser braucht diesen Wert
       schon VOR der Anmeldung, um pushManager.subscribe() aufzurufen. */
    json(res, 200, { publicKey: vapidKeys.publicKey });
  },
  'POST /api/push/subscribe': async (req, res) => {
    const a = await auth(req); if (!a) return json(res, 401, { error: 'Nicht angemeldet' });
    const b = await readBody(req);
    if (!b.platform || !b.endpoint) return json(res, 400, { error: 'platform oder endpoint fehlt' });
    if (!['web', 'fcm'].includes(b.platform)) return json(res, 400, { error: 'Unbekannte Plattform' });
    await q.putPush.run(a.device.id, b.platform, b.endpoint, b.p256dh || null, b.auth || null, Date.now());
    json(res, 200, { ok: true });
  },
  'POST /api/push/unsubscribe': async (req, res) => {
    const a = await auth(req); if (!a) return json(res, 401, { error: 'Nicht angemeldet' });
    await q.dropPush.run(a.device.id);
    json(res, 200, { ok: true });
  },

  /* ---- Prekeys (pro Gerät) ---- */
  /* deviceId optional im Query-String: wenn angegeben, wird genau das
     Bundle DIESES Geräts geliefert (für gezielte Zustellung im Fanout).
     Ohne Angabe: alle aktiven Geräte des Nutzers — der Client baut dann
     für jedes einzeln eine Ratchet-Sitzung auf. */
  'GET /api/bundle': async (req, res, url) => {
    const a = await auth(req); if (!a) return json(res, 401, { error: 'Nicht angemeldet' });
    const targetUser = url.searchParams.get('user');
    const onlyDevice = url.searchParams.get('device');
    const t = await q.userById.get(targetUser);
    if (!t) return json(res, 404, { error: 'Unbekannter Nutzer' });
    if (await q.isBlocked.get(targetUser, a.user.id)) return json(res, 403, { error: 'Zustellung nicht möglich' });

    const devices = onlyDevice
      ? [await q.deviceById.get(onlyDevice)].filter(Boolean)
      : await q.devicesOf.all(targetUser);
    if (!devices.length) return json(res, 404, { error: 'Kein aktives Gerät für diesen Nutzer' });

    const entry = await q.ktLatestFor.get(targetUser);
    const lv = await allLeaves();
    const sth = await latestSTH();
    const ktProof = entry ? {
      entry: { userId: entry.user_id, keyX: entry.key_x, keyY: entry.key_y, version: entry.version },
      index: entry.idx, path: inclusionPath(entry.idx, lv).map(b64), sth
    } : null;

    const bundles = [];
    for (const dev of devices) {
      const spk = await q.getSPK.get(dev.id);
      if (!spk) continue;
      /* WICHTIG, sicherheitsrelevant: takeOPK (auslesen) und markOPK
         (als verbraucht markieren) müssen in dieser Reihenfolge und
         beide vollständig abgeschlossen sein, bevor der nächste Schritt
         läuft — sonst könnte derselbe One-Time-Prekey bei zwei schnell
         aufeinanderfolgenden Anfragen zweimal ausgeliefert werden. Das
         await hier stellt sicher, dass markOPK wirklich abgeschlossen
         ist, bevor die Schleife zum nächsten Gerät weitergeht. */
      const opk = await q.takeOPK.get(dev.id);
      if (opk) await q.markOPK.run(Date.now(), opk.id);
      const opksLeft = await q.countOPK.get(dev.id);
      bundles.push({
        deviceId: dev.id, deviceName: dev.name, isPrimary: !!dev.is_primary,
        ikDH: JSON.parse(dev.ik_dh), ikSign: JSON.parse(dev.ik_sign),
        spk: JSON.parse(spk.pub), spkId: spk.spk_id,
        spkCreatedAt: spk.created_at, spkSig: spk.signature,
        opk: opk ? JSON.parse(opk.pub) : null, opkId: opk ? opk.opk_id : null,
        opksLeft: opksLeft.n
      });
    }
    json(res, 200, { bundles, kt: ktProof });
  },

  'POST /api/prekeys': async (req, res) => {
    const a = await auth(req); if (!a) return json(res, 401, { error: 'Nicht angemeldet' });
    const b = await readBody(req);
    if (b.spk) await q.putSPK.run(a.device.id, b.spk.spkId, JSON.stringify(b.spk.pub),
      b.spk.signature, b.spk.createdAt);
    let added = 0;
    for (const o of (b.opks || [])) { await q.addOPK.run(a.device.id, o.opkId, JSON.stringify(o.pub)); added++; }
    const available = await q.countOPK.get(a.device.id);
    json(res, 200, { ok: true, added, available: available.n });
  },


  /* Rotation betrifft nur das Hauptgerät und damit den Log-Eintrag der
     Person — ein Zweitgerät hat ohnehin keinen eigenen Log-Eintrag. */
  'POST /api/rotate-identity': async (req, res) => {
    const a = await auth(req); if (!a) return json(res, 401, { error: 'Nicht angemeldet' });
    if (!a.device.is_primary)
      return json(res, 403, { error: 'Nur das Hauptgerät kann die Identität im Transparenz-Log rotieren' });
    const b = await readBody(req);
    if (!b.ikDH) return json(res, 400, { error: 'ikDH fehlt' });
    await db.prepare('UPDATE devices SET ik_dh=? WHERE id=?').run(JSON.stringify(b.ikDH), a.device.id);
    json(res, 200, { sth: await ktAppend(a.user.id, b.ikDH) });
  },

  /* ---- Nachrichten ---- */
  /* Der Client liefert PRO EMPFÄNGERGERÄT ein eigenes Chiffrat — er kennt
     die Geräteliste aus /api/bundle und hat für jedes einen eigenen
     Ratchet-Zustand. Ein logischer "Send"-Aufruf des Nutzers wird also
     zu N Umschlägen, einem pro aktivem Gerät des Empfängers (Fanout). */
  'POST /api/send': async (req, res) => {
    const a = await auth(req); if (!a) return json(res, 401, { error: 'Nicht angemeldet' });
    const b = await readBody(req);
    if (!b.recipientId || !Array.isArray(b.perDevice) || !b.perDevice.length)
      return json(res, 400, { error: 'Empfänger oder perDevice-Liste fehlt' });
    if (await q.isBlocked.get(b.recipientId, a.user.id))
      return json(res, 403, { error: 'Du wurdest von diesem Nutzer blockiert' });

    const now = Date.now();
    const results = [];
    for (const d of b.perDevice) {
      if (!d.deviceId || !d.ciphertext) continue;
      const id = 'e' + crypto.randomBytes(10).toString('hex');
      await q.putEnvelope.run(id, a.user.id, a.device.id, 0, b.recipientId, d.deviceId,
        b.convId || '', b.groupId || null, b.kind || 'text',
        d.header ? JSON.stringify(d.header) : null, d.ciphertext,
        b.gossip ? JSON.stringify(b.gossip) : null, now);

      const env = {
        type: 'envelope', id, senderId: a.user.id, senderDeviceId: a.device.id,
        recipientId: b.recipientId, recipientDeviceId: d.deviceId,
        convId: b.convId, groupId: b.groupId || null, kind: b.kind || 'text',
        header: d.header || null, ciphertext: d.ciphertext, gossip: b.gossip || null, sentAt: now
      };
      const online = deliverToDevice(d.deviceId, env);
      /* Gerät nicht per WebSocket erreichbar: Push-Weckruf auslösen,
         damit die App auch geschlossen etwas mitbekommt. Läuft
         bewusst ohne await — der Sendeaufruf soll nicht auf die
         Push-Zustellung warten, das wäre unnötige Latenz für den
         Absender und würde bei einem langsamen Push-Dienst spürbar. */
      if (!online) notifyOffline(d.deviceId);
      results.push({ deviceId: d.deviceId, id, delivered: online });
    }
    json(res, 200, { sentAt: now, results });
  },

  'GET /api/inbox': async (req, res) => {
    const a = await auth(req); if (!a) return json(res, 401, { error: 'Nicht angemeldet' });
    const pendingRows = await q.pending.all(a.device.id);
    const rows = pendingRows.map(r => ({
      id: r.id, senderId: r.sender_id, senderDeviceId: r.sender_device_id,
      sealed: !!r.sealed, convId: r.conv_id, groupId: r.group_id,
      kind: r.kind, header: r.header ? JSON.parse(r.header) : null,
      ciphertext: r.ciphertext, gossip: r.gossip ? JSON.parse(r.gossip) : null, sentAt: r.sent_at
    }));
    json(res, 200, { envelopes: rows });
  },

  'POST /api/ack': async (req, res) => {
    const a = await auth(req); if (!a) return json(res, 401, { error: 'Nicht angemeldet' });
    const b = await readBody(req);
    let n = 0;
    for (const id of (b.ids || [])) { await q.ackEnvelope.run(Date.now(), id, a.device.id); n++; }
    await q.purgeAcked.run(Date.now() - 7 * 864e5);
    json(res, 200, { acked: n });
  },

  /* ---- Blockieren & Melden ---- */
  'POST /api/block': async (req, res) => {
    const a = await auth(req); if (!a) return json(res, 401, { error: 'Nicht angemeldet' });
    const b = await readBody(req);
    if (!b.userId) return json(res, 400, { error: 'userId fehlt' });
    await q.addBlock.run(a.user.id, b.userId, Date.now());
    json(res, 200, { ok: true });
  },

  'POST /api/unblock': async (req, res) => {
    const a = await auth(req); if (!a) return json(res, 401, { error: 'Nicht angemeldet' });
    const b = await readBody(req);
    await q.removeBlock.run(a.user.id, b.userId || '');
    json(res, 200, { ok: true });
  },
  'GET /api/blocks': async (req, res) => {
    const a = await auth(req); if (!a) return json(res, 401, { error: 'Nicht angemeldet' });
    const blockedRows = await q.blockedByMe.all(a.user.id);
    json(res, 200, { blocked: blockedRows.map(r => r.blocked_id) });
  },

  /* Meldung überträgt NUR Kennung + Grund; Inhalt nur, wenn der Meldende
     ihn ausdrücklich beifügt — der Server hat bei E2EE sonst keinen
     Klartext (siehe reportMessage() im Client, APPSTORE-PWA.md Punkt 2). */
  'POST /api/report': async (req, res) => {
    const a = await auth(req); if (!a) return json(res, 401, { error: 'Nicht angemeldet' });
    const b = await readBody(req);
    if (!b.reportedId || !b.reason) return json(res, 400, { error: 'reportedId oder reason fehlt' });
    const id = 'rep' + crypto.randomBytes(8).toString('hex');
    await q.addReport.run(id, a.user.id, b.reportedId, b.convId || null, b.reason,
      b.note || null, b.includedContent || null, Date.now());
    json(res, 200, { ok: true, id });
  },

  /* ---- Kontaktabgleich ("X nutzt die App auch") ----
     Der Client hasht Telefonnummern/E-Mails LOKAL (siehe hashContact in
     api-client.js) und schickt nur Hashes. Der Server vergleicht Hash
     gegen Hash — er bekommt nie eine Nummer im Klartext, weder die
     eigenen Kontakte des Nutzers noch die anderer. */
  'POST /api/contacts/sync': async (req, res) => {
    const a = await auth(req); if (!a) return json(res, 401, { error: 'Nicht angemeldet' });
    const b = await readBody(req);
    if (!Array.isArray(b.hashes) || !b.hashes.length)
      return json(res, 400, { error: 'hashes fehlt oder leer' });
    if (b.hashes.length > 5000)
      return json(res, 400, { error: 'Zu viele Hashes auf einmal' });

    /* Bisherige Hashes ersetzen (Kontakte können gelöscht worden sein) */
    await q.clearContactHashes.run(a.user.id);
    for (const h of b.hashes) {
      if (typeof h === 'string' && h.length <= 64) await q.putContactHash.run(a.user.id, h);
    }

    /* Treffer: eigene Kontakt-Hashes, die dem SELBST-Hash eines anderen
       Nutzers entsprechen — heißt, diese Person hat diesen Nutzer im
       Adressbuch, und der andere Nutzer ist mit genau dieser Nummer/
       E-Mail registriert. */
    const matches = await q.findByHash.all(a.user.id, a.user.id);
    const newMatches = [];
    for (const m of matches) {
      if (!await q.wasNotified.get(a.user.id, m.matched_id)) {
        await q.markNotified.run(a.user.id, m.matched_id, Date.now());
        newMatches.push(m.matched_id);
      }
    }

    /* Push nur für WIRKLICH neue Treffer — sonst würde jeder erneute
       Sync (App-Start etc.) dieselbe Benachrichtigung wiederholen. */
    for (const matchedId of newMatches) {
      const matchedDevices = await q.devicesOf.all(matchedId);
      for (const d of matchedDevices) {
        deliverToDevice(d.id, { type: 'contact-joined', userId: a.user.id });
        notifyOffline(d.id);
      }
    }

    json(res, 200, {
      matches: matches.map(m => m.matched_id),
      newMatches
    });
  },

  /* ---- Sealed Sender ---- */

  /* Kurzlebiges Absenderzertifikat holen (nur mit Login) */
  'GET /api/sender-certificate': async (req, res) => {
    const a = await auth(req); if (!a) return json(res, 401, { error: 'Nicht angemeldet' });
    json(res, 200, { certificate: issueSenderCertificate(a.user, a.device), logKey: logKeys.jwk, ttl: CERT_TTL });
  },

  /* Eigenen Unidentified Access Key hinterlegen.
     Der Server speichert nur den Wert zum Vergleich — abgeleitet wird er
     clientseitig aus dem Profilschlüssel, den nur Kontakte kennen. */
  'POST /api/access-key': async (req, res) => {
    const a = await auth(req); if (!a) return json(res, 401, { error: 'Nicht angemeldet' });
    const b = await readBody(req);
    if (!b.uak) return json(res, 400, { error: 'uak fehlt' });
    await q.setUAK.run(String(b.uak), b.allowSealed === false ? 0 : 1, a.user.id);
    json(res, 200, { ok: true, allowSealed: b.allowSealed !== false });
  },

  /* Anonyme Zustellung: KEIN Bearer-Token.
     Legitimation ist allein der UAK des Empfängers im Header. Genau wie
     /api/send liefert der Client eine Liste versiegelter Umschläge, einen
     pro aktivem Empfängergerät — das Bundle für die Geräteliste hat er
     zuvor öffentlich über /api/bundle abgerufen (das erfordert selbst
     keine Auth-Preisgabe des Absenders). */
  'POST /api/send-sealed': async (req, res) => {
    const b = await readBody(req);
    const uak = req.headers['x-unidentified-access-key'];
    if (!uak) return json(res, 401, { error: 'Kein Zustellrecht vorgelegt' });
    if (!b.recipientId || !Array.isArray(b.perDevice) || !b.perDevice.length)
      return json(res, 400, { error: 'Empfänger oder perDevice-Liste fehlt' });

    const target = await q.byUAK.get(b.recipientId, String(uak));
    if (!target) return json(res, 403, { error: 'Zustellrecht ungültig oder abgelehnt' });

    const now = Date.now();
    const results = [];
    for (const d of b.perDevice) {
      if (!d.deviceId || !d.sealed) continue;
      const dev = await q.deviceById.get(d.deviceId);
      if (!dev || dev.user_id !== target.id) continue;   // fremdes/entferntes Gerät ignorieren

      const id = 'e' + crypto.randomBytes(10).toString('hex');
      /* sender_id UND sender_device_id bleiben NULL — der Server kann
         beide nicht ermitteln, das ist der ganze Zweck. */
      await q.putEnvelope.run(id, null, null, 1, b.recipientId, d.deviceId,
        b.convId || '', null, 'sealed', null, d.sealed,
        b.gossip ? JSON.stringify(b.gossip) : null, now);

      const env = {
        type: 'envelope', id, sealed: true, senderId: null, senderDeviceId: null,
        recipientId: b.recipientId, recipientDeviceId: d.deviceId,
        convId: b.convId, kind: 'sealed', ciphertext: d.sealed,
        gossip: b.gossip || null, sentAt: now
      };
      const online = deliverToDevice(d.deviceId, env);
      if (!online) notifyOffline(d.deviceId);
      results.push({ deviceId: d.deviceId, id, delivered: online });
    }
    json(res, 200, { sentAt: now, results });
  },
  'POST /api/group': async (req, res) => {
    const a = await auth(req); if (!a) return json(res, 401, { error: 'Nicht angemeldet' });
    const b = await readBody(req);
    const id = 'g' + crypto.randomBytes(8).toString('hex');
    await q.addGroup.run(id, b.name, b.avatar || '👥', a.user.id, Date.now());
    await q.addMember.run(id, a.user.id, b.wrapped?.[a.user.id] || null, 1);
    for (const m of (b.members || [])) await q.addMember.run(id, m, b.wrapped?.[m] || null, 0);
    json(res, 201, { groupId: id });
  },

  'GET /api/groups': async (req, res) => {
    const a = await auth(req); if (!a) return json(res, 401, { error: 'Nicht angemeldet' });
    const groupRows = await q.groupsOf.all(a.user.id);
    const gs = await Promise.all(groupRows.map(async g => {
      const members = await q.membersOf.all(g.id);
      const myWrapped = await q.myWrapped.get(g.id, a.user.id);
      return {
        id: g.id, name: g.name, avatar: g.avatar, ownerId: g.owner_id, createdAt: g.created_at,
        members: members.map(m => ({ userId: m.user_id, isAdmin: !!m.is_admin })),
        wrapped: myWrapped?.wrapped || null
      };
    }));
    json(res, 200, { groups: gs });
  },

  /* ---- Key Transparency ---- */
  'GET /api/kt/sth': async (req, res) => json(res, 200, {
    sth: latestSTH(), logKey: logKeys.jwk,
    witnesses: witnesses.map(w => ({ name: w.name, jwk: w.jwk, refusals: w.refusals.length }))
  }),

  'GET /api/kt/consistency': async (req, res, url) => {
    const from = parseInt(url.searchParams.get('from') || '0', 10);
    const lv = await allLeaves();
    json(res, 200, {
      from, to: lv.length,
      proof: consistencyProof(from, lv).map(b64),
      sth: await latestSTH()
    });
  },

  'GET /api/kt/proof': async (req, res, url) => {
    const target = url.searchParams.get('user');
    const e = await q.ktLatestFor.get(target);
    if (!e) return json(res, 404, { error: 'Kein Log-Eintrag' });
    const lv = await allLeaves();
    json(res, 200, {
      entry: { userId: e.user_id, keyX: e.key_x, keyY: e.key_y, version: e.version },
      index: e.idx, path: inclusionPath(e.idx, lv).map(b64), sth: await latestSTH()
    });
  },

  'GET /api/kt/history': async (req, res, url) => {
    const target = url.searchParams.get('user');
    const lv = await allLeaves();
    const historyRows = await q.ktByUser.all(target);
    const sth = await latestSTH();
    const rows = historyRows.map(e => ({
      version: e.version, keyX: e.key_x, keyY: e.key_y, index: e.idx,
      addedAt: e.added_at, path: inclusionPath(e.idx, lv).map(b64)
    }));
    json(res, 200, { userId: target, entries: rows, sth });
  },

  /* ---- Mixnet ---- */

  /* Knotenverzeichnis: öffentliche Schlüssel für den Zwiebelbau.
     wireSize ist die tatsächliche Größe AUF DER LEITUNG (inklusive des
     einen Versionsbyte-Präfix) — packetSize bleibt die Basisgröße der
     aktuellen Protokollversion, damit bestehende Clients, die den alten
     Namen lesen, nicht brechen. */
  'GET /api/mix/directory': async (req, res) => json(res, 200, {
    nodes: mixNet.directory,
    pathLength: MIX.PATH_LENGTH,
    packetSize: MIX.PACKET_SIZE,
    wireSize: MIX.VERSION_BYTE_SIZE + MIX.PACKET_SIZE,
    maxPayload: MIX.MAX_PAYLOAD,
    meanDelayMs: MIX.MEAN_DELAY_MS,
    protocolVersion: MIX.CURRENT_VERSION,
    supportedVersions: MIX.SUPPORTED_VERSIONS
  }),

  /* Paket einspeisen — bewusst OHNE Login.
     Wer sich hier authentifizieren müsste, wäre sofort wieder verkettbar. */
  'POST /api/mix/inject': async (req, res) => {
    const b = await readBody(req);
    if (!b.packet || !b.firstHop)
      return json(res, 400, { error: 'packet oder firstHop fehlt' });
    let packet;
    try { packet = Buffer.from(b.packet, 'base64'); }
    catch { return json(res, 400, { error: 'packet ist kein gültiges Base64' }); }
    /* Vorprüfung synchron: offensichtlicher Unsinn soll nicht erst die
       Warteschlange eines Mix-Knotens belasten. Geprüft wird gegen ALLE
       gültigen Außengrößen über alle unterstützten Protokollversionen —
       nicht gegen eine einzelne feste Zahl, sonst bräche das bei jedem
       Versionswechsel wieder. Die eigentliche, autoritative Prüfung
       (welche Version, welcher Hop) macht weiterhin MixNode.peel. */
    const validSizes = MIX.SUPPORTED_VERSIONS.flatMap(v => MIX.sizesFor(v).hopSizes);
    if (!validSizes.includes(packet.length))
      return json(res, 400, {
        error: `Paketgröße ${packet.length} passt zu keiner unterstützten Protokollversion`
      });

    /* Sofort quittieren. Würden wir auf die Zustellung warten, verriete
       die Antwortzeit die Gesamtlatenz und damit indirekt den Pfad. */
    json(res, 202, { accepted: true, at: Date.now() });
    mixNet.inject(b.firstHop, packet).catch(e => {
      if (!/Replay|Paketgröße|Unbekannter|Protokollversion/.test(e.message)) console.error('mix:', e.message);
    });
  },

  'GET /api/mix/stats': async (req, res) => json(res, 200, {
    nodes: mixNet.stats(), inFlight: mixNet.inFlight
  }),

  'GET /api/health': async (req, res) => {
    const allUsersRows = await q.allUsers.all();
    const logSize = await q.ktCount.get();
    json(res, 200, {
      ok: true, users: allUsersRows.length,
      logSize: logSize.n, online: live.size,
      mixNodes: mixNodes.length, uptime: Math.round(process.uptime())
    });
  }
};

/*───────────────────────────────────────────────────────────────────────────
  SERVER
───────────────────────────────────────────────────────────────────────────*/
/*───────────────────────────────────────────────────────────────────────────
  STATISCHE AUSLIEFERUNG
  ─────────────────────────────────────────────────────────────────────────
  Liefert Dateien aus public/. "/", "/index.html" und "/app.html" liefern
  alle dieselbe echte App (index.html ist die Kopie, die als Startseite
  dient — Konvention für Webserver, die "/" ohne Dateinamen auflösen).
───────────────────────────────────────────────────────────────────────────*/
const PUBLIC_DIR = path.join(__dirname, 'public');
const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js':   'text/javascript; charset=utf-8',
  '.mjs':  'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.css':  'text/css; charset=utf-8',
  '.png':  'image/png',
  '.svg':  'image/svg+xml',
  '.ico':  'image/x-icon',
  '.webmanifest': 'application/manifest+json'
};

function serveStatic(pathname, res) {
  const target = (pathname === '/' || pathname === '/index.html' || pathname === '/app.html')
    ? '/index.html' : pathname;

  /* Gegen Pfad-Traversal (../../etc/passwd o. Ä.): erst normalisieren,
     dann sicherstellen, dass das Ergebnis wirklich noch INNERHALB von
     public/ liegt. decodeURIComponent zuerst, weil ein codiertes ../
     (%2e%2e%2f) sonst die Prüfung umginge. */
  let decoded;
  try { decoded = decodeURIComponent(target); } catch { return false; }
  const filePath = path.normalize(path.join(PUBLIC_DIR, decoded));
  if (!filePath.startsWith(PUBLIC_DIR + path.sep) && filePath !== PUBLIC_DIR) return false;

  if (!fs.existsSync(filePath) || !fs.statSync(filePath).isFile()) return false;

  const ext = path.extname(filePath);
  const mime = MIME_TYPES[ext] || 'application/octet-stream';
  const body = fs.readFileSync(filePath);
  res.writeHead(200, {
    'Content-Type': mime,
    'Content-Length': body.length,
    /* index.html/app.html selbst nie langfristig cachen — sonst sieht
       ein Nutzer nach einem Deploy erst nach hartem Reload die neue
       Version. Module dahinter (app.js etc.) landen im Service-Worker-
       Cache, der hat eine eigene, kontrollierte Invalidierung. */
    'Cache-Control': ext === '.html' ? 'no-cache' : 'public, max-age=3600'
  });
  res.end(body);
  return true;
}

const server = http.createServer(async (req, res) => {
  const ip = req.socket.remoteAddress || '?';
  if (req.method === 'OPTIONS') return json(res, 204, {});
  if (!rateLimit(ip)) return json(res, 429, { error: 'Zu viele Anfragen' });

  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const key = `${req.method} ${url.pathname}`;

  /* ─── Statische Auslieferung des Clients ───────────────────────────────
     index.html ist jetzt die echte Anwendung (spricht über app.js/
     api-client.js mit diesem Server) und damit die Standardseite unter
     "/" — Konvention für Webserver. app.html liefert denselben Inhalt
     als Alias. Die frühere Entwicklungs-Simulation ohne echte Server-
     anbindung liegt als index-simulation-demo.html weiterhin vor.

     Bislang existierte NUR eine Route für die alte index.html; app.js, crypto-
     core.js, api-client.js, i18n.js, device-info.js, manifest.json,
     sw.js und die Icons wurden nie über HTTP ausgeliefert — app.html
     hätte im Browser funktioniert, ihr <script src="/app.js"> aber mit
     404 wäre gescheitert. Das ist jetzt eine echte, generische
     Verzeichnisauslieferung statt einer Einzeldatei-Ausnahme. */
  /* /reset — löscht localStorage im Browser und leitet zur Startseite.
     Nützlich wenn die App beim Boot hängt (z. B. abgelaufenes Token). */
  if (req.method === 'GET' && url.pathname === '/reset') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end('<!DOCTYPE html><html><head><meta charset="utf-8"><title>Reset</title></head><body>' +
      '<script>' +
      'localStorage.clear();sessionStorage.clear();' +
      '(async()=>{' +
      '  if("serviceWorker" in navigator){' +
      '    const regs = await navigator.serviceWorker.getRegistrations();' +
      '    for(const r of regs) await r.unregister();' +
      '    const keys = await caches.keys();' +
      '    for(const k of keys) await caches.delete(k);' +
      '  }' +
      '  location.href="/";' +
      '})();' +
      '</script><p>Wird zurückgesetzt…</p></body></html>');
    return;
  }

  if (req.method === 'GET' && !url.pathname.startsWith('/api/')) {
    const served = serveStatic(url.pathname, res);
    if (served) return;
  }

  const handler = routes[key];
  if (!handler) return json(res, 404, { error: 'Unbekannter Endpunkt' });
  try { await handler(req, res, url); }
  catch (e) { console.error(key, e.message); json(res, 500, { error: e.message }); }
});

/* WebSocket-Upgrade: Realtime-Zustellung und Präsenz */
server.on('upgrade', async (req, sock) => {
  const url = new URL(req.url, 'http://x');
  const token = url.searchParams.get('token');
  const s = token && await q.session.get(token, Date.now());
  const key = req.headers['sec-websocket-key'];
  if (!s || !key) { sock.end('HTTP/1.1 401 Unauthorized\r\n\r\n'); return; }
  const device = await q.deviceById.get(s.device_id);
  if (!device) { sock.end('HTTP/1.1 401 Unauthorized\r\n\r\n'); return; }   // Gerät entfernt

  sock.write(
    'HTTP/1.1 101 Switching Protocols\r\n' +
    'Upgrade: websocket\r\nConnection: Upgrade\r\n' +
    `Sec-WebSocket-Accept: ${wsAccept(key)}\r\n\r\n`);
  sock.setNoDelay(true);

  const uid = s.user_id, did = s.device_id;
  if (!live.has(did)) live.set(did, new Set());
  live.get(did).add(sock);
  deviceOwner.set(did, uid);
  await q.touchUser.run(Date.now(), uid);
  await q.touchDevice.run(Date.now(), did);
  broadcastPresence(uid, true, did);

  /* Wartende Umschläge NUR für dieses Gerät nachliefern — jedes andere
     Gerät desselben Nutzers hat seine eigene, unabhängige Warteschlange
     (weil jedes einen eigenen Ratchet-Zustand mit dem Absender hat). */
  const pendingRows = await q.pending.all(did);
  for (const r of pendingRows) {
    wsSend(sock, {
      type: 'envelope', id: r.id, senderId: r.sender_id, senderDeviceId: r.sender_device_id,
      sealed: !!r.sealed, convId: r.conv_id, groupId: r.group_id, kind: r.kind,
      header: r.header ? JSON.parse(r.header) : null,
      ciphertext: r.ciphertext, gossip: r.gossip ? JSON.parse(r.gossip) : null, sentAt: r.sent_at
    });
  }
  wsSend(sock, { type: 'ready', userId: uid, deviceId: did, sth: await latestSTH() });

  let cleaned = false;
  const cleanup = async () => {
    if (cleaned) return; cleaned = true;
    const set = live.get(did);
    if (set) { set.delete(sock); if (!set.size) { live.delete(did); deviceOwner.delete(did); } }
    await q.touchUser.run(Date.now(), uid);
    await q.touchDevice.run(Date.now(), did);
    broadcastPresence(uid, isOnline(uid), did);
    try { sock.destroy(); } catch {}
  };

  const parse = makeWsParser(async msg => {
    if (msg.type === 'ack' && Array.isArray(msg.ids)) {
      for (const id of msg.ids) await q.ackEnvelope.run(Date.now(), id, did);
    } else if (msg.type === 'typing' && msg.to) {
      deliverToUser(msg.to, { type: 'typing', from: uid, convId: msg.convId });
    } else if (msg.type === 'read' && msg.to) {
      deliverToUser(msg.to, { type: 'read', from: uid, convId: msg.convId, ids: msg.ids || [] });
    } else if (msg.type === 'ping') {
      wsSend(sock, { type: 'pong', ts: Date.now() });

    /* ── WebRTC-Anruf-Signalisierung ──────────────────────────────
       Der Server reicht hier NUR das SDP-Angebot/-Antwort und die
       ICE-Kandidaten zwischen den beiden Gesprächspartnern durch —
       genau wie eine Telefonvermittlung, die die Verbindung herstellt,
       aber nicht mithört. Der eigentliche Audio-/Videostrom läuft
       danach direkt (peer-to-peer) zwischen den Browsern, nie über
       diesen Server. callId identifiziert den Anrufversuch eindeutig,
       damit veraltete Nachrichten eines bereits beendeten/abgelehnten
       Anrufs nicht versehentlich einen neuen beeinflussen. */
    } else if (msg.type === 'call-offer' && msg.to && msg.callId && msg.sdp) {
      const online = deliverToUser(msg.to, {
        type: 'call-offer', from: uid, fromDeviceId: did,
        callId: msg.callId, kind: msg.kind === 'video' ? 'video' : 'audio', sdp: msg.sdp
      });
      /* Empfänger komplett offline -> Anrufer muss das SOFORT erfahren,
         sonst wartet die Anruf-Oberfläche endlos auf eine Antwort, die
         nie kommt. */
      if (!online) wsSend(sock, { type: 'call-unavailable', callId: msg.callId });
    } else if (msg.type === 'call-answer' && msg.to && msg.callId && msg.sdp) {
      deliverToUser(msg.to, { type: 'call-answer', from: uid, callId: msg.callId, sdp: msg.sdp });
    } else if (msg.type === 'call-ice' && msg.to && msg.callId && msg.candidate) {
      deliverToUser(msg.to, { type: 'call-ice', from: uid, callId: msg.callId, candidate: msg.candidate });
    } else if (msg.type === 'call-reject' && msg.to && msg.callId) {
      deliverToUser(msg.to, { type: 'call-reject', from: uid, callId: msg.callId, reason: msg.reason || 'declined' });
    } else if (msg.type === 'call-end' && msg.to && msg.callId) {
      deliverToUser(msg.to, { type: 'call-end', from: uid, callId: msg.callId });
    }
  }, cleanup);

  sock.on('data', parse);
  sock.on('close', cleanup);
  sock.on('end', cleanup);
  sock.on('error', cleanup);
  sock.setTimeout(0);
});

function broadcastPresence(uid, online, fromDeviceId) {
  const msg = { type: 'presence', userId: uid, online, at: Date.now() };
  for (const [devId, owner] of deviceOwner) {
    if (devId === fromDeviceId) continue;   // nicht sich selbst benachrichtigen
    for (const s of liveSockets(devId)) wsSend(s, msg);
  }
}

/* Push-Benachrichtigung auslösen, wenn ein Gerät offline ist und eine
   Nachricht bekommt. Inhalt bleibt bewusst leer (siehe sw.js) — der
   Server kennt den Klartext nie, kann ihn also auch nicht in die Push-
   Nutzlast packen. Ein abgelaufenes Abo (Nutzer hat Benachrichtigungen
   deaktiviert oder Browserdaten gelöscht) wird automatisch entfernt,
   statt bei jeder künftigen Nachricht erneut ins Leere zu laufen. */
async function notifyOffline(deviceId) {
  const sub = await q.pushForDevice.get(deviceId);
  if (!sub) return;
  try {
    let result;
    if (sub.platform === 'web') result = await sendWebPush(sub);
    else if (sub.platform === 'fcm') result = await sendFcmPush(sub);
    if (result?.expired) {
      await q.dropPush.run(deviceId);
      console.log('→ Abgelaufenes Push-Abo entfernt für Gerät', deviceId);
    }
  } catch (e) { console.warn('Push fehlgeschlagen:', e.message); }
}

/* Web Push (RFC 8291/8292) über push.js — kein Fremdanbieter, kein
   npm-Paket. Ohne VAPID-Schlüssel (siehe oben, wird beim ersten Start
   automatisch erzeugt) würde diese Funktion nie erreicht — die
   Schlüssel existieren also immer, sobald der Server läuft. */
async function sendWebPush(sub) {
  return PUSH.sendWebPush(
    { endpoint: sub.endpoint, p256dh: sub.p256dh, auth: sub.auth },
    { type: 'new-message' },   // keine Vorschau, kein Klartext — nur ein Weckruf
    { publicKey: vapidKeys.publicKey, privateKeyJwk: vapidKeys.privateKeyJwk, subject: VAPID_SUBJECT }
  );
}

/* FCM HTTP v1 — die Legacy-API (fcm.googleapis.com/fcm/send mit
   Server-Key) wurde von Google Mitte 2024 endgültig abgeschaltet; ein
   Aufruf dorthin würde nie ankommen. HTTP v1 verlangt stattdessen ein
   Service-Account-JSON, das push.js selbst zu einem OAuth2-Token
   signiert. Ohne fcm-service-account.json bleibt Android/iOS-Push aus,
   alles andere funktioniert unverändert. */
async function sendFcmPush(sub) {
  if (!fcmServiceAccount) return { ok: false, skipped: true };
  return PUSH.sendFcmPush(sub.endpoint, { type: 'new-message' }, fcmServiceAccount);
}

/* Prekey-Pools überwachen und Clients zum Nachfüllen auffordern —
   pro GERÄT, weil jedes Gerät seinen eigenen One-Time-Prekey-Pool hat. */
setInterval(async () => {
  const allUsersRows = await q.allUsers.all();
  for (const u of allUsersRows) {
    const devices = await q.devicesOf.all(u.id);
    for (const d of devices) {
      const opkCount = await q.countOPK.get(d.id);
      const n = opkCount.n;
      if (n < OPK_LOW_WATER) deliverToDevice(d.id, { type: 'need-prekeys', available: n });
    }
  }
}, 60000).unref();

/* Alte, bereits ZUGESTELLTE Nachrichten (inkl. Bild-/Datei-Anhänge, die
   als Umschlag denselben envelopes-Weg nehmen) nach 7 Tagen entfernen.
   Bewusst nur acked=1: eine Nachricht, die ein Empfänger noch nie
   abgeholt hat (z. B. weil sein Gerät länger offline war), bleibt
   erhalten, bis sie tatsächlich zugestellt wurde — sonst ginge sie
   komplett verloren, bevor sie überhaupt ankam.

   Lief bisher nur als Nebeneffekt von POST /api/ack (siehe dort) —
   das heißt, ohne aktiven Client, der gerade quittiert, sammelten sich
   alte Nachrichten unbegrenzt an. Als eigener Intervall-Job läuft das
   Aufräumen jetzt zuverlässig, unabhängig davon, ob gerade ein Nutzer
   aktiv ist. Einmal pro Stunde reicht bei einer Sieben-Tage-Frist völlig
   aus; unref() verhindert, dass der Timer den Prozess am Beenden
   hindert (Test-Skripte, sauberes Herunterfahren). */
setInterval(async () => {
  const cutoff = Date.now() - 7 * 864e5;
  const result = await q.purgeAcked.run(cutoff);
  if (result.changes > 0) {
    console.log(`→ ${result.changes} zugestellte Nachricht(en) älter als 7 Tage entfernt`);
  }
}, 3600000).unref();

if (require.main === module) {
  const logSize = await q.ktCount.get();
  /* WICHTIG: explizit auf 0.0.0.0 binden, nicht nur den Port angeben.
     Ohne Host-Angabe kann Node je nach Container-Netzwerkkonfiguration
     nur auf einer internen Adresse lauschen, die von außen (z. B. über
     den Fly.io-Proxy oder Renders Load Balancer) nicht erreichbar ist —
     0.0.0.0 bedeutet "auf allen Netzwerkschnittstellen lauschen" und ist
     auf praktisch jeder Cloud-Plattform die richtige Bindung für einen
     öffentlich erreichbaren Dienst. */
  const HOST = process.env.HOST || '0.0.0.0';
  server.listen(PORT, HOST, () => {
    console.log(`SecureChat-Server läuft auf http://${HOST}:${PORT}`);
    console.log(`  Datenbank : ${process.env.DATABASE_URL ? 'Postgres/Neon (verbunden)' : 'NICHT KONFIGURIERT — DATABASE_URL fehlt'}`);
    console.log(`  Log-Größe : ${logSize.n} Einträge`);
    console.log(`  Witnesses : ${witnesses.map(w => w.name).join(', ')}`);
  });
}

return { server, db, q, issueSenderCertificate, certBytes, MTH, inclusionPath, consistencyProof, verifyConsistency,
  leafHash, entryBytes, publishSTH, latestSTH, ktAppend, hashPw, verifyPw, allLeaves };
}   // Ende von async function main()

/* main() startet den Server sofort beim Laden dieses Moduls (wie bisher
   das Top-Level-server.listen), gibt aber gleichzeitig ein Promise
   zurück, das die wichtigen internen Objekte enthält — nötig, damit
   Testskripte (die vorher synchron auf module.exports.q zugreifen
   konnten) weiterhin Zugriff bekommen, nur eben über await statt direkt.
   module.exports selbst bleibt ein Promise, kein fertiges Objekt —
   das ist die sichtbarste äußere Auswirkung der Async-Migration für
   alles, was diese Datei importiert. */
module.exports = main();
module.exports.catch(err => {
  console.error('Serverstart fehlgeschlagen:', err);
  process.exit(1);
});

