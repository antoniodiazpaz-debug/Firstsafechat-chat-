# SecureChat auf dem Handy testen — nur Android, kein Computer

Termux macht aus deinem Android-Handy ein echtes Linux-Terminal. Kostenlos,
kein Root nötig. Der Server läuft direkt auf dem Handy, der Browser auf
demselben Handy verbindet sich über `localhost` — kein Tunnel, kein
zweites Gerät.

**Dauer:** rund 15 Minuten, hauptsächlich Wartezeit beim Herunterladen.

---

## 1 — Termux installieren

**Nur über F-Droid**, nicht über den Play Store — die Play-Store-Version
wird seit Jahren nicht mehr gepflegt und lässt sich nicht mehr sauber
aktualisieren.

1. Im Handy-Browser: **f-droid.org**
2. F-Droid-App herunterladen und installieren (einmalig „Unbekannte
   Quellen zulassen", das fragt Android automatisch ab)
3. In F-Droid nach **Termux** suchen, installieren

## 2 — Node.js installieren

Termux öffnen, dann direkt hintereinander eintippen:

```bash
pkg update -y && pkg upgrade -y
pkg install nodejs-lts -y
node --version
```

**Kein Compiler nötig.** Viele Node-Projekte auf Termux brauchen
zusätzlich `build-essential` und `python3`, weil sie npm-Pakete mit
nativem Code (z. B. das `sqlite3`-Paket) aus dem Quelltext kompilieren
müssen — das schlägt auf Termux öfter fehl. SecureChat hat bewusst
keine einzige npm-Abhängigkeit, auch nicht für SQLite (`node:sqlite`
ist in Node selbst eingebaut) oder Push-Benachrichtigungen — nur
`pkg install nodejs-lts` reicht aus.

Die letzte Zeile muss **v22.5.0 oder neuer** zeigen — das Projekt nutzt
`node:sqlite`, das erst ab dieser Version eingebaut ist. Termux liefert
inzwischen Node 22 LTS oder neuer standardmäßig aus.

Falls eine ältere Version installiert wurde:
```bash
pkg install nodejs -y   # aktuellere, nicht-LTS-Linie als Fallback
```

## 3 — Speicherzugriff freigeben und Projekt holen

Damit Termux auf den normalen Handyspeicher zugreifen kann (praktisch,
falls du die Projektdateien schon irgendwo abgelegt hast):

```bash
termux-setup-storage
```
Android fragt nach einer Berechtigung — zulassen.

**Projekt herunterladen**, je nachdem wo es liegt:

Wenn es auf GitHub liegt (siehe `GITHUB.md` im Projekt):
```bash
pkg install git -y
git clone https://github.com/<dein-name>/securechat.git
cd securechat
```

Wenn du die Dateien manuell übertragen hast (z. B. per Datei-Sync in den
Downloads-Ordner):
```bash
cd ~/storage/downloads/securechat-server
```

## 4 — Server starten

```bash
node server.js
```

Erwartete Ausgabe:
```
→ Neuer Log-Signaturschlüssel erzeugt: …
→ Neue VAPID-Schlüssel erzeugt: …
SecureChat-Server läuft auf http://localhost:8787
  Datenbank : …/securechat.db
  Log-Größe : 0 Einträge
  Witnesses : Auditor-EU, Auditor-US, Uni-Labor
```

**Dieses Terminal-Fenster muss offen bleiben**, solange du die App
benutzt — der Server läuft nur, während dieser Befehl aktiv ist.

## 5 — App öffnen

Auf demselben Handy den normalen Browser öffnen (Chrome, Firefox, egal)
und aufrufen:

```
http://localhost:8787
```

Das funktioniert ohne HTTPS-Zertifikat, weil `localhost` von WebCrypto
automatisch als sicherer Kontext behandelt wird — das Projekt braucht
genau das für die Ende-zu-Ende-Verschlüsselung (siehe die Prüfung in
`crypto-core.js`).

Registrieren, chatten, alles testen wie in einer echten App.

## 6 — Als App-Icon auf dem Startbildschirm

Im Browser-Menü (⋮) → **„Zum Startbildschirm hinzufügen"**.
Danach startet SecureChat mit eigenem Icon, ohne Adressleiste — der
PWA-Modus, für den `manifest.json` und `sw.js` im Projekt gebaut sind.

---

## Damit Termux weiterläuft, wenn du die App wechselst

Android beendet Termux gern im Hintergrund, um Akku zu sparen. Zwei
Dinge helfen:

**Wecker-Symbol in Termux aktivieren** — in der Android-Benachrichtigung
von Termux gibt es einen Schieberegler „Acquire Wakelock". Antippen,
bevor du zur App wechselst.

**Batterieoptimierung für Termux ausschalten:**
Android-Einstellungen → Apps → Termux → Akku → „Nicht optimieren"

Ohne das kann der Server nach einigen Minuten im Hintergrund pausiert
werden, und die App verliert die Verbindung.

---

## Zweites Gerät koppeln (Multi-Device testen)

Willst du das Multi-Device-Feature ausprobieren, brauchst du ein zweites
Gerät im selben WLAN, das den Server über die lokale Handy-IP erreicht:

```bash
ip addr show wlan0 | grep "inet "
```

Liefert etwas wie `192.168.1.42`. Auf dem zweiten Gerät dann:
```
http://192.168.1.42:8787
```

**Achtung:** WebCrypto verlangt HTTPS oder `localhost` — über die reine
IP-Adresse wird ein zweiter Browser die Verschlüsselung verweigern. Für
einen echten Zweitgeräte-Test brauchst du dann doch ein Zertifikat, z. B.
über `npx cloudflared tunnel --url http://localhost:8787` aus Termux
heraus (funktioniert genauso wie auf einem Computer).

---

## Wenn etwas klemmt

| Problem | Lösung |
|---|---|
| `node: command not found` | `pkg install nodejs-lts -y` erneut, dann neues Termux-Fenster öffnen |
| `Error: Cannot find module 'node:sqlite'` | Node-Version zu alt, `node --version` prüfen, siehe Schritt 2 |
| Seite lädt nicht im Browser | Terminal prüfen, ob der Server noch läuft (siehe Schritt 4) |
| Verbindung bricht nach Minuten ab | Wakelock/Batterieoptimierung, siehe oben |
| `EADDRINUSE` beim Start | Server läuft schon in einem anderen Termux-Fenster — dorthin wechseln oder `pkill node` |
| Downloads-Ordner nicht sichtbar | `termux-setup-storage` erneut ausführen, Berechtigung bestätigen |

---

## Nach dem Test: Server sauber beenden

Im Termux-Fenster: `Strg` + `C` (bei externer Tastatur) oder in Termux
selbst die Lautstärke-runter-Taste + `C` gedrückt halten — das ist
Termux' Ersatz für Strg+C auf dem virtuellen Keyboard.
