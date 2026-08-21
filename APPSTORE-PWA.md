# App Store und Web-App

## Kurzfassung

**App Store: geht.** Signal, Threema und Element sind dort — Ende-zu-Ende-
Verschlüsselung ist kein Ablehnungsgrund. Es gibt aber vier Hürden, die
nichts mit Krypto zu tun haben und an denen Erstversuche regelmäßig
scheitern.

**Web-App zum Speichern: geht auch** — mit einem Vorbehalt, der dein
Schlüsselkonzept direkt trifft.

---

## Die Web-App (PWA)

Der Nutzer öffnet die Seite und wählt „Zum Home-Bildschirm". Danach hat er
ein Symbol wie bei einer App, Vollbild ohne Browserleiste, und die App
startet auch offline.

Das kostet nichts, braucht keine Prüfung, keine Store-Konten, und
Aktualisierungen sind sofort bei allen Nutzern.

### Der Vorbehalt: iOS kann den Speicher löschen

iOS entfernt den Speicher einer Web-App nach etwa einer Woche
Nichtnutzung, sofern kein dauerhafter Speicher gewährt wurde. Für
Homescreen-Apps gilt diese Frist offiziell nicht, aber gelöscht werden
kann trotzdem — bei Speicherdruck oder überschrittenem Kontingent.

Bei einem gewöhnlichen Dienst ist das ärgerlich. Hier heißt es:
**Identitätsschlüssel weg, gesamter Verlauf unlesbar.**

Deshalb liegt in `public/storage-guard.js` eine dreifache Absicherung:

| Schicht | Was sie tut | Verlässlich? |
|---|---|---|
| `navigator.storage.persist()` | bittet um dauerhaften Speicher | meistens |
| Zustandsprüfung bei jedem Start | warnt vor Gefahr | erkennt nur |
| **Wiederherstellungsphrase** | 29 Wörter zum Notieren | **ja** |

Nur die dritte ist wirklich verlässlich. Die Phrase ist getestet: 200
zufällige Schlüssel exakt rekonstruiert, 94 % der Tippfehler durch die
Prüfsumme erkannt.

**Regel: Kein Konto ohne gesicherte Wiederherstellungsphrase.** Nicht als
Hinweis, den man wegklicken kann, sondern als Schritt bei der
Registrierung. Der Nutzer muss drei zufällige Wörter zurücktippen, bevor
es weitergeht — sonst notiert sie niemand.

### Was auf iOS als PWA nicht geht

- **Kein Klingeln bei geschlossener App.** Für eingehende Anrufe fehlt
  VoIP-Push. Das ist der Hauptgrund, überhaupt eine native App zu bauen.
- **Keine Hintergrundsynchronisierung.** Nachrichten kommen erst beim
  Öffnen an — Push weckt zwar auf, holt aber nichts nach.
- **Keine Auffindbarkeit.** Niemand sucht im Browser nach einem Messenger.

Auf Android ist die Lage entspannter: Push, Hintergrundsync und
Installation funktionieren weitgehend wie bei nativen Apps.

---

## App Store: die vier echten Hürden

### 1. Ausfuhrerklärung für Verschlüsselung

In `Info.plist` gehört:

```xml
<key>ITSAppUsesNonExemptEncryption</key><true/>
<key>ITSEncryptionExportComplianceCode</key><string>…</string>
```

Du brauchst eine **CCATS-Einstufung** vom US-Handelsministerium. Klingt
schlimmer, ist ein Formular und dauert zwei bis sechs Wochen. Kostenlos,
aber plane die Zeit ein. Wer hier `false` einträgt, obwohl er
verschlüsselt, riskiert die Entfernung der App.

Frankreich verlangt zusätzlich eine Meldung bei der ANSSI.

### 2. Moderation nutzergenerierter Inhalte

Apples Richtlinie 1.2 verlangt bei Apps mit Nutzerinhalten:

- eine Meldefunktion für Missbrauch
- eine Blockierfunktion
- Nutzungsbedingungen, denen zugestimmt wird
- Reaktion auf Meldungen binnen 24 Stunden

**Der Knackpunkt:** Bei Ende-zu-Ende-Verschlüsselung kannst du Inhalte
nicht prüfen. Der akzeptierte Weg ist der von Signal: Blockieren und
Melden vorhanden, Meldung überträgt nur die Kennung des Absenders, keine
Inhalte. Das genügt Apple — aber es muss vorhanden sein.

Blockieren ist schon eingebaut, Melden fehlt noch.

### 3. Kein reiner Web-Wrapper

Richtlinie 4.2: Eine App, die nur eine Webseite anzeigt, wird abgelehnt.
Du brauchst mindestens:

- native Push-Benachrichtigungen
- Zugriff auf Kamera und Mikrofon über native APIs
- Kontaktimport oder Teilen-Integration
- funktionierender Offline-Zustand

Praktikabel: **Capacitor**. Deine Web-App im nativen Rahmen, mit echten
Plugins für Push, Kamera und Dateien. Etwa fünf Tage Arbeit statt einer
Neuentwicklung.

### 4. Konto löschen im Programm

Seit 2022 verpflichtend: Wer ein Konto anlegen kann, muss es in der App
auch löschen können. Nicht per E-Mail, nicht über die Webseite.

Das betrifft dein Schema: Kontolöschung muss Profile, Prekeys, Umschläge
und Medien entfernen — nur die Einträge im Transparenz-Log bleiben, weil
das Log append-only ist. Das ist zulässig, gehört aber in die
Datenschutzerklärung.

---

## Aufwand und Kosten

| Weg | Aufwand | Kosten | Ergebnis |
|---|---|---|---|
| **PWA** | 1 Tag | 0 € | läuft überall, kein Anrufklingeln auf iOS |
| PWA + Capacitor Android | +3 Tage | 25 € einmalig | Play Store, Push, Anrufe |
| + iOS | +4 Tage | 99 €/Jahr | App Store, VoIP-Push |

Dazu einmalig zwei bis sechs Wochen Wartezeit für die CCATS-Einstufung.

---

## Empfehlung

**Zuerst PWA, mit Wiederherstellungsphrase als Pflichtschritt.** Ein Tag
Arbeit, kostet nichts, und du erfährst, ob überhaupt jemand die App
benutzen will, bevor du Wochen in Store-Formalitäten steckst.

**Dann Android über Capacitor.** 25 € einmalig, drei Tage, und du
bekommst funktionierende Anrufe und Push.

**iOS zuletzt** — dort ist der Aufwand am höchsten und der Nutzen erst
dann groß, wenn du echte Nutzer hast, die danach fragen.

Signal hat das genauso gemacht: erst eine App, dann die zweite Plattform,
dann der Rest.
