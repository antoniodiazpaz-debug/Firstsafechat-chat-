# Kostenfrei und automatisch

Die 15 €/Monat für Fly.io entfallen bei drei der vier Komponenten ohnehin.
Nur die Mix-Knoten brauchen einen Ersatz, weil sie Zustand und Timer
benötigen — genau das, was serverlose Funktionen nicht haben.

| Komponente | Kostenfreie Lösung | Grenze |
|---|---|---|
| Client | Netlify Free | 100 GB/Monat |
| Datenbank + Auth + Realtime | Supabase Free | 500 MB, 200 gleichzeitige Verbindungen |
| Transparenz-Log | Netlify Function | 125 000 Aufrufe/Monat |
| **Mix-Knoten** | siehe unten | |

## Die drei Wege für Mix-Knoten

### A — Oracle Cloud Always Free ⭐ empfohlen

Zwei ARM-VMs mit zusammen 4 Kernen und 24 GB RAM, dauerhaft kostenlos, kein
Ablaufdatum. Das ist mit Abstand das großzügigste Angebot am Markt.

**Der entscheidende Vorteil:** Es sind echte Linux-Maschinen. `mix-node.js`
läuft dort **unverändert** — dieselbe Datei, die hier durch 26 Tests
gegangen ist. Keine Portierung, keine neue Fehlerquelle.

Nachteil: Die Registrierung verlangt eine Kreditkarte zur Verifikation
(ohne Abbuchung), und in beliebten Regionen sind ARM-Kapazitäten manchmal
knapp. Dann eine andere Region wählen.

### B — Cloudflare Durable Objects

Der technisch interessanteste Weg. Ein Durable Object ist eine einzelne,
dauerhafte Instanz mit eigenem Speicher — und mit **Alarms**, mit denen es
sich selbst zu einem späteren Zeitpunkt aufwecken kann. Damit lässt sich
die Poisson-Verzögerung serverlos umsetzen, was auf Netlify unmöglich ist.

Seit 2025 im Free-Plan enthalten. Kein Einschlafen, keine Kaltstarts beim
Weiterleiten.

Nachteil: `mix-node.js` läuft dort nicht direkt. Die Krypto müsste von
`node:crypto` auf WebCrypto portiert werden — machbar, aber neuer Code,
der neu getestet werden muss. Und: Ein Alarm pro Objekt gleichzeitig, also
ein Durable Object pro Paket statt pro Knoten.

### C — Render / Koyeb / Deno Deploy

Schnell eingerichtet, aber die kostenlosen Tarife lassen Dienste nach
Leerlauf einschlafen. Für einen Mix-Knoten ist das fatal: Beim Einschlafen
gehen wartende Pakete und der Replay-Cache verloren. Nur brauchbar, wenn
durchgehend Verkehr läuft — worauf man sich nicht verlassen sollte.

## Was ich empfehle

**Anbieter mischen, nicht sparen.** Drei Knoten bei drei verschiedenen
Betreibern:

```
mix-eu  → Oracle Always Free   (Frankfurt)
mix-us  → Oracle Always Free   (Ashburn, zweite VM)
mix-ap  → Cloudflare Workers   (global)
```

Das ist nicht nur billiger als Fly.io, sondern **sicherer**: Bei Fly.io
lägen alle drei Knoten bei einem Betreiber, der jede Zwiebel Schicht für
Schicht verfolgen könnte. Verschiedene Anbieter in verschiedenen
Jurisdiktionen sind der ganze Punkt der Übung.

Ganz sauber wäre es erst, wenn die Knoten unterschiedlichen *Personen*
gehören. Zwei Oracle-VMs im selben Konto sind formal ein Betreiber — du.
Wenn das Projekt echte Nutzer bekommt, such dir zwei Leute, die je einen
Knoten betreiben.

## Kosten im Vergleich

| | Fly.io | Kostenfrei |
|---|---|---|
| Client + DB + Log | 0 € | 0 € |
| 3 Mix-Knoten | ~15 €/Monat | 0 € |
| Betreibervielfalt | 1 | 2–3 |

Die kostenfreie Variante ist hier die bessere, nicht die schlechtere.
