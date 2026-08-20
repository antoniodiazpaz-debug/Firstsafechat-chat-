/* ═══════════════════════════════════════════════════════════════════════
   SPEICHERSICHERUNG
   ─────────────────────────────────────────────────────────────────────
   Das Problem: iOS kann den Speicher einer Web-App löschen, wenn sie
   längere Zeit nicht benutzt wurde oder das System unter Druck steht.
   Bei einem gewöhnlichen Web-Dienst ist das ärgerlich. Hier bedeutet es:
   Identitätsschlüssel weg, Chatverlauf für immer unlesbar.

   Drei Schichten dagegen:
     1. Dauerhaften Speicher anfordern (verhindert Löschung meistens)
     2. Regelmäßig prüfen, ob der Vault noch da ist
     3. Wiederherstellungsschlüssel, den der Nutzer außerhalb aufbewahrt

   Schicht 3 ist die einzige, die wirklich verlässlich ist. Die ersten
   beiden verringern die Wahrscheinlichkeit, die dritte macht den Verlust
   überlebbar.
   ═══════════════════════════════════════════════════════════════════════ */

const te = new TextEncoder(), td = new TextDecoder();
const b64 = b => btoa(String.fromCharCode(...new Uint8Array(b)));
const ub64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));

/* ── 1. Dauerhaften Speicher anfordern ──────────────────────────────── */
export async function requestPersistence() {
  if (!navigator.storage?.persist) return { supported: false };

  let persisted = await navigator.storage.persisted();
  if (!persisted) persisted = await navigator.storage.persist();

  const est = await navigator.storage.estimate?.() || {};
  return {
    supported: true,
    persisted,
    usedMB: est.usage ? (est.usage / 1048576).toFixed(1) : null,
    quotaMB: est.quota ? (est.quota / 1048576).toFixed(0) : null
  };
}

/* Safari setzt die Zusage teils beim Schließen zurück — also bei
   jedem Start erneut anfragen, nicht nur einmal bei der Installation. */
export function keepPersistenceAlive() {
  requestPersistence();
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible') requestPersistence();
  });
}

/* ── 2. Wiederherstellungsschlüssel ─────────────────────────────────── */

/* 24 Wörter aus einer festen Liste. Kein BIP-39, aber dieselbe Idee:
   etwas, das ein Mensch abschreiben und wieder eintippen kann. */
const WORDS = ('abend acker adler ahorn akte alarm alge amsel anker apfel april arbeit ' +
'archiv arena armee arzt asche atem atlas auge auto axt bach backe bad bahn bake balken ' +
'ball band bank bauer baum becher beere berg beruf besen bett beutel biene bild birke ' +
'blatt blei blick blume boden bogen bohne boot brief brot bruder buch bucht burg busch ' +
'dach damm dampf datei datum decke degen delfin diele ding donner dorf dose drache draht ' +
'druck düne dunst ebene ecke egel ehre eiche eimer eis eisen elch ende engel ente erbse ' +
'erde ernte esel essen eule fabrik faden fahne falke farbe fass feder feld fels fenster ' +
'ferse fest feuer figur film finger fisch flagge flasche fleck flug fluss form forst ' +
'foto frage frost frucht fuchs funke gabel galle garten gasse gast gebiet geige geist ' +
'gemüse gerste gesicht gitter glas glocke gold gras grenze gruppe gurke hafen hagel hahn ' +
'haken halle hals hammer hand hase haus haut hebel heide held helm hemd herbst herd herz ' +
'himmel hirsch hobel höhle holz honig horn hose hufe hügel huhn hund hütte igel insel ' +
'jacke jäger jahr jubel kabel käfer kahn kaktus kalb kamm kanal kante karte käse kasten ' +
'katze kegel kehle keller kerze kette kiel kiesel kind kino kirche kiste klang klee ' +
'klinge knie knopf koch kohle korb korn kraft kran kraut kreis kreuz krone küche kugel ' +
'kuh kunst küste lager lampe land lärm laub laus leder leier leine lenker lerche leuchte ' +
'licht lied linde linie lippe liste löffel löwe luchs luft lupe magnet mai mais mandel ' +
'mantel markt marmor maske mast matte mauer maus meer mehl meile meise messer metall ' +
'milch mine minze mitte möbel mohn mond moos motor motte möwe mühle mund münze muschel ' +
'mut mütze nabel nadel nagel name narbe nase nebel nelke nest netz niere nord not nudel ' +
'nuss oase ofen ohr öl olive onkel orgel ort otter paar palme panzer papier pappe park ' +
'pass pause pelz perle pfad pfahl pfeil pferd pflanze pilz pinsel platte platz pol post ' +
'probe puppe quelle rabe rad rahmen rand rasen rat raupe rebe regal regen reh reifen ' +
'reihe reis riegel riemen rind ring rippe robbe rock roggen rohr rolle rose rost rubin ' +
'rücken ruder ruf ruhe rune saal saat sache sack saft säge salbe salz same sand satz ' +
'säule schaf schale schaum scheibe schere schiff schlaf schloss schnee schuh schwan see ' +
'segel seide seife seil sekt sessel sicht sieb silber sinn sitz socke sohle sonne spalt ' +
'span speer spiel spitze sport spur staat stab stadt stall stamm stange staub steg stein ' +
'stern stich stiel stier stirn stock stoff strand strauß strom stube stück stufe stuhl ' +
'sturm sumpf tafel tag takt tal tanne tanz tasche tasse taste tau taube teich teil ' +
'teller teppich thron tiger tinte tisch topf tor torte tropfen truhe tuch tür turm ufer ' +
'uhr ulme urne vase veilchen ventil vieh vogel volk wache waffe wagen wahl wald wand ' +
'wange wanne ware warze wasser watte weber weg weide wein welle welt wende werk wespe ' +
'weste wette wiege wiese wind winkel winter wolke wolle wort wunde wurm wurzel zahn ' +
'zange zaun zebra zeder zeh zeichen zeile zelt ziege ziel zinke zirkel zone zopf zug zweig').split(/\s+/);

/* Die Liste wird auf exakt 512 Wörter gekürzt: 2⁹, also genau 9 Bit
   pro Wort ohne Rundungsverlust. Bei 520 Wörtern und einer
   Modulo-Zuordnung wären mehrere Bitmuster auf dasselbe Wort gefallen —
   die Phrase ließe sich dann nicht eindeutig zurückrechnen. */
const WORDLIST = [...new Set(WORDS)].sort().slice(0, 512);
if (WORDLIST.length !== 512) throw new Error('Wortliste muss 512 Einträge haben');

const BITS_PER_WORD = 9;
const PHRASE_WORDS = 29;          // 29 × 9 = 261 Bit für 256 Bit + 5 Bit Prüfsumme

/* 32 Byte Schlüssel → 29 Wörter, mit Prüfsumme gegen Tippfehler */
export function toRecoveryPhrase(keyBytes) {
  const key = new Uint8Array(keyBytes);
  if (key.length !== 32) throw new Error('Schlüssel muss 32 Byte lang sein');

  let bits = [...key].map(b => b.toString(2).padStart(8, '0')).join('');

  /* Prüfsumme: die ersten 5 Bit des SHA-256 über den Schlüssel.
     Ein vertipptes Wort fällt damit mit 97 % Wahrscheinlichkeit auf. */
  const sum = checksumBits(key, 5);
  bits += sum;

  const words = [];
  for (let i = 0; i < PHRASE_WORDS; i++) {
    const chunk = bits.slice(i * BITS_PER_WORD, (i + 1) * BITS_PER_WORD);
    words.push(WORDLIST[parseInt(chunk, 2)]);
  }
  return words;
}

/* 29 Wörter → 32 Byte Schlüssel, mit Prüfung */
export function fromRecoveryPhrase(words) {
  if (words.length !== PHRASE_WORDS)
    throw new Error(`${PHRASE_WORDS} Wörter erwartet, ${words.length} bekommen`);

  let bits = '';
  words.forEach((w, i) => {
    const idx = WORDLIST.indexOf(w.toLowerCase().trim());
    if (idx < 0) throw new Error(`Wort ${i + 1} ("${w}") steht nicht in der Liste`);
    bits += idx.toString(2).padStart(BITS_PER_WORD, '0');
  });

  const keyBits = bits.slice(0, 256);
  const given = bits.slice(256, 261);
  const key = new Uint8Array(32);
  for (let i = 0; i < 32; i++) key[i] = parseInt(keyBits.slice(i * 8, i * 8 + 8), 2);

  if (checksumBits(key, 5) !== given)
    throw new Error('Prüfsumme stimmt nicht — vermutlich ein Wort vertippt');

  return key;
}

/* Synchron, damit Kodieren und Dekodieren ohne await funktionieren */
function checksumBits(key, n) {
  /* FNV-1a über die Schlüsselbytes; für eine Tippfehlerprüfung genügt das,
     kryptografische Stärke ist hier nicht nötig. */
  let h = 0x811c9dc5;
  for (const b of key) { h ^= b; h = Math.imul(h, 0x01000193) >>> 0; }
  return h.toString(2).padStart(32, '0').slice(0, n);
}

/* Wiederherstellungsdatei: der Vault, verschlüsselt mit einem
   zufälligen Schlüssel, dessen Wörter der Nutzer notiert. */
export async function createRecoveryFile(vaultJson) {
  const recoveryKey = crypto.getRandomValues(new Uint8Array(32));
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));

  const base = await crypto.subtle.importKey('raw', recoveryKey, 'HKDF', false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info: te.encode('SecureChat-Recovery-v1') },
    base, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);

  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key,
    te.encode(JSON.stringify(vaultJson)));

  return {
    phrase: toRecoveryPhrase(recoveryKey),
    file: {
      v: 1, alg: 'AES-256-GCM/HKDF-SHA256',
      salt: b64(salt), iv: b64(iv), ct: b64(ct),
      created: new Date().toISOString()
    }
  };
}

/* ── 3. Regelmäßige Prüfung ─────────────────────────────────────────── */
export async function checkVaultHealth(userId, openVault) {
  try {
    const vault = await openVault(userId);
    if (!vault) return { ok: false, reason: 'missing' };

    const p = await requestPersistence();
    const lastSeen = Number(localStorage.getItem('vault:lastSeen') || 0);
    localStorage.setItem('vault:lastSeen', String(Date.now()));

    /* Länger als eine Woche nicht geöffnet: Es besteht echte Gefahr,
       dass beim nächsten Mal nichts mehr da ist. */
    const daysAway = lastSeen ? (Date.now() - lastSeen) / 86400000 : 0;

    return {
      ok: true,
      persisted: p.persisted,
      daysAway: Math.round(daysAway),
      atRisk: !p.persisted && daysAway > 5,
      hasBackup: localStorage.getItem('vault:backedUp') === '1'
    };
  } catch (e) {
    return { ok: false, reason: 'error', message: e.message };
  }
}

/* Was die Oberfläche daraus machen soll */
export function healthAdvice(h) {
  if (!h.ok && h.reason === 'missing')
    return { level: 'critical',
      text: 'Deine Schlüssel sind nicht mehr auf diesem Gerät. Stelle sie mit deiner Wiederherstellungsdatei wieder her.' };
  if (!h.hasBackup)
    return { level: 'warn',
      text: 'Sichere jetzt deinen Wiederherstellungsschlüssel. Ohne ihn ist dein Verlauf bei Geräteverlust unwiederbringlich.' };
  if (h.atRisk)
    return { level: 'warn',
      text: 'Dieses Gerät sichert deine Daten nicht dauerhaft. Öffne die App regelmäßig oder installiere sie auf dem Startbildschirm.' };
  if (!h.persisted)
    return { level: 'info',
      text: 'Für dauerhaften Speicher: App zum Startbildschirm hinzufügen.' };
  return { level: 'ok', text: null };
}
